#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Never-stuck self-update primitives (4.9.150).

- Mirror-first URL list (asteria.run cloud cache of GitHub release assets) + GitHub.
- Resumable download (HTTP Range on ``.partial``), retries with backoff,
  SHA-256 + size check against the release manifest.
- Fresh helper: ``update-and-install.ps1`` is fetched from the *target* release
  each time (chicken-egg proof), validated by manifest SHA-256.
- PowerShell preamble: TLS 1.2/1.3 forced, progress bar off, first-line log.
- Rescue scheduled task: if the helper dies / hangs, it re-enables tasks and
  restarts the old agent (outbound 443 to cloud restored by the agent itself).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from typing import Callable, Iterable, List, Optional, Tuple

MIRROR_BASE = "https://asteria.run/api/agent/releases"
MANIFEST_ASSET = "asteria-release-manifest.json"
HELPER_ASSET = "update-and-install.ps1"
INSTALLER_ASSET = "asteria-client-installer.exe"
RESCUE_TASK_PREFIX = "Asteria-UpdateRescue"
BACKOFF_SEC = (2, 5, 10, 20, 30)
_TAG_RE = re.compile(r"^v?\d+\.\d+\.\d+$")

# Inserted right after param(...) in every PS script we run.
PS_PREAMBLE = (
    "# --- asteria never-stuck preamble (TLS 1.2/1.3, no progress bar) ---\n"
    "$ProgressPreference = 'SilentlyContinue'\n"
    "try { [Net.ServicePointManager]::SecurityProtocol = "
    "[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}\n"
    "try { [Net.ServicePointManager]::SecurityProtocol = "
    "[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]3072 } catch {}\n"
    "try { [Net.ServicePointManager]::SecurityProtocol = "
    "[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]12288 } catch {}\n"
    "# --- end preamble ---\n"
)


def _norm_tag(tag: str) -> str:
    t = str(tag or "").strip()
    if not t:
        return ""
    if not t.lower().startswith("v"):
        t = "v" + t
    return t if _TAG_RE.match(t) else ""


def _log_path() -> str:
    return os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"), "Asteria", "update-install.log"
    )


def uplog(msg: str) -> None:
    """Append one line to update-install.log (never raises)."""
    try:
        p = _log_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "a", encoding="ascii", errors="replace") as fh:
            fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass


def asset_urls(tag: str, asset: str, extra: Iterable[str] = ()) -> List[str]:
    """Mirror first, then GitHub, then any caller-provided (already allow-listed) URLs."""
    t = _norm_tag(tag)
    out: List[str] = []
    if t:
        out.append(f"{MIRROR_BASE}/{t}/{asset}")
        try:
            from client_constants import GITHUB_OWNER, GITHUB_REPO
            out.append(
                f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/download/{t}/{asset}"
            )
        except Exception:
            pass
    for u in extra or ():
        u = (u or "").strip()
        if u and u not in out:
            out.append(u)
    return out


def is_mirror_url(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        p = urlparse(str(url or ""))
        return (
            p.scheme == "https"
            and (p.hostname or "").lower() in ("asteria.run", "www.asteria.run")
            and (p.path or "").startswith("/api/agent/releases/")
        )
    except Exception:
        return False


def _default_get(url, **kw):
    import requests
    try:
        from client_security_utils import resolve_tls_verify
        kw.setdefault("verify", resolve_tls_verify())
    except Exception:
        pass
    return requests.get(url, **kw)


def fetch_manifest(tag: str, *, http_get: Callable = _default_get) -> Optional[dict]:
    """Release manifest: {"version", "assets": {name: {"sha256","size"}}}."""
    for url in asset_urls(tag, MANIFEST_ASSET):
        try:
            r = http_get(url, timeout=(15, 30))
            if getattr(r, "status_code", 0) != 200:
                continue
            data = json.loads(r.content.decode("utf-8") if isinstance(r.content, bytes) else r.text)
            if isinstance(data, dict) and isinstance(data.get("assets"), dict):
                return data
        except Exception:
            continue
    return None


def manifest_entry(manifest: Optional[dict], asset: str) -> Tuple[str, int]:
    try:
        e = (manifest or {}).get("assets", {}).get(asset) or {}
        return str(e.get("sha256") or "").lower(), int(e.get("size") or 0)
    except Exception:
        return "", 0


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_resumable(
    urls: List[str],
    dest: str,
    *,
    expected_sha256: str = "",
    expected_size: int = 0,
    attempts_per_url: int = 3,
    http_get: Callable = _default_get,
    sleep: Callable[[float], None] = time.sleep,
    progress: Optional[Callable[[int, int], None]] = None,
    log_func: Optional[Callable[[str], None]] = None,
    stall_timeout: int = 90,
) -> Tuple[bool, str]:
    """Download with resume (Range), retries/backoff, size + SHA-256 verification.

    Returns (ok, detail). On hash mismatch the partial is discarded and the next
    URL is tried (a poisoned cache must not brick the update).
    """
    _log = log_func or uplog
    partial = dest + ".partial"
    last = "no_urls"
    exp_sha = (expected_sha256 or "").lower()
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    for url in urls:
        for attempt in range(1, max(1, attempts_per_url) + 1):
            have = os.path.getsize(partial) if os.path.isfile(partial) else 0
            headers = {"User-Agent": "Asteria-Updater/4.9.150"}
            if have > 0:
                headers["Range"] = f"bytes={have}-"
            try:
                r = http_get(url, headers=headers, stream=True, timeout=(30, stall_timeout))
                code = int(getattr(r, "status_code", 0) or 0)
                if code == 416 and have > 0:
                    # Already complete (or server lost the file) - verify below
                    pass
                elif code == 206 and have > 0:
                    mode = "ab"
                elif code == 200:
                    mode = "wb"
                    have = 0
                else:
                    raise RuntimeError(f"http_{code}")
                if code in (200, 206):
                    total_hdr = 0
                    try:
                        total_hdr = int(r.headers.get("Content-Length") or 0) + have
                    except Exception:
                        total_hdr = 0
                    total = expected_size or total_hdr
                    done = have
                    with open(partial, mode) as fh:
                        for chunk in r.iter_content(chunk_size=256 * 1024):
                            if not chunk:
                                continue
                            fh.write(chunk)
                            done += len(chunk)
                            if progress:
                                try:
                                    progress(done, total)
                                except Exception:
                                    pass
                size = os.path.getsize(partial) if os.path.isfile(partial) else 0
                if expected_size and size < expected_size:
                    raise RuntimeError(f"incomplete {size}/{expected_size}")
                if expected_size and size > expected_size:
                    os.remove(partial)
                    raise RuntimeError(f"oversize {size}/{expected_size}")
                if size < 1024:
                    os.remove(partial)
                    raise RuntimeError(f"too_small {size}")
                if exp_sha:
                    got = _sha256_file(partial)
                    if got != exp_sha:
                        os.remove(partial)
                        last = f"hash_mismatch url={url[:80]} got={got[:12]}"
                        _log(f"[UPDATE-DL] {last}")
                        break  # next URL, do not retry poisoned source
                if os.path.isfile(dest):
                    os.remove(dest)
                os.replace(partial, dest)
                _log(f"[UPDATE-DL] ok url={url[:80]} size={size} resumed={have > 0}")
                return True, "complete"
            except Exception as exc:
                last = f"{type(exc).__name__}:{str(exc)[:140]}"
                _log(f"[UPDATE-DL] attempt {attempt} url={url[:80]} fail {last}")
                if attempt < attempts_per_url:
                    sleep(BACKOFF_SEC[min(attempt - 1, len(BACKOFF_SEC) - 1)])
    return False, last


def fetch_fresh_helper(tag: str, staging: str, manifest: Optional[dict], *,
                       http_get: Callable = _default_get) -> Optional[str]:
    """Download the target release's update-and-install.ps1 (manifest SHA required)."""
    sha, size = manifest_entry(manifest, HELPER_ASSET)
    if not sha:
        uplog("fresh_helper skip=no_manifest_sha")
        return None
    dst = os.path.join(staging, "update-and-install.fresh.ps1")
    ok, detail = download_resumable(
        asset_urls(tag, HELPER_ASSET), dst, expected_sha256=sha, expected_size=size,
        attempts_per_url=2, http_get=http_get, sleep=lambda s: time.sleep(min(s, 3)),
    )
    if not ok:
        uplog(f"fresh_helper fail detail={detail}")
        return None
    uplog(f"fresh_helper ok tag={tag} sha={sha[:12]}")
    return dst


def ensure_ps_preamble(text: str) -> str:
    """Insert PS_PREAMBLE right after the top-level param(...) block (or at top)."""
    if "asteria never-stuck preamble" in text:
        return text
    m = re.search(r"(?ims)^\s*param\s*\(", text)
    if not m:
        return PS_PREAMBLE + text
    i = m.end()
    depth = 1
    while i < len(text) and depth:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        i += 1
    nl = text.find("\n", i)
    nl = len(text) if nl < 0 else nl + 1
    return text[:nl] + PS_PREAMBLE + text[nl:]


RESCUE_PS1 = r"""# Asteria update rescue (ASCII). Runs once ~N min after a self-update launch.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$dir = Join-Path $env:ProgramData 'Asteria'
$log = Join-Path $dir 'update-install.log'
function W([string]$m){ try { Add-Content -Path $log -Value ('['+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+'] rescue: '+$m) -Encoding ASCII } catch {} }
W 'start'
$helperAlive = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'update-and-install' }).Count -gt 0
$nsis = @(Get-Process -Name 'asteria-client-installer*' -ErrorAction SilentlyContinue).Count -gt 0
$agent = @(Get-Process -Name 'asteria-client' -ErrorAction SilentlyContinue).Count -gt 0
W ("helperAlive=" + $helperAlive + " nsis=" + $nsis + " agent=" + $agent)
if ($nsis) { W 'installer still running - killing (timeout)'; Get-Process -Name 'asteria-client-installer*' | Stop-Process -Force }
if ($helperAlive -and -not $agent) { W 'helper hung - killing'; Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'update-and-install' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force } }
foreach ($n in @('Asteria-Background','Asteria-Watchdog','Asteria-Tray','Asteria-Updater','Asteria-SilentUpdater','Asteria-MemoryRestart','AsteriaClientGuard')) { schtasks /change /tn $n /enable 2>$null | Out-Null }
foreach ($f in @((Join-Path $dir 'update_in_progress.lock'), (Join-Path $env:ProgramData 'YesNext\CloudHoneypot\watchdog_stop.flag'))) { if (Test-Path $f) { Remove-Item $f -Force; W ('cleared ' + $f) } }
if (-not @(Get-Process -Name 'asteria-client' -ErrorAction SilentlyContinue).Count) {
  W 'agent not running - starting Asteria-Background'
  schtasks /run /tn 'Asteria-Background' 2>$null | Out-Null
  Start-Sleep -Seconds 20
  if (-not @(Get-Process -Name 'asteria-client' -ErrorAction SilentlyContinue).Count) {
    $exe = Join-Path ${env:ProgramFiles} 'Asteria\Asteria Client\asteria-client.exe'
    if (Test-Path $exe) { W 'fallback Start-Process daemon'; Start-Process -FilePath $exe -ArgumentList '--daemon' -WindowStyle Hidden }
  }
}
try { sc.exe start AsteriaGuardian 2>$null | Out-Null } catch {}
W 'done'
schtasks /delete /tn $env:ASTERIA_RESCUE_TASK /f 2>$null | Out-Null
exit 0
"""


def _schtasks(args: List[str]) -> int:
    try:
        r = subprocess.run(
            ["schtasks", *args], capture_output=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return int(r.returncode)
    except Exception:
        return -1


def arm_rescue_task(staging: str, pid: int, delay_min: int = 20) -> Optional[str]:
    """Create a one-shot SYSTEM task that restores the agent if update stalls."""
    name = f"{RESCUE_TASK_PREFIX}-{pid}"
    path = os.path.join(staging, "update-rescue.ps1")
    try:
        body = RESCUE_PS1.replace("$env:ASTERIA_RESCUE_TASK", f"'{name}'")
        with open(path, "w", encoding="ascii", errors="replace", newline="\r\n") as fh:
            fh.write(body)
    except OSError:
        return None
    t = time.localtime(time.time() + max(2, delay_min) * 60)
    st = time.strftime("%H:%M", t)
    sd = time.strftime("%m/%d/%Y", t)
    tr = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{path}"'
    rc = _schtasks(["/Create", "/TN", name, "/TR", tr, "/SC", "ONCE", "/ST", st, "/SD", sd,
                    "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"])
    if rc != 0:
        # Locale-specific date formats: retry without /SD (today only).
        rc = _schtasks(["/Create", "/TN", name, "/TR", tr, "/SC", "ONCE", "/ST", st,
                        "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"])
    uplog(f"rescue_task armed={rc == 0} name={name} at={st}")
    return name if rc == 0 else None


def disarm_rescue_tasks() -> None:
    """Called by a healthy agent at startup: remove stale rescue tasks."""
    try:
        r = subprocess.run(["schtasks", "/Query", "/FO", "CSV", "/NH"], capture_output=True,
                           text=True, timeout=20,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        for line in (r.stdout or "").splitlines():
            m = re.search(r'\\(' + RESCUE_TASK_PREFIX + r'-\d+)"', line)
            if m:
                _schtasks(["/Delete", "/TN", m.group(1), "/F"])
    except Exception:
        pass


def expire_stale_update_state(max_age_sec: float = 3600.0) -> List[str]:
    """Delete lock/flag files older than max_age_sec. Returns removed paths."""
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    cands = [
        os.path.join(pd, "Asteria", "update_in_progress.lock"),
        os.path.join(pd, "Asteria", "last_update_fail.txt"),
        os.path.join(pd, "YesNext", "CloudHoneypot", "watchdog_stop.flag"),
    ]
    removed = []
    now = time.time()
    for p in cands:
        try:
            if os.path.isfile(p) and now - os.path.getmtime(p) > max_age_sec:
                os.remove(p)
                removed.append(p)
        except OSError:
            pass
    if removed:
        uplog("stale_state_expired " + ",".join(os.path.basename(x) for x in removed))
    return removed
