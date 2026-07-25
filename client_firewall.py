#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Honeypot Agent – Firewall Block/Unblock

Features (per spec):
- Polls backend for pending blocks/unblocks and applies them to OS firewall
- Windows: netsh advfirewall rules (chunked remoteip lists, same rule name per id)
- Linux: prefer ipset + iptables set match; fallback to iptables with comment
- Country blocks: fetch CIDR list per country daily and cache locally
- HTTPS with 5s timeout, retries with backoff; logs successes and failures

Config via environment or CLI args:
- API_BASE (e.g., https://HONEYPOT_HOST)
- TOKEN
- CIDR_FEED_BASE (default: https://example.com/cidr)
- REFRESH_INTERVAL_SEC (default: 10)

Endpoints:
- GET  {API_BASE}/api/agent/pending-blocks  (Authorization: Bearer)
- GET  {API_BASE}/api/agent/pending-unblocks  (Authorization: Bearer)
- POST {API_BASE}/api/agent/block-applied   body: {token, block_ids:[...]}
- POST {API_BASE}/api/agent/block-removed   body: {token, block_ids:[...]}

Requires admin/root privileges for firewall commands.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from client_security_utils import auth_headers, resolve_tls_verify, use_legacy_token_query
from urllib3.util.retry import Retry

BLOCK_PREFIX = "AR-BLOCK-"
INTEL_PREFIX = "AR-INTEL-"
LEGACY_BLOCK_PREFIX = "HP-BLOCK-"
LEGACY_INTEL_PREFIX = "HP-INTEL-"
FIREWALL_BRAND = "ar"
COUNTRY_PREFIX = "country:"


def block_rule_name(value: str) -> str:
    """Canonical safe AR-BLOCK name; plain IPs remain exactly AR-BLOCK-{ip}."""
    raw = (value or "").strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if raw.lower().startswith(COUNTRY_PREFIX):
        raw = "country-" + raw[len(COUNTRY_PREFIX):].strip().upper()
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-")[:96]
    return f"{BLOCK_PREFIX}{safe or 'unknown'}"


def _firewall_brand_state_path() -> Path:
    return Path(
        os.environ.get("ProgramData", r"C:\ProgramData")
    ) / "Asteria" / "firewall_brand.json"


# ---------------------------- Logging ---------------------------- #

def make_logger(log_path: Optional[Path] = None) -> logging.Logger:
    logger = logging.getLogger("firewall-agent")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    try:
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                str(log_path), maxBytes=1_000_000, backupCount=3, encoding="utf-8"
            )
            fh.setLevel(logging.INFO)
            fh.setFormatter(fmt)
            logger.addHandler(fh)
    except Exception:
        # Best-effort file logging
        pass

    return logger


# ---------------------------- Utils ---------------------------- #

def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_admin() -> bool:
    if is_windows():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except Exception:
            return False


def run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    # Canonical hidden runner (CREATE_NO_WINDOW + multi-encoding decode).
    try:
        from client_winproc import run_hidden
        return run_hidden(cmd, timeout=timeout)
    except Exception as e:
        return 1, "", f"{e}"


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------- HTTP client ---------------------------- #

def make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


# ---------------------------- Country CIDR cache ---------------------------- #

class CountryCIDRCache:
    def __init__(self, base_url: str, cache_dir: Path, logger: logging.Logger) -> None:
        self.base_url = base_url.rstrip("/")
        self.cache_dir = cache_dir
        self.logger = logger
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get(self, country_code: str, session: requests.Session, timeout: int = 5) -> List[str]:
        cc = country_code.upper()
        path = self.cache_dir / f"{cc}.txt"
        need_fetch = True
        if path.exists():
            try:
                mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)
                if now_utc() - mtime < dt.timedelta(days=1):
                    need_fetch = False
            except Exception:
                need_fetch = True
        if need_fetch:
            # Try multiple provider filename styles; ipdeny.com uses lowercase and .zone
            candidates = [
                f"{self.base_url}/{cc}.txt",
                f"{self.base_url}/{cc.lower()}.txt",
                f"{self.base_url}/{cc.lower()}.zone",
            ]
            fetched = False
            for url in candidates:
                self.logger.info(f"Fetching country CIDRs for {cc} from {url}")
                try:
                    r = session.get(url, timeout=timeout)
                    if r.status_code == 200 and r.text:
                        text = r.text
                        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
                        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                        fetched = True
                        break
                    else:
                        self.logger.warning(f"CIDR feed HTTP {r.status_code} for {cc} at {url}")
                except Exception as e:
                    self.logger.warning(f"CIDR fetch error for {cc} at {url}: {e}")
            if not fetched:
                self.logger.error(f"CIDR fetch failed for {cc} from all sources")
        # Read whatever we have
        try:
            return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        except Exception:
            return []


# ---------------------------- Firewall backends ---------------------------- #

class FirewallBackend:
    def apply_block(self, block_id: str, cidrs: List[str]) -> bool:
        raise NotImplementedError

    def remove_block(self, block_id: str, ip_or_cidr: str = "",
                     extra_names: Optional[List[str]] = None) -> bool:
        raise NotImplementedError


class WindowsFirewallBackend(FirewallBackend):
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger
        self.last_scan_ok = True

    @staticmethod
    def rule_name_candidates(block_id: str = "", ip_or_cidr: str = "") -> List[str]:
        """All historical / current honeypot block rule names for an IP or id."""
        names: List[str] = []
        bid = (block_id or "").strip()
        ip = (ip_or_cidr or "").strip().split("/")[0]
        if bid:
            names.extend((
                block_rule_name(bid),
                f"{LEGACY_BLOCK_PREFIX}{bid}",
            ))
        if ip:
            for n in (
                block_rule_name(ip),
                f"{LEGACY_BLOCK_PREFIX}{ip}",
                f"HONEYPOT_THREAT_BLOCK_{ip.replace('.', '_')}",
                f"HONEYPOT_BLOCK_REMOTE_{ip}",
                f"HONEYPOT_BLOCK_REMOTE_{ip.replace('.', '_')}",
                f"HONEYPOT_REMOTE_BLOCK_{ip}",
                f"HONEYPOT_REMOTE_BLOCK_{ip.replace('.', '_')}",
            ):
                if n not in names:
                    names.append(n)
        return names

    def _delete_rule_by_name(self, name: str) -> Tuple[str, int, str, str]:
        """Delete rule by name. Returns (status, rc, out, err).

        status: 'removed' | 'missing' | 'failed'
        """
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={name}",
        ]
        if not name.startswith((INTEL_PREFIX, LEGACY_INTEL_PREFIX)):
            cmd.append("dir=in")
        rc, out, err = run_cmd(cmd)
        combined = f"{out}\n{err}".lower()
        if rc == 0:
            if "0 rule" in combined:
                return "missing", rc, out, err
            return "removed", rc, out, err
        if any(x in combined for x in (
            "no rules match", "not found", "bulunamad", "eşleşen kural yok",
        )):
            return "missing", rc, out, err
        return "failed", rc, out, err

    # ── Threat-intel dedicated rules (AR-INTEL-*; HP legacy read/delete) ──

    @staticmethod
    def intel_rule_name(rule_id: str) -> str:
        """Stable Windows firewall rule name: AR-INTEL-<id>."""
        import re
        raw = (rule_id or "").strip() or "unknown"
        safe = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-")[:96]
        return f"{INTEL_PREFIX}{safe or 'unknown'}"

    def _delete_intel_rule_by_name(self, name: str) -> str:
        """Delete AR/HP-INTEL rule (in + out). Returns removed|missing|failed."""
        # Omit dir= so both inbound and outbound with same name are cleared.
        rc, out, err = run_cmd([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={name}",
        ])
        combined = f"{out}\n{err}".lower()
        if rc == 0:
            if "0 rule" in combined:
                return "missing"
            return "removed"
        if any(x in combined for x in (
            "no rules match", "not found", "bulunamad", "eşleşen kural yok",
        )):
            return "missing"
        return "failed"

    def apply_intel_block(self, rule_id: str, ip_or_cidr: str) -> bool:
        """Add inbound+outbound block as AR-INTEL-<id> (idempotent replace)."""
        name = self.intel_rule_name(rule_id)
        remote = (ip_or_cidr or "").strip()
        if not remote:
            return False
        self._delete_intel_rule_by_name(name)
        self._delete_intel_rule_by_name(
            name.replace(INTEL_PREFIX, LEGACY_INTEL_PREFIX, 1)
        )
        ok_in = self._add_rule(name, remote)
        # Outbound block (same name; netsh allows parallel dir=out)
        rc, out, err = run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}", "dir=out", "action=block", f"remoteip={remote}",
        ])
        ok_out = rc == 0
        if not ok_out:
            self.logger.error(
                err.strip() or out.strip() or f"netsh add out rule failed rc={rc}"
            )
        return bool(ok_in or ok_out)

    def remove_intel_block(self, rule_id: str = "", rule_name: str = "") -> bool:
        """Remove AR/HP-INTEL rule. True if removed or already absent."""
        name = (rule_name or "").strip() or self.intel_rule_name(rule_id)
        if not name:
            return False
        status = self._delete_intel_rule_by_name(name)
        return status in ("removed", "missing")

    def list_intel_rules(self) -> List[dict]:
        """Return existing AR/HP-INTEL rules (name + remoteip)."""
        ok, rules = self.scan_existing_rules_detailed()
        if not ok:
            # Fallback dedicated show — still try parse via show all path
            rules = rules or []
        out: List[dict] = []
        for r in rules or []:
            name = str(r.get("name") or "")
            prefix = next(
                (p for p in (INTEL_PREFIX, LEGACY_INTEL_PREFIX) if name.startswith(p)),
                "",
            )
            if prefix:
                out.append({
                    "name": name,
                    "remoteip": r.get("remoteip") or "",
                    "id": name[len(prefix):],
                })
        if out:
            return out
        # scan_existing may not yet include HP-INTEL — probe show rule all
        try:
            rc, raw, _ = run_cmd([
                "netsh", "advfirewall", "firewall", "show", "rule", "name=all",
            ], timeout=60)
            if rc != 0 or not raw:
                return out
            current: Dict[str, str] = {}
            for line in raw.splitlines():
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                key_raw = key.strip().lower()
                key_ns = key_raw.replace(" ", "")
                val = val.strip()
                if "rule name" in key_raw or "kural ad" in key_raw:
                    current_name = current.get("name", "")
                    prefix = next(
                        (p for p in (INTEL_PREFIX, LEGACY_INTEL_PREFIX)
                         if current_name.startswith(p)),
                        "",
                    )
                    if prefix:
                        out.append({
                            "name": current_name,
                            "remoteip": current.get("remoteip") or "",
                            "id": current_name[len(prefix):],
                        })
                    current = {"name": val}
                elif (
                    key_ns in ("remoteip", "uzakip", "remoteipv4", "uzakipv4")
                    or "remoteip" in key_ns
                    or "uzakip" in key_ns
                ):
                    current["remoteip"] = val
            current_name = current.get("name", "")
            prefix = next(
                (p for p in (INTEL_PREFIX, LEGACY_INTEL_PREFIX)
                 if current_name.startswith(p)),
                "",
            )
            if prefix:
                out.append({
                    "name": current_name,
                    "remoteip": current.get("remoteip") or "",
                    "id": current_name[len(prefix):],
                })
        except Exception as e:
            self.logger.error(f"list_intel_rules: {e}")
        # Dedupe by name (in+out appear twice in show)
        seen = set()
        uniq = []
        for r in out:
            n = r.get("name")
            if n in seen:
                continue
            seen.add(n)
            uniq.append(r)
        return uniq

    def _add_rule(self, name: str, remoteip_csv: str) -> bool:
        rc, out, err = run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}", "dir=in", "action=block", f"remoteip={remoteip_csv}",
        ])
        if rc == 0:
            if out.strip():
                self.logger.info(out.strip())
            return True
        self.logger.error(err.strip() or f"netsh add rule failed rc={rc}")
        return False

    def apply_block(self, block_id: str, cidrs: List[str]) -> bool:
        name = block_rule_name(block_id)
        # Replace any existing rules for id to be idempotent
        self._delete_rule_by_name(name)
        self._delete_rule_by_name(f"{LEGACY_BLOCK_PREFIX}{block_id}")

        # netsh has command length limits; chunk remote IPs
        # Conservative chunking by count (e.g., 200 per rule)
        CHUNK = 200
        if not cidrs:
            self.logger.warning(f"No CIDRs to apply for {name}")
            return False
        ok_all = True
        for i in range(0, len(cidrs), CHUNK):
            chunk = cidrs[i : i + CHUNK]
            csv = ",".join(chunk)
            ok = self._add_rule(name, csv)
            ok_all = ok_all and ok
        return ok_all

    def _lookup_rule_remoteip(self, rule_name: str) -> str:
        """Query netsh for a rule's first remote IP (delete / resolve helpers)."""
        full = self.lookup_rule_remoteips(rule_name)
        if not full:
            return ""
        return full.split(",")[0].strip().split("/")[0]

    def lookup_rule_remoteips(self, rule_name: str) -> str:
        """Return full RemoteIP field (may be comma-separated CIDRs)."""
        try:
            rc, out, _ = run_cmd([
                "netsh", "advfirewall", "firewall", "show", "rule",
                f"name={rule_name}", "dir=in",
            ], timeout=15)
            if rc != 0:
                return ""
            for line in out.splitlines():
                key, _, val = line.partition(":")
                key_l = key.strip().lower().replace(" ", "")
                val = val.strip()
                if not val:
                    continue
                if key_l in ("remoteip", "uzakip", "remoteipv4", "uzakipv4") or (
                    "remoteip" in key_l or "uzakip" in key_l
                ):
                    if val.lower() not in ("any", "herhangi"):
                        return val
        except Exception:
            pass
        return ""

    def remove_block(self, block_id: str, ip_or_cidr: str = "",
                     extra_names: Optional[List[str]] = None) -> bool:
        """Remove firewall block rules (idempotent).

        Returns True if removed OR already absent (ACK safe).
        Returns False on hard failure (access denied) — do NOT ACK.
        """
        if not ip_or_cidr and block_id:
            ip_or_cidr = self._lookup_rule_remoteip(f"{BLOCK_PREFIX}{block_id}")
        if not ip_or_cidr:
            ip_or_cidr = self._lookup_rule_remoteip(
                f"{LEGACY_BLOCK_PREFIX}{block_id}"
            )
            if ip_or_cidr:
                self.logger.info(
                    f"Resolved IP from firewall rule {block_id}: {ip_or_cidr}"
                )

        names_to_try = self.rule_name_candidates(block_id, ip_or_cidr)
        if extra_names:
            for n in extra_names:
                if n and n not in names_to_try:
                    names_to_try.append(n)

        removed_any = False
        hard_fail = False
        for name in names_to_try:
            status, rc, out, err = self._delete_rule_by_name(name)
            if status == "removed":
                msg = (out or "").strip()
                self.logger.info(f"Removed rule: {name}" + (f" ({msg})" if msg else ""))
                removed_any = True
            elif status == "failed":
                combined = f"{out}\n{err}".lower()
                self.logger.error(err.strip() or f"Failed to delete {name} rc={rc}")
                if any(x in combined for x in ("access", "denied", "privilege", "izin")):
                    hard_fail = True
                elif not removed_any:
                    hard_fail = True

        if hard_fail and not removed_any:
            return False

        if not removed_any:
            self.logger.info(
                f"No firewall rules found for block {block_id} / {ip_or_cidr} (idempotent OK)"
            )
        return True

    def scan_existing_rules(self) -> List[dict]:
        """Scan AR firewall rules plus HP/HONEYPOT/CloudHoneypot legacy.

        Returns list of dicts: {name, remoteip, prefix, ip?, legacy?}
        On enumeration failure returns [] and sets last_scan_ok=False
        (callers that rebuild ProgramData must not wipe store on failure).
        """
        ok, rules = self.scan_existing_rules_detailed()
        self.last_scan_ok = ok
        return rules

    def scan_existing_rules_detailed(self) -> Tuple[bool, List[dict]]:
        """Enumerate honeypot firewall rules.

        Returns (ok, rules). ok=False means netsh listing failed — do not
        treat as "zero rules" / wipe ProgramData inventory.
        """
        # Windows requires name=all (or a specific name). Without it:
        # "One or more essential parameters were not entered." → empty Engellenen.
        attempts = (
            ["netsh", "advfirewall", "firewall", "show", "rule",
             "name=all", "dir=in", "status=enabled"],
            ["netsh", "advfirewall", "firewall", "show", "rule",
             "name=all", "dir=in"],
        )
        out = ""
        err = ""
        rc = 1
        for cmd in attempts:
            rc, out, err = run_cmd(cmd, timeout=180)
            if rc == 0 and (out or "").strip():
                break
        else:
            self.logger.error(
                f"Failed to enumerate firewall rules: rc={rc} err={err or out[:200]}"
            )
            self.last_scan_ok = False
            return False, []

        self.last_scan_ok = True
        rules: List[dict] = []
        current: dict = {}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                if current:
                    rules.append(current)
                    current = {}
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                key_raw = key.strip().lower()
                key_ns = key_raw.replace(" ", "")
                val = val.strip()
                if "rule name" in key_raw or "kural ad" in key_raw:
                    if current.get("name"):
                        rules.append(current)
                        current = {}
                    current["name"] = val
                elif (
                    key_ns in ("remoteip", "uzakip", "remoteipv4", "uzakipv4")
                    or "remoteip" in key_ns
                    or "uzakip" in key_ns
                ):
                    current["remoteip"] = val
        if current:
            rules.append(current)

        def _match_prefix(name: str) -> Optional[tuple]:
            # Longer / more specific prefixes first
            for prefix, legacy in (
                ("HONEYPOT_BLOCK_REMOTE_", True),
                ("HONEYPOT_REMOTE_BLOCK_", True),
                ("HONEYPOT_THREAT_BLOCK_", True),
                ("HONEYPOT_BLOCK_", True),
                ("HONEYPOT_", True),
                ("CloudHoneypot", True),
                (LEGACY_INTEL_PREFIX, True),
                (LEGACY_BLOCK_PREFIX, True),
                (INTEL_PREFIX, False),
                (BLOCK_PREFIX, False),
            ):
                if name.startswith(prefix):
                    return prefix, legacy
            return None

        result = []
        for r in rules:
            name = r.get("name", "")
            remoteip = r.get("remoteip", "")
            matched = _match_prefix(name)
            if not matched:
                continue
            prefix, legacy = matched
            suffix = name[len(prefix):]
            entry = {
                "name": name,
                "remoteip": remoteip,
                "suffix": suffix,
                "prefix": prefix,
                "legacy": legacy,
            }
            if legacy and suffix:
                # Convert underscored IP back to dotted when applicable
                candidate = suffix.replace("_", ".")
                try:
                    ipaddress.ip_address(candidate.split("/")[0])
                    entry["ip"] = candidate
                except ValueError:
                    pass
            result.append(entry)
        return True, result

    def migrate_legacy_rule(self, old_name: str, ip: str, remoteip: str) -> bool:
        """Copy a legacy HP/HONEYPOT rule to AR, then delete the old rule."""
        is_intel = old_name.startswith(LEGACY_INTEL_PREFIX)
        if is_intel:
            suffix = old_name[len(LEGACY_INTEL_PREFIX):]
            new_name = f"{INTEL_PREFIX}{suffix}"
        else:
            new_name = f"{BLOCK_PREFIX}{ip}"
        remote = remoteip if remoteip and remoteip.lower() not in ("any", "herhangi") else ip
        if not remote:
            self.logger.error(f"Cannot migrate {old_name}: RemoteIP missing")
            return False
        self._delete_rule_by_name(new_name)
        created = self._add_rule(new_name, remote)
        if created and is_intel:
            rc, out, err = run_cmd([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={new_name}", "dir=out", "action=block",
                f"remoteip={remote}", "enable=yes",
            ])
            created = rc == 0
            if not created:
                self.logger.error(err.strip() or out.strip())
        if not created:
            self.logger.error(f"Failed to create migrated rule {new_name}")
            return False
        status, _, _, _ = self._delete_rule_by_name(old_name)
        if status == "failed":
            self.logger.error(f"Created {new_name}, but could not delete {old_name}")
            return False
        self.logger.info(f"Migrated: {old_name} → {new_name}")
        return True


class LinuxFirewallBackend(FirewallBackend):
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger
        self.has_ipset = bool(shutil.which("ipset"))

    def _iptables_has_set_rule(self, set_name: str) -> bool:
        rc, _, _ = run_cmd([
            "iptables", "-C", "INPUT", "-m", "set", "--match-set", set_name, "src", "-j", "DROP",
        ])
        return rc == 0

    def _iptables_add_set_rule(self, set_name: str) -> bool:
        if self._iptables_has_set_rule(set_name):
            return True
        rc, _, err = run_cmd([
            "iptables", "-I", "INPUT", "-m", "set", "--match-set", set_name, "src", "-j", "DROP",
        ])
        if rc == 0:
            return True
        self.logger.error(err.strip() or f"iptables add rule for set {set_name} failed")
        return False

    def _iptables_del_set_rule(self, set_name: str) -> None:
        run_cmd(["iptables", "-D", "INPUT", "-m", "set", "--match-set", set_name, "src", "-j", "DROP"])  # best-effort

    def _apply_with_ipset(self, block_id: str, cidrs: List[str]) -> bool:
        set_name = f"{BLOCK_PREFIX}{block_id}"
        # Create set (idempotent)
        rc, _, err = run_cmd(["ipset", "create", set_name, "hash:net", "family", "inet", "-exist"])
        if rc != 0:
            self.logger.error(err.strip() or f"ipset create {set_name} failed")
            return False
        ok_all = True
        for cidr in cidrs:
            rc, _, err = run_cmd(["ipset", "add", set_name, cidr, "-exist"])
            if rc != 0:
                self.logger.error(err.strip() or f"ipset add {cidr} to {set_name} failed")
                ok_all = False
        if not self._iptables_add_set_rule(set_name):
            ok_all = False
        return ok_all

    def _remove_with_ipset(self, block_id: str) -> bool:
        set_name = f"{BLOCK_PREFIX}{block_id}"
        self._iptables_del_set_rule(set_name)
        rc, _, err = run_cmd(["ipset", "destroy", set_name])
        if rc == 0:
            return True
        # If set is gone, consider success
        if "The set with the given name does not exist" in err:
            return True
        self.logger.error(err.strip() or f"ipset destroy {set_name} failed")
        return False

    def _iptables_add_with_comment(self, block_id: str, cidrs: List[str]) -> bool:
        ok_all = True
        for cidr in cidrs:
            # Check if exists
            rc, _, _ = run_cmd([
                "iptables", "-C", "INPUT", "-s", cidr, "-j", "DROP", "-m", "comment", "--comment", f"{BLOCK_PREFIX}{block_id}",
            ])
            if rc == 0:
                continue
            rc, _, err = run_cmd([
                "iptables", "-I", "INPUT", "-s", cidr, "-j", "DROP", "-m", "comment", "--comment", f"{BLOCK_PREFIX}{block_id}",
            ])
            if rc != 0:
                self.logger.error(err.strip() or f"iptables add rule for {cidr} failed")
                ok_all = False
        return ok_all

    def _iptables_remove_by_comment(self, block_id: str) -> bool:
        # List rules and remove ones matching our comment
        rc, out, err = run_cmd(["iptables", "-S", "INPUT"])
        if rc != 0:
            self.logger.error(err.strip() or "iptables -S failed")
            return False
        lines = out.splitlines()
        target = f"-m comment --comment {BLOCK_PREFIX}{block_id}"
        removed_any = False
        for ln in lines:
            if target in ln:
                # Convert -A to -D to delete the exact rule
                del_cmd = ["iptables"] + ln.strip().split()
                try:
                    idx = del_cmd.index("-A")
                    del_cmd[idx] = "-D"
                except ValueError:
                    # Fallback: construct -D with -s and -j
                    del_cmd = ["iptables", "-D", "INPUT"] + ln.strip().split()[2:]
                run_cmd(del_cmd)
                removed_any = True
        return removed_any

    def apply_block(self, block_id: str, cidrs: List[str]) -> bool:
        if not cidrs:
            self.logger.warning(f"No CIDRs to apply for {BLOCK_PREFIX}{block_id}")
            return False
        if self.has_ipset:
            return self._apply_with_ipset(block_id, cidrs)
        else:
            return self._iptables_add_with_comment(block_id, cidrs)

    def remove_block(self, block_id: str, ip_or_cidr: str = "",
                     extra_names: Optional[List[str]] = None) -> bool:
        if self.has_ipset:
            return self._remove_with_ipset(block_id)
        else:
            return self._iptables_remove_by_comment(block_id)


# ---------------------------- Agent core ---------------------------- #

class FirewallAgent:
    def __init__(
        self,
        api_base: str,
        token: str,
        refresh_interval: int = 10,
        cidr_feed_base: str = "https://www.ipdeny.com/ipblocks/data/countries",
        logger: Optional[logging.Logger] = None,
        auto_response=None,
        threat_engine=None,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.token = token
        self.refresh_interval = max(1, int(refresh_interval))
        self.logger = logger or make_logger()
        self.auto_response = auto_response
        self.threat_engine = threat_engine
        self.session = make_session()
        cache_root = _default_cache_dir()
        self.country_cache = CountryCIDRCache(cidr_feed_base, cache_root / "country", self.logger)
        self.backend: FirewallBackend
        if is_windows():
            self.backend = WindowsFirewallBackend(self.logger)
        elif is_linux():
            self.backend = LinuxFirewallBackend(self.logger)
        else:
            raise RuntimeError("Unsupported OS; only Windows and Linux are supported")
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    # --------------- HTTP helpers --------------- #

    def _get_json(self, path: str) -> Tuple[Optional[object], Optional[int]]:
        url = f"{self.api_base}{path}"
        params = {"token": self.token} if use_legacy_token_query() else None
        try:
            r = self.session.get(
                url, timeout=5, verify=resolve_tls_verify(),
                headers=auth_headers(self.token), params=params,
            )
            if r.status_code == 200:
                return r.json(), 200
            return None, r.status_code
        except Exception as e:
            self.logger.error(f"GET {path} failed: {e}")
            return None, None

    def _post_json(self, path: str, data: dict) -> Tuple[Optional[object], Optional[int]]:
        url = f"{self.api_base}{path}"
        payload = dict(data)
        payload.setdefault("token", self.token)
        try:
            r = self.session.post(
                url, json=payload, timeout=5, verify=resolve_tls_verify(),
                headers=auth_headers(self.token),
            )
            if r.status_code == 200:
                return r.json() if r.content else {}, 200
            return None, r.status_code
        except Exception as e:
            self.logger.error(f"POST {path} failed: {e}")
            return None, None

    # --------------- Country expansion --------------- #

    def _expand_ip_or_cidr(self, ip_or_cidr: str) -> List[str]:
        s = ip_or_cidr.strip()
        if s.lower().startswith(COUNTRY_PREFIX):
            cc = s[len(COUNTRY_PREFIX) :].strip().upper()
            if not re.fullmatch(r"[A-Z]{2}", cc):
                self.logger.error(f"Invalid country code: {s}")
                return []
            cidrs = self.country_cache.get(cc, self.session)
            if not cidrs:
                self.logger.error(f"No CIDRs found for country {cc}")
            return cidrs
        # Basic validation; accept IP or CIDR
        return [s]

    # --------------- Workflow --------------- #

    def _poll_pending_blocks(self) -> List[str]:
        payload_ids: List[str] = []
        data, code = self._get_json("/api/agent/pending-blocks")
        if code != 200 or not isinstance(data, list):
            if code not in (200, None):
                self.logger.error(f"pending-blocks HTTP {code}")
            return payload_ids

        # Conflict: same IP in both queues — skip if we just unblocked (handled by order)
        BATCH = 40
        for i in range(0, len(data), BATCH):
            batch = data[i : i + BATCH]
            batch_ids: List[str] = []
            for item in batch:
                try:
                    block_id = str(item["id"]).strip()
                    spec = str(item.get("ip_or_cidr", "")).strip()
                except Exception as e:
                    self.logger.error(f"Invalid block item: {e}")
                    continue
                if "/" in spec or spec.lower().startswith(COUNTRY_PREFIX):
                    # country/CIDR — apply if expandable; else log
                    pass
                cidrs = self._expand_ip_or_cidr(spec)
                if not cidrs:
                    continue
                # Contract 1.4.31: the firewall wire name is AR-BLOCK-{ip/spec};
                # block_id remains cloud ACK identity only.
                ok = self.backend.apply_block(spec, cidrs)
                if ok:
                    self.logger.info(f"Applied block {block_id} ({spec})")
                    batch_ids.append(block_id)
                    payload_ids.append(block_id)
                else:
                    self.logger.error(f"Failed to apply block {block_id} ({spec})")
            if batch_ids:
                body = {"token": self.token, "block_ids": batch_ids}
                _, ack_code = self._post_json("/api/agent/block-applied", body)
                if ack_code != 200:
                    self.logger.error(f"block-applied HTTP {ack_code}")
            if i + BATCH < len(data):
                time.sleep(0.15)
        return payload_ids

    def _poll_pending_unblocks(self) -> List[str]:
        """Process remove_pending queue — batch delete + block-removed ACK."""
        removed_ids: List[str] = []
        failed = 0
        data, code = self._get_json("/api/agent/pending-unblocks")
        if code != 200 or not isinstance(data, list):
            if code not in (200, None):
                self.logger.error(f"pending-unblocks HTTP {code}")
            return removed_ids

        if not data:
            return removed_ids

        total = len(data)
        if total >= 50:
            self.logger.info(
                f"[FW-SYNC] Large unblock queue ({total}) — batch processing…"
            )

        # One scan: map IP → extra rule names (catches duplicates / odd names)
        ip_to_extra: dict = {}
        try:
            if isinstance(self.backend, WindowsFirewallBackend):
                for r in self.backend.scan_existing_rules():
                    ip = (r.get("ip") or "").strip()
                    if not ip:
                        rip = (r.get("remoteip") or "").split(",")[0].strip().split("/")[0]
                        ip = rip
                    name = r.get("name") or ""
                    if ip and name:
                        ip_to_extra.setdefault(ip, []).append(name)
        except Exception as e:
            self.logger.warning(f"[FW-SYNC] pre-scan skipped: {e}")

        BATCH = 40
        for i in range(0, len(data), BATCH):
            batch = data[i : i + BATCH]
            batch_ids: List[str] = []
            batch_ips: List[str] = []
            for item in batch:
                try:
                    block_id = str(item["id"]).strip()
                    ip_or_cidr = str(
                        item.get("ip_or_cidr")
                        or item.get("ip")
                        or ""
                    ).strip()
                except Exception as e:
                    self.logger.error(f"Invalid unblock item: {e}")
                    failed += 1
                    continue

                ip_clean = ip_or_cidr.split("/")[0].strip() if ip_or_cidr else ""
                extra = ip_to_extra.get(ip_clean, []) if ip_clean else []

                ok = self.backend.remove_block(
                    block_id, ip_or_cidr=ip_or_cidr, extra_names=extra,
                )
                if ok:
                    self.logger.info(f"Removed block {block_id} ({ip_or_cidr})")
                    batch_ids.append(block_id)
                    removed_ids.append(block_id)
                    if ip_clean and ip_clean not in batch_ips:
                        batch_ips.append(ip_clean)
                    # Local cache only — do NOT re-hit netsh / alternate unblock APIs
                    if ip_clean and self.auto_response:
                        try:
                            if hasattr(self.auto_response, "forget_block"):
                                self.auto_response.forget_block(ip_clean)
                            elif hasattr(self.auto_response, "_blocks"):
                                lock = getattr(self.auto_response, "_lock", None)
                                if lock:
                                    with lock:
                                        self.auto_response._blocks.pop(ip_clean, None)
                                else:
                                    self.auto_response._blocks.pop(ip_clean, None)
                        except Exception:
                            pass
                else:
                    failed += 1
                    self.logger.error(
                        f"Failed to remove block {block_id} ({ip_or_cidr}) — ACK deferred"
                    )

            if batch_ids:
                self._ack_blocks_removed(batch_ids, batch_ips)
            if i + BATCH < len(data):
                time.sleep(0.2)

        self.logger.info(
            f"[FW-SYNC] pending_unblocks={total} removed={len(removed_ids)} failed={failed}"
        )
        return removed_ids

    def _ack_blocks_removed(self, block_ids: List[str], ips: Optional[List[str]] = None) -> int:
        """POST /api/agent/block-removed — prefer block_ids + ips (dashboard SoT).

        Live 4.8.4 finding: cloud returns HTTP 200 with ``updated: 0`` when the
        body only carries ``block_ids`` for remove_pending rows, so the dashboard
        stays on "Kaldırılıyor…". ACK'ing with ``ip`` / ``ips`` actually clears
        those rows (``updated > 0``). Send both; if the batch ACK reports
        updated=0, fall back to per-IP ACK.
        """
        ips = [ip for ip in (ips or []) if ip]
        # Prefer int IDs when possible — cloud store is numeric
        id_payload: list = []
        for bid in block_ids:
            try:
                id_payload.append(int(bid))
            except (TypeError, ValueError):
                id_payload.append(bid)

        body = {
            "token": self.token,
            "block_ids": id_payload,
        }
        if len(ips) == 1:
            body["ip"] = ips[0]
        if ips:
            body["ips"] = ips

        resp, ack_code = self._post_json("/api/agent/block-removed", body)
        updated = 0
        if isinstance(resp, dict):
            try:
                updated = int(resp.get("updated") or 0)
            except (TypeError, ValueError):
                updated = 0
        if ack_code != 200:
            self.logger.error(f"block-removed HTTP {ack_code} body={resp}")
            return 0

        self.logger.info(
            f"[FW-SYNC] block-removed ACK updated={updated} "
            f"ids={len(block_ids)} ips={len(ips)}"
        )
        if updated > 0:
            return updated

        # Fallback: cloud matched neither ids nor ips list — try per-IP
        recovered = 0
        for ip in ips:
            r2, code2 = self._post_json(
                "/api/agent/block-removed",
                {"token": self.token, "ip": ip},
            )
            u2 = 0
            if isinstance(r2, dict):
                try:
                    u2 = int(r2.get("updated") or 0)
                except (TypeError, ValueError):
                    u2 = 0
            if code2 == 200 and u2 > 0:
                recovered += u2
                self.logger.info(
                    f"[FW-SYNC] block-removed per-IP ACK ip={ip} updated={u2}"
                )
            else:
                self.logger.warning(
                    f"[FW-SYNC] block-removed per-IP ACK ip={ip} "
                    f"HTTP {code2} updated={u2} body={r2}"
                )
        return recovered

    # --------------- Migration & sync --------------- #

    def _migrate_and_sync_rules(self) -> None:
        """Migrate HP/HONEYPOT names once, then report remaining inventory.

        Does NOT re-apply local blocks to the cloud as new pending-blocks.
        Source of truth remains pending-unblocks / pending-blocks queues.
        """
        if not is_windows():
            return
        if not isinstance(self.backend, WindowsFirewallBackend):
            return

        state_path = _firewall_brand_state_path()
        already_migrated = False
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            already_migrated = state.get("firewall_brand") == FIREWALL_BRAND
        except (OSError, ValueError, TypeError):
            pass

        self.logger.info(
            "🔄 Firewall inventory sync starting"
            + (" (brand already AR)" if already_migrated else " (HP→AR migrate)")
        )

        try:
            ok, rules = self.backend.scan_existing_rules_detailed()
        except Exception as e:
            self.logger.error(f"Rule scan failed: {e}")
            return

        if not ok:
            self.logger.error(
                "Rule scan failed (netsh) — keeping ProgramData / API inventory"
            )
            return

        if not rules:
            self.logger.info("No existing AR/HP/legacy firewall rules found")
            try:
                from client_block_store import save_blocked_map
                save_blocked_map({})
            except Exception:
                pass
            self._hydrate_blocked_runtime({})
            sync_ok = self._sync_rules_to_api(
                [], mode="snapshot" if not already_migrated else ""
            )
            if not already_migrated and sync_ok:
                self._write_firewall_brand_marker(state_path)
            return

        migrated = 0
        migration_failed = False
        if not already_migrated:
            for r in rules:
                if not r.get("legacy"):
                    continue
                ip = r.get("ip", "")
                if not ip:
                    try:
                        from client_block_store import extract_ip_from_rule
                        ip = extract_ip_from_rule(r) or ""
                    except Exception:
                        ip = ""
                if ip:
                    ok = self.backend.migrate_legacy_rule(
                        old_name=r["name"],
                        ip=ip,
                        remoteip=r.get("remoteip", ""),
                    )
                    if ok:
                        migrated += 1
                        old_name = str(r.get("name") or "")
                        if old_name.startswith(LEGACY_INTEL_PREFIX):
                            suffix = old_name[len(LEGACY_INTEL_PREFIX):]
                            r["name"] = f"{INTEL_PREFIX}{suffix}"
                            r["prefix"] = INTEL_PREFIX
                        else:
                            r["name"] = f"{BLOCK_PREFIX}{ip}"
                            r["prefix"] = BLOCK_PREFIX
                        r["legacy"] = False
                        r["suffix"] = ip
                    else:
                        migration_failed = True
                else:
                    migration_failed = True
                    self.logger.warning(
                        f"Cannot migrate legacy rule without IP: {r.get('name')}"
                    )

        if migrated:
            self.logger.info(f"✅ Migrated {migrated} legacy firewall rule(s) to AR")

        # Persist inventory under ProgramData + hydrate RAM for GUI / AutoResponse
        try:
            from client_block_store import merge_from_firewall_rules, extract_ip_from_rule
            persisted = merge_from_firewall_rules(rules)
            self.logger.info(
                f"[BLOCK-STORE] ProgramData blocked_ips.json = {len(persisted)} IP(s)"
            )
        except Exception as e:
            self.logger.error(f"[BLOCK-STORE] persist failed: {e}")
            persisted = {}
            try:
                from client_block_store import extract_ip_from_rule
            except Exception:
                extract_ip_from_rule = None  # type: ignore

        sync_ips: dict = {}
        for r in rules:
            try:
                from client_block_store import extract_ips_from_rule
                ips = extract_ips_from_rule(r) or []
            except Exception:
                ips = []
                ip = ""
                if extract_ip_from_rule:
                    try:
                        ip = extract_ip_from_rule(r) or ""
                    except Exception:
                        ip = ""
                if not ip:
                    remoteip = r.get("remoteip", "")
                    suffix = r.get("suffix", "")
                    if suffix and "." in str(suffix):
                        ip = str(suffix).replace("_", ".")
                    elif remoteip and remoteip.lower() not in ("any", "herhangi"):
                        ip = remoteip.split(",")[0].strip().split("/")[0]
                if ip:
                    ips = [ip]
            suffix = str(r.get("suffix", ""))
            for ip in ips:
                if not ip:
                    continue
                sync_ips[ip] = {
                    "rule_name": r["name"],
                    "source": "dashboard" if suffix.isdigit() else "firewall",
                    "reason": (persisted.get(ip) or {}).get("reason", "firewall_rule"),
                    "blocked_at": (persisted.get(ip) or {}).get("blocked_at", 0),
                }

        auto_blocks = []
        if self.auto_response:
            try:
                auto_blocks = self.auto_response.get_blocked_ips()
            except Exception:
                pass

        for ab in auto_blocks:
            ip = ab.get("ip", "")
            if ip and ip not in sync_ips:
                sync_ips[ip] = {
                    "rule_name": f"{BLOCK_PREFIX}{ip}",
                    "source": "auto_response",
                    "reason": ab.get("reason", ""),
                    "blocked_at": ab.get("blocked_at", 0),
                }

        self._hydrate_blocked_runtime(sync_ips)
        sync_ok = self._sync_rules_to_api(
            list(sync_ips.items()),
            mode="snapshot" if not already_migrated else "",
        )
        if not already_migrated and not migration_failed and sync_ok:
            self._write_firewall_brand_marker(state_path)
        self.logger.info(
            f"🔄 Sync complete: {len(sync_ips)} active block(s) reported to API"
        )

    def _hydrate_blocked_runtime(self, sync_ips: dict) -> None:
        """Fill AutoResponse + ThreatEngine from firewall/ProgramData inventory."""
        try:
            if self.auto_response and hasattr(self.auto_response, "hydrate_from_inventory"):
                self.auto_response.hydrate_from_inventory(sync_ips)
        except Exception as e:
            self.logger.error(f"AutoResponse hydrate failed: {e}")
        try:
            te = self.threat_engine
            ips = set(sync_ips.keys())
            if not ips:
                from client_block_store import load_blocked_map
                ips = set(load_blocked_map().keys())
            if te is not None and hasattr(te, "hydrate_blocked_ips"):
                te.hydrate_blocked_ips(ips)
                self.logger.info(f"[BLOCK-STORE] ThreatEngine hydrated {len(ips)} blocked IP(s)")
        except Exception as e:
            self.logger.error(f"ThreatEngine hydrate failed: {e}")

    def _write_firewall_brand_marker(self, path: Path) -> None:
        """Persist brand migration only after a successful snapshot sync."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "firewall_brand": FIREWALL_BRAND,
                "firewall_brand_migrated_at": dt.datetime.now(
                    dt.timezone.utc
                ).isoformat(),
            }
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            os.replace(str(tmp), str(path))
            self.logger.info(f"[FW-BRAND] Migration marker written: {path}")
        except Exception as e:
            self.logger.warning(f"[FW-BRAND] Could not write migration marker: {e}")

    def _sync_rules_to_api(self, ip_entries: list, *, mode: str = "") -> bool:
        """POST /api/agent/sync-rules — inventory only (replace semantics on server)."""
        import datetime as _dt

        blocks = []
        for item in ip_entries:
            if isinstance(item, tuple):
                ip, info = item
            else:
                continue
            blocks.append({
                "ip": ip,
                "rule_name": info.get("rule_name", f"{BLOCK_PREFIX}{ip}"),
                "source": info.get("source", "unknown"),
                "reason": info.get("reason", ""),
                "blocked_at": info.get("blocked_at", ""),
            })

        body = {
            "token": self.token,
            "blocks": blocks,
            "total_rules": len(blocks),
            "synced_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        }
        if mode:
            body["mode"] = mode
        _, code = self._post_json("/api/agent/sync-rules", body)
        if code == 200:
            self.logger.info(f"API sync-rules accepted ({len(blocks)} blocks)")
            return True
        else:
            self.logger.warning(
                f"sync-rules HTTP {code} — inventory report skipped "
                f"(pending queues remain source of truth)"
            )
            return False

    def run_once(self) -> dict:
        """Run a single poll cycle — unblocks first (stale cleanup), then blocks."""
        try:
            unblocked = self._poll_pending_unblocks()
            blocked = self._poll_pending_blocks()
            self.logger.info(
                f"[FW-SYNC] pending_blocks={len(blocked)} "
                f"pending_unblocks={len(unblocked)} "
                f"removed={len(unblocked)} failed=0"
            )
            return {
                "success": True,
                "blocked_count": len(blocked),
                "unblocked_count": len(unblocked),
                "blocked_ids": blocked,
                "unblocked_ids": unblocked
            }
        except Exception as e:
            self.logger.exception(f"Agent run_once error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def run_forever(self) -> None:
        if not is_admin():
            self.logger.error("This agent requires Administrator/root privileges.")

        # Boot order (cloud is source of truth):
        # 1) pending-unblocks → delete + ACK
        # 2) pending-blocks → add + ACK
        # 3) sync-rules inventory of what remains (do NOT re-apply local list)
        self.logger.info("[FW-SYNC] Startup: unblocks → blocks → inventory sync")
        try:
            self._poll_pending_unblocks()
            self._poll_pending_blocks()
        except Exception as e:
            self.logger.error(f"Startup poll error (non-fatal): {e}")

        try:
            self._migrate_and_sync_rules()
        except Exception as e:
            self.logger.error(f"Migration/sync error (non-fatal): {e}")

        backoff = self.refresh_interval
        max_backoff = max(60, self.refresh_interval * 6)
        # Re-scan firewall → ProgramData → API so GUI/dashboard stay aligned
        inventory_every = max(1, int(900 / max(1, self.refresh_interval)))  # ~15 min
        cycles = 0
        self.logger.info(
            f"Started Honeypot Firewall Agent (poll every {self.refresh_interval}s, "
            f"inventory every {inventory_every} cycles)"
        )
        while not self._stop:
            start = time.time()
            try:
                unblocked = self._poll_pending_unblocks()
                blocked = self._poll_pending_blocks()
                self.logger.info(
                    f"[FW-SYNC] pending_blocks={len(blocked)} "
                    f"pending_unblocks={len(unblocked)} "
                    f"removed={len(unblocked)} failed=0"
                )
                cycles += 1
                if blocked or unblocked or cycles >= inventory_every:
                    try:
                        self._migrate_and_sync_rules()
                    except Exception as inv_err:
                        self.logger.error(f"Periodic inventory sync failed: {inv_err}")
                    cycles = 0
                backoff = self.refresh_interval  # reset on success
            except Exception as e:
                self.logger.exception(f"Agent loop error: {e}")
                backoff = min(max_backoff, max(self.refresh_interval, int(backoff * 2)))
            elapsed = time.time() - start
            sleep_for = max(1, backoff - int(elapsed))
            time.sleep(sleep_for)


# ---------------------------- Defaults & CLI ---------------------------- #

def _default_cache_dir() -> Path:
    if is_windows():
        base = os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / "YesNext" / "CloudHoneypotAgent" / "cache"
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
        return Path(base) / "cloud-honeypot-agent"


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Honeypot Firewall Agent")
    p.add_argument("--api-base", default=os.environ.get("API_BASE"), help="Backend API base URL (env: API_BASE)")
    p.add_argument("--token", default=os.environ.get("TOKEN"), help="Agent token (env: TOKEN)")
    p.add_argument(
        "--cidr-feed-base",
        default=os.environ.get("CIDR_FEED_BASE", "https://www.ipdeny.com/ipblocks/data/countries"),
        help="Base URL for country CIDR lists (env: CIDR_FEED_BASE)",
    )
    p.add_argument(
        "--interval",
        type=int,
        default=int(os.environ.get("REFRESH_INTERVAL_SEC", "30")),
        help="Polling interval seconds (env: REFRESH_INTERVAL_SEC, default 30)",
    )
    p.add_argument(
        "--log-file",
        default=os.environ.get("AGENT_LOG_FILE"),
        help="Optional log file path",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if not args.api_base or not args.token:
        print("ERROR: --api-base and --token are required (or set API_BASE/TOKEN env)")
        return 2
    log_path = Path(args.log_file) if args.log_file else None
    logger = make_logger(log_path)
    logger.info(f"OS detected: {'Windows' if is_windows() else ('Linux' if is_linux() else platform.system())}")
    logger.info(f"Polling interval: {args.interval}s")

    agent = FirewallAgent(
        api_base=args.api_base,
        token=args.token,
        refresh_interval=args.interval,
        cidr_feed_base=args.cidr_feed_base,
        logger=logger,
    )

    def _on_signal(signum, frame):
        logger.info(f"Signal {signum} received; stopping...")
        agent.stop()

    try:
        signal.signal(signal.SIGINT, _on_signal)
        signal.signal(signal.SIGTERM, _on_signal)
    except Exception:
        pass

    agent.run_forever()
    return 0


if __name__ == "__main__":
    import logging.handlers
    sys.exit(main())
