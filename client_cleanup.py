#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Data Cleanup — yerel + firewall + sunucu/dashboard senkronu.

Scopes:
  local     — IP pool, session stats, dedup, threats.log
  firewall  — AR + HP/HONEYPOT legacy kuralları + auto_response + sync-rules([])
  server    — POST /api/agent/clear-data (attacks/blocks/alerts)
  all       — hepsi

Auto limits:
  enforce_firewall_limit(max_rules)
  enforce_ip_pool_limit(max_ips)
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from client_helpers import log
from client_utils import get_from_config

# Defaults (overridable via client_config.json → cleanup.*)
DEFAULT_MAX_FIREWALL_RULES = 500
DEFAULT_MAX_IP_POOL = 8000
DEFAULT_AUTO_ENFORCE_INTERVAL = 3600  # 1h


class DataCleanupManager:
    """Bakım / temizlik işlemleri — GUI ve otomatik limitler için."""

    def __init__(self, app):
        self.app = app
        self._lock = threading.Lock()
        self._auto_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._stats = {
            "local_runs": 0,
            "firewall_runs": 0,
            "server_runs": 0,
            "rules_removed": 0,
            "last_result": {},
        }

    # ── Public API ────────────────────────────────────────────────

    def clear_local(self) -> Dict[str, Any]:
        """Bellek + yerel log temizliği (API yok)."""
        result = {
            "ip_pool_cleared": 0,
            "session_reset": False,
            "dedup_cleared": False,
            "threats_log_cleared": False,
            "fp_tuner_cleared": False,
        }
        with self._lock:
            te = getattr(self.app, "threat_engine", None)
            if te and hasattr(te, "clear_contexts"):
                result["ip_pool_cleared"] = te.clear_contexts()
            elif te and hasattr(te, "_ip_pool"):
                with te._lock:
                    n = len(te._ip_pool)
                    te._ip_pool.clear()
                    if hasattr(te, "_rule_blocked_ips"):
                        te._rule_blocked_ips.clear()
                    if hasattr(te, "_rdp_grace"):
                        te._rdp_grace.clear()
                result["ip_pool_cleared"] = n
                log(f"[CLEANUP] Threat IP pool cleared ({n})")

            sm = getattr(self.app, "service_manager", None)
            if sm and hasattr(sm, "session_stats"):
                with sm._stats_lock:
                    sm.session_stats = {
                        "total_credentials": 0,
                        "per_service": {},
                        "last_attack_ts": None,
                        "last_attacker_ip": None,
                        "last_service": None,
                        "unique_ips": set(),
                    }
                result["session_reset"] = True

            ap = getattr(self.app, "alert_pipeline", None)
            if ap:
                if hasattr(ap, "_dedup"):
                    ap._dedup.clear()
                    result["dedup_cleared"] = True
                if hasattr(ap, "_batch_buffer"):
                    with getattr(ap, "_batch_lock", threading.Lock()):
                        ap._batch_buffer.clear()

            fp = getattr(self.app, "fp_tuner", None)
            if fp and hasattr(fp, "cleanup_stale"):
                try:
                    fp.cleanup_stale(0)
                    result["fp_tuner_cleared"] = True
                except Exception:
                    pass

            result["threats_log_cleared"] = self._truncate_threats_log()

            # GUI counters
            if hasattr(self.app, "_last_attack_count"):
                # Keep server count until refresh; session card will show 0
                pass

            self._stats["local_runs"] += 1
            self._stats["last_result"] = result
            log(f"[CLEANUP] Local cleanup done: {result}")
            return result

    def clear_firewall(self, sync_dashboard: bool = True) -> Dict[str, Any]:
        """Tüm AR/HP/HONEYPOT firewall kurallarını sil + dashboard sync.

        Must run elevated (SYSTEM daemon). Non-admin GUI must IPC to daemon.
        Long netsh/API work runs outside _lock so IPC/enforcer do not hang.
        """
        result = {
            "rules_removed": 0,
            "auto_blocks_cleared": 0,
            "api_synced": False,
            "server_cleared": False,
            "elevated": False,
            "error": None,
        }
        with self._lock:
            if getattr(self, "_firewall_clear_busy", False):
                result["error"] = "busy"
                return result
            self._firewall_clear_busy = True
            try:
                from client_firewall import is_admin
                result["elevated"] = bool(is_admin())
            except Exception:
                result["elevated"] = False
            if getattr(self.app, "_is_daemon_motor", False) or getattr(self.app, "daemon_is_active", False):
                result["elevated"] = True
            try:
                import getpass
                if (getpass.getuser() or "").upper() in ("SYSTEM", "LOCAL SYSTEM"):
                    result["elevated"] = True
            except Exception:
                pass
            ar = getattr(self.app, "auto_response", None)
            clear_ar_fw = bool(ar and result["elevated"] and hasattr(ar, "clear_all_blocks"))
            clear_ar_mem_only = bool(ar and hasattr(ar, "_blocks") and not clear_ar_fw)

        try:
            if clear_ar_fw:
                result["auto_blocks_cleared"] = ar.clear_all_blocks()
            elif clear_ar_mem_only:
                with ar._lock:
                    n = len(ar._blocks)
                    ar._blocks.clear()
                result["auto_blocks_cleared"] = n

            removed = self._delete_all_hp_block_rules()
            result["rules_removed"] = removed

            if not result["elevated"]:
                result["error"] = "elevation_required"
                log("[CLEANUP] clear_firewall aborted — elevation_required")
                return result

            try:
                from client_firewall import WindowsFirewallBackend
                backend = WindowsFirewallBackend(logger=_CleanupLogger())
                ok, left_rules = backend.scan_existing_rules_detailed()
                left_n = len(left_rules) if ok else -1
                result["rules_left"] = left_n
                if ok and left_n > 0:
                    result["error"] = "purge_incomplete"
                    log(f"[CLEANUP] clear_firewall incomplete — {left_n} rules still present")
                    return result
            except Exception as e:
                log(f"[CLEANUP] post-purge verify error: {e}")

            try:
                from client_block_store import save_blocked_map
                save_blocked_map({})
            except Exception:
                pass

            if sync_dashboard:
                token = self._token()
                api = getattr(self.app, "api_client", None)
                if token and api:
                    ok = api.sync_firewall_rules(token, [])
                    result["api_synced"] = bool(ok)
                    cleared = api.clear_client_data(
                        token, scopes=["blocks"], reason="firewall_cleanup",
                    )
                    result["server_cleared"] = cleared is not None
                    result["server_response"] = cleared
                else:
                    result["error"] = result.get("error") or "no_token_or_api"

            log(f"[CLEANUP] Firewall cleanup done: {result}")
            return result
        finally:
            with self._lock:
                self._firewall_clear_busy = False
                self._stats["rules_removed"] += int(result.get("rules_removed") or 0)
                self._stats["firewall_runs"] += 1
                self._stats["last_result"] = result

    def clear_server(self, scopes: Optional[List[str]] = None) -> Dict[str, Any]:
        """Sunucu/dashboard saldırı + alert + blok kayıtlarını temizle."""
        scopes = scopes or ["attacks", "blocks", "alerts", "threat_summary"]
        result = {"ok": False, "scopes": scopes, "response": None, "error": None}
        token = self._token()
        api = getattr(self.app, "api_client", None)
        if not token or not api:
            result["error"] = "no_token_or_api"
            return result
        try:
            resp = api.clear_client_data(token, scopes=scopes, reason="user_requested_cleanup")
            result["response"] = resp
            result["ok"] = resp is not None
            if result["ok"]:
                self._stats["server_runs"] += 1
                # Refresh attack count card
                try:
                    self.app.refresh_attack_count(async_thread=True)
                except Exception:
                    pass
            else:
                result["error"] = "api_rejected_or_missing_endpoint"
            log(f"[CLEANUP] Server clear: {result}")
        except Exception as e:
            result["error"] = str(e)
            log(f"[CLEANUP] Server clear error: {e}")
        self._stats["last_result"] = result
        return result

    def clear_all(self) -> Dict[str, Any]:
        """Yerel + firewall + sunucu — tam bakım."""
        out = {
            "local": self.clear_local(),
            "firewall": self.clear_firewall(sync_dashboard=True),
            "server": self.clear_server(
                scopes=["attacks", "blocks", "alerts", "threat_summary", "all"]
            ),
        }
        log(f"[CLEANUP] Full cleanup finished")
        return out

    def enforce_limits(self) -> Dict[str, Any]:
        """Otomatik limit: max firewall kuralı + IP pool boyutu."""
        max_rules = int(get_from_config(
            "cleanup.max_firewall_rules", DEFAULT_MAX_FIREWALL_RULES))
        max_ips = int(get_from_config(
            "cleanup.max_ip_pool", DEFAULT_MAX_IP_POOL))
        out = {
            "firewall_trimmed": 0,
            "ip_pool_trimmed": 0,
            "update_artifacts": {},
        }
        out["firewall_trimmed"] = self._trim_firewall_rules(max_rules)
        try:
            from client_utils import cleanup_update_artifacts
            out["update_artifacts"] = cleanup_update_artifacts(
                keep_installer=None,
                remove_installers=True,
                remove_launchers=True,
                include_downloads=True,
                only_if_not_updating=True,
            )
        except Exception as e:
            log(f"[CLEANUP] Update artifact prune error: {e}")
        te = getattr(self.app, "threat_engine", None)
        if te and hasattr(te, "_cleanup_stale_contexts"):
            before = 0
            try:
                with te._lock:
                    before = len(te._ip_pool)
            except Exception:
                pass
            te._cleanup_stale_contexts()
            # Extra hard cap
            try:
                with te._lock:
                    if len(te._ip_pool) > max_ips:
                        items = sorted(
                            te._ip_pool.items(),
                            key=lambda x: x[1].last_seen,
                        )
                        drop = len(te._ip_pool) - max_ips
                        for ip, ctx in items[:drop]:
                            if ip != "local" and not getattr(ctx, "is_blocked", False):
                                del te._ip_pool[ip]
                                out["ip_pool_trimmed"] += 1
            except Exception as e:
                log(f"[CLEANUP] IP pool trim error: {e}")
        if out["firewall_trimmed"] or out["ip_pool_trimmed"] or any(
            (out.get("update_artifacts") or {}).values()
        ):
            log(f"[CLEANUP] Auto limits enforced: {out}")
        return out

    def start_auto_enforcer(self):
        """Periyodik limit enforcer (daemon)."""
        if not get_from_config("cleanup.auto_enforce", True):
            return
        if self._auto_thread and self._auto_thread.is_alive():
            return
        self._stop.clear()
        interval = int(get_from_config(
            "cleanup.auto_enforce_interval_seconds", DEFAULT_AUTO_ENFORCE_INTERVAL))

        def _loop():
            # İlk çalıştırma biraz gecikmeli (startup yükü olmasın)
            for _ in range(min(60, interval)):
                if self._stop.is_set():
                    return
                time.sleep(1)
            while not self._stop.is_set():
                try:
                    self.enforce_limits()
                except Exception as e:
                    log(f"[CLEANUP] Auto enforce error: {e}")
                for _ in range(interval):
                    if self._stop.is_set():
                        return
                    time.sleep(1)

        self._auto_thread = threading.Thread(
            target=_loop, daemon=True, name="CleanupEnforcer",
        )
        self._auto_thread.start()
        log(f"[CLEANUP] Auto enforcer started (every {interval}s)")

    def stop(self):
        self._stop.set()

    def get_stats(self) -> dict:
        return dict(self._stats)

    # ── Internals ─────────────────────────────────────────────────

    def _token(self) -> str:
        try:
            return self.app.state.get("token") or ""
        except Exception:
            return ""

    def _truncate_threats_log(self) -> bool:
        try:
            from client_constants import APP_DIR, ALERT_THREAT_LOG_FILE
            path = os.path.join(APP_DIR, ALERT_THREAT_LOG_FILE)
            if os.path.isfile(path):
                open(path, "w", encoding="utf-8").close()
                return True
            # Also try threats.log next to exe / cwd
            for alt in (
                os.path.join(os.getcwd(), "threats.log"),
                os.path.join(APP_DIR, "threats.log"),
            ):
                if os.path.isfile(alt):
                    open(alt, "w", encoding="utf-8").close()
                    return True
        except Exception as e:
            log(f"[CLEANUP] threats.log truncate error: {e}")
        return False

    def _delete_all_hp_block_rules(self) -> int:
        """Remove all honeypot firewall rules (requires elevation / SYSTEM).

        Uses one hidden PowerShell sweep first (fast, no CMD flash storm),
        then a netsh fallback for any leftovers.
        """
        removed = 0
        try:
            from client_firewall import WindowsFirewallBackend, is_windows, run_cmd, is_admin
            if not is_windows():
                return 0

            elevated = False
            try:
                elevated = bool(is_admin())
            except Exception:
                elevated = False
            if getattr(self.app, "_is_daemon_motor", False) or getattr(self.app, "daemon_is_active", False):
                elevated = True
            try:
                import getpass
                if (getpass.getuser() or "").upper() in ("SYSTEM", "LOCAL SYSTEM"):
                    elevated = True
            except Exception:
                pass

            backend = WindowsFirewallBackend(logger=_CleanupLogger())
            before_ok, before = backend.scan_existing_rules_detailed()
            before_n = len(before) if before_ok else 0

            if not elevated and before_n > 0:
                log(
                    f"[CLEANUP] Firewall purge needs elevation "
                    f"(found {before_n} rules) — refusing non-admin delete"
                )
                return 0

            # Single PowerShell process — no per-rule CMD windows
            ps = (
                "$ErrorActionPreference='SilentlyContinue'; "
                "$rules = Get-NetFirewallRule | Where-Object { "
                "  $n = $_.DisplayName; "
                "  $n -like 'AR-BLOCK-*' -or "
                "  $n -like 'AR-INTEL-*' -or "
                "  $n -like 'HP-BLOCK-*' -or "
                "  $n -like 'HP-INTEL-*' -or "
                "  $n -like 'HONEYPOT_*' -or "
                "  $n -like 'CloudHoneypot*' "
                "}; "
                "$c = @($rules).Count; "
                "if ($c -gt 0) { $rules | Remove-NetFirewallRule }; "
                "Write-Output $c"
            )
            rc, out, err = run_cmd([
                "powershell", "-NoProfile", "-NonInteractive",
                "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
                "-Command", ps,
            ], timeout=180)
            try:
                removed = int((out or "").strip().splitlines()[-1].strip())
            except Exception:
                removed = 0
            if rc != 0:
                log(f"[CLEANUP] PowerShell purge rc={rc} err={(err or out)[:200]}")

            # Fallback: netsh per leftover (still hidden via run_cmd)
            after_ok, after = backend.scan_existing_rules_detailed()
            leftovers = after if after_ok else []
            for r in leftovers:
                name = r.get("name") or ""
                if not name:
                    continue
                drc, dout, _ = run_cmd([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={name}", "dir=in",
                ], timeout=30)
                if drc == 0 and "0 rule" not in (dout or "").lower():
                    removed += 1

            final_ok, final = backend.scan_existing_rules_detailed()
            left = len(final) if final_ok else -1
            log(
                f"[CLEANUP] Firewall purge: before={before_n} "
                f"reported_removed≈{removed} left={left}"
            )
            if before_n and left == 0:
                return before_n
            if before_n and left >= 0:
                return max(0, before_n - left)
            return removed
        except Exception as e:
            log(f"[CLEANUP] Firewall rule purge error: {e}")
        return removed

    def _trim_firewall_rules(self, max_rules: int) -> int:
        """Max üstü en eski AR/legacy block kurallarını sil."""
        trimmed = 0
        try:
            from client_firewall import WindowsFirewallBackend, is_windows, run_cmd
            if not is_windows():
                return 0
            backend = WindowsFirewallBackend(logger=_CleanupLogger())
            rules = backend.scan_existing_rules()
            if len(rules) <= max_rules:
                return 0
            # Prefer auto_response IP-named rules for trim; keep numeric dashboard IDs longer
            def _priority(r):
                name = r.get("name", "")
                suffix = (
                    name.replace("AR-BLOCK-", "")
                    .replace("HP-BLOCK-", "")
                    .replace("HONEYPOT_THREAT_BLOCK_", "")
                )
                return (0 if any(c.isalpha() for c in suffix.replace(".", "").replace("_", "")) else 1, name)

            ordered = sorted(rules, key=_priority)
            excess = len(rules) - max_rules
            for r in ordered[:excess]:
                name = r.get("name") or ""
                rc, out, _ = run_cmd([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={name}", "dir=in",
                ])
                if rc == 0 and "0 rule" not in (out or "").lower():
                    trimmed += 1
                    # Drop from auto_response memory if IP rule
                    ip = r.get("ip") or r.get("remoteip", "").split("/")[0]
                    ar = getattr(self.app, "auto_response", None)
                    if ar and ip and hasattr(ar, "_blocks"):
                        with ar._lock:
                            ar._blocks.pop(ip, None)
            if trimmed:
                token = self._token()
                api = getattr(self.app, "api_client", None)
                if token and api:
                    # Re-sync remaining
                    remaining = backend.scan_existing_rules()
                    blocks = []
                    for r in remaining:
                        ip = r.get("ip") or (r.get("remoteip") or "").split("/")[0]
                        if ip:
                            blocks.append({
                                "ip": ip,
                                "rule_name": r.get("name", ""),
                                "source": "auto_response",
                                "reason": "trim_sync",
                            })
                    api.sync_firewall_rules(token, blocks)
                log(f"[CLEANUP] Trimmed {trimmed} firewall rules (max={max_rules})")
        except Exception as e:
            log(f"[CLEANUP] Firewall trim error: {e}")
        return trimmed


class _CleanupLogger:
    def info(self, msg): log(f"[CLEANUP] {msg}")
    def warning(self, msg): log(f"[CLEANUP] ⚠ {msg}")
    def error(self, msg): log(f"[CLEANUP] ❌ {msg}")
    def exception(self, msg): log(f"[CLEANUP] ❌ {msg}")
