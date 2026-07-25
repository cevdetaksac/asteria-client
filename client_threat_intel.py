#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloud-driven threat intel — poll bundle, cache, apply defense layers.

Contract: honeypot-contract api/09-threat-intel.md
Cloud is the source of truth. This module does NOT scrape Abuse.ch/CISA.
Firewall IoCs → AR-INTEL-<id> (HP-* remains read/delete legacy only).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

from client_helpers import log

_POLL_SEC_DEFAULT = 20 * 60
_CACHE_NAME = "threat_intel_bundle.json"
_META_NAME = "threat_intel_meta.json"


def _programdata_dir() -> str:
    try:
        from client_utils import _programdata_client_dir
        return _programdata_client_dir()
    except Exception:
        return os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "Asteria",
        )


def _cache_path() -> str:
    return os.path.join(_programdata_dir(), _CACHE_NAME)


def _meta_path() -> str:
    return os.path.join(_programdata_dir(), _META_NAME)


def _severity_rank(s: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get((s or "").lower(), 0)


def _parse_expires_at(raw: Any) -> Optional[datetime]:
    if raw is None or raw == "":
        return None
    try:
        text = str(raw).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _is_expired(item: dict, *, now: Optional[datetime] = None) -> bool:
    exp = _parse_expires_at(item.get("expires_at") if isinstance(item, dict) else None)
    if exp is None:
        return False
    now = now or datetime.now(timezone.utc)
    return exp <= now


def _collect_allowlist(policy: dict, bundle: dict) -> Set[str]:
    """IPs/CIDRs that must never receive AR-INTEL blocks."""
    out: Set[str] = set()

    def _add(val: Any) -> None:
        if isinstance(val, str):
            v = val.strip()
            if v:
                out.add(v.lower().split("/")[0] if "/" not in v else v.lower())
        elif isinstance(val, dict):
            for key in ("ip", "value", "cidr", "ip_or_cidr"):
                if val.get(key):
                    _add(val.get(key))
        elif isinstance(val, (list, tuple, set)):
            for x in val:
                _add(x)

    for src in (
        policy.get("allowlist"),
        policy.get("allowlist_ips"),
        policy.get("firewall_allowlist"),
        bundle.get("allowlist"),
        bundle.get("allowlist_ips"),
    ):
        _add(src)
    return out


def _iso_z_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class ThreatIntelManager:
    """Daemon-side manager: sync from cloud + apply local layers."""

    def __init__(
        self,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
        ransomware_shield=None,
        auto_response=None,
        firewall_agent=None,
        on_alert: Optional[Callable[[dict], None]] = None,
        poll_sec: int = _POLL_SEC_DEFAULT,
    ):
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.ransomware_shield = ransomware_shield
        self.auto_response = auto_response  # unused for intel FW (HP-BLOCK path)
        self.firewall_agent = firewall_agent
        self.on_alert = on_alert
        self.poll_sec = max(300, int(poll_sec or _POLL_SEC_DEFAULT))
        self._running = False
        self._lock = threading.RLock()
        self._bundle: Dict[str, Any] = {}
        self._etag = ""
        self._version = ""
        self._fw_backend = None
        self._stats = {
            "syncs_ok": 0,
            "syncs_304": 0,
            "syncs_fail": 0,
            "firewall_applied": 0,
            "rs_rules_merged": 0,
            "last_error": "",
        }
        self._load_cache()

    # ── lifecycle ───────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        threading.Thread(
            target=self._loop, name="ThreatIntelSync", daemon=True
        ).start()
        threading.Thread(
            target=self._startup_sync, name="ThreatIntelBoot", daemon=True
        ).start()
        log("[THREAT-INTEL] manager started")

    def stop(self) -> None:
        self._running = False

    def get_stats(self) -> dict:
        with self._lock:
            return {
                **self._stats,
                "bundle_version": self._version,
                "etag": self._etag,
                "running": self._running,
            }

    def get_bundle(self) -> dict:
        with self._lock:
            return dict(self._bundle or {})

    def _backend(self):
        """WindowsFirewallBackend — prefer FirewallAgent's, else lazy own."""
        agent = self.firewall_agent
        if agent is not None:
            be = getattr(agent, "backend", None)
            if be is not None and hasattr(be, "apply_intel_block"):
                return be
        if self._fw_backend is None:
            from client_firewall import WindowsFirewallBackend
            self._fw_backend = WindowsFirewallBackend(
                logging.getLogger("honeypot.threat_intel_fw")
            )
        return self._fw_backend

    # ── sync ────────────────────────────────────────────────────

    def _startup_sync(self) -> None:
        time.sleep(8.0)
        try:
            self.sync_once()
        except Exception as e:
            log(f"[THREAT-INTEL] boot sync error: {e}")

    def _loop(self) -> None:
        while self._running:
            time.sleep(self.poll_sec)
            if not self._running:
                break
            try:
                self.sync_once()
            except Exception as e:
                log(f"[THREAT-INTEL] sync loop error: {e}")

    def sync_once(self) -> bool:
        token = (self.token_getter() or "").strip()
        if not token or not self.api_client:
            return False
        if not hasattr(self.api_client, "fetch_threat_intel"):
            return False

        try:
            from client_constants import VERSION
            client_ver = VERSION
        except Exception:
            client_ver = ""

        result = self.api_client.fetch_threat_intel(
            token=token,
            since_version=self._version or None,
            etag=self._etag or None,
            client_version=client_ver,
            os_name="windows",
        )
        if result is None:
            self._stats["syncs_fail"] += 1
            self._stats["last_error"] = "fetch_null"
            return False

        if result.get("not_modified"):
            self._stats["syncs_304"] += 1
            self._touch_meta(ok=True)
            # Reconcile expires/orphans locally; ACK only if FW state changed
            try:
                if self._bundle:
                    applied = self.apply_bundle(self._bundle)
                    changed = int(applied.get("firewall_added") or 0) + int(
                        applied.get("firewall_removed") or 0
                    )
                    if changed:
                        self._touch_meta(ok=True, applied=applied)
                        if hasattr(self.api_client, "ack_threat_intel"):
                            self.api_client.ack_threat_intel(
                                token=token,
                                bundle_version=self._version,
                                stats=applied,
                            )
            except Exception as e:
                log(f"[THREAT-INTEL] 304 reconcile error: {e}")
            return True

        bundle = result.get("bundle")
        if not isinstance(bundle, dict):
            self._stats["syncs_fail"] += 1
            self._stats["last_error"] = "bad_bundle"
            return False

        with self._lock:
            self._bundle = bundle
            self._version = str(bundle.get("bundle_version") or "")
            self._etag = str(
                result.get("etag") or bundle.get("etag") or self._etag or ""
            )
            self._save_cache()

        applied = self.apply_bundle(bundle)
        self._stats["syncs_ok"] += 1
        self._stats["last_error"] = ""
        self._touch_meta(ok=True, applied=applied)

        try:
            if hasattr(self.api_client, "ack_threat_intel"):
                self.api_client.ack_threat_intel(
                    token=token,
                    bundle_version=self._version,
                    stats=applied,
                )
        except Exception as e:
            log(f"[THREAT-INTEL] ack error: {e}")

        log(
            f"[THREAT-INTEL] applied bundle={self._version} "
            f"fw+={applied.get('firewall_added', 0)} "
            f"fw-={applied.get('firewall_removed', 0)} "
            f"skip={applied.get('firewall_skipped', 0)} "
            f"rs={applied.get('ransomware_rules', 0)}"
        )
        return True

    # ── apply ───────────────────────────────────────────────────

    def apply_bundle(self, bundle: Optional[dict] = None) -> dict:
        b = bundle if isinstance(bundle, dict) else self.get_bundle()
        layers = b.get("layers") if isinstance(b.get("layers"), dict) else {}
        policy = b.get("policy") if isinstance(b.get("policy"), dict) else {}
        stats = {
            "firewall_added": 0,
            "firewall_skipped": 0,
            "firewall_removed": 0,
            "ransomware_rules": 0,
            "process_watch": 0,
            "banners": 0,
            "errors": [],
        }

        try:
            stats.update(
                self._apply_firewall(
                    layers.get("firewall_blocks") or [],
                    policy,
                    bundle=b,
                )
            )
        except Exception as e:
            stats["errors"].append(f"firewall:{e}")

        try:
            n = self._apply_ransomware(layers.get("ransomware") or {})
            stats["ransomware_rules"] = n
            self._stats["rs_rules_merged"] = n
        except Exception as e:
            stats["errors"].append(f"ransomware:{e}")

        try:
            stats["process_watch"] = self._apply_process_watch(
                layers.get("process_watch") or []
            )
        except Exception as e:
            stats["errors"].append(f"process:{e}")

        try:
            banners = layers.get("ui_banners") or []
            if isinstance(banners, list):
                stats["banners"] = len(banners)
                self._emit_banners(banners)
        except Exception as e:
            stats["errors"].append(f"banners:{e}")

        try:
            kev = layers.get("kev_cves") or []
            if kev:
                log(f"[THREAT-INTEL] kev_cves in bundle: {len(kev)}")
        except Exception:
            pass

        return stats

    def _apply_firewall(
        self,
        blocks: list,
        policy: dict,
        *,
        bundle: Optional[dict] = None,
    ) -> dict:
        """Reconcile AR-INTEL-* rules to bundle.firewall_blocks (contract 09)."""
        out = {
            "firewall_added": 0,
            "firewall_skipped": 0,
            "firewall_removed": 0,
        }
        backend = self._backend()
        if backend is None or not hasattr(backend, "apply_intel_block"):
            out["firewall_skipped"] = len(blocks) if isinstance(blocks, list) else 0
            return out

        # Policy off → remove all intel rules, do not add
        if not policy.get("auto_block_firewall", True):
            try:
                existing = backend.list_intel_rules()
                for r in existing:
                    if backend.remove_intel_block(rule_name=r.get("name") or ""):
                        out["firewall_removed"] += 1
            except Exception as e:
                log(f"[THREAT-INTEL] policy-off purge error: {e}")
            out["firewall_skipped"] = len(blocks) if isinstance(blocks, list) else 0
            return out

        min_sev = str(policy.get("intel_block_requires_severity_at_least") or "high")
        max_rules = int(policy.get("max_firewall_rules_from_intel") or 500)
        allow = _collect_allowlist(policy, bundle or {})
        now = datetime.now(timezone.utc)

        if not isinstance(blocks, list):
            blocks = []

        candidates: List[dict] = []
        for item in blocks:
            if not isinstance(item, dict):
                out["firewall_skipped"] += 1
                continue
            if (item.get("action") or "block_ip") != "block_ip":
                out["firewall_skipped"] += 1
                continue
            if _severity_rank(item.get("severity") or "") < _severity_rank(min_sev):
                out["firewall_skipped"] += 1
                continue
            if _is_expired(item, now=now):
                out["firewall_skipped"] += 1
                continue
            ip = str(item.get("value") or item.get("ip") or item.get("ip_or_cidr") or "").strip()
            if not ip:
                out["firewall_skipped"] += 1
                continue
            ip_key = ip.lower().split("/")[0]
            if ip.lower() in allow or ip_key in allow:
                out["firewall_skipped"] += 1
                continue
            # Local AutoResponse whitelist (operator) — never intel-block
            try:
                ar = self.auto_response
                if ar is not None:
                    check = getattr(ar, "_is_whitelisted", None) or getattr(
                        ar, "is_whitelisted", None
                    )
                    if callable(check) and check(ip_key):
                        out["firewall_skipped"] += 1
                        continue
            except Exception:
                pass
            rule_id = str(item.get("id") or ip).strip()
            candidates.append({
                **item,
                "_ip": ip,
                "_id": rule_id,
                "_sev": _severity_rank(item.get("severity") or ""),
            })

        # Highest severity first when over cap
        candidates.sort(key=lambda x: (-x["_sev"], x["_id"]))
        if len(candidates) > max_rules:
            out["firewall_skipped"] += len(candidates) - max_rules
            candidates = candidates[:max_rules]

        desired_names: Set[str] = set()
        desired_ids: Dict[str, str] = {}  # name -> ip
        for c in candidates:
            name = backend.intel_rule_name(c["_id"])
            desired_names.add(name)
            desired_ids[name] = c["_ip"]

        # Orphan cleanup — AR desired; HP legacy is always removed.
        try:
            existing = backend.list_intel_rules()
        except Exception as e:
            existing = []
            log(f"[THREAT-INTEL] list_intel_rules: {e}")

        existing_names = {str(r.get("name") or "") for r in existing}
        for r in existing:
            name = str(r.get("name") or "")
            if not name.startswith(("AR-INTEL-", "HP-INTEL-")):
                continue
            if name not in desired_names:
                try:
                    if backend.remove_intel_block(rule_name=name):
                        out["firewall_removed"] += 1
                except Exception:
                    pass

        # Add / refresh desired
        added = 0
        for c in candidates:
            name = backend.intel_rule_name(c["_id"])
            ip = c["_ip"]
            already = name in existing_names
            # If present with same remoteip, treat as keep (not added)
            if already:
                try:
                    remote = ""
                    for r in existing:
                        if r.get("name") == name:
                            remote = str(r.get("remoteip") or "")
                            break
                    if remote and ip in remote.replace(" ", ""):
                        continue  # already applied
                except Exception:
                    pass
            try:
                ok = backend.apply_intel_block(c["_id"], ip)
                if ok:
                    if not already:
                        added += 1
                else:
                    out["firewall_skipped"] += 1
            except Exception as e:
                out["firewall_skipped"] += 1
                log(f"[THREAT-INTEL] apply_intel_block {c['_id']}: {e}")

        out["firewall_added"] = added
        self._stats["firewall_applied"] = added
        return out

    def _apply_ransomware(self, rs: dict) -> int:
        if not isinstance(rs, dict):
            return 0
        shield = self.ransomware_shield
        if not shield:
            return 0
        n = 0
        exts = rs.get("extensions") if isinstance(rs.get("extensions"), list) else []
        procs = rs.get("process_names") if isinstance(rs.get("process_names"), list) else []
        patterns = rs.get("cmdline_patterns") if isinstance(rs.get("cmdline_patterns"), list) else []

        if hasattr(shield, "merge_cloud_intel"):
            try:
                return int(shield.merge_cloud_intel(rs) or 0)
            except Exception as e:
                log(f"[THREAT-INTEL] merge_cloud_intel failed: {e}")

        for attr, values in (
            ("_extra_extensions", [str(x).lower() for x in exts if x]),
            ("_extra_process_names", [str(x).lower() for x in procs if x]),
            ("_extra_cmdline_patterns", patterns),
        ):
            if not values:
                continue
            try:
                cur = getattr(shield, attr, None)
                if cur is None:
                    setattr(shield, attr, list(values))
                elif isinstance(cur, list):
                    for v in values:
                        if v not in cur:
                            cur.append(v)
                n += len(values)
            except Exception:
                pass
        return n

    def _apply_process_watch(self, items: list) -> int:
        if not isinstance(items, list) or not items:
            return 0
        with self._lock:
            self._bundle.setdefault("_applied_process_watch", items)
        if self.on_alert:
            try:
                self.on_alert({
                    "event_type": "threat_intel_process_watch",
                    "threat_type": "intel_watch",
                    "severity": "info",
                    "threat_score": 5,
                    "description": f"Cloud process_watch rules loaded: {len(items)}",
                    "details": {"count": len(items)},
                })
            except Exception:
                pass
        return len(items)

    def _emit_banners(self, banners: list) -> None:
        for b in banners[:10]:
            if not isinstance(b, dict):
                continue
            title = b.get("title_tr") or b.get("title") or "Threat Intel"
            body = b.get("body_tr") or b.get("body") or ""
            log(f"[THREAT-INTEL] banner: {title} — {body[:160]}")
            if self.on_alert:
                try:
                    self.on_alert({
                        "event_type": "threat_intel_banner",
                        "threat_type": "intel_banner",
                        "severity": b.get("severity") or "info",
                        "threat_score": 5,
                        "description": f"{title}: {body}",
                        "details": b,
                    })
                except Exception:
                    pass

    # ── cache ───────────────────────────────────────────────────

    def _load_cache(self) -> None:
        # Prefer meta etag (survives body without etag field)
        try:
            meta_path = _meta_path()
            if os.path.isfile(meta_path):
                with open(meta_path, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
                if isinstance(meta, dict):
                    self._etag = str(meta.get("etag") or self._etag or "")
                    if not self._version:
                        self._version = str(meta.get("bundle_version") or "")
        except Exception:
            pass

        path = _cache_path()
        try:
            if not os.path.isfile(path):
                return
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._bundle = data
                self._version = str(data.get("bundle_version") or self._version or "")
                body_etag = str(data.get("etag") or "")
                if body_etag:
                    self._etag = body_etag
                log(
                    f"[THREAT-INTEL] cache loaded version={self._version} "
                    f"etag={'yes' if self._etag else 'no'}"
                )
                try:
                    self.apply_bundle(data)
                except Exception as e:
                    log(f"[THREAT-INTEL] cache apply error: {e}")
        except Exception as e:
            log(f"[THREAT-INTEL] cache load error: {e}")

    def _save_cache(self) -> None:
        try:
            os.makedirs(_programdata_dir(), exist_ok=True)
            path = _cache_path()
            payload = dict(self._bundle or {})
            # Persist etag inside cache so If-None-Match survives restart
            if self._etag:
                payload["etag"] = self._etag
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        except Exception as e:
            log(f"[THREAT-INTEL] cache save error: {e}")

    def _touch_meta(self, ok: bool = True, applied: Optional[dict] = None) -> None:
        try:
            os.makedirs(_programdata_dir(), exist_ok=True)
            meta = {
                "last_check_at": time.time(),
                "last_check_at_iso": _iso_z_now(),
                "ok": ok,
                "bundle_version": self._version,
                "etag": self._etag,
                "applied": applied or {},
            }
            path = _meta_path()
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(meta, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        except Exception:
            pass
