# -*- coding: utf-8 -*-
"""
Settings schema + patch builder for the GUI "Ayarlar" tab.

The cloud (`GET/POST /api/threats/config`) is the single source of truth.
The GUI renders widgets from SECTIONS, then turns the widget values back
into a nested patch with `build_threat_config_patch`. Keeping this logic
Tk-free makes it unit-testable.

Flat keys use dots for nesting: "silent_hours.enabled" →
{"silent_hours": {"enabled": ...}}.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

SEVERITIES = ["low", "medium", "high", "critical"]
SILENT_MODES = ["disabled", "night_only", "outside_working", "always"]

# Human labels for OptionMenu (lang-key → value). GUI translates via t().
CHOICE_LABEL_KEYS = {
    "min_severity_for_email": {
        "low": "settings_sev_low",
        "medium": "settings_sev_medium",
        "high": "settings_sev_high",
        "critical": "settings_sev_critical",
    },
    "silent_hours.mode": {
        "disabled": "settings_mode_disabled",
        "night_only": "settings_mode_night",
        "outside_working": "settings_mode_outside",
        "always": "settings_mode_always",
    },
}

_TIME_RE = re.compile(r"^([01]?\d|2[0-3]):[0-5]\d$")

# (section_label_key, [(flat_key, kind, label_key, extra), ...])
#   kind: bool | int | time | str | choice
#   extra: (min, max) for int, list of values for choice, None otherwise
SECTIONS: List[Tuple[str, list]] = [
    ("settings_sec_email", [
        ("alert_email_enabled", "bool", "settings_email_enabled", None),
        ("instant_email_for_critical", "bool", "settings_email_critical", None),
        ("min_severity_for_email", "choice", "settings_email_min_severity", SEVERITIES),
        ("daily_digest_enabled", "bool", "settings_daily_digest", None),
    ]),
    ("settings_sec_autoblock", [
        ("auto_block_enabled", "bool", "settings_autoblock_enabled", None),
        ("auto_block_threshold", "int", "settings_autoblock_threshold", (1, 100)),
        ("auto_block_duration_hours", "int", "settings_autoblock_duration", (0, 8760)),
        ("max_auto_blocks_per_hour", "int", "settings_autoblock_max_hour", (1, 1000)),
        ("max_auto_blocks_per_day", "int", "settings_autoblock_max_day", (1, 10000)),
    ]),
    ("settings_sec_silent", [
        ("silent_hours.enabled", "bool", "settings_silent_enabled", None),
        ("silent_hours.mode", "choice", "settings_silent_mode", SILENT_MODES),
        ("silent_hours.night_start", "time", "settings_silent_night_start", None),
        ("silent_hours.night_end", "time", "settings_silent_night_end", None),
        ("silent_hours.weekend_all_day_silent", "bool", "settings_silent_weekend", None),
        ("silent_hours.auto_block_ip", "bool", "settings_silent_auto_block", None),
        ("silent_hours.auto_logoff", "bool", "settings_silent_auto_logoff", None),
        ("silent_hours.auto_disable_account", "bool", "settings_silent_auto_disable", None),
    ]),
    ("settings_sec_webhook", [
        ("webhook_enabled", "bool", "settings_webhook_enabled", None),
        ("webhook_url", "str", "settings_webhook_url", None),
    ]),
]

DEFAULTS: Dict[str, Any] = {
    "alert_email_enabled": True,
    "instant_email_for_critical": True,
    "min_severity_for_email": "medium",
    "daily_digest_enabled": False,
    "auto_block_enabled": True,
    "auto_block_threshold": 3,
    "auto_block_duration_hours": 0,
    "max_auto_blocks_per_hour": 20,
    "max_auto_blocks_per_day": 100,
    "silent_hours.enabled": False,
    "silent_hours.mode": "night_only",
    "silent_hours.night_start": "00:00",
    "silent_hours.night_end": "07:00",
    "silent_hours.weekend_all_day_silent": False,
    "silent_hours.auto_block_ip": False,
    "silent_hours.auto_logoff": False,
    "silent_hours.auto_disable_account": False,
    "webhook_enabled": False,
    "webhook_url": "",
}


def _get_nested(config: dict, flat_key: str) -> Any:
    node: Any = config
    for part in flat_key.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def extract_settings_values(config: dict) -> Dict[str, Any]:
    """Flatten the cloud config into {flat_key: value} with defaults filled in."""
    if not isinstance(config, dict):
        config = {}
    values: Dict[str, Any] = {}
    for _sec, fields in SECTIONS:
        for flat_key, kind, _label, extra in fields:
            raw = _get_nested(config, flat_key)
            if raw is None:
                values[flat_key] = DEFAULTS.get(flat_key)
                continue
            if kind == "bool":
                values[flat_key] = bool(raw)
            elif kind == "int":
                try:
                    values[flat_key] = int(raw)
                except (TypeError, ValueError):
                    values[flat_key] = DEFAULTS.get(flat_key)
            elif kind == "choice":
                values[flat_key] = raw if raw in (extra or []) else DEFAULTS.get(flat_key)
            else:  # time | str
                values[flat_key] = str(raw)
    return values


def build_threat_config_patch(values: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Validate flat values and build the nested threats/config patch.

    Returns (patch, invalid_flat_keys). An empty error list means the patch
    is safe to POST. Unknown keys in `values` are ignored on purpose.
    """
    patch: Dict[str, Any] = {}
    errors: List[str] = []
    for _sec, fields in SECTIONS:
        for flat_key, kind, _label, extra in fields:
            if flat_key not in values:
                continue
            raw = values[flat_key]
            ok = True
            val: Any = raw
            if kind == "bool":
                val = bool(raw)
            elif kind == "int":
                try:
                    val = int(str(raw).strip())
                except (TypeError, ValueError):
                    ok = False
                else:
                    lo, hi = extra or (None, None)
                    if lo is not None and (val < lo or val > hi):
                        ok = False
            elif kind == "time":
                val = str(raw).strip()
                if not _TIME_RE.match(val):
                    ok = False
            elif kind == "choice":
                val = str(raw).strip()
                if val not in (extra or []):
                    ok = False
            else:  # str
                val = str(raw).strip()

            if not ok:
                errors.append(flat_key)
                continue

            node = patch
            parts = flat_key.split(".")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = val

    # Cross-field rule: enabled webhook needs a plausible URL
    if patch.get("webhook_enabled") and not str(
        patch.get("webhook_url", values.get("webhook_url", ""))
    ).strip().lower().startswith(("http://", "https://")):
        errors.append("webhook_url")
        patch.pop("webhook_url", None)
        patch.pop("webhook_enabled", None)

    return patch, errors
