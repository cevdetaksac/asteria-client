#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inject fake MySQL / IIS FTP / MSSQL auth-fail lines for AuthLogWatcher lab.

Writes under ``%ProgramData%\\Asteria\\authlog_probe\\{mysql,ftp,mssql}\\``.
Running Asteria Client ≥4.9.122 tails these paths and should enqueue Attacks
(when protection.block_rules for that service are enabled).

Usage (elevated not required for ProgramData\\Asteria if client already created it)::

  python tools/sim_authlog_inject.py
  python tools/sim_authlog_inject.py --ip 203.0.113.50 --once
  python tools/sim_authlog_inject.py --watch   # append every 15s
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone


def _probe_root() -> str:
    root = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
    return os.path.join(root, "Asteria", "authlog_probe")


def _ensure_dirs(base: str) -> dict:
    paths = {
        "mysql": os.path.join(base, "mysql", "mysqld.err"),
        "ftp": os.path.join(base, "ftp", "u_exsim.log"),
        "mssql": os.path.join(base, "mssql", "ERRORLOG"),
    }
    for p in paths.values():
        os.makedirs(os.path.dirname(p), exist_ok=True)
    return paths


def _append(path: str, lines: list[str]) -> None:
    with open(path, "a", encoding="utf-8", errors="replace") as fh:
        for line in lines:
            fh.write(line if line.endswith("\n") else line + "\n")


def inject(ip: str, user: str = "lab_probe") -> dict:
    base = _probe_root()
    paths = _ensure_dirs(base)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    stamp_t = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    # Seed FTP Fields header once
    if not os.path.isfile(paths["ftp"]) or os.path.getsize(paths["ftp"]) == 0:
        _append(
            paths["ftp"],
            ["#Fields: date time c-ip cs-username cs-method sc-status s-port"],
        )

    _append(
        paths["mysql"],
        [
            f"{stamp_t} [Note] Access denied for user '{user}'@'{ip}' "
            f"(using password: YES)"
        ],
    )
    _append(
        paths["ftp"],
        [f"{stamp} {ip} {user} PASS 530 21"],
    )
    _append(
        paths["mssql"],
        [
            f"{stamp}.00 Logon       Error: 18456, Severity: 14, State: 8.",
            f"Login failed for user '{user}'. Reason: Password did not match "
            f"that for the login provided. [CLIENT: {ip}]",
        ],
    )
    return paths


def main() -> int:
    ap = argparse.ArgumentParser(description="AuthLogWatcher lab log injector")
    ap.add_argument("--ip", default="203.0.113.90", help="Fake attacker IP (not loopback)")
    ap.add_argument("--user", default="lab_probe")
    ap.add_argument("--once", action="store_true", default=True)
    ap.add_argument("--watch", action="store_true", help="Append every 15 seconds")
    ap.add_argument("--interval", type=float, default=15.0)
    args = ap.parse_args()
    if args.ip in ("127.0.0.1", "localhost", "::1"):
        print("Refuse loopback IP — AuthLogWatcher skips localhost", file=sys.stderr)
        return 2

    def _run() -> None:
        paths = inject(args.ip, args.user)
        print(f"[sim] injected MySQL/FTP/MSSQL fails from {args.ip}")
        for k, p in paths.items():
            print(f"  {k}: {p}")

    if args.watch:
        print(f"[sim] watch mode every {args.interval}s — Ctrl+C to stop")
        while True:
            _run()
            time.sleep(max(5.0, args.interval))
    _run()
    print(
        "\nNext: wait ~5–10s for AuthLogWatcher poll, then check "
        "C:\\ProgramData\\Asteria\\client-*.log for AUTHLOG / attack enqueue "
        "and Cloud Attacks for MYSQL:3306 / FTP:21 / MSSQL:1433."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
