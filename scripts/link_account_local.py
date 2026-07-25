#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Link this machine's agent token to an Asteria account (no secrets in git).

Usage (PowerShell):
  $env:ASTERIA_EMAIL = 'you@example.com'
  $env:ASTERIA_PASSWORD = '***'
  python scripts/link_account_local.py

Optional:
  $env:ASTERIA_TOKEN = '<token>'   # else reads ProgramData token.dat
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    email = (os.environ.get("ASTERIA_EMAIL") or "").strip()
    password = os.environ.get("ASTERIA_PASSWORD") or ""
    token = (os.environ.get("ASTERIA_TOKEN") or "").strip()

    if not email or not password:
        print("ERROR: set ASTERIA_EMAIL and ASTERIA_PASSWORD env vars (do not commit them).")
        return 2

    if not token:
        try:
            from client_utils import TokenStore, _programdata_client_dir

            path = os.path.join(_programdata_client_dir(), "token.dat")
            token = TokenStore.load(path) or ""
        except Exception as exc:
            print(f"ERROR: token load failed: {exc}")
            return 3

    if not token:
        print("ERROR: no agent token (token.dat missing/unreadable). Re-enroll this host first.")
        return 4

    from client_api import link_account_with_credentials

    result = link_account_with_credentials(email=email, password=password, agent_token=token)
    ok = bool(result.get("ok") or result.get("account_linked"))
    print(
        "LINK_OK" if ok else "LINK_FAIL",
        {
            "ok": ok,
            "email": email,
            "error": result.get("error"),
            "linked": result.get("account_linked"),
        },
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
