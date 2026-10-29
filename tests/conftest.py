"""Test izolasyonu: testler gercek makine token'i ile canli cloud'a lifecycle olayi GONDERMEZ.

Kok neden (client 60 '02:10 self_update_begin 4.9.62 from 4.9.54'): test_update_recovery vb.
run_self_update_command'i cagiriyor; report_now gercek DPAPI token'i yukleyip
ProgramData kuyruguna yaziyor ve asteria.run'a POST ediyordu.
"""
import os
import sys
import tempfile
import pathlib

os.environ["ASTERIA_TEST_ISOLATION"] = "1"

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_tmp = tempfile.mkdtemp(prefix="asteria-test-lifecycle-")
try:
    import client_lifecycle as _cl
    _cl.LIFECYCLE_LOG = os.path.join(_tmp, "lifecycle.log")
    _cl.LIFECYCLE_QUEUE = os.path.join(_tmp, "lifecycle_queue.jsonl")
except Exception:
    pass


import sys as _sys

import pytest as _pytest


@_pytest.fixture(autouse=True)
def _reset_threat_local_read_cache():
    """P3 read cache must not leak between tests."""
    mod = _sys.modules.get("client_threat_local")
    if mod is not None and hasattr(mod, "invalidate_read_cache"):
        mod.invalidate_read_cache()
    yield
