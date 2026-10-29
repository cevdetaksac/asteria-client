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
