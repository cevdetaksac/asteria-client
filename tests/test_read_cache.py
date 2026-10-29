"""P3: SVC_LIST / SHARES_LIST TTL single-flight cache, invalidated on mutation."""
import threading
import time

import client_threat_local as tl


def setup_function(_):
    tl.invalidate_read_cache()


def test_cache_hits_within_ttl(monkeypatch):
    calls = []
    monkeypatch.setattr(tl, "_list_smb_shares_uncached", lambda: calls.append(1) or {"ok": True, "shares": []})
    tl.list_smb_shares(); tl.list_smb_shares(); tl.list_smb_shares()
    assert len(calls) == 1


def test_failures_not_cached(monkeypatch):
    calls = []
    monkeypatch.setattr(tl, "_list_smb_shares_uncached", lambda: calls.append(1) or {"ok": False})
    tl.list_smb_shares(); tl.list_smb_shares()
    assert len(calls) == 2


def test_single_flight(monkeypatch):
    calls = []

    def slow(max_rows=0):
        calls.append(1)
        time.sleep(0.3)
        return {"ok": True, "services": []}

    monkeypatch.setattr(tl, "_list_third_party_services_uncached", slow)
    ths = [threading.Thread(target=tl.list_third_party_services) for _ in range(5)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    assert len(calls) == 1


def test_mutation_invalidates(monkeypatch):
    calls = []
    monkeypatch.setattr(tl, "_list_smb_shares_uncached", lambda: calls.append(1) or {"ok": True, "shares": []})
    monkeypatch.setattr(tl, "_remove_smb_share", lambda name: {"ok": True})
    tl.list_smb_shares()
    tl.remove_smb_share("x")
    tl.list_smb_shares()
    assert len(calls) == 2


def test_ttl_expiry(monkeypatch):
    calls = []
    monkeypatch.setattr(tl, "_list_smb_shares_uncached", lambda: calls.append(1) or {"ok": True})
    monkeypatch.setattr(tl, "READ_CACHE_TTL_SEC", 0.05)
    tl._cached("shares", tl._list_smb_shares_uncached, ttl=0.05)
    time.sleep(0.1)
    tl._cached("shares", tl._list_smb_shares_uncached, ttl=0.05)
    assert len(calls) == 2