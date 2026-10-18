"""C-RD-PROD-1: embedded relay supervisor (URL, token only in env, backoff)."""
import client_rd_relay as r


def test_relay_url():
    assert r.relay_url("https://asteria.run/api") == "wss://asteria.run/ws/rd/agent"
    assert r.relay_url("https://asteria.run/") == "wss://asteria.run/ws/rd/agent"
    assert r.relay_url("http://127.0.0.1:8000/api") == "ws://127.0.0.1:8000/ws/rd/agent"
    assert r.relay_url("") == ""


def test_token_never_in_argv(monkeypatch):
    s = r.RdRelaySupervisor(None, lambda: "SECRET")
    cmd = s._cmd("C:/x/asteria-encode.exe", "wss://h/ws/rd/agent")
    assert "SECRET" not in " ".join(cmd) and cmd[1:5] == ["--session", "console", "--relay", "wss://h/ws/rd/agent"]
    monkeypatch.setenv("ASTERIA_RD_DEBUG", "1")
    assert s._cmd("x", "u")[-1] == "--debug"
