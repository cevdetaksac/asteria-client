"""P4: control socket handles connections in parallel; slow reads never block STATUS."""
import socket
import threading
import time

import pytest

client = pytest.importorskip("client")
C = client.CloudHoneypotClient


class _Stub:
    _CTRL_PARALLEL_SAFE = C._CTRL_PARALLEL_SAFE
    _CTRL_MAX_WORKERS = C._CTRL_MAX_WORKERS
    control_server_loop = C.control_server_loop
    _ctrl_conn_worker = C._ctrl_conn_worker
    _handle_ctrl_conn = C._handle_ctrl_conn
    _ctrl_cmd_is_parallel_safe = C._ctrl_cmd_is_parallel_safe

    def __init__(self):
        self.active_mut = 0
        self.max_mut = 0
        self._m = threading.Lock()

    def _dispatch_ctrl(self, conn, cmd, cmd_u, _send):
        if cmd_u == "SVC_LIST":
            time.sleep(2.0)
            _send('{"ok": true}')
        elif cmd_u.startswith("MUT"):
            with self._m:
                self.active_mut += 1
                self.max_mut = max(self.max_mut, self.active_mut)
            time.sleep(0.3)
            with self._m:
                self.active_mut -= 1
            _send("OK")
        else:
            _send('{"ok": true, "cmd": "%s"}' % cmd_u)


def _server():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(16)
    stub = _Stub()
    threading.Thread(target=stub.control_server_loop, args=(s,), daemon=True).start()
    return stub, s.getsockname()[1]


def _req(port, cmd, timeout=5.0):
    t0 = time.time()
    c = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    c.sendall((cmd + "\n").encode())
    data = c.recv(4096)
    c.close()
    return data, time.time() - t0


def test_status_not_blocked_by_slow_svc_list():
    _, port = _server()
    slow = [threading.Thread(target=_req, args=(port, "SVC_LIST")) for _ in range(2)]
    for t in slow:
        t.start()
    time.sleep(0.2)
    data, dt = _req(port, "STATUS", timeout=3.0)
    assert b"STATUS" in data
    assert dt < 0.5, dt
    for t in slow:
        t.join()


def test_mutating_commands_stay_serialized():
    stub, port = _server()
    ths = [threading.Thread(target=_req, args=(port, f"MUT{i}")) for i in range(4)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    assert stub.max_mut == 1


def test_parallel_safe_set():
    s = _Stub()
    assert s._ctrl_cmd_is_parallel_safe("STATUS")
    assert s._ctrl_cmd_is_parallel_safe("SVC_LIST")
    assert not s._ctrl_cmd_is_parallel_safe("QUIT")
    assert not s._ctrl_cmd_is_parallel_safe("BLOCK_IP 1.2.3.4")
    assert not s._ctrl_cmd_is_parallel_safe("SELF_UPDATE")