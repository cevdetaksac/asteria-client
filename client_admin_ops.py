"""Admin commands v2 — reliable single path for dashboard server control.

Contract: features/server-management.md (admin result shape v2).

Every operation returns the standard shape::

    {"ok": bool, "success": bool, "code": str, "message": str, "steps": [...], "data": {...}}

``success`` mirrors ``ok`` for older cloud/dashboard readers; ``error`` is set to
``code`` on failure. Windows calls go through small backend classes so tests can
inject fakes (no subprocess parsing, no localized text matching).
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional

CREATE_NO_WINDOW = 0x08000000


# ---------------------------------------------------------------- result shape
def std(ok: bool, code: str, message: str, steps: Optional[list] = None, **data) -> dict:
    r = {
        "ok": bool(ok),
        "success": bool(ok),
        "code": str(code),
        "message": str(message or ""),
        "steps": list(steps or []),
    }
    if not ok:
        r["error"] = str(code)
    if data:
        r["data"] = data
    return r


def step(name: str, ok: bool, detail: str = "", **kw) -> dict:
    d = {"step": name, "ok": bool(ok)}
    if detail:
        d["detail"] = str(detail)[:300]
    d.update(kw)
    return d


def winerror_of(exc: BaseException) -> Optional[int]:
    w = getattr(exc, "winerror", None)
    if isinstance(w, int):
        return w
    try:
        a0 = exc.args[0]
        if isinstance(a0, int):
            return a0
    except Exception:
        pass
    return None


def system32(exe: str) -> str:
    """Full System32 path (agent is a 64-bit build → no WOW64 redirection)."""
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return os.path.join(root, "System32", exe)


# ---------------------------------------------------------------- create_user
NET_ERRORS = {
    5: ("ACCESS_DENIED", "Erişim reddedildi"),
    87: ("INVALID_PARAMETER", "Geçersiz parametre"),
    1317: ("NO_SUCH_USER", "Kullanıcı bulunamadı"),
    1332: ("NO_SUCH_USER", "Hesap adı çözümlenemedi"),
    1376: ("GROUP_NOT_FOUND", "Yerel grup bulunamadı"),
    1378: ("ALREADY_MEMBER", "Zaten grup üyesi"),
    2202: ("INVALID_USERNAME", "Geçersiz kullanıcı adı"),
    2220: ("GROUP_NOT_FOUND", "Grup bulunamadı"),
    2221: ("NO_SUCH_USER", "Kullanıcı bulunamadı"),
    2224: ("USER_EXISTS", "Kullanıcı zaten var"),
    2245: ("PASSWORD_POLICY", "Şifre parola ilkesine uymuyor (uzunluk/karmaşıklık/geçmiş)"),
}

# Well-known local groups by SID — names are localized (TR: "Yöneticiler").
WELL_KNOWN_GROUPS = {
    "administrators": "S-1-5-32-544", "yöneticiler": "S-1-5-32-544", "admin": "S-1-5-32-544",
    "users": "S-1-5-32-545", "kullanıcılar": "S-1-5-32-545",
    "remote desktop users": "S-1-5-32-555", "uzak masaüstü kullanıcıları": "S-1-5-32-555",
    "rdp": "S-1-5-32-555",
}

UF_SCRIPT = 0x0001
UF_ACCOUNTDISABLE = 0x0002
UF_NORMAL_ACCOUNT = 0x0200
UF_DONT_EXPIRE_PASSWD = 0x10000


class Win32Net:
    """NetUser*/NetLocalGroup* via pywin32."""

    def __init__(self):
        import win32net  # noqa: WPS433
        self._n = win32net

    def user_exists(self, username: str) -> bool:
        try:
            self._n.NetUserGetInfo(None, username, 0)
            return True
        except Exception as e:
            if winerror_of(e) == 2221:
                return False
            raise

    def add_user(self, username: str, password: str, comment: str, flags: int) -> None:
        self._n.NetUserAdd(None, 1, {
            "name": username, "password": password, "priv": 1,  # USER_PRIV_USER
            "home_dir": None, "comment": comment or None, "flags": flags, "script_path": None,
        })

    def reset_user(self, username: str, password: str, flags: int) -> None:
        self._n.NetUserSetInfo(None, username, 1003, {"password": password})
        self._n.NetUserSetInfo(None, username, 1008, {"flags": flags})

    def add_to_group(self, group: str, username: str) -> None:
        self._n.NetLocalGroupAddMembers(None, group, 3, [{"domainandname": username}])

    def resolve_group(self, name: str) -> str:
        sid = WELL_KNOWN_GROUPS.get((name or "").strip().lower())
        if not sid:
            return name
        try:
            import win32security
            return win32security.LookupAccountSid(None, win32security.ConvertStringSidToSid(sid))[0]
        except Exception:
            return name

    def delete_user(self, username: str) -> None:
        self._n.NetUserDel(None, username)


def _net_err(e: BaseException, fallback: str) -> tuple:
    w = winerror_of(e)
    code, msg = NET_ERRORS.get(w, (fallback, str(e)[:200] or fallback))
    return code, (f"{msg} (Win32 {w})" if w is not None else msg)


def create_user(username: str, password: str, groups: Iterable[str] = ("Users",), *,
                enable: bool = True, comment: str = "", password_never_expires: bool = False,
                if_exists: str = "fail", net=None) -> dict:
    username = (username or "").strip()
    if not username:
        return std(False, "MISSING_USERNAME", "Kullanıcı adı gerekli")
    if password is None or str(password) == "":
        return std(False, "MISSING_PASSWORD", "Şifre gerekli", username=username)
    try:
        net = net or Win32Net()
    except Exception as e:
        return std(False, "API_UNAVAILABLE", f"NetUser API yüklenemedi: {e}", username=username)
    flags = UF_SCRIPT | UF_NORMAL_ACCOUNT
    if password_never_expires:
        flags |= UF_DONT_EXPIRE_PASSWD
    if not enable:
        flags |= UF_ACCOUNTDISABLE
    steps: List[dict] = []
    try:
        existed = bool(net.user_exists(username))
    except Exception as e:
        code, msg = _net_err(e, "LOOKUP_FAILED")
        return std(False, code, msg, [step("lookup", False, msg)], username=username)
    if existed and str(if_exists or "fail").lower() != "reset_enable":
        return std(False, "USER_EXISTS", f"{username} zaten var",
                   [step("lookup", True, "exists")], username=username, created=False)
    try:
        if existed:
            net.reset_user(username, str(password), flags)
            steps.append(step("reset_password_enable", True))
        else:
            net.add_user(username, str(password), comment, flags)
            steps.append(step("create", True))
    except Exception as e:
        code, msg = _net_err(e, "CREATE_FAILED")
        steps.append(step("reset_password_enable" if existed else "create", False, msg, code=code))
        return std(False, code, msg, steps, username=username, created=False)

    if isinstance(groups, str):
        groups = [groups]
    added, failed = [], []
    for g in [str(x).strip() for x in (groups or []) if str(x).strip()]:
        real = g
        try:
            real = net.resolve_group(g)
            net.add_to_group(real, username)
            added.append(real)
            steps.append(step("group", True, group=real))
        except Exception as e:
            code, msg = _net_err(e, "GROUP_ADD_FAILED")
            if code == "ALREADY_MEMBER":
                added.append(real)
                steps.append(step("group", True, "already_member", group=real))
            else:
                failed.append(real)
                steps.append(step("group", False, msg, group=real, code=code))
    verb = "sıfırlandı" if existed else "oluşturuldu"
    if failed:
        return std(False, "GROUP_ADD_FAILED",
                   f"{username} {verb} ama gruba eklenemedi: {', '.join(failed)}",
                   steps, username=username, created=not existed, groups=added, failed_groups=failed)
    return std(True, "USER_RESET" if existed else "USER_CREATED", f"{username} {verb}",
               steps, username=username, created=not existed, groups=added, enabled=bool(enable))


# ---------------------------------------------------------------- kill_process
def _start_time_epoch(v) -> Optional[float]:
    if v in (None, ""):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        pass
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def kill_process(pid, *, expected_image: str = "", process_start_time=None, tree: bool = False,
                 protected_names: Iterable[str] = (), protected_pids: Iterable[int] = (),
                 psutil_mod=None, wait_sec: float = 5.0) -> dict:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return std(False, "INVALID_TARGET", "PID gerekli")
    if pid in (0, 4) or pid in set(int(x) for x in protected_pids):
        return std(False, "PROTECTED_PROCESS", f"Korunan süreç (PID {pid})", pid=pid)
    ps = psutil_mod
    if ps is None:
        import psutil as ps  # noqa: WPS433
    try:
        p = ps.Process(pid)
        name = (p.name() or "")
        created = float(p.create_time())
    except ps.NoSuchProcess:
        return std(False, "PROCESS_GONE", f"Süreç zaten yok (PID {pid})", pid=pid)
    except ps.AccessDenied:
        return std(False, "ACCESS_DENIED", f"Süreç bilgisi okunamadı (PID {pid})", pid=pid)
    exp = (expected_image or "").strip().lower()
    if exp and exp != name.lower():
        return std(False, "STALE_TARGET",
                   f"PID {pid} artık {name} (beklenen {expected_image}) — listeyi yenileyin",
                   pid=pid, found_image=name)
    st = _start_time_epoch(process_start_time)
    if st is not None and abs(created - st) > 2.0:
        return std(False, "STALE_TARGET",
                   f"PID {pid} yeniden kullanılmış (başlama zamanı farklı) — listeyi yenileyin",
                   pid=pid, found_image=name)
    if name.lower() in {str(x).lower() for x in protected_names}:
        return std(False, "PROTECTED_PROCESS", f"Korunan süreç: {name}", pid=pid)
    targets = [p]
    if tree:
        try:
            targets = p.children(recursive=True) + [p]
        except Exception:
            targets = [p]
    steps = []
    for t in targets:
        try:
            t.kill()
            steps.append(step("kill", True, pid=t.pid))
        except ps.NoSuchProcess:
            steps.append(step("kill", True, "already_gone", pid=t.pid))
        except ps.AccessDenied:
            steps.append(step("kill", False, "access_denied", pid=t.pid))
        except Exception as e:
            steps.append(step("kill", False, str(e), pid=t.pid))
    try:
        _gone, alive = ps.wait_procs(targets, timeout=wait_sec)
    except Exception:
        alive = []
    alive_pids = [a.pid for a in alive]
    if alive_pids:
        denied = any(s.get("detail") == "access_denied" for s in steps)
        return std(False, "ACCESS_DENIED" if denied else "KILL_FAILED",
                   f"Süreç sonlandırılamadı: {alive_pids}", steps, pid=pid, image=name, alive=alive_pids)
    return std(True, "KILLED",
               f"{name} (PID {pid}) sonlandırıldı" + (f" + {len(targets) - 1} alt süreç" if len(targets) > 1 else ""),
               steps, pid=pid, image=name, killed=[t.pid for t in targets])


# ---------------------------------------------------------------- restart_service
SVC_STOPPED, SVC_START_PENDING, SVC_STOP_PENDING, SVC_RUNNING = 1, 2, 3, 4
SVC_STATE_NAMES = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING", 4: "RUNNING",
                   5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED"}


class Win32Svc:
    def __init__(self):
        import win32service  # noqa: WPS433
        import win32serviceutil  # noqa: WPS433
        self._s = win32service
        self._u = win32serviceutil

    def state(self, name: str) -> int:
        return int(self._u.QueryServiceStatus(name)[1])

    def stop(self, name: str) -> None:
        self._u.StopService(name)

    def start(self, name: str) -> None:
        self._u.StartService(name)

    def active_dependents(self, name: str) -> List[str]:
        s = self._s
        scm = s.OpenSCManager(None, None, s.SC_MANAGER_CONNECT)
        try:
            h = s.OpenService(scm, name, s.SERVICE_ENUMERATE_DEPENDENTS)
            try:
                return [d[0] for d in (s.EnumDependentServices(h, s.SERVICE_ACTIVE) or [])]
            finally:
                s.CloseServiceHandle(h)
        finally:
            s.CloseServiceHandle(scm)


def _wait_state(svc, name: str, want: int, timeout: float, sleep: Callable = time.sleep,
                clock: Callable = time.monotonic) -> int:
    end = clock() + timeout
    st = svc.state(name)
    while st != want and clock() < end:
        sleep(0.5)
        st = svc.state(name)
    return st


def restart_service(name: str, *, timeout: float = 45.0, svc=None, protected: Iterable[str] = (),
                    sleep: Callable = time.sleep, clock: Callable = time.monotonic) -> dict:
    name = (name or "").strip()
    if not name:
        return std(False, "MISSING_SERVICE", "Servis adı gerekli")
    if name.lower() in {str(x).lower() for x in protected}:
        return std(False, "PROTECTED_SERVICE", f"Korunan servis: {name}", service=name)
    try:
        svc = svc or Win32Svc()
    except Exception as e:
        return std(False, "API_UNAVAILABLE", f"Servis API yüklenemedi: {e}", service=name)
    steps: List[dict] = []
    try:
        initial = svc.state(name)
    except Exception as e:
        w = winerror_of(e)
        if w == 1060:
            return std(False, "SERVICE_NOT_FOUND", f"Servis bulunamadı: {name}", service=name)
        if w == 5:
            return std(False, "ACCESS_DENIED", f"Servise erişim reddedildi: {name}", service=name)
        return std(False, "QUERY_FAILED", str(e)[:200], service=name)
    steps.append(step("query", True, SVC_STATE_NAMES.get(initial, str(initial))))

    deps: List[str] = []
    if initial != SVC_STOPPED:
        try:
            deps = list(svc.active_dependents(name))
        except Exception as e:
            steps.append(step("dependents", False, str(e)))
        for d in deps:  # EnumDependentServices order == safe stop order
            try:
                svc.stop(d)
            except Exception as e:
                if winerror_of(e) != 1062:  # not started
                    steps.append(step("stop_dependent", False, str(e), service=d))
                    return std(False, "DEPENDENT_STOP_FAILED", f"Bağımlı servis durdurulamadı: {d}",
                               steps, service=name, dependents=deps)
            st = _wait_state(svc, d, SVC_STOPPED, timeout, sleep, clock)
            ok = st == SVC_STOPPED
            steps.append(step("stop_dependent", ok, SVC_STATE_NAMES.get(st, str(st)), service=d))
            if not ok:
                return std(False, "DEPENDENT_STOP_TIMEOUT", f"Bağımlı servis durmadı: {d}",
                           steps, service=name, dependents=deps)
        try:
            svc.stop(name)
        except Exception as e:
            if winerror_of(e) != 1062:
                code = "ACCESS_DENIED" if winerror_of(e) == 5 else "STOP_FAILED"
                steps.append(step("stop", False, str(e)))
                return std(False, code, f"{name} durdurulamadı: {e}", steps, service=name)
        st = _wait_state(svc, name, SVC_STOPPED, timeout, sleep, clock)
        steps.append(step("stop", st == SVC_STOPPED, SVC_STATE_NAMES.get(st, str(st))))
        if st != SVC_STOPPED:
            return std(False, "STOP_TIMEOUT", f"{name} {int(timeout)} sn içinde durmadı", steps, service=name)

    try:
        svc.start(name)
    except Exception as e:
        if winerror_of(e) != 1056:  # already running
            code = "ACCESS_DENIED" if winerror_of(e) == 5 else "START_FAILED"
            steps.append(step("start", False, str(e)))
            return std(False, code, f"{name} başlatılamadı: {e}", steps, service=name)
    st = _wait_state(svc, name, SVC_RUNNING, timeout, sleep, clock)
    steps.append(step("start", st == SVC_RUNNING, SVC_STATE_NAMES.get(st, str(st))))
    if st != SVC_RUNNING:
        return std(False, "START_TIMEOUT", f"{name} {int(timeout)} sn içinde başlamadı", steps, service=name)

    dep_fail = []
    for d in reversed(deps):
        try:
            svc.start(d)
        except Exception as e:
            if winerror_of(e) != 1056:
                dep_fail.append(d)
                steps.append(step("start_dependent", False, str(e), service=d))
                continue
        st = _wait_state(svc, d, SVC_RUNNING, timeout, sleep, clock)
        steps.append(step("start_dependent", st == SVC_RUNNING, SVC_STATE_NAMES.get(st, str(st)), service=d))
        if st != SVC_RUNNING:
            dep_fail.append(d)
    if dep_fail:
        return std(False, "DEPENDENT_START_FAILED",
                   f"{name} yeniden başladı ama bağımlı servisler başlamadı: {', '.join(dep_fail)}",
                   steps, service=name, dependents=deps)
    verb = "başlatıldı" if initial == SVC_STOPPED else "yeniden başlatıldı"
    return std(True, "RESTARTED", f"{name} {verb}" + (f" (+{len(deps)} bağımlı)" if deps else ""),
               steps, service=name, dependents=deps)


# ---------------------------------------------------------------- logoff
def _user_of(s: dict) -> str:
    return (s.get("username") or "").strip()


def _match_user(target: str, s: dict) -> bool:
    t = (target or "").strip().lower()
    if not t:
        return False
    u = _user_of(s).lower()
    dom = (s.get("domain") or "").strip().lower()
    if "\\" in t:
        td, tu = t.rsplit("\\", 1)
        return tu == u and (not dom or td == dom)
    return t == u


def logoff_session(target, *, wts, protected_ids: Iterable[int] = (0,),
                   exclude_ids: Iterable[int] = (), exclude_users: Iterable[str] = (),
                   include_console: bool = True, verify_timeout: float = 20.0,
                   sleep: Callable = time.sleep, clock: Callable = time.monotonic) -> dict:
    """target: int session id | "all" | {"username": ...} handled by caller → str user."""
    prot = {int(x) for x in protected_ids}
    try:
        sessions = list(wts.enumerate())
    except Exception as e:
        return std(False, "ENUM_FAILED", f"Oturumlar okunamadı: {e}")
    live = [s for s in sessions if _user_of(s) and s.get("state") != "Listen"]
    ex_ids = {int(x) for x in exclude_ids if str(x).strip().lstrip("-").isdigit()}
    ex_users = {str(u).strip().lower() for u in exclude_users if str(u).strip()}
    steps: List[dict] = []
    ids: List[int] = []
    mode = "all" if str(target).strip().lower() == "all" else None
    if mode == "all":
        for s in live:
            sid = int(s["session_id"])
            if sid in prot:
                continue
            if sid in ex_ids or _user_of(s).lower() in ex_users:
                steps.append(step("skip", True, "excluded", session_id=sid, username=_user_of(s)))
                continue
            if not include_console and (s.get("station") or "").lower() == "console":
                steps.append(step("skip", True, "console", session_id=sid, username=_user_of(s)))
                continue
            ids.append(sid)
    else:
        try:
            ids = [int(target)]
        except (TypeError, ValueError):
            ids = [int(s["session_id"]) for s in live if _match_user(str(target), s)]
            if not ids:
                return std(False, "NO_SESSION", f"{target} için açık oturum yok", steps)
    if not ids:
        return std(True, "NO_SESSIONS", "Kapatılacak kullanıcı oturumu yok", steps, sessions=[])
    by_id = {int(s["session_id"]): s for s in sessions}
    requested = []
    for sid in ids:
        if sid in prot:
            steps.append(step("logoff", False, "protected_session", session_id=sid))
            continue
        if sid not in by_id:
            steps.append(step("logoff", False, "session_not_found", session_id=sid))
            continue
        try:
            wts.logoff(sid)
            requested.append(sid)
            steps.append(step("logoff", True, "requested", session_id=sid,
                              username=_user_of(by_id[sid])))
        except Exception as e:
            steps.append(step("logoff", False, str(e), session_id=sid, username=_user_of(by_id[sid])))
    # verify: session gone or no user attached
    remaining = set(requested)
    end = clock() + verify_timeout
    while remaining and clock() < end:
        try:
            now = {int(s["session_id"]): s for s in wts.enumerate()}
        except Exception:
            now = {}
        remaining = {sid for sid in remaining if sid in now and _user_of(now[sid])}
        if remaining:
            sleep(1.0)
    for sid in requested:
        steps.append(step("verify", sid not in remaining, "still_present" if sid in remaining else "gone",
                          session_id=sid))
    failed = [s for s in steps if s["step"] in ("logoff", "verify") and not s["ok"]]
    done = [sid for sid in requested if sid not in remaining]
    if failed:
        return std(False, "LOGOFF_FAILED" if not done else "LOGOFF_PARTIAL",
                   f"Kapatılamayan oturum var (kapanan: {done or '-'})", steps, sessions=done)
    return std(True, "LOGGED_OFF", f"{len(done)} oturum kapatıldı: {done}", steps, sessions=done)


# ---------------------------------------------------------------- reboot
def _marker_path() -> str:
    base = os.environ.get("ProgramData") or r"C:\ProgramData"
    return os.path.join(base, "Asteria", "reboot_pending.json")


def _boot_time() -> float:
    try:
        import psutil
        return float(psutil.boot_time())
    except Exception:
        return 0.0


def schedule_reboot(grace_sec: int = 30, reason: str = "", *, command_id: str = "",
                    runner: Callable = subprocess.run, marker_path: Optional[str] = None,
                    boot_time: Callable = _boot_time) -> dict:
    try:
        grace = max(0, min(600, int(grace_sec)))
    except (TypeError, ValueError):
        grace = 30
    reason = (reason or "Asteria dashboard reboot")[:120]
    try:
        r = runner([system32("shutdown.exe"), "/r", "/t", str(grace), "/c", reason, "/d", "p:0:0"],
                   capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW)
    except Exception as e:
        return std(False, "SHUTDOWN_EXEC_FAILED", f"shutdown.exe çalıştırılamadı: {e}")
    out = ((r.stderr or "") + " " + (r.stdout or "")).strip()
    if r.returncode != 0:
        if r.returncode == 1190 or "1190" in out:
            return std(False, "ALREADY_SCHEDULED", "Zaten planlanmış bir kapatma/yeniden başlatma var",
                       [step("shutdown", False, out, rc=r.returncode)])
        code = "ACCESS_DENIED" if r.returncode == 5 else "SHUTDOWN_FAILED"
        return std(False, code, f"Yeniden başlatma planlanamadı (rc={r.returncode}) {out}"[:240],
                   [step("shutdown", False, out, rc=r.returncode)])
    steps = [step("shutdown", True, f"/r /t {grace}")]
    try:
        mp = marker_path or _marker_path()
        os.makedirs(os.path.dirname(mp), exist_ok=True)
        with open(mp, "w", encoding="utf-8") as f:
            json.dump({"command_id": command_id, "boot_time_before": boot_time(),
                       "requested_at": time.time(), "grace_sec": grace}, f)
        steps.append(step("marker", True))
    except Exception as e:
        steps.append(step("marker", False, str(e)))
    return std(True, "SCHEDULED", f"Yeniden başlatma {grace} sn sonra", steps,
               grace_sec=grace, reason=reason, phase="scheduled")


def consume_reboot_marker(marker_path: Optional[str] = None, boot_time: Callable = _boot_time) -> Optional[dict]:
    """On startup: if a dashboard reboot was pending and the host booted since → info dict."""
    mp = marker_path or _marker_path()
    try:
        with open(mp, "r", encoding="utf-8") as f:
            info = json.load(f)
    except Exception:
        return None
    before = float(info.get("boot_time_before") or 0)
    now_boot = boot_time()
    rebooted = bool(now_boot and before and now_boot > before + 5)
    age = time.time() - float(info.get("requested_at") or 0)
    if not rebooted and age < 3600:
        return None  # still waiting for the reboot (agent restarted for another reason)
    try:
        os.remove(mp)
    except Exception:
        pass
    info["rebooted"] = rebooted
    info["boot_time"] = now_boot
    return info
