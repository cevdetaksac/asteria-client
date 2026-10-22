"""Process containment + host isolation (contract features/containment.md)."""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import threading
import time
import uuid
from typing import List, Optional
from urllib.parse import urlparse

from client_admin_ops import CREATE_NO_WINDOW, std, step, system32, _start_time_epoch

_isolate_timer = None
_isolate_lock = threading.Lock()
_ISOLATE_RULE_PREFIX = "AR-ISOLATE-"


def _contain_dir() -> str:
    base = os.environ.get("ProgramData") or r"C:\ProgramData"
    path = os.path.join(base, "Asteria", "containment")
    os.makedirs(path, exist_ok=True)
    return path


def _save_state(undo_id: str, data: dict) -> str:
    path = os.path.join(_contain_dir(), f"{undo_id}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return path


def _load_state(undo_id: str) -> Optional[dict]:
    path = os.path.join(_contain_dir(), f"{undo_id}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _drop_state(undo_id: str) -> None:
    try:
        os.remove(os.path.join(_contain_dir(), f"{undo_id}.json"))
    except Exception:
        pass


def _run(cmd, timeout=20):
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )


def resolve_asteria_remotes() -> List[str]:
    hosts = ["asteria.run", "www.asteria.run"]
    try:
        from client_constants import LEGITIMATE_DOMAINS, API_URL
        h = urlparse(API_URL or "").hostname
        hosts = [x for x in [h] + list(LEGITIMATE_DOMAINS) + hosts if x]
        # unique preserve order
        seen = set()
        hosts = [x for x in hosts if not (x in seen or seen.add(x))]
    except Exception:
        pass
    ips = set()
    for h in hosts:
        try:
            for _fam, _, _, _, sa in socket.getaddrinfo(h, None):
                ip = sa[0]
                if ":" not in ip:
                    ips.add(ip)
        except Exception:
            continue
    return sorted(ips)


def block_process_ifeo(image: str) -> dict:
    image = os.path.basename(image or "").strip()
    if not image:
        return std(False, "MISSING_IMAGE", "exe adi gerekli")
    if not image.lower().endswith(".exe"):
        image = image + ".exe"
    try:
        import winreg
        key_path = (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\"
            + image
        )
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "Debugger", 0, winreg.REG_SZ, "nyan")
        return std(True, "IFE_BLOCKED", f"IFEO engeli: {image}",
                   [step("ifeo", True, image=image)], image=image)
    except PermissionError:
        return std(False, "ACCESS_DENIED", "IFEO icin yonetici gerekli", image=image)
    except Exception as e:
        return std(False, "IFE_FAILED", str(e)[:200], image=image)


def unblock_process_ifeo(image: str) -> dict:
    image = os.path.basename(image or "").strip()
    if not image:
        return std(False, "MISSING_IMAGE", "exe adi gerekli")
    if not image.lower().endswith(".exe"):
        image = image + ".exe"
    try:
        import winreg
        key_path = (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\"
            + image
        )
        try:
            with winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as k:
                try:
                    winreg.DeleteValue(k, "Debugger")
                except FileNotFoundError:
                    pass
            try:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            except OSError:
                pass
        except FileNotFoundError:
            return std(True, "IFE_GONE", f"IFEO yoktu: {image}",
                       [step("ifeo_clear", True, "already_gone")], image=image)
        return std(True, "IFE_CLEARED", f"IFEO kaldirildi: {image}",
                   [step("ifeo_clear", True)], image=image)
    except PermissionError:
        return std(False, "ACCESS_DENIED", "IFEO kaldirma icin yonetici gerekli", image=image)
    except Exception as e:
        return std(False, "IFE_CLEAR_FAILED", str(e)[:200], image=image)


def suspend_process(pid, *, expected_image: str = "", process_start_time=None,
                    protected_names=(), protected_pids=(), psutil_mod=None) -> dict:
    try:
        ps = psutil_mod
        if ps is None:
            import psutil as ps
    except Exception as e:
        return std(False, "API_UNAVAILABLE", str(e))
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return std(False, "INVALID_TARGET", "PID gerekli")
    if pid in (0, 4) or pid in {int(x) for x in protected_pids}:
        return std(False, "PROTECTED_PROCESS", f"Korunan surec PID {pid}", pid=pid)
    try:
        p = ps.Process(pid)
        name = p.name() or ""
        try:
            path = p.exe() or ""
        except Exception:
            path = ""
        created = float(p.create_time())
    except Exception as e:
        if "NoSuchProcess" in type(e).__name__:
            return std(False, "PROCESS_GONE", f"Surec yok (PID {pid})", pid=pid)
        return std(False, "ACCESS_DENIED", str(e)[:200], pid=pid)
    exp = (expected_image or "").strip().lower()
    if exp and exp != name.lower():
        return std(False, "STALE_TARGET", f"PID {pid} artik {name}", pid=pid, found_image=name)
    st = _start_time_epoch(process_start_time)
    if st is not None and abs(created - st) > 2.0:
        return std(False, "STALE_TARGET", "PID yeniden kullanilmis", pid=pid)
    if name.lower() in {str(x).lower() for x in protected_names}:
        return std(False, "PROTECTED_PROCESS", f"Korunan: {name}", pid=pid)
    try:
        p.suspend()
    except Exception as e:
        return std(False, "SUSPEND_FAILED", str(e)[:200], pid=pid, image=name)
    return std(True, "SUSPENDED", f"{name} (PID {pid}) donduruldu",
               [step("suspend", True)], pid=pid, image=name, path=path,
               process_start_time=created, state="suspended")


def resume_process(pid, *, expected_image: str = "", process_start_time=None,
                   protected_names=(), protected_pids=(), psutil_mod=None) -> dict:
    try:
        ps = psutil_mod
        if ps is None:
            import psutil as ps
    except Exception as e:
        return std(False, "API_UNAVAILABLE", str(e))
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return std(False, "INVALID_TARGET", "PID gerekli")
    try:
        p = ps.Process(pid)
        name = p.name() or ""
        try:
            path = p.exe() or ""
        except Exception:
            path = ""
    except Exception as e:
        if "NoSuchProcess" in type(e).__name__:
            return std(False, "PROCESS_GONE", f"Surec yok (PID {pid})", pid=pid)
        return std(False, "ACCESS_DENIED", str(e)[:200], pid=pid)
    exp = (expected_image or "").strip().lower()
    if exp and exp != name.lower():
        return std(False, "STALE_TARGET", f"PID {pid} artik {name}", pid=pid)
    try:
        p.resume()
    except Exception as e:
        return std(False, "RESUME_FAILED", str(e)[:200], pid=pid, image=name)
    return std(True, "RESUMED", f"{name} (PID {pid}) surduruldu",
               [step("resume", True)], pid=pid, image=name, path=path, state="running")


def find_persistence(exe_path: str, image: str) -> dict:
    image_l = (image or os.path.basename(exe_path or "")).lower()
    path_l = (exe_path or "").lower()
    services, tasks, run_keys = [], [], []
    try:
        ps = (
            "Get-CimInstance Win32_Service | "
            "Select-Object Name,StartMode,State,PathName | ConvertTo-Json -Compress"
        )
        r = _run([
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                         r"System32\WindowsPowerShell\v1.0\powershell.exe"),
            "-NoProfile", "-Command", ps,
        ], timeout=45)
        if r.returncode == 0 and (r.stdout or "").strip():
            data = json.loads(r.stdout)
            if isinstance(data, dict):
                data = [data]
            for s in data or []:
                pn = (s.get("PathName") or "").lower()
                if (image_l and image_l in pn) or (path_l and path_l in pn):
                    services.append({
                        "name": s.get("Name"),
                        "start_mode": s.get("StartMode"),
                        "state": s.get("State"),
                        "path": s.get("PathName"),
                    })
    except Exception:
        pass
    try:
        r = _run([system32("schtasks.exe"), "/query", "/fo", "LIST", "/v"], timeout=60)
        cur = {}
        def _flush():
            nonlocal cur
            if not cur:
                return
            tr = (cur.get("task_to_run") or "").lower()
            tn = cur.get("task_name") or ""
            if (image_l and image_l in tr) or (path_l and path_l in tr):
                tasks.append({"name": tn.strip(), "task_to_run": cur.get("task_to_run") or ""})
            cur = {}
        for line in (r.stdout or "").splitlines():
            if not line.strip():
                _flush()
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                cur[k.strip().lower().replace(" ", "_")] = v.strip()
        _flush()
    except Exception:
        pass
    try:
        import winreg
        for root, hive_name in (
            (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
            (winreg.HKEY_CURRENT_USER, "HKCU"),
        ):
            for sub in (
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            ):
                try:
                    with winreg.OpenKeyEx(root, sub, 0, winreg.KEY_READ) as k:
                        i = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(k, i)
                            except OSError:
                                break
                            i += 1
                            vl = str(val or "").lower()
                            if (image_l and image_l in vl) or (path_l and path_l in vl):
                                run_keys.append({
                                    "hive": hive_name, "key": sub,
                                    "name": name, "value": str(val),
                                })
                except OSError:
                    continue
    except Exception:
        pass
    return {"services": services, "tasks": tasks, "run_keys": run_keys}


def _disable_persistence(pers: dict, steps: list) -> dict:
    undone = {"services": [], "tasks": [], "run_keys": []}
    for s in pers.get("services") or []:
        name = s.get("name")
        if not name:
            continue
        entry = {"name": name, "start_mode": s.get("start_mode") or "Demand"}
        try:
            from client_admin_ops import Win32Svc, SVC_STOPPED, _wait_state
            svc = Win32Svc()
            try:
                svc.stop(name)
                _wait_state(svc, name, SVC_STOPPED, 30)
            except Exception:
                pass
            r = _run([system32("sc.exe"), "config", name, "start=", "disabled"], timeout=15)
            ok = r.returncode == 0
            steps.append(step("disable_service", ok, name=name))
            if ok:
                undone["services"].append(entry)
        except Exception as e:
            steps.append(step("disable_service", False, str(e), name=name))
    for t in pers.get("tasks") or []:
        name = (t.get("name") or "").lstrip("\\")
        if not name:
            continue
        r = _run([system32("schtasks.exe"), "/change", "/tn", name, "/disable"], timeout=20)
        ok = r.returncode == 0
        steps.append(step("disable_task", ok, name=name))
        if ok:
            undone["tasks"].append({"name": name})
    try:
        import winreg
        roots = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
        for rk in pers.get("run_keys") or []:
            try:
                with winreg.OpenKeyEx(roots[rk["hive"]], rk["key"], 0, winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, rk["name"])
                steps.append(step("remove_run", True, name=rk["name"], hive=rk["hive"]))
                undone["run_keys"].append(rk)
            except Exception as e:
                steps.append(step("remove_run", False, str(e), name=rk.get("name")))
    except Exception as e:
        steps.append(step("remove_run", False, str(e)))
    return undone


def _restore_persistence(undone: dict, steps: list) -> None:
    start_map = {
        "auto": "auto", "automatic": "auto", "demand": "demand",
        "manual": "demand", "disabled": "disabled", "boot": "boot", "system": "system",
    }
    for s in undone.get("services") or []:
        name = s.get("name")
        mode = start_map.get(str(s.get("start_mode") or "demand").lower(), "demand")
        r = _run([system32("sc.exe"), "config", name, "start=", mode], timeout=15)
        steps.append(step("restore_service", r.returncode == 0, name=name, mode=mode))
        try:
            from client_admin_ops import Win32Svc
            Win32Svc().start(name)
            steps.append(step("start_service", True, name=name))
        except Exception as e:
            steps.append(step("start_service", False, str(e), name=name))
    for t in undone.get("tasks") or []:
        name = t.get("name")
        r = _run([system32("schtasks.exe"), "/change", "/tn", name, "/enable"], timeout=20)
        steps.append(step("enable_task", r.returncode == 0, name=name))
    try:
        import winreg
        roots = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
        for rk in undone.get("run_keys") or []:
            try:
                with winreg.CreateKeyEx(roots[rk["hive"]], rk["key"], 0, winreg.KEY_SET_VALUE) as k:
                    winreg.SetValueEx(k, rk["name"], 0, winreg.REG_SZ, rk["value"])
                steps.append(step("restore_run", True, name=rk["name"]))
            except Exception as e:
                steps.append(step("restore_run", False, str(e)))
    except Exception as e:
        steps.append(step("restore_run", False, str(e)))


def _fw_add_out_block(program: str, rule_name: str) -> dict:
    from client_firewall_inventory import firewall_rule
    return firewall_rule({
        "op": "add", "name": rule_name, "direction": "Out", "action": "Block",
        "program": program, "enable": True, "profile": "any",
        "description": "Asteria contain_process outbound block",
    })


def _fw_delete(rule_name: str, direction: str = "Out") -> dict:
    from client_firewall_inventory import firewall_rule
    return firewall_rule({"op": "delete", "name": rule_name, "direction": direction})


def contain_process(pid, *, expected_image: str = "", process_start_time=None,
                    net_block: bool = True, persistence: bool = True, suspend: bool = True,
                    ifeo: bool = False, dry_run: bool = False,
                    protected_names=(), protected_pids=(), psutil_mod=None) -> dict:
    steps = []
    if suspend:
        sus = suspend_process(
            pid, expected_image=expected_image, process_start_time=process_start_time,
            protected_names=protected_names, protected_pids=protected_pids, psutil_mod=psutil_mod,
        )
    else:
        sus = std(True, "SKIP_SUSPEND", "skip")
    if suspend and not sus.get("ok") and sus.get("code") in (
        "STALE_TARGET", "PROTECTED_PROCESS", "INVALID_TARGET", "MISSING_IMAGE",
    ):
        return sus
    steps.extend(sus.get("steps") or [])
    data = sus.get("data") or {}
    image = data.get("image") or expected_image or ""
    path = data.get("path") or ""
    if not path and pid not in (None, ""):
        try:
            import psutil
            path = psutil.Process(int(pid)).exe() or ""
        except Exception:
            pass
    if not image and path:
        image = os.path.basename(path)
    if image and image.lower() in {str(x).lower() for x in protected_names}:
        if suspend and sus.get("ok"):
            resume_process(pid, expected_image=image)
        return std(False, "PROTECTED_PROCESS", f"Korunan: {image}", steps)

    pers = find_persistence(path, image) if persistence else {
        "services": [], "tasks": [], "run_keys": [],
    }
    steps.append(step(
        "discover_persistence", True,
        f"svc={len(pers['services'])} task={len(pers['tasks'])} run={len(pers['run_keys'])}",
    ))
    if dry_run:
        return std(True, "DRY_RUN", "contain_process plan", steps,
                   pid=pid, image=image, path=path, persistence=pers,
                   would_suspend=bool(suspend), would_net_block=bool(net_block and path),
                   would_ifeo=bool(ifeo))

    undo_id = str(uuid.uuid4())
    rule_name = f"AR-CONTAIN-{undo_id[:8]}"
    if net_block and path:
        fw = _fw_add_out_block(path, rule_name)
        steps.append(step("outbound_block", bool(fw.get("ok")),
                          fw.get("message") or fw.get("error"), rule=rule_name, program=path))
        if not fw.get("ok"):
            if suspend and sus.get("ok"):
                resume_process(pid, expected_image=image)
            return std(False, "NET_BLOCK_FAILED", fw.get("message") or "outbound block failed",
                       steps, pid=pid, image=image)
    else:
        rule_name = None

    undone_pers = _disable_persistence(pers, steps) if persistence else {}
    ifeo_state = None
    if ifeo and image:
        br = block_process_ifeo(image)
        steps.extend(br.get("steps") or [])
        ifeo_state = image if br.get("ok") else None

    state = {
        "kind": "contain_process", "undo_id": undo_id, "created_at": time.time(),
        "pid": int(pid) if pid not in (None, "") else None,
        "image": image, "path": path,
        "process_start_time": data.get("process_start_time"),
        "suspended": bool(suspend and sus.get("ok")),
        "rule_name": rule_name, "persistence": undone_pers, "ifeo_image": ifeo_state,
    }
    _save_state(undo_id, state)
    return std(True, "CONTAINED", f"{image or pid} izole edildi (undo_id={undo_id[:8]})",
               steps, undo_id=undo_id, pid=pid, image=image, path=path,
               rule_name=rule_name, persistence=undone_pers)


def release_process(undo_id: str = "", **kwargs) -> dict:
    undo_id = (undo_id or kwargs.get("undo_id") or "").strip()
    if not undo_id:
        return std(False, "MISSING_UNDO_ID", "undo_id gerekli")
    state = _load_state(undo_id)
    if not state or state.get("kind") != "contain_process":
        return std(False, "UNDO_NOT_FOUND", f"contain kaydi yok: {undo_id}")
    steps = []
    if state.get("suspended") and state.get("pid"):
        r = resume_process(state["pid"], expected_image=state.get("image") or "",
                           process_start_time=state.get("process_start_time"))
        steps.extend(r.get("steps") or [step("resume", r.get("ok"), r.get("message"))])
    if state.get("rule_name"):
        fw = _fw_delete(state["rule_name"])
        steps.append(step("outbound_unblock", bool(fw.get("ok")),
                          fw.get("message") or fw.get("error"), rule=state["rule_name"]))
    _restore_persistence(state.get("persistence") or {}, steps)
    if state.get("ifeo_image"):
        u = unblock_process_ifeo(state["ifeo_image"])
        steps.extend(u.get("steps") or [])
    _drop_state(undo_id)
    return std(True, "RELEASED", f"contain geri alindi ({undo_id[:8]})",
               steps, undo_id=undo_id)


def isolate_host(*, management_ip: str = "", dead_man_minutes: int = 15,
                 dry_run: bool = False, dns_servers: Optional[List[str]] = None) -> dict:
    import ipaddress
    mip = (management_ip or "").strip()
    if mip:
        try:
            ipaddress.ip_address(mip)
        except ValueError:
            return std(False, "INVALID_IP", "management_ip gecersiz")
    cloud_ips = resolve_asteria_remotes()
    dns = list(dns_servers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    steps = [step("resolve_cloud", True, ",".join(cloud_ips) or "none")]
    if not cloud_ips and not dry_run:
        return std(False, "NO_CLOUD_IPS",
                   "Asteria IP cozulemedi — izolasyon reddedildi (agent kesilmesin)", steps)
    plan = {
        "allow_cloud": cloud_ips, "allow_dns": dns,
        "management_ip": mip or None,
        "dead_man_minutes": max(5, min(120, int(dead_man_minutes or 15))),
    }
    if dry_run:
        return std(True, "DRY_RUN", "isolate_host plan", steps, **plan)

    undo_id = str(uuid.uuid4())
    rules = []
    from client_firewall_inventory import firewall_rule

    def add(name, **kw):
        r = firewall_rule({"op": "add", "name": name, **kw})
        ok = bool(r.get("ok"))
        steps.append(step("fw_add", ok, r.get("message") or r.get("error"), rule=name))
        if ok:
            rules.append({"name": name, "direction": kw.get("direction", "Out")})
        return ok

    for i, ip in enumerate(cloud_ips):
        add(f"{_ISOLATE_RULE_PREFIX}{undo_id[:8]}-cloud-out-{i}",
            direction="Out", action="Allow", remote_address=ip, enable=True, profile="any",
            description="Asteria cloud allow")
        add(f"{_ISOLATE_RULE_PREFIX}{undo_id[:8]}-cloud-in-{i}",
            direction="In", action="Allow", remote_address=ip, enable=True, profile="any",
            description="Asteria cloud allow in")
    for i, dip in enumerate(dns):
        add(f"{_ISOLATE_RULE_PREFIX}{undo_id[:8]}-dns-{i}",
            direction="Out", action="Allow", remote_address=dip, protocol="UDP",
            remote_port="53", enable=True, profile="any")
        add(f"{_ISOLATE_RULE_PREFIX}{undo_id[:8]}-dns-tcp-{i}",
            direction="Out", action="Allow", remote_address=dip, protocol="TCP",
            remote_port="53", enable=True, profile="any")
    if mip:
        add(f"{_ISOLATE_RULE_PREFIX}{undo_id[:8]}-mgmt-in",
            direction="In", action="Allow", remote_address=mip, enable=True, profile="any")
        add(f"{_ISOLATE_RULE_PREFIX}{undo_id[:8]}-mgmt-out",
            direction="Out", action="Allow", remote_address=mip, enable=True, profile="any")
    add(f"{_ISOLATE_RULE_PREFIX}{undo_id[:8]}-block-out",
        direction="Out", action="Block", enable=True, profile="any",
        description="Asteria isolate catch-all out")
    add(f"{_ISOLATE_RULE_PREFIX}{undo_id[:8]}-block-in",
        direction="In", action="Block", enable=True, profile="any",
        description="Asteria isolate catch-all in")

    state = {
        "kind": "isolate_host", "undo_id": undo_id, "created_at": time.time(),
        "rules": rules, "management_ip": mip, "cloud_ips": cloud_ips,
        "dead_man_minutes": plan["dead_man_minutes"], "last_cloud_ok_at": time.time(),
    }
    _save_state(undo_id, state)
    _save_state("ISOLATE_ACTIVE", {"undo_id": undo_id})
    _arm_dead_man(undo_id, plan["dead_man_minutes"])
    return std(True, "ISOLATED",
               f"Host izole (undo_id={undo_id[:8]}, dead-man {plan['dead_man_minutes']}dk)",
               steps, undo_id=undo_id, **plan)


def lift_isolation(undo_id: str = "", **kwargs) -> dict:
    undo_id = (undo_id or kwargs.get("undo_id") or "").strip()
    if not undo_id:
        undo_id = ((_load_state("ISOLATE_ACTIVE") or {}).get("undo_id") or "").strip()
    if not undo_id:
        return std(False, "NOT_ISOLATED", "Aktif izolasyon yok")
    state = _load_state(undo_id)
    if not state or state.get("kind") != "isolate_host":
        return std(False, "UNDO_NOT_FOUND", f"isolate kaydi yok: {undo_id}")
    steps = []
    from client_firewall_inventory import firewall_rule
    for r in state.get("rules") or []:
        res = firewall_rule({"op": "delete", "name": r["name"], "direction": r.get("direction")})
        steps.append(step("fw_del", bool(res.get("ok")),
                          res.get("message") or res.get("error"), rule=r["name"]))
    _drop_state(undo_id)
    _drop_state("ISOLATE_ACTIVE")
    _cancel_dead_man()
    return std(True, "ISOLATION_LIFTED", f"Izolasyon kaldirildi ({undo_id[:8]})",
               steps, undo_id=undo_id)


def _cancel_dead_man():
    global _isolate_timer
    with _isolate_lock:
        t = _isolate_timer
        _isolate_timer = None
    if t:
        try:
            t.cancel()
        except Exception:
            pass


def _arm_dead_man(undo_id: str, minutes: int):
    global _isolate_timer
    _cancel_dead_man()
    interval = 60.0

    def tick():
        global _isolate_timer
        active = _load_state("ISOLATE_ACTIVE") or {}
        if active.get("undo_id") != undo_id:
            return
        ok = _cloud_reachable()
        st = _load_state(undo_id) or {}
        if ok:
            st["last_cloud_ok_at"] = time.time()
            _save_state(undo_id, st)
        else:
            last = float(st.get("last_cloud_ok_at") or st.get("created_at") or 0)
            if time.time() - last >= max(5, minutes) * 60:
                try:
                    from client_helpers import log
                    log(f"[CONTAIN] dead-man lift isolate undo_id={undo_id[:8]}")
                except Exception:
                    pass
                lift_isolation(undo_id)
                return
        with _isolate_lock:
            _isolate_timer = threading.Timer(interval, tick)
            _isolate_timer.daemon = True
            _isolate_timer.start()

    with _isolate_lock:
        _isolate_timer = threading.Timer(interval, tick)
        _isolate_timer.daemon = True
        _isolate_timer.start()


def _cloud_reachable() -> bool:
    try:
        from client_constants import API_URL
        host = urlparse(API_URL or "https://asteria.run/api").hostname or "asteria.run"
    except Exception:
        host = "asteria.run"
    try:
        sock = socket.create_connection((host, 443), timeout=5)
        sock.close()
        return True
    except Exception:
        return False


def resume_dead_man_if_needed():
    active = _load_state("ISOLATE_ACTIVE") or {}
    uid = active.get("undo_id")
    if not uid:
        return
    st = _load_state(uid) or {}
    if st.get("kind") == "isolate_host":
        _arm_dead_man(uid, int(st.get("dead_man_minutes") or 15))


def delete_user(username: str, net=None) -> dict:
    username = (username or "").strip()
    if not username:
        return std(False, "MISSING_USERNAME", "Kullanici adi gerekli")
    try:
        from client_admin_ops import Win32Net, _net_err
        (net or Win32Net()).delete_user(username)
        return std(True, "USER_DELETED", f"{username} silindi",
                   [step("delete", True)], username=username)
    except Exception as e:
        from client_admin_ops import _net_err
        code, msg = _net_err(e, "DELETE_FAILED")
        return std(False, code, msg, [step("delete", False, msg)], username=username)


def disable_service(name: str, *, protected=(), stop_first: bool = True) -> dict:
    from client_admin_ops import Win32Svc, SVC_STOPPED, _wait_state
    name = (name or "").strip()
    if not name:
        return std(False, "MISSING_SERVICE", "Servis adi gerekli")
    if name.lower() in {str(x).lower() for x in protected}:
        return std(False, "PROTECTED_SERVICE", f"Korunan servis: {name}", service=name)
    steps = []
    try:
        svc = Win32Svc()
        prev = "demand"
        r = _run([system32("sc.exe"), "qc", name], timeout=15)
        m = re.search(r"START_TYPE\s*:\s*\d+\s+(\w+)", r.stdout or "", re.I)
        if m:
            prev = m.group(1).lower()
        if stop_first:
            try:
                svc.stop(name)
                st = _wait_state(svc, name, SVC_STOPPED, 30)
                steps.append(step("stop", st == SVC_STOPPED, str(st)))
            except Exception as e:
                steps.append(step("stop", False, str(e)))
        r2 = _run([system32("sc.exe"), "config", name, "start=", "disabled"], timeout=15)
        ok = r2.returncode == 0
        steps.append(step("disable", ok, (r2.stderr or r2.stdout or "")[:120]))
        if not ok:
            return std(False, "DISABLE_FAILED", f"{name} disable edilemedi", steps, service=name)
        undo_id = str(uuid.uuid4())
        _save_state(undo_id, {
            "kind": "disable_service", "name": name, "start_mode": prev, "undo_id": undo_id,
        })
        return std(True, "SERVICE_DISABLED", f"{name} disabled (onceki: {prev})",
                   steps, service=name, previous_start=prev, undo_id=undo_id)
    except Exception as e:
        return std(False, "DISABLE_FAILED", str(e)[:200], steps, service=name)


def enable_service_undo(undo_id: str = "", name: str = "", start_mode: str = "demand") -> dict:
    st = _load_state(undo_id) if undo_id else None
    if st and st.get("kind") == "disable_service":
        name = st.get("name") or name
        start_mode = st.get("start_mode") or start_mode
    name = (name or "").strip()
    if not name:
        return std(False, "MISSING_SERVICE", "Servis adi veya undo_id gerekli")
    start_map = {
        "auto": "auto", "automatic": "auto", "demand": "demand", "manual": "demand",
        "disabled": "demand", "boot": "boot", "system": "system",
    }
    mode = start_map.get(str(start_mode).lower(), "demand")
    r = _run([system32("sc.exe"), "config", name, "start=", mode], timeout=15)
    steps = [step("restore_start", r.returncode == 0, mode=mode)]
    try:
        from client_admin_ops import Win32Svc
        Win32Svc().start(name)
        steps.append(step("start", True))
    except Exception as e:
        steps.append(step("start", False, str(e)))
    if undo_id:
        _drop_state(undo_id)
    ok = r.returncode == 0
    return std(ok, "SERVICE_RESTORED" if ok else "RESTORE_FAILED",
               f"{name} start={mode}", steps, service=name)


def disable_account(username: str) -> dict:
    username = (username or "").strip()
    if not username:
        return std(False, "MISSING_USERNAME", "Kullanici adi gerekli")
    r = _run([system32("net.exe"), "user", username, "/active:no"], timeout=15)
    ok = r.returncode == 0
    msg = (r.stderr or r.stdout or "").strip()
    return std(ok, "ACCOUNT_DISABLED" if ok else "DISABLE_FAILED",
               msg or (f"{username} pasif" if ok else "failed"),
               [step("disable", ok)], username=username)


def enable_account(username: str) -> dict:
    username = (username or "").strip()
    if not username:
        return std(False, "MISSING_USERNAME", "Kullanici adi gerekli")
    r = _run([system32("net.exe"), "user", username, "/active:yes"], timeout=15)
    ok = r.returncode == 0
    msg = (r.stderr or r.stdout or "").strip()
    return std(ok, "ACCOUNT_ENABLED" if ok else "ENABLE_FAILED",
               msg or (f"{username} aktif" if ok else "failed"),
               [step("enable", ok)], username=username)


def reset_password(username: str, new_password: str) -> dict:
    username = (username or "").strip()
    if not username:
        return std(False, "MISSING_USERNAME", "Kullanici adi gerekli")
    if not new_password or len(str(new_password)) < 8:
        return std(False, "PASSWORD_TOO_SHORT", "Sifre en az 8 karakter", username=username)
    r = _run([system32("net.exe"), "user", username, str(new_password)], timeout=15)
    if r.returncode == 0:
        return std(True, "PASSWORD_RESET", f"{username} sifresi sifirlandi",
                   [step("reset_password", True)], username=username)
    try:
        from client_admin_ops import Win32Net, _net_err
        import win32net
        info = win32net.NetUserGetInfo(None, username, 1)
        Win32Net().reset_user(username, str(new_password), int(info.get("flags") or 0))
        return std(True, "PASSWORD_RESET", f"{username} sifresi sifirlandi",
                   [step("reset_password", True)], username=username)
    except Exception as e:
        from client_admin_ops import _net_err
        code, msg = _net_err(e, "RESET_FAILED")
        return std(False, code, msg or (r.stderr or r.stdout or "")[:200],
                   [step("reset_password", False)], username=username)
