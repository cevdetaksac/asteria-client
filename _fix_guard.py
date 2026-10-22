from pathlib import Path
p = Path("client_firewall_inventory.py")
s = p.read_text(encoding="utf-8")
old = '''    # RDP inbound allow — don't disable/delete the last allow, don't drop mgmt IP
    is_rdp = ("3389" in lp) or ("remote desktop" in name.lower()) or name.lower().startswith("ar-port-3389")
    if is_rdp and op in ("disable", "delete"):
        if not (force and confirm_name):
            return {
                "ok": False, "error": "GUARD_RDP",
                "code": "GUARD_RDP",
                "message": "Refusing to disable/delete an RDP allow rule "
                           "(override: force+confirm_name matching server)",
            }
    if is_rdp and op == "edit" and rem:
'''
new = '''    # RDP inbound allow — only when the rule actually targets the RDP listen port.
    if not lp and name:
        try:
            resolved = next(
                (r for r in (_enumerate_rules(direction)[1] or [])
                 if (r.get("name") or "") == name),
                None,
            )
            if resolved:
                lp = str(resolved.get("local_port") or "")
        except Exception:
            pass
    try:
        from client_netports import listen_port_for
        rdp_port = str(listen_port_for("RDP") or 3389)
    except Exception:
        rdp_port = "3389"
    ports = {x.strip() for x in lp.split(",") if x.strip()}
    is_rdp = (rdp_port in ports) or name.lower().startswith(f"ar-port-{rdp_port}")
    if is_rdp and op in ("disable", "delete"):
        if not (force and confirm_name):
            return {
                "ok": False, "error": "GUARD_RDP",
                "code": "GUARD_RDP",
                "message": "Refusing to disable/delete an RDP allow rule "
                           "(override: force+confirm_name matching server)",
            }
    if is_rdp and op == "edit" and rem:
'''
if old not in s:
    raise SystemExit("block not found")
p.write_text(s.replace(old, new), encoding="utf-8")
print("patched")
