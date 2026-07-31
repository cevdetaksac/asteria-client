# Asteria Client 4.9.71 — Fix `launch_helper_failed` / `stage_helper`

## Why
Hosts on **4.9.68** (and earlier) showed:

`Güncelleme başarısız · 4.9.68 → 4.9.70 · launch_helper_failed`

`%ProgramData%\Asteria\update-install.log` repeated:

`launch_helper_failed detail=stage_helper`

Root cause: `_harden_update_staging` stripped **BUILTIN\Users** from
`%ProgramData%\Asteria\update`. Medium-integrity GUI / SilentUpdater could still
append the log in the parent folder, but could **not** write
`update-and-install.ps1` → permanent stage failure (every ~1 min).

## Fixes
- Stop locking Users out of update staging; heal ACL to SYSTEM/Admins/Users **M**
- Writable probe + fallback dirs: `update` → `update_work` → `%TEMP%\AsteriaUpdate`
- Emergency bootstrap can stage under TEMP when ProgramData is ACL-bricked
- `heal_update_machinery` repairs staging ACL on each tick
- Interactive `self_update`: elevated NSIS fallback if helper still cannot start

## This host (chicken-egg)
4.9.68 cannot self-heal until one successful install lands 4.9.71.
Run the installer once elevated (or reset ACL on `ProgramData\Asteria\update`),
then remote/GUI updates work again.
