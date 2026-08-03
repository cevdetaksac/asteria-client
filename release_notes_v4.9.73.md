# Asteria Client 4.9.73 — Update path harden + GitHub hygiene

## Why
Fleet updates still hit edge cases after the 4.9.71 folder-ACL fix:
a leftover `update-and-install.ps1` could keep a **SYSTEM-only file ACL**
even when the parent `ProgramData\Asteria\update` folder was writable →
`write_ascii_ps1` failed → TEMP fallback / `stage_helper` storms.

Also finished dropping the `cloud-client-installer.exe` release alias.

## Fixes
- Heal ACLs on **existing children** in update staging; delete bricked helper
- `write_ascii_ps1`: remove/replace when overwrite is Permission denied
- Stage probe checks helper-named `.ps1` writability (not only a tiny probe file)
- Self-update / build publish **only** `asteria-client-installer.exe`
- GitHub: prune old releases; kept tags carry a single installer asset

## Verify on a lab host
1. GUI or dashboard **Check updates** → download progresses past 0%
2. No `launch_helper_failed detail=stage_helper` in `update-install.log`
3. Helper log contains `update-and-install start`
4. Agent comes back on **4.9.73**
