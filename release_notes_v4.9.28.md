# Cloud Honeypot Client v4.9.28

## Highlights

### Critical — unique token per physical host (clone split)
- Two servers sharing one token (same UUID / same account email) usually means an
  unsysprep’d VM clone copied `MachineGuid` and/or `token.dat`.
- `/register` `machine_id` is now a **SHA-256 hardware fingerprint**
  (`MachineGuid` + NIC MACs + SMBIOS UUID + volume serial) — not MachineGuid alone.
- `token.dat` CHP2 + `device_binding.json` bind the token to that fingerprint;
  mismatch → quarantine + fresh enroll.
- **One-time** schema v2 upgrade re-enrolls under the fingerprint so clones that
  already share a token each get a **distinct** Client. Re-link Account on each host
  (Settings → Account link).

### Ops
- `scripts/reset-agent-identity.ps1` — manual identity wipe if needed.
- Prefer sysprep/generalize before sealing images; never bake `token.dat`.

## Install

Silent: `cloud-client-installer.exe /S`
