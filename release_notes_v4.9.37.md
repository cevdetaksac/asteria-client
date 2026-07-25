# 4.9.37 — account re-authentication and durable identity

## Account security
- The signed-in account email is visible in the top-right header with a user icon.
- The Help menu shows **Unlink account** instead of **Link account** when linked.
- Link/unlink operations require a fresh local GUI PIN verification in addition
  to account credentials. An unlocked GUI session alone is not sufficient.

## Token persistence
- Identity schema upgrades rewrap the existing token in the current DPAPI
  envelope instead of rotating it.
- NIC/hardware drift on the same Windows MachineGuid preserves the token and
  repairs only the local binding.
- A failed rotate request never quarantines `token.dat` or creates a new client
  identity. Existing token, client_id, history, and account link are retained.
- Upgrades continue to preserve canonical ProgramData identity:
  `%ProgramData%\YesNext\CloudHoneypotClient\token.dat`.

Cloned machines with a changed/ambiguous MachineGuid are not automatically
re-registered. Run `scripts\reset-agent-identity.ps1` explicitly on the clone.
