## Attacks — NLA RDP fail → RDP (not NETWORK:445) (contract 1.4.88)

- Subscribe `RdpCoreTS/Operational` **Event 131** (pre-auth TCP + client IP) to seed RDP IP hints
- Flatten Event **UserData** so TS Param* / ClientIP parse for 1149/131
- Classifier: NTLM + empty/`-` workstation → **RDP** *before* NtLmSsp → Network
- Wrong-password spray must not depend on Event 1149 (often success-only)

### Lab
- External `mstsc` wrong password → Attacks **`RDP`** + real TermService port + `<failed_logon>`
- SMB wrong password → still **`NETWORK:445`**
- Honeypot tunnels optional for real-port EventLog fails

### Pin
Recommend fleet / Ninety **≥ 4.9.121**. Contract **1.4.88**.
