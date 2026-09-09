## Attacks — AuthLog FTP / MySQL / MSSQL (contract 1.4.89)

- Tail MySQL/MariaDB (+ XAMPP/Laragon) `*.err`/`*.log` “Access denied”
- IIS FTP W3C logs with sc-status **530**
- MSSQL **ERRORLOG** `Login failed for user … [CLIENT: ip]` (plus EventLog 18456)
- Lab probe dirs: `%ProgramData%\Asteria\authlog_probe\{mysql,ftp,mssql}`
- Env override: `ASTERIA_AUTHLOG_EXTRA` (`;`-separated globs)
- Skip loopback; health snapshot includes `auth_log_health`
- Tool: `tools/sim_authlog_inject.py`

### Lab
- After update: inject or real spray → Attacks **FTP:21** / **MYSQL:3306** / **MSSQL:1433** (or relocated listen)
- Enable matching `protection.block_rules`

### Pin
Recommend fleet / Derin / Ninety **≥ 4.9.122**. Contract **1.4.89**.
