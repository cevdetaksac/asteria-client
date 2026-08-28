## Remote Desktop — full local capture fail dumps (contract 1.4.86)

- Start terminal fails (`SESSION0_HELPER_NO_FRAME`, `CAPTURE_NO_DESKTOP`, winlogon flat/black) write `%ProgramData%\Asteria\rd_capture_diag\` JSON (+JPEG when available)
- Streaming Default empty frames dump after ~2s (`default_no_frame` / `default_no_frame_helper`)
- Follow `FOLLOW_NO_DEFAULT_FRAME` and Default black recover fail also dump
- Capture health gets `local_dump_path` + `recovery_steps` (dump contents stay on host for RDP pull)

Lab: Ninety-Web / Derin-Web Default connect → fail → inspect `rd_capture_diag`.

**SHA256:** `2cfa99e4ccd686195eac437ea30d7c30f9f30010a4736941ae1595a5faba1afb`
