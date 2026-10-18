# asteria-encode third-party licenses

Policy (contract 1.4.94 C-RD-HW-1): permissive only (MIT/Apache-2.0/BSD/ISC/Zlib). No GPL/AGPL/LGPL.

| Crate | License |
|---|---|
| windows / windows-core / windows-targets (+ macros) | MIT OR Apache-2.0 |
| serde_json / serde / serde_core | MIT OR Apache-2.0 |
| itoa, memchr, ryu/zmij, proc-macro2, quote, syn, unicode-ident | MIT OR Apache-2.0 (unicode-ident: + Unicode-3.0) |
| str0m (+ str0m-proto, str0m-wincrypto, is, sctp-proto, …) | MIT OR Apache-2.0 |
| thiserror, log, tracing, once_cell, … (str0m tree) | MIT OR Apache-2.0 / permissive |

Toolchain: Rust stable x86_64-pc-windows-gnullvm + llvm-mingw (Apache-2.0 WITH LLVM-exception).

OpenH264 (BSD-2, Cisco binary) is **not** bundled; may be downloaded at runtime later under Cisco's terms.
