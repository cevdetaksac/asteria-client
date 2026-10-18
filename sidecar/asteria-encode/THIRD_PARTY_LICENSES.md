# asteria-encode third-party licenses

Policy (contract 1.4.94 C-RD-HW-1): permissive only (MIT/Apache-2.0/BSD/ISC/Zlib). No GPL/AGPL/LGPL.

| Crate | License |
|---|---|
| windows / windows-core / windows-targets (+ macros) | MIT OR Apache-2.0 |
| serde_json / serde / serde_core | MIT OR Apache-2.0 |
| itoa, memchr, ryu/zmij, proc-macro2, quote, syn, unicode-ident | MIT OR Apache-2.0 (unicode-ident: + Unicode-3.0) |

Toolchain: Rust stable x86_64-pc-windows-gnullvm + llvm-mingw (Apache-2.0 WITH LLVM-exception; mingw-w64 runtime: ZPL/public domain, statically linked CRT startup only).

Planned: webrtc-rs crates (MIT OR Apache-2.0). OpenH264 (BSD-2, Cisco binary downloaded at runtime, never bundled).
