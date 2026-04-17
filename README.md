# fips-dropbox

A CMMC-compliant vendor file-sharing tool for small Defense Industrial Base (DIB) shops. Runs on Windows Server 2022 as a single service. Inherits FIPS validation from the Windows Cryptographic Primitives Library (CMVP cert #4339) via CNG/Schannel.

**Status:** v0.1 skeleton. Not yet functional. See [the road to fips.md](the%20road%20to%20fips.md) for the full plan.

## Workspace layout

```
crates/
├── cng/            Unsafe FFI over Windows CNG. Only crate that calls BCrypt/NCrypt.
├── crypto/         FIPS boundary — safe Rust API, delegates to cng.
├── audit/          Hash-chained JSONL audit log.
├── storage/        SQLite + encrypted blob storage.
├── service/        Business logic.
├── web/            axum HTTP handlers + Askama templates.
├── notifier/       Email (SMTP) + SMS (Twilio) senders.
├── app/            Binary: Windows service wrapper + composition root.
└── sender-agent/   Binary: right-click "Send to" GUI.
```

## Build

```
cargo check
cargo build --release
```

Requires: Rust stable, MSVC toolchain, Windows target.

## Running in dev

(not yet wired up — returns to this section once the app crate has a working main loop.)

## Compliance boundaries

- Every cryptographic operation flows through `crates/crypto`, which delegates exclusively to `crates/cng`.
- No other crate may import `cng`, `windows-sys::*::Cryptography::*`, `ring`, `rustls` default provider, `RustCrypto`, or any other crypto library. Enforced by convention (and eventually a `deny.toml` rule).
- The Windows host must have "System cryptography: Use FIPS compliant algorithms" enabled; the app refuses to start otherwise.
