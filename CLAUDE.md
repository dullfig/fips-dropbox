# fips-dropbox — instructions for Claude

A CMMC-compliant vendor file-sharing tool for small DIB machine shops. Rust, Windows Server 2022 target, FIPS crypto inherited from Windows CNG (CMVP cert #4339) via the `cng` crate.

See `the road to fips.md` for the full plan. See `~/.claude/projects/C--src-fips-dropbox/memory/` for accumulated context (user role, stack decisions, working dynamic).

## Working style — read this before starting work

**Use subagents aggressively.** Dan prefers long, uninterrupted sessions where the main conversation carries irreplaceable context: the back-and-forth about design trade-offs, compliance reasoning, and the shared mental model. That context cannot be reconstructed if the session restarts. Protect it.

- **Any exploration >2–3 tool calls** → delegate to `Agent(subagent_type=Explore)`.
- **Any non-trivial implementation plan** → delegate to `Agent(subagent_type=Plan)` first, then execute.
- **Any broad search, review, or "find everything that…" task** → `Agent(subagent_type=general-purpose)`.
- **Run independent subagents in parallel** — one message, multiple `Agent` tool calls.
- **Use TaskCreate/TaskUpdate** to track work inside this conversation so it's visible and resumable.
- **Save to memory** when something non-obvious, durable, or cross-session surfaces. Don't save ephemeral task state or things derivable from the code.

## Hard architectural rules

Non-negotiable. If you would break one of these, stop and raise it with Dan first.

1. **`cng` is the only crate that calls `windows-sys::Win32::Security::Cryptography::*`.** No shortcuts, no "just this once."
2. **`crypto` is the only non-`cng` crate that performs cryptographic operations.** Every other crate must go through `crypto`. This is the FIPS boundary named in the SSP.
3. **Forbidden dependencies anywhere in the workspace:** `ring`, `rustls` default provider, `RustCrypto` suite (`aes`, `sha2`, `hmac`, `hkdf`, `pbkdf2`, etc.), `libsodium`/`sodiumoxide`, `openssl` (unless we later add FIPS-OpenSSL explicitly), `orion`, `dryoc`. For `rustls` or `reqwest`, use `native-tls` (Schannel on Windows) — never the default `ring` provider.
4. **Only FIPS 140-3 Approved algorithms touch CUI.** No ChaCha20, Poly1305, Ed25519, Curve25519, X25519, BLAKE2/3, Argon2, scrypt, MD5 for CUI paths. Password hashing is PBKDF2-HMAC-SHA-256 with ≥600,000 iterations.
5. **Every new crypto primitive gets a known-answer test** in `cng` against a published vector (FIPS 180-4, RFC 4231, NIST ACVP, RFC 5869, etc.).
6. **Host must be in FIPS mode.** `crypto::assert_fips_mode()` is called at service startup and must refuse to run otherwise.

## Workspace layout

```
crates/
├── cng/            FFI boundary — BCrypt/NCrypt. Sole FIPS-inheritance surface.
├── crypto/         Safe wrapper over cng. The FIPS boundary named in the SSP.
├── audit/          Hash-chained JSONL log.
├── storage/        SQLite + encrypted blob I/O.
├── service/        Business logic.
├── web/            axum handlers + Askama templates.
├── notifier/       Email (SMTP) + SMS (Twilio) traits.
├── app/            Binary: cuishare (Windows service).
└── sender-agent/   Binary: cuishare-send (right-click GUI).
migrations/         SQL schema.
the road to fips.md The living regulatory + technical plan.
```

## Build

```
cargo check --workspace
cargo test -p cng          # KATs against FIPS vectors
cargo build --release
```

## Git discipline

- Never commit with `--no-verify` or skip hooks — if a hook fails, fix the underlying issue.
- Never commit files that could contain CUI, keys, or real vendor data. `.gitignore` already excludes `/data`, `/blobs`, `/logs`, `*.db`, `*.key`, `/config.local.toml`.
- Commit messages can reference the NIST 800-171 control a change implements or strengthens (e.g., "audit: add IP to share.download events — §3.3.1").

## Dan's collaboration style

Dan owns product vision and UX. Claude owns implementation. When Dan describes how a flow should feel, treat it as a requirement. Push back only if it breaks compliance, not just taste. Keep responses tight, lead with the trade-off, end with a concrete next step.
