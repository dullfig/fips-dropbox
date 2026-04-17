# The Road to FIPS

A working reference for building (or buying) a CMMC-compliant vendor file-sharing product for the small DIB market.

---

## 1. The regulatory stack, correctly framed

"FedRAMP" is the wrong north star for an on-prem tool serving a machine shop. FedRAMP applies to **cloud service providers selling to federal agencies**. What actually binds a DIB supplier handling CUI:

| Layer | What it is | Where it bites |
|---|---|---|
| **DFARS 252.204-7012** | Contract clause requiring "adequate security" for CUI | Every DoD contract touching CUI |
| **NIST SP 800-171 r2** | 110 controls that define "adequate security" | The actual checklist |
| **CMMC Level 2** | The assessment framework that validates 800-171 compliance | Every ~3 years, by a C3PAO |
| **FIPS 140-2 / 140-3** | Validation program for cryptographic modules | NIST 800-171 §3.13.11 requires it for CUI confidentiality |

**The practical rule:** every cryptographic module touching CUI must appear on NIST's CMVP validated list with a live certificate number. Not "uses AES-256" — the module itself must be certified.

FedRAMP only enters the picture if the product becomes a SaaS used by federal agencies. Defer it.

---

## 2. The Rust trap

Modern Rust crypto — `ring`, `rustls` default provider, ChaCha20-Poly1305 — **is not FIPS-validated.** An assessor will fail a CUI system using it even though the math is correct.

Viable paths that keep Rust as the application language:

| Path | Module | Trade-off |
|---|---|---|
| **`aws-lc-rs` + rustls (aws-lc backend)** | AWS-LC, CMVP certs #4631 / #4759 | Cleanest Rust integration. Must use exact validated build artifacts. |
| **`openssl` crate → FIPS-built OpenSSL 3.0** | OpenSSL FIPS Provider, cert #4282 | Well-trodden. Windows build complexity. |
| **Windows CNG in FIPS mode via `windows-sys`** | Windows Cryptographic Primitives Library, cert #4339 | Zero extra supply chain; already on Win2022. Ties you to Windows. |
| **Rust app, FFI to a validated module** | Any of the above | Keeps Rust where it shines, crypto where it's certified. |

**Recommendation for MVP on Win2022:** Windows CNG in FIPS mode. The validated module is already on the server.

---

## 3. Getting your own FIPS cert — the brutal truth

Skip this unless revenue or a prime contractor demands it. The process:

1. **Scope a cryptographic module** — a narrow boundary of code (or code+hardware), *not* the whole application.
2. **Engage an accredited CST lab** — atsec, Acumen, Leidos, Lightship, UL, Gossamer (~20 worldwide).
3. **Make the module compliant** with FIPS 140-3 + SP 800-140 series: power-on self-tests, approved algorithms only, RNG requirements, key zeroization, formal Security Policy, role-based access.
4. **Lab tests and writes the report** (CAVP + module testing).
5. **Submit to CMVP.** Enter the queue: **IUT → MIP → Validated**.
6. **Receive a certificate number.**

**Real 2026 numbers:**
- Lab fees: **$150k–$500k**
- Total engineering cost: 2–3× that
- Timeline: **12–24 months**, plus long MIP queue backlog
- Re-validation required on every non-trivial code change
- Ongoing: $50k+/yr maintenance is common

---

## 4. The strategy that 95% of products use: inherit a cert

You do not implement crypto. You consume a pre-validated module and document it:

> "Cryptographic operations are performed by [Windows Cryptographic Primitives Library, CMVP cert #4339]. The application does not implement its own cryptography."

An assessor will accept that. Rules for inheritance to actually hold:

- Use the **exact validated build artifact** — not "OpenSSL 3.0" but "3.0.8 with FIPS provider from cert #4282." Change the build → lose the cert.
- Keep the module in **FIPS mode at runtime** (OS-level on Windows; provider config on OpenSSL).
- Never call a non-approved algorithm for CUI. No ChaCha20, no MD5 anywhere near CUI.
- Document the module boundary in the SSP: what goes in, what comes out, where keys live.

---

## 5. Minimum feature set, mapped to controls

Every feature must trace to a NIST 800-171 control:

| Feature | Control(s) |
|---|---|
| Per-vendor identities with MFA (TOTP min, FIDO2 better) | §3.5.3 |
| Time-bounded share links, scoped to one vendor + one part | §3.1.1, §3.1.3 |
| TLS 1.2+ with FIPS-approved cipher suites only | §3.13.8, §3.13.11 |
| At-rest encryption via FIPS module (AES-256-GCM through CNG) | §3.13.16, §3.8.9 |
| Tamper-evident audit log (append-only, hash-chained; user+IP+time) | §3.3.1, §3.3.2 |
| Session timeout + device binding | §3.1.10, §3.1.11 |
| Ingest DLP: CUI marking check, EXIF strip, malware scan | §3.14.2 |
| One-click vendor offboarding | §3.1.7 |
| Backup + key custody (losing KEK = losing CUI, legally) | §3.8.9, §3.13.10 |

---

## 6. The moat — not crypto

Crypto is table stakes. The defensible moat for a CMMC-focused product:

1. **SSP-in-a-box** — NIST 800-171 System Security Plan template, pre-filled for the tool. Every control marked as product-handled vs. customer-handled.
2. **C3PAO endorsement** — one or two friendly C3PAOs who will vouch that shops using the product clear assessment.
3. **Priced for job shops** — $50–$200/month. Not $2k+.
4. **One-server deploy** — MSI installer, web UI to add vendors. No Kubernetes. Customer is a machinist.
5. **Audit log shaped for assessors** — CSV export filtered by control ID.

---

## 7. Self-hosted vs SaaS — pick one, for now

| Mode | Pros | Cons |
|---|---|---|
| **Self-hosted** | Each customer owns their own CMMC scope. No FedRAMP exposure. Sell software + support. Faster to market. | Harder to update. Support burden. |
| **SaaS** | Recurring revenue. Central updates. Larger TAM. | FedRAMP Moderate eventually (~$1M+, 18–24 mo). You're in scope for customers' CMMC. |

**Start self-hosted, Windows-first, on the CUI server shops are already buying.** Graduate to SaaS only after demand is proven and the self-hosted product is stable.

---

## 8. A realistic 12-month plan

| Phase | Months | Work |
|---|---|---|
| 1. MVP on inherited crypto | 0–3 | Rust app, `aws-lc-rs` or Windows CNG, TLS 1.2+, upload/download, MFA, audit log. Your shop first. |
| 2. SSP + controls map | 2–4 (parallel) | Write the template. Map every 800-171 control to product or customer. |
| 3. Friendly C3PAO review | 4–6 | Mock assessment. Fix findings. Get a letter. |
| 4. Dogfood your own CMMC assessment | 6–9 | You become reference customer #1. Real cert on real gear. |
| 5. Pilot shops | 9–12 | 3–5 other small DIBs. Charge them. Harden from feedback. |
| Later — own FIPS cert | Year 2+ | Only if a prime or federal customer demands *your* name on the CMVP list. |

---

## 9. Buy-then-build: acquisition as an accelerator

In regulated markets, buying customers + compliance posture beats cold-starting. Walker Deibel's thesis applies especially well here.

### What you're actually acquiring

A FIPS cert is **not a cleanly transferable asset.** CMVP rules:

- Ownership/name change → "non-security-relevant change" letter, usually approved, cert stays.
- Build or code change → back in queue, potentially full re-validation.
- Major platform shift → new cert entirely.

If you plan to rewrite the product after acquisition, you'll likely invalidate the cert. **The real assets are customers, C3PAO relationships, SSP templates, contracts, and brand** — more than the cert itself.

### Where to look

**Primary map — CMVP Validated Modules list:**
`csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules`

Filter by:
- Vendors with 1–3 certs (not Cisco/Microsoft)
- 2018–2022 certs not yet renewed
- Niche module names: "secure file transfer," "cryptographic library," "VPN client"

Cross-reference against LinkedIn (founder age), Pitchbook/Crunchbase (headcount, funding). Solo founder in their 60s, 2019 cert, no recent press = prime target.

### Category targets

| Category | Signature |
|---|---|
| Small secure-file-transfer vendors | 3–20 employees, sub-tier defense suppliers |
| Legacy MFT tools | On-prem installers, Java-era stacks being revived by CMMC demand |
| Defense-adjacent PLM / print-management niche | Already inside shops, already touching drawings |
| CMMC consulting firms with a home-grown portal | Built for their own clients; never productized |
| Defunct GovCloud SaaS | Founder pivoted; product still running |

### Listing & broker sources

- **Acquire.com** — sub-$5M SaaS. Tags: cybersecurity, compliance, file sharing, government.
- **Quiet Light, FE International, Empire Flippers** — SaaS brokers.
- **Axial** — lower-middle-market M&A, mostly by invitation.
- **BizBuySell** — noisy but small software does appear.
- **SBA 7(a)** — eligible for sub-$5M deals with clean financials. Defense-sector fine if no ITAR.

### Non-obvious sources (the real ones)

- **Corsec Security** — FIPS consulting firm; knows every cert holder. Say "I'm an acquirer, who's trying to exit?"
- **CST labs** (atsec, Acumen, Leidos, Gossamer, Lightship, UL) — engineers know which clients stopped returning calls.
- **AFCEA and NDIA small-business committees** — tired defense-software founders hang out at these conferences.
- **Project Spectrum, CMMC-AB marketplace, DIB.scoe.org** — browse smallest vendors with no press.
- **GSA Schedule 70 holders** with <$1M/yr on SAM.gov — struggling but legitimate.
- **Your own C3PAO, once chosen** — ask who among product vendors seems tired.

### Landscape (not for sale, but calibration)

- **SafeLogic** — seller of CryptoComply; a *supplier*, not a target.
- **wolfSSL** — privately held, small, niche; acquirable in principle, not cheap.
- **Kiteworks, PreVeil, Virtru** — too big for you; study to price under.
- **DataLocker, SafeBreach, Archon Secure** — mid-sized, occasionally in flux.

### Screen for any target

1. Real customer list — 20 paying DIB shops beat one impressive logo.
2. Churn — <10%/yr normal in compliance; 20%+ is a red flag.
3. C3PAO/assessor relationships — if they leave with the seller, they're not assets.
4. Crypto inheritance story — own module ($50k+/yr maintenance) vs. inherited (cleaner).
5. Ticking bombs — "we need to migrate off [stack] by 2027" — opportunity or liability.
6. Multiple — 2–4× SDE typical for stable B2B micro-SaaS; CMMC niche may carry a small premium.

### One weekend action

Pull the CMVP list into a spreadsheet, filter to vendors with 1–2 certs, LinkedIn-stalk the top 30. Five candidates by Sunday night.

---

## 10. Open next-step tracks

- **MVP architecture sketch** — Rust + Windows CNG, storage layout, API surface, audit log schema.
- **SSP / control-mapping outline** — the deliverable that's valuable whether you build or buy.
- **CMVP scouting spreadsheet template** — columns, filters, contact-tracking.

Pick one and the next document writes itself.
