# Security Policy

SPO Tools handles Cardano stake pool cold keys and signs transactions
that move real ADA. Vulnerability reports are taken seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.** Instead, email:

> developmentbkind@gmail.com

with subject line `[spo-tools security]` followed by a short summary.
Include:

- The component (online tool, signer, shared crate, frontend, or
  protocol-level concern such as the encrypted channel or pairing
  fingerprint)
- The version (binary tag or commit hash)
- A reproduction or proof-of-concept if available
- Your assessment of severity and the worst-case impact

You can expect an acknowledgement within five working days. Triage,
fix, and release timelines depend on severity but the maintainer aims
to ship a patched binary set within fifteen working days for high-
impact issues.

## Scope

In scope:

- The two binaries (`spo-tools-online`, `spo-tools-signer`) and the
  crates that build them (`shared`, `online-tool`, `signer`)
- The encrypted channel between online tool and signer
  (X25519 + XChaCha20-Poly1305, pairing fingerprint, UR transport)
- The body-level transaction validator on the signer
  (`shared::tx_validator`)
- The CSRF and DNS-rebinding guard on both servers
- Any leak of cold-key material or skey paths through the HTTP
  surface, the embedded frontend, the on-disk config files, or logs

Out of scope:

- The Vue frontend running in your browser if your browser itself is
  compromised (an attacker with code execution in your browser has
  already lost the game)
- Issues in upstream dependencies (Pallas, axum, etc.) unless the
  embedding amplifies them
- Anything that requires the attacker to already have shell access on
  the air-gapped signer machine
- Bugs that require a malicious local user with the same Linux
  account (the threat model assumes the signer host is trusted)

## Assumptions the tool relies on

The following assumptions are part of the threat model. Operators
who break them lose the corresponding guarantees.

### Host trust
- The signer host is trusted: LUKS-encrypted, no network during
  signing, single trusted operator. A breach of the host's local
  trust is not in scope.
- Both binaries listen on `127.0.0.1` only. Exposing them on a
  public interface defeats the threat model and is not supported.

### Pairing
- The operator visually compares the 16-byte pairing fingerprint on
  both screens before clicking Confirm. Skipping this step lets a
  man-in-the-middle complete the pairing.

### Per-request fingerprint and PIN
- The operator visually compares the 8-byte request fingerprint
  shown next to the QR on the online tool with the one shown on the
  signer's preview screen, **before** clicking Confirm and sign.
  Identical fingerprints prove the encrypted payload reached the
  signer intact.
- The operator types the same 4-digit PIN on both sides for every
  request, and the signer refuses to sign on a mismatch. This is a
  deliberate extra layer: a per-request, human-supplied approval that
  proves a person is present at the signer and intends *this* signing,
  bound to the request so it cannot be replayed. It complements — it
  does not replace — the fingerprint check above: a PIN typed without
  first verifying the request preview confirms presence but not that
  the request is the one the operator built.
- The PIN search space is 10 000 (4 decimal digits). The proof is
  domain-separated and bound to the request (kind +
  `chain_context.built_at_unix`), so a PIN guess is per-request, not
  global. The proof is not a brute-force-resistant authenticator;
  rather, it is a small bit of entropy the operator must supply at
  both ends of the encrypted-channel boundary, defeating signing
  triggered by a fully compromised online tool that holds a paired
  X25519 key but has no human at the signer screen.

### Body validator (reward withdrawal, DRep delegation, pool update, SPO vote)
- The body validator on the signer checks that every field of the
  Conway TransactionBody — fee, TTL, outputs, certificates, inputs
  — matches the request. **However** the validator can only
  cross-check the request's `inputs[i].address_bech32` against the
  request's `payment_address_bech32`; it cannot independently
  consult the chain to confirm that those input UTxOs really sit at
  that address. A sophisticated attacker controlling a paired
  online tool can therefore lie about the input addresses while
  keeping the cryptographic body itself consistent.
- The signer's preview **does** surface the funding inputs (each UTxO
  and its amount) so the operator sees exactly what is being spent —
  useful visibility. But it cannot detect a *lying* tool, which presents
  consistent attacker-supplied addresses, so that visibility is a sanity
  check, **not** the trust anchor for this case. The trust anchor is the
  mandated setup in the README's "Strongly recommended setup": with the
  payment address equal to the pledged base address (a), or a separate
  key for the enterprise fee address (b), the validator's same-address
  check forbids a pledged UTxO from funding the transaction — or the
  signer never holds the pledge key at all — so the lie has no leverage.
- The repository README's "Strongly recommended setup" section
  describes how to choose `payment_address` so that the validator
  alone is sufficient against this class of attack.

### Air-gap
- The signer's startup banner and the periodic carrier + `rx_bytes`/`tx_bytes` traffic-delta check
  are **advisory**, not enforcement. A determined
  attacker who already has shell access on the signer host can
  re-enable network connectivity after the check passes. Air-gap is
  ultimately operator-enforced (physical separation), not
  software-enforced.

### System clock (request freshness)
- The signer refuses to sign a request whose `chain_context` snapshot is
  older than 24 hours, bounding replay of a stale-but-still-valid signed
  transaction. This check reads the signer host's wall clock, which on an
  air-gapped machine is the one piece of live state it cannot
  cross-check. A dead RTC battery can boot the host to a bogus near-epoch
  time; against such a clock every genuine request looks far in the
  future and the freshness check is meaningless. The signer guards
  against this by refusing to sign when its clock reads before the UNIX
  epoch, or before 2024-01-01 UTC (treated as "clock unset"), returning a
  distinct "set the clock" error rather than a misleading "request is
  older than 24 hours" one. The freshness window is a coarse upper bound
  on request age, **not** a substitute for the per-request exactly-once
  ledger, which is clock-independent and is what actually prevents a
  request from being signed twice. Keep the air-gapped machine's clock
  set; the online tool stamps `built_at_unix` from a network-synced host.

### Forward-compatibility
- The signer's skey loader does **not** use `deny_unknown_fields`.
  Future cardano-cli versions that add new top-level JSON fields
  will continue to load. The trade-off is that a forged skey JSON
  with extra fields will not be rejected at parse time; the
  cryptographic content (cborHex with strict header + length check)
  is still validated.

### Vendored cryptography
- `vrf_dalek`, `kes_summed_ed25519`, and `amaru-curve25519-dalek`
  are vendored from the upstream Pragma-org Amaru repository at a
  pinned revision. Audits of those crates apply directly. Updating
  to a newer Amaru release is a deliberate maintainer action, not
  an automatic `cargo update`.
- The vendored `amaru-curve25519-dalek` is at version 3.2.0, the line
  RUSTSEC-2024-0344 flags for timing variability in `Scalar29::sub` /
  `Scalar52::sub` (LLVM may lower the masked conditional add into a `jns`
  branch that is skipped when the underflow mask is zero). The signer's
  VRF-03 signing path runs through this fork, so the variability is fixed
  in place rather than merely accepted: the upstream 4.1.3 `black_box`
  (volatile-read) optimization barrier has been backported verbatim into
  both scalar backends. The barrier constrains code generation only, not
  the arithmetic — the result is bit-for-bit identical, verified by
  re-running the libsodium `draft-irtf-cfrg-vrf-03` known-answer vectors
  before and after the change (see `vendor/PROVENANCE.md`). This is
  defense-in-depth: the signing host is also air-gapped, so no remote
  attacker can observe its timing.
- The advisory database matches RUSTSEC-2024-0344 against the **published**
  crates.io `curve25519-dalek` 3.2.0 (the fork is a separate crate name and
  is never matched). That published crate is an off-by-default optional
  `vrf10` dependency of `amaru-vrf-dalek`, feeding only the unused VRF
  draft-10 modules, so the default build — the signer — never compiles or
  links it. `cargo deny` works from the default-feature build graph and so
  does not flag it. `cargo audit` works from `Cargo.lock`, where the optional
  dependency is still pinned, so it does flag the advisory; the suppression
  in `.cargo/audit.toml` (and the CI `cargo audit` step) is therefore
  required, and records that the crate is present-but-uncompiled rather than
  silently shipped.
- The signer uses VRF **only** for Cardano Praos leader-log proofs; the
  consensus protocol mandates the PRE-Babbage VRF-03 flavour that upstream
  `curve25519-dalek` 4.x intentionally drops, which is why the fork is
  vendored rather than replaced. The signer's encrypted-channel layer
  (operator ↔ signer over QR) uses a separate `x25519-dalek` 2.x stack on
  top of upstream `curve25519-dalek` 4.x with constant-time scalar
  arithmetic — unaffected throughout.

### Channel-layer secret on disk
- Each binary stores its X25519 long-term static secret as a hex
  string inside its config file (`~/.config/spo-tools/{online,signer}.json`),
  written 0600 with the parent directory 0700 via an atomic
  tmp+rename so the secret is never visible to non-owner processes
  for any window. The secret is **not** encrypted at rest. A backup
  taken from a partly-compromised host, a forensic disk image, or any
  process running under the same UID can recover it.
- The encrypted channel does not provide forward secrecy: every QR
  payload is sealed under a key derived from the same static-static
  ECDH, so recovery of either side's secret retroactively decrypts
  any captured exchange. The signer host's `LUKS-encrypted, no
  network during signing` assumption above covers this for the
  signer side; the online tool's host trust assumption is the same as
  for the cold-key files it points at via Setup.
- A future revision could OS-keyring the secret; for v1.0 the model is
  "trust the same host the cold keys live on."

### Cold-key file mode
- `load_skey` rejects any `.skey` file whose mode permits group or
  other access (`mode & 0o077 != 0`) before reading the file. This
  guards against operator copy-paste workflows that produce a 0644
  skey on a removable drive. cardano-cli writes 0600 by default; if
  the operator has tightened or moved files manually they may need
  to `chmod 600` before the tool will load them.

### Best-effort secret zeroization
- The signer wraps cold/payment/stake/VRF seeds in `Zeroize` /
  `Zeroizing` so the raw bytes are wiped on drop. The Sum6Kes
  expansion buffer used during rotation is explicitly zeroed.
  This reduces — but does not eliminate — exposure to core dumps,
  swap-out under memory pressure, and same-UID `/proc/<pid>/mem`
  reads. Third-party crates that hold key material internally
  (`ed25519-dalek::SigningKey`, `vrf_dalek::SecretKey03`,
  `kes_summed_ed25519::Sum6Kes`) keep their own copies that this
  tool does not zeroize; their lifetimes are short (per-call) but a
  hostile process snapshotting at the wrong moment could recover
  bytes. Treat the signer host as a trust boundary regardless.

### Key and nonce entropy source
- Every secret this tool generates — the cold and payment/stake Ed25519
  seed, the Sum6Kes (KES) seed, the X25519 channel static secret, and
  every XChaCha20-Poly1305 nonce — is drawn directly from the operating
  system CSPRNG via `getrandom` (the `getrandom(2)` syscall, `/dev/urandom`
  on Linux). No seeded or userspace PRNG (`StdRng`, `SmallRng`,
  `thread_rng`, or a `Math.random`-equivalent) is ever used for key
  material, and there is no hardcoded or time-derived seed anywhere.
- The entropy call **fails closed**: if the OS cannot supply randomness the
  generator returns an error and aborts; it never falls back to a weaker
  source. That weak-fallback / predictable-generation branch is the failure
  mode behind the June 2026 SecondFi/Yoroi mass drain (predictable
  web-wallet key generation). It cannot occur here because the only entropy
  path is the kernel CSPRNG and there is no alternative branch.
- Keys are generated offline on the air-gapped signer and never leave it.
  Imported keys (cardano-cli `.skey` files, or extended keys *derived* from
  a user-supplied mnemonic — the tool derives, it never *generates* a
  mnemonic) carry whatever entropy quality their original generator had;
  that provenance is the operator's responsibility, not introduced by this
  tool.
- Verified by source audit 2026-06-24: `../airgap-core/src/crypto.rs`
  (`generate_keypair` channel keypair, `seal` nonces — airgap-core is
  checked out as a sibling of this repo and re-exported as
  `shared::crypto`) and `signer/src/sign_core.rs` (cold and KES seed).

## No bug bounty

This is a single-maintainer open-source project. There is currently
no monetary bounty. Public credit on the release notes and a thank-you
in the next release are offered for valid reports unless you prefer
to remain anonymous.
