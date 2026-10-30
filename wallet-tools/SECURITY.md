# Security Policy

Wallet Tools holds a Cardano payment signing key plus a stake signing key per
wallet, up to ten wallets, and signs transactions that move real funds:
payments (ADA + native assets), pool stake delegations, and DRep vote
delegations. Vulnerability reports are taken seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.** Instead, email:

> developmentbkind@gmail.com

with subject line `[wallet-tools security]` followed by a short summary.
Include:

- The component (online tool, signer, shared crate, frontend, or protocol-level
  concern such as the encrypted channel or pairing fingerprint)
- The version (binary tag or commit hash)
- A reproduction or proof-of-concept if available
- Your assessment of severity and the worst-case impact

You can expect an acknowledgement within five working days.

## Scope

In scope:

- The two binaries (`wallet-tools-online`, `wallet-tools-signer`) and the
  crates that build them (`shared`, `wallet-online`, `wallet-signer`)
- The encrypted channel between online tool and signer
  (X25519 + XChaCha20-Poly1305, pairing fingerprint, UR transport)
- The body-level transaction validators on the signer (`shared::tx_validator`:
  payment, pool delegation, DRep delegation) including the change-guard
- The CSRF and DNS-rebinding guard on both servers
- Any leak of payment/stake key material or skey paths through the HTTP
  surface, the embedded frontend, the on-disk config files, or logs

Out of scope:

- The Vue frontend running in your browser if your browser itself is compromised
- Issues in upstream dependencies (Pallas, axum, etc.) unless the embedding
  amplifies them
- Anything that requires the attacker to already have shell access on the
  air-gapped signer machine
- Bugs that require a malicious local user with the same Linux account (the
  threat model assumes the signer host is trusted)

## Assumptions the tool relies on

The following assumptions are part of the threat model. Operators who break them
lose the corresponding guarantees.

### Host trust
- The signer host is trusted: LUKS-encrypted, no network during signing, single
  trusted operator. A breach of the host's local trust is not in scope.
- Both binaries listen on `127.0.0.1` only: a non-loopback `--listen` address
  is refused at startup unless `--allow-non-loopback` is explicitly passed,
  which logs a security warning and is strongly discouraged. Exposing them on
  a public interface defeats the threat model and is not supported.

### Pairing
- The operator visually compares the 16-byte pairing fingerprint on both screens
  before clicking Confirm. Skipping this step lets a man-in-the-middle complete
  the pairing.

### Per-request fingerprint and PIN
- The operator visually compares the 8-byte request fingerprint shown next to
  the QR on the online tool with the one shown on the signer's preview screen,
  **before** clicking Confirm and sign. Identical fingerprints prove the
  encrypted payload reached the signer intact.
- The operator types the same 4-digit PIN on both sides for every request, and
  the signer refuses to sign on a mismatch. This is a deliberate extra layer: a
  per-request, human-supplied approval that proves a person is present at the
  signer and intends *this* signing, bound to the request so it cannot be
  replayed. It complements, it does not replace, the fingerprint check above.
- The PIN search space is 10 000 (4 decimal digits). The proof is
  domain-separated and bound to the request, so a PIN guess is per-request, not
  global, and the signer locks a request out after 5 wrong-PIN attempts,
  forcing a rebuild on the online tool. It is not a brute-force-resistant
  authenticator. It is the entropy the operator must supply at both ends of the
  encrypted-channel boundary, defeating signing triggered by a fully
  compromised online tool that holds a paired X25519 key but has no human at
  the signer screen.

### Body validators (payment, pool delegation, DRep delegation, reward withdrawal)
- The body validators on the signer check that every field of the Conway
  TransactionBody (fee, TTL, the destination output (amount and native
  assets), the change output, the certificate(s) or the withdrawal where
  applicable, the optional CIP-20 metadata hash, and the inputs) matches
  the request, and that no unexpected field (a withdrawal outside a reward
  withdrawal, extra certificates, ...) is present. The check runs when the
  request is received, so a request that misdescribes its body is refused
  before any preview is shown, and again at signing, before a key is used.
- The signer selects the signing keys whose **derived** address equals the
  request's source address, never a label or any online-supplied value, and
  refuses when no held key matches. The change-guard derives the source
  wallet's own address and checks that the change output returns there. A
  compromised online tool therefore cannot make the signer spend as a
  different wallet, nor sign a body that does not match the preview. For a
  delegation or a reward withdrawal the signer also derives the wallet's own
  stake address from the stake key and refuses a request naming any other.
- A reward withdrawal carries exactly one withdrawal, of the stated amount,
  from the wallet's own key-controlled reward account, and exactly one
  output, to the wallet's own address. The stated figures must balance
  (inputs + rewards = change + fee). The rewards therefore have nowhere to go
  but the wallet itself.
- As with any air-gapped signer, the validator can only cross-check the
  request's `inputs[i].address_bech32` against the request's source address.
  It cannot consult the chain to confirm those UTxOs really sit there. A
  compromised paired online tool could lie about the input addresses, but a
  body spending UTxOs the selected wallet does not own fails on-chain for
  lack of the owning witness: the signer only ever adds the selected
  wallet's signatures. The signer's preview surfaces the funding inputs
  (each UTxO and its amount) for visibility.
- The fee, min-ADA change, and deposit amounts are computed by the online
  tool from protocol parameters fetched from Koios. The validator checks the
  body is *consistent* with the request, not that those values are *sensible*,
  with one exception: the signer refuses any fee above 3 ADA
  (`MAX_FEE_LOVELACE`), well over the largest fee these operations honestly
  produce at the current mainnet parameters. A malicious chain-data provider
  or a compromised online tool can still steer the fee upward below that
  ceiling: the defence there is the operator reading the fee/deposit on the
  signer preview before approving (see the README's "Chain data source"
  section). The online tool itself refuses protocol parameters outside the
  range the Cardano constitution's guardrails allow (fee coefficients,
  `utxoCostPerByte`, stake deposit, `maxTxSize`), and computes the fee with
  checked arithmetic. An inflated deposit is rejected by the network, which
  accepts only the protocol's own deposit. If a protocol-parameter change ever lifts
  honest fees past the ceiling, the signer refuses until it is updated.

### Air-gap
- The signer's startup banner and the periodic carrier + `rx_bytes`/`tx_bytes`
  traffic-delta check are **advisory**, not enforcement. A determined attacker
  with shell access on the signer host can re-enable network connectivity after
  the check passes. Air-gap is operator-enforced (physical separation), not
  software-enforced.

### System clock (request freshness)
- The signer refuses to sign a request whose `chain_context` snapshot is older
  than 24 hours, so a request left waiting cannot be signed long after it was built.
  This reads the host wall clock: the one piece of live state an air-gapped
  machine cannot cross-check. The signer refuses to sign when its clock reads
  before 2024-01-01 UTC ("clock unset"), returning a distinct "set the clock"
  error. The freshness window is a coarse upper bound. The per-request
  exactly-once ledger (clock-independent) is what actually prevents a request
  from being signed twice. Keep the air-gapped machine's clock set.
- The signer also refuses a transaction whose time-to-live lies more than
  three hours past its own clock (`MAX_TTL_AHEAD_SLOTS` in airgap-core), so
  whatever it signs expires within three hours and cannot be held back and
  submitted much later. The slot numbers in the request come from the
  online tool and cannot bound this. The signer's clock can.

### Forward-compatibility
- The signer's skey loader does **not** use `deny_unknown_fields`, so future
  cardano-cli versions that add new top-level JSON fields still load. The
  cryptographic content (cborHex with strict header + length check) is still
  validated.
- Extended BIP32-Ed25519 skeys (mnemonic-wallet keys converted with
  `cardano-address` + `cardano-cli key convert-cardano-address-key`) are
  signed scalar-based, never treated as a 32-byte seed, and the embedded
  public key is cross-checked against the one derived from the secret on load.

### Channel-layer secret on disk
- Each binary stores its X25519 long-term static secret as a hex string in its
  config file (`~/.config/wallet-tools/{online,signer}.json`), written 0600 with
  the parent directory 0700 via an atomic tmp+rename. The secret is **not**
  encrypted at rest, and the channel does not provide forward secrecy: recovery
  of either side's static secret retroactively decrypts captured exchanges. The
  "LUKS-encrypted, no network during signing" host assumption covers this.

### Signing-key file mode
- `load_skey` rejects any `.skey` file whose mode permits group or other access
  (`mode & 0o077 != 0`) before reading it. cardano-cli writes 0600 by default.
  Manually moved files may need `chmod 600`.

### Best-effort secret zeroization
- The signer wraps the payment and stake seeds in `Zeroize` / `Zeroizing` so
  the raw bytes are wiped on drop, and the keygen write path holds the hex
  encoding and the skey-envelope JSON in `Zeroizing` too. This reduces, but
  does not eliminate, exposure to core dumps, swap-out, and same-UID
  `/proc/<pid>/mem` reads. Third-party crates (`ed25519-dalek::SigningKey`)
  keep their own short-lived copies that this tool does not zeroize. Treat the
  signer host as a trust boundary regardless.

### Key and nonce entropy source
- Every secret this tool generates (the payment and stake Ed25519 seeds, the
  X25519 channel static secret, and every XChaCha20-Poly1305 nonce) is drawn
  directly from the operating-system CSPRNG via `getrandom` (`/dev/urandom` on
  Linux). No seeded or userspace PRNG is ever used for key material, and there
  is no hardcoded or time-derived seed anywhere.
- The entropy call **fails closed**: if the OS cannot supply randomness the
  generator returns an error and aborts. It never falls back to a weaker source.
- Signing is deterministic Ed25519 (RFC 8032). The per-signature nonce is
  derived from a secret prefix of the signing key together with the message
  (`ed25519-dalek` for plain keys, `pallas-crypto` for extended BIP32-Ed25519
  keys, where the secret half kR is the prefix). It is never derived from
  public transaction data alone, the flaw class that lets anyone compute a
  private key from a single on-chain signature.
- Keys are generated offline on the air-gapped signer and never leave it.

## Dependencies

- Wallet Tools vendors nothing. Every dependency is a published crates.io
  crate. `deny.toml` enforces a license allow-list, one version per crate, and
  crates.io as the only source, and CI runs `cargo audit --deny warnings` and
  `cargo deny check` on every push and pull request. The encrypted-channel
  layer uses `x25519-dalek` 2.x over upstream `curve25519-dalek` 4.x with
  constant-time scalar arithmetic.
- Updating a dependency is a deliberate maintainer action, not an automatic
  `cargo update`.

## No bug bounty

This is a single-maintainer open-source project. There is currently no monetary
bounty. Public credit on the release notes is offered for valid reports unless
you prefer to remain anonymous.
