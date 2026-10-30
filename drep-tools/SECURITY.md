# Security Policy

DRep Tools handles a Cardano DRep signing key plus a payment key, and signs
governance transactions (DRep register, update, retire, and vote) that lock a
refundable deposit and cast on-chain votes. Vulnerability reports are taken
seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.** Instead, email:

> developmentbkind@gmail.com

with subject line `[drep-tools security]` followed by a short summary. Include:

- The component (online tool, signer, shared crate, frontend, or protocol-level
  concern such as the encrypted channel or pairing fingerprint)
- The version (binary tag or commit hash)
- A reproduction or proof-of-concept if available
- Your assessment of severity and the worst-case impact

You can expect an acknowledgement within five working days.

## Scope

In scope:

- The two binaries (`drep-tools-online`, `drep-tools-signer`) and the crates
  that build them (`shared`, `drep-online`, `drep-signer`)
- The encrypted channel between online tool and signer
  (X25519 + XChaCha20-Poly1305, pairing fingerprint, UR transport)
- The body-level transaction validator on the signer (`shared::tx_validator`)
- The CSRF and DNS-rebinding guard on both servers
- Any leak of DRep/payment key material or skey paths through the HTTP surface,
  the embedded frontend, the on-disk config files, or logs

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

### Body validator (DRep register, update, retire, vote)
- The body validator on the signer checks that every field of the Conway
  TransactionBody (fee, TTL, the single change output, the certificate, the
  optional governance anchor (CIP-119 / CIP-136), and the inputs) matches the
  request, and that the loaded DRep verification key hashes (blake2b-224) to the
  DRep id named in the request. A compromised online tool therefore cannot make
  the signer act as a different DRep, nor sign a body that does not match the
  preview. The check runs when the request is received, so a request that
  misdescribes its body is refused before any preview is shown, and again at
  signing, before a key is used.
- The signer refuses a request whose `payment_address_bech32` is not
  controlled by the payment key it holds: the address's payment credential
  must be the blake2b-224 hash of that key. The validator sends the change to
  the request's payment address, and the request is written by the online
  tool. Without this check a compromised online tool could name an address of
  its own, spend the operator's real UTxOs and collect the change there. Only
  the payment part is bound, so an enterprise address or a base address with
  any stake part is accepted. An address with the operator's payment
  credential and a foreign stake part stays spendable by the operator's key
  alone.
- The signer refuses any fee above 3 ADA (`MAX_FEE_LOVELACE`), well over the
  largest fee these operations honestly produce. If a protocol-parameter
  change ever lifts honest fees past the ceiling, the signer refuses until it
  is updated.
- As with any air-gapped signer, the validator can only cross-check the
  request's `inputs[i].address_bech32` against the request's
  `payment_address_bech32`. It cannot consult the chain to confirm those UTxOs
  really sit there. A compromised paired online tool could lie about the input
  addresses. Because the change returns to an address the operator's own
  payment key controls (see above) and the fee is capped, the worst case is
  funding the operation from a different one of the operator's own UTxOs, not
  a drain to an attacker. The signer's preview surfaces the funding inputs (each UTxO and its
  amount) for visibility.

### Rationale witness
- The CIP-100 canonical body the DRep key signs is produced by the online
  tool's browser (URDNA2015). The signer does not recompute it. It shows the
  operator the text of the exact bytes it will sign, read back statement by
  statement, with invisible and text-reordering characters made visible and
  any line it cannot read shown as it is. The operator comparing that text
  with the rationale they wrote is what binds the witness to their words. A
  compromised online tool can still canonicalise a different document. It
  cannot do so without the signer's screen showing that other text.
- The signer refuses a payload that is not a canonical N-Quads body, so the
  witness path cannot be used to sign a transaction.

### Document fetch (online tool)
- The manifest-hash helper fetches an operator-supplied URL. It connects only
  to public internet addresses: loopback, private, link-local, carrier-grade
  NAT and reserved ranges are refused, for an IP literal, for every address a
  name resolves to, and for each redirect hop. It uses a client of its own, so
  the Koios API key is never sent to a document host. Only `https://` is
  fetched, also across redirects: the result is a hash the operator anchors
  on-chain, and over plain HTTP a network attacker could alter the document
  and with it that hash. Behind an HTTP proxy the proxy resolves names itself.
  The tool then checks the name once before the request, cannot bind the
  connection, and follows no redirect.

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

### Channel-layer secret on disk
- Each binary stores its X25519 long-term static secret as a hex string in its
  config file (`~/.config/drep-tools/{online,signer}.json`), written 0600 with
  the parent directory 0700 via an atomic tmp+rename. The secret is **not**
  encrypted at rest, and the channel does not provide forward secrecy: recovery
  of either side's static secret retroactively decrypts captured exchanges. The
  "LUKS-encrypted, no network during signing" host assumption covers this.

### Signing-key file mode
- `load_skey` rejects any `.skey` file whose mode permits group or other access
  (`mode & 0o077 != 0`) before reading it. cardano-cli writes 0600 by default.
  Manually moved files may need `chmod 600`.

### Best-effort secret zeroization
- The signer wraps the DRep and payment seeds in `Zeroize` / `Zeroizing` so the
  raw bytes are wiped on drop, and the keygen write path holds the hex encoding
  and the skey-envelope JSON in `Zeroizing` too. This reduces, but does not
  eliminate, exposure to core dumps, swap-out, and same-UID `/proc/<pid>/mem`
  reads. Third-party crates (`ed25519-dalek::SigningKey`) keep their own
  short-lived copies that this tool does not zeroize. Treat the signer host as a
  trust boundary regardless.

### Key and nonce entropy source
- Every secret this tool generates (the DRep and payment Ed25519 seeds, the
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

- DRep Tools vendors nothing. Every dependency is a published crates.io crate.
  `deny.toml` enforces a license allow-list, one version per crate, and
  crates.io as the only source. The encrypted-channel layer uses `x25519-dalek`
  2.x over upstream `curve25519-dalek` 4.x with constant-time scalar arithmetic.
- Updating a dependency is a deliberate maintainer action, not an automatic
  `cargo update`.

## No bug bounty

This is a single-maintainer open-source project. There is currently no monetary
bounty. Public credit on the release notes is offered for valid reports unless
you prefer to remain anonymous.
