# SPO Tools

Cardano Stake Pool Operator management toolkit. Air-gapped signer plus
online coordinator, with QR/UR fragments crossing the boundary so the
skeys never touch the network. Each side runs a local web UI in
your browser — no CLI flags, no Haskell, no Plutus knowledge needed.

Self-hosted, open source, Linux-only. No Docker, no SaaS, no mobile apps.

## Status

**v1.0.0** — production-ready. Six operational features, body-level
validation on the signer, and an end-to-end encrypted channel between
online tool and signer. All six features validated on Cardano mainnet
against a live stake pool.

## Features

- **Leaderlog** — Praos VRF block-schedule prediction. Automatic
  fallback to the current epoch when the next-epoch nonce has not yet
  been finalised by the protocol's stability window.
- **KES rotation** — fresh Sum6Kes keypair, operational certificate
  built and signed by the cold key, three `cardano-cli`-compatible
  envelope files (`kes.skey`, `node.cert`, `cold.counter`) ready for
  deployment to the block producer node.
- **Reward withdrawal** — Conway-era stake withdrawal with payment
  plus owner-stake witnesses, fee in lovelace, change to payment
  address.
- **DRep delegation** — Abstain / No-Confidence / specific DRep,
  required so reward withdrawal stays valid under Conway's
  `ConwayWdrlNotDelegatedToDRep` rule.
- **Pool parameter updates** — full re-registration covering pledge,
  margin, fixed cost, reward account, owner stake keys, relays and
  metadata. Pre-submit pledge-vs-owner-stake check warns when the
  active stake snapshot may not yet meet a raised pledge. On-chain
  pending-update detection so the operator sees what will activate
  on the next epoch boundary.
- **SPO governance vote** — cast a Yes / No / Abstain vote on an open
  Conway governance action with the pool's full stake weight. Signed by
  the **cold key**; the signer additionally checks that the cold
  verification key hashes to the voted pool id. Optional CIP-136
  rationale anchor.

In addition to the six operational features, the channel between
online tool and signer is **end-to-end encrypted**. After a one-time
visual-fingerprint pairing, every QR / UR payload is sealed with
X25519 + XChaCha20-Poly1305. A passive observer of the QR channel
sees only ciphertext; substitution mid-channel is rejected by the
AEAD tag; a man-in-the-middle during the pairing dance is caught
visually because the 16-byte fingerprint on the two screens will not
agree. Operations refuse to run unpaired.

Every 4xx/5xx response from the online tool is a structured JSON
envelope (`{"code": "not_paired", "message": "..."}`) so external
integrations and tests can dispatch on the stable `code` instead of
parsing free-form text.

Both `spo-tools-online` and `spo-tools-signer` ship as single
self-contained binaries — the Vue frontend is embedded via
`rust-embed`. Copy the binary anywhere and run.

## Supported key formats

Two `cardano-cli` signing-key forms are accepted for the **payment** and
**stake** keys:

- **Plain Ed25519** — `PaymentSigningKeyShelley_ed25519` /
  `StakeSigningKeyShelley_ed25519`, as produced by `cardano-cli address
  key-gen` and `stake-address key-gen`.
- **Extended BIP32-Ed25519** —
  `PaymentExtendedSigningKeyShelley_ed25519_bip32` /
  `StakeExtendedSigningKeyShelley_ed25519_bip32`. This is what a
  mnemonic-wallet owner (Eternl, Lace, Yoroi, …) gets by exporting the
  recovery phrase with `cardano-address` (standard CIP-1852 path) and
  converting with `cardano-cli key convert-cardano-address-key`. The
  signer detects the extended form automatically and signs scalar-based
  — it never treats an extended key as a 32-byte seed, which would
  derive a different key and a different address. On load it cross-checks
  the public key embedded in the skey envelope against the one derived
  from the secret.

The pool **cold key** is always a `cardano-cli`-generated
`StakePoolSigningKey_ed25519` (plain 32-byte, or the legacy 64-byte
form); cold keys are not mnemonic-derived. KES and VRF keys keep their
cardano-cli formats.

Hardware wallets (Ledger, Trezor) are not supported.

## Limitations (v1.0)

- Linux only.

Single-pool operators only — by design, not a missing feature. Multi-pool
operation concentrates stake and works against the decentralisation this tool
exists to support, so it is deliberately out of scope.

## Strongly recommended setup

The canonical Cardano stake pool setup (CoinCashew, Cardano Foundation
SPO course, Hitchhiker's Guide) creates two address forms from the
same payment signing key:

- an **enterprise address** (`addr1v...`, no stake credential), and
- a **base address** (`addr1q...`, with stake credential = pledged
  owner stake key).

Both addresses are controlled by the same `payment.skey`. The pool's
pledge sits at the base-form address; day-to-day fee UTxOs may live
at either form depending on how cardano-cli wallets were created.

This shared-key setup means a compromised online tool — even with the
signer's body validator in place — could in principle build a
withdrawal whose inputs come from the *pledged* base-form address
instead of the enterprise address you intend, draining the pledge.
The signer is air-gapped and cannot see on-chain UTxO ownership, so
it must trust the inputs the online tool claims it picked. SPO Tools
v1.0 closes this with the validator's same-address check, made airtight
by the recommended setup below:

1. The online tool sends the funding **inputs** (with their claimed
   addresses) alongside each request. The signer's body validator
   cross-checks `body.inputs` against `request.inputs` and rejects a
   tx whose inputs do not all sit at the request's
   `payment_address_bech32`.
2. Operator PIN (typed on the online tool, retyped on the signer)
   gates the actual signing.

A fully-compromised online tool can report *consistent but false* input
addresses, so neither the validator nor an operator reading the on-screen
details can catch the lie on its own — the signer cannot see on-chain
UTxO ownership. The fund-safety guarantee therefore rests on the setup
below, which removes the lie's leverage entirely:

To make layer 1 fully effective, pick **one** of these setups when
you fill in the online tool's Setup page:

- **(a) Use the pledged base-form address as `payment_address`.** This
  is the simplest fix: the validator's "all inputs must equal
  payment_address" check then forbids any UTxO from a different
  address from funding the tx. Side effect: change goes back to the
  pledged address, which is what you want anyway.
- **(b) Use a separate `payment.skey` for the enterprise address.**
  This is the Cardano Foundation "Secure Pledge" pattern. The
  pledged base-form is controlled by one key, the day-to-day fee
  address by another. The validator's same-address check then
  guarantees a withdrawal cannot accidentally include a pledged
  UTxO.

Setup (a) is the lower-friction option; (b) is stricter. Either is
acceptable. Setting `payment_address` to an enterprise address whose
stake credential is *also* a pledged stake key is **not** acceptable
and is the scenario the validator alone cannot defend against.

## Air-gap is operator-enforced, not enforced by software

The signer process makes a best effort to detect that the host has
no network: at startup it shows a banner asking you to acknowledge
the air-gap, and a small monitor periodically samples each live
non-loopback interface's `carrier` flag and `rx_bytes`/`tx_bytes`
counters, flagging the host as air-gapped when no traffic crosses any
link. **Treat both as advisory.** A determined attacker who
already has shell access on the signer host can bring the network
back up after the check passes. The trust anchor is the operator
keeping the signer host physically separated, not the software
detecting that separation.

## Workspace layout

- `shared/` — types and traits used by both binaries
- `shared-frontend/` — Vue components, stores, formatters used by both UIs
- `online-tool/` — internet-connected coordinator (Axum + Pallas)
- `signer/` — air-gapped signer (Pallas, no network)

All build on the sibling **`airgap-core`** crate — the role-neutral air-gap
transport (X25519 + XChaCha20-Poly1305, UR/QR, pairing, PIN) and Cardano
primitives (tx assembly, body validation, key loading) shared with DRep
Tools and Wallet Tools. Check it out next to this repo:

```
parent/
  airgap-core/     (the shared library)
  spo-tools/       (this repo)
```

Both the Rust workspace (`airgap-core = { path = "../../airgap-core" }` in
`shared/Cargo.toml`) and the npm workspaces (`@airgap-core/frontend` as a
`file:` dependency in each frontend's `package.json`) resolve `airgap-core`
relative to this repo, so `npm install` and `cargo build` fail without the
sibling checkout.

## Build

Requires Rust 1.85+ (stable) and Node.js 22+, with `airgap-core` checked
out as a sibling directory.

```bash
# 1. Frontend assets
npm install
( cd online-tool/frontend && npm run build )
( cd signer/frontend && npm run build )

# 2. Rust binaries (frontend assets get embedded)
cargo build --release
```

Binaries land in `target/release/spo-tools-online` and
`target/release/spo-tools-signer`. Both are self-contained; no further
dependencies at runtime besides a modern Linux kernel and a recent
browser to drive the web UI.

## Tests

```bash
# Rust unit + handler-level tests across the workspace
cargo test

# End-to-end integration test: spawns both binaries with isolated
# tempdir HOME, hits a Koios stub, exercises pairing + error paths.
cargo build --bin spo-tools-online --bin spo-tools-signer
cargo test -p signer --test round_trip

# Frontend (Vue + vitest)
( cd online-tool/frontend && npx vitest run )
```

## Quick start

### Online client (any networked machine)

```
./spo-tools-online --listen 127.0.0.1:8200
./spo-tools-online --listen 127.0.0.1:8200 --debug      # verbose tracing
```

`--listen ADDR:PORT` is required: there is no default port, both for
security (no fixed port to scan) and to allow side-by-side instances.
For a self-hosted or custom *mainnet* Koios deployment, add
`--koios-url URL` (defaults to `https://api.koios.rest/api/v1`). This is
not a preprod switch: the binary is hard-wired to mainnet (network id,
address prefixes, Shelley-era slot anchors), so pointing it at a
preprod/preview Koios yields wrong timings and unsignable transactions.
`RUST_LOG` overrides log filtering.

Open the URL printed at startup and complete Setup with your pool ID,
payment address and reward-receive address. Saved to
`~/.config/spo-tools/online.json`.

The Setup form has an optional Koios API key field. The key is read at
startup and attached as `Authorization: Bearer <key>` to every Koios
request (raises Koios's free-tier limit from 5 000 to 50 000 requests
per day). Adding or changing the key via Setup persists it to the
config file but does not rebuild the running HTTP client — restart the
online tool for the new key to take effect on subsequent calls.

### Signer (air-gapped machine)

Mount your encrypted key storage (typically a LUKS-encrypted USB stick),
then:

```
./spo-tools-signer --listen 127.0.0.1:8201
./spo-tools-signer --listen 127.0.0.1:8201 --debug      # verbose tracing
```

Acknowledge the air-gap reminder, open the URL printed at startup and
configure the file paths to your VRF, cold, owner-stake, reward-stake
and payment signing keys. Keys are read from disk on every sign — kept
in memory only for the duration of the operation.

### Pair the two sides (one-time, ~1 min)

Once both binaries are running, open **Pairing** in either UI. Each
side displays its own public key as a static QR; scan the other side's
QR with the camera, and visually compare the 16-byte fingerprint shown
on both screens. They must match exactly. Click Confirm and the
channel is permanently encrypted between this online tool and this
signer. Operational features refuse to run before pairing is complete.

### Workflow

Every feature follows the same five-step shape:

1. Fill in the form on the online client and click **Send to Signer**.
   A confirmation modal opens summarising the operation and asking for
   a 4-digit **operator PIN**. Pick any 4 digits — you will retype the
   same PIN on the signer screen in step 3.
2. The online client builds the request, encrypts it (X25519 +
   XChaCha20-Poly1305), and shows it as an animated QR plus a list of
   UR fragments alongside an 8-byte **request fingerprint** (e.g.
   `a37f-2c91-5be2-c8d4`).
3. The signer scans the QR (or accepts pasted UR fragments), decrypts
   the payload, displays the same request fingerprint and an
   operation-specific preview. Verify the fingerprint matches the one
   on the online tool, click **Confirm and sign**, and retype the PIN
   when prompted. The signer refuses to sign on PIN mismatch.
4. The signer encrypts the result and shows it as another QR / UR
   sequence.
5. The online client scans (or pastes) the result and submits the
   signed transaction to Koios.

Both sides accept UR fragments either via webcam-scanned QR or pasted
as text.

## Maintainer

Smit Blockchain Operations (Pool BKIND) — <developmentbkind@gmail.com>

## Support this work

If you want me to continue maintaining and expanding these tools for the
Cardano ecosystem, please support it by delegating your stake:

- **Delegate to pool BKIND**
  (`pool1m83drqwlugdt9jn7jkz8hx3pne53acfkd539d9cj8yr92dr4k9y`)

This keeps the work visible and sustainable. Thank you.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) for disclosure.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or
implied, as set out in the MIT and Apache-2.0 licenses below. It constructs,
signs, and submits real transactions on the Cardano mainnet using your
private keys.

You alone are responsible for:

- safeguarding your signing keys (cold, KES, VRF, payment, stake);
- verifying every transaction on the signer's screen before you approve it;
- the outcome of any transaction you sign and submit.

To the fullest extent permitted by law, the author accepts no liability for
any loss or damage — including loss of funds, keys, rewards, or pool
operation — arising from the use of, or inability to use, this software. Use
it at your own risk.

Nothing here is financial, tax, or legal advice. Always confirm against the
on-chain state and your own records.

This is open source so that you never have to take it on trust. In case of
any doubt, read the source — or have someone you trust check it for you —
before you rely on it.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE),
at your option.

Third-party code vendored under `vendor/` is distributed under its own licenses (BSD-3-Clause and Apache-2.0); see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
