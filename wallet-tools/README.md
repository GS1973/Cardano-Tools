# Wallet Tools

Air-gapped Cardano **wallet** for holding and moving funds under sole
operator control. An online coordinator plus an air-gapped signer, with
QR/UR fragments crossing the boundary so the spending keys never touch the
network. Each side runs a local web UI in your browser, no CLI flags, no
Haskell, no Plutus knowledge needed.

Self-hosted, open source, Linux-only. No Docker, no SaaS, no mobile apps.

Keys are **CLI-style Ed25519** (cardano-cli compatible skey JSON), born on
the air-gapped signer, **there is no 24-word seed phrase** for an app to
read or a fake download to leak. The online side only ever sees public
material (addresses, pubkeys) and unsigned transactions.

A companion to **SPO Tools** and **DRep Tools**, built on the same
role-neutral `airgap-core` library. All three are fully separate: none
contains a line of another's code. Each depends only on `airgap-core`.

## Status

**v1.4.0**: create CLI-derived addresses, delegate stake to a pool and to
a DRep, withdraw staking rewards, and send/receive ADA + native assets,
with a multi-wallet address book and enterprise (payment-only) wallets. Built and tested:
builder↔validator round-trips for every operation, the signer-side
body↔request binding and change-guard, the back-compatible address-book
migration, a headless serve-check of both embedded SPAs, and live
air-gapped end-to-end runs on mainnet.

## Features: the five operations

- **New address**: a payment and a stake Ed25519 keypair are generated
  **on the air-gapped signer** (OS CSPRNG, fail-closed) and written as
  cardano-cli skey JSON. The base address (`addr1q…`) and stake address
  (`stake1…`) are derived from them. Only the address + pubkeys cross to
  online. The private keys never leave the offline box. Enterprise
  (payment-only, `addr1v…`) addresses are supported for send/receive.
- **Delegate to pool**: a stake registration (+ deposit) if the stake key
  is not yet registered, plus the pool stake-delegation certificate. Conway
  combined certificates let "new address → registered → delegated" happen in
  a single signed transaction (`StakeRegDeleg`, else `StakeDelegation`).
- **Delegate to DRep**: a vote-delegation certificate (`VoteRegDeleg`,
  else `VoteDeleg`), signed with the stake key.
- **Withdraw rewards**: moves the stake key's accumulated staking rewards
  from its reward account to the wallet's own payment address. The network
  only accepts a withdrawal of the exact account balance, so the full
  balance is withdrawn. There is no amount to choose and no destination to
  enter. It also requires the vote to be delegated to a DRep already (a
  ledger rule since the Conway bootstrap phase ended), so delegate the vote
  first. Signed with the payment and the stake key.
- **Send / receive incl. native assets**: the online tool reads the UTxOs
  from Koios, runs coin-selection covering amount + assets + fee + min-ADA
  change, and builds the multi-asset transaction. Fee and min-UTxO are
  computed from live protocol params. Receive is just displaying the
  address + QR. Nothing to sign.

Each spend or delegation funds itself from a selected **source wallet**: a
single fee/asset input set, a change output that preserves any native
assets, the operation's certificate(s) where applicable, and the witnesses
needed to authorise it, the **payment** key always, plus the **stake** key
for delegations and reward withdrawals.

The channel between online tool and signer is **end-to-end encrypted**.
After a one-time visual-fingerprint pairing, every QR / UR payload is
sealed with X25519 + XChaCha20-Poly1305. A passive observer of the QR
channel sees only ciphertext. Substitution mid-channel is rejected by the
AEAD tag. A man-in-the-middle during the pairing dance is caught visually
because the 16-byte fingerprint on the two screens will not agree.
Operations refuse to run unpaired.

Every 4xx/5xx response from the online tool is a structured JSON envelope
(`{"code": "not_paired", "message": "..."}`) so integrations and tests can
dispatch on the stable `code` instead of parsing free-form text.

Both `wallet-tools-online` and `wallet-tools-signer` ship as single
self-contained binaries, the Vue frontend is embedded via `rust-embed`.
Copy the binary anywhere and run.

## Key isolation

The `wallet-signer` holds only **payment** and **stake** signing keys. Its
config struct has no field for a pool cold key or a DRep key, the binary
cannot name, let alone load, those secrets. A compromise of the wallet
signer cannot reach the SPO or DRep role's keys, and vice versa.

At signing time the signer selects the key pair whose **derived** base
address equals the request's address, never a label or any online-supplied
value, then validates, runs the change-guard, and signs. No match → it
refuses. The signer never trusts an imported address. It derives.

## Multi-wallet address book

Manage several wallets behind an address book, with the funding wallet
chosen per operation:

- Up to ten **own** wallets (signable, their keys live on the signer) plus
  any number of **external** destinations (send-to / watch only). A curated,
  labelled, verified book is itself a defence against clipboard-swapping
  malware: pick a verified label instead of pasting an address.
- **Source selection** is uniform across Send, pool delegation and DRep
  delegation. With one wallet it is implicit. With several, an explicit
  choice is required, so funds are never spent from the wrong wallet by
  accident.
- The signer holds a matching key-book of up to ten
  `{label, payment key, stake key}` entries and picks by derived address, as
  above. Enterprise entries omit the stake key.

## Keys born offline

The signer's `keygen` mints payment + stake key pairs in cardano-cli
envelope format directly, no external cardano-cli step. Every secret (the
Ed25519 seeds, the X25519 channel secret, every AEAD nonce) is drawn from
the OS CSPRNG via `getrandom`, wrapped in `Zeroizing`, and **fails closed**:
if the OS cannot supply entropy the generator aborts. No seeded/userspace
PRNG, no hardcoded seed, no weak fallback. Signing is deterministic Ed25519
(RFC 8032) with a secret nonce prefix, so a signature on the chain never
gives the key away.

Imported cardano-cli keys are also accepted: plain Ed25519
(`PaymentSigningKeyShelley_ed25519` / `StakeSigningKeyShelley_ed25519`) and
extended BIP32-Ed25519 (`…ExtendedSigningKeyShelley_ed25519_bip32`, e.g. a
mnemonic-wallet key converted with `cardano-address` +
`cardano-cli key convert-cardano-address-key`). The signer detects the
extended form and signs scalar-based, it never treats an extended key as a
32-byte seed, and cross-checks the embedded public key against the one
derived from the secret on load.

## Limitations (v1.4.0)

- Linux, x86-64 and arm64. For x86-64, prebuilt binaries ship in two builds: a standard
  **glibc** build (modern distributions, glibc >= 2.34: Ubuntu 22.04+,
  Debian 12+, Fedora 35+, RHEL/Rocky/Alma 9+, Arch, recent openSUSE) and
  a fully static **musl** build (`-musl`) that runs on any x86-64 Linux,
  including older LTS releases, Alpine, and minimal/live environments.
  Use `-musl` if the standard build reports `GLIBC_x.xx not found`. For arm64
  (Raspberry Pi 3/4/5, Zero 2, and other 64-bit ARM boards on a 64-bit OS), a
  fully static **`-arm64`** build is provided.
- Key-based wallets only. Hardware-wallet owners are not
  yet supported, on-device signing is on the roadmap.
- Enterprise (payment-only) wallets can send and receive but cannot
  delegate or earn rewards, they have no stake credential (a Cardano rule,
  not a tool limit).
- A reward withdrawal built shortly before an epoch boundary can be
  rejected at submit if new rewards land first (the balance no longer
  matches). Nothing is lost. Build it again.

## The air-gapped verification (defense-in-depth)

A send is exactly where address-swapping (clipper) malware strikes, so the
decisive check sits on the offline side. The signer cannot consult the
chain, so it trusts neither the online tool's claims nor its screen:

1. The signer **decodes the transaction body itself** and holds every
   field against the request: destination, amount, native assets, fee,
   certificates, withdrawal, inputs. Only a request whose body matches is
   shown, in human-readable form on the air-gapped screen. One that
   misdescribes its body is refused before any preview appears. The
   operator verifies there, not on the possibly-compromised online machine.
   The same check runs again at signing, before a key is used.
2. **Change-guard.** The signer derives the source wallet's own address from
   its keys and refuses to sign unless the change output returns there. For
   a delegation or a reward withdrawal it likewise derives the wallet's own
   stake address and refuses any other.
3. **Fee ceiling.** The signer never signs a fee above 3 ADA, whatever the
   request says. An honest fee stays well below that (about 0.17 ADA for a
   simple transaction).
4. The online tool sends the funding **inputs** alongside each request. The
   body validator cross-checks them and rejects a tx whose inputs do not all
   sit at the request's address.
5. An operator **PIN** (typed on the online tool, retyped on the signer)
   gates the actual signing.

## Chain data source (Koios)

The online tool reads chain state (UTxOs, protocol params, tip) and submits
transactions via **Koios** over HTTPS. The default endpoint is
`https://api.koios.rest/api/v1`. Override it with `--koios-url` to point at
your own self-hosted mainnet Koios instance, no client change needed. The
URL must be https. Plain http is accepted only for a Koios on the same
machine (localhost, 127.0.0.1 or ::1).

Custody does **not** rest on trusting the provider. A signed transaction
cannot be tampered in transit (the witnesses sign the body, any change
breaks them), and the destination and amount are independently decoded and
displayed by the air-gapped signer before signing, a lying provider cannot
redirect funds. It **can** steer the numbers derived from its data: inflated
protocol parameters (`min_fee_a`/`min_fee_b`, `utxoCostPerByte`, deposits)
yield an inflated but internally consistent fee, min-ADA or deposit. The
online tool refuses parameters outside the range the Cardano constitution's
guardrails allow, the signer caps the fee at 3 ADA, and the network rejects
a deposit that is not the protocol's own, so the damage is bounded, but
within those bounds the signer's validator accepts what it is given. So verify the fee and any
deposit on the signer preview before approving, that screen is the backstop
for provider faults too, not only for a compromised online machine. Transient 429/5xx responses
are retried with backoff. (Submit is safe to retry: the same signed tx has
the same hash and the ledger cannot apply it twice.)

## Air-gap is operator-enforced, not enforced by software

The signer process makes a best effort to detect that the host has no
network: at startup it shows a banner asking you to acknowledge the
air-gap, and a small monitor checks for IP traffic on connected interfaces
periodically (the top bar then reads "No network detected", which is all it
can honestly say). **Treat both as advisory.** No operation consults the
monitor. It gates nothing. A determined attacker who already
has shell access on the signer host can bring the network back up after the
check passes, and file-transfer channels (VM shared folders,
USB-passthrough, Bluetooth OBEX) are not detected at all. The trust anchor
is the operator keeping the signer host physically separated, not the
software detecting that separation.

## Workspace layout

- `shared/`, wallet wire types, address derivation + body validators
- `shared-frontend/`, Vue transport components, stores, formatters (the
  wallet's own copy, never imports another tool)
- `wallet-online/`, internet-connected coordinator (Axum + Pallas + Koios)
- `wallet-signer/`, air-gapped signer (Pallas, no network)

All build on the sibling **`airgap-core`** crate, the role-neutral air-gap
transport (X25519 + XChaCha20-Poly1305, UR/QR, pairing, PIN) and Cardano
primitives (tx assembly, body validation, key loading) shared with SPO
Tools and DRep Tools. Check it out next to this repo:

```
parent/
  airgap-core/     (the shared library)
  wallet-tools/    (this repo)
```

## Build

Requires Rust 1.95+ (stable) and Node.js 22+, with `airgap-core` checked
out as a sibling directory.

```bash
# 1. Frontend assets (embedded into the binaries at compile time)
npm install
( cd wallet-online/frontend && npm run build )
( cd wallet-signer/frontend && npm run build )

# 2. Rust binaries
cargo build --release
```

Binaries land in `target/release/wallet-tools-online` and
`target/release/wallet-tools-signer`. Both are self-contained. No further
runtime dependencies besides a modern Linux kernel and a recent browser to
drive the web UI.

## Tests

```bash
cargo test --workspace
```

Covers address derivation (base / stake / enterprise), coin-selection and
multi-asset change arithmetic, the body validators plus the
address↔key binding and change-guard, builder↔validator round-trips for
payment, both delegations and the reward withdrawal, the back-compatible single-wallet →
address-book migration, and an end-to-end sign that verifies the Ed25519
witnesses over the body hash.

## Quick start

### Online client (any networked machine)

```
./wallet-tools-online --listen 127.0.0.1:8400
./wallet-tools-online --listen 127.0.0.1:8400 --debug      # verbose tracing
```

`--listen ADDR:PORT` is required: there is no default port, both for
security and to allow side-by-side instances. For a self-hosted mainnet
Koios, add `--koios-url URL` (defaults to `https://api.koios.rest/api/v1`).
The URL must be https, or plain http on the same machine.

Both binaries listen on a loopback address only (127.0.0.0/8 or ::1) and
refuse any other `--listen` address. The flag `--allow-non-loopback`
overrides that refusal. Do not use it: the online tool holds Koios access
and builds and submits transactions, the signer holds your keys, and
neither has any authentication beyond the operator PIN. Anything that can
reach the address can drive the tool. The flag exists only for a setup you
have isolated yourself, and that is on you.

Open the URL printed at startup, then build your **Address book**: add your
own wallets (by address, with the keys held on the signer) and any external
destinations. Saved to `~/.config/wallet-tools/online.json`. The optional
Koios API key is attached as `Authorization: Bearer <key>` to every Koios
request. Restart the online tool for a new key to take effect.

### Signer (air-gapped machine)

Mount your encrypted key storage (typically a LUKS-encrypted USB stick),
then:

```
./wallet-tools-signer --listen 127.0.0.1:8401
```

Acknowledge the air-gap reminder, open the URL printed at startup and either
**generate** new payment/stake keypairs on the signer or configure the file
paths to existing skeys, up to ten wallets in the key-book. Keys are read
from disk per operation and kept in memory only for its duration. Config is
saved to `~/.config/wallet-tools/signer.json` (mode 0600).

### Pair the two sides (one-time, ~1 min)

Once both binaries are running, open **Pairing** in either UI. Each side
displays its own public key as a static QR. Scan the other side's QR with
the camera, and visually compare the 16-byte fingerprint shown on both
screens. They must match exactly. Click Confirm and the channel is
permanently encrypted between this online tool and this signer. Operations
refuse to run before pairing is complete.

### Workflow

Every operation follows the same five-step shape:

1. Fill in the form on the online client (for a send: pick the source
   wallet, the destination, the amount and any native assets) and click
   **Send to Signer**. A confirmation modal opens summarising the operation
   and asking for a 4-digit **operator PIN**: retyped on the signer in
   step 3.
2. The online client builds the request, encrypts it, and shows it as an
   animated QR plus a list of UR fragments alongside an 8-byte **request
   fingerprint** (e.g. `a37f-2c91-5be2-c8d4`).
3. The signer scans the QR (or accepts pasted UR fragments), decrypts the
   payload, and shows the same fingerprint plus the decoded destination,
   amount, assets, fee and change-guard result. Verify the fingerprint
   matches, click **Confirm and sign**, and retype the PIN. The signer
   refuses to sign on PIN mismatch, or if no held key derives to the
   request's source address.
4. The signer encrypts the result and shows it as another QR / UR sequence.
5. The online client scans (or pastes) the result and submits the signed
   transaction to Koios.

Both sides accept UR fragments either via webcam-scanned QR or pasted as
text.

## Maintainer

Smit Blockchain Operations (Pool BKIND), <developmentbkind@gmail.com>

## Support this work

If you want me to continue maintaining and expanding these tools for the
Cardano ecosystem, please support it by delegating your stake:

- **Delegate to pool BKIND**
  (`pool1m83drqwlugdt9jn7jkz8hx3pne53acfkd539d9cj8yr92dr4k9y`)

This keeps the work visible and sustainable. Thank you.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) for disclosure,
please do not open a public issue. The same file spells out the threat-model
assumptions (loopback-only listeners, PIN semantics, channel secret at rest,
no forward secrecy, entropy source) that this wallet shares with SPO Tools
and DRep Tools.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or
implied, as set out in the MIT and Apache-2.0 licenses below. It constructs,
signs, and submits real transactions on the Cardano mainnet using your
private keys.

You alone are responsible for:

- safeguarding your signing keys (payment, stake),
- verifying every transaction on the signer's screen before you approve it,
- the outcome of any transaction you sign and submit.

To the fullest extent permitted by law, the author accepts no liability for
any loss or damage, including loss of funds or keys, arising from the use
of, or inability to use, this software. Use it at your own risk.

Nothing here is financial, tax, or legal advice. Always confirm against the
on-chain state and your own records.

This is open source so that you never have to take it on trust. In case of
any doubt, read the source, or have someone you trust check it for you,
before you rely on it.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE),
at your option.
