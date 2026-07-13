# airgap-core

Role-neutral core shared by the Cardano air-gapped tooling — SPO Tools,
DRep Tools, and Wallet Tools. It holds the transport and the Cardano
primitives that every tool reuses, so each tool's online client and
offline signer speak the same wire format and validate transactions the
same way.

Consumed as a path dependency by each tool; it is not published to
crates.io.

## What it provides

- **Air-gapped transport** — QR / UR fragment codec (`qr`), framed
  reader-writer I/O (`wire_io`), and the online-to-signer pairing channel
  (`pairing`, `crypto`, `csrf`, `pin`).
- **Cardano primitives** — key loading (`cardano_keys`), transaction
  assembly and body validation (`tx`, `validate`, `witness`), assets and
  UTxOs (`asset`, `utxo`), chain context and asset fingerprints
  (`chain_context`, `fingerprint`).
- **Frontend types** — the `@airgap-core/frontend` TypeScript package
  re-exports the shared wire types so the web front ends stay in lockstep
  with the Rust definitions.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Author

Smit Blockchain Operations (Pool BKIND) — <developmentbkind@gmail.com>
