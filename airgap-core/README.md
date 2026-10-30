# airgap-core

Role-neutral core shared by the Cardano air-gapped tooling, SPO Tools,
DRep Tools, and Wallet Tools. It holds the transport and the Cardano
primitives that every tool reuses, so each tool's online client and
offline signer speak the same wire format and validate transactions the
same way.

Consumed as a path dependency by each tool. It is not published to
crates.io.

## What it provides

- **Air-gapped transport**: QR / UR fragment codec (`qr`), the encrypt and
  UR-encode wrappers the handlers call (`wire_io`), and the online-to-signer
  pairing channel (`pairing`, `crypto`, `csrf`, `pin`).
- **Cardano primitives**: key loading (`cardano_keys`), transaction
  assembly and body validation (`tx`, `validate`, `witness`), assets and
  UTxOs (`asset`, `utxo`), the chain context (`chain_context`) and the
  request fingerprint both screens show (`fingerprint`).
- **Signer-side guards shared by every tool**: the fee ceiling and the
  check that the payment address belongs to the signer's own payment key
  (`validate`), and the reader that shows the text of a CIP-100 canonical
  body from the exact bytes being signed (`nquads`).
- **Signer building blocks shared by every signer**: the exactly-once
  request ledger and chain-context snapshot each signer keeps
  (`signer_state`), signing-key material for plain and extended keys
  (`signing`), writing a new key file without ever overwriting one
  (`key_files`), the air-gap monitor (`airgap_monitor`) and the Setup
  screen's directory browser (`list_dir`), the loopback-only listener
  check (`listen`), the shared error type (`error`) and the config file
  helpers (`config_helpers`).
- **Fetch guard**: the classification of public versus internal addresses
  (`netguard`), and beside the core, in `fetch-guard/`, the
  `airgap-fetch-guard` crate: the one guarded HTTP client the online tools
  use to fetch a document from an operator-supplied URL and hash it
  (`document_hash`, https only, public addresses only, no API key). It is a crate of its own because the
  air-gapped signers link the core and must not carry an HTTP client.
- **Frontend types**: the `@airgap-core/frontend` TypeScript package
  re-exports the shared wire types so the web front ends stay in lockstep
  with the Rust definitions.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Author

Smit Blockchain Operations (Pool BKIND), <developmentbkind@gmail.com>
