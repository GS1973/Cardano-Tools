# Cardano-Tools

GUI-based Cardano tools with online clients and offline (air-gapped) signers.

Each tool lives in its own subfolder and shares a common core:

- **[spo-tools](spo-tools/)** — Stake Pool Operator toolkit. From an online
  client the operator registers and updates pool parameters, rotates KES
  keys, forecasts the leader schedule, withdraws rewards, sets DRep
  delegation, and casts SPO governance votes — every transaction is signed
  on an air-gapped machine so the keys never touch the network.
- **[airgap-core](airgap-core/)** — role-neutral transport and Cardano
  primitives shared by the tools: signing, key loading, CBOR transaction
  validation, QR/UR transport, and the online-to-signer pairing channel.

Prebuilt binaries are published under [Releases](../../releases). Each tool's
own README covers building from source and its security model.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See the license files
in each subfolder.
