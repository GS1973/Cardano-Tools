# Vendored crate provenance

Three cryptographic crates are vendored under `vendor/` as path
dependencies of the signer (see `signer/Cargo.toml`) instead of being
pulled from crates.io. They implement Cardano-specific primitives — Praos
VRF-03 (over the elligator sign-bit fork) and KES (Sum6Kes) — for which no
maintained crates.io release matches the signer's edition / MSRV
constraints. Vendoring freezes the exact bytes that produce operational
certificates and leader-log proofs.

This file pins each vendored copy to a verifiable, offline content
identity. Cargo's `.cargo_vcs_info.json` — which would carry the upstream
publish commit — is absent here, because these are source-tree copies and
not packaged crates. The pin is therefore the git subtree hash plus a
rolled-up SHA-256 of the tracked file contents. Both are reproducible by
anyone holding this repository and change if any vendored byte changes;
neither can be forged into matching a tampered tree.

## Verifying a vendored tree

```sh
# git subtree hash (SHA-1 of the tree object):
git rev-parse HEAD:vendor/<crate>

# rolled-up content digest (SHA-256, content only, path-sorted):
( cd vendor/<crate> && git ls-files -z | sort -z | xargs -0 sha256sum | sha256sum )
```

Both must equal the values recorded below. To locate the matching upstream
commit when network access is available, clone the upstream repository and
diff against the recorded version; the lineage notes below describe the
single intended deviation in each fork.

## Pinned crates

### amaru-vrf-dalek 0.1.0
- Upstream: https://github.com/pragma-org/amaru (low-level `vrf_dalek`)
- Role: Praos VRF-03 (`SecretKey03` / `PublicKey03` / `VrfProof03`) for leader-log proofs.
- Lineage: depends on the curve25519 fork below for the elligator sign-bit behaviour VRF-03 requires.
- Local deviation (2026-06-23): the published draft-10 modules (`vrf`, `vrf10`, `vrf10_batchcompat`) and their dependency on the unforked crates.io `curve25519-dalek` 3.2.0 are placed behind an off-by-default `vrf10` Cargo feature. The signer builds VRF-03 only, so the default build no longer links the 3.2.0 release RUSTSEC-2024-0344 flags. See `../SECURITY.md`.
- git subtree: `c1f13e2da6b5481069290eb3b8d20b0e567bb04a`
- content sha256: `503c0cdaf66d23a5da0eb8483721fd9fb5add47321c0ecf196e1b4e5e9889d4a`
- tracked files: 13

### amaru-kes-summed-ed25519 0.2.1
- Upstream: https://github.com/txpipe/kes (originally input-output-hk/kes)
- Role: Sum6Kes key-evolving signatures for operational-certificate generation.
- git subtree: `c6fa5aba285981052f3d546ae527c21831e52f1c`
- content sha256: `cbb0105f11057e79c703e7358f5e1a537a4f499e0da25c0c6d43936d53a2ff34`
- tracked files: 29

### amaru-curve25519-dalek 3.2.0
- Upstream: https://github.com/pragma-org/amaru (fork of curve25519-dalek 3.2.0)
- Role: transitive dependency of `amaru-vrf-dalek`.
- Lineage: forked one commit ahead of upstream curve25519-dalek v3.2.0 to flip the elligator sign bit so the crate matches the VRF-03 reference in input-output-hk/libsodium (`draft-irtf-cfrg-vrf-03`). See `amaru-curve25519-dalek/README.md`.
- Local deviation (2026-06-23): the `black_box` (volatile-read) optimization barrier from upstream `curve25519-dalek` 4.1.3 is backported verbatim into `Scalar29::sub` (`backend/serial/u32/scalar.rs`) and `Scalar52::sub` (`backend/serial/u64/scalar.rs`), resolving RUSTSEC-2024-0344's timing variability while keeping output bit-for-bit identical — gated by the libsodium VRF-03 known-answer vectors in `amaru-vrf-dalek`. This is in addition to the sign-bit flip above, so the fork is no longer a single-commit deviation from upstream 3.2.0.
- git subtree: `6b77346849bb79303eed5d25d3018d2afd726aa6`
- content sha256: `2c95eb04297caa21e7b9232715d6b0c4a9f33455a3dbc447bfcc40c1e20f5226`
- tracked files: 65
