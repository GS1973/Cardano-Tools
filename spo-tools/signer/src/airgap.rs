//! Air-gap heuristic for this signer: the shared monitor in `airgap-core`
//! (`airgap_monitor`). Advisory only, it gates no handler.

pub(crate) use shared::airgap_monitor::{air_gapped, spawn_air_gap_monitor};
