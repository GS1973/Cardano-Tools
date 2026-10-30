//! Air-gap heuristic every signer runs.
//!
//! Background task that compares cumulative rx+tx bytes across linked
//! interfaces every few seconds. A zero-delta sample → cache
//! `air_gapped = true`. Any traffic on a connected interface flips it to
//! `false`.
//!
//! **Advisory only.** This indicator gates no handler: operations run
//! regardless of its value. The body validator and channel encryption
//! are the actual security boundaries; the air-gap flag is just a UI hint.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

/// Monitor states. No sample has been compared yet, the last sample saw no
/// traffic on a connected interface, or it did.
const UNMEASURED: u8 = 0;
const NO_TRAFFIC: u8 = 1;
const TRAFFIC: u8 = 2;

/// Cached air-gap status, written by the background monitor task and
/// read by `signer_status`. Starts unmeasured: until the monitor has
/// compared two samples the signer claims neither "no network" nor
/// "network", and the status bar shows the check as unverified.
static AIR_GAP_STATE: AtomicU8 = AtomicU8::new(UNMEASURED);

/// What a monitor state claims: `Some(true)` for no traffic, `Some(false)`
/// for traffic, `None` before the first measurement.
fn claim(state: u8) -> Option<bool> {
    match state {
        NO_TRAFFIC => Some(true),
        TRAFFIC => Some(false),
        _ => None,
    }
}

/// The last measurement, as [`claim`] reads it.
pub fn air_gapped() -> Option<bool> {
    claim(AIR_GAP_STATE.load(Ordering::Relaxed))
}

/// Sum of rx_bytes + tx_bytes across non-loopback interfaces with a
/// live link (`carrier=1`). The kernel exposes per-interface counters
/// in `/sys/class/net/<iface>/statistics/{rx,tx}_bytes`, but a live OS
/// keeps generating background traffic (DHCP DISCOVER, ARP probes,
/// mDNS) on interfaces that are administratively up even when no
/// link is actually present, typical case: VM with "Cable Connected"
/// disabled. Counters are therefore only taken from interfaces whose
/// `carrier` file reads `1`, meaning the link is physically/virtually
/// connected. Combined with the delta check that wraps this function,
/// the air-gap signal becomes: traffic on a connected interface.
pub fn read_total_traffic_bytes() -> u64 {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return 0;
    };
    let mut total: u64 = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == "lo" {
            continue;
        }
        let path = entry.path();
        let has_carrier = std::fs::read_to_string(path.join("carrier"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        if !has_carrier {
            continue;
        }
        let stats = path.join("statistics");
        let rx = std::fs::read_to_string(stats.join("rx_bytes"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let tx = std::fs::read_to_string(stats.join("tx_bytes"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        total = total.saturating_add(rx).saturating_add(tx);
    }
    total
}

/// Spawn the background air-gap monitor. Every AIR_GAP_SAMPLE_INTERVAL
/// it samples the cumulative rx+tx bytes across all non-loopback
/// interfaces and compares to the previous sample. Delta of zero means
/// no IP-traffic in that window → cache `air_gapped = true`. Any delta
/// → cache `air_gapped = false`. Reads are async-safe (sysfs is
/// non-blocking) but this is kept on the runtime as a normal task.
///
/// **Advisory only.** This indicator gates no handler: operations run
/// regardless of its value. Its purpose is to surface a UI warning when
/// the air-gap is unexpectedly broken; it cannot detect file-transfer
/// channels (USB-passthrough, VM shared folders, Bluetooth OBEX, etc.).
/// The body validator and channel encryption are the actual security
/// boundaries.
pub fn spawn_air_gap_monitor() {
    const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
    tokio::spawn(async move {
        let mut prev = read_total_traffic_bytes();
        loop {
            tokio::time::sleep(SAMPLE_INTERVAL).await;
            let curr = read_total_traffic_bytes();
            let delta = curr.saturating_sub(prev);
            AIR_GAP_STATE.store(
                if delta == 0 { NO_TRAFFIC } else { TRAFFIC },
                Ordering::Relaxed,
            );
            prev = curr;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_claimed_before_the_first_measurement() {
        assert_eq!(claim(UNMEASURED), None);
        assert_eq!(claim(NO_TRAFFIC), Some(true));
        assert_eq!(claim(TRAFFIC), Some(false));
    }
}
