//! Air-gap heuristic for the signer.
//!
//! Background task that compares cumulative rx+tx bytes across linked
//! interfaces every few seconds. A zero-delta sample → cache
//! `air_gapped = true`. Any traffic on a connected interface flips it to
//! `false`.
//!
//! **Advisory only.** This indicator gates no handler — operations run
//! regardless of its value. The body validator and channel encryption
//! are the actual security boundaries; the air-gap flag is just a UI hint.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Cached air-gap status, written by the background monitor task and
/// read by `signer_status`. Starts at `true` so the gap between boot and
/// the first sample does not flash "online" on the operator's screen;
/// the monitor flips it to `false` within one sample interval if it
/// observes traffic on a connected interface.
pub(crate) static AIR_GAPPED: AtomicBool = AtomicBool::new(true);

/// Sum of rx_bytes + tx_bytes across non-loopback interfaces with a
/// live link (`carrier=1`). The kernel exposes per-interface counters
/// in `/sys/class/net/<iface>/statistics/{rx,tx}_bytes`, but a live OS
/// keeps generating background traffic (DHCP DISCOVER, ARP probes,
/// mDNS) on interfaces that are administratively up even when no
/// link is actually present — typical case: VM with "Cable Connected"
/// disabled. Counters are therefore only taken from interfaces whose
/// `carrier` file reads `1`, meaning the link is physically/virtually
/// connected. Combined with the delta check that wraps this function,
/// the air-gap signal becomes: traffic on a connected interface.
pub(crate) fn read_total_traffic_bytes() -> u64 {
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
/// **Advisory only.** This indicator gates no handler — operations run
/// regardless of its value. Its purpose is to surface a UI warning when
/// the air-gap is unexpectedly broken; it cannot detect file-transfer
/// channels (USB-passthrough, VM shared folders, Bluetooth OBEX, etc.).
/// The body validator and channel encryption are the actual security
/// boundaries.
pub(crate) fn spawn_air_gap_monitor() {
    const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
    tokio::spawn(async move {
        let mut prev = read_total_traffic_bytes();
        loop {
            tokio::time::sleep(SAMPLE_INTERVAL).await;
            let curr = read_total_traffic_bytes();
            let delta = curr.saturating_sub(prev);
            AIR_GAPPED.store(delta == 0, Ordering::Relaxed);
            prev = curr;
        }
    });
}
