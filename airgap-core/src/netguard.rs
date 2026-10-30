//! Tell a public internet address from one that must never be fetched on
//! an operator's behalf.
//!
//! The online tools fetch a document from an operator-supplied URL to hash
//! it. Without a guard that fetch can be pointed at the machine itself, at
//! the local network, or at a cloud metadata endpoint. The classification
//! lives here, std-only, so every tool applies the same list; the network
//! code that uses it stays in the online binaries (the signers never fetch
//! anything).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// True when `ip` is a globally routable unicast address: not loopback,
/// private, link-local, carrier-grade NAT, multicast, reserved or
/// documentation space, and not an IPv6 form that wraps such an IPv4
/// address.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

/// When `host` is an IP literal (with or without the brackets a URL puts
/// around IPv6), say whether it is public. `None` means `host` is a name
/// that still has to be resolved.
pub fn host_literal_is_public(host: &str) -> Option<bool> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<IpAddr>().ok().map(is_public_ip)
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0                                   // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (o[1] & 0xC0) == 64)        // 100.64.0.0/10 carrier-grade NAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // 192.0.0.0/24 protocol assignments
        || (o[0] == 198 && (o[1] & 0xFE) == 18)        // 198.18.0.0/15 benchmarking
        || o[0] >= 240) // 240.0.0.0/4 reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    // Forms that carry an IPv4 address are as public as that address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let embedded =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    if s[..6] == [0, 0, 0, 0, 0, 0] {
        return is_public_v4(embedded(s[6], s[7])); // ::a.b.c.d (IPv4-compatible)
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_public_v4(embedded(s[6], s[7])); // 64:ff9b::/96 NAT64
    }
    if s[0] == 0x2002 {
        return is_public_v4(embedded(s[1], s[2])); // 2002::/16 6to4
    }
    !((s[0] & 0xfe00) == 0xfc00                        // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80                   // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0                   // fec0::/10 site-local (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8)          // 2001:db8::/32 documentation
        || (s[0] == 0x2001 && s[1] == 0)               // 2001::/32 Teredo
        || (s[0] == 0x2001 && s[1] == 2 && s[2] == 0)  // 2001:2::/48 benchmarking
        || s[..4] == [0x100, 0, 0, 0]                  // 100::/64 discard-only
        || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)) // 64:ff9b:1::/48 local-use NAT64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(s: &str) -> bool {
        is_public_ip(s.parse().unwrap())
    }

    #[test]
    fn public_addresses_pass() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "198.17.0.1",
            "198.20.0.1",
            "2606:4700:4700::1111",
            "2a00:1450:4001::200e",
        ] {
            assert!(public(ip), "{ip} should be public");
        }
    }

    #[test]
    fn internal_and_special_addresses_are_refused() {
        for ip in [
            "127.0.0.1",
            "127.255.255.254",
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "2001:0:1::1",
            "64:ff9b:1::1",
        ] {
            assert!(!public(ip), "{ip} should be refused");
        }
    }

    #[test]
    fn ipv6_forms_that_wrap_ipv4_follow_the_ipv4_verdict() {
        assert!(!public("::ffff:127.0.0.1"));
        assert!(!public("::ffff:169.254.169.254"));
        assert!(!public("::ffff:10.0.0.1"));
        assert!(public("::ffff:1.1.1.1"));
        assert!(!public("::10.0.0.1"));
        assert!(!public("64:ff9b::7f00:1"));
        assert!(!public("64:ff9b::a9fe:a9fe"));
        assert!(public("64:ff9b::101:101"));
        assert!(!public("2002:7f00:1::1"));
        assert!(!public("2002:c0a8:101::1"));
        assert!(public("2002:101:101::1"));
    }

    #[test]
    fn host_literals() {
        assert_eq!(host_literal_is_public("127.0.0.1"), Some(false));
        assert_eq!(host_literal_is_public("[::1]"), Some(false));
        assert_eq!(host_literal_is_public("::1"), Some(false));
        assert_eq!(host_literal_is_public("[2606:4700:4700::1111]"), Some(true));
        assert_eq!(host_literal_is_public("1.1.1.1"), Some(true));
        assert_eq!(host_literal_is_public("example.org"), None);
        assert_eq!(host_literal_is_public("localhost"), None);
        // Not an IP literal in the std parser, so it is treated as a name.
        assert_eq!(host_literal_is_public("0x7f.1"), None);
    }

    #[test]
    fn benchmarking_and_discard_blocks_are_not_public() {
        for a in [
            "2001:2::1",
            "2001:2:0:ffff::1",
            "100::1",
            "100::ffff:ffff:ffff:ffff",
        ] {
            assert!(!is_public_ip(a.parse().unwrap()), "{a}");
        }
        // Their neighbours stay public.
        for a in ["2001:2:1::1", "100:0:0:1::1"] {
            assert!(is_public_ip(a.parse().unwrap()), "{a}");
        }
    }
}
