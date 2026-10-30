//! The message a binary prints when it cannot listen on its address.

use std::net::SocketAddr;

/// Explain a failed bind. A port another process already holds is by far
/// the most common cause, so that case names the way out.
pub fn listen_error(addr: SocketAddr, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::AddrInUse {
        format!(
            "port {} on {} is already in use. Stop the other process or pick another port with --listen",
            addr.port(),
            addr.ip()
        )
    } else {
        format!("cannot listen on {addr}: {e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_taken_port_names_the_way_out() {
        let addr: SocketAddr = "127.0.0.1:8400".parse().unwrap();
        let taken = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        assert_eq!(
            listen_error(addr, &taken),
            "port 8400 on 127.0.0.1 is already in use. Stop the other process or pick another port with --listen"
        );
        let other = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(listen_error(addr, &other).starts_with("cannot listen on 127.0.0.1:8400"));
    }
}
