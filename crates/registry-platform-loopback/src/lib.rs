//! The one definition of "loopback" for outbound destinations and loopback origins.
//! Bind sites keep their own, stricter rule.
//!
//! A host is loopback when it is an address literal in `127.0.0.0/8`, `::1`, or an
//! IPv4-mapped IPv6 form of an address in `127.0.0.0/8`, or when it is the exact
//! name `localhost` and the connection is made only to loopback addresses the
//! caller has checked. `*.localhost`, `localhost.` and every other name are never
//! loopback.

use std::net::{IpAddr, Ipv6Addr};

/// The one name that may stand for the loopback interface.
const LOCALHOST: &str = "localhost";

/// True for `127.0.0.0/8`, `::1`, and IPv4-mapped IPv6 forms of `127.0.0.0/8`.
#[must_use]
pub fn loopback_address(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// How a host text claims to be loopback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopbackHost {
    /// An address literal that is loopback.
    Literal(IpAddr),
    /// The exact name `localhost`. It is loopback only when
    /// [`LoopbackHost::pinned_by`] holds for the addresses the connection uses.
    LocalhostName,
}

impl LoopbackHost {
    /// `Literal` is always pinned. `LocalhostName` is pinned when `resolved` is not
    /// empty and every address in it is a loopback address.
    #[must_use]
    pub fn pinned_by(self, resolved: &[IpAddr]) -> bool {
        match self {
            Self::Literal(_) => true,
            Self::LocalhostName => {
                !resolved.is_empty() && resolved.iter().all(|ip| loopback_address(*ip))
            }
        }
    }
}

/// Classify a URL host. `[::1]` and `::1` are both accepted. Returns `None` for every
/// other host.
///
/// `loopback_host(..).is_some()` treats the bare name `localhost` as loopback. A
/// site that accepts the name that way must also pin the connection to loopback
/// addresses, as [`LoopbackHost::pinned_by`] checks, or a hosts file or resolver
/// can send it off the machine. A site that cannot pin uses [`loopback_literal`].
#[must_use]
pub fn loopback_host(host: &str) -> Option<LoopbackHost> {
    if host.eq_ignore_ascii_case(LOCALHOST) {
        return Some(LoopbackHost::LocalhostName);
    }
    loopback_literal(host).map(LoopbackHost::Literal)
}

/// The literal arm alone, for a site that cannot pin a name. Brackets are
/// accepted around an IPv6 literal only, as in a URL host.
#[must_use]
pub fn loopback_literal(host: &str) -> Option<IpAddr> {
    let ip = match host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(inner) => IpAddr::V6(inner.parse::<Ipv6Addr>().ok()?),
        None => host.parse().ok()?,
    };
    loopback_address(ip).then_some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_claims_are_exactly_the_literals_and_the_name() {
        for host in [
            "127.0.0.1",
            "127.255.255.254",
            "::1",
            "[::1]",
            "::ffff:127.0.0.1",
            "[::ffff:127.0.0.1]",
            "localhost",
            "LOCALHOST",
        ] {
            assert!(loopback_host(host).is_some(), "{host} is a loopback claim");
        }
        for host in [
            "localhost.",
            "a.localhost",
            "127.0.0.1.example",
            "0.0.0.0",
            "::",
            "10.0.0.1",
            "169.254.169.254",
            "[::ffff:10.0.0.1]",
            "[::1",
            "::1]",
            "[127.0.0.1]",
            "[127.0.0.2]",
            "[localhost]",
            "",
        ] {
            assert!(
                loopback_host(host).is_none(),
                "{host:?} is not a loopback claim"
            );
        }
    }

    #[test]
    fn the_name_is_a_name_claim_and_the_rest_are_literals() {
        assert_eq!(
            loopback_host("LocalHost"),
            Some(LoopbackHost::LocalhostName)
        );
        assert_eq!(
            loopback_host("127.0.0.2"),
            Some(LoopbackHost::Literal("127.0.0.2".parse().unwrap()))
        );
        assert!(loopback_literal("localhost").is_none());
        assert!(loopback_literal("[::1]").is_some());
        assert!(loopback_literal("[::ffff:127.0.0.1]").is_some());
        assert!(
            loopback_literal("[127.0.0.1]").is_none(),
            "a bracketed IPv4 literal is not a URL host"
        );
    }

    #[test]
    fn a_name_claim_needs_every_resolved_address_to_be_loopback() {
        let name = LoopbackHost::LocalhostName;
        let v4: IpAddr = "127.0.0.1".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!name.pinned_by(&[]));
        assert!(name.pinned_by(&[v4, v6, mapped]));
        assert!(!name.pinned_by(&[v4, other]));
        assert!(!name.pinned_by(&[other, v6]));
        assert!(LoopbackHost::Literal(v4).pinned_by(&[]));
    }

    #[test]
    fn loopback_address_covers_the_block_and_mapped_forms() {
        for ip in ["127.0.0.1", "127.9.9.9", "::1", "::ffff:127.0.0.1"] {
            assert!(loopback_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["0.0.0.0", "::", "10.0.0.1", "::ffff:10.0.0.1", "fe80::1"] {
            assert!(!loopback_address(ip.parse().unwrap()), "{ip}");
        }
    }
}
