//! The one definition of "loopback" for outbound destinations and loopback origins.
//! Bind sites keep their own, stricter rule. It also holds the one definition of
//! "private" for outbound destinations: which addresses and ranges are eligible
//! to be named private, the [`PrivateRange`] type and its bound.
//!
//! A host is loopback when it is an address literal in `127.0.0.0/8`, `::1`, or an
//! IPv4-mapped IPv6 form of an address in `127.0.0.0/8`, or when it is the exact
//! name `localhost` and the connection is made only to loopback addresses the
//! caller has checked. `*.localhost`, `localhost.` and every other name are never
//! loopback.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

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

/// How an outbound destination is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportClass {
    /// TLS with verification.
    VerifiedTls,
    /// No TLS, to the loopback interface only.
    LoopbackPlaintext,
    /// No TLS, to addresses inside declared private ranges only.
    PrivateNetworkPlaintext,
}

/// True for RFC 1918, RFC 6598 (carrier-grade NAT) and IPv6 unique local
/// addresses. An IPv4-mapped IPv6 address is judged as the IPv4 address it maps.
///
/// Eligible does not mean admitted. Two cloud metadata addresses lie inside
/// private space (`100.100.100.200` and `fd00:ec2::254`) and are eligible here.
/// A caller refuses a cloud metadata address ([`cloud_metadata_address`]) and
/// every always-denied address
/// before it asks this question, and decodes NAT64 forms itself.
#[must_use]
pub fn private_address_eligible(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(mapped) => private_ipv4(mapped),
            None => ip.is_unique_local(),
        },
        IpAddr::V4(ip) => private_ipv4(ip),
    }
}

/// The cloud instance-metadata addresses: `169.254.169.254` (AWS, GCP, Azure),
/// `100.100.100.200` (Alibaba Cloud) and `fd00:ec2::254` (AWS IPv6). An
/// IPv4-mapped IPv6 address is judged as the IPv4 address it maps. This is the
/// one list of them: every outbound guard calls it.
#[must_use]
pub fn cloud_metadata_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => metadata_ipv4(ip),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(mapped) => metadata_ipv4(mapped),
            None => ip == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
        },
    }
}

fn metadata_ipv4(ip: Ipv4Addr) -> bool {
    ip == Ipv4Addr::new(169, 254, 169, 254) || ip == Ipv4Addr::new(100, 100, 100, 200)
}

fn private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private() || (octets[0] == 100 && octets[1] & 0b1100_0000 == 0b0100_0000)
}

/// True when the whole range `network/prefix` lies inside RFC 1918, RFC 6598
/// or `fc00::/7`. The caller supplies the network address of the range. A
/// prefix longer than the address family allows is not eligible. As with
/// [`private_address_eligible`], eligible does not mean admitted.
#[must_use]
pub fn private_range_eligible(network: IpAddr, prefix: u8) -> bool {
    if prefix > address_bits(network) {
        return false;
    }
    match network {
        IpAddr::V4(address) => {
            (prefix >= 8 && ipv4_in_prefix(address, Ipv4Addr::new(10, 0, 0, 0), 8))
                || (prefix >= 12 && ipv4_in_prefix(address, Ipv4Addr::new(172, 16, 0, 0), 12))
                || (prefix >= 16 && ipv4_in_prefix(address, Ipv4Addr::new(192, 168, 0, 0), 16))
                || (prefix >= 10 && ipv4_in_prefix(address, Ipv4Addr::new(100, 64, 0, 0), 10))
        }
        IpAddr::V6(address) => {
            prefix >= 7 && ipv6_in_prefix(address, Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7)
        }
    }
}

fn address_bits(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

fn ipv4_in_prefix(ip: Ipv4Addr, network: Ipv4Addr, prefix_len: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
    u32::from(ip) & mask == u32::from(network) & mask
}

fn ipv6_in_prefix(ip: Ipv6Addr, network: Ipv6Addr, prefix_len: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - prefix_len).unwrap_or(0);
    u128::from(ip) & mask == u128::from(network) & mask
}

/// The most ranges one destination lists.
pub const MAX_PRIVATE_RANGES: usize = 16;

/// Why text is not a [`PrivateRange`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrivateRangeError {
    /// Not a network address and a prefix length written as `address/prefix`.
    Malformed,
    /// The address has host bits set.
    NotCanonical,
    /// The range is not wholly inside RFC 1918, RFC 6598 or `fc00::/7`.
    NotPrivate,
}

impl fmt::Display for PrivateRangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "not a network address and a prefix length",
            Self::NotCanonical => "the network address has host bits set",
            Self::NotPrivate => "not wholly inside private space",
        })
    }
}

impl std::error::Error for PrivateRangeError {}

/// One private range: a canonical network address and its prefix length,
/// wholly inside RFC 1918, RFC 6598 or `fc00::/7`.
///
/// The range may contain a cloud metadata address, and may be exactly one. A
/// caller refuses a cloud metadata address before it consults a range, as
/// [`private_address_eligible`] explains.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PrivateRange {
    network: IpAddr,
    prefix: u8,
}

impl PrivateRange {
    /// The network address.
    #[must_use]
    pub const fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length in bits.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` lies inside the range. An IPv4-mapped IPv6 address is
    /// judged as the IPv4 address it maps.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                ipv4_in_prefix(address, network, u32::from(self.prefix))
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                ipv6_in_prefix(address, network, u32::from(self.prefix))
            }
            _ => false,
        }
    }
}

impl FromStr for PrivateRange {
    type Err = PrivateRangeError;

    /// `address/prefix`, the address as `std` reads it and the prefix in
    /// decimal with no sign and no leading zero.
    fn from_str(text: &str) -> Result<Self, PrivateRangeError> {
        let (address, length) = text.split_once('/').ok_or(PrivateRangeError::Malformed)?;
        let network: IpAddr = address.parse().map_err(|_| PrivateRangeError::Malformed)?;
        let prefix = prefix_length(length).ok_or(PrivateRangeError::Malformed)?;
        if prefix > address_bits(network) {
            return Err(PrivateRangeError::Malformed);
        }
        if host_bits_set(network, prefix) {
            return Err(PrivateRangeError::NotCanonical);
        }
        if !private_range_eligible(network, prefix) {
            return Err(PrivateRangeError::NotPrivate);
        }
        Ok(Self { network, prefix })
    }
}

impl fmt::Display for PrivateRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix)
    }
}

/// Decimal digits only, at most three, and no leading zero.
fn prefix_length(text: &str) -> Option<u8> {
    let digits = !text.is_empty() && text.len() <= 3 && text.bytes().all(|b| b.is_ascii_digit());
    if !digits || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

fn host_bits_set(network: IpAddr, prefix: u8) -> bool {
    match network {
        IpAddr::V4(address) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(address) & !mask != 0
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(address) & !mask != 0
        }
    }
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

    #[test]
    fn private_addresses_are_rfc1918_cgnat_ula_and_their_mapped_forms() {
        for ip in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "fc00::1",
            "fd00:1::5",
            "fd00:ec2::254",
            "::ffff:10.20.3.4",
        ] {
            assert!(private_address_eligible(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "93.184.216.34",
            "2606:4700::1111",
            "172.15.255.255",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.0",
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "169.254.169.254",
            "192.0.2.1",
            "224.0.0.1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:8.8.8.8",
            "64:ff9b::a14:304",
        ] {
            assert!(!private_address_eligible(ip.parse().unwrap()), "{ip}");
        }
    }

    fn range(text: &str) -> (IpAddr, u8) {
        let (network, prefix) = text.split_once('/').unwrap();
        (network.parse().unwrap(), prefix.parse().unwrap())
    }

    #[test]
    fn private_ranges_are_wholly_inside_rfc1918_cgnat_or_ula() {
        for text in [
            "10.0.0.0/8",
            "10.1.2.0/24",
            "172.16.0.0/12",
            "172.31.255.255/32",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "100.127.255.255/32",
            "fc00::/7",
            "fd12:3456::/32",
        ] {
            let (network, prefix) = range(text);
            assert!(private_range_eligible(network, prefix), "{text}");
        }
        for text in [
            "0.0.0.0/0",
            "10.0.0.0/7",
            "100.0.0.0/9",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "192.0.2.0/24",
            "198.18.0.0/15",
            "224.0.0.0/4",
            "::/0",
            "fe80::/10",
            "2001:2::/48",
            "2001:db8::/32",
            "3fff::/20",
            "ff00::/8",
        ] {
            let (network, prefix) = range(text);
            assert!(!private_range_eligible(network, prefix), "{text}");
        }
    }

    #[test]
    fn addresses_that_are_not_private_are_not_eligible() {
        for ip in [
            "::",
            "255.255.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "fec0::1",
            "::a00:1",
            "2002:a00:1::",
            "::ffff:169.254.169.254",
        ] {
            assert!(!private_address_eligible(ip.parse().unwrap()), "{ip}");
        }
    }

    /// Eligible does not mean admitted: a caller refuses a cloud metadata
    /// address before it asks this question.
    #[test]
    fn eligible_is_not_admitted_for_the_metadata_addresses_inside_private_space() {
        for ip in [
            "100.100.100.200",
            "::ffff:100.100.100.200",
            "::ffff:100.64.0.1",
            "::ffff:192.168.0.1",
            "fd00:ec2::254",
        ] {
            assert!(private_address_eligible(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn ranges_that_are_not_wholly_private_are_not_eligible() {
        for text in [
            "fc00::/6",
            "fe00::/7",
            "172.16.0.0/11",
            "192.168.0.0/15",
            "100.64.0.0/9",
            "::ffff:10.0.0.0/104",
        ] {
            let (network, prefix) = range(text);
            assert!(!private_range_eligible(network, prefix), "{text}");
        }
        let (network, prefix) = range("fd00:ec2::/32");
        assert!(private_range_eligible(network, prefix));
    }

    #[test]
    fn a_prefix_wider_than_the_family_is_not_eligible() {
        assert!(!private_range_eligible("10.0.0.0".parse().unwrap(), 33));
        assert!(!private_range_eligible("10.0.0.0".parse().unwrap(), 200));
        assert!(!private_range_eligible("fd00::".parse().unwrap(), 129));
    }

    fn parsed(text: &str) -> PrivateRange {
        text.parse().unwrap_or_else(|e| panic!("{text}: {e:?}"))
    }

    #[test]
    fn a_range_parses_and_displays_as_written_in_canonical_form() {
        for text in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "100.64.0.0/10",
            "fd12:3456::/32",
        ] {
            assert_eq!(parsed(text).to_string(), text);
        }
        let upper = parsed("FD00::/8");
        assert_eq!(upper, parsed("fd00:0:0:0:0:0:0:0/8"));
        assert_eq!(upper.to_string(), "fd00::/8");
        assert_eq!(upper.network(), "fd00::".parse::<IpAddr>().unwrap());
        assert_eq!(upper.prefix(), 8);
    }

    #[test]
    fn text_that_is_not_a_range_is_malformed() {
        for text in [
            "10.0.0.0",
            "10.0.0.0/",
            "/8",
            "",
            "hooks/8",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/+8",
            "10.0.0.0/08",
            "10.0.0.0/0000000008",
            "10.0.0.0/-1",
            "10.0.0.0/8/8",
            "fd00::%eth0/8",
            "fd00::%1/8",
            " 10.0.0.0/8",
            "10.0.0.0/8 ",
            "10.0.0.0 /8",
            "[fd00::]/8",
            "010.0.0.0/8",
        ] {
            assert_eq!(
                text.parse::<PrivateRange>(),
                Err(PrivateRangeError::Malformed),
                "{text:?}"
            );
        }
    }

    #[test]
    fn host_bits_make_a_range_not_canonical() {
        for text in ["10.0.0.1/8", "172.16.0.1/12", "fd00::1/8", "10.0.0.0/0"] {
            assert_eq!(
                text.parse::<PrivateRange>(),
                Err(PrivateRangeError::NotCanonical),
                "{text}"
            );
        }
    }

    #[test]
    fn a_range_outside_private_space_is_not_private() {
        for text in [
            "0.0.0.0/32",
            "169.254.0.0/16",
            "::/0",
            "127.0.0.0/8",
            "::ffff:10.0.0.0/104",
            "::ffff:100.100.100.200/128",
        ] {
            assert_eq!(
                text.parse::<PrivateRange>(),
                Err(PrivateRangeError::NotPrivate),
                "{text}"
            );
        }
    }

    #[test]
    fn a_range_contains_the_addresses_inside_it_and_their_mapped_forms() {
        let ten = parsed("10.0.0.0/8");
        for ip in ["10.0.0.1", "10.255.255.255", "::ffff:10.1.2.3"] {
            assert!(ten.contains(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["11.0.0.1", "9.255.255.255", "fd00::1", "::ffff:11.0.0.1"] {
            assert!(!ten.contains(ip.parse().unwrap()), "{ip}");
        }
        let ula = parsed("fd00::/8");
        assert!(ula.contains("fd12::1".parse().unwrap()));
        assert!(!ula.contains("fc00::1".parse().unwrap()));
        assert!(!ula.contains("10.0.0.1".parse().unwrap()));
        let host = parsed("172.31.255.255/32");
        assert!(host.contains("172.31.255.255".parse().unwrap()));
        assert!(!host.contains("172.31.255.254".parse().unwrap()));
    }

    #[test]
    fn the_cloud_metadata_addresses_are_exactly_these_and_their_mapped_forms() {
        for ip in [
            "169.254.169.254",
            "100.100.100.200",
            "fd00:ec2::254",
            "::ffff:169.254.169.254",
            "::ffff:100.100.100.200",
        ] {
            assert!(cloud_metadata_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "169.254.169.253",
            "100.100.100.201",
            "169.254.0.1",
            "fd00:ec2::255",
            "fd00:ec2::253",
            "::ffff:10.0.0.1",
            "10.0.0.1",
            "::",
        ] {
            assert!(!cloud_metadata_address(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn the_bound_is_sixteen() {
        assert_eq!(MAX_PRIVATE_RANGES, 16);
    }
}
