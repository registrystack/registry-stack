//! The one rule for an operator-private `metricsListener.bind`.
//!
//! The counters are operator material, so the metrics socket is loopback or
//! private, names a port, and is never a socket the product also serves. An
//! operator who cannot know the container address ahead of time declares
//! `networkExposure: container-private`, which also permits the wildcard.
//! Each product keeps its own problem codes and wording and maps
//! [`MetricsBindError`] onto them.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::ListenerNetworkExposure;

/// The rule a metrics bind failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricsBindError {
    /// The port is zero, which asks the kernel for an arbitrary port.
    PortZero,
    /// The address is the wildcard, `0.0.0.0` or `::`, and the exposure is not
    /// `container-private`.
    Unspecified,
    /// The address is multicast.
    Multicast,
    /// The address is link-local (IPv4 169.254.0.0/16 or IPv6 fe80::/10).
    LinkLocal,
    /// The address is an IPv4-mapped IPv6 form (`::ffff:a.b.c.d`). Write the
    /// IPv4 address instead.
    Ipv4Mapped,
    /// The address is neither loopback nor private (RFC 1918 or unique local
    /// `fc00::/7`).
    NotPrivate,
    /// The bind uses a socket the product also serves. Carries the name the
    /// caller gave that socket.
    OverlapsServedSocket(&'static str),
}

impl fmt::Display for MetricsBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PortZero => formatter.write_str("the port must be non-zero"),
            Self::Unspecified => formatter.write_str("the address must not be a wildcard"),
            Self::Multicast => formatter.write_str("the address must not be multicast"),
            Self::LinkLocal => formatter.write_str("the address must not be link-local"),
            Self::Ipv4Mapped => {
                formatter.write_str("the address must not be an IPv4-mapped IPv6 form")
            }
            Self::NotPrivate => formatter.write_str("the address must be loopback or private"),
            Self::OverlapsServedSocket(name) => {
                write!(formatter, "the bind must differ from the {name} socket")
            }
        }
    }
}

impl std::error::Error for MetricsBindError {}

/// Check a metrics bind against the address and port rules alone.
///
/// [`ListenerNetworkExposure::PrivateAddress`] requires a loopback or private
/// address. [`ListenerNetworkExposure::ContainerPrivate`] also permits the
/// unspecified address (`0.0.0.0` or `::`), for a container whose private
/// address is not known when the file is written. Every other refusal holds
/// under both values.
///
/// # Errors
///
/// The first rule the bind fails.
pub fn check_metrics_bind_address(
    bind: SocketAddr,
    exposure: ListenerNetworkExposure,
) -> Result<(), MetricsBindError> {
    let wildcard_permitted = exposure == ListenerNetworkExposure::ContainerPrivate;
    if bind.port() == 0 {
        return Err(MetricsBindError::PortZero);
    }
    match bind.ip() {
        IpAddr::V4(address) => {
            if address.is_unspecified() {
                unspecified_result(wildcard_permitted)
            } else if address.is_multicast() {
                Err(MetricsBindError::Multicast)
            } else if address.is_link_local() {
                Err(MetricsBindError::LinkLocal)
            } else if address.is_loopback() || address.is_private() {
                Ok(())
            } else {
                Err(MetricsBindError::NotPrivate)
            }
        }
        IpAddr::V6(address) => {
            if address.is_unspecified() {
                unspecified_result(wildcard_permitted)
            } else if address.is_multicast() {
                Err(MetricsBindError::Multicast)
            } else if address.to_ipv4_mapped().is_some() {
                Err(MetricsBindError::Ipv4Mapped)
            } else if address.segments()[0] & 0xffc0 == 0xfe80 {
                Err(MetricsBindError::LinkLocal)
            } else if address.is_loopback() || is_unique_local(address) {
                Ok(())
            } else {
                Err(MetricsBindError::NotPrivate)
            }
        }
    }
}

fn unspecified_result(permitted: bool) -> Result<(), MetricsBindError> {
    if permitted {
        Ok(())
    } else {
        Err(MetricsBindError::Unspecified)
    }
}

/// Check that a metrics bind occupies none of the sockets the product serves.
/// Each socket carries the name an error reports it by.
///
/// # Errors
///
/// [`MetricsBindError::OverlapsServedSocket`] for the first overlapping socket.
pub fn check_metrics_bind_apart(
    bind: SocketAddr,
    served: &[(&'static str, SocketAddr)],
) -> Result<(), MetricsBindError> {
    for (name, socket) in served {
        if sockets_overlap(bind, *socket) {
            return Err(MetricsBindError::OverlapsServedSocket(name));
        }
    }
    Ok(())
}

/// Check a metrics bind against every rule: the address and port rules, then
/// the sockets the product serves.
///
/// # Errors
///
/// The first rule the bind fails.
pub fn check_metrics_bind(
    bind: SocketAddr,
    exposure: ListenerNetworkExposure,
    served: &[(&'static str, SocketAddr)],
) -> Result<(), MetricsBindError> {
    check_metrics_bind_address(bind, exposure)?;
    check_metrics_bind_apart(bind, served)
}

/// Whether two socket addresses would occupy the same socket. IPv4-mapped
/// forms compare as their IPv4 address. An IPv6 wildcard is commonly
/// dual-stack, so it covers both families on every host. The IPv4 wildcard
/// covers only IPv4.
fn sockets_overlap(first: SocketAddr, second: SocketAddr) -> bool {
    if first.port() != second.port() {
        return false;
    }
    let (first, second) = (first.ip().to_canonical(), second.ip().to_canonical());
    let wildcard_covers = |wildcard: IpAddr, other: IpAddr| match wildcard {
        IpAddr::V4(wildcard) => wildcard.is_unspecified() && other.is_ipv4(),
        IpAddr::V6(wildcard) => wildcard.is_unspecified(),
    };
    first == second || wildcard_covers(first, second) || wildcard_covers(second, first)
}

fn is_unique_local(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;
    use ListenerNetworkExposure::{ContainerPrivate, PrivateAddress};

    fn bind(text: &str) -> SocketAddr {
        text.parse().expect("a socket address")
    }

    #[test]
    fn loopback_and_private_addresses_are_accepted() {
        for text in [
            "127.0.0.1:9100",
            "127.8.9.10:9100",
            "10.0.0.1:9100",
            "172.16.0.1:9100",
            "172.31.255.255:9100",
            "192.168.1.1:9100",
            "[::1]:9100",
            "[fc00::1]:9100",
            "[fd12:3456::1]:9100",
        ] {
            assert_eq!(
                check_metrics_bind_address(bind(text), PrivateAddress),
                Ok(()),
                "{text}"
            );
        }
    }

    #[test]
    fn each_refused_class_names_its_rule() {
        for (text, expected) in [
            ("127.0.0.1:0", MetricsBindError::PortZero),
            ("[::1]:0", MetricsBindError::PortZero),
            ("0.0.0.0:9100", MetricsBindError::Unspecified),
            ("[::]:9100", MetricsBindError::Unspecified),
            ("224.0.0.1:9100", MetricsBindError::Multicast),
            ("[ff02::1]:9100", MetricsBindError::Multicast),
            ("169.254.1.1:9100", MetricsBindError::LinkLocal),
            ("[fe80::1]:9100", MetricsBindError::LinkLocal),
            ("[febf:ffff::1]:9100", MetricsBindError::LinkLocal),
            ("8.8.8.8:9100", MetricsBindError::NotPrivate),
            ("172.32.0.1:9100", MetricsBindError::NotPrivate),
            ("100.64.0.1:9100", MetricsBindError::NotPrivate),
            ("[2606:4700::1111]:9100", MetricsBindError::NotPrivate),
            ("[fe00::1]:9100", MetricsBindError::NotPrivate),
        ] {
            assert_eq!(
                check_metrics_bind_address(bind(text), PrivateAddress),
                Err(expected),
                "{text}"
            );
        }
    }

    #[test]
    fn ipv4_mapped_forms_of_refused_addresses_are_refused() {
        for text in [
            "[::ffff:0.0.0.0]:9100",
            "[::ffff:224.0.0.1]:9100",
            "[::ffff:169.254.1.1]:9100",
            "[::ffff:8.8.8.8]:9100",
            "[::ffff:127.0.0.1]:9100",
            "[::ffff:10.0.0.1]:9100",
        ] {
            assert!(
                check_metrics_bind_address(bind(text), PrivateAddress).is_err(),
                "{text}"
            );
        }
        assert_eq!(
            check_metrics_bind_address(bind("[::ffff:8.8.8.8]:9100"), PrivateAddress),
            Err(MetricsBindError::Ipv4Mapped)
        );
    }

    #[test]
    fn an_exact_overlap_names_the_socket() {
        let served = [
            ("listener", bind("127.0.0.1:8080")),
            ("hook ingress", bind("10.0.0.5:8081")),
        ];
        assert_eq!(
            check_metrics_bind(bind("127.0.0.1:9100"), PrivateAddress, &served),
            Ok(())
        );
        assert_eq!(
            check_metrics_bind(bind("127.0.0.1:8080"), PrivateAddress, &served),
            Err(MetricsBindError::OverlapsServedSocket("listener"))
        );
        assert_eq!(
            check_metrics_bind(bind("10.0.0.5:8081"), PrivateAddress, &served),
            Err(MetricsBindError::OverlapsServedSocket("hook ingress"))
        );
        // The same port on another address is a different socket.
        assert_eq!(
            check_metrics_bind(bind("10.0.0.5:8080"), PrivateAddress, &served),
            Ok(())
        );
    }

    #[test]
    fn a_wildcard_serving_bind_on_the_same_port_overlaps() {
        let ipv4 = [("listener", bind("0.0.0.0:8080"))];
        assert_eq!(
            check_metrics_bind(bind("127.0.0.1:8080"), PrivateAddress, &ipv4),
            Err(MetricsBindError::OverlapsServedSocket("listener"))
        );
        // The IPv4 wildcard does not cover IPv6.
        assert_eq!(
            check_metrics_bind(bind("[::1]:8080"), PrivateAddress, &ipv4),
            Ok(())
        );
        assert_eq!(
            check_metrics_bind(bind("127.0.0.1:9100"), PrivateAddress, &ipv4),
            Ok(())
        );

        let ipv6 = [("listener", bind("[::]:8080"))];
        for text in ["[::1]:8080", "127.0.0.1:8080", "10.0.0.1:8080"] {
            assert_eq!(
                check_metrics_bind(bind(text), PrivateAddress, &ipv6),
                Err(MetricsBindError::OverlapsServedSocket("listener")),
                "{text}"
            );
        }
        assert_eq!(
            check_metrics_bind(bind("127.0.0.1:9100"), PrivateAddress, &ipv6),
            Ok(())
        );
    }

    #[test]
    fn an_ipv4_mapped_serving_bind_cannot_hide_an_overlap() {
        assert_eq!(
            check_metrics_bind_apart(
                bind("127.0.0.1:8080"),
                &[("listener", bind("[::ffff:127.0.0.1]:8080"))]
            ),
            Err(MetricsBindError::OverlapsServedSocket("listener"))
        );
        assert_eq!(
            check_metrics_bind_apart(
                bind("10.0.0.1:8080"),
                &[("listener", bind("[::ffff:0.0.0.0]:8080"))]
            ),
            Err(MetricsBindError::OverlapsServedSocket("listener"))
        );
    }

    #[test]
    fn the_address_rules_come_before_the_overlap_rule() {
        assert_eq!(
            check_metrics_bind(
                bind("0.0.0.0:8080"),
                PrivateAddress,
                &[("listener", bind("0.0.0.0:8080"))]
            ),
            Err(MetricsBindError::Unspecified)
        );
    }

    #[test]
    fn container_private_permits_the_unspecified_address() {
        for text in [
            "0.0.0.0:9100",
            "[::]:9100",
            "127.0.0.1:9100",
            "10.0.0.1:9100",
        ] {
            assert_eq!(
                check_metrics_bind_address(bind(text), ContainerPrivate),
                Ok(()),
                "{text}"
            );
        }
    }

    #[test]
    fn private_address_refuses_the_unspecified_address() {
        for text in ["0.0.0.0:9100", "[::]:9100"] {
            assert_eq!(
                check_metrics_bind_address(bind(text), PrivateAddress),
                Err(MetricsBindError::Unspecified),
                "{text}"
            );
        }
    }

    #[test]
    fn container_private_still_refuses_everything_else() {
        for (text, expected) in [
            ("0.0.0.0:0", MetricsBindError::PortZero),
            ("[::]:0", MetricsBindError::PortZero),
            ("224.0.0.1:9100", MetricsBindError::Multicast),
            ("[ff02::1]:9100", MetricsBindError::Multicast),
            ("169.254.1.1:9100", MetricsBindError::LinkLocal),
            ("[fe80::1]:9100", MetricsBindError::LinkLocal),
            ("8.8.8.8:9100", MetricsBindError::NotPrivate),
            ("[2606:4700::1111]:9100", MetricsBindError::NotPrivate),
            ("[::ffff:0.0.0.0]:9100", MetricsBindError::Ipv4Mapped),
            ("[::ffff:10.0.0.1]:9100", MetricsBindError::Ipv4Mapped),
        ] {
            assert_eq!(
                check_metrics_bind_address(bind(text), ContainerPrivate),
                Err(expected),
                "{text}"
            );
        }
    }

    #[test]
    fn a_wildcard_metrics_bind_on_a_served_port_overlaps() {
        let served = [("listener", bind("10.0.0.5:8080"))];
        assert_eq!(
            check_metrics_bind(bind("0.0.0.0:8080"), ContainerPrivate, &served),
            Err(MetricsBindError::OverlapsServedSocket("listener"))
        );
        assert_eq!(
            check_metrics_bind(bind("0.0.0.0:9100"), ContainerPrivate, &served),
            Ok(())
        );
        // The IPv4 wildcard does not cover an IPv6 socket.
        assert_eq!(
            check_metrics_bind(
                bind("0.0.0.0:8080"),
                ContainerPrivate,
                &[("listener", bind("[::1]:8080"))]
            ),
            Ok(())
        );
        // The IPv6 wildcard covers both families.
        for text in ["10.0.0.5:8080", "[::1]:8080"] {
            assert_eq!(
                check_metrics_bind(
                    bind("[::]:8080"),
                    ContainerPrivate,
                    &[("listener", bind(text))]
                ),
                Err(MetricsBindError::OverlapsServedSocket("listener")),
                "{text}"
            );
        }
    }
}
