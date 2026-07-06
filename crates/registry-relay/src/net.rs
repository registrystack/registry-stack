// SPDX-License-Identifier: Apache-2.0
//! Trust-proxy-aware client address resolution, shared by the audit
//! middleware and the auth-failure throttle so both key on the same
//! resolved client address.
//!
//! When `trust_proxy_enabled` is false, or the socket peer is not itself
//! a trusted proxy, the resolved address is always the raw socket peer:
//! `X-Forwarded-For` is only honored from a peer the deployment has
//! explicitly configured as a trusted proxy.

use std::net::IpAddr;

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;

/// Resolve the client address for a request, walking `X-Forwarded-For`
/// from a trusted proxy peer to the rightmost hop that is not itself
/// trusted. Falls back to the raw socket peer when trust-proxy support
/// is disabled, the peer is untrusted, or the header is absent or
/// malformed.
pub(crate) fn resolve_remote_addr(
    headers: &HeaderMap,
    connect_info: Option<&ConnectInfo<std::net::SocketAddr>>,
    trust_proxy_enabled: bool,
    trusted_proxies: &[String],
) -> IpAddr {
    let peer = connect_info
        .map(|ConnectInfo(addr)| addr.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    if !trust_proxy_enabled || !trusted_proxy_contains(peer, trusted_proxies) {
        return peer;
    }

    x_forwarded_for_chain(headers)
        .map(|mut chain| {
            chain.push(peer);
            chain
                .iter()
                .rev()
                .find(|hop| !trusted_proxy_contains(**hop, trusted_proxies))
                .copied()
                .unwrap_or(peer)
        })
        .unwrap_or(peer)
}

fn x_forwarded_for_chain(headers: &HeaderMap) -> Option<Vec<IpAddr>> {
    let mut chain = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let value = value.to_str().ok()?;
        for hop in value.split(',') {
            let hop = hop.trim();
            if hop.is_empty() {
                return None;
            }
            chain.push(hop.parse::<IpAddr>().ok()?);
        }
    }
    if chain.is_empty() {
        None
    } else {
        Some(chain)
    }
}

fn trusted_proxy_contains(peer: IpAddr, trusted_proxies: &[String]) -> bool {
    trusted_proxies
        .iter()
        .any(|spec| trusted_proxy_spec_matches(peer, spec))
}

fn trusted_proxy_spec_matches(peer: IpAddr, spec: &str) -> bool {
    let trimmed = spec.trim();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return ip == peer;
    }
    let Some((addr, prefix)) = trimmed.split_once('/') else {
        return false;
    };
    let Ok(network) = addr.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match (peer, network) {
        (IpAddr::V4(peer), IpAddr::V4(network)) if prefix <= 32 => {
            let peer = u32::from(peer);
            let network = u32::from(network);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (peer & mask) == (network & mask)
        }
        (IpAddr::V6(peer), IpAddr::V6(network)) if prefix <= 128 => {
            let peer = u128::from(peer);
            let network = u128::from(network);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (peer & mask) == (network & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_proxy_cidr_matching_supports_v4_and_v6() {
        assert!(trusted_proxy_spec_matches(
            "10.1.2.3".parse().unwrap(),
            "10.0.0.0/8"
        ));
        assert!(!trusted_proxy_spec_matches(
            "11.1.2.3".parse().unwrap(),
            "10.0.0.0/8"
        ));
        assert!(trusted_proxy_spec_matches(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::/32"
        ));
    }
}
