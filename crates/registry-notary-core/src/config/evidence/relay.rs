// SPDX-License-Identifier: Apache-2.0
//! Sealed Registry Relay connection configuration.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path};

use ipnet::IpNet;

use super::*;

const MAX_RELAY_BASE_URL_BYTES: usize = 2_048;
const MAX_RELAY_TOKEN_FILE_BYTES: usize = 4_096;
const MAX_RELAY_PRIVATE_CIDRS: usize = 16;
const MAX_RELAY_IN_FLIGHT: usize = 64;

const fn default_relay_max_in_flight() -> usize {
    8
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConnectionConfig {
    pub base_url: String,
    pub workload_client_id: String,
    pub token_file: PathBuf,
    #[serde(default)]
    pub allowed_private_cidrs: Vec<IpNet>,
    #[serde(default)]
    pub allow_insecure_localhost: bool,
    #[serde(default = "default_relay_max_in_flight")]
    pub max_in_flight: usize,
}

impl std::fmt::Debug for RelayConnectionConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayConnectionConfig")
            .field("base_url", &"<redacted>")
            .field("token_file", &"<redacted>")
            .field(
                "allowed_private_cidr_count",
                &self.allowed_private_cidrs.len(),
            )
            .field("allow_insecure_localhost", &self.allow_insecure_localhost)
            .field("max_in_flight", &self.max_in_flight)
            .finish()
    }
}

impl RelayConnectionConfig {
    pub(in crate::config) fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.base_url.is_empty()
            || self.base_url.len() > MAX_RELAY_BASE_URL_BYTES
            || self.base_url.trim() != self.base_url
        {
            return invalid_relay("base_url must be a non-empty URL of bounded length");
        }
        if !stable_workload_id(&self.workload_client_id) {
            return invalid_relay(
                "workload_client_id must be a stable lowercase workload identifier",
            );
        }
        let Some(origin) = parse_relay_origin(&self.base_url) else {
            return invalid_relay(
                "base_url must be an absolute HTTP(S) origin with path exactly / and no credentials, query, or fragment",
            );
        };
        match origin.scheme() {
            "https" => {}
            "http" if self.allow_insecure_localhost && is_loopback_origin(&origin) => {}
            "http" => {
                return invalid_relay(
                    "base_url must use https unless allow_insecure_localhost permits an HTTP loopback URL",
                );
            }
            _ => return invalid_relay("base_url must use the http or https scheme"),
        }
        if !valid_token_file(&self.token_file) {
            return invalid_relay("token_file must be a bounded absolute canonical file path");
        }
        validate_private_cidrs(&self.allowed_private_cidrs)?;
        if !(1..=MAX_RELAY_IN_FLIGHT).contains(&self.max_in_flight) {
            return invalid_relay("max_in_flight must be between 1 and 64");
        }
        Ok(())
    }

    #[must_use]
    pub fn uses_insecure_url(&self) -> bool {
        self.base_url.starts_with("http://")
    }
}

fn stable_workload_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 96
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn is_loopback_origin(origin: &url::Url) -> bool {
    match origin.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(_)) | None => false,
    }
}

fn parse_relay_origin(value: &str) -> Option<url::Url> {
    let (scheme, rest) = value.split_once("://")?;
    if !matches!(scheme, "http" | "https") || rest.is_empty() || rest.contains(['?', '#']) {
        return None;
    }
    // Check the raw shape before URL normalization so `/private/..` cannot
    // normalize into the accepted root origin.
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() || authority.contains('/') {
        return None;
    }
    let origin = url::Url::parse(value).ok()?;
    (!origin.cannot_be_a_base()
        && origin.host().is_some()
        && origin.port() != Some(0)
        && origin.username().is_empty()
        && origin.password().is_none()
        && origin.path() == "/"
        && origin.query().is_none()
        && origin.fragment().is_none())
    .then_some(origin)
}

fn valid_token_file(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    !text.is_empty()
        && text.len() <= MAX_RELAY_TOKEN_FILE_BYTES
        && path.is_absolute()
        && path.file_name().is_some()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

fn validate_private_cidrs(cidrs: &[IpNet]) -> Result<(), EvidenceConfigError> {
    if cidrs.len() > MAX_RELAY_PRIVATE_CIDRS {
        return invalid_relay("allowed_private_cidrs cannot contain more than 16 entries");
    }
    let mut seen = BTreeSet::new();
    for cidr in cidrs {
        if cidr.trunc() != *cidr
            || !eligible_private_cidr(*cidr)
            || metadata_singleton(*cidr)
            || !seen.insert(*cidr)
        {
            return invalid_relay(
                "allowed_private_cidrs must contain unique canonical RFC 1918, RFC 6598, or IPv6 ULA networks",
            );
        }
    }
    Ok(())
}

fn eligible_private_cidr(cidr: IpNet) -> bool {
    match cidr {
        IpNet::V4(cidr) => {
            let address = cidr.network();
            let prefix = cidr.prefix_len();
            (prefix >= 8 && ipv4_in_prefix(address, Ipv4Addr::new(10, 0, 0, 0), 8))
                || (prefix >= 12 && ipv4_in_prefix(address, Ipv4Addr::new(172, 16, 0, 0), 12))
                || (prefix >= 16 && ipv4_in_prefix(address, Ipv4Addr::new(192, 168, 0, 0), 16))
                || (prefix >= 10 && ipv4_in_prefix(address, Ipv4Addr::new(100, 64, 0, 0), 10))
        }
        IpNet::V6(cidr) => {
            cidr.prefix_len() >= 7
                && ipv6_in_prefix(
                    cidr.network(),
                    Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
                    7,
                )
        }
    }
}

fn ipv4_in_prefix(address: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX << (32 - prefix);
    u32::from(address) & mask == u32::from(network) & mask
}

fn ipv6_in_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let mask = u128::MAX << (128 - prefix);
    u128::from(address) & mask == u128::from(network) & mask
}

fn metadata_singleton(cidr: IpNet) -> bool {
    match cidr {
        IpNet::V4(cidr) if cidr.prefix_len() == 32 => {
            IpAddr::V4(cidr.network()) == IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200))
        }
        IpNet::V6(cidr) if cidr.prefix_len() == 128 => {
            IpAddr::V6(cidr.network())
                == IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254))
        }
        _ => false,
    }
}

fn invalid_relay<T>(reason: &str) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidRelayConfig {
        reason: reason.to_string(),
    })
}
