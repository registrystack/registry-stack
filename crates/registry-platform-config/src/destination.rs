// SPDX-License-Identifier: Apache-2.0
//! How an outbound destination is reached, and the private ranges it may use.
//!
//! A destination block names its `transport` beside `allowedPrivateCidrs`.
//! `verified-tls` and `loopback-plaintext` are valid in every posture. Only
//! `private-network-plaintext` is an explicit production setting, so it reaches
//! the posture report and the startup log without refusing anything.
//! [`PrivateRanges`] is the `allowedPrivateCidrs` list: network addresses
//! inside RFC 1918, RFC 6598 or `fc00::/7`, written once each, at most
//! [`MAX_PRIVATE_RANGES`] of them. [`PrivateRange`] itself lives in
//! `registry-platform-loopback`, beside the eligibility checks it uses.

use std::fmt;
use std::net::IpAddr;

use registry_platform_loopback::{cloud_metadata_address, TransportClass};
pub use registry_platform_loopback::{PrivateRange, PrivateRangeError, MAX_PRIVATE_RANGES};
use registry_platform_yaml::{Diagnostic, UniqueList};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ExplicitClass, ExplicitProductionSetting, RuntimeFileCheck};

static DESTINATION_PRIVATE_PLAINTEXT: ExplicitProductionSetting = ExplicitProductionSetting {
    code: "platform.posture.destination-private-plaintext",
    key: "transport",
    summary: "An outbound destination is reached without TLS, inside declared private ranges",
};

/// How an outbound destination is reached.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DestinationTransport {
    /// https, with verification. Private addresses are admitted only inside
    /// `allowedPrivateCidrs`.
    VerifiedTls,
    /// http to `localhost` or a loopback address literal.
    LoopbackPlaintext,
    /// http to addresses that all lie inside `allowedPrivateCidrs`. The
    /// ranges must not be empty.
    PrivateNetworkPlaintext,
}

impl From<DestinationTransport> for TransportClass {
    fn from(transport: DestinationTransport) -> Self {
        match transport {
            DestinationTransport::VerifiedTls => Self::VerifiedTls,
            DestinationTransport::LoopbackPlaintext => Self::LoopbackPlaintext,
            DestinationTransport::PrivateNetworkPlaintext => Self::PrivateNetworkPlaintext,
        }
    }
}

impl ExplicitClass for DestinationTransport {
    const SETTINGS: &'static [&'static ExplicitProductionSetting] =
        &[&DESTINATION_PRIVATE_PLAINTEXT];

    fn explicit_setting(&self) -> Option<&'static ExplicitProductionSetting> {
        match self {
            Self::VerifiedTls | Self::LoopbackPlaintext => None,
            Self::PrivateNetworkPlaintext => Some(&DESTINATION_PRIVATE_PLAINTEXT),
        }
    }
}

/// Why a listed range is refused. Each has a stable code and one fix, which
/// reach the operator as the diagnostic's code and suggested action
/// (CFG-DIAG-3).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrivateRangeRefusal {
    /// Not a network address and a prefix length.
    Malformed,
    /// Not wholly inside private space.
    NotPrivate,
    /// A single cloud metadata address.
    MetadataAddress,
    /// The network address has host bits set.
    NotCanonical,
    /// More than [`MAX_PRIVATE_RANGES`] ranges are listed.
    TooMany,
}

impl PrivateRangeRefusal {
    /// The stable code of the refusal.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed => "platform.destination.range-malformed",
            Self::NotPrivate | Self::MetadataAddress => "platform.destination.range-not-private",
            Self::NotCanonical => "platform.destination.range-not-canonical",
            Self::TooMany => "platform.destination.too-many-ranges",
        }
    }

    /// What to write instead.
    #[must_use]
    pub const fn suggested_action(&self) -> &'static str {
        match self {
            Self::Malformed => {
                "Write each range as a network address and a prefix length, such as 172.16.0.0/12."
            }
            Self::NotPrivate => {
                "Name only private ranges: inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 or fc00::/7."
            }
            Self::MetadataAddress => "Remove the metadata address. A destination never reaches it.",
            Self::NotCanonical => "Write the network address, such as 10.0.0.0/8 and not 10.0.0.1/8.",
            Self::TooMany => "Merge ranges until at most 16 remain.",
        }
    }
}

/// The sentence names the problem and never repeats the value read from the file.
impl fmt::Display for PrivateRangeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "the range is not a network address and a prefix length",
            Self::NotPrivate => "the range is not wholly inside private space",
            Self::MetadataAddress => "the range is a single cloud metadata address",
            Self::NotCanonical => "the range has host bits set in its network address",
            Self::TooMany => "more than 16 ranges are listed",
        })
    }
}

impl std::error::Error for PrivateRangeRefusal {}

impl From<PrivateRangeError> for PrivateRangeRefusal {
    fn from(error: PrivateRangeError) -> Self {
        match error {
            PrivateRangeError::Malformed => Self::Malformed,
            PrivateRangeError::NotCanonical => Self::NotCanonical,
            PrivateRangeError::NotPrivate => Self::NotPrivate,
        }
    }
}

fn read_range(text: &str) -> Result<PrivateRange, PrivateRangeRefusal> {
    let range: PrivateRange = text.parse()?;
    if range.prefix() == address_bits(range.network()) && cloud_metadata_address(range.network()) {
        return Err(PrivateRangeRefusal::MetadataAddress);
    }
    Ok(range)
}

fn address_bits(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

/// One entry of the list: a range, or the refusal it earned. An entry that
/// is refused is never read back as a range.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Entry {
    Range(PrivateRange),
    /// The refusal and the item's position, so no two refused entries repeat
    /// each other.
    Refused(PrivateRangeRefusal, usize),
}

/// The `allowedPrivateCidrs` list: each entry a canonical [`PrivateRange`],
/// none repeated, at most [`MAX_PRIVATE_RANGES`]. An empty list admits none.
///
/// The list decodes whatever strings it holds, and a repeated range is refused
/// at decode as `config.duplicate-item`. Every other refusal carries its own
/// `platform.destination.*` code, reported by [`PrivateRanges::check`] and
/// [`PrivateRanges::check_file`], as a [`CallerIssuers`](crate::CallerIssuers)
/// finding is. [`PrivateRanges::ranges`] hands out ranges only when no entry
/// is refused, so a product that skips the check still fails at startup.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivateRanges {
    entries: Vec<Entry>,
}

impl PrivateRanges {
    /// The number of entries written, refused or not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The first refusal in the list, if any.
    fn first_refusal(&self) -> Option<PrivateRangeRefusal> {
        if self.entries.len() > MAX_PRIVATE_RANGES {
            return Some(PrivateRangeRefusal::TooMany);
        }
        self.entries.iter().find_map(|entry| match entry {
            Entry::Refused(refusal, _) => Some(*refusal),
            Entry::Range(_) => None,
        })
    }

    /// The ranges, in the order written, or the first refusal.
    pub fn ranges(&self) -> Result<Vec<PrivateRange>, PrivateRangeRefusal> {
        match self.first_refusal() {
            Some(refusal) => Err(refusal),
            None => Ok(self.valid().collect()),
        }
    }

    /// [`Self::ranges`], consuming the list.
    pub fn into_ranges(self) -> Result<Vec<PrivateRange>, PrivateRangeRefusal> {
        self.ranges()
    }

    fn valid(&self) -> impl Iterator<Item = PrivateRange> + '_ {
        self.entries.iter().filter_map(|entry| match entry {
            Entry::Range(range) => Some(*range),
            Entry::Refused(..) => None,
        })
    }

    /// Every refusal in the list as a diagnostic at `field`, the pointer of
    /// the list (`/hook/allowedPrivateCidrs`), or at `{field}/{index}` for an
    /// entry.
    #[must_use]
    pub fn check(&self, field: &str) -> Vec<Diagnostic> {
        self.refusals(field)
            .map(|(refusal, pointer)| {
                Diagnostic::error(
                    refusal.code(),
                    pointer,
                    refusal.to_string(),
                    refusal.suggested_action(),
                )
            })
            .collect()
    }

    /// [`Self::check`] for an offline check of `file`, whose document kind is
    /// `artifact`. Each diagnostic is positioned at the value it points at. An
    /// entry that holds an expression the check did not fill is skipped.
    #[must_use]
    pub fn check_file<T>(
        &self,
        field: &str,
        file: &RuntimeFileCheck<T>,
        artifact: &str,
    ) -> Vec<Diagnostic> {
        self.refusals(field)
            .filter(|(_, pointer)| pointer == field || !file.defers(pointer))
            .map(|(refusal, pointer)| {
                file.error_at(
                    artifact,
                    refusal.code(),
                    &pointer,
                    refusal.to_string(),
                    refusal.suggested_action(),
                )
            })
            .collect()
    }

    fn refusals<'a>(
        &'a self,
        field: &'a str,
    ) -> impl Iterator<Item = (PrivateRangeRefusal, String)> + 'a {
        let too_many = (self.entries.len() > MAX_PRIVATE_RANGES)
            .then(|| (PrivateRangeRefusal::TooMany, field.to_owned()));
        let entries =
            self.entries
                .iter()
                .enumerate()
                .filter_map(move |(index, entry)| match entry {
                    Entry::Refused(refusal, _) => Some((*refusal, format!("{field}/{index}"))),
                    Entry::Range(_) => None,
                });
        too_many.into_iter().chain(entries)
    }
}

impl Serialize for PrivateRanges {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some(refusal) = self.first_refusal() {
            return Err(serde::ser::Error::custom(refusal));
        }
        serializer.collect_seq(self.valid().map(|range| range.to_string()))
    }
}

impl<'de> Deserialize<'de> for PrivateRanges {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let texts = Vec::<String>::deserialize(deserializer)?;
        let entries: Vec<Entry> = texts
            .iter()
            .enumerate()
            .map(|(index, text)| match read_range(text) {
                Ok(range) => Entry::Range(range),
                Err(refusal) => Entry::Refused(refusal, index),
            })
            .collect();
        let unique = UniqueList::new(entries).map_err(serde::de::Error::custom)?;
        Ok(Self {
            entries: unique.into_vec(),
        })
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for PrivateRanges {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PrivateRanges".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "array",
            "items": {
                "type": "string",
                "pattern": "^[0-9a-fA-F.:]+/(0|[1-9][0-9]{0,2})$",
                "description": "A private network address and prefix length, such as 172.16.0.0/12. The address has no host bits set and lies inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 or fc00::/7. A single cloud metadata address is not a range.",
            },
            "maxItems": MAX_PRIVATE_RANGES,
            "uniqueItems": true,
        })
    }
}

#[cfg(test)]
#[path = "destination_tests.rs"]
mod tests;
