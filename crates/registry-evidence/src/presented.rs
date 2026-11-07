//! Trusted facts a holder-presented host protocol hands to assertion
//! construction.
//!
//! A host protocol verifier attaches [`PresentedFacts`] to its verified
//! response through the Adapter engine's opaque attachment. Assertion
//! construction reads the channel and the presented credential members from
//! this value alone; nothing a source script emits can set them.

use chrono::{DateTime, Utc};

use crate::model::{AssertionChannel, PresentedCredential};

/// The verified credential a holder presented, with the instant it stops
/// being acceptable.
#[derive(Clone, PartialEq, Eq)]
pub struct PresentedFacts {
    credential: PresentedCredential,
    expires_at: DateTime<Utc>,
}

impl PresentedFacts {
    /// State a verified presented credential and its own expiry (`exp`).
    ///
    /// The expiry is required: an assertion built from these facts is never
    /// valid beyond it.
    #[must_use]
    pub fn new(credential: PresentedCredential, expires_at: DateTime<Utc>) -> Self {
        Self {
            credential,
            expires_at,
        }
    }

    #[must_use]
    pub fn credential(&self) -> &PresentedCredential {
        &self.credential
    }

    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl std::fmt::Debug for PresentedFacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PresentedFacts")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// The channel and validity cap assertion construction uses.
///
/// Without presented facts the channel is `source` and the cap is the
/// source's own. With them the channel is `holder-presented` carrying the
/// credential members, and the cap is the earlier of the source's deadline
/// and the credential's expiry.
pub(crate) fn construction_channel(
    presented: Option<&PresentedFacts>,
    source_valid_until: Option<DateTime<Utc>>,
) -> (AssertionChannel, Option<DateTime<Utc>>) {
    match presented {
        None => (AssertionChannel::Source, source_valid_until),
        Some(facts) => (
            AssertionChannel::HolderPresented(facts.credential.clone()),
            Some(
                source_valid_until.map_or(facts.expires_at, |source| source.min(facts.expires_at)),
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ChannelKind, SubjectLinkMode};

    fn instant(text: &str) -> DateTime<Utc> {
        text.parse().expect("instant")
    }

    fn facts() -> PresentedFacts {
        PresentedFacts::new(
            PresentedCredential::new(
                "national-id",
                "https://issuer.example",
                "https://credentials.example/identity",
                instant("2026-11-01T00:00:00Z"),
                SubjectLinkMode::AttributeMatch,
            )
            .expect("members are in contract"),
            instant("2026-11-06T12:00:00Z"),
        )
    }

    #[test]
    fn without_presented_facts_the_channel_is_source_and_the_cap_is_the_sources() {
        let cap = Some(instant("2026-11-06T10:00:00Z"));
        let (channel, valid_until) = construction_channel(None, cap);
        assert_eq!(channel.kind(), ChannelKind::Source);
        assert_eq!(valid_until, cap);
        assert_eq!(construction_channel(None, None).1, None);
    }

    #[test]
    fn presented_facts_make_the_channel_holder_presented() {
        let (channel, _) = construction_channel(Some(&facts()), None);
        assert_eq!(
            channel,
            AssertionChannel::HolderPresented(facts().credential)
        );
    }

    #[test]
    fn the_cap_is_the_earlier_of_the_source_deadline_and_the_credential_expiry() {
        let earlier = instant("2026-11-06T10:00:00Z");
        let later = instant("2026-11-06T13:00:00Z");
        assert_eq!(
            construction_channel(Some(&facts()), Some(earlier)).1,
            Some(earlier)
        );
        assert_eq!(
            construction_channel(Some(&facts()), Some(later)).1,
            Some(facts().expires_at())
        );
        assert_eq!(
            construction_channel(Some(&facts()), None).1,
            Some(facts().expires_at()),
            "a credential with no source cap still bounds the assertion"
        );
    }
}
