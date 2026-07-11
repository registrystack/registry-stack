// SPDX-License-Identifier: Apache-2.0
//! Typed identifiers shared by artifact validation, runtime profiles, and seeds.

use std::fmt;

const MAX_SEED_IDENTIFIER_BYTES: usize = 96;
const MAX_CANONICAL_PURPOSE_BYTES: usize = 256;

fn is_seed_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= MAX_SEED_IDENTIFIER_BYTES
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

macro_rules! seed_identifier {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub(crate) struct $name(Box<str>);

        impl $name {
            #[must_use]
            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ();

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                is_seed_identifier(value)
                    .then(|| Self(value.into()))
                    .ok_or(())
            }
        }
    };
}

seed_identifier!(
    /// Hash-covered legal-basis identifier persisted in completion seeds.
    LegalBasisId
);
seed_identifier!(
    /// Private destination identifier persisted in completion seeds.
    SourceDestinationId
);
seed_identifier!(
    /// Private credential reference persisted only in restricted state/audit context.
    CredentialReferenceId
);

impl fmt::Debug for LegalBasisId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LegalBasisId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Debug for SourceDestinationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceDestinationId(<redacted>)")
    }
}

impl fmt::Debug for CredentialReferenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialReferenceId(<redacted>)")
    }
}

/// One canonical, hash-covered purpose accepted by a consultation profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct CanonicalPurpose(Box<str>);

impl CanonicalPurpose {
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for CanonicalPurpose {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let valid = !value.is_empty()
            && value.len() <= MAX_CANONICAL_PURPOSE_BYTES
            && !value.contains(',')
            && !value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace());
        valid.then(|| Self(value.into())).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_identifier_grammar_matches_postgres_v1() {
        for value in ["a", "public_task", "registry.data-1", &"a".repeat(96)] {
            assert!(LegalBasisId::try_from(value).is_ok());
            assert!(SourceDestinationId::try_from(value).is_ok());
            assert!(CredentialReferenceId::try_from(value).is_ok());
        }
        for value in [
            "",
            "Uppercase",
            "1leading",
            "contains:colon",
            "contains/slash",
            &"a".repeat(97),
        ] {
            assert!(LegalBasisId::try_from(value).is_err());
            assert!(SourceDestinationId::try_from(value).is_err());
            assert!(CredentialReferenceId::try_from(value).is_err());
        }
    }

    #[test]
    fn canonical_purpose_rejects_comma_whitespace_and_controls() {
        assert!(CanonicalPurpose::try_from("benefit-verification").is_ok());
        for value in ["", "benefit,verification", "has space", "line\nbreak"] {
            assert!(CanonicalPurpose::try_from(value).is_err());
        }
    }

    #[test]
    fn private_topology_identifier_debug_is_redacted() {
        let destination =
            SourceDestinationId::try_from("registry-data-private").expect("destination identifier");
        let reference = CredentialReferenceId::try_from("reader-v1").expect("reference");
        assert!(!format!("{destination:?}").contains("registry-data-private"));
        assert!(!format!("{reference:?}").contains("reader-v1"));
    }
}
