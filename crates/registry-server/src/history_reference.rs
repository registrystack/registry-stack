// SPDX-License-Identifier: Apache-2.0

//! Bounded Registry Server history snapshot references.

use std::fmt;

use uuid::Uuid;

const SNAPSHOT_REFERENCE_PREFIX: &str = "rs1_";
const SNAPSHOT_REFERENCE_BYTES: usize = 40;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SnapshotReference {
    id: Uuid,
}

impl SnapshotReference {
    #[cfg(feature = "runtime")]
    #[must_use]
    pub(crate) fn new_random() -> Self {
        Self { id: Uuid::new_v4() }
    }

    #[cfg(any(feature = "runtime", test))]
    #[must_use]
    pub(crate) fn for_uuid(id: Uuid) -> Self {
        Self { id }
    }

    pub(crate) fn parse(input: &str) -> Result<Self, SnapshotReferenceError> {
        if input.len() != SNAPSHOT_REFERENCE_BYTES {
            return Err(SnapshotReferenceError::Invalid);
        }
        let uuid = input
            .strip_prefix(SNAPSHOT_REFERENCE_PREFIX)
            .ok_or(SnapshotReferenceError::Invalid)?;
        let id = Uuid::parse_str(uuid).map_err(|_| SnapshotReferenceError::Invalid)?;
        if uuid != id.hyphenated().to_string() {
            return Err(SnapshotReferenceError::Invalid);
        }
        Ok(Self { id })
    }

    #[cfg(feature = "runtime")]
    #[must_use]
    pub(crate) fn uuid(self) -> Uuid {
        self.id
    }

    #[must_use]
    pub(crate) fn as_string(self) -> String {
        format!("{SNAPSHOT_REFERENCE_PREFIX}{}", self.id.hyphenated())
    }
}

impl fmt::Display for SnapshotReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum SnapshotReferenceError {
    #[error("snapshot reference is invalid")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reference_is_strictly_versioned_and_canonical() {
        let id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07af7").unwrap();
        let reference = SnapshotReference::for_uuid(id);

        assert_eq!(
            reference.to_string(),
            "rs1_018feaa0-68f9-4a45-b9e3-58436df07af7"
        );
        assert_eq!(
            SnapshotReference::parse(&reference.to_string()).unwrap(),
            reference
        );
        assert!(SnapshotReference::parse("018feaa0-68f9-4a45-b9e3-58436df07af7").is_err());
        assert!(SnapshotReference::parse("rs1_018FEAA0-68F9-4A45-B9E3-58436DF07AF7").is_err());
        assert!(SnapshotReference::parse("rs2_018feaa0-68f9-4a45-b9e3-58436df07af7").is_err());
    }
}
