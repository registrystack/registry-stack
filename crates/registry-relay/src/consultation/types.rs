// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

const MAX_PROFILE_ID_BYTES: usize = 96;
const MAX_STABLE_ID_BYTES: usize = 96;
const MAX_PROFILE_VERSION: u64 = 9_999_999_999;
const MAX_CANONICAL_PURPOSE_BYTES: usize = 256;
const MAX_CANONICAL_INPUT_BYTES: usize = 4_096;
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DATA_EXCHANGES: u8 = 16;
const MAX_CREDENTIAL_EXCHANGES: u8 = 1;
const MAX_DATA_DESTINATIONS: u8 = 1;
const MAX_SOURCE_MATCHES: u8 = 2;
const MAX_DISCLOSED_RECORDS: u8 = 1;
const MAX_TIMEOUT_MS: u32 = 60_000;

/// A safe, value-free reason that a consultation domain value was rejected.
///
/// The variants intentionally omit the rejected input so logs and error paths
/// cannot accidentally expose a subject selector.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ConsultationValidationError {
    /// A resolved registry proof does not name the supplied compiled plan.
    #[error("resolved consultation profile does not match its compiled plan")]
    ResolvedProfileMismatch,
    /// A profile identifier does not use the v1 path grammar.
    #[error("invalid consultation profile identifier")]
    InvalidProfileId,
    /// A profile version is not a canonical positive v1 version.
    #[error("invalid consultation profile version")]
    InvalidProfileVersion,
    /// A stable artifact or operation identifier is invalid.
    #[error("invalid consultation artifact identifier")]
    InvalidStableIdentifier,
    /// A hash is not a lowercase `sha256:` digest.
    #[error("invalid consultation SHA-256 digest")]
    InvalidSha256Digest,
    /// A purpose is empty, oversized, or contains whitespace or controls.
    #[error("invalid parsed consultation purpose")]
    InvalidParsedPurpose,
    /// An input name is outside the generic consultation-input grammar.
    #[error("invalid parsed consultation input name")]
    InvalidParsedInputName,
    /// A string input is oversized or contains controls.
    #[error("invalid parsed consultation input value")]
    InvalidParsedInputValue,
    /// A reviewed operation declares no acquired field.
    #[error("consultation operation must acquire at least one declared field")]
    EmptyAcquisitionSchema,
    /// A reviewed operation repeats an acquired field.
    #[error("consultation operation contains a duplicate acquired field")]
    DuplicateAcquiredField,
    /// A source-match bound is outside the closed singleton or ambiguity probe.
    #[error("consultation source-match bound must be one or two")]
    InvalidSourceMatchBound,
    /// A disclosed-record bound is outside the v1 exact profile contract.
    #[error("consultation disclosed-record bound must be one")]
    InvalidDisclosedRecordBound,
    /// A live bound is outside `1..=16`, or a Snapshot bound is not zero.
    #[error("consultation data-exchange bound is invalid for its acquisition class")]
    InvalidDataExchangeBound,
    /// A live bound is outside `0..=1`, or a Snapshot bound is not zero.
    #[error("consultation credential-exchange bound is invalid for its acquisition class")]
    InvalidCredentialExchangeBound,
    /// A live plan does not declare one origin, or a Snapshot declares any.
    #[error("consultation data-destination bound is invalid for its acquisition class")]
    InvalidDataDestinationBound,
    /// An aggregate byte bound is zero or exceeds 1 MiB.
    #[error("consultation source-byte bound is outside the v1 ceiling")]
    InvalidSourceByteBound,
    /// A deadline is zero or exceeds twenty seconds.
    #[error("consultation timeout is outside the v1 ceiling")]
    InvalidTimeout,
    /// `ambiguous` was used for a source-enforced singleton.
    #[error("ambiguous outcome is not permitted by this profile")]
    AmbiguousOutcomeNotPermitted,
    /// A snapshot identifier is not a canonical ULID.
    #[error("invalid snapshot generation identifier")]
    InvalidSnapshotGenerationId,
}

fn is_stable_id(value: &str, max_bytes: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= max_bytes
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

macro_rules! stable_id {
    ($(#[$meta:meta])* $name:ident, $max:expr, $error:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Box<str>);

        impl $name {
            /// Return the canonical identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ConsultationValidationError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                is_stable_id(value, $max)
                    .then(|| Self(value.into()))
                    .ok_or($error)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

stable_id!(
    /// A profile identifier using the v1 public path grammar.
    ProfileId,
    MAX_PROFILE_ID_BYTES,
    ConsultationValidationError::InvalidProfileId
);
stable_id!(
    /// A reviewed integration-pack identifier.
    IntegrationPackId,
    MAX_STABLE_ID_BYTES,
    ConsultationValidationError::InvalidStableIdentifier
);
stable_id!(
    /// A Relay policy identifier.
    PolicyId,
    MAX_STABLE_ID_BYTES,
    ConsultationValidationError::InvalidStableIdentifier
);
stable_id!(
    /// A reviewed source operation identifier.
    OperationId,
    MAX_STABLE_ID_BYTES,
    ConsultationValidationError::InvalidStableIdentifier
);
stable_id!(
    /// A logical field in the worst-case acquisition schema.
    AcquiredField,
    MAX_STABLE_ID_BYTES,
    ConsultationValidationError::InvalidStableIdentifier
);

/// A canonical positive decimal profile or artifact version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProfileVersion(u64);

impl ProfileVersion {
    /// Return the numeric version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<&str> for ProfileVersion {
    type Error = ConsultationValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let canonical = !value.is_empty()
            && value.len() <= 10
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value.as_bytes()[0].is_ascii_digit()
            && value.as_bytes()[0] != b'0';
        let parsed = canonical
            .then(|| value.parse::<u64>().ok())
            .flatten()
            .filter(|version| *version <= MAX_PROFILE_VERSION);
        parsed
            .map(Self)
            .ok_or(ConsultationValidationError::InvalidProfileVersion)
    }
}

impl fmt::Display for ProfileVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

macro_rules! sha256_hash {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Box<str>);

        impl $name {
            /// Return the canonical lowercase `sha256:` digest.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ConsultationValidationError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                is_sha256_digest(value)
                    .then(|| Self(value.into()))
                    .ok_or(ConsultationValidationError::InvalidSha256Digest)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

sha256_hash!(
    /// Hash of the typed public consultation contract.
    ProfileContractHash
);
sha256_hash!(
    /// Hash of a reviewed integration pack.
    IntegrationPackHash
);
sha256_hash!(
    /// Hash of a Relay policy contract.
    PolicyHash
);
/// The complete public identity pinned by a consultation client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileIdentity {
    id: ProfileId,
    version: ProfileVersion,
    contract_hash: ProfileContractHash,
}

impl ProfileIdentity {
    /// Construct a validated profile identity.
    #[must_use]
    pub const fn new(
        id: ProfileId,
        version: ProfileVersion,
        contract_hash: ProfileContractHash,
    ) -> Self {
        Self {
            id,
            version,
            contract_hash,
        }
    }

    /// Return the profile identifier.
    #[must_use]
    pub const fn id(&self) -> &ProfileId {
        &self.id
    }

    /// Return the profile version.
    #[must_use]
    pub const fn version(&self) -> ProfileVersion {
        self.version
    }

    /// Return the public contract hash.
    #[must_use]
    pub const fn contract_hash(&self) -> &ProfileContractHash {
        &self.contract_hash
    }
}

/// A versioned reviewed integration pack and its pinned hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationPackIdentity {
    id: IntegrationPackId,
    version: ProfileVersion,
    hash: IntegrationPackHash,
}

impl IntegrationPackIdentity {
    /// Construct an integration-pack identity from validated parts.
    #[must_use]
    pub const fn new(
        id: IntegrationPackId,
        version: ProfileVersion,
        hash: IntegrationPackHash,
    ) -> Self {
        Self { id, version, hash }
    }

    /// Return the integration-pack identifier.
    #[must_use]
    pub const fn id(&self) -> &IntegrationPackId {
        &self.id
    }

    /// Return the integration-pack version.
    #[must_use]
    pub const fn version(&self) -> ProfileVersion {
        self.version
    }

    /// Return the integration-pack hash.
    #[must_use]
    pub const fn hash(&self) -> &IntegrationPackHash {
        &self.hash
    }
}

/// A pinned policy identity safe for public provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIdentity {
    id: PolicyId,
    hash: PolicyHash,
}

impl PolicyIdentity {
    /// Construct a policy identity from validated parts.
    #[must_use]
    pub const fn new(id: PolicyId, hash: PolicyHash) -> Self {
        Self { id, hash }
    }

    /// Return the policy identifier.
    #[must_use]
    pub const fn id(&self) -> &PolicyId {
        &self.id
    }

    /// Return the policy hash.
    #[must_use]
    pub const fn hash(&self) -> &PolicyHash {
        &self.hash
    }
}

/// The selector provenance class accepted by consultation v1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorProvenance {
    /// The configured workload selects an exact lookup key under a reviewed
    /// non-consent legal basis.
    WorkloadSelected,
}

/// A generically parsed purpose awaiting profile-specific canonicalization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ParsedPurpose(Box<str>);

impl ParsedPurpose {
    /// Apply only generic size and control-character validation.
    ///
    /// This does not prove that a profile recognizes, canonicalizes, or
    /// authorizes the purpose.
    pub fn try_parse(value: &str) -> Result<Self, ConsultationValidationError> {
        let valid = !value.is_empty()
            && value.len() <= MAX_CANONICAL_PURPOSE_BYTES
            && !value.contains(',')
            && value
                .chars()
                .all(|character| !character.is_control() && !character.is_whitespace());
        valid
            .then(|| Self(value.into()))
            .ok_or(ConsultationValidationError::InvalidParsedPurpose)
    }

    /// Return the parsed value before profile canonicalization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One to sixteen generically parsed consultation inputs awaiting profile validation.
///
/// This type intentionally implements neither `Debug` nor serialization. The
/// string values are zeroized when dropped and visible only inside Relay. This
/// type does not prove role, nullability, bounds, pattern, or canonicalization.
#[derive(PartialEq, Eq)]
pub struct ParsedConsultationInputs {
    values: BTreeMap<Box<str>, ParsedConsultationScalar>,
}

/// A JSON-safe scalar accepted before the selected profile applies its type.
#[derive(PartialEq, Eq)]
pub enum ParsedConsultationScalar {
    String(Zeroizing<String>),
    Boolean(bool),
    Integer(i64),
    Null,
}

impl ParsedConsultationInputs {
    /// Maximum decoded structural input-name bytes accepted by v1.
    pub(crate) const MAX_NAME_BYTES: usize = crate::source_plan::CONSULTATION_INPUT_NAME_MAX_BYTES;
    /// Maximum decoded String-input bytes accepted by v1.
    pub(crate) const MAX_VALUE_BYTES: usize = MAX_CANONICAL_INPUT_BYTES;

    /// Apply the generic one-key and bounded-string parsing rules.
    pub fn try_parse(name: &str, value: &str) -> Result<Self, ConsultationValidationError> {
        Self::try_parse_components([(
            Zeroizing::new(name.to_owned()),
            ParsedConsultationScalar::String(Zeroizing::new(value.to_owned())),
        )])
    }

    pub(crate) fn try_parse_components(
        components: impl IntoIterator<Item = (Zeroizing<String>, ParsedConsultationScalar)>,
    ) -> Result<Self, ConsultationValidationError> {
        let mut values = BTreeMap::new();
        for (name, value) in components {
            if !crate::source_plan::valid_consultation_input_name(&name) {
                return Err(ConsultationValidationError::InvalidParsedInputName);
            }
            if let ParsedConsultationScalar::String(value) = &value {
                let valid_value = value.len() <= MAX_CANONICAL_INPUT_BYTES
                    && value.chars().all(|character| !character.is_control());
                if !valid_value {
                    return Err(ConsultationValidationError::InvalidParsedInputValue);
                }
            }
            if values.insert(name.as_str().into(), value).is_some() {
                return Err(ConsultationValidationError::InvalidParsedInputName);
            }
        }
        if !(1..=16).contains(&values.len()) {
            return Err(ConsultationValidationError::InvalidParsedInputName);
        }
        Ok(Self { values })
    }

    /// Return the parsed input name, which is safe request structure.
    #[must_use]
    pub fn name(&self) -> &str {
        self.values.first_key_value().map_or("", |(name, _)| name)
    }

    /// Return the first String input only inside Relay's invariant tests.
    ///
    /// This accessor is deliberately crate-private. Public API and backend
    /// types cannot serialize or debug the raw selector.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn value_for_internal_use(&self) -> &str {
        self.values
            .first_key_value()
            .and_then(|(_, value)| match value {
                ParsedConsultationScalar::String(value) => Some(value.as_str()),
                _ => None,
            })
            .unwrap_or("")
    }

    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn values(
        &self,
    ) -> impl ExactSizeIterator<Item = (&str, &ParsedConsultationScalar)> {
        self.values
            .iter()
            .map(|(name, value)| (name.as_ref(), value))
    }

    #[cfg(test)]
    fn expose_value_for_test(&self) -> &str {
        self.value_for_internal_use()
    }
}

/// The public acquisition meaning of a reviewed source plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AcquisitionClass {
    /// The source enforces selector, logical projection, and cardinality.
    SourceProjectedExact,
    /// Relay receives a closed, bounded full record before projection.
    BoundedFullRecord,
    /// Consultation reads a separately audited immutable local snapshot.
    MaterializedSnapshot,
}

/// Raw operation limits accepted by [`DeclaredOperationFootprint::try_new`].
///
/// These values describe and numerically bound a reviewed declaration. They do
/// not compile a source plan or authorize execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationBounds {
    /// Maximum source records acquired or probed.
    pub max_source_matches: u8,
    /// Maximum records disclosed in a successful public result.
    pub max_disclosed_records: u8,
    /// Maximum registry data operations.
    pub max_data_exchanges: u8,
    /// Maximum credential acquisition operations.
    pub max_credential_exchanges: u8,
    /// Maximum registry data origins.
    pub max_data_destinations: u8,
    /// Aggregate maximum source bytes.
    pub max_source_bytes: u64,
    /// Total credential-plus-data deadline in milliseconds.
    pub timeout_ms: u32,
}

/// A numerically validated declared worst-case operation footprint.
///
/// This is not an executable plan. A later compiler must validate the complete
/// operation union, schema, private binding, and non-widening rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredOperationFootprint {
    operation: OperationId,
    acquisition_class: AcquisitionClass,
    acquired_fields: BTreeSet<AcquiredField>,
    bounds: OperationBounds,
}

impl DeclaredOperationFootprint {
    /// Validate one operation declaration against numeric v1 ceilings.
    pub fn try_new<I, S>(
        operation: &str,
        acquisition_class: AcquisitionClass,
        acquired_fields: I,
        bounds: OperationBounds,
    ) -> Result<Self, ConsultationValidationError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if !(1..=MAX_SOURCE_MATCHES).contains(&bounds.max_source_matches) {
            return Err(ConsultationValidationError::InvalidSourceMatchBound);
        }
        if bounds.max_disclosed_records != MAX_DISCLOSED_RECORDS {
            return Err(ConsultationValidationError::InvalidDisclosedRecordBound);
        }
        match acquisition_class {
            AcquisitionClass::SourceProjectedExact | AcquisitionClass::BoundedFullRecord => {
                if !(1..=MAX_DATA_EXCHANGES).contains(&bounds.max_data_exchanges) {
                    return Err(ConsultationValidationError::InvalidDataExchangeBound);
                }
                if bounds.max_credential_exchanges > MAX_CREDENTIAL_EXCHANGES {
                    return Err(ConsultationValidationError::InvalidCredentialExchangeBound);
                }
                if bounds.max_data_destinations != MAX_DATA_DESTINATIONS {
                    return Err(ConsultationValidationError::InvalidDataDestinationBound);
                }
            }
            AcquisitionClass::MaterializedSnapshot => {
                if bounds.max_data_exchanges != 0 {
                    return Err(ConsultationValidationError::InvalidDataExchangeBound);
                }
                if bounds.max_credential_exchanges != 0 {
                    return Err(ConsultationValidationError::InvalidCredentialExchangeBound);
                }
                if bounds.max_data_destinations != 0 {
                    return Err(ConsultationValidationError::InvalidDataDestinationBound);
                }
            }
        }
        if !(1..=MAX_SOURCE_BYTES).contains(&bounds.max_source_bytes) {
            return Err(ConsultationValidationError::InvalidSourceByteBound);
        }
        if !(1..=MAX_TIMEOUT_MS).contains(&bounds.timeout_ms) {
            return Err(ConsultationValidationError::InvalidTimeout);
        }

        let mut fields = BTreeSet::new();
        for field in acquired_fields {
            let field = AcquiredField::try_from(field.as_ref())?;
            if !fields.insert(field) {
                return Err(ConsultationValidationError::DuplicateAcquiredField);
            }
        }
        if fields.is_empty() {
            return Err(ConsultationValidationError::EmptyAcquisitionSchema);
        }

        Ok(Self {
            operation: OperationId::try_from(operation)?,
            acquisition_class,
            acquired_fields: fields,
            bounds,
        })
    }

    /// Return the reviewed source operation identifier.
    #[must_use]
    pub const fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// Return the declared acquisition class.
    #[must_use]
    pub const fn acquisition_class(&self) -> AcquisitionClass {
        self.acquisition_class
    }

    /// Iterate the closed worst-case logical acquisition schema.
    pub fn acquired_fields(&self) -> impl ExactSizeIterator<Item = &str> {
        self.acquired_fields.iter().map(AcquiredField::as_str)
    }

    /// Return the numerically validated declared operation bounds.
    #[must_use]
    pub const fn bounds(&self) -> OperationBounds {
        self.bounds
    }

    /// Check whether this footprint permits a public outcome.
    pub fn validate_outcome(
        &self,
        outcome: ConsultationOutcome,
    ) -> Result<(), ConsultationValidationError> {
        if outcome == ConsultationOutcome::Ambiguous && self.bounds.max_source_matches != 2 {
            return Err(ConsultationValidationError::AmbiguousOutcomeNotPermitted);
        }
        Ok(())
    }
}

/// Closed public consultation outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsultationOutcome {
    /// Exactly one normalized row matched.
    Match,
    /// No row matched.
    NoMatch,
    /// At least two rows matched; no row is disclosed.
    Ambiguous,
}

/// A validated immutable snapshot generation identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnapshotGenerationId(Ulid);

impl SnapshotGenerationId {
    /// Return the canonical ULID text.
    #[must_use]
    pub fn to_canonical_string(self) -> String {
        self.0.to_string()
    }
}

impl TryFrom<&str> for SnapshotGenerationId {
    type Error = ConsultationValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let generation = Ulid::from_string(value)
            .map_err(|_| ConsultationValidationError::InvalidSnapshotGenerationId)?;
        if generation.to_string() != value {
            return Err(ConsultationValidationError::InvalidSnapshotGenerationId);
        }
        Ok(Self(generation))
    }
}

/// Parsed, declared consultation data produced before profile authorization.
///
/// The type is intentionally not serializable, debuggable, clonable, or
/// publicly constructible. It carries a parsed input and declared profile
/// meaning, but contains no profile-specific input validation, canonicalized
/// purpose, workload, legal basis, policy, consent,
/// obligation, audit, or fencing authority. It cannot be passed to a source
/// backend.
pub struct PreAuthorizationConsultationCore {
    profile: ProfileIdentity,
    selector_provenance: SelectorProvenance,
    purpose: ParsedPurpose,
    input: ParsedConsultationInputs,
    footprint: DeclaredOperationFootprint,
}

impl PreAuthorizationConsultationCore {
    /// Bind one owned parsed request to the exact plan proven visible by the
    /// authenticated registry lookup. Profile-specific purpose and input
    /// validation still happens when this core is consumed into canonical
    /// consultation inputs.
    #[allow(
        dead_code,
        reason = "consumed by the consultation service activation slice"
    )]
    pub(crate) fn from_resolved_plan(
        resolved: super::ResolvedConsultationProfile,
        plan: &crate::source_plan::CompiledSourcePlan,
        purpose: ParsedPurpose,
        input: ParsedConsultationInputs,
    ) -> Result<Self, ConsultationValidationError> {
        let profile = plan.runtime_profile();
        if !resolved.matches_exact_plan(plan) {
            return Err(ConsultationValidationError::ResolvedProfileMismatch);
        }
        Ok(Self {
            profile: profile.profile().clone(),
            selector_provenance: profile.subject().selector_provenance().clone(),
            purpose,
            input,
            footprint: profile.footprint().clone(),
        })
    }

    #[cfg(test)]
    pub(crate) const fn new_for_test(
        profile: ProfileIdentity,
        selector_provenance: SelectorProvenance,
        purpose: ParsedPurpose,
        input: ParsedConsultationInputs,
        footprint: DeclaredOperationFootprint,
    ) -> Self {
        Self {
            profile,
            selector_provenance,
            purpose,
            input,
            footprint,
        }
    }

    /// Return the pinned profile identity.
    #[must_use]
    pub const fn profile(&self) -> &ProfileIdentity {
        &self.profile
    }

    /// Return the server-selected selector provenance.
    #[must_use]
    pub const fn selector_provenance(&self) -> &SelectorProvenance {
        &self.selector_provenance
    }

    /// Return the parsed purpose before profile canonicalization and
    /// authorization.
    #[must_use]
    pub const fn purpose(&self) -> &ParsedPurpose {
        &self.purpose
    }

    /// Return the parsed input container without exposing its value.
    #[must_use]
    pub const fn parsed_input(&self) -> &ParsedConsultationInputs {
        &self.input
    }

    /// Return the declared worst-case operation footprint.
    #[must_use]
    pub const fn footprint(&self) -> &DeclaredOperationFootprint {
        &self.footprint
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn profile_identity() -> ProfileIdentity {
        ProfileIdentity::new(
            ProfileId::try_from("example.person-status.exact").expect("profile id"),
            ProfileVersion::try_from("1").expect("profile version"),
            ProfileContractHash::try_from(HASH).expect("contract hash"),
        )
    }

    fn footprint(max_source_matches: u8) -> DeclaredOperationFootprint {
        DeclaredOperationFootprint::try_new(
            "person-status-exact",
            AcquisitionClass::SourceProjectedExact,
            ["registration_status"],
            OperationBounds {
                max_source_matches,
                max_disclosed_records: 1,
                max_data_exchanges: 1,
                max_credential_exchanges: 1,
                max_data_destinations: 1,
                max_source_bytes: 262_144,
                timeout_ms: 5_000,
            },
        )
        .expect("bounded operation footprint")
    }

    fn pre_authorization_core(max_source_matches: u8) -> PreAuthorizationConsultationCore {
        PreAuthorizationConsultationCore::new_for_test(
            profile_identity(),
            SelectorProvenance::WorkloadSelected,
            ParsedPurpose::try_parse("benefit-verification").expect("purpose"),
            ParsedConsultationInputs::try_parse("subject_id", "12345").expect("input"),
            footprint(max_source_matches),
        )
    }

    /// Test-only stand-in for the future audited and fenced dispatch grant.
    /// Production construction must bind durable attempt-audit and fencing
    /// proofs before any source backend receives a callable value.
    struct TestOnlyAuditedFencedDispatchGrant {
        core: PreAuthorizationConsultationCore,
    }

    impl TestOnlyAuditedFencedDispatchGrant {
        fn from_test_proofs(core: PreAuthorizationConsultationCore) -> Self {
            Self { core }
        }
    }

    trait AuditedFencedGrantOnlyBackend {
        fn execute(&self, grant: &TestOnlyAuditedFencedDispatchGrant) -> ConsultationOutcome;
    }

    struct CountingFakeBackend {
        calls: AtomicUsize,
        outcome: ConsultationOutcome,
    }

    impl CountingFakeBackend {
        fn new(outcome: ConsultationOutcome) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                outcome,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl AuditedFencedGrantOnlyBackend for CountingFakeBackend {
        fn execute(&self, grant: &TestOnlyAuditedFencedDispatchGrant) -> ConsultationOutcome {
            grant
                .core
                .footprint()
                .validate_outcome(self.outcome)
                .expect("fake backend outcome must fit capability");
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome
        }
    }

    #[test]
    fn profile_identity_enforces_path_version_and_hash_grammar() {
        assert!(ProfileId::try_from("a").is_ok());
        assert!(ProfileId::try_from("opencrvs.birth-status_v1").is_ok());
        assert_eq!(
            ProfileId::try_from("OpenCRVS"),
            Err(ConsultationValidationError::InvalidProfileId)
        );
        assert_eq!(
            ProfileVersion::try_from("01"),
            Err(ConsultationValidationError::InvalidProfileVersion)
        );
        assert_eq!(
            ProfileVersion::try_from("9999999999").unwrap().get(),
            9_999_999_999
        );
        assert_eq!(
            ProfileVersion::try_from("10000000000"),
            Err(ConsultationValidationError::InvalidProfileVersion)
        );
        assert!(ProfileContractHash::try_from(HASH).is_ok());
        assert_eq!(
            ProfileContractHash::try_from(
                "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            Err(ConsultationValidationError::InvalidSha256Digest)
        );
    }

    #[test]
    fn selector_provenance_is_closed_to_workload_selected() {
        assert_eq!(
            SelectorProvenance::WorkloadSelected,
            SelectorProvenance::WorkloadSelected
        );
    }

    #[test]
    fn parsed_input_rejects_unsafe_shapes_without_implicit_normalization() {
        let name_64 = format!("a{}", "0".repeat(63));
        let name_65 = format!("a{}", "0".repeat(64));
        assert!(ParsedConsultationInputs::try_parse(&name_64, "12345").is_ok());
        assert_eq!(
            ParsedConsultationInputs::try_parse(&name_65, "12345").err(),
            Some(ConsultationValidationError::InvalidParsedInputName)
        );
        assert!(ParsedConsultationInputs::try_parse("subject_id", " 12345 ").is_ok());
        assert_eq!(
            ParsedConsultationInputs::try_parse("subject-id", "12345").err(),
            Some(ConsultationValidationError::InvalidParsedInputName)
        );
        assert!(ParsedConsultationInputs::try_parse("subject_id", "").is_ok());
        assert_eq!(
            ParsedConsultationInputs::try_parse("subject_id", "123\n45").err(),
            Some(ConsultationValidationError::InvalidParsedInputValue)
        );

        let input = ParsedConsultationInputs::try_parse("subject_id", " 12345 ").unwrap();
        assert_eq!(input.name(), "subject_id");
        assert_eq!(input.expose_value_for_test(), " 12345 ");
    }

    #[test]
    fn parsed_inputs_accept_sixteen_json_safe_scalars() {
        let sixteen = (0..16).map(|index| {
            (
                Zeroizing::new(format!("input_{index}")),
                match index % 4 {
                    0 => ParsedConsultationScalar::String(Zeroizing::new("x".repeat(512))),
                    1 => ParsedConsultationScalar::Boolean(true),
                    2 => ParsedConsultationScalar::Integer(42),
                    _ => ParsedConsultationScalar::Null,
                },
            )
        });
        assert!(ParsedConsultationInputs::try_parse_components(sixteen).is_ok());

        let seventeen = (0..17).map(|index| {
            (
                Zeroizing::new(format!("input_{index}")),
                ParsedConsultationScalar::Boolean(true),
            )
        });
        assert_eq!(
            ParsedConsultationInputs::try_parse_components(seventeen).err(),
            Some(ConsultationValidationError::InvalidParsedInputName)
        );
    }

    #[test]
    fn parsed_purpose_is_bounded_without_overclaiming_canonicalization() {
        assert_eq!(
            ParsedPurpose::try_parse("benefit-verification")
                .unwrap()
                .as_str(),
            "benefit-verification"
        );
        assert_eq!(
            ParsedPurpose::try_parse("benefit verification"),
            Err(ConsultationValidationError::InvalidParsedPurpose)
        );
        assert_eq!(
            ParsedPurpose::try_parse("benefit-verification,other-purpose"),
            Err(ConsultationValidationError::InvalidParsedPurpose)
        );
        assert_eq!(
            ParsedPurpose::try_parse(""),
            Err(ConsultationValidationError::InvalidParsedPurpose)
        );
    }

    #[test]
    fn operation_footprint_enforces_every_v1_ceiling() {
        let valid = footprint(2);
        assert_eq!(valid.operation().as_str(), "person-status-exact");
        assert_eq!(
            valid.acquired_fields().collect::<Vec<_>>(),
            ["registration_status"]
        );
        assert_eq!(valid.bounds().max_data_exchanges, 1);

        let invalid = |bounds: OperationBounds| {
            DeclaredOperationFootprint::try_new(
                "person-status-exact",
                AcquisitionClass::BoundedFullRecord,
                ["registration_status"],
                bounds,
            )
        };
        let base = valid.bounds();
        assert_eq!(
            invalid(OperationBounds {
                max_source_matches: 3,
                ..base
            }),
            Err(ConsultationValidationError::InvalidSourceMatchBound)
        );
        assert_eq!(
            invalid(OperationBounds {
                max_disclosed_records: 2,
                ..base
            }),
            Err(ConsultationValidationError::InvalidDisclosedRecordBound)
        );
        assert_eq!(
            invalid(OperationBounds {
                max_data_exchanges: 0,
                ..base
            }),
            Err(ConsultationValidationError::InvalidDataExchangeBound)
        );
        let at_data_exchange_ceiling = invalid(OperationBounds {
            max_data_exchanges: 16,
            ..base
        })
        .expect("approved data-exchange ceiling");
        assert_eq!(at_data_exchange_ceiling.bounds().max_data_exchanges, 16);
        assert_eq!(
            invalid(OperationBounds {
                max_data_exchanges: 17,
                ..base
            }),
            Err(ConsultationValidationError::InvalidDataExchangeBound)
        );
        assert_eq!(
            invalid(OperationBounds {
                max_credential_exchanges: 2,
                ..base
            }),
            Err(ConsultationValidationError::InvalidCredentialExchangeBound)
        );
        assert_eq!(
            invalid(OperationBounds {
                max_data_destinations: 0,
                ..base
            }),
            Err(ConsultationValidationError::InvalidDataDestinationBound)
        );
        assert_eq!(
            invalid(OperationBounds {
                max_source_bytes: 0,
                ..base
            }),
            Err(ConsultationValidationError::InvalidSourceByteBound)
        );
        assert_eq!(
            invalid(OperationBounds {
                max_source_bytes: MAX_SOURCE_BYTES + 1,
                ..base
            }),
            Err(ConsultationValidationError::InvalidSourceByteBound)
        );
        assert_eq!(
            invalid(OperationBounds {
                timeout_ms: 0,
                ..base
            }),
            Err(ConsultationValidationError::InvalidTimeout)
        );
        assert_eq!(
            invalid(OperationBounds {
                timeout_ms: MAX_TIMEOUT_MS + 1,
                ..base
            }),
            Err(ConsultationValidationError::InvalidTimeout)
        );
        assert_eq!(
            DeclaredOperationFootprint::try_new(
                "person-status-exact",
                AcquisitionClass::SourceProjectedExact,
                std::iter::empty::<&str>(),
                base,
            ),
            Err(ConsultationValidationError::EmptyAcquisitionSchema)
        );
        assert_eq!(
            DeclaredOperationFootprint::try_new(
                "person-status-exact",
                AcquisitionClass::SourceProjectedExact,
                ["registration_status", "registration_status"],
                base,
            ),
            Err(ConsultationValidationError::DuplicateAcquiredField)
        );

        let snapshot_bounds = OperationBounds {
            max_data_exchanges: 0,
            max_credential_exchanges: 0,
            max_data_destinations: 0,
            ..base
        };
        assert!(DeclaredOperationFootprint::try_new(
            "person-status-snapshot",
            AcquisitionClass::MaterializedSnapshot,
            ["registration_status"],
            snapshot_bounds,
        )
        .is_ok());
        for (bounds, error) in [
            (
                OperationBounds {
                    max_data_exchanges: 1,
                    ..snapshot_bounds
                },
                ConsultationValidationError::InvalidDataExchangeBound,
            ),
            (
                OperationBounds {
                    max_credential_exchanges: 1,
                    ..snapshot_bounds
                },
                ConsultationValidationError::InvalidCredentialExchangeBound,
            ),
            (
                OperationBounds {
                    max_data_destinations: 1,
                    ..snapshot_bounds
                },
                ConsultationValidationError::InvalidDataDestinationBound,
            ),
        ] {
            assert_eq!(
                DeclaredOperationFootprint::try_new(
                    "person-status-snapshot",
                    AcquisitionClass::MaterializedSnapshot,
                    ["registration_status"],
                    bounds,
                ),
                Err(error)
            );
        }
    }

    #[test]
    fn singleton_and_ambiguity_outcomes_are_distinct() {
        assert_eq!(
            footprint(1).validate_outcome(ConsultationOutcome::Ambiguous),
            Err(ConsultationValidationError::AmbiguousOutcomeNotPermitted)
        );
        assert!(footprint(2)
            .validate_outcome(ConsultationOutcome::Ambiguous)
            .is_ok());
        assert!(footprint(1)
            .validate_outcome(ConsultationOutcome::Match)
            .is_ok());
        assert!(footprint(1)
            .validate_outcome(ConsultationOutcome::NoMatch)
            .is_ok());
    }

    #[test]
    fn snapshot_generation_id_requires_canonical_ulid_text() {
        let canonical = "01J2D9W2G00000000000000000";
        assert_eq!(
            SnapshotGenerationId::try_from(canonical)
                .unwrap()
                .to_canonical_string(),
            canonical
        );
        let lowercase = canonical.to_ascii_lowercase();
        assert_eq!(
            SnapshotGenerationId::try_from(lowercase.as_str()),
            Err(ConsultationValidationError::InvalidSnapshotGenerationId)
        );
        assert_eq!(
            SnapshotGenerationId::try_from("1J2D9W2G00000000000000000"),
            Err(ConsultationValidationError::InvalidSnapshotGenerationId)
        );
    }

    #[test]
    fn counting_backend_requires_a_sealed_audited_and_fenced_grant() {
        let backend = CountingFakeBackend::new(ConsultationOutcome::Match);
        assert_eq!(backend.calls(), 0);

        let core = pre_authorization_core(1);
        assert_eq!(core.profile(), &profile_identity());
        assert_eq!(core.purpose().as_str(), "benefit-verification");
        assert_eq!(core.parsed_input().name(), "subject_id");
        assert_eq!(backend.calls(), 0);

        let dispatch = TestOnlyAuditedFencedDispatchGrant::from_test_proofs(core);
        assert_eq!(backend.execute(&dispatch), ConsultationOutcome::Match);
        assert_eq!(backend.calls(), 1);
    }

    #[test]
    fn invalid_domain_values_never_reach_counting_backend() {
        let backend = CountingFakeBackend::new(ConsultationOutcome::NoMatch);

        let rejected = ParsedConsultationInputs::try_parse("subject-id", "12345");
        assert_eq!(
            rejected.err(),
            Some(ConsultationValidationError::InvalidParsedInputName)
        );
        assert_eq!(backend.calls(), 0);
    }
}
