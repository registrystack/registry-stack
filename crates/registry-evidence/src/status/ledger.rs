//! The status ledger: list policy, list identifiers, entry references, and
//! the ledger handle every store operation goes through.

use std::fmt;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand_core::{OsRng, RngCore};
use url::Url;

use super::error::StatusError;
use super::keys::{HolderDigestKeyRing, KeyVersion, PseudonymKeyRing};
use super::pools::ReservedPool;
use super::schema::{self, SchemaName};

/// Entries per status list in production: 2^20 entries of 2 bits.
pub const STATUS_LIST_ENTRY_COUNT: u32 = 1 << 20;

/// Bits per status list entry.
pub const STATUS_LIST_BITS: i16 = 2;

/// Random bytes in a list identifier; 16 bytes give 22 base64url characters.
const LIST_ID_BYTES: usize = 16;
const LIST_ID_CHARS: usize = 22;

/// When an open list stops taking allocations: at half its entries, so a
/// uniform random draw over its unallocated indices succeeds at least half
/// the time, or at its configured age.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListPolicy {
    entry_count: u32,
    maximum_age: Duration,
}

impl ListPolicy {
    /// Production lists of [`STATUS_LIST_ENTRY_COUNT`] entries that close at
    /// `maximum_age`.
    pub fn new(maximum_age: Duration) -> Result<Self, StatusError> {
        Self::checked(STATUS_LIST_ENTRY_COUNT, maximum_age)
    }

    /// Lists of `entry_count` entries, for tests that fill a list.
    #[cfg(any(test, feature = "postgres-test"))]
    pub fn with_entry_count(entry_count: u32, maximum_age: Duration) -> Result<Self, StatusError> {
        if !(2..=STATUS_LIST_ENTRY_COUNT).contains(&entry_count) {
            return Err(StatusError::Configuration(
                "a status list holds between 2 and 2^20 entries",
            ));
        }
        Self::checked(entry_count, maximum_age)
    }

    fn checked(entry_count: u32, maximum_age: Duration) -> Result<Self, StatusError> {
        if maximum_age.is_zero() || i64::try_from(maximum_age.as_millis()).is_err() {
            return Err(StatusError::Configuration(
                "the status list maximum age must be positive and representable in milliseconds",
            ));
        }
        Ok(Self {
            entry_count,
            maximum_age,
        })
    }

    #[must_use]
    pub const fn entry_count(&self) -> u32 {
        self.entry_count
    }

    #[must_use]
    pub const fn maximum_age(&self) -> Duration {
        self.maximum_age
    }

    /// The most entries one list ever takes.
    pub(crate) const fn allocation_limit(&self) -> u32 {
        self.entry_count / 2
    }
}

/// A random status list identifier: 16 bytes from the operating system's
/// CSPRNG in unpadded base64url. List identifiers may appear in logs.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusListId(String);

impl StatusListId {
    pub(crate) fn generate() -> Result<Self, StatusError> {
        let mut bytes = [0_u8; LIST_ID_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| StatusError::Randomness)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// Parse an identifier read from a route or the ledger.
    pub fn parse(value: &str) -> Result<Self, StatusError> {
        let decodes = URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == LIST_ID_BYTES);
        if value.len() == LIST_ID_CHARS && decodes {
            Ok(Self(value.to_owned()))
        } else {
            Err(StatusError::InvalidInput("not a status list identifier"))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StatusListId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for StatusListId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("StatusListId")
            .field(&self.0)
            .finish()
    }
}

/// One entry of one list. The index is a signed credential claim; it stays
/// out of logs and diagnostics, which carry list identifiers and counts only.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusEntry {
    list_id: StatusListId,
    idx: u32,
}

impl StatusEntry {
    #[must_use]
    pub const fn new(list_id: StatusListId, idx: u32) -> Self {
        Self { list_id, idx }
    }

    #[must_use]
    pub const fn list_id(&self) -> &StatusListId {
        &self.list_id
    }

    #[must_use]
    pub const fn idx(&self) -> u32 {
        self.idx
    }

    /// The index as stored.
    pub(crate) fn idx_column(&self) -> Result<i32, StatusError> {
        i32::try_from(self.idx).map_err(|_| StatusError::UnknownEntry)
    }
}

impl fmt::Debug for StatusEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatusEntry")
            .field("list_id", &self.list_id)
            .field("idx", &"[REDACTED]")
            .finish()
    }
}

/// The `status_list` claim of one credential: its entry and the list URI.
#[derive(Clone, PartialEq, Eq)]
pub struct StatusReference {
    entry: StatusEntry,
    uri: String,
}

impl StatusReference {
    #[must_use]
    pub const fn entry(&self) -> &StatusEntry {
        &self.entry
    }

    #[must_use]
    pub const fn list_id(&self) -> &StatusListId {
        &self.entry.list_id
    }

    #[must_use]
    pub const fn idx(&self) -> u32 {
        self.entry.idx
    }

    /// `https://<public origin>/status/v1/lists/<list-id>`.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }
}

impl fmt::Debug for StatusReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatusReference")
            .field("entry", &self.entry)
            .field("uri", &self.uri)
            .finish()
    }
}

/// What a ledger is built from. Key separation from the audit
/// pseudonymization key and the subject-binding secret is checked by the
/// caller at startup with [`super::validate_key_separation`], since this
/// ledger never holds those keys.
pub struct LedgerConfig {
    pub schema: SchemaName,
    /// The `https` origin status lists are published under, with no path,
    /// query, fragment or credentials.
    pub public_origin: String,
    pub list_policy: ListPolicy,
    pub pseudonym_keys: PseudonymKeyRing,
    pub holder_digest_keys: HolderDigestKeyRing,
    pub clock_skew: Duration,
}

/// The credential status ledger in one PostgreSQL schema.
pub struct StatusLedger {
    pub(crate) schema: SchemaName,
    public_origin: String,
    pub(crate) list_policy: ListPolicy,
    pub(crate) pseudonym_keys: PseudonymKeyRing,
    pub(crate) holder_digest_keys: HolderDigestKeyRing,
    pub(crate) clock_skew: Duration,
    pub(crate) statements: Statements,
}

impl StatusLedger {
    pub fn new(config: LedgerConfig) -> Result<Self, StatusError> {
        let public_origin = public_origin(&config.public_origin)?;
        let statements = Statements::new(&config.schema);
        Ok(Self {
            schema: config.schema,
            public_origin,
            list_policy: config.list_policy,
            pseudonym_keys: config.pseudonym_keys,
            holder_digest_keys: config.holder_digest_keys,
            clock_skew: config.clock_skew,
            statements,
        })
    }

    /// Create the schema if needed and apply the migrations it lacks.
    pub async fn migrate(&self, pool: &ReservedPool) -> Result<(), StatusError> {
        schema::migrate(&self.schema, pool).await
    }

    /// The publication URI of a list.
    #[must_use]
    pub fn list_uri(&self, list_id: &StatusListId) -> String {
        format!("{}/status/v1/lists/{list_id}", self.public_origin)
    }

    pub(crate) fn reference(&self, entry: StatusEntry) -> StatusReference {
        let uri = self.list_uri(&entry.list_id);
        StatusReference { entry, uri }
    }
}

impl fmt::Debug for StatusLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatusLedger")
            .field("schema", &self.schema)
            .field("public_origin", &self.public_origin)
            .field("list_policy", &self.list_policy)
            .field("clock_skew", &self.clock_skew)
            .finish_non_exhaustive()
    }
}

fn public_origin(value: &str) -> Result<String, StatusError> {
    let refused = StatusError::Configuration(
        "the status public origin must be an https origin with no path, query, fragment or credentials",
    );
    let url = Url::parse(value)
        .map_err(|_| StatusError::Configuration("the status public origin is not a URL"))?;
    let bare_origin = url.scheme() == "https"
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none();
    if bare_origin {
        Ok(url.origin().ascii_serialization())
    } else {
        Err(refused)
    }
}

/// A key version as stored. Key versions are at most `i32::MAX`.
pub(crate) fn version_column(version: KeyVersion) -> Result<i32, StatusError> {
    i32::try_from(version.get()).map_err(|_| StatusError::InvalidInput("key version out of range"))
}

/// Every statement the ledger runs, with the schema quoted in once.
pub(crate) struct Statements {
    pub(crate) reserve: String,
    pub(crate) close_open_list: String,
    pub(crate) open_list: String,
    pub(crate) insert_allocation: String,
    pub(crate) inherit: String,
    pub(crate) entry_status: String,
    pub(crate) lock_entry: String,
    pub(crate) record_entry_revision: String,
    pub(crate) change_entry_status: String,
    pub(crate) insert_transition: String,
    pub(crate) highest_mapping_version: String,
    pub(crate) share_highest_mapping_version: String,
    pub(crate) register_mapping_version: String,
    pub(crate) latest_observation_provenance: String,
    pub(crate) latest_observation: String,
    pub(crate) upsert_observation: String,
    pub(crate) purge_observations: String,
    pub(crate) set_staleness_clock: String,
    pub(crate) staleness_clock: String,
}

impl Statements {
    fn new(schema: &SchemaName) -> Self {
        let s = schema.quoted();
        Self {
            reserve: format!(
                "UPDATE {s}.lists SET allocated_count = allocated_count + $1 \
                 WHERE closed_at IS NULL \
                   AND allocated_count + $1 <= entry_count / 2 \
                   AND created_at > statement_timestamp() \
                       - ($2::bigint::double precision * interval '1 millisecond') \
                 RETURNING list_id, entry_count"
            ),
            close_open_list: format!(
                "UPDATE {s}.lists SET closed_at = statement_timestamp() \
                 WHERE closed_at IS NULL RETURNING list_id"
            ),
            open_list: format!(
                "INSERT INTO {s}.lists \
                 (list_id, entry_count, bits, created_at, closed_at, allocated_count) \
                 VALUES ($1, $2, $3, statement_timestamp(), NULL, $4)"
            ),
            // The transaction-scoped advisory lock on (list, index) makes a
            // draw that collides with another open issuance skip to a fresh
            // index instead of waiting on, or deadlocking with, that
            // transaction. It uses the single-key lock space, apart from the
            // two-key migration and rotation locks.
            insert_allocation: format!(
                "INSERT INTO {s}.allocations \
                 (list_id, idx, holder_key_digest, holder_digest_key_version, requirement_id, \
                  selector_pseudonym, pseudonym_key_version, issued_at, not_after, status, \
                  last_applied_source_revision, mapping_version, source_read_hour) \
                 SELECT $1::text, $2::integer, $3::bytea, $4::integer, $5::text, $6::bytea, \
                        $7::integer, $8::timestamptz, $9::timestamptz, $10::smallint, \
                        $11::bigint, $12::integer, $13::timestamptz \
                 WHERE pg_try_advisory_xact_lock((hashtext($1::text)::bigint << 32) | $2::bigint) \
                 ON CONFLICT ON CONSTRAINT allocations_pkey DO NOTHING \
                 RETURNING idx"
            ),
            inherit: format!(
                "UPDATE {s}.allocations \
                 SET status = $3, last_applied_source_revision = $4, mapping_version = $5 \
                 WHERE list_id = $1 AND idx = ANY($2::integer[])"
            ),
            entry_status: format!(
                "SELECT status FROM {s}.allocations WHERE list_id = $1 AND idx = $2"
            ),
            lock_entry: format!(
                "SELECT status, last_applied_source_revision, source_read_hour \
                 FROM {s}.allocations WHERE list_id = $1 AND idx = $2 FOR UPDATE"
            ),
            record_entry_revision: format!(
                "UPDATE {s}.allocations \
                 SET last_applied_source_revision = $3, mapping_version = $4 \
                 WHERE list_id = $1 AND idx = $2"
            ),
            // Conditional on the status the transition table was applied to,
            // so a writer that read a stale status changes nothing.
            change_entry_status: format!(
                "UPDATE {s}.allocations \
                 SET status = $3, \
                     last_applied_source_revision = \
                         COALESCE($5::bigint, last_applied_source_revision), \
                     mapping_version = COALESCE($6::integer, mapping_version) \
                 WHERE list_id = $1 AND idx = $2 AND status = $4"
            ),
            insert_transition: format!(
                "INSERT INTO {s}.transitions \
                 (transition_id, list_id, idx, from_status, to_status, cause, mapping_version, \
                  reason_category, event_id, source_revision, package_revision, event_source, \
                  operator_principals, case_reference, run_id, extract_digest, occurred_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
                         statement_timestamp())"
            ),
            highest_mapping_version: format!(
                "SELECT highest FROM {s}.mapping_versions WHERE singleton"
            ),
            // Held until the transition commits, so a registration of a
            // higher version waits for it and every later transition sees
            // the new version.
            share_highest_mapping_version: format!(
                "SELECT highest FROM {s}.mapping_versions WHERE singleton FOR SHARE"
            ),
            register_mapping_version: format!(
                "INSERT INTO {s}.mapping_versions AS registered (singleton, highest) \
                 VALUES (true, $1) \
                 ON CONFLICT (singleton) DO UPDATE \
                 SET highest = GREATEST(registered.highest, EXCLUDED.highest) \
                 RETURNING highest"
            ),
            latest_observation_provenance: format!(
                "SELECT source_revision, mapping_version FROM {s}.observations \
                 WHERE requirement_id = $1 AND selector_pseudonym = ANY($2::bytea[]) \
                 ORDER BY source_revision DESC, mapping_version DESC LIMIT 1"
            ),
            latest_observation: format!(
                "SELECT status, source_revision, captured_at, mapping_version \
                 FROM {s}.observations \
                 WHERE requirement_id = $1 AND selector_pseudonym = ANY($2::bytea[]) \
                 ORDER BY source_revision DESC, mapping_version DESC, captured_at DESC LIMIT 1"
            ),
            upsert_observation: format!(
                "INSERT INTO {s}.observations \
                 (requirement_id, selector_pseudonym, pseudonym_key_version, status, \
                  source_revision, captured_at, mapping_version) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (requirement_id, selector_pseudonym) DO UPDATE \
                 SET pseudonym_key_version = EXCLUDED.pseudonym_key_version, \
                     status = EXCLUDED.status, \
                     source_revision = EXCLUDED.source_revision, \
                     captured_at = EXCLUDED.captured_at, \
                     mapping_version = EXCLUDED.mapping_version"
            ),
            purge_observations: format!(
                "DELETE FROM {s}.observations \
                 WHERE captured_at < statement_timestamp() \
                       - ($1::bigint::double precision * interval '1 millisecond')"
            ),
            set_staleness_clock: format!(
                "INSERT INTO {s}.staleness_clock (mapping_block, last_observed_at) \
                 VALUES ($1, $2) \
                 ON CONFLICT (mapping_block) DO UPDATE \
                 SET last_observed_at = EXCLUDED.last_observed_at"
            ),
            staleness_clock: format!(
                "SELECT count(*), min(last_observed_at) FROM {s}.staleness_clock \
                 WHERE mapping_block = ANY($1::text[])"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{public_origin, ListPolicy, StatusListId, STATUS_LIST_ENTRY_COUNT};

    #[test]
    fn the_public_origin_is_a_bare_https_origin() {
        assert_eq!(
            public_origin("https://Status.Example.test").unwrap(),
            "https://status.example.test"
        );
        assert_eq!(
            public_origin("https://status.example.test:8443/").unwrap(),
            "https://status.example.test:8443"
        );
        for refused in [
            "http://status.example.test",
            "https://status.example.test/status",
            "https://status.example.test/?q=1",
            "https://status.example.test/#top",
            "https://user:secret@status.example.test",
            "status.example.test",
        ] {
            assert!(public_origin(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn list_identifiers_are_fresh_random_base64url() {
        let first = StatusListId::generate().unwrap();
        let second = StatusListId::generate().unwrap();
        assert_ne!(first, second);
        assert_eq!(first.as_str().len(), 22);
        assert_eq!(StatusListId::parse(first.as_str()).unwrap(), first);
        for refused in [
            "",
            "short",
            "AAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAA+",
        ] {
            assert!(StatusListId::parse(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn list_policy_closes_at_half_and_refuses_unusable_values() {
        let policy = ListPolicy::new(Duration::from_secs(3600)).unwrap();
        assert_eq!(policy.entry_count(), STATUS_LIST_ENTRY_COUNT);
        assert_eq!(policy.allocation_limit(), STATUS_LIST_ENTRY_COUNT / 2);
        assert!(ListPolicy::new(Duration::ZERO).is_err());
        assert!(ListPolicy::new(Duration::MAX).is_err());
        assert!(ListPolicy::with_entry_count(1, Duration::from_secs(1)).is_err());
        assert!(
            ListPolicy::with_entry_count(STATUS_LIST_ENTRY_COUNT + 1, Duration::from_secs(1))
                .is_err()
        );
        assert_eq!(
            ListPolicy::with_entry_count(8, Duration::from_secs(1))
                .unwrap()
                .allocation_limit(),
            4
        );
    }
}
