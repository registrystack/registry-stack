// SPDX-License-Identifier: Apache-2.0

//! The ledger every status suite runs against: an isolated schema in the
//! database `EVIDENCE_STATUS_TEST_DATABASE_URL` names, the issuance and
//! reserved pools, and test key rings and subjects.
//!
//! Every suite that includes this module uses a different part of it, so an
//! item one suite leaves unused is not dead code.
#![allow(dead_code)]

use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use registry_evidence::config::SelectorProfile;
use registry_evidence::status::{
    AllocationFields, CredentialMembers, HolderDigestKeyRing, HolderKeyThumbprint, IssuancePool,
    KeyRing, KeyVersion, LedgerConfig, ListPolicy, MappingVersion, ProvenanceText,
    PseudonymKeyRing, ReasonCategory, ReservedPool, SchemaName, SourceRead, SourceRevision,
    StatusKey, StatusLedger, StatusReference, StatusSubject, DEFAULT_CLOCK_SKEW,
    DEFAULT_ISSUANCE_POOL_SIZE, DEFAULT_RESERVED_POOL_SIZE,
};
use serde_json::{json, Map, Value};
use tokio_postgres::NoTls;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const DATABASE_URL_VARIABLE: &str = "EVIDENCE_STATUS_TEST_DATABASE_URL";
pub const PUBLIC_ORIGIN: &str = "https://status.example.test";
pub const SELECTOR_PROFILE_ID: &str = "person-reference";
pub const REQUIREMENT_ID: &str = "practice-permit";
/// A second status-required requirement keyed by the same selector profile.
pub const OTHER_REQUIREMENT_ID: &str = "disability-benefit";
pub const PSEUDONYM_KEY_BYTE: u8 = 0x51;
pub const HOLDER_DIGEST_KEY_BYTE: u8 = 0x52;
pub const PROMOTED_PSEUDONYM_KEY_BYTE: u8 = 0x53;
/// The ledger's advisory lock class for a pseudonym. A test holds it from
/// its own connection to interleave with the ledger deterministically.
pub const PSEUDONYM_LOCK_CLASS: i32 = 0x6576_7031;

/// A migrated ledger in its own schema, with both pools.
pub struct TestLedger {
    pub ledger: StatusLedger,
    pub issuance: IssuancePool,
    pub reserved: ReservedPool,
    pub schema: String,
}

fn database_config() -> tokio_postgres::Config {
    let url = std::env::var(DATABASE_URL_VARIABLE)
        .unwrap_or_else(|_| panic!("{DATABASE_URL_VARIABLE} must name a test database"));
    tokio_postgres::Config::from_str(&url)
        .unwrap_or_else(|_| panic!("{DATABASE_URL_VARIABLE} is not a PostgreSQL URL"))
}

/// A plaintext pool of `size` connections to the test database, optionally
/// tagged with an application name so a test can find its sessions.
pub fn pool(size: usize, application_name: Option<&str>) -> Pool {
    let mut config = database_config();
    if let Some(name) = application_name {
        config.application_name(name);
    }
    let manager = Manager::from_config(
        config,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        },
    );
    Pool::builder(manager)
        .max_size(size)
        .runtime(Runtime::Tokio1)
        .build()
        .expect("test pool builds")
}

/// A ledger over a fresh schema with the given list policy and key rings.
pub async fn ledger_with(
    list_policy: ListPolicy,
    pseudonym_keys: PseudonymKeyRing,
    holder_digest_keys: HolderDigestKeyRing,
    issuance_application_name: Option<&str>,
) -> TestLedger {
    let schema = format!("evidence_status_{}", Uuid::new_v4().simple());
    let ledger = StatusLedger::new(LedgerConfig {
        schema: SchemaName::new(&schema).expect("test schema name is valid"),
        public_origin: PUBLIC_ORIGIN.to_owned(),
        list_policy,
        pseudonym_keys,
        holder_digest_keys,
        clock_skew: DEFAULT_CLOCK_SKEW,
    })
    .expect("test ledger configuration is valid");
    let issuance = IssuancePool::new(pool(DEFAULT_ISSUANCE_POOL_SIZE, issuance_application_name));
    let reserved = ReservedPool::new(pool(DEFAULT_RESERVED_POOL_SIZE, None));
    ledger.migrate(&reserved).await.expect("ledger migrates");
    TestLedger {
        ledger,
        issuance,
        reserved,
        schema,
    }
}

/// A second ledger over `schema`, as another process sharing the database
/// with its own pseudonym key ring holds it.
pub fn ledger_on(schema: &str, pseudonym_keys: PseudonymKeyRing) -> StatusLedger {
    StatusLedger::new(LedgerConfig {
        schema: SchemaName::new(schema).expect("test schema name is valid"),
        public_origin: PUBLIC_ORIGIN.to_owned(),
        list_policy: ListPolicy::new(Duration::from_secs(30 * 24 * 60 * 60))
            .expect("policy is valid"),
        pseudonym_keys,
        holder_digest_keys: holder_digest_keys(),
        clock_skew: DEFAULT_CLOCK_SKEW,
    })
    .expect("test ledger configuration is valid")
}

/// A ledger with production list sizes and one key per ring.
pub async fn ledger() -> TestLedger {
    ledger_with(
        ListPolicy::new(Duration::from_secs(30 * 24 * 60 * 60)).expect("policy is valid"),
        pseudonym_keys(),
        holder_digest_keys(),
        None,
    )
    .await
}

/// A ledger whose lists hold `entry_count` entries.
pub async fn small_list_ledger(entry_count: u32, maximum_age: Duration) -> TestLedger {
    ledger_with(
        ListPolicy::with_entry_count(entry_count, maximum_age).expect("policy is valid"),
        pseudonym_keys(),
        holder_digest_keys(),
        None,
    )
    .await
}

pub fn key(version: u32, byte: u8) -> StatusKey {
    StatusKey::new(
        KeyVersion::new(version).expect("version is valid"),
        Zeroizing::new(vec![byte; 32]),
    )
    .expect("key is valid")
}

pub fn pseudonym_keys() -> PseudonymKeyRing {
    PseudonymKeyRing::new(KeyRing::new(key(1, PSEUDONYM_KEY_BYTE), Vec::new()).unwrap())
}

/// The pseudonym ring after a rotation promotes a second key and retains
/// the first.
pub fn promoted_pseudonym_keys() -> PseudonymKeyRing {
    PseudonymKeyRing::new(
        KeyRing::new(
            key(2, PROMOTED_PSEUDONYM_KEY_BYTE),
            vec![key(1, PSEUDONYM_KEY_BYTE)],
        )
        .unwrap(),
    )
}

pub fn holder_digest_keys() -> HolderDigestKeyRing {
    HolderDigestKeyRing::new(KeyRing::new(key(1, HOLDER_DIGEST_KEY_BYTE), Vec::new()).unwrap())
}

/// The ledger's second advisory lock key for `subject`'s pseudonym under the
/// current key of `keys`: its first four bytes.
pub fn pseudonym_lock_key(keys: &PseudonymKeyRing, subject: &StatusSubject) -> i32 {
    let pseudonym = keys.pseudonym(subject).expect("subject has a pseudonym");
    let bytes = pseudonym.as_bytes();
    i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Wait until some session waits on the pseudonym lock `key`, while `pending`
/// keeps being polled and must not finish.
pub async fn until_waiting_on_pseudonym_lock<F>(
    inspector: &tokio_postgres::Client,
    key: i32,
    pending: &mut std::pin::Pin<&mut F>,
) where
    F: std::future::Future,
{
    for _ in 0..100 {
        assert!(
            tokio::time::timeout(Duration::from_millis(50), pending.as_mut())
                .await
                .is_err(),
            "the ledger finished while the pseudonym lock was held"
        );
        let waiting: i64 = inspector
            .query_one(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted \
                 AND classid = $1::integer::oid AND objid = $2::integer::oid AND objsubid = 2",
                &[&PSEUDONYM_LOCK_CLASS, &key],
            )
            .await
            .expect("locks read")
            .get(0);
        if waiting > 0 {
            return;
        }
    }
    panic!("no session waited on the pseudonym lock");
}

pub fn selector_profile() -> SelectorProfile {
    serde_json::from_value(json!({
        "maximumAggregateBytes": 256,
        "fields": {
            "person_ref": {"type": "string", "minimumBytes": 1, "maximumBytes": 64}
        }
    }))
    .expect("selector profile parses")
}

/// The subject a hook projection would name with `person_ref` = `value`.
pub fn subject(value: &str) -> StatusSubject {
    let mut projection = Map::new();
    projection.insert("person_ref".to_owned(), Value::String(value.to_owned()));
    StatusSubject::from_json_projection(SELECTOR_PROFILE_ID, &selector_profile(), &projection)
        .expect("subject is valid")
}

/// A base64url SHA-256 thumbprint made of one repeated byte.
pub fn thumbprint(byte: u8) -> HolderKeyThumbprint {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    HolderKeyThumbprint::from_base64url(&URL_SAFE_NO_PAD.encode([byte; 32]))
        .expect("thumbprint is valid")
}

pub fn http_read(at: DateTime<Utc>) -> SourceRead {
    SourceRead::Http { request_time: at }
}

pub fn extract_read(published_at: DateTime<Utc>, evaluation_instant: DateTime<Utc>) -> SourceRead {
    SourceRead::Extract {
        published_at,
        evaluation_instant,
    }
}

pub fn mapping_version(version: u32) -> MappingVersion {
    MappingVersion::new(version).expect("mapping version is valid")
}

pub fn revision(revision: i64) -> SourceRevision {
    SourceRevision::new(revision).expect("revision is valid")
}

pub fn text(value: &str) -> ProvenanceText {
    ProvenanceText::new(value).expect("provenance text is valid")
}

pub fn reason(value: &str) -> ReasonCategory {
    ReasonCategory::new(value).expect("reason category is valid")
}

/// Allocate and commit `members` for `subject` with the given source read.
pub async fn allocate_for(
    ledger: &TestLedger,
    subject: &StatusSubject,
    source_read: SourceRead,
    members: CredentialMembers<'_>,
) -> Vec<StatusReference> {
    allocate_under(ledger, REQUIREMENT_ID, subject, source_read, members).await
}

/// Allocate and commit `members` of a `requirement_id` credential for
/// `subject` with the given source read.
pub async fn allocate_under(
    ledger: &TestLedger,
    requirement_id: &str,
    subject: &StatusSubject,
    source_read: SourceRead,
    members: CredentialMembers<'_>,
) -> Vec<StatusReference> {
    let issued_at = now();
    let fields = AllocationFields {
        requirement_id,
        subject,
        issued_at,
        not_after: issued_at + days(30),
        source_read,
    };
    let mut transaction = ledger
        .ledger
        .begin(&ledger.issuance, Duration::from_secs(20))
        .await
        .expect("issuance transaction begins");
    let references = transaction
        .allocate(&fields, members)
        .await
        .expect("entries allocate");
    transaction.commit().await.expect("allocation commits");
    references
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}

pub fn days(count: i64) -> TimeDelta {
    TimeDelta::days(count)
}

/// One plain connection for assertions, outside both ledger pools.
pub async fn inspector() -> tokio_postgres::Client {
    let (client, connection) = database_config()
        .connect(NoTls)
        .await
        .expect("test database is reachable");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            panic!("inspection connection failed: {error}");
        }
    });
    client
}

/// Every row of `table` in `schema`, in a stable order.
pub async fn rows(client: &tokio_postgres::Client, schema: &str, table: &str) -> Vec<Value> {
    let statement = format!(
        "SELECT row_to_json(t)::text FROM \"{schema}\".\"{table}\" t ORDER BY row_to_json(t)::text"
    );
    client
        .query(&statement, &[])
        .await
        .expect("table reads")
        .into_iter()
        .map(|row| serde_json::from_str(&row.get::<_, String>(0)).expect("row is JSON"))
        .collect()
}

/// One row of a schema dump: its table, its JSON form and its text form.
pub struct DumpedRow {
    pub table: String,
    pub json: Value,
    pub text: String,
}

/// Every row of every table in `schema`, as JSON and as PostgreSQL's row text.
pub async fn dump_schema(client: &tokio_postgres::Client, schema: &str) -> Vec<DumpedRow> {
    let tables = client
        .query(
            "SELECT table_name::text FROM information_schema.tables \
             WHERE table_schema = $1 ORDER BY table_name",
            &[&schema],
        )
        .await
        .expect("tables list");
    let mut dump = Vec::new();
    for table in tables {
        let table: String = table.get(0);
        let statement =
            format!("SELECT row_to_json(t)::text, t::text FROM \"{schema}\".\"{table}\" t");
        for row in client.query(&statement, &[]).await.expect("table dumps") {
            dump.push(DumpedRow {
                table: table.clone(),
                json: serde_json::from_str(&row.get::<_, String>(0)).expect("row is JSON"),
                text: row.get(1),
            });
        }
    }
    dump
}
