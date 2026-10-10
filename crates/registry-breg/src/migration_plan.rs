// SPDX-License-Identifier: Apache-2.0
//! Closed, reviewed migration descriptors and PostgreSQL AST validation.
//!
//! Threat: a reviewed migration artifact could otherwise smuggle a second
//! statement, session or role mutation, cross-schema access, unbounded DML, or
//! evidence for a different package into a package. This module is the
//! single validator used while constructing and rederiving package closure.

#[cfg(feature = "tooling")]
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "tooling")]
use pg_query::protobuf::{
    a_const, node::Node as PgNode, AExprKind, AlterTableType, ConstrType, ObjectType, SetOperation,
    SubLinkType,
};
#[cfg(feature = "tooling")]
use pg_query::NodeRef;
#[cfg(feature = "tooling")]
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_yaml::{
    ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader, RemovedKey, Report,
};

use crate::literal_text::{LiteralText, WRITE_THE_VALUE};
#[cfg(feature = "tooling")]
use registry_platform_yaml::{Diagnostic, Document, Severity};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "tooling")]
use sha2::{Digest, Sha256};
#[cfg(feature = "tooling")]
use thiserror::Error;

#[cfg(feature = "tooling")]
use crate::model::CompiledEntity;
#[cfg(feature = "tooling")]
use crate::package::CompiledRegistryChangeTargetKind;
use crate::package::{
    CompiledRegistryChange, CompiledRegistryChangeClass, CompiledRegistryChangeCode,
    CompiledRegistryChangeTarget,
};

#[cfg(feature = "tooling")]
const MAX_DESCRIPTOR_BYTES: usize = 1024 * 1024;
#[cfg(feature = "tooling")]
const MAX_SQL_BYTES: usize = 1024 * 1024;
#[cfg(feature = "tooling")]
const MAX_FIXTURE_BYTES: usize = 16 * 1024 * 1024;
#[cfg(feature = "tooling")]
const MAX_ARTIFACTS: usize = 1024;
#[cfg(feature = "tooling")]
const MAX_STEPS: usize = 256;
#[cfg(feature = "tooling")]
const MAX_ASSERTIONS: usize = 256;
const MAX_LOCK_TIMEOUT_MS: u64 = 300_000;
const MAX_STATEMENT_TIMEOUT_MS: u64 = 3_600_000;
/// Every chunk of a chunked or field-encryption backfill journals one commit
/// whose member budget the history machinery caps, so the chunk size shares
/// that cap.
const MAX_CHUNK_SIZE: u32 = crate::history_migration::MAX_HISTORY_MIGRATION_COMMIT_MEMBERS as u32;
const MAX_TOTAL_ROWS: u64 = 100_000_000;

pub const MIGRATION_DESCRIPTOR_API_VERSION: &str =
    "id.registrystack.org/formats/breg/migration-descriptor/v1alpha1";
pub const MIGRATION_DESCRIPTOR_KIND: &str = "BRegMigrationDescriptor";
pub const MIGRATION_REHEARSAL_RECEIPT_API_VERSION: &str =
    "id.registrystack.org/formats/breg/migration-rehearsal-receipt/v1alpha1";
pub const MIGRATION_REHEARSAL_RECEIPT_KIND: &str = "BRegMigrationRehearsalReceipt";
pub const BACKUP_BINDING_API_VERSION: &str =
    "id.registrystack.org/formats/breg/backup-binding/v1alpha1";
pub const BACKUP_BINDING_KIND: &str = "BRegBackupBinding";

/// A reviewed migration's `descriptor.json`.
pub const MIGRATION_DESCRIPTOR_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: MIGRATION_DESCRIPTOR_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(MIGRATION_DESCRIPTOR_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/lockTimeoutMs",
            replacement: "Rename `lockTimeoutMs` to `lockTimeoutMilliseconds`.",
        },
        RemovedKey {
            pointer: "/statementTimeoutMs",
            replacement: "Rename `statementTimeoutMs` to `statementTimeoutMilliseconds`.",
        },
        RemovedKey {
            pointer: "/steps/*/kind",
            replacement: "Rename `kind` to `type` and write its value in kebab case, such as `transactional-sql`.",
        },
        RemovedKey {
            pointer: "/steps/*/sql_path",
            replacement: "Rename `sql_path` to `sqlPath`.",
        },
        RemovedKey {
            pointer: "/steps/*/entity_id",
            replacement: "Rename `entity_id` to `entity`.",
        },
        RemovedKey {
            pointer: "/steps/*/affected_rows",
            replacement: "Rename `affected_rows` to `affectedRows`, with `minimum` and `maximum` members.",
        },
        RemovedKey {
            pointer: "/steps/*/affectedRows/min",
            replacement: "Rename `min` to `minimum`.",
        },
        RemovedKey {
            pointer: "/steps/*/affectedRows/max",
            replacement: "Rename `max` to `maximum`.",
        },
        RemovedKey {
            pointer: "/steps/*/chunk_size",
            replacement: "Rename `chunk_size` to `chunkSize`.",
        },
        RemovedKey {
            pointer: "/steps/*/max_total_rows",
            replacement: "Rename `max_total_rows` to `maximumTotalRows`.",
        },
        RemovedKey {
            pointer: "/steps/*/lock_timeout_ms",
            replacement: "Rename `lock_timeout_ms` to `lockTimeoutMilliseconds`.",
        },
        RemovedKey {
            pointer: "/steps/*/statement_timeout_ms",
            replacement: "Rename `statement_timeout_ms` to `statementTimeoutMilliseconds`.",
        },
        RemovedKey {
            pointer: "/steps/*/exact_affected_rows",
            replacement: "Rename `exact_affected_rows` to `exactAffectedRows`.",
        },
        RemovedKey {
            pointer: "/steps/*/objects/*/entityId",
            replacement: "Rename `entityId` to `entity`.",
        },
        RemovedKey {
            pointer: "/steps/*/objects/*/memberId",
            replacement: "Rename `memberId` to `member`.",
        },
    ],
};

/// A reviewed migration's `rehearsal.json`.
pub const MIGRATION_REHEARSAL_RECEIPT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: MIGRATION_REHEARSAL_RECEIPT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(MIGRATION_REHEARSAL_RECEIPT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/proofs",
            replacement: "Delete `proofs`; the descriptor already determines everything it asserted.",
        },
        RemovedKey {
            pointer: "/planSha256",
            replacement: "Rename `planSha256` to `planDigest`.",
        },
        RemovedKey {
            pointer: "/sqlSha256",
            replacement: "Rename `sqlSha256` to `sqlDigests`, whose items carry `path` and `digest`.",
        },
        RemovedKey {
            pointer: "/assertionSha256",
            replacement: "Rename `assertionSha256` to `assertionDigests`, whose items carry `path` and `digest`.",
        },
        RemovedKey {
            pointer: "/sqlDigests/*/sha256",
            replacement: "Rename `sha256` to `digest`.",
        },
        RemovedKey {
            pointer: "/assertionDigests/*/sha256",
            replacement: "Rename `sha256` to `digest`.",
        },
        RemovedKey {
            pointer: "/fixtureInventory/*/sha256",
            replacement: "Rename `sha256` to `digest`.",
        },
        RemovedKey {
            pointer: "/rowAssertions/*/stepId",
            replacement: "Rename `stepId` to `step`.",
        },
    ],
};

/// The operator's backup binding a destructive apply names with `--backup`.
pub const BACKUP_BINDING_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: BACKUP_BINDING_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(BACKUP_BINDING_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/databaseId",
            replacement: "Rename `databaseId` to `database`.",
        },
        RemovedKey {
            pointer: "/sha256",
            replacement: "Rename `sha256` to `digest`.",
        },
        RemovedKey {
            pointer: "/byteLength",
            replacement: "Rename `byteLength` to `sizeBytes`.",
        },
        RemovedKey {
            pointer: "/maxAgeSeconds",
            replacement: "Rename `maxAgeSeconds` to `maximumAgeSeconds`.",
        },
    ],
};

/// Read a reviewed migration descriptor through the shared reader, naming
/// it `file` in diagnostics.
pub fn read_migration_descriptor(
    file: &str,
    bytes: &[u8],
) -> Result<ReviewedMigrationDescriptor, Report> {
    Reader::new(file)
        .with_hook(&mut LiteralText {
            remedy: WRITE_THE_VALUE,
        })
        .decode(bytes, &Expect::one(&MIGRATION_DESCRIPTOR_FORMAT))
        .map(|decoded| decoded.value)
}

/// Read a migration rehearsal receipt through the shared reader, naming it
/// `file` in diagnostics.
pub fn read_rehearsal_receipt(
    file: &str,
    bytes: &[u8],
) -> Result<MigrationRehearsalReceipt, Report> {
    Reader::new(file)
        .decode(bytes, &Expect::one(&MIGRATION_REHEARSAL_RECEIPT_FORMAT))
        .map(|decoded| decoded.value)
}

/// Read a backup binding through the shared reader, naming it `file` in
/// diagnostics.
pub fn read_backup_binding_document(
    file: &str,
    bytes: &[u8],
) -> Result<ExternalBackupBinding, Report> {
    Reader::new(file)
        .with_hook(&mut LiteralText {
            remedy: WRITE_THE_VALUE,
        })
        .decode(bytes, &Expect::one(&BACKUP_BINDING_FORMAT))
        .map(|decoded| decoded.value)
}

/// Check a backup binding on its own: what [`ExternalBackupBinding`] must
/// satisfy before `bregctl migration apply` weighs it against the database,
/// the package, and the clock. `Err` carries the reader's refusal; `Ok` the
/// findings, each placed at the member it concerns.
#[cfg(feature = "tooling")]
pub fn check_backup_binding_document(document: &Document) -> Result<Vec<Diagnostic>, Report> {
    let binding: ExternalBackupBinding = document.decode()?;
    let mut diagnostics = Vec::new();
    if time::OffsetDateTime::parse(
        &binding.created_at,
        &time::format_description::well_known::Rfc3339,
    )
    .is_err()
    {
        diagnostics.push(document.diagnostic_at_value(
            Severity::Error,
            "breg.backup-binding.created-at",
            "/createdAt",
            "the creation time is not an RFC 3339 date and time",
            "Write `createdAt` as an RFC 3339 timestamp, such as 2026-01-31T09:30:00Z.",
        ));
    }
    if !std::path::Path::new(&binding.backup_file).is_absolute() {
        diagnostics.push(document.diagnostic_at_value(
            Severity::Error,
            "breg.backup-binding.backup-file",
            "/backupFile",
            "the backup file is not named by an absolute path",
            "Name the backup file by its absolute path on the host that applies the migration.",
        ));
    }
    Ok(diagnostics)
}

/// The three documents serialize with their `apiVersion` and `kind` header
/// first, so a written document is one the reader accepts. Decoding never
/// sees the header: the reader checks and strips it.
macro_rules! enveloped_document {
    ($type:ty, $api_version:expr, $kind:expr) => {
        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::Error as _;
                let serde_json::Value::Object(members) =
                    <$type>::serialize(self, serde_json::value::Serializer)
                        .map_err(S::Error::custom)?
                else {
                    return Err(S::Error::custom("a document serializes as a mapping"));
                };
                let mut document = serde_json::Map::with_capacity(members.len() + 2);
                document.insert("apiVersion".to_owned(), $api_version.into());
                document.insert("kind".to_owned(), $kind.into());
                document.extend(members);
                document.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                <$type>::deserialize(deserializer)
            }
        }
    };
}

/// Members decoded through the shared reader's types, so a refusal carries
/// its code and position (CFG-ID-1, CFG-QTY-4, CFG-VAL-6, CFG-ID-5).
mod members {
    use registry_platform_yaml::{
        BoundedU32, BoundedU64, Digest, Identified, Invalid, LocalId, UniqueIdList,
    };
    use serde::{Deserialize, Deserializer};

    pub(super) fn local_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
        LocalId::deserialize(deserializer).map(LocalId::into_string)
    }

    pub(super) fn digest<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
        Digest::deserialize(deserializer).map(Digest::into_string)
    }

    pub(super) fn unique_ids<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> + Identified,
    {
        UniqueIdList::<T>::deserialize(deserializer).map(UniqueIdList::into_vec)
    }

    pub(super) fn lock_timeout<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<u64, D::Error> {
        BoundedU64::<1, { super::MAX_LOCK_TIMEOUT_MS }>::deserialize(deserializer)
            .map(BoundedU64::get)
    }

    pub(super) fn statement_timeout<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<u64, D::Error> {
        BoundedU64::<1, { super::MAX_STATEMENT_TIMEOUT_MS }>::deserialize(deserializer)
            .map(BoundedU64::get)
    }

    pub(super) fn chunk_size<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        BoundedU32::<1, { super::MAX_CHUNK_SIZE }>::deserialize(deserializer).map(BoundedU32::get)
    }

    pub(super) fn total_rows<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        BoundedU64::<1, { super::MAX_TOTAL_ROWS }>::deserialize(deserializer).map(BoundedU64::get)
    }

    pub(super) fn row_count<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        BoundedU64::<0, { super::MAX_TOTAL_ROWS }>::deserialize(deserializer).map(BoundedU64::get)
    }

    pub(super) fn postgres_major<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<u16, D::Error> {
        let major = BoundedU32::<15, 18>::deserialize(deserializer)?;
        u16::try_from(major.get()).map_err(|_| Invalid::out_of_range(15, 18).into_error())
    }

    pub(super) fn backup_age<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        BoundedU64::<1, { crate::migration::MAX_BACKUP_AGE_SECONDS }>::deserialize(deserializer)
            .map(BoundedU64::get)
    }

    pub(super) fn size_bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        BoundedU64::<1, { u64::MAX }>::deserialize(deserializer).map(BoundedU64::get)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedMigrationFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedMigrationSource {
    pub module_id: String,
    pub descriptor: ReviewedMigrationFile,
    pub files: Vec<ReviewedMigrationFile>,
}

/// A reviewed migration's `descriptor.json`. Rust field names keep their
/// engine spelling; each serde rename names the document member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(remote = "Self", deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "schema", schemars(!remote))]
pub struct ReviewedMigrationDescriptor {
    #[serde(deserialize_with = "members::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    // Package comparison keeps the compiled class representation; semantic
    // descriptor validation below refuses the two non-reviewed classes.
    #[cfg_attr(feature = "schema", schemars(with = "ReviewedMigrationChangeClass"))]
    pub change_class: CompiledRegistryChangeClass,
    pub covers: Vec<ReviewedChangeCover>,
    pub recovery: ReviewedMigrationRecovery,
    /// The document member `lockTimeoutMilliseconds`.
    #[serde(
        rename = "lockTimeoutMilliseconds",
        deserialize_with = "members::lock_timeout"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU64<1, { MAX_LOCK_TIMEOUT_MS }>")
    )]
    pub lock_timeout_ms: u64,
    /// The document member `statementTimeoutMilliseconds`.
    #[serde(
        rename = "statementTimeoutMilliseconds",
        deserialize_with = "members::statement_timeout"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU64<1, { MAX_STATEMENT_TIMEOUT_MS }>")
    )]
    pub statement_timeout_ms: u64,
    #[serde(deserialize_with = "members::unique_ids")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::UniqueIdList<ReviewedMigrationStepDescriptor>")
    )]
    pub steps: Vec<ReviewedMigrationStepDescriptor>,
    #[serde(deserialize_with = "members::unique_ids")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueIdList<ReviewedMigrationAssertionDescriptor>"
        )
    )]
    pub pre_assertions: Vec<ReviewedMigrationAssertionDescriptor>,
    #[serde(deserialize_with = "members::unique_ids")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueIdList<ReviewedMigrationAssertionDescriptor>"
        )
    )]
    pub post_assertions: Vec<ReviewedMigrationAssertionDescriptor>,
    pub rehearsal_receipt_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_binding_path: Option<String>,
    /// The reviewed choice for pre-flip plaintext history. Required exactly
    /// when a cover turns field encryption on; carried with no default so a
    /// missing or silently assumed choice can never reach a plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<ReviewedFieldEncryptionHistory>,
}
enveloped_document!(
    ReviewedMigrationDescriptor,
    MIGRATION_DESCRIPTOR_API_VERSION,
    MIGRATION_DESCRIPTOR_KIND
);

/// The descriptor's schema vocabulary mirrors `descriptor_problems`, while
/// compiled package changes retain their broader internal classification.
#[cfg(feature = "schema")]
#[derive(schemars::JsonSchema)]
#[schemars(rename_all = "kebab-case")]
pub enum ReviewedMigrationChangeClass {
    DataBackfillRequired,
    AccessOrDisclosureChange,
    DestructiveOrIrreversible,
}

/// The JSON Schema of the descriptor members the reader decodes. The header
/// is checked and removed before decoding, so the publisher adds it.
#[cfg(feature = "schema")]
pub fn migration_descriptor_schema() -> schemars::Schema {
    schemars::schema_for!(ReviewedMigrationDescriptor)
}

/// What the reviewed plan does with the plaintext history that exists before
/// a field-encryption flip activates. `EraseAndRebaseline` destroys the full
/// per-record history after activation through the operator lifecycle;
/// `RetainPlaintextHistory` keeps serving pre-flip revisions as they were
/// written, scoped by the flip boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewedFieldEncryptionHistory {
    EraseAndRebaseline,
    RetainPlaintextHistory,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewedChangeCover {
    pub code: CompiledRegistryChangeCode,
    pub target: CompiledRegistryChangeTarget,
}

impl From<&CompiledRegistryChange> for ReviewedChangeCover {
    fn from(change: &CompiledRegistryChange) -> Self {
        Self {
            code: change.code,
            target: change.target.clone(),
        }
    }
}

/// How an interrupted activation of the reviewed plan is recovered.
/// `bregctl plan --format json` prints the same word.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewedMigrationRecovery {
    ExactTargetResume,
}

/// One reviewed step, tagged by `type` (CFG-ID-7). Rust field names keep
/// their engine spelling; each serde rename names the document member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    deny_unknown_fields,
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum ReviewedMigrationStepDescriptor {
    TransactionalSql {
        #[serde(deserialize_with = "members::local_id")]
        #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
        id: String,
        sql_path: String,
        objects: Vec<ReviewedMigrationObject>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        affected_rows: Option<AffectedRowBounds>,
    },
    ChunkedBackfill {
        #[serde(deserialize_with = "members::local_id")]
        #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
        id: String,
        /// The document member `entity`.
        #[serde(rename = "entity")]
        entity_id: String,
        sql_path: String,
        objects: Vec<ReviewedMigrationObject>,
        cursor: ChunkCursorProtocol,
        #[serde(deserialize_with = "members::chunk_size")]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_yaml::BoundedU32<1, { MAX_CHUNK_SIZE }>")
        )]
        chunk_size: u32,
        /// The document member `maximumTotalRows`.
        #[serde(rename = "maximumTotalRows", deserialize_with = "members::total_rows")]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_yaml::BoundedU64<1, { MAX_TOTAL_ROWS }>")
        )]
        max_total_rows: u64,
        /// The document member `lockTimeoutMilliseconds`.
        #[serde(
            rename = "lockTimeoutMilliseconds",
            deserialize_with = "members::lock_timeout"
        )]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_yaml::BoundedU64<1, { MAX_LOCK_TIMEOUT_MS }>")
        )]
        lock_timeout_ms: u64,
        /// The document member `statementTimeoutMilliseconds`.
        #[serde(
            rename = "statementTimeoutMilliseconds",
            deserialize_with = "members::statement_timeout"
        )]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_yaml::BoundedU64<1, { MAX_STATEMENT_TIMEOUT_MS }>")
        )]
        statement_timeout_ms: u64,
        exact_affected_rows: bool,
    },
    /// The engine-executed field-encryption backfill: it seals the plaintext
    /// column of every covered field into envelopes and blind indexes, chunk
    /// by chunk, with the journal and cursor effects each chunk commits. It
    /// carries no authored SQL; its bound statement content is the canonical
    /// JSON of this descriptor step, so the ledger checksum pins it without a
    /// SQL artifact.
    FieldEncryptionBackfill {
        #[serde(deserialize_with = "members::local_id")]
        #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
        id: String,
        /// The document member `entity`.
        #[serde(rename = "entity")]
        entity_id: String,
        objects: Vec<ReviewedMigrationObject>,
        cursor: ChunkCursorProtocol,
        #[serde(deserialize_with = "members::chunk_size")]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_yaml::BoundedU32<1, { MAX_CHUNK_SIZE }>")
        )]
        chunk_size: u32,
        /// The document member `maximumTotalRows`.
        #[serde(rename = "maximumTotalRows", deserialize_with = "members::total_rows")]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_yaml::BoundedU64<1, { MAX_TOTAL_ROWS }>")
        )]
        max_total_rows: u64,
        /// The document member `lockTimeoutMilliseconds`.
        #[serde(
            rename = "lockTimeoutMilliseconds",
            deserialize_with = "members::lock_timeout"
        )]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_yaml::BoundedU64<1, { MAX_LOCK_TIMEOUT_MS }>")
        )]
        lock_timeout_ms: u64,
        /// The document member `statementTimeoutMilliseconds`.
        #[serde(
            rename = "statementTimeoutMilliseconds",
            deserialize_with = "members::statement_timeout"
        )]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_yaml::BoundedU64<1, { MAX_STATEMENT_TIMEOUT_MS }>")
        )]
        statement_timeout_ms: u64,
    },
}
registry_platform_yaml::tagged_union!(ReviewedMigrationStepDescriptor);

/// A step serializes in the same `type`-tagged form it is read in, so the
/// canonical JSON a field-encryption backfill's checksum covers is the
/// reviewed document's own spelling.
impl Serialize for ReviewedMigrationStepDescriptor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let serde_json::Value::Object(external) =
            Self::serialize(self, serde_json::value::Serializer).map_err(S::Error::custom)?
        else {
            return Err(S::Error::custom("a step serializes as a mapping"));
        };
        let Some((tag, serde_json::Value::Object(members))) = external.into_iter().next() else {
            return Err(S::Error::custom("a step serializes as one tagged mapping"));
        };
        let mut step = serde_json::Map::with_capacity(members.len() + 1);
        step.insert("type".to_owned(), serde_json::Value::String(tag));
        step.extend(members);
        step.serialize(serializer)
    }
}

impl registry_platform_yaml::Identified for ReviewedMigrationStepDescriptor {
    fn id(&self) -> &str {
        match self {
            Self::TransactionalSql { id, .. }
            | Self::ChunkedBackfill { id, .. }
            | Self::FieldEncryptionBackfill { id, .. } => id,
        }
    }
}

impl ReviewedMigrationStepDescriptor {
    #[cfg(feature = "tooling")]
    fn id(&self) -> &str {
        registry_platform_yaml::Identified::id(self)
    }

    #[cfg(feature = "tooling")]
    fn sql_path(&self) -> Option<&str> {
        match self {
            Self::TransactionalSql { sql_path, .. } | Self::ChunkedBackfill { sql_path, .. } => {
                Some(sql_path)
            }
            Self::FieldEncryptionBackfill { .. } => None,
        }
    }

    #[cfg(feature = "tooling")]
    fn objects(&self) -> &[ReviewedMigrationObject] {
        match self {
            Self::TransactionalSql { objects, .. }
            | Self::ChunkedBackfill { objects, .. }
            | Self::FieldEncryptionBackfill { objects, .. } => objects,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewedMigrationObject {
    pub schema: String,
    pub table: String,
    /// The document member `entity`.
    #[serde(rename = "entity")]
    pub entity_id: String,
    pub kind: ReviewedMigrationObjectKind,
    /// The document member `member`.
    #[serde(rename = "member", default, skip_serializing_if = "Option::is_none")]
    pub member_id: Option<String>,
    pub physical_name: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewedMigrationObjectKind {
    Entity,
    Field,
    Constraint,
    Index,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ChunkCursorProtocol {
    RecordIdUuidArray,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AffectedRowBounds {
    /// The document member `minimum`.
    #[serde(rename = "minimum", deserialize_with = "members::row_count")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU64<0, { MAX_TOTAL_ROWS }>")
    )]
    pub min: u64,
    /// The document member `maximum`.
    #[serde(rename = "maximum", deserialize_with = "members::row_count")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU64<0, { MAX_TOTAL_ROWS }>")
    )]
    pub max: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewedMigrationAssertionDescriptor {
    #[serde(deserialize_with = "members::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub sql_path: String,
}

impl registry_platform_yaml::Identified for ReviewedMigrationAssertionDescriptor {
    fn id(&self) -> &str {
        &self.id
    }
}

/// A reviewed migration's `rehearsal.json`. Rust field names keep their
/// engine spelling; each serde rename names the document member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields, rename_all = "camelCase")]
pub struct MigrationRehearsalReceipt {
    #[serde(deserialize_with = "members::digest")]
    pub prior_package_digest: String,
    #[serde(deserialize_with = "members::digest")]
    pub prior_schema_fingerprint: String,
    /// The document member `planDigest`: the digest of the descriptor's
    /// canonical JSON.
    #[serde(rename = "planDigest", deserialize_with = "members::digest")]
    pub plan_sha256: String,
    /// The document member `sqlDigests`.
    #[serde(rename = "sqlDigests")]
    pub sql_sha256: Vec<ArtifactDigestBinding>,
    /// The document member `assertionDigests`.
    #[serde(rename = "assertionDigests")]
    pub assertion_sha256: Vec<ArtifactDigestBinding>,
    pub fixture_inventory: Vec<RehearsalFixture>,
    #[serde(deserialize_with = "members::postgres_major")]
    pub postgres_major: u16,
    pub row_assertions: Vec<RehearsalRowAssertion>,
    #[serde(deserialize_with = "members::digest")]
    pub final_schema_fingerprint: String,
}
enveloped_document!(
    MigrationRehearsalReceipt,
    MIGRATION_REHEARSAL_RECEIPT_API_VERSION,
    MIGRATION_REHEARSAL_RECEIPT_KIND
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArtifactDigestBinding {
    pub path: String,
    /// The document member `digest`.
    #[serde(rename = "digest", deserialize_with = "members::digest")]
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RehearsalFixture {
    #[serde(deserialize_with = "members::local_id")]
    pub id: String,
    pub path: String,
    /// The document member `digest`.
    #[serde(rename = "digest", deserialize_with = "members::digest")]
    pub sha256: String,
    #[serde(deserialize_with = "members::row_count")]
    pub row_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RehearsalRowAssertion {
    /// The document member `step`.
    #[serde(rename = "step", deserialize_with = "members::local_id")]
    pub step_id: String,
    #[serde(deserialize_with = "members::row_count")]
    pub affected_rows: u64,
}

/// The operator's backup binding. Rust field names keep their engine
/// spelling; each serde rename names the document member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(remote = "Self", deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "schema", schemars(!remote))]
pub struct ExternalBackupBinding {
    /// The document member `database`: the database identity the binding
    /// was taken from.
    #[serde(rename = "database")]
    pub database_id: String,
    #[serde(deserialize_with = "members::digest")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Digest"))]
    pub prior_package_digest: String,
    #[serde(deserialize_with = "members::digest")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Digest"))]
    pub prior_schema_fingerprint: String,
    pub backup_file: String,
    /// The document member `digest`.
    #[serde(rename = "digest", deserialize_with = "members::digest")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Digest"))]
    pub sha256: String,
    /// The document member `sizeBytes`.
    #[serde(rename = "sizeBytes", deserialize_with = "members::size_bytes")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU64<1, { u64::MAX }>")
    )]
    pub byte_length: u64,
    pub created_at: String,
    /// The document member `maximumAgeSeconds`.
    #[serde(rename = "maximumAgeSeconds", deserialize_with = "members::backup_age")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::BoundedU64<1, { crate::migration::MAX_BACKUP_AGE_SECONDS }>"
        )
    )]
    pub max_age_seconds: u64,
}

/// The JSON Schema of the backup binding members the reader decodes. The
/// header is checked and removed before decoding, so the publisher adds it.
#[cfg(feature = "schema")]
pub fn backup_binding_schema() -> schemars::Schema {
    schemars::schema_for!(ExternalBackupBinding)
}
enveloped_document!(
    ExternalBackupBinding,
    BACKUP_BINDING_API_VERSION,
    BACKUP_BINDING_KIND
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReviewedMigrationPlan {
    migrations: Vec<ValidatedReviewedMigration>,
}

impl ValidatedReviewedMigrationPlan {
    #[must_use]
    pub fn migrations(&self) -> &[ValidatedReviewedMigration] {
        &self.migrations
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReviewedMigration {
    pub module_id: String,
    pub descriptor_path: String,
    pub descriptor: ReviewedMigrationDescriptor,
    pub steps: Vec<ValidatedReviewedMigrationStep>,
    pub pre_assertions: Vec<ValidatedReviewedMigrationAssertion>,
    pub post_assertions: Vec<ValidatedReviewedMigrationAssertion>,
    pub rehearsal_receipt: MigrationRehearsalReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReviewedMigrationStep {
    pub descriptor: ReviewedMigrationStepDescriptor,
    pub sql: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReviewedMigrationAssertion {
    pub descriptor: ReviewedMigrationAssertionDescriptor,
    pub sql: String,
    pub sha256: String,
}

#[cfg(feature = "tooling")]
#[derive(Clone, Debug)]
pub(crate) struct ReviewedPlanBindings<'a> {
    pub prior_package_digest: &'a str,
    pub prior_schema_fingerprint: &'a str,
    pub final_schema_fingerprint: &'a str,
    pub changes: &'a [CompiledRegistryChange],
    pub prior_entities: &'a BTreeMap<String, CompiledEntity>,
    pub candidate_entities: &'a BTreeMap<String, CompiledEntity>,
    pub prior_physical_names: &'a crate::physical_names::PhysicalNameInventory,
    pub candidate_physical_names: &'a crate::physical_names::PhysicalNameInventory,
}

#[cfg(feature = "tooling")]
#[derive(Clone, Debug)]
pub(crate) struct PreparedReviewedMigrationPlan {
    pub descriptor_paths: Vec<String>,
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewedArtifactKind {
    Descriptor,
    StepSql,
    AssertionSql,
    RehearsalReceipt,
    Fixture,
}

#[cfg(feature = "tooling")]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReviewedMigrationError {
    #[error("the reviewed migration descriptor is invalid")]
    Descriptor,
    #[error("the reviewed migration coverage is invalid")]
    Coverage,
    #[error("the reviewed migration SQL is outside the accepted AST")]
    Sql,
    #[error("the reviewed migration evidence is not bound")]
    Evidence,
    #[error("the reviewed migration artifact closure is invalid")]
    Closure,
}

#[cfg(feature = "tooling")]
pub(crate) fn prepare_reviewed_migration_plan(
    sources: &[ReviewedMigrationSource],
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<PreparedReviewedMigrationPlan, ReviewedMigrationError> {
    if sources.is_empty() || sources.len() > MAX_ARTIFACTS {
        return Err(ReviewedMigrationError::Coverage);
    }
    let mut descriptor_paths = Vec::with_capacity(sources.len());
    let mut files = BTreeMap::new();
    let mut prior_descriptor = None;
    for source in sources {
        if !valid_id(&source.module_id)
            || prior_descriptor
                .as_ref()
                .is_some_and(|prior: &String| prior >= &source.descriptor.path)
        {
            return Err(ReviewedMigrationError::Descriptor);
        }
        prior_descriptor = Some(source.descriptor.path.clone());
        descriptor_paths.push(source.descriptor.path.clone());
        if files
            .insert(
                source.descriptor.path.clone(),
                source.descriptor.bytes.clone(),
            )
            .is_some()
        {
            return Err(ReviewedMigrationError::Closure);
        }
        for file in &source.files {
            // Only reviewed artifacts in the package layout travel with a
            // review. A backup binding describes one database's backup, so it
            // is an apply input and never a package file.
            if reviewed_artifact_kind(&file.path).is_none()
                || files
                    .insert(file.path.clone(), file.bytes.clone())
                    .is_some()
            {
                return Err(ReviewedMigrationError::Closure);
            }
        }
    }
    let validated = validate_reviewed_migration_plan(&descriptor_paths, &files, bindings)?;
    for (source, migration) in sources.iter().zip(validated.migrations()) {
        if source.module_id != migration.module_id {
            return Err(ReviewedMigrationError::Descriptor);
        }
    }
    Ok(PreparedReviewedMigrationPlan {
        descriptor_paths,
        files,
    })
}

#[cfg(feature = "tooling")]
pub(crate) fn validate_reviewed_migration_plan(
    descriptor_paths: &[String],
    files: &BTreeMap<String, Vec<u8>>,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<ValidatedReviewedMigrationPlan, ReviewedMigrationError> {
    if descriptor_paths.len() > MAX_ARTIFACTS
        || !strictly_sorted(descriptor_paths.iter().map(String::as_str))
    {
        return Err(ReviewedMigrationError::Closure);
    }
    if bindings
        .changes
        .iter()
        .any(|change| change.class == CompiledRegistryChangeClass::Unsupported)
    {
        return Err(ReviewedMigrationError::Coverage);
    }

    let declared_tables = bindings
        .prior_entities
        .values()
        .chain(bindings.candidate_entities.values())
        .map(|entity| entity.physical_table.as_str())
        .collect::<BTreeSet<_>>();
    let non_additive = bindings
        .changes
        .iter()
        .filter(|change| change.class != CompiledRegistryChangeClass::CompatibleAdditive)
        .map(|change| (ReviewedChangeCover::from(change), change.class))
        .collect::<BTreeMap<_, _>>();
    if non_additive.is_empty() != descriptor_paths.is_empty() {
        return Err(ReviewedMigrationError::Coverage);
    }

    let mut claimed = BTreeSet::new();
    let mut referenced_paths = BTreeSet::new();
    let mut migrations = Vec::with_capacity(descriptor_paths.len());
    for descriptor_path in descriptor_paths {
        let descriptor_bytes = files
            .get(descriptor_path)
            .ok_or(ReviewedMigrationError::Closure)?;
        if descriptor_bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(ReviewedMigrationError::Descriptor);
        }
        let decoded = Reader::new(descriptor_path.as_str())
            .with_hook(&mut LiteralText {
                remedy: WRITE_THE_VALUE,
            })
            .decode::<ReviewedMigrationDescriptor>(
                descriptor_bytes,
                &Expect::one(&MIGRATION_DESCRIPTOR_FORMAT),
            )
            .map_err(|_| ReviewedMigrationError::Descriptor)?;
        // The receipt binds the descriptor's canonical JSON, so reformatting
        // the authored file never invalidates its rehearsal.
        let plan_digest = digest(
            &canonicalize_json(&decoded.document.to_json_value())
                .map_err(|_| ReviewedMigrationError::Descriptor)?,
        );
        let descriptor = decoded.value;
        let (module_id, base) = descriptor_base(descriptor_path, &descriptor.id)?;
        referenced_paths.insert(descriptor_path.clone());
        validate_descriptor_shape(&descriptor, &base)?;
        for cover in &descriptor.covers {
            let Some(expected_class) = non_additive.get(cover) else {
                return Err(ReviewedMigrationError::Coverage);
            };
            if *expected_class != descriptor.change_class || !claimed.insert(cover.clone()) {
                return Err(ReviewedMigrationError::Coverage);
            }
        }

        let mut steps = Vec::with_capacity(descriptor.steps.len());
        let mut object_covers = BTreeSet::new();
        for step in &descriptor.steps {
            match step.sql_path() {
                Some(path) => {
                    referenced_paths.insert(path.to_owned());
                    let sql = read_sql(files, path)?;
                    validate_step_sql(step, sql, &descriptor, bindings, &declared_tables)?;
                    for object in step.objects() {
                        object_covers.insert(object_cover(object, &descriptor.covers)?);
                    }
                    steps.push(ValidatedReviewedMigrationStep {
                        descriptor: step.clone(),
                        sql: sql.to_owned(),
                        sha256: digest(sql.as_bytes()),
                    });
                }
                None => {
                    // The engine-executed backfill binds no SQL artifact. Its
                    // ledger checksum covers the canonical JSON of the step
                    // descriptor itself, so any field of the step is pinned
                    // exactly the way authored SQL would be.
                    validate_step_sql(step, "", &descriptor, bindings, &declared_tables)?;
                    for object in step.objects() {
                        object_covers.insert(object_cover(object, &descriptor.covers)?);
                    }
                    let canonical_step = canonicalize_json(
                        &serde_json::to_value(step)
                            .map_err(|_| ReviewedMigrationError::Descriptor)?,
                    )
                    .map_err(|_| ReviewedMigrationError::Descriptor)?;
                    let sql = String::from_utf8(canonical_step)
                        .map_err(|_| ReviewedMigrationError::Descriptor)?;
                    steps.push(ValidatedReviewedMigrationStep {
                        descriptor: step.clone(),
                        sha256: digest(sql.as_bytes()),
                        sql,
                    });
                }
            }
        }
        validate_field_encryption_drop_order(&descriptor, &steps)?;
        let descriptor_covers = descriptor.covers.iter().cloned().collect::<BTreeSet<_>>();
        if descriptor.steps.is_empty() && covers_are_metadata_only(&descriptor.covers) {
            object_covers = descriptor_covers.clone();
        }
        if object_covers != descriptor_covers {
            return Err(ReviewedMigrationError::Coverage);
        }
        let pre_assertions = validate_assertions(
            &descriptor.pre_assertions,
            files,
            &declared_tables,
            &mut referenced_paths,
        )?;
        let post_assertions = validate_assertions(
            &descriptor.post_assertions,
            files,
            &declared_tables,
            &mut referenced_paths,
        )?;

        referenced_paths.insert(descriptor.rehearsal_receipt_path.clone());
        let receipt_bytes = files
            .get(&descriptor.rehearsal_receipt_path)
            .ok_or(ReviewedMigrationError::Evidence)?;
        let receipt = read_rehearsal_receipt(&descriptor.rehearsal_receipt_path, receipt_bytes)
            .map_err(|_| ReviewedMigrationError::Evidence)?;
        validate_receipt(
            &receipt,
            ReceiptValidationContext {
                plan_digest: &plan_digest,
                steps: &steps,
                pre_assertions: &pre_assertions,
                post_assertions: &post_assertions,
                descriptor: &descriptor,
                bindings,
                base: &base,
                files,
                referenced_paths: &mut referenced_paths,
            },
        )?;

        // A destructive migration names the backup binding apply requires;
        // the binding itself describes one database's backup, so it is an
        // apply input and never a package file.
        if descriptor.change_class == CompiledRegistryChangeClass::DestructiveOrIrreversible
            && descriptor.backup_binding_path.is_none()
        {
            return Err(ReviewedMigrationError::Evidence);
        }
        migrations.push(ValidatedReviewedMigration {
            module_id,
            descriptor_path: descriptor_path.clone(),
            descriptor,
            steps,
            pre_assertions,
            post_assertions,
            rehearsal_receipt: receipt,
        });
    }
    if claimed != non_additive.keys().cloned().collect()
        || referenced_paths != files.keys().cloned().collect()
    {
        return Err(ReviewedMigrationError::Coverage);
    }
    validate_field_encryption_step_grouping(&migrations)?;
    Ok(ValidatedReviewedMigrationPlan { migrations })
}

/// Every simultaneous plaintext-to-envelope transition for one entity shares
/// one engine step. History capture projects the successor entity, so splitting
/// those fields across steps would record later envelope columns as null before
/// their predecessor plaintext had been sealed.
#[cfg(feature = "tooling")]
fn validate_field_encryption_step_grouping(
    migrations: &[ValidatedReviewedMigration],
) -> Result<(), ReviewedMigrationError> {
    let mut expected = BTreeMap::<String, BTreeSet<String>>::new();
    let mut steps = BTreeMap::<String, Vec<BTreeSet<String>>>::new();
    for migration in migrations {
        for cover in &migration.descriptor.covers {
            if cover.code != CompiledRegistryChangeCode::FieldEncryptionChanged {
                continue;
            }
            let entity_id = cover
                .target
                .entity_id
                .as_ref()
                .ok_or(ReviewedMigrationError::Coverage)?;
            let field_id = cover
                .target
                .member_id
                .as_ref()
                .ok_or(ReviewedMigrationError::Coverage)?;
            expected
                .entry(entity_id.clone())
                .or_default()
                .insert(field_id.clone());
        }
        for step in &migration.steps {
            let ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
                entity_id, objects, ..
            } = &step.descriptor
            else {
                continue;
            };
            let fields = objects
                .iter()
                .filter_map(|object| {
                    let member_id = object.member_id.as_deref()?;
                    (!member_id.ends_with("#lookup")).then(|| member_id.to_owned())
                })
                .collect::<BTreeSet<_>>();
            steps.entry(entity_id.clone()).or_default().push(fields);
        }
    }
    if expected.len() != steps.len() {
        return Err(ReviewedMigrationError::Coverage);
    }
    for (entity_id, fields) in expected {
        let entity_steps = steps
            .get(&entity_id)
            .ok_or(ReviewedMigrationError::Coverage)?;
        if entity_steps.len() != 1 || entity_steps[0] != fields {
            return Err(ReviewedMigrationError::Coverage);
        }
    }
    Ok(())
}

/// A plaintext column covered by a field-encryption flip must remain available
/// until the engine-executed backfill has sealed it. The reviewed descriptor
/// already binds both the logical member and each physical SQL object, so this
/// ordering check needs no inferred catalog state.
#[cfg(feature = "tooling")]
fn validate_field_encryption_drop_order(
    descriptor: &ReviewedMigrationDescriptor,
    steps: &[ValidatedReviewedMigrationStep],
) -> Result<(), ReviewedMigrationError> {
    let flipped_fields = descriptor
        .covers
        .iter()
        .filter(|cover| cover.code == CompiledRegistryChangeCode::FieldEncryptionChanged)
        .filter_map(|cover| {
            Some((
                cover.target.entity_id.as_ref()?.clone(),
                cover.target.member_id.as_ref()?.clone(),
            ))
        })
        .collect::<BTreeSet<_>>();
    if flipped_fields.is_empty() {
        return Ok(());
    }

    let mut sealed_fields = BTreeSet::new();
    for step in steps {
        match &step.descriptor {
            ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { objects, .. } => {
                sealed_fields.extend(objects.iter().filter_map(|object| {
                    let member_id = object.member_id.as_deref()?;
                    if member_id.ends_with("#lookup") {
                        return None;
                    }
                    let field = (object.entity_id.clone(), member_id.to_owned());
                    flipped_fields.contains(&field).then_some(field)
                }));
            }
            ReviewedMigrationStepDescriptor::TransactionalSql { objects, .. } => {
                let parsed = parse_one(&step.sql)?;
                let PgNode::AlterTableStmt(alter) = root_node(&parsed)? else {
                    continue;
                };
                for command in &alter.cmds {
                    let Some(PgNode::AlterTableCmd(command)) = command.node.as_ref() else {
                        return Err(ReviewedMigrationError::Sql);
                    };
                    if AlterTableType::try_from(command.subtype).ok()
                        != Some(AlterTableType::AtDropColumn)
                    {
                        continue;
                    }
                    let Some(object) = objects.iter().find(|object| {
                        object.kind == ReviewedMigrationObjectKind::Field
                            && object.physical_name == command.name
                    }) else {
                        return Err(ReviewedMigrationError::Sql);
                    };
                    let Some(member_id) = object.member_id.as_ref() else {
                        return Err(ReviewedMigrationError::Descriptor);
                    };
                    let field = (object.entity_id.clone(), member_id.clone());
                    if flipped_fields.contains(&field) && !sealed_fields.contains(&field) {
                        return Err(ReviewedMigrationError::Descriptor);
                    }
                }
            }
            ReviewedMigrationStepDescriptor::ChunkedBackfill { .. } => {}
        }
    }
    Ok(())
}

/// Classify a permitted package-relative reviewed artifact path before reading it.
pub fn reviewed_artifact_kind(path: &str) -> Option<ReviewedArtifactKind> {
    let components = path.split('/').collect::<Vec<_>>();
    match components.as_slice() {
        ["modules", module, "migrations", migration, "descriptor.json"]
            if valid_id(module) && valid_id(migration) =>
        {
            Some(ReviewedArtifactKind::Descriptor)
        }
        ["modules", module, "migrations", migration, "steps", file]
            if valid_id(module)
                && valid_id(migration)
                && file.strip_suffix(".sql").is_some_and(valid_id) =>
        {
            Some(ReviewedArtifactKind::StepSql)
        }
        ["modules", module, "migrations", migration, "assertions", file]
            if valid_id(module)
                && valid_id(migration)
                && file.strip_suffix(".sql").is_some_and(valid_id) =>
        {
            Some(ReviewedArtifactKind::AssertionSql)
        }
        ["modules", module, "migrations", migration, "rehearsal.json"]
            if valid_id(module) && valid_id(migration) =>
        {
            Some(ReviewedArtifactKind::RehearsalReceipt)
        }
        ["modules", module, "migrations", migration, "fixtures", file]
            if valid_id(module)
                && valid_id(migration)
                && file.strip_suffix(".jsonl").is_some_and(valid_id) =>
        {
            Some(ReviewedArtifactKind::Fixture)
        }
        _ => None,
    }
}

#[cfg(feature = "tooling")]
fn validate_descriptor_shape(
    descriptor: &ReviewedMigrationDescriptor,
    base: &str,
) -> Result<(), ReviewedMigrationError> {
    if descriptor_problems(descriptor, Some(base)).is_empty() {
        Ok(())
    } else {
        Err(ReviewedMigrationError::Descriptor)
    }
}

/// Check a reviewed migration descriptor on its own, without the project
/// it belongs to: everything [`ReviewedMigrationDescriptor`] must satisfy
/// before its coverage, SQL, and rehearsal are weighed against a candidate.
/// `location` is the descriptor's path from the project root, when the file
/// sits at `modules/<module>/migrations/<id>/descriptor.json`; without it,
/// the artifact paths the descriptor names are not checked and a warning
/// says so. `Err` carries the reader's refusal; `Ok` the findings, each
/// placed at the member it concerns.
#[cfg(feature = "tooling")]
pub fn check_migration_descriptor(
    document: &Document,
    location: Option<&str>,
) -> Result<Vec<Diagnostic>, Report> {
    let descriptor: ReviewedMigrationDescriptor = document.decode()?;
    let mut diagnostics = Vec::new();
    let base = match location.map(|location| descriptor_base(location, &descriptor.id)) {
        Some(Ok((_, base))) => Some(base),
        Some(Err(_)) => {
            diagnostics.push(document.diagnostic_at_value(
                Severity::Error,
                "breg.migration.descriptor-location",
                "/id",
                "the descriptor's `id` is not the name of the directory it is in",
                "Rename the directory or change `id` so the two match.",
            ));
            None
        }
        None => {
            diagnostics.push(document.diagnostic_at_value(
                Severity::Warning,
                "breg.migration.descriptor-location",
                "",
                "the file is not at modules/<module>/migrations/<id>/descriptor.json, so the \
                 artifact paths it names were not checked",
                "Check the descriptor where it lives in the project.",
            ));
            None
        }
    };
    for problem in descriptor_problems(&descriptor, base.as_deref()) {
        diagnostics.push(diagnostic_near(
            document,
            problem.code,
            &problem.pointer,
            &problem.message,
            problem.action,
        ));
    }
    Ok(diagnostics)
}

/// An error about the member at `pointer`, placed at the nearest member the
/// document writes when that one is absent.
#[cfg(feature = "tooling")]
fn diagnostic_near(
    document: &Document,
    code: &str,
    pointer: &str,
    message: &str,
    action: &str,
) -> Diagnostic {
    let mut written = pointer;
    while document.span_of(written).is_none() {
        match written.rfind('/') {
            Some(parent) => written = &written[..parent],
            None => break,
        }
    }
    let mut diagnostic =
        document.diagnostic_at_value(Severity::Error, code, written, message, action);
    diagnostic.path = pointer.to_owned();
    diagnostic
}

/// One reason a descriptor's own content is refused: the member at fault,
/// what is wrong with it, and the fix. No message repeats a value.
#[cfg(feature = "tooling")]
struct DescriptorProblem {
    code: &'static str,
    pointer: String,
    message: String,
    action: &'static str,
}

/// Every reason the descriptor's own content is refused. With `base`, the
/// descriptor's directory from the project root, the artifact paths it
/// names are checked too.
#[cfg(feature = "tooling")]
fn descriptor_problems(
    descriptor: &ReviewedMigrationDescriptor,
    base: Option<&str>,
) -> Vec<DescriptorProblem> {
    let mut problems = Vec::new();
    let mut refuse =
        |code: &'static str, pointer: String, message: String, action: &'static str| {
            problems.push(DescriptorProblem {
                code,
                pointer,
                message,
                action,
            });
        };
    let identifier_rule = "Use 1 to 96 characters, starting with a lowercase letter, from a-z, \
                           0-9, `-`, and `_`.";
    let metadata_only = covers_are_metadata_only(&descriptor.covers);
    if !valid_id(&descriptor.id) {
        refuse(
            "breg.migration.identifier",
            "/id".to_owned(),
            "the descriptor identifier is not valid".to_owned(),
            identifier_rule,
        );
    }
    if matches!(
        descriptor.change_class,
        CompiledRegistryChangeClass::CompatibleAdditive | CompiledRegistryChangeClass::Unsupported
    ) {
        refuse(
            "breg.migration.change-class",
            "/changeClass".to_owned(),
            "a reviewed migration covers data-backfill-required, access-or-disclosure-change, or \
             destructive-or-irreversible changes only"
                .to_owned(),
            "Name the change class `bregctl migration plan` reports for the covered changes.",
        );
    }
    if descriptor.covers.is_empty() {
        refuse(
            "breg.migration.covers",
            "/covers".to_owned(),
            "a descriptor covers at least one change".to_owned(),
            "List the changes this migration reviews, as `bregctl migration plan` reports them.",
        );
    } else if !strictly_sorted(descriptor.covers.iter()) {
        refuse(
            "breg.migration.covers",
            "/covers".to_owned(),
            "`covers` must be sorted and name each change once".to_owned(),
            "Sort the covers by code and then target, and remove repeats.",
        );
    }
    if descriptor.steps.is_empty() && !metadata_only {
        refuse(
            "breg.migration.steps",
            "/steps".to_owned(),
            "a descriptor covering more than metadata names at least one step".to_owned(),
            "Add the steps that carry out the change.",
        );
    }
    if descriptor.steps.len() > MAX_STEPS {
        refuse(
            "breg.migration.steps",
            "/steps".to_owned(),
            format!("a descriptor names at most {MAX_STEPS} steps"),
            "Split the migration across several descriptors.",
        );
    }
    for (member, assertions) in [
        ("preAssertions", &descriptor.pre_assertions),
        ("postAssertions", &descriptor.post_assertions),
    ] {
        if assertions.is_empty() && !metadata_only {
            refuse(
                "breg.migration.assertions",
                format!("/{member}"),
                "a descriptor covering more than metadata names at least one assertion here"
                    .to_owned(),
                "Add an assertion that proves the state the migration starts or ends in.",
            );
        }
        if assertions.len() > MAX_ASSERTIONS {
            refuse(
                "breg.migration.assertions",
                format!("/{member}"),
                format!("a descriptor names at most {MAX_ASSERTIONS} assertions here"),
                "Combine assertions, or split the migration across several descriptors.",
            );
        }
    }
    if !valid_timeout(descriptor.lock_timeout_ms, MAX_LOCK_TIMEOUT_MS) {
        refuse(
            "breg.migration.timeout",
            "/lockTimeoutMilliseconds".to_owned(),
            format!("the lock timeout is from 1 to {MAX_LOCK_TIMEOUT_MS} milliseconds"),
            "Set a lock timeout within the bound.",
        );
    }
    if !valid_timeout(descriptor.statement_timeout_ms, MAX_STATEMENT_TIMEOUT_MS) {
        refuse(
            "breg.migration.timeout",
            "/statementTimeoutMilliseconds".to_owned(),
            format!("the statement timeout is from 1 to {MAX_STATEMENT_TIMEOUT_MS} milliseconds"),
            "Set a statement timeout within the bound.",
        );
    }
    if descriptor.recovery != ReviewedMigrationRecovery::ExactTargetResume {
        refuse(
            "breg.migration.recovery",
            "/recovery".to_owned(),
            "the only recovery a reviewed migration has is exact-target-resume".to_owned(),
            "Set `recovery` to exact-target-resume.",
        );
    }
    if let Some(base) = base {
        if descriptor.rehearsal_receipt_path != format!("{base}/rehearsal.json") {
            refuse(
                "breg.migration.artifact-path",
                "/rehearsalReceiptPath".to_owned(),
                "the rehearsal receipt is the file rehearsal.json beside the descriptor, named \
                 from the project root"
                    .to_owned(),
                "Set `rehearsalReceiptPath` to modules/<module>/migrations/<id>/rehearsal.json.",
            );
        }
        if descriptor
            .backup_binding_path
            .as_ref()
            .is_some_and(|path| path != &format!("{base}/backup.json"))
        {
            refuse(
                "breg.migration.artifact-path",
                "/backupBindingPath".to_owned(),
                "the backup binding is the file backup.json beside the descriptor, named from \
                 the project root"
                    .to_owned(),
                "Set `backupBindingPath` to modules/<module>/migrations/<id>/backup.json.",
            );
        }
    }
    // The history choice is explicit or absent, never assumed: a plan that
    // turns field encryption on refuses without one, and any other plan
    // refuses with one.
    match (
        descriptor_covers_field_encryption_flip(descriptor),
        descriptor.history.is_some(),
    ) {
        (true, false) => refuse(
            "breg.migration.history",
            "/history".to_owned(),
            "a plan that turns field encryption on carries a reviewed `history` choice".to_owned(),
            "Add `history` with erase-and-rebaseline or retain-plaintext-history.",
        ),
        (false, true) => refuse(
            "breg.migration.history",
            "/history".to_owned(),
            "`history` applies only to a plan that turns field encryption on".to_owned(),
            "Remove `history`.",
        ),
        _ => {}
    }
    let mut ids = BTreeSet::new();
    for (index, step) in descriptor.steps.iter().enumerate() {
        let pointer = format!("/steps/{index}");
        if !valid_id(step.id()) {
            refuse(
                "breg.migration.identifier",
                format!("{pointer}/id"),
                "the step identifier is not valid".to_owned(),
                identifier_rule,
            );
        } else if !ids.insert(step.id()) {
            refuse(
                "breg.migration.identifier",
                format!("{pointer}/id"),
                "an earlier step or assertion already has this identifier".to_owned(),
                "Give every step and assertion its own identifier.",
            );
        }
        if let (Some(base), Some(sql_path)) = (base, step.sql_path()) {
            if sql_path != format!("{base}/steps/{}.sql", step.id()).as_str() {
                refuse(
                    "breg.migration.artifact-path",
                    format!("{pointer}/sqlPath"),
                    "a step's SQL is the file steps/<step id>.sql beside the descriptor, named \
                     from the project root"
                        .to_owned(),
                    "Set `sqlPath` to modules/<module>/migrations/<id>/steps/<step id>.sql.",
                );
            }
        }
        if step.objects().is_empty() {
            refuse(
                "breg.migration.objects",
                format!("{pointer}/objects"),
                "a step names at least one object it changes".to_owned(),
                "List the tables, fields, constraints, and indexes the step changes.",
            );
        } else if !strictly_sorted(step.objects().iter()) {
            refuse(
                "breg.migration.objects",
                format!("{pointer}/objects"),
                "`objects` must be sorted and name each object once".to_owned(),
                "Sort the objects and remove repeats.",
            );
        }
        match step {
            ReviewedMigrationStepDescriptor::TransactionalSql {
                affected_rows: Some(bounds),
                ..
            } => {
                if bounds.min > bounds.max {
                    refuse(
                        "breg.migration.affected-rows",
                        format!("{pointer}/affectedRows"),
                        "the minimum is larger than the maximum".to_owned(),
                        "Set a minimum no larger than the maximum.",
                    );
                }
                if bounds.max > MAX_TOTAL_ROWS {
                    refuse(
                        "breg.migration.affected-rows",
                        format!("{pointer}/affectedRows/maximum"),
                        format!("a step changes at most {MAX_TOTAL_ROWS} rows"),
                        "Set a maximum within the bound, or split the step.",
                    );
                }
            }
            ReviewedMigrationStepDescriptor::ChunkedBackfill {
                entity_id,
                chunk_size,
                max_total_rows,
                lock_timeout_ms,
                statement_timeout_ms,
                ..
            }
            | ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
                entity_id,
                chunk_size,
                max_total_rows,
                lock_timeout_ms,
                statement_timeout_ms,
                ..
            } => {
                if !valid_id(entity_id) {
                    refuse(
                        "breg.migration.backfill",
                        format!("{pointer}/entity"),
                        "the entity identifier is not valid".to_owned(),
                        identifier_rule,
                    );
                }
                if *chunk_size == 0 || *chunk_size > MAX_CHUNK_SIZE {
                    refuse(
                        "breg.migration.backfill",
                        format!("{pointer}/chunkSize"),
                        format!("a chunk holds from 1 to {MAX_CHUNK_SIZE} rows"),
                        "Set a chunk size within the bound.",
                    );
                }
                if *max_total_rows == 0 || *max_total_rows > MAX_TOTAL_ROWS {
                    refuse(
                        "breg.migration.backfill",
                        format!("{pointer}/maximumTotalRows"),
                        format!("a backfill changes from 1 to {MAX_TOTAL_ROWS} rows"),
                        "Set a maximum within the bound, or split the backfill.",
                    );
                }
                if !valid_timeout(*lock_timeout_ms, descriptor.lock_timeout_ms) {
                    refuse(
                        "breg.migration.timeout",
                        format!("{pointer}/lockTimeoutMilliseconds"),
                        "a step's lock timeout is from 1 millisecond to the descriptor's own"
                            .to_owned(),
                        "Set a lock timeout no longer than the descriptor's.",
                    );
                }
                if !valid_timeout(*statement_timeout_ms, descriptor.statement_timeout_ms) {
                    refuse(
                        "breg.migration.timeout",
                        format!("{pointer}/statementTimeoutMilliseconds"),
                        "a step's statement timeout is from 1 millisecond to the descriptor's own"
                            .to_owned(),
                        "Set a statement timeout no longer than the descriptor's.",
                    );
                }
                if matches!(
                    step,
                    ReviewedMigrationStepDescriptor::ChunkedBackfill {
                        exact_affected_rows: false,
                        ..
                    }
                ) {
                    refuse(
                        "breg.migration.backfill",
                        format!("{pointer}/exactAffectedRows"),
                        "a chunked backfill counts the rows it changes exactly".to_owned(),
                        "Set `exactAffectedRows` to true.",
                    );
                }
            }
            ReviewedMigrationStepDescriptor::TransactionalSql {
                affected_rows: None,
                ..
            } => {}
        }
    }
    for (member, assertions) in [
        ("preAssertions", &descriptor.pre_assertions),
        ("postAssertions", &descriptor.post_assertions),
    ] {
        for (index, assertion) in assertions.iter().enumerate() {
            let pointer = format!("/{member}/{index}");
            if !valid_id(&assertion.id) {
                refuse(
                    "breg.migration.identifier",
                    format!("{pointer}/id"),
                    "the assertion identifier is not valid".to_owned(),
                    identifier_rule,
                );
            } else if !ids.insert(&assertion.id) {
                refuse(
                    "breg.migration.identifier",
                    format!("{pointer}/id"),
                    "an earlier step or assertion already has this identifier".to_owned(),
                    "Give every step and assertion its own identifier.",
                );
            }
            if let Some(base) = base {
                if assertion.sql_path != format!("{base}/assertions/{}.sql", assertion.id) {
                    refuse(
                        "breg.migration.artifact-path",
                        format!("{pointer}/sqlPath"),
                        "an assertion's SQL is the file assertions/<assertion id>.sql beside the \
                         descriptor, named from the project root"
                            .to_owned(),
                        "Set `sqlPath` to \
                         modules/<module>/migrations/<id>/assertions/<assertion id>.sql.",
                    );
                }
            }
        }
    }
    problems
}

#[cfg(feature = "tooling")]
fn validate_step_sql(
    step: &ReviewedMigrationStepDescriptor,
    sql: &str,
    descriptor: &ReviewedMigrationDescriptor,
    bindings: &ReviewedPlanBindings<'_>,
    declared_tables: &BTreeSet<&str>,
) -> Result<(), ReviewedMigrationError> {
    if let ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { .. } = step {
        return validate_field_encryption_backfill_step(step, descriptor, bindings);
    }
    let parsed = parse_one(sql)?;
    validate_ast_objects(&parsed, declared_tables, false)?;
    let root = root_node(&parsed)?;
    let parsed_objects = match step {
        ReviewedMigrationStepDescriptor::TransactionalSql { affected_rows, .. } => {
            let (dml, objects) = match root {
                PgNode::UpdateStmt(update) => {
                    validate_update_relation(update, declared_tables)?;
                    (true, update_objects(update, bindings)?)
                }
                PgNode::AlterTableStmt(alter) => {
                    validate_alter_table(alter, declared_tables)?;
                    (false, alter_table_objects(alter, bindings)?)
                }
                PgNode::IndexStmt(index) => {
                    if index.concurrent {
                        return Err(ReviewedMigrationError::Sql);
                    }
                    validate_range_var(
                        index.relation.as_ref().ok_or(ReviewedMigrationError::Sql)?,
                        declared_tables,
                    )?;
                    (false, index_objects(index, bindings)?)
                }
                PgNode::DropStmt(drop) => {
                    validate_drop_table(drop, declared_tables)?;
                    (false, drop_table_objects(drop, bindings)?)
                }
                _ => return Err(ReviewedMigrationError::Sql),
            };
            if dml != affected_rows.is_some() {
                return Err(ReviewedMigrationError::Sql);
            }
            objects
        }
        ReviewedMigrationStepDescriptor::ChunkedBackfill { entity_id, .. } => {
            if descriptor.change_class != CompiledRegistryChangeClass::DataBackfillRequired {
                return Err(ReviewedMigrationError::Descriptor);
            }
            let entity = bindings
                .candidate_entities
                .get(entity_id)
                .or_else(|| bindings.prior_entities.get(entity_id))
                .ok_or(ReviewedMigrationError::Descriptor)?;
            if !descriptor
                .covers
                .iter()
                .any(|cover| cover.target.entity_id.as_deref() == Some(entity_id))
            {
                return Err(ReviewedMigrationError::Coverage);
            }
            let PgNode::UpdateStmt(update) = root else {
                return Err(ReviewedMigrationError::Sql);
            };
            validate_chunked_update(update, &entity.physical_table, declared_tables, &parsed)?;
            update_objects(update, bindings)?
        }
        ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { .. } => {
            unreachable!("the engine-executed backfill is handled before SQL parsing")
        }
    };
    if parsed_objects != step.objects() {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

/// The engine-executed backfill is declared, not authored: its objects must
/// name the envelope column of a covered field the candidate compiles as
/// encrypted, plus that field's blind-index sibling under the implicit
/// `#lookup` member, and its cursor protocol must be the record-id keyset the
/// engine walks.
#[cfg(feature = "tooling")]
fn validate_field_encryption_backfill_step(
    step: &ReviewedMigrationStepDescriptor,
    descriptor: &ReviewedMigrationDescriptor,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<(), ReviewedMigrationError> {
    let ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
        entity_id,
        objects,
        cursor,
        ..
    } = step
    else {
        return Err(ReviewedMigrationError::Descriptor);
    };
    if descriptor.change_class != CompiledRegistryChangeClass::DataBackfillRequired {
        return Err(ReviewedMigrationError::Descriptor);
    }
    if !descriptor.covers.iter().any(|cover| {
        cover.code == CompiledRegistryChangeCode::FieldEncryptionChanged
            && cover.target.entity_id.as_deref() == Some(entity_id.as_str())
    }) {
        return Err(ReviewedMigrationError::Coverage);
    }
    let entity = bindings
        .candidate_entities
        .get(entity_id)
        .ok_or(ReviewedMigrationError::Descriptor)?;
    if *cursor != ChunkCursorProtocol::RecordIdUuidArray {
        return Err(ReviewedMigrationError::Descriptor);
    }
    for object in objects {
        let Some(member_id) = object.member_id.as_deref() else {
            return Err(ReviewedMigrationError::Descriptor);
        };
        let field_id = member_id.strip_suffix("#lookup").unwrap_or(member_id);
        let field = entity
            .fields
            .get(field_id)
            .ok_or(ReviewedMigrationError::Descriptor)?;
        let encryption = field
            .encryption
            .as_ref()
            .ok_or(ReviewedMigrationError::Descriptor)?;
        if member_id.ends_with("#lookup") {
            let blind = encryption
                .blind_index
                .as_ref()
                .ok_or(ReviewedMigrationError::Descriptor)?;
            if object.physical_name != blind.physical_name {
                return Err(ReviewedMigrationError::Descriptor);
            }
        } else if object.physical_name != field.physical_name {
            return Err(ReviewedMigrationError::Descriptor);
        }
    }
    Ok(())
}

/// Whether this descriptor covers turning field encryption on: the change
/// code the compiler emits for a flip, or the engine-executed backfill step
/// that seals it.
#[cfg(feature = "tooling")]
fn descriptor_covers_field_encryption_flip(descriptor: &ReviewedMigrationDescriptor) -> bool {
    descriptor
        .covers
        .iter()
        .any(|cover| cover.code == CompiledRegistryChangeCode::FieldEncryptionChanged)
        || descriptor.steps.iter().any(|step| {
            matches!(
                step,
                ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { .. }
            )
        })
}

#[cfg(feature = "tooling")]
fn validate_assertions(
    descriptors: &[ReviewedMigrationAssertionDescriptor],
    files: &BTreeMap<String, Vec<u8>>,
    declared_tables: &BTreeSet<&str>,
    referenced_paths: &mut BTreeSet<String>,
) -> Result<Vec<ValidatedReviewedMigrationAssertion>, ReviewedMigrationError> {
    let mut result = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        referenced_paths.insert(descriptor.sql_path.clone());
        let sql = read_sql(files, &descriptor.sql_path)?;
        let parsed = parse_one(sql)?;
        validate_ast_objects(&parsed, declared_tables, true)?;
        let PgNode::SelectStmt(select) = root_node(&parsed)? else {
            return Err(ReviewedMigrationError::Sql);
        };
        if select.into_clause.is_some()
            || select.with_clause.is_some()
            || !select.locking_clause.is_empty()
            || SetOperation::try_from(select.op).ok() != Some(SetOperation::SetopNone)
            || select.target_list.len() != 1
        {
            return Err(ReviewedMigrationError::Sql);
        }
        let value = select
            .target_list
            .first()
            .and_then(|node| node.node.as_ref())
            .and_then(|node| match node {
                PgNode::ResTarget(target) => target.val.as_deref(),
                _ => None,
            })
            .and_then(|node| node.node.as_ref())
            .ok_or(ReviewedMigrationError::Sql)?;
        if !boolean_result_expression(value)? {
            return Err(ReviewedMigrationError::Sql);
        }
        result.push(ValidatedReviewedMigrationAssertion {
            descriptor: descriptor.clone(),
            sql: sql.to_owned(),
            sha256: digest(sql.as_bytes()),
        });
    }
    Ok(result)
}

#[cfg(feature = "tooling")]
struct ReceiptValidationContext<'a> {
    plan_digest: &'a str,
    steps: &'a [ValidatedReviewedMigrationStep],
    pre_assertions: &'a [ValidatedReviewedMigrationAssertion],
    post_assertions: &'a [ValidatedReviewedMigrationAssertion],
    descriptor: &'a ReviewedMigrationDescriptor,
    bindings: &'a ReviewedPlanBindings<'a>,
    base: &'a str,
    files: &'a BTreeMap<String, Vec<u8>>,
    referenced_paths: &'a mut BTreeSet<String>,
}

#[cfg(feature = "tooling")]
fn validate_receipt(
    receipt: &MigrationRehearsalReceipt,
    context: ReceiptValidationContext<'_>,
) -> Result<(), ReviewedMigrationError> {
    let ReceiptValidationContext {
        plan_digest,
        steps,
        pre_assertions,
        post_assertions,
        descriptor,
        bindings,
        base,
        files,
        referenced_paths,
    } = context;
    // The engine-executed backfill carries no SQL artifact, so the receipt
    // binds no digest for it: its canonical-JSON checksum is pinned through
    // the plan digest over the whole descriptor, and row assertions carry its
    // rehearsal row count.
    let expected_sql = steps
        .iter()
        .filter(|step| step.descriptor.sql_path().is_some())
        .map(|step| ArtifactDigestBinding {
            path: step.descriptor.sql_path().unwrap_or_default().to_owned(),
            sha256: step.sha256.clone(),
        })
        .collect::<Vec<_>>();
    let expected_assertions = pre_assertions
        .iter()
        .chain(post_assertions)
        .map(|assertion| ArtifactDigestBinding {
            path: assertion.descriptor.sql_path.clone(),
            sha256: assertion.sha256.clone(),
        })
        .collect::<Vec<_>>();
    let metadata_only = steps.is_empty() && covers_are_metadata_only(&descriptor.covers);
    if receipt.prior_package_digest != bindings.prior_package_digest
        || receipt.prior_schema_fingerprint != bindings.prior_schema_fingerprint
        || receipt.final_schema_fingerprint != bindings.final_schema_fingerprint
        || receipt.plan_sha256 != plan_digest
        || receipt.sql_sha256 != expected_sql
        || receipt.assertion_sha256 != expected_assertions
        || !(15..=18).contains(&receipt.postgres_major)
        || (receipt.fixture_inventory.is_empty() && !metadata_only)
        || !strictly_sorted(
            receipt
                .fixture_inventory
                .iter()
                .map(|fixture| fixture.id.as_str()),
        )
    {
        return Err(ReviewedMigrationError::Evidence);
    }
    for fixture in &receipt.fixture_inventory {
        if !valid_id(&fixture.id)
            || fixture.path != format!("{base}/fixtures/{}.jsonl", fixture.id)
            || !valid_digest(&fixture.sha256)
            || !referenced_paths.insert(fixture.path.clone())
        {
            return Err(ReviewedMigrationError::Evidence);
        }
        let bytes = files
            .get(&fixture.path)
            .ok_or(ReviewedMigrationError::Evidence)?;
        if bytes.is_empty()
            || bytes.len() > MAX_FIXTURE_BYTES
            || !bytes.ends_with(b"\n")
            || digest(bytes) != fixture.sha256
            || validate_fixture_jsonl(bytes)? != fixture.row_count
        {
            return Err(ReviewedMigrationError::Evidence);
        }
    }
    let expected_row_steps = steps
        .iter()
        .filter_map(|step| match &step.descriptor {
            ReviewedMigrationStepDescriptor::TransactionalSql {
                id,
                affected_rows: Some(bounds),
                ..
            } => Some((id.as_str(), bounds.min, bounds.max)),
            ReviewedMigrationStepDescriptor::ChunkedBackfill {
                id, max_total_rows, ..
            }
            | ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
                id, max_total_rows, ..
            } => Some((id.as_str(), 0, *max_total_rows)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if receipt.row_assertions.len() != expected_row_steps.len() {
        return Err(ReviewedMigrationError::Evidence);
    }
    for (assertion, (step_id, min, max)) in receipt.row_assertions.iter().zip(expected_row_steps) {
        if assertion.step_id != step_id
            || assertion.affected_rows < min
            || assertion.affected_rows > max
        {
            return Err(ReviewedMigrationError::Evidence);
        }
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_fixture_jsonl(bytes: &[u8]) -> Result<u64, ReviewedMigrationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ReviewedMigrationError::Evidence)?;
    let mut count = 0_u64;
    for line in text.split_terminator('\n') {
        if line.is_empty() || line.ends_with('\r') {
            return Err(ReviewedMigrationError::Evidence);
        }
        let value =
            parse_json_strict(line.as_bytes()).map_err(|_| ReviewedMigrationError::Evidence)?;
        let canonical = canonicalize_json(&value).map_err(|_| ReviewedMigrationError::Evidence)?;
        if canonical != line.as_bytes() {
            return Err(ReviewedMigrationError::Evidence);
        }
        count = count
            .checked_add(1)
            .ok_or(ReviewedMigrationError::Evidence)?;
    }
    Ok(count)
}

#[cfg(feature = "tooling")]
fn parse_one(sql: &str) -> Result<pg_query::ParseResult, ReviewedMigrationError> {
    if sql.is_empty() || sql.len() > MAX_SQL_BYTES || sql.as_bytes().contains(&0) {
        return Err(ReviewedMigrationError::Sql);
    }
    let parsed = pg_query::parse(sql).map_err(|_| ReviewedMigrationError::Sql)?;
    if parsed.protobuf.stmts.len() != 1 || !parsed.warnings.is_empty() {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(parsed)
}

#[cfg(feature = "tooling")]
fn root_node(parsed: &pg_query::ParseResult) -> Result<&PgNode, ReviewedMigrationError> {
    parsed
        .protobuf
        .stmts
        .first()
        .and_then(|statement| statement.stmt.as_deref())
        .and_then(|statement| statement.node.as_ref())
        .ok_or(ReviewedMigrationError::Sql)
}

#[cfg(feature = "tooling")]
fn validate_ast_objects(
    parsed: &pg_query::ParseResult,
    declared_tables: &BTreeSet<&str>,
    assertion: bool,
) -> Result<(), ReviewedMigrationError> {
    let mut statement_nodes = 0;
    for (node, _, _, _) in parsed.protobuf.nodes() {
        match node {
            NodeRef::RangeVar(range) => validate_range_var(range, declared_tables)?,
            NodeRef::FuncCall(function) => validate_function(function)?,
            NodeRef::AExpr(expression) => validate_operator(expression)?,
            NodeRef::TypeName(type_name) => validate_type_name(type_name)?,
            NodeRef::ParamRef(_) if assertion => return Err(ReviewedMigrationError::Sql),
            NodeRef::SqlvalueFunction(_)
            | NodeRef::RangeFunction(_)
            | NodeRef::TableFunc(_)
            | NodeRef::IntoClause(_) => return Err(ReviewedMigrationError::Sql),
            NodeRef::SelectStmt(_) if assertion => statement_nodes += 1,
            NodeRef::UpdateStmt(_)
            | NodeRef::AlterTableStmt(_)
            | NodeRef::IndexStmt(_)
            | NodeRef::DropStmt(_)
            | NodeRef::SelectStmt(_) => statement_nodes += 1,
            node if is_forbidden_statement_node(node) => return Err(ReviewedMigrationError::Sql),
            _ => {}
        }
    }
    if (!assertion && statement_nodes != 1) || (assertion && statement_nodes == 0) {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[allow(clippy::match_same_arms)]
#[cfg(feature = "tooling")]
fn is_forbidden_statement_node(node: NodeRef<'_>) -> bool {
    matches!(
        node,
        NodeRef::InsertStmt(_)
            | NodeRef::DeleteStmt(_)
            | NodeRef::MergeStmt(_)
            | NodeRef::TransactionStmt(_)
            | NodeRef::VariableSetStmt(_)
            | NodeRef::VariableShowStmt(_)
            | NodeRef::CreateStmt(_)
            | NodeRef::CreateTableAsStmt(_)
            | NodeRef::CopyStmt(_)
            | NodeRef::CreateFunctionStmt(_)
            | NodeRef::AlterFunctionStmt(_)
            | NodeRef::DoStmt(_)
            | NodeRef::CreateTrigStmt(_)
            | NodeRef::CreateEventTrigStmt(_)
            | NodeRef::AlterEventTrigStmt(_)
            | NodeRef::CreateSchemaStmt(_)
            | NodeRef::AlterObjectSchemaStmt(_)
            | NodeRef::CreateExtensionStmt(_)
            | NodeRef::AlterExtensionStmt(_)
            | NodeRef::AlterExtensionContentsStmt(_)
            | NodeRef::CreatedbStmt(_)
            | NodeRef::DropdbStmt(_)
            | NodeRef::CreateRoleStmt(_)
            | NodeRef::AlterRoleStmt(_)
            | NodeRef::DropRoleStmt(_)
            | NodeRef::AlterRoleSetStmt(_)
            | NodeRef::AlterDatabaseStmt(_)
            | NodeRef::AlterDatabaseSetStmt(_)
            | NodeRef::GrantStmt(_)
            | NodeRef::GrantRoleStmt(_)
            | NodeRef::AlterDefaultPrivilegesStmt(_)
            | NodeRef::TruncateStmt(_)
            | NodeRef::VacuumStmt(_)
            | NodeRef::CallStmt(_)
            | NodeRef::LockStmt(_)
            | NodeRef::PrepareStmt(_)
            | NodeRef::ExecuteStmt(_)
            | NodeRef::DeallocateStmt(_)
            | NodeRef::DeclareCursorStmt(_)
            | NodeRef::CreateSeqStmt(_)
            | NodeRef::AlterSeqStmt(_)
            | NodeRef::CreatePolicyStmt(_)
            | NodeRef::AlterPolicyStmt(_)
            | NodeRef::ViewStmt(_)
            | NodeRef::RuleStmt(_)
            | NodeRef::RefreshMatViewStmt(_)
            | NodeRef::ReindexStmt(_)
            | NodeRef::ClusterStmt(_)
            | NodeRef::LoadStmt(_)
    )
}

#[cfg(feature = "tooling")]
fn validate_range_var(
    range: &pg_query::protobuf::RangeVar,
    declared_tables: &BTreeSet<&str>,
) -> Result<(), ReviewedMigrationError> {
    if !range.catalogname.is_empty()
        || range.schemaname != "registry_data"
        || !declared_tables.contains(range.relname.as_str())
        || (!range.relpersistence.is_empty() && range.relpersistence != "p")
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_function(
    function: &pg_query::protobuf::FuncCall,
) -> Result<(), ReviewedMigrationError> {
    let name = node_strings(&function.funcname)?;
    if !matches!(
        name.as_slice(),
        [schema, function]
            if schema == "pg_catalog"
                && matches!(function.as_str(), "count" | "bool_and" | "every")
    ) || function.over.is_some()
        || function.agg_within_group
        || function.func_variadic
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_operator(expression: &pg_query::protobuf::AExpr) -> Result<(), ReviewedMigrationError> {
    let names = node_strings(&expression.name)?;
    if names.len() != 1
        || !matches!(
            names[0].as_str(),
            "=" | "<>" | "<" | ">" | "<=" | ">=" | "+" | "-" | "*" | "/" | "~"
        )
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn boolean_result_expression(node: &PgNode) -> Result<bool, ReviewedMigrationError> {
    Ok(match node {
        PgNode::AExpr(expression) => {
            let names = node_strings(&expression.name)?;
            names.len() == 1
                && matches!(
                    names[0].as_str(),
                    "=" | "<>" | "<" | ">" | "<=" | ">=" | "~"
                )
        }
        PgNode::BoolExpr(_) | PgNode::BooleanTest(_) | PgNode::NullTest(_) => true,
        PgNode::SubLink(link) => {
            SubLinkType::try_from(link.sub_link_type).ok() == Some(SubLinkType::ExistsSublink)
        }
        PgNode::AConst(constant) => matches!(constant.val, Some(a_const::Val::Boolval(_))),
        _ => false,
    })
}

#[cfg(feature = "tooling")]
fn validate_type_name(
    type_name: &pg_query::protobuf::TypeName,
) -> Result<(), ReviewedMigrationError> {
    let names = node_strings(&type_name.names)?;
    if type_name.setof
        || type_name.pct_type
        || !matches!(
            names.as_slice(),
            [schema, name]
                if schema == "pg_catalog"
                    && matches!(
                        name.as_str(),
                        "bool"
                            | "date"
                            | "float8"
                            | "int2"
                            | "int4"
                            | "int8"
                            | "jsonb"
                            | "numeric"
                            | "text"
                            | "timestamp"
                            | "timestamptz"
                            | "uuid"
                            | "varchar"
                    )
        )
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_update_relation(
    update: &pg_query::protobuf::UpdateStmt,
    declared_tables: &BTreeSet<&str>,
) -> Result<(), ReviewedMigrationError> {
    validate_range_var(
        update
            .relation
            .as_ref()
            .ok_or(ReviewedMigrationError::Sql)?,
        declared_tables,
    )?;
    if update.target_list.is_empty()
        || update.where_clause.is_none()
        || update.with_clause.is_some()
        || !update.from_clause.is_empty()
        || !update.returning_list.is_empty()
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_chunked_update(
    update: &pg_query::protobuf::UpdateStmt,
    physical_table: &str,
    declared_tables: &BTreeSet<&str>,
    parsed: &pg_query::ParseResult,
) -> Result<(), ReviewedMigrationError> {
    validate_update_relation(update, declared_tables)?;
    let relation = update
        .relation
        .as_ref()
        .ok_or(ReviewedMigrationError::Sql)?;
    if relation.relname != physical_table {
        return Err(ReviewedMigrationError::Sql);
    }
    for target in &update.target_list {
        let Some(PgNode::ResTarget(target)) = target.node.as_ref() else {
            return Err(ReviewedMigrationError::Sql);
        };
        if target.name.is_empty() || target.name == "record_id" || !target.indirection.is_empty() {
            return Err(ReviewedMigrationError::Sql);
        }
    }
    let where_node = update
        .where_clause
        .as_deref()
        .and_then(|node| node.node.as_ref())
        .ok_or(ReviewedMigrationError::Sql)?;
    let PgNode::AExpr(expression) = where_node else {
        return Err(ReviewedMigrationError::Sql);
    };
    if AExprKind::try_from(expression.kind).ok() != Some(AExprKind::AexprOpAny)
        || node_strings(&expression.name)?.as_slice() != ["="]
        || !is_column_ref(expression.lexpr.as_deref(), "record_id")
        || !is_uuid_array_parameter(expression.rexpr.as_deref())
    {
        return Err(ReviewedMigrationError::Sql);
    }
    let parameters = parsed
        .protobuf
        .nodes()
        .into_iter()
        .filter_map(|(node, _, _, _)| match node {
            NodeRef::ParamRef(parameter) => Some(parameter.number),
            _ => None,
        })
        .collect::<Vec<_>>();
    if parameters != [1] {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_alter_table(
    alter: &pg_query::protobuf::AlterTableStmt,
    declared_tables: &BTreeSet<&str>,
) -> Result<(), ReviewedMigrationError> {
    validate_range_var(
        alter.relation.as_ref().ok_or(ReviewedMigrationError::Sql)?,
        declared_tables,
    )?;
    if alter.cmds.is_empty() {
        return Err(ReviewedMigrationError::Sql);
    }
    for command in &alter.cmds {
        let Some(PgNode::AlterTableCmd(command)) = command.node.as_ref() else {
            return Err(ReviewedMigrationError::Sql);
        };
        let subtype =
            AlterTableType::try_from(command.subtype).map_err(|_| ReviewedMigrationError::Sql)?;
        if !matches!(
            subtype,
            AlterTableType::AtColumnDefault
                | AlterTableType::AtDropNotNull
                | AlterTableType::AtSetNotNull
                | AlterTableType::AtDropColumn
                | AlterTableType::AtAddConstraint
                | AlterTableType::AtAlterConstraint
                | AlterTableType::AtValidateConstraint
                | AlterTableType::AtDropConstraint
                | AlterTableType::AtAlterColumnType
        ) {
            return Err(ReviewedMigrationError::Sql);
        }
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_drop_table(
    drop: &pg_query::protobuf::DropStmt,
    declared_tables: &BTreeSet<&str>,
) -> Result<(), ReviewedMigrationError> {
    if ObjectType::try_from(drop.remove_type).ok() != Some(ObjectType::ObjectTable)
        || drop.concurrent
        || drop.objects.len() != 1
    {
        return Err(ReviewedMigrationError::Sql);
    }
    let Some(PgNode::List(object)) = drop.objects[0].node.as_ref() else {
        return Err(ReviewedMigrationError::Sql);
    };
    let names = node_strings(&object.items)?;
    if names.len() != 2
        || names[0] != "registry_data"
        || !declared_tables.contains(names[1].as_str())
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn update_objects(
    update: &pg_query::protobuf::UpdateStmt,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<Vec<ReviewedMigrationObject>, ReviewedMigrationError> {
    let relation = update
        .relation
        .as_ref()
        .ok_or(ReviewedMigrationError::Sql)?;
    let entity_id = entity_for_table(&relation.relname, bindings)?;
    let mut objects = Vec::with_capacity(update.target_list.len());
    for target in &update.target_list {
        let Some(PgNode::ResTarget(target)) = target.node.as_ref() else {
            return Err(ReviewedMigrationError::Sql);
        };
        let member_id = member_for_physical(
            &entity_id,
            &target.name,
            ReviewedMigrationObjectKind::Field,
            bindings,
        )?;
        objects.push(reviewed_object(
            &relation.relname,
            &entity_id,
            ReviewedMigrationObjectKind::Field,
            Some(member_id),
            &target.name,
        ));
    }
    finish_objects(objects)
}

#[cfg(feature = "tooling")]
fn alter_table_objects(
    alter: &pg_query::protobuf::AlterTableStmt,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<Vec<ReviewedMigrationObject>, ReviewedMigrationError> {
    let relation = alter.relation.as_ref().ok_or(ReviewedMigrationError::Sql)?;
    let entity_id = entity_for_table(&relation.relname, bindings)?;
    let mut objects = Vec::with_capacity(alter.cmds.len());
    for command in &alter.cmds {
        let Some(PgNode::AlterTableCmd(command)) = command.node.as_ref() else {
            return Err(ReviewedMigrationError::Sql);
        };
        let subtype =
            AlterTableType::try_from(command.subtype).map_err(|_| ReviewedMigrationError::Sql)?;
        let kind = match subtype {
            AlterTableType::AtAddConstraint
            | AlterTableType::AtAlterConstraint
            | AlterTableType::AtValidateConstraint
            | AlterTableType::AtDropConstraint => ReviewedMigrationObjectKind::Constraint,
            AlterTableType::AtColumnDefault
            | AlterTableType::AtDropNotNull
            | AlterTableType::AtSetNotNull
            | AlterTableType::AtDropColumn
            | AlterTableType::AtAlterColumnType => ReviewedMigrationObjectKind::Field,
            _ => return Err(ReviewedMigrationError::Sql),
        };
        let member_name = alter_table_command_member_name(command, subtype)?;
        let member_id = member_for_physical(&entity_id, member_name, kind, bindings)?;
        objects.push(reviewed_object(
            &relation.relname,
            &entity_id,
            kind,
            Some(member_id),
            member_name,
        ));
    }
    // One ALTER may atomically drop and replace the same managed constraint.
    // Coverage describes its unique object footprint, not the number of clauses.
    objects.sort();
    objects.dedup();
    finish_objects(objects)
}

#[cfg(feature = "tooling")]
fn alter_table_command_member_name(
    command: &pg_query::protobuf::AlterTableCmd,
    subtype: AlterTableType,
) -> Result<&str, ReviewedMigrationError> {
    if !command.name.is_empty() {
        return Ok(&command.name);
    }
    if subtype == AlterTableType::AtAddConstraint {
        let Some(PgNode::Constraint(constraint)) =
            command.def.as_deref().and_then(|node| node.node.as_ref())
        else {
            return Err(ReviewedMigrationError::Sql);
        };
        if ConstrType::try_from(constraint.contype).is_err() || constraint.conname.is_empty() {
            return Err(ReviewedMigrationError::Sql);
        }
        return Ok(&constraint.conname);
    }
    Err(ReviewedMigrationError::Sql)
}

#[cfg(feature = "tooling")]
fn index_objects(
    index: &pg_query::protobuf::IndexStmt,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<Vec<ReviewedMigrationObject>, ReviewedMigrationError> {
    let relation = index.relation.as_ref().ok_or(ReviewedMigrationError::Sql)?;
    if index.idxname.is_empty()
        || !index.table_space.is_empty()
        || (!index.access_method.is_empty() && index.access_method != "btree")
    {
        return Err(ReviewedMigrationError::Sql);
    }
    let entity_id = entity_for_table(&relation.relname, bindings)?;
    let member_id = member_for_physical(
        &entity_id,
        &index.idxname,
        ReviewedMigrationObjectKind::Index,
        bindings,
    )?;
    Ok(vec![reviewed_object(
        &relation.relname,
        &entity_id,
        ReviewedMigrationObjectKind::Index,
        Some(member_id),
        &index.idxname,
    )])
}

#[cfg(feature = "tooling")]
fn drop_table_objects(
    drop: &pg_query::protobuf::DropStmt,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<Vec<ReviewedMigrationObject>, ReviewedMigrationError> {
    let Some(PgNode::List(object)) = drop.objects[0].node.as_ref() else {
        return Err(ReviewedMigrationError::Sql);
    };
    let names = node_strings(&object.items)?;
    let table = names.get(1).ok_or(ReviewedMigrationError::Sql)?;
    let entity_id = entity_for_table(table, bindings)?;
    Ok(vec![reviewed_object(
        table,
        &entity_id,
        ReviewedMigrationObjectKind::Entity,
        None,
        table,
    )])
}

#[cfg(feature = "tooling")]
fn entity_for_table(
    table: &str,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<String, ReviewedMigrationError> {
    let ids = bindings
        .prior_entities
        .values()
        .chain(bindings.candidate_entities.values())
        .filter(|entity| entity.physical_table == table)
        .map(|entity| entity.id.as_str())
        .collect::<BTreeSet<_>>();
    if ids.len() != 1 {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(ids.into_iter().next().expect("one id exists").to_owned())
}

#[cfg(feature = "tooling")]
fn member_for_physical(
    entity_id: &str,
    physical_name: &str,
    kind: ReviewedMigrationObjectKind,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<String, ReviewedMigrationError> {
    let inventories = [
        bindings.prior_physical_names,
        bindings.candidate_physical_names,
    ];
    let mut ids = BTreeSet::new();
    for inventory in inventories {
        let Some(entity) = inventory.entities.get(entity_id) else {
            continue;
        };
        let members = match kind {
            ReviewedMigrationObjectKind::Field => &entity.fields,
            ReviewedMigrationObjectKind::Constraint => &entity.constraints,
            ReviewedMigrationObjectKind::Index => &entity.indexes,
            ReviewedMigrationObjectKind::Entity => return Err(ReviewedMigrationError::Sql),
        };
        ids.extend(
            members
                .iter()
                .filter(|(_, physical)| physical.as_str() == physical_name)
                .map(|(id, _)| id.as_str()),
        );
    }
    if ids.len() != 1 {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(ids.into_iter().next().expect("one id exists").to_owned())
}

#[cfg(feature = "tooling")]
fn reviewed_object(
    table: &str,
    entity_id: &str,
    kind: ReviewedMigrationObjectKind,
    member_id: Option<String>,
    physical_name: &str,
) -> ReviewedMigrationObject {
    ReviewedMigrationObject {
        schema: "registry_data".to_owned(),
        table: table.to_owned(),
        entity_id: entity_id.to_owned(),
        kind,
        member_id,
        physical_name: physical_name.to_owned(),
    }
}

#[cfg(feature = "tooling")]
fn finish_objects(
    mut objects: Vec<ReviewedMigrationObject>,
) -> Result<Vec<ReviewedMigrationObject>, ReviewedMigrationError> {
    objects.sort();
    if objects.is_empty() || objects.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(objects)
}

#[cfg(feature = "tooling")]
fn object_cover(
    object: &ReviewedMigrationObject,
    covers: &[ReviewedChangeCover],
) -> Result<ReviewedChangeCover, ReviewedMigrationError> {
    let kind = match object.kind {
        ReviewedMigrationObjectKind::Entity => CompiledRegistryChangeTargetKind::Entity,
        ReviewedMigrationObjectKind::Field => CompiledRegistryChangeTargetKind::Field,
        ReviewedMigrationObjectKind::Constraint => CompiledRegistryChangeTargetKind::Constraint,
        ReviewedMigrationObjectKind::Index => CompiledRegistryChangeTargetKind::Index,
    };
    let target = CompiledRegistryChangeTarget {
        kind,
        entity_id: Some(object.entity_id.clone()),
        member_id: object.member_id.clone(),
    };
    let matches = covers
        .iter()
        .filter(|cover| {
            cover.target == target
                || reference_target_cover_matches_implicit_constraint(cover, object)
                || pattern_cover_matches_implicit_constraint(cover, object)
                || encryption_cover_matches_implicit_lookup_column(cover, object)
                || encryption_cover_matches_implicit_lookup_index(cover, object)
        })
        .cloned()
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(ReviewedMigrationError::Coverage);
    }
    Ok(matches.into_iter().next().expect("one cover exists"))
}

#[cfg(feature = "tooling")]
fn reference_target_cover_matches_implicit_constraint(
    cover: &ReviewedChangeCover,
    object: &ReviewedMigrationObject,
) -> bool {
    cover.code == CompiledRegistryChangeCode::ReferenceTargetChanged
        && object.kind == ReviewedMigrationObjectKind::Constraint
        && cover.target.kind == CompiledRegistryChangeTargetKind::Field
        && cover.target.entity_id.as_deref() == Some(object.entity_id.as_str())
        && object
            .member_id
            .as_deref()
            .and_then(|member| member.strip_prefix("reference:"))
            == cover.target.member_id.as_deref()
}

#[cfg(feature = "tooling")]
fn pattern_cover_matches_implicit_constraint(
    cover: &ReviewedChangeCover,
    object: &ReviewedMigrationObject,
) -> bool {
    matches!(
        cover.code,
        CompiledRegistryChangeCode::FieldPatternChanged
            | CompiledRegistryChangeCode::FieldPatternRemoved
    ) && object.kind == ReviewedMigrationObjectKind::Constraint
        && cover.target.kind == CompiledRegistryChangeTargetKind::Field
        && cover.target.entity_id.as_deref() == Some(object.entity_id.as_str())
        && object
            .member_id
            .as_deref()
            .and_then(|member| member.strip_prefix("pattern:"))
            == cover.target.member_id.as_deref()
}

/// The blind-index sibling column carries no change code of its own: the
/// encryption and lookup change codes reach it through the physical-name
/// inventory member `"{field}#lookup"`, the way a reference or pattern change
/// reaches its implicit constraint.
#[cfg(feature = "tooling")]
fn encryption_cover_matches_implicit_lookup_column(
    cover: &ReviewedChangeCover,
    object: &ReviewedMigrationObject,
) -> bool {
    matches!(
        cover.code,
        CompiledRegistryChangeCode::FieldEncryptionChanged
            | CompiledRegistryChangeCode::FieldLookupChanged
    ) && object.kind == ReviewedMigrationObjectKind::Field
        && cover.target.kind == CompiledRegistryChangeTargetKind::Field
        && cover.target.entity_id.as_deref() == Some(object.entity_id.as_str())
        && object
            .member_id
            .as_deref()
            .and_then(|member| member.strip_suffix("#lookup"))
            == cover.target.member_id.as_deref()
}

/// The unique blind-index lookup index is compiler-owned but bound to the
/// field's lookup, registered as the inventory member `"lookup:{field}"`, so
/// an encryption or lookup change covers the SQL that creates or retires it.
#[cfg(feature = "tooling")]
fn encryption_cover_matches_implicit_lookup_index(
    cover: &ReviewedChangeCover,
    object: &ReviewedMigrationObject,
) -> bool {
    matches!(
        cover.code,
        CompiledRegistryChangeCode::FieldEncryptionChanged
            | CompiledRegistryChangeCode::FieldLookupChanged
    ) && object.kind == ReviewedMigrationObjectKind::Index
        && cover.target.kind == CompiledRegistryChangeTargetKind::Field
        && cover.target.entity_id.as_deref() == Some(object.entity_id.as_str())
        && object
            .member_id
            .as_deref()
            .and_then(|member| member.strip_prefix("lookup:"))
            == cover.target.member_id.as_deref()
}

#[cfg(feature = "tooling")]
fn covers_are_metadata_only(covers: &[ReviewedChangeCover]) -> bool {
    covers.iter().all(|cover| {
        matches!(
            cover.code,
            CompiledRegistryChangeCode::EntityRouteChanged
                | CompiledRegistryChangeCode::EntityMutationModeChanged
                | CompiledRegistryChangeCode::EntityClassificationChanged
                | CompiledRegistryChangeCode::EntityAccessRequirementsChanged
                | CompiledRegistryChangeCode::EntityGeoJsonChanged
                | CompiledRegistryChangeCode::FieldClassificationChanged
                | CompiledRegistryChangeCode::FieldTemporalRoleChanged
                | CompiledRegistryChangeCode::AccessProfileAdded
                | CompiledRegistryChangeCode::AccessProfileRemoved
                | CompiledRegistryChangeCode::AccessProfileChanged
                | CompiledRegistryChangeCode::RouteAdded
                | CompiledRegistryChangeCode::RouteRemoved
                | CompiledRegistryChangeCode::RouteChanged
                | CompiledRegistryChangeCode::QueryInventoryChanged
                | CompiledRegistryChangeCode::EventAdded
                | CompiledRegistryChangeCode::EventRemoved
                | CompiledRegistryChangeCode::EventChanged
                | CompiledRegistryChangeCode::ActionAdded
                | CompiledRegistryChangeCode::ActionRemoved
                | CompiledRegistryChangeCode::ActionChanged
                | CompiledRegistryChangeCode::ActionVocabularyCodesAdded
                | CompiledRegistryChangeCode::ActionTargetFieldsWidened
                | CompiledRegistryChangeCode::RecipientOrganizationAdded
                | CompiledRegistryChangeCode::RecipientOrganizationRemoved
                | CompiledRegistryChangeCode::RecipientOrganizationChanged
                | CompiledRegistryChangeCode::RecipientGroupAdded
                | CompiledRegistryChangeCode::RecipientGroupRemoved
                | CompiledRegistryChangeCode::RecipientGroupChanged
        )
    })
}

#[cfg(feature = "tooling")]
fn is_column_ref(node: Option<&pg_query::protobuf::Node>, expected: &str) -> bool {
    let Some(PgNode::ColumnRef(column)) = node.and_then(|node| node.node.as_ref()) else {
        return false;
    };
    node_strings(&column.fields).is_ok_and(|names| names.as_slice() == [expected])
}

#[cfg(feature = "tooling")]
fn is_uuid_array_parameter(node: Option<&pg_query::protobuf::Node>) -> bool {
    let Some(PgNode::TypeCast(cast)) = node.and_then(|node| node.node.as_ref()) else {
        return false;
    };
    let parameter = cast.arg.as_deref().and_then(|node| node.node.as_ref());
    let type_name = cast.type_name.as_ref();
    matches!(parameter, Some(PgNode::ParamRef(parameter)) if parameter.number == 1)
        && type_name.is_some_and(|name| {
            name.array_bounds.len() == 1
                && node_strings(&name.names)
                    .is_ok_and(|names| names.as_slice() == ["pg_catalog", "uuid"])
        })
}

#[cfg(feature = "tooling")]
fn node_strings(nodes: &[pg_query::protobuf::Node]) -> Result<Vec<String>, ReviewedMigrationError> {
    nodes
        .iter()
        .map(|node| match node.node.as_ref() {
            Some(PgNode::String(value)) => Ok(value.sval.clone()),
            _ => Err(ReviewedMigrationError::Sql),
        })
        .collect()
}

#[cfg(feature = "tooling")]
fn read_sql<'a>(
    files: &'a BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Result<&'a str, ReviewedMigrationError> {
    let bytes = files.get(path).ok_or(ReviewedMigrationError::Closure)?;
    if reviewed_artifact_kind(path) != Some(ReviewedArtifactKind::StepSql)
        && reviewed_artifact_kind(path) != Some(ReviewedArtifactKind::AssertionSql)
    {
        return Err(ReviewedMigrationError::Closure);
    }
    std::str::from_utf8(bytes).map_err(|_| ReviewedMigrationError::Sql)
}

#[cfg(feature = "tooling")]
fn descriptor_base(
    path: &str,
    descriptor_id: &str,
) -> Result<(String, String), ReviewedMigrationError> {
    if reviewed_artifact_kind(path) != Some(ReviewedArtifactKind::Descriptor) {
        return Err(ReviewedMigrationError::Descriptor);
    }
    let components = path.split('/').collect::<Vec<_>>();
    let module_id = components[1];
    if components[3] != descriptor_id {
        return Err(ReviewedMigrationError::Descriptor);
    }
    Ok((
        module_id.to_owned(),
        format!("modules/{module_id}/migrations/{descriptor_id}"),
    ))
}

#[cfg(feature = "tooling")]
fn strictly_sorted<T: Ord>(values: impl Iterator<Item = T>) -> bool {
    let mut prior = None;
    for value in values {
        if prior.as_ref().is_some_and(|prior| prior >= &value) {
            return false;
        }
        prior = Some(value);
    }
    true
}

#[cfg(feature = "tooling")]
fn valid_timeout(value: u64, ceiling: u64) -> bool {
    value > 0 && value <= ceiling
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[cfg(feature = "tooling")]
fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(feature = "tooling")]
fn digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(71);
    result.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

#[cfg(all(test, feature = "tooling"))]
mod tests {
    use super::*;

    fn cover(code: CompiledRegistryChangeCode) -> ReviewedChangeCover {
        ReviewedChangeCover {
            code,
            target: CompiledRegistryChangeTarget {
                kind: CompiledRegistryChangeTargetKind::Recipient,
                entity_id: None,
                member_id: Some("recipient".to_owned()),
            },
        }
    }

    #[test]
    fn recipient_changes_are_metadata_only_covers() {
        for code in [
            CompiledRegistryChangeCode::RecipientOrganizationAdded,
            CompiledRegistryChangeCode::RecipientOrganizationRemoved,
            CompiledRegistryChangeCode::RecipientOrganizationChanged,
            CompiledRegistryChangeCode::RecipientGroupAdded,
            CompiledRegistryChangeCode::RecipientGroupRemoved,
            CompiledRegistryChangeCode::RecipientGroupChanged,
        ] {
            assert!(covers_are_metadata_only(&[cover(code)]), "{code:?}");
        }
        // A consent record change replaces the probe function, so it is not.
        assert!(!covers_are_metadata_only(&[cover(
            CompiledRegistryChangeCode::ConsentRecordChanged
        )]));
    }
}
