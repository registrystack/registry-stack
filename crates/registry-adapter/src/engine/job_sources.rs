// SPDX-License-Identifier: Apache-2.0

//! The engine-side sources block of the operator runtime config
//! (`products/adapter/CONCEPT.md` sections 10.2 and 17.2) over the
//! endpoint bindings core owns
//! (`registry_adapter_core::AdapterEndpointBindings`): the environment
//! state of the governed-ingestion sources, which no endpoint binding
//! can carry. The job runtime document is its own format
//! (`AdapterJobRuntimeConfig`), distinct from the facade's
//! (`registry_adapter_core::AdapterRuntimeConfig`): the facade reader
//! refuses the block, so a facade deployment accepts no job source
//! state, and the job compiler reads its document through
//! [`JobRuntimeConfig`], whose bindings core is the core-owned type and
//! whose `sources` member this module parses. The bindings core keeps
//! its own unknown-key refusal, so a facade member in a job document
//! refuses exactly as the core reader refuses it. Numeric bounds are reader-checked through the platform's
//! bounded types; every other shape rule is a `Deserialize` impl here,
//! value-free, so a malformed source binding refuses at the reader and
//! not at the first read.

use std::collections::BTreeMap;

use registry_adapter_core::{
    AdapterEndpointBindings, Cidr, EndpointBinding, OutboundTls, MAXIMUM_JOB_FIELD_BYTES,
    MAXIMUM_JOB_FILE_BYTES, MAXIMUM_JOB_ROWS_PER_PAGE, MAXIMUM_JOB_ROW_BYTES,
};
use registry_platform_config::{RuntimeConfigLoader, RuntimeEnvelope};
use registry_platform_yaml::{
    BoundedU32, BoundedU64, LocalId, SecretReference, UniqueIdList, UniqueList,
};
use serde::Deserialize;

/// The read bounds of a route that runs no read step: the format's
/// widest values. Facade deployments carry no job profile, so this is
/// the state their routes run under; no facade path reads it.
#[must_use]
pub fn unused_read_bounds() -> registry_adapter_core::ReadBounds {
    registry_adapter_core::ReadBounds {
        maximum_file_bytes: MAXIMUM_JOB_FILE_BYTES,
        maximum_row_bytes: MAXIMUM_JOB_ROW_BYTES,
        maximum_field_bytes: MAXIMUM_JOB_FIELD_BYTES,
        maximum_rows_per_page: MAXIMUM_JOB_ROWS_PER_PAGE,
    }
}

/// The governed-ingestion state one route run carries: the job profile
/// whose bounds the read steps hold, and the compiled file sources by
/// endpoint id. Empty in every facade deployment and replay, whose
/// routes carry no job step.
#[derive(Clone, Default)]
pub struct JobPageState {
    /// The job profile of the run; `None` in every facade deployment.
    /// Read only by the read steps, so a build without them never reads
    /// it.
    #[cfg_attr(not(feature = "job-file"), allow(dead_code))]
    pub(crate) profile: Option<registry_adapter_core::JobProfile>,
    /// The compiled file sources by pack endpoint id.
    #[cfg_attr(not(feature = "job-file"), allow(dead_code))]
    pub(crate) files: BTreeMap<String, FileSourceConfig>,
    /// The compiled read-only postgres source plans by pack endpoint
    /// id; a build without job-postgres carries none.
    #[cfg(feature = "job-postgres")]
    pub(crate) postgres:
        BTreeMap<String, std::sync::Arc<crate::engine::component::postgres::PostgresPlan>>,
    /// The source clients the host registered beside the plans; the
    /// engine boundary carries no client of its own.
    #[cfg(feature = "job-postgres")]
    pub(crate) postgres_clients:
        BTreeMap<String, std::sync::Arc<dyn crate::engine::component::postgres::PostgresSource>>,
}

/// The runtime config as the job mode reads it: the endpoint bindings
/// core beside the job-only `sources` block and the job host's `store`
/// block. The document decodes as one typed mapping that declares the
/// bindings core's members beside the other two, so a facade member in a
/// job document refuses as an unknown key with its pointer and position,
/// exactly as the facade reader refuses a job member. The facade reader refuses the job
/// document's kind, and its `sources` member besides. The bindings core is
/// `registry_adapter_core::AdapterEndpointBindings`, the shape the
/// facade document sets aside with `AdapterRuntimeConfig::endpoint_bindings`.
#[derive(Debug)]
pub struct JobRuntimeConfig {
    /// The endpoint bindings every mode shares.
    pub core: AdapterEndpointBindings,
    /// The governed-ingestion source bindings. Absent, the deployment
    /// binds no job source; a pack whose source route reads one refuses
    /// at the job compile, never at the first read.
    pub sources: Option<JobSources>,
    /// The job host's store block: the item table's connection
    /// references, read and checked here like every other member and
    /// resolved by the host. Absent, the document configures no job
    /// store.
    pub store: Option<JobStoreConfig>,
}

impl JobRuntimeConfig {
    /// Read the job runtime document through the platform runtime
    /// loader: its own envelope (`AdapterJobRuntimeConfig`, never the
    /// facade's `AdapterRuntimeConfig`), the retired keys the facade
    /// document also refuses, then this document's own member
    /// discipline. The one reader the compile path and the job host
    /// share.
    ///
    /// # Errors
    ///
    /// The loader's refusal, the reader's own value-free report.
    pub fn load(
        path: &std::path::Path,
    ) -> Result<Self, registry_platform_config::RuntimeConfigError> {
        // The loader refuses a path with a symbolic-link component; the
        // canonical path names the same file without one (the system
        // temporary directory carries such a component on some
        // platforms). A path that cannot be canonicalized is left to
        // the loader's own unreadable refusal.
        let absolute = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        RuntimeConfigLoader::new(RuntimeEnvelope {
            api_version: registry_adapter_core::ADAPTER_JOB_RUNTIME_API_VERSION,
            kind: registry_adapter_core::ADAPTER_JOB_RUNTIME_KIND,
        })
        .removed_keys(registry_adapter_core::ADAPTER_REMOVED_KEYS)
        .load::<Self>(&absolute)
        .map(|loaded| loaded.config)
    }
}

/// The job runtime document as the reader decodes it: every member typed,
/// so each refusal carries the reader's own code, pointer, and position,
/// and an undeclared member at any depth refuses. The endpoint bindings
/// members are the ones `AdapterEndpointBindings` declares, under the
/// same rules.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JobRuntimeDocument {
    id: LocalId,
    endpoints: UniqueIdList<EndpointBinding>,
    #[serde(default)]
    outbound_tls: Option<OutboundTls>,
    #[serde(deserialize_with = "registry_adapter_core::at_least_one_cidr")]
    allowed_private_cidrs: UniqueList<Cidr>,
    #[serde(default)]
    sources: Option<JobSources>,
    #[serde(default)]
    store: Option<JobStoreConfig>,
}

impl<'de> Deserialize<'de> for JobRuntimeConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let document = JobRuntimeDocument::deserialize(deserializer)?;
        Ok(Self {
            core: AdapterEndpointBindings {
                id: document.id,
                endpoints: document.endpoints,
                outbound_tls: document.outbound_tls,
                allowed_private_cidrs: document.allowed_private_cidrs,
            },
            sources: document.sources,
            store: document.store,
        })
    }
}

/// The job store block of the job runtime config (`store:`): the item
/// table's single connection reference. The job store runs its
/// migrations on the same connection it serves from, so the block
/// carries no separate migration member; the facade's database block
/// (journal and idempotency pools) is a facade member the job document
/// refuses. Secret references only, resolved by the job host, never a
/// URL in the document. The engine reads the block and never connects.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobStoreConfig {
    /// The runtime connection reference of the item table's database.
    pub runtime_url_ref: SecretReference,
    /// The root certificate the connection trusts beside the platform
    /// roots; absent, the platform roots alone.
    #[serde(default)]
    pub trusted_root_certificate_ref: Option<SecretReference>,
    /// Plaintext connections for the loopback test database only;
    /// refused by the job host in any build without its `postgres-test`
    /// feature, the way the facade database refuses it.
    #[serde(default)]
    pub test_only_plaintext: bool,
}

/// The job source bindings of one runtime config, keyed by the pack
/// endpoint each binds.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobSources {
    /// The file sources, keyed by endpoint id.
    #[serde(default, deserialize_with = "local_id_keys")]
    pub(crate) file: BTreeMap<String, FileSourceConfig>,
    /// The read-only postgres sources, keyed by endpoint id. The
    /// engine's compile reads it only with job-postgres; the host client
    /// reads the same block for its pool.
    #[cfg_attr(not(feature = "job-postgres"), allow(dead_code))]
    #[serde(default, deserialize_with = "local_postgres_keys")]
    pub(crate) postgres: BTreeMap<String, PostgresSourceConfig>,
}

/// Deserialize a map whose keys are `LocalId`s into a map keyed by the
/// plain text, the same discipline
/// `registry_adapter_core::model::local_id_map` holds for core maps.
fn local_id_keys<'de, D>(deserializer: D) -> Result<BTreeMap<String, FileSourceConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map = BTreeMap::<LocalId, FileSourceConfig>::deserialize(deserializer)?;
    Ok(map
        .into_iter()
        .map(|(key, value)| (key.into_string(), value))
        .collect())
}

/// The same key discipline for the postgres sources.
fn local_postgres_keys<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, PostgresSourceConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map = BTreeMap::<LocalId, PostgresSourceConfig>::deserialize(deserializer)?;
    Ok(map
        .into_iter()
        .map(|(key, value)| (key.into_string(), value))
        .collect())
}

/// The runtime binding of one read-only `postgres` source endpoint
/// (`products/adapter/CONCEPT.md` sections 10.2 and 17.2): its own pool,
/// never the journal's, with its own credential and TLS posture. The
/// engine's compile reads only the namespace; the host client reads the
/// connection members from this same block.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PostgresSourceConfig {
    /// The source host.
    pub(crate) host: String,
    /// The source port (1 to 65535); absent, 5432.
    #[serde(default = "default_postgres_port")]
    pub(crate) port: BoundedU64<1, 65_535>,
    /// The source database.
    pub(crate) database: String,
    /// The source user.
    pub(crate) user: String,
    /// The reference the source password resolves from; resolved
    /// through the platform secret providers, never logged.
    pub(crate) password_ref: SecretReference,
    /// The namespace every item key of this source carries.
    pub(crate) namespace: String,
    /// The TLS posture of the connection; absent, the system roots and
    /// a required TLS connection.
    #[serde(default)]
    pub(crate) tls: SourceTls,
}

fn default_postgres_port() -> BoundedU64<1, 65_535> {
    BoundedU64::new(5_432).expect("5432 is inside the bound")
}

/// The TLS posture of one postgres source connection. The default is
/// the secure one: system roots, TLS required. Plaintext exists for the
/// loopback test database only and refuses in every other build.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum SourceTls {
    /// The platform trust roots, TLS required, no client certificate.
    #[default]
    #[serde(rename = "system-roots")]
    SystemRoots,
    /// One private CA bundle file beside the platform roots, the same
    /// shape a facade trust profile carries: a CA bundle is not a
    /// secret, so the member names a file.
    #[serde(rename = "ca-bundle", rename_all = "camelCase")]
    CaBundle {
        /// The absolute path of the PEM file holding the bundle.
        ca_bundle_file: String,
    },
    /// Plaintext, loopback test databases only; refused in any build
    /// without the postgres-test feature, the way the facade database
    /// block refuses it.
    #[cfg(feature = "postgres-test")]
    #[serde(rename = "plaintext")]
    Plaintext,
}

/// The runtime binding of one `file` source endpoint
/// (`products/adapter/CONCEPT.md` sections 10.2 and 17.2): the absolute
/// base directory the read never leaves, the namespace the item keys
/// carry, and the read behavior the port of camel-file selects. The
/// members are read by the file source runtime, so a build without that
/// feature parses the block and reads none of it.
#[cfg_attr(not(feature = "job-file"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileSourceConfig {
    /// The absolute path of the directory the read lists and reads.
    /// A relative path refuses at the reader.
    #[serde(deserialize_with = "absolute_directory")]
    pub(crate) directory: std::path::PathBuf,
    /// The namespace every item key of this source carries.
    pub(crate) namespace: String,
    /// The Ant-style glob a candidate file name must match; absent,
    /// every file is a candidate. A glob carrying a path separator
    /// refuses at the reader: the read is non-recursive, so names carry
    /// none.
    #[serde(default, deserialize_with = "flat_include")]
    pub(crate) include: Option<String>,
    /// The done-file convention a candidate must satisfy; absent, no
    /// done-file check runs.
    #[serde(default, deserialize_with = "done_file_name")]
    pub(crate) done_file_name: Option<DoneFileName>,
    /// The read lock: `none` (the Camel default) or `changed`
    /// (camel-4.23.0:components/camel-file/src/main/java/org/apache/camel/component/file/GenericFileEndpoint.java,
    /// `readLock`, "none" is the default of the options the read-only
    /// port keeps). The reader carries the closed set itself, so a lock
    /// name outside the pair refuses at the reader and never reaches a
    /// read.
    #[serde(default)]
    pub(crate) read_lock: Option<ReadLockName>,
    /// The `changed` lock's timeout, in milliseconds (1 to 10000, the
    /// pollEnrich step's own timeout ceiling, so the lock wait can finish
    /// inside the read); camel-4.23.0's `readLockTimeout` field default
    /// of 10000. Refused beside any read lock but `changed`.
    #[serde(default)]
    pub(crate) read_lock_timeout_milliseconds: Option<BoundedU64<1, 10_000>>,
    /// The `changed` lock's space between its two checks, in
    /// milliseconds (100 to 5000); camel-4.23.0's
    /// `readLockCheckInterval` field default of 1000. Refused beside
    /// any read lock but `changed`.
    #[serde(default)]
    pub(crate) read_lock_check_interval_milliseconds: Option<BoundedU64<100, 5_000>>,
    /// Camel's `maxMessagesPerPoll`, accepted for Camel parity at a
    /// bounded default (Camel's field default of zero means no limit,
    /// which no bounded option can port; 500 is the recorded
    /// divergence). It windows the candidates after the cursor, but one
    /// read emits at most one file and a consumed resume file never
    /// spends the window, so any value of one or more reaches the same
    /// file: the member bounds nothing a read does not already bound.
    #[serde(default = "default_max_messages_per_poll")]
    pub(crate) max_messages_per_poll: BoundedU32<1, { u32::MAX }>,
}

fn default_max_messages_per_poll() -> BoundedU32<1, { u32::MAX }> {
    BoundedU32::new(500).expect("500 is inside the bound")
}

/// The read lock's closed name set, as the reader carries it.
#[cfg_attr(not(feature = "job-file"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum ReadLockName {
    /// No lock: a candidate is read as it stands, Camel's default.
    None,
    /// Camel's `changed` lock.
    Changed,
}

/// The resolved read lock of one file source.
#[cfg_attr(not(feature = "job-file"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadLockKind {
    /// No lock: a candidate is read as it stands, Camel's default.
    None,
    /// Camel's `changed` lock: the file's length and last-modified time
    /// stable across two checks spaced the check interval apart, inside
    /// the timeout.
    Changed {
        /// The longest the lock may take, in milliseconds.
        timeout_milliseconds: u64,
        /// The space between the two checks, in milliseconds.
        check_interval_milliseconds: u64,
    },
}

#[cfg_attr(not(feature = "job-file"), allow(dead_code))]
impl FileSourceConfig {
    /// The source's resolved read lock. A lock name outside the closed
    /// pair, or a lock bound beside any lock but `changed`, refuses;
    /// the message names the member, never a value.
    ///
    /// # Errors
    ///
    /// A `readLock` outside `{none, changed}`, or a
    /// `readLockTimeoutMilliseconds` or
    /// `readLockCheckIntervalMilliseconds` beside any lock but
    /// `changed`.
    pub fn read_lock(&self) -> Result<ReadLockKind, String> {
        let changed = matches!(self.read_lock, Some(ReadLockName::Changed));
        if !changed
            && (self.read_lock_timeout_milliseconds.is_some()
                || self.read_lock_check_interval_milliseconds.is_some())
        {
            return Err("the file source read lock bounds ride no changed read lock".to_owned());
        }
        Ok(if changed {
            ReadLockKind::Changed {
                timeout_milliseconds: self
                    .read_lock_timeout_milliseconds
                    .map_or(10_000, |bound| bound.get()),
                check_interval_milliseconds: self
                    .read_lock_check_interval_milliseconds
                    .map_or(1_000, |bound| bound.get()),
            }
        } else {
            ReadLockKind::None
        })
    }
}

/// The done-file convention of one file source: a literal name, or one
/// file-name placeholder with a fixed prefix or suffix (or both),
/// camel-4.23.0's `doneFileName` forms
/// (camel-4.23.0:components/camel-file/src/main/java/org/apache/camel/component/file/GenericFileEndpoint.java,
/// `createDoneFileName`). The runtime reader's own substitution grammar
/// claims every `${...}` in a value, so the placeholder is written in
/// that processor's equivalent `$simple{file:name}` spelling, which
/// `createDoneFileName` resolves exactly like `${file:name}`; both
/// spellings read the same here. The `${file:name.noext}` form is not
/// ported.
#[derive(Debug, Clone)]
pub(crate) enum DoneFileName {
    /// A fixed name, shared by every candidate.
    Literal(String),
    /// A fixed prefix and suffix around the candidate's own name.
    Placeholder { prefix: String, suffix: String },
}

#[cfg_attr(not(feature = "job-file"), allow(dead_code))]
impl DoneFileName {
    /// The done-file name one candidate carries.
    #[must_use]
    pub fn of(&self, name: &str) -> String {
        match self {
            Self::Literal(literal) => literal.clone(),
            Self::Placeholder { prefix, suffix } => format!("{prefix}{name}{suffix}"),
        }
    }

    /// Whether the candidate name is itself a done file, which the read
    /// never emits as data.
    #[must_use]
    pub fn is_done_file(&self, name: &str) -> bool {
        match self {
            Self::Literal(literal) => literal == name,
            Self::Placeholder { prefix, suffix } => {
                name.len() >= prefix.len() + suffix.len()
                    && name.starts_with(prefix.as_str())
                    && name.ends_with(suffix.as_str())
            }
        }
    }
}

const FILE_NAME_PLACEHOLDER: &str = "${file:name}";
const SIMPLE_FILE_NAME_PLACEHOLDER: &str = "$simple{file:name}";

/// Refuse any `doneFileName` but a literal or one file-name placeholder
/// with fixed text around it. Any other `${` spelling is an unresolved
/// placeholder, which camel-4.23.0 refuses too
/// (`createDoneFileName`'s `isSimpleLanguage` check), so it never
/// silently names a literal file.
fn done_file_name<'de, D>(deserializer: D) -> Result<Option<DoneFileName>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let written = Option::<String>::deserialize(deserializer)?;
    let Some(written) = written else {
        return Ok(None);
    };
    // Both processor spellings of the file-name placeholder read the
    // same; the substitution grammar claims `${...}` in a runtime
    // value, so the `$simple{...}` spelling is the one a runtime config
    // can carry.
    let pattern = written.replace(SIMPLE_FILE_NAME_PLACEHOLDER, FILE_NAME_PLACEHOLDER);
    if !pattern.contains("${") {
        if pattern.is_empty() || pattern.contains('/') || pattern.contains('\\') {
            return Err(serde::de::Error::custom(
                "doneFileName carries a path separator or is empty; write a plain file name",
            ));
        }
        return Ok(Some(DoneFileName::Literal(pattern)));
    }
    let first = pattern.find(FILE_NAME_PLACEHOLDER);
    let last = pattern.rfind(FILE_NAME_PLACEHOLDER);
    if first != last {
        return Err(serde::de::Error::custom(
            "doneFileName carries more than one file-name placeholder; write one",
        ));
    }
    let Some(start) = first else {
        return Err(serde::de::Error::custom(
            "doneFileName carries a placeholder the reader does not port; write a plain name or one file-name placeholder",
        ));
    };
    let (prefix, rest) = pattern.split_at(start);
    let suffix = &rest[FILE_NAME_PLACEHOLDER.len()..];
    if prefix.contains("${") || suffix.contains("${") {
        return Err(serde::de::Error::custom(
            "doneFileName carries a placeholder the reader does not port; write a plain name or one file-name placeholder",
        ));
    }
    if prefix.contains('/')
        || prefix.contains('\\')
        || suffix.contains('/')
        || suffix.contains('\\')
    {
        return Err(serde::de::Error::custom(
            "doneFileName carries a path separator; the done file sits in the source directory",
        ));
    }
    Ok(Some(DoneFileName::Placeholder {
        prefix: prefix.to_owned(),
        suffix: suffix.to_owned(),
    }))
}

/// Refuse a relative directory: the read never resolves one against the
/// process's working directory.
fn absolute_directory<'de, D>(deserializer: D) -> Result<std::path::PathBuf, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    let path = std::path::PathBuf::from(&text);
    if !path.is_absolute() {
        return Err(serde::de::Error::custom(
            "the file source directory is relative; write the absolute path of the directory",
        ));
    }
    Ok(path)
}

/// Refuse an include glob that could never match a flat file name.
fn flat_include<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let pattern = Option::<String>::deserialize(deserializer)?;
    if let Some(pattern) = &pattern {
        if pattern.is_empty() || pattern.contains('/') || pattern.contains('\\') {
            return Err(serde::de::Error::custom(
                "include carries a path separator or is empty; the read is non-recursive, so a glob matches plain names",
            ));
        }
    }
    Ok(pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The postgres source's CA bundle member is spelled `caBundleFile`,
    /// the way a facade trust profile spells it, and a member the
    /// `ca-bundle` posture does not carry refuses.
    #[test]
    fn the_postgres_source_tls_reads_camel_case_members_only() {
        let source = |tls: &str| {
            serde_json::from_str::<PostgresSourceConfig>(&format!(
                r#"{{ "host": "db.example.invalid", "database": "cases", "user": "reader",
                     "passwordRef": "secret:env/SOURCE_PASSWORD", "namespace": "cases",
                     "tls": {tls} }}"#
            ))
        };
        let read = source(r#"{ "type": "ca-bundle", "caBundleFile": "/etc/trust/ca.pem" }"#)
            .expect("the camelCase bundle member reads");
        assert!(
            matches!(read.tls, SourceTls::CaBundle { ref ca_bundle_file } if ca_bundle_file == "/etc/trust/ca.pem")
        );
        assert!(
            source(r#"{ "type": "ca-bundle", "ca_bundle_file": "/etc/trust/ca.pem" }"#).is_err(),
            "the snake_case spelling is not the format's"
        );
        assert!(
            source(
                r#"{ "type": "ca-bundle", "caBundleFile": "/etc/trust/ca.pem", "caBundle": "/etc/trust/ca.pem" }"#
            )
            .is_err(),
            "a member the posture does not carry refuses"
        );
    }

    /// The job runtime config reads the core document plus a sources
    /// block, and every other unknown member still refuses, because the
    /// flattened core keeps its own refusal.
    #[test]
    fn the_job_runtime_reader_accepts_sources_and_refuses_unknown_members() {
        let head = r#"{
                "id": "job-deployment",
                "endpoints": [],
                "allowedPrivateCidrs": ["10.0.0.0/8"]
            }"#;
        let with_sources = head.replace(
            r#""endpoints": [],"#,
            r#""endpoints": [], "sources": { "file": { "dropbox": {
                "directory": "/var/data/dropbox",
                "namespace": "exports"
            } } },"#,
        );
        let read: JobRuntimeConfig =
            serde_json::from_str(&with_sources).expect("the sources block reads");
        let config = read.sources.expect("the sources block is present");
        assert_eq!(config.file.len(), 1);
        let source = config.file.get("dropbox").expect("the dropbox source");
        assert_eq!(source.namespace, "exports");
        assert_eq!(source.read_lock(), Ok(ReadLockKind::None));
        assert_eq!(source.max_messages_per_poll.get(), 500);

        let stray = head.replace(r#""endpoints": [],"#, r#""endpoints": [], "bogus": 1,"#);
        assert!(
            serde_json::from_str::<JobRuntimeConfig>(&stray).is_err(),
            "a member the core refuses stays refused through the wrapper"
        );
    }

    /// A relative directory, a separator-carrying glob, and a
    /// placeholder form outside the supported set refuse at the reader.
    #[test]
    fn the_file_source_reader_refuses_out_of_bounds_shapes() {
        let head = |directory: &str, extra: &str| {
            format!(r#"{{ "directory": "{directory}", "namespace": "exports"{extra} }}"#)
        };
        assert!(
            serde_json::from_str::<FileSourceConfig>(&head("var/data", "")).is_err(),
            "a relative directory refuses"
        );
        assert!(
            serde_json::from_str::<FileSourceConfig>(&head("/var/data", r#", "include": "a/*b""#))
                .is_err(),
            "a separator-carrying include refuses"
        );
        assert!(
            serde_json::from_str::<FileSourceConfig>(&head(
                "/var/data",
                r#", "maxMessagesPerPoll": 0"#
            ))
            .is_err(),
            "an unlimited maxMessagesPerPoll refuses; every read stays bounded"
        );
        assert!(
            serde_json::from_str::<FileSourceConfig>(&head(
                "/var/data",
                r#", "doneFileName": "${file:name}${file:name}.done""#
            ))
            .is_err(),
            "a doneFileName with two placeholders refuses"
        );
        assert!(
            serde_json::from_str::<FileSourceConfig>(&head(
                "/var/data",
                r#", "doneFileName": "${file:onlyname}.done""#
            ))
            .is_err(),
            "an unported placeholder spelling refuses, never reads as a literal name"
        );
        let read: FileSourceConfig = serde_json::from_str(&head(
            "/var/data",
            r#", "doneFileName": "done-${file:name}""#,
        ))
        .expect("the prefix form reads");
        let done = read
            .done_file_name
            .clone()
            .expect("the done file convention");
        assert_eq!(done.of("a.csv"), "done-a.csv");
        assert!(
            done.is_done_file("done-a.csv"),
            "the done file itself is never a candidate"
        );
    }

    /// The facade's own reader refuses the sources member: job source
    /// state never enters a facade deployment. The job bindings reader
    /// refuses the facade members the same way, both directions of the
    /// one line.
    #[test]
    fn the_readers_refuse_each_others_members() {
        let job_json = r#"{
                "id": "job-deployment",
                "endpoints": [],
                "allowedPrivateCidrs": ["10.0.0.0/8"],
                "listener": { "bind": "127.0.0.1:8080" },
                "database": {
                    "runtimeUrlRef": "secret:env/DB_RUNTIME",
                    "migrationUrlRef": "secret:env/DB_MIGRATION"
                },
                "oidc": { "issuer": "https://issuer.example.invalid", "audience": "job" },
                "allowedClients": ["job-client"],
                "audit": { "retentionDays": 90 }
            }"#;
        assert!(
            serde_json::from_str::<AdapterEndpointBindings>(job_json).is_err(),
            "a facade member refuses a job bindings document"
        );
        let facade_json = r#"{
                "id": "case-deployment",
                "endpoints": [],
                "allowedPrivateCidrs": ["10.0.0.0/8"],
                "listener": { "bind": "127.0.0.1:8080" },
                "database": {
                    "runtimeUrlRef": "secret:env/DB_RUNTIME",
                    "migrationUrlRef": "secret:env/DB_MIGRATION"
                },
                "oidc": { "issuer": "https://issuer.example.invalid", "audience": "case-api" },
                "allowedClients": ["case-portal"],
                "audit": { "retentionDays": 90 },
                "sources": { "file": {} }
            }"#;
        assert!(
            serde_json::from_str::<registry_adapter_core::AdapterRuntimeConfig>(facade_json)
                .is_err(),
            "the sources block refuses a facade document"
        );
    }

    /// The job host's store block sits beside the engine's members and
    /// reads under the same member discipline: an undeclared store
    /// member refuses, as does any member no part of the document
    /// declares.
    #[test]
    fn the_store_block_reads_beside_the_sources_under_one_discipline() {
        let with_store = r#"{
                "id": "job-deployment",
                "endpoints": [],
                "allowedPrivateCidrs": ["10.0.0.0/8"],
                "sources": { "file": {} },
                "store": { "runtimeUrlRef": "secret:env/JOB_DB" }
            }"#;
        let read: JobRuntimeConfig =
            serde_json::from_str(with_store).expect("the store block reads");
        assert!(read.sources.is_some(), "the sources block still reads");
        assert!(read.store.is_some(), "the store block reads");
        let undeclared_store_member = r#"{
                "id": "job-deployment",
                "endpoints": [],
                "allowedPrivateCidrs": ["10.0.0.0/8"],
                "store": {
                    "runtimeUrlRef": "secret:env/JOB_DB",
                    "a_member_no_reader_declares": true
                }
            }"#;
        assert!(
            serde_json::from_str::<JobRuntimeConfig>(undeclared_store_member).is_err(),
            "an undeclared store member refuses"
        );
        let unclaimed = r#"{
                "id": "job-deployment",
                "endpoints": [],
                "allowedPrivateCidrs": ["10.0.0.0/8"],
                "listeners": { "bind": "127.0.0.1:8080" }
            }"#;
        assert!(
            serde_json::from_str::<JobRuntimeConfig>(unclaimed).is_err(),
            "a member no reader claims refuses"
        );
    }

    /// The changed read lock carries camel-4.23.0's field defaults: a
    /// 10000-millisecond timeout over checks 1000 milliseconds apart,
    /// written flat like the component options the port keeps.
    #[test]
    fn the_changed_read_lock_defaults_match_camel() {
        let read: FileSourceConfig = serde_json::from_str(
            r#"{ "directory": "/var/data", "namespace": "exports", "readLock": "changed" }"#,
        )
        .expect("the changed lock reads");
        assert_eq!(
            read.read_lock(),
            Ok(ReadLockKind::Changed {
                timeout_milliseconds: 10_000,
                check_interval_milliseconds: 1_000,
            }),
            "the defaults are camel-4.23.0's own"
        );
        let slow: Result<FileSourceConfig, _> = serde_json::from_str(
            r#"{ "directory": "/var/data", "namespace": "exports", "readLock": "changed", "readLockCheckIntervalMilliseconds": 99 }"#,
        );
        assert!(slow.is_err(), "an out-of-bounds check interval refuses");
        let stray: FileSourceConfig = serde_json::from_str(
            r#"{ "directory": "/var/data", "namespace": "exports", "readLock": "none", "readLockTimeoutMilliseconds": 500 }"#,
        )
        .expect("the reader carries the members");
        assert!(
            stray.read_lock().is_err(),
            "a timeout beside no changed lock refuses"
        );
        // The closed set rides the reader itself: a lock name outside
        // the pair never reaches a read to be resolved.
        let unknown: Result<FileSourceConfig, _> = serde_json::from_str(
            r#"{ "directory": "/var/data", "namespace": "exports", "readLock": "rename" }"#,
        );
        assert!(unknown.is_err(), "rename is not ported");
    }

    /// The changed lock's timeout stays inside the pollEnrich step's own
    /// read timeout (1 to 10000 milliseconds): a longer lock wait could
    /// never finish before the step gives up on the read.
    #[test]
    fn the_read_lock_timeout_fits_inside_the_poll_timeout() {
        let lock = |timeout: u64| {
            serde_json::from_str::<FileSourceConfig>(&format!(
                r#"{{ "directory": "/var/data", "namespace": "exports", "readLock": "changed", "readLockTimeoutMilliseconds": {timeout} }}"#
            ))
        };
        assert!(lock(10_000).is_ok(), "the poll timeout's own ceiling reads");
        assert!(
            lock(10_001).is_err(),
            "a lock wait longer than any poll timeout refuses"
        );
    }
}

#[cfg(test)]
mod loader_tests {
    use super::*;
    use registry_adapter_core::{
        ADAPTER_JOB_RUNTIME_API_VERSION, ADAPTER_JOB_RUNTIME_KIND, ADAPTER_RUNTIME_API_VERSION,
        ADAPTER_RUNTIME_KIND,
    };

    fn document(api_version: &str, kind: &str) -> String {
        format!(
            "apiVersion: {api_version}\nkind: {kind}\nid: job-deployment\nendpoints: []\nallowedPrivateCidrs:\n  - 10.0.0.0/8\nsources:\n  file:\n    submissions:\n      directory: /var/data\n      namespace: submissions\n"
        )
    }

    fn load(text: &str) -> Result<JobRuntimeConfig, registry_platform_config::RuntimeConfigError> {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime.yaml");
        std::fs::write(&path, text).expect("write the runtime document");
        JobRuntimeConfig::load(&path)
    }

    /// The job runtime config reads through the shared loader under its
    /// own envelope.
    #[test]
    fn the_loader_reads_the_job_runtime_config() {
        let read = load(&document(
            ADAPTER_JOB_RUNTIME_API_VERSION,
            ADAPTER_JOB_RUNTIME_KIND,
        ));
        assert!(read.is_ok(), "{read:?}");
    }

    /// An undeclared member refuses at every depth with the reader's own
    /// code and pointer: at the root, inside the bindings, and inside
    /// the job store block the host resolves.
    #[test]
    fn an_undeclared_member_refuses_with_its_pointer_at_every_depth() {
        let base = document(ADAPTER_JOB_RUNTIME_API_VERSION, ADAPTER_JOB_RUNTIME_KIND);
        for (text, pointer) in [
            (format!("{base}conformanceFirst: 1\n"), "/conformanceFirst"),
            (
                format!(
                    "{base}store:\n  runtimeUrlRef: secret:env/JOB_DB\n  conformanceUnknown: 1\n"
                ),
                "/store/conformanceUnknown",
            ),
        ] {
            let refused = load(&text).expect_err("an undeclared member refuses");
            assert!(
                refused
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.code == "config.unknown-key"
                        && diagnostic.path == pointer),
                "{pointer}: {:?}",
                refused.diagnostics()
            );
        }
    }

    /// The store block reads typed beside the bindings.
    #[test]
    fn the_store_block_reads_typed() {
        let text = format!(
            "{}store:\n  runtimeUrlRef: secret:env/JOB_DB\n",
            document(ADAPTER_JOB_RUNTIME_API_VERSION, ADAPTER_JOB_RUNTIME_KIND)
        );
        let read = load(&text).expect("the store block reads");
        let store = read.store.expect("a store block");
        assert!(!store.test_only_plaintext);
        assert!(store.trusted_root_certificate_ref.is_none());
    }

    /// The job and facade runtime documents are two formats: the job
    /// loader refuses the facade envelope, and the facade envelope
    /// refuses a job document, so neither schema describes the other's
    /// shape.
    #[test]
    fn the_job_and_facade_envelopes_refuse_each_other() {
        assert!(
            load(&document(ADAPTER_RUNTIME_API_VERSION, ADAPTER_RUNTIME_KIND)).is_err(),
            "the job loader refuses the facade envelope"
        );
        let facade = registry_platform_config::RuntimeConfigLoader::new(
            registry_platform_config::RuntimeEnvelope {
                api_version: ADAPTER_RUNTIME_API_VERSION,
                kind: ADAPTER_RUNTIME_KIND,
            },
        );
        let read = facade.parse_str::<serde_json::Value>(
            &document(ADAPTER_JOB_RUNTIME_API_VERSION, ADAPTER_JOB_RUNTIME_KIND),
            |_| None,
        );
        assert!(read.is_err(), "the facade envelope refuses a job document");
    }
}
