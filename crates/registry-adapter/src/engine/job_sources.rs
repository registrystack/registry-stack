// SPDX-License-Identifier: Apache-2.0

//! The engine-side sources block of the operator runtime config
//! (`products/adapter/CONCEPT.md` sections 10.2 and 17.2) over the
//! endpoint bindings core owns
//! (`registry_adapter_core::AdapterEndpointBindings`): the environment
//! state of the governed-ingestion sources, which no endpoint binding
//! can carry. The facade reader
//! (`registry_adapter_core::AdapterRuntimeConfig`) refuses the block, so
//! a facade deployment accepts no job source state; the job compiler
//! reads the same document through [`JobRuntimeConfig`], whose bindings
//! core is the core-owned type and whose `sources` member this module
//! parses. The bindings core keeps its own unknown-key refusal, so a
//! facade member in a job document refuses exactly as the core reader
//! refuses it. Numeric bounds are reader-checked through the platform's
//! bounded types; every other shape rule is a `Deserialize` impl here,
//! value-free, so a malformed source binding refuses at the reader and
//! not at the first read.

use std::collections::BTreeMap;

use registry_adapter_core::{
    AdapterEndpointBindings, MAXIMUM_JOB_FIELD_BYTES, MAXIMUM_JOB_FILE_BYTES,
    MAXIMUM_JOB_ROWS_PER_PAGE, MAXIMUM_JOB_ROW_BYTES,
};
use registry_platform_yaml::{BoundedU64, LocalId, SecretReference};
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

/// The runtime config as the job compiler reads it: the core document
/// the facade reader accepts, plus the job-only `sources` block. The
/// core member is decoded from the same document with `sources` set
/// aside, so the bindings core's own unknown-key refusal stands: a
/// facade member in a job document refuses exactly as the facade reader
/// refuses it, and a facade load of the same file refuses the `sources`
/// member itself. The bindings core is
/// `registry_adapter_core::AdapterEndpointBindings`, the shape the
/// facade document sets aside with `AdapterRuntimeConfig::endpoint_bindings`.
#[derive(Debug)]
pub(crate) struct JobRuntimeConfig {
    pub(crate) core: AdapterEndpointBindings,
    /// The governed-ingestion source bindings. Absent, the deployment
    /// binds no job source; a pack whose source route reads one refuses
    /// at the job compile, never at the first read.
    pub(crate) sources: Option<JobSources>,
}

impl<'de> Deserialize<'de> for JobRuntimeConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The shared reader admits only the YAML subset that maps to
        // JSON, so this round trip loses nothing. The envelope members
        // are the reader's, checked before decoding, so they sit beside
        // `sources` in the set-aside.
        let document = serde_json::Value::deserialize(deserializer)?;
        let Some(members) = document.as_object() else {
            return Err(serde::de::Error::custom(
                "the runtime config is not a mapping",
            ));
        };
        let sources = members.get("sources").cloned();
        let mut core_members = members.clone();
        core_members.remove("sources");
        core_members.remove("apiVersion");
        core_members.remove("kind");
        let core = AdapterEndpointBindings::deserialize(serde_json::Value::Object(core_members))
            .map_err(|error| {
                serde::de::Error::custom(format!("the runtime bindings were refused: {error}"))
            })?;
        let sources = match sources {
            None => None,
            Some(sources) => {
                Some(JobSources::deserialize(sources).map_err(serde::de::Error::custom)?)
            }
        };
        Ok(Self { core, sources })
    }
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
#[serde(tag = "type", rename_all = "kebab-case")]
pub(crate) enum SourceTls {
    /// The platform trust roots, TLS required, no client certificate.
    #[default]
    #[serde(rename = "system-roots")]
    SystemRoots,
    /// One private CA bundle file beside the platform roots, the same
    /// shape a facade trust profile carries: a CA bundle is not a
    /// secret, so the member names a file.
    #[serde(rename = "ca-bundle")]
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
    /// port keeps).
    #[serde(default)]
    pub(crate) read_lock: Option<String>,
    /// The `changed` lock's timeout, in milliseconds (1 to 30000);
    /// camel-4.23.0's `readLockTimeout` field default of 10000. Refused
    /// beside any read lock but `changed`.
    #[serde(default)]
    pub(crate) read_lock_timeout_milliseconds: Option<BoundedU64<1, 30_000>>,
    /// The `changed` lock's space between its two checks, in
    /// milliseconds (100 to 5000); camel-4.23.0's
    /// `readLockCheckInterval` field default of 1000. Refused beside
    /// any read lock but `changed`.
    #[serde(default)]
    pub(crate) read_lock_check_interval_milliseconds: Option<BoundedU64<100, 5_000>>,
    /// The most candidates one read considers, Camel's
    /// `maxMessagesPerPoll` at a bounded default (Camel's field default
    /// of zero means no limit, which no bounded read can port; 500 is
    /// the recorded divergence, capped again by the profile's rows
    /// bound at the read).
    #[serde(default = "default_max_messages_per_poll")]
    pub(crate) max_messages_per_poll: u32,
}

fn default_max_messages_per_poll() -> u32 {
    500
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
        let changed = match self.read_lock.as_deref() {
            None | Some("none") => false,
            Some("changed") => true,
            Some(_) => {
                return Err("the file source readLock names neither none nor changed".to_owned())
            }
        };
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
        assert_eq!(source.max_messages_per_poll, 500);

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
        let unknown: FileSourceConfig = serde_json::from_str(
            r#"{ "directory": "/var/data", "namespace": "exports", "readLock": "rename" }"#,
        )
        .expect("the reader carries the members");
        assert!(unknown.read_lock().is_err(), "rename is not ported");
    }
}

#[cfg(test)]
mod loader_tests {
    use super::*;
    use registry_adapter_core::{ADAPTER_RUNTIME_API_VERSION, ADAPTER_RUNTIME_KIND};

    /// The job runtime config reads through the shared loader.
    #[test]
    fn the_loader_reads_the_job_runtime_config() {
        let loader = registry_platform_config::RuntimeConfigLoader::new(
            registry_platform_config::RuntimeEnvelope {
                api_version: ADAPTER_RUNTIME_API_VERSION,
                kind: ADAPTER_RUNTIME_KIND,
            },
        );
        let read = loader.parse_str::<JobRuntimeConfig>(
            r#"{
                "apiVersion": "id.registrystack.org/formats/adapter/runtime/v1alpha1",
                "kind": "AdapterRuntimeConfig",
                "id": "job-deployment",
                "endpoints": [],
                "allowedPrivateCidrs": ["10.0.0.0/8"]
            }"#,
            |_| None,
        );
        assert!(read.is_ok(), "{read:?}");
    }
}
