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
use registry_platform_config::{
    PrivateListenerConfig, RuntimeConfigLoader, RuntimeEnvelope, SecretProvidersConfig,
    SecretResolver, TlsTermination,
};
use registry_platform_yaml::{
    BoundedU32, BoundedU64, LocalId, SecretReference, UniqueIdList, UniqueList,
};
use serde::Deserialize;

use crate::rabbitmq_config::RabbitMqSourceConfig;
#[cfg(feature = "job-rabbitmq")]
pub use crate::rabbitmq_config::{RabbitMqSourceBinding, RabbitMqSourceTls};

/// A reader-bounded flat-name glob compiled once when runtime configuration
/// loads. Matching walks each candidate string in place without allocating.
#[derive(Clone, Debug)]
pub struct FlatGlob {
    tokens: std::sync::Arc<[FlatGlobToken]>,
}

#[derive(Clone, Copy, Debug)]
enum FlatGlobToken {
    Literal(char),
    One,
    Many,
}

impl FlatGlob {
    /// Compile the deliberately small `*`/`?` flat-name grammar.
    pub fn compile(pattern: &str) -> Result<Self, &'static str> {
        if pattern.is_empty()
            || pattern.len() > 1024
            || pattern.contains('/')
            || pattern.contains('\\')
            || pattern.chars().any(char::is_control)
        {
            return Err(
                "include must carry 1 to 1024 bytes of flat text without path separators or control characters",
            );
        }
        let mut tokens = Vec::with_capacity(pattern.chars().count());
        for character in pattern.chars() {
            let token = match character {
                '?' => FlatGlobToken::One,
                '*' => FlatGlobToken::Many,
                literal => FlatGlobToken::Literal(literal),
            };
            if matches!(token, FlatGlobToken::Many)
                && matches!(tokens.last(), Some(FlatGlobToken::Many))
            {
                continue;
            }
            tokens.push(token);
        }
        Ok(Self {
            tokens: tokens.into(),
        })
    }

    /// Match Unicode scalar values, with `*` spanning any run and `?`
    /// spanning exactly one scalar value.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        let (mut pattern, mut name_at) = (0_usize, 0_usize);
        let mut star = None::<usize>;
        let mut star_name_at = 0_usize;
        while name_at < name.len() {
            let Some(character) = name[name_at..].chars().next() else {
                return false;
            };
            let next_name_at = name_at + character.len_utf8();
            match self.tokens.get(pattern) {
                Some(FlatGlobToken::One) => {
                    pattern += 1;
                    name_at = next_name_at;
                }
                Some(FlatGlobToken::Literal(expected)) if *expected == character => {
                    pattern += 1;
                    name_at = next_name_at;
                }
                Some(FlatGlobToken::Many) => {
                    pattern += 1;
                    star = Some(pattern);
                    star_name_at = name_at;
                }
                _ => {
                    let Some(after_star) = star else {
                        return false;
                    };
                    let Some(character) = name[star_name_at..].chars().next() else {
                        return false;
                    };
                    star_name_at += character.len_utf8();
                    name_at = star_name_at;
                    pattern = after_star;
                }
            }
        }
        while matches!(self.tokens.get(pattern), Some(FlatGlobToken::Many)) {
            pattern += 1;
        }
        pattern == self.tokens.len()
    }
}

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

/// One source read as the pollEnrich aggregation boundary carries it. File,
/// SFTP, and RabbitMQ share only this page carrier; their decoders and
/// transports remain independently feature-gated.
#[cfg(any(feature = "job-file", feature = "job-rabbitmq"))]
pub(crate) struct SourceReadPage {
    /// The `{items, next}` page value.
    pub(crate) body: serde_json::Value,
    /// Malformed input records skipped by a decoder, when that profile permits
    /// skipping them.
    pub(crate) malformed_lines: u32,
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
    pub(crate) postgres: BTreeMap<String, std::sync::Arc<crate::component::postgres::PostgresPlan>>,
    /// The source clients the host registered beside the plans; the
    /// engine boundary carries no client of its own.
    #[cfg(feature = "job-postgres")]
    pub(crate) postgres_clients:
        BTreeMap<String, std::sync::Arc<dyn crate::component::postgres::PostgresSource>>,
    /// The selected route's owned PostgreSQL connection snapshots. The
    /// job host activates only these bindings and never re-reads the
    /// runtime path after compilation.
    #[cfg(feature = "job-postgres")]
    pub(crate) postgres_bindings: BTreeMap<String, PostgresSourceBinding>,
    /// The engine-side immutable RabbitMQ plans by pack endpoint id.
    #[cfg(feature = "job-rabbitmq")]
    pub(crate) rabbitmq: BTreeMap<String, std::sync::Arc<crate::component::rabbitmq::RabbitMqPlan>>,
    /// The RabbitMQ source clients the host registered beside the plans.
    #[cfg(feature = "job-rabbitmq")]
    pub(crate) rabbitmq_clients:
        BTreeMap<String, std::sync::Arc<dyn crate::component::rabbitmq::RabbitMqSource>>,
    /// The selected route's immutable RabbitMQ connection snapshots.
    #[cfg(feature = "job-rabbitmq")]
    pub(crate) rabbitmq_bindings: BTreeMap<String, RabbitMqSourceBinding>,
    /// The one source receipt a one-message RabbitMQ poll parks for this run.
    /// `run_job_page` always replaces this with a fresh empty slot, so two
    /// runs never share settlement state.
    #[cfg(feature = "job-rabbitmq")]
    pub(crate) rabbitmq_receipt:
        std::sync::Arc<std::sync::Mutex<Option<crate::component::rabbitmq::RabbitMqPageReceipt>>>,
    /// The engine-side immutable SFTP plans by pack endpoint id.
    #[cfg(feature = "job-sftp")]
    pub(crate) sftp: BTreeMap<String, std::sync::Arc<crate::component::sftp::SftpPlan>>,
    /// The read-only SFTP clients the job host registered beside the plans.
    #[cfg(feature = "job-sftp")]
    pub(crate) sftp_clients:
        BTreeMap<String, std::sync::Arc<dyn crate::component::sftp::SftpSource>>,
    /// The selected route's immutable SFTP connection snapshots.
    #[cfg(feature = "job-sftp")]
    pub(crate) sftp_bindings: BTreeMap<String, SftpSourceBinding>,
}

/// The runtime config as the job mode reads it: the endpoint bindings
/// core beside the job-only `sources` block and the job host's `store` and
/// `destinations` blocks. The document decodes as one typed mapping for
/// the engine-owned bindings, sources, and store, so a facade member in a
/// job document refuses at its exact pointer and position. Destination
/// bindings remain a host-owned typed seam outside the engine. The bindings core is
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
    /// references, read and checked here like every other engine-owned
    /// member and resolved by the host. Absent, the document configures
    /// no job store.
    pub store: Option<JobStoreConfig>,
    /// The job host's destination bindings, passed through raw and
    /// uninterpreted by the engine. Product clients stay in the host and are
    /// never carried into `JobProgram`.
    pub destinations: Option<serde_json::Value>,
    /// The shared secret providers every job-host capability uses. Omission
    /// preserves the existing environment-only runtime. A file reference is
    /// accepted only when this block enables the file provider explicitly.
    pub secret_providers: Option<SecretProvidersConfig>,
    /// The separate authenticated hook ingress. Absent, this job runtime opens
    /// no inbound socket.
    pub hook_ingress: Option<HookIngressConfig>,
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

    /// Build the one resolver every source, store, destination, and hook
    /// activation in this job host shares. The legacy omission is deliberately
    /// environment-only; file authority is always explicit in the document.
    pub fn secret_resolver(&self) -> Result<SecretResolver, registry_platform_config::SecretError> {
        match &self.secret_providers {
            Some(providers) => providers.resolver(),
            None => {
                SecretResolver::new([registry_platform_config::SecretProvider::Environment], "")
            }
        }
    }
}

/// The fixed hook-ingress listener and its per-source Basic-auth bindings.
/// The first served subset is loopback-only: production traffic arrives from
/// an operator-controlled TLS reverse proxy, while direct plaintext is limited
/// to the shared development-loopback posture.
#[derive(Debug)]
pub struct HookIngressConfig {
    pub listener: PrivateListenerConfig,
    pub sources: BTreeMap<LocalId, HookSourceConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HookIngressDocument {
    listener: PrivateListenerConfig,
    sources: BTreeMap<LocalId, HookSourceConfig>,
}

impl<'de> Deserialize<'de> for HookIngressConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let document = HookIngressDocument::deserialize(deserializer)?;
        if document.sources.is_empty() || document.sources.len() > 16 {
            return Err(serde::de::Error::custom(
                "hookIngress.sources must carry 1 to 16 source bindings",
            ));
        }
        if !document.listener.is_valid() || !document.listener.bind.ip().is_loopback() {
            return Err(serde::de::Error::custom(
                "hookIngress.listener must bind loopback under the declared TLS termination",
            ));
        }
        if document.listener.bind.socket_addr().port() == 0
            && document.listener.tls_termination != TlsTermination::DevelopmentLoopback
        {
            return Err(serde::de::Error::custom(
                "hookIngress.listener port 0 is limited to development-loopback",
            ));
        }
        if document
            .sources
            .values()
            .any(|source| source.burst.get() > source.requests_per_minute.get())
        {
            return Err(serde::de::Error::custom(
                "hookIngress source burst must not exceed requestsPerMinute",
            ));
        }
        Ok(Self {
            listener: document.listener,
            sources: document.sources,
        })
    }
}

/// One source's immutable Basic credential references and process-local rate
/// budget. Resolved credential bytes never enter this reader type.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookSourceConfig {
    pub username_ref: SecretReference,
    pub password_ref: SecretReference,
    pub requests_per_minute: BoundedU64<1, 60_000>,
    pub burst: BoundedU64<1, 1_000>,
}

/// The host-visible, owned connection snapshot of one reviewed PostgreSQL
/// source. Namespace and query state stay in the compiled engine plan; this
/// value carries only what the host needs to establish the dedicated pool.
#[cfg(feature = "job-postgres")]
#[derive(Clone, Debug)]
pub struct PostgresSourceBinding {
    /// The pack endpoint this source binds.
    pub endpoint: String,
    /// The source database host.
    pub host: String,
    /// The source database port.
    pub port: u16,
    /// The source database name.
    pub database: String,
    /// The dedicated source reader role.
    pub user: String,
    /// The password reference the host resolves.
    pub password_ref: SecretReference,
    /// The connection's fail-closed TLS posture.
    pub tls: PostgresSourceTls,
}

/// The TLS posture the host installs for one PostgreSQL source. Plaintext is
/// absent from production builds, so no runtime value can select it there.
#[cfg(feature = "job-postgres")]
#[derive(Clone, Debug)]
pub enum PostgresSourceTls {
    /// TLS required with the platform's native roots.
    SystemRoots,
    /// TLS required with one bounded process-local CA bundle.
    CaBundle {
        /// The process-local bounded PEM bundle file.
        ca_bundle_file: String,
    },
    /// Plaintext to a loopback disposable database in the PostgreSQL suite.
    #[cfg(feature = "postgres-test")]
    Plaintext,
}

/// The host-visible immutable binding of one SFTP source. The engine keeps
/// source selection and decoding; the job host alone receives connection and
/// credential state.
#[cfg(feature = "job-sftp")]
#[derive(Clone, Debug)]
pub struct SftpSourceBinding {
    /// The pack endpoint this source binds.
    pub endpoint: String,
    /// The fixed SSH origin.
    pub host: String,
    /// The fixed SSH port.
    pub port: u16,
    /// The SSH account used only for this source.
    pub user: String,
    /// The normalized absolute POSIX directory no read may leave.
    /// The dedicated read-only account must also be confined to this tree by
    /// server-side authorization; SFTP v3 client path checks are not atomic.
    pub base_directory: String,
    /// The complete OpenSSH public key pinned for the server.
    pub pinned_host_key: String,
    /// The only client credential the connection may use.
    pub credential: SftpCredentialBinding,
    /// The maximum entries retained or inspected across one listing.
    pub maximum_listing_entries: u32,
    /// The immutable engine-side selection and completion rules the host
    /// enforces again at the transport boundary.
    pub plan: crate::component::sftp::SftpPlan,
}

/// One explicit SSH credential reference. No agent, forwarding, default key,
/// or ambient credential form exists.
#[cfg(feature = "job-sftp")]
#[derive(Clone, Debug)]
pub enum SftpCredentialBinding {
    /// Password authentication through one secret reference.
    Password { password_ref: SecretReference },
    /// Public-key authentication through one private-key reference and an
    /// optional passphrase reference.
    PrivateKey {
        private_key_ref: SecretReference,
        passphrase_ref: Option<SecretReference>,
    },
}

/// The job runtime document as the reader decodes it. Every engine-owned
/// member is typed so an undeclared member at any such depth keeps the
/// shared reader's code, pointer, line, and column. Destination bindings
/// are passed to the job host, which owns their product-specific clients
/// and validates their closed variants before activation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JobRuntimeDocument {
    id: LocalId,
    endpoints: UniqueIdList<EndpointBinding>,
    #[serde(default)]
    outbound_tls: Option<OutboundTls>,
    /// A listener-free job with no private destination needs no private
    /// range. The facade retains the nonempty policy on its own runtime
    /// document.
    #[serde(default)]
    allowed_private_cidrs: UniqueList<Cidr>,
    #[serde(default)]
    sources: Option<JobSources>,
    #[serde(default)]
    store: Option<JobStoreConfig>,
    #[serde(default)]
    destinations: Option<serde_json::Value>,
    #[serde(default)]
    secret_providers: Option<SecretProvidersConfig>,
    #[serde(default)]
    hook_ingress: Option<HookIngressConfig>,
}

impl<'de> Deserialize<'de> for JobRuntimeConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let document = JobRuntimeDocument::deserialize(deserializer)?;
        if let Some(providers) = &document.secret_providers {
            providers.check().map_err(serde::de::Error::custom)?;
        }
        if let Some(ingress) = &document.hook_ingress {
            let default_providers = SecretProvidersConfig {
                file: None,
                environment: Some(registry_platform_config::EnvironmentSecretProviderConfig {}),
            };
            let providers = document
                .secret_providers
                .as_ref()
                .unwrap_or(&default_providers);
            for source in ingress.sources.values() {
                providers
                    .check_reference(
                        "hookIngress.sources.*.usernameRef",
                        source.username_ref.as_str(),
                    )
                    .map_err(serde::de::Error::custom)?;
                providers
                    .check_reference(
                        "hookIngress.sources.*.passwordRef",
                        source.password_ref.as_str(),
                    )
                    .map_err(serde::de::Error::custom)?;
            }
        }
        Ok(Self {
            core: AdapterEndpointBindings {
                id: document.id,
                endpoints: document.endpoints,
                outbound_tls: document.outbound_tls,
                allowed_private_cidrs: document.allowed_private_cidrs,
            },
            sources: document.sources,
            store: document.store,
            destinations: document.destinations,
            secret_providers: document.secret_providers,
            hook_ingress: document.hook_ingress,
        })
    }
}

/// The job store block of the job runtime config (`store:`): the item
/// table's single connection reference. The store runs migrations on the
/// same connection it serves from, so the block carries no separate
/// migration member. Secret references only, resolved by the job host,
/// never a URL in the document. The engine reads the block and never
/// connects.
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
    /// RabbitMQ sources, keyed by endpoint id. The pure shape is parsed even
    /// without a broker connection; the host alone resolves its credential.
    #[serde(default, deserialize_with = "local_rabbitmq_keys")]
    pub(crate) rabbitmq: BTreeMap<String, RabbitMqSourceConfig>,
    /// The read-only SFTP sources, keyed by endpoint id. The shape is parsed
    /// even when the feature is absent, so an unavailable source refuses at
    /// compile rather than as an unknown operator member.
    #[serde(default, deserialize_with = "local_sftp_keys")]
    pub(crate) sftp: BTreeMap<String, SftpSourceConfig>,
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

fn local_rabbitmq_keys<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, RabbitMqSourceConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map = BTreeMap::<LocalId, RabbitMqSourceConfig>::deserialize(deserializer)?;
    Ok(map
        .into_iter()
        .map(|(key, value)| (key.into_string(), value))
        .collect())
}

fn local_sftp_keys<'de, D>(deserializer: D) -> Result<BTreeMap<String, SftpSourceConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map = BTreeMap::<LocalId, SftpSourceConfig>::deserialize(deserializer)?;
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

#[cfg(feature = "job-postgres")]
impl PostgresSourceConfig {
    pub(crate) fn host_binding(&self, endpoint: &str) -> PostgresSourceBinding {
        let tls = match &self.tls {
            SourceTls::SystemRoots => PostgresSourceTls::SystemRoots,
            SourceTls::CaBundle { ca_bundle_file } => PostgresSourceTls::CaBundle {
                ca_bundle_file: ca_bundle_file.clone(),
            },
            #[cfg(feature = "postgres-test")]
            SourceTls::Plaintext => PostgresSourceTls::Plaintext,
        };
        PostgresSourceBinding {
            endpoint: endpoint.to_owned(),
            host: self.host.clone(),
            port: u16::try_from(self.port.get())
                .expect("the runtime reader bounds a PostgreSQL port to u16"),
            database: self.database.clone(),
            user: self.user.clone(),
            password_ref: self.password_ref.clone(),
            tls,
        }
    }
}

fn default_postgres_port() -> BoundedU64<1, 65_535> {
    BoundedU64::new(5_432).expect("5432 is inside the bound")
}

/// The runtime binding of one read-only SFTP source. It is closed and
/// reader-checked before the host opens a socket or resolves a credential.
#[cfg_attr(not(feature = "job-sftp"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SftpSourceConfig {
    #[serde(deserialize_with = "bounded_sftp_text")]
    host: String,
    #[serde(default = "default_sftp_port")]
    port: BoundedU64<1, 65_535>,
    #[serde(deserialize_with = "bounded_sftp_text")]
    user: String,
    #[serde(deserialize_with = "absolute_sftp_directory")]
    base_directory: String,
    #[serde(deserialize_with = "bounded_sftp_key")]
    pinned_host_key: String,
    credential: SftpCredentialConfig,
    #[serde(deserialize_with = "bounded_sftp_text")]
    namespace: String,
    #[serde(default, deserialize_with = "flat_include")]
    include: Option<FlatGlob>,
    completion: SftpCompletionConfig,
    #[serde(default = "default_maximum_sftp_listing_entries")]
    maximum_listing_entries: BoundedU32<1, 10_000>,
}

#[cfg_attr(not(feature = "job-sftp"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum SftpCredentialConfig {
    Password {
        password_ref: SecretReference,
    },
    PrivateKey {
        private_key_ref: SecretReference,
        #[serde(default)]
        passphrase_ref: Option<SecretReference>,
    },
}

#[cfg_attr(not(feature = "job-sftp"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum SftpCompletionConfig {
    DoneFile {
        #[serde(deserialize_with = "required_sftp_done_file_name")]
        name: DoneFileName,
    },
    CompletedName {
        #[serde(deserialize_with = "required_true")]
        producer_atomic_handover: bool,
    },
}

fn default_sftp_port() -> BoundedU64<1, 65_535> {
    BoundedU64::new(22).expect("22 is inside the bound")
}

fn default_maximum_sftp_listing_entries() -> BoundedU32<1, 10_000> {
    BoundedU32::new(500).expect("500 is inside the bound")
}

fn bounded_sftp_text<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    if text.is_empty() || text.len() > 1024 || text.chars().any(char::is_control) {
        return Err(serde::de::Error::custom(
            "the SFTP member must carry 1 to 1024 bytes of text without control characters",
        ));
    }
    Ok(text)
}

fn bounded_sftp_key<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    if text.is_empty() || text.len() > 16 * 1024 || text.chars().any(char::is_control) {
        return Err(serde::de::Error::custom(
            "pinnedHostKey must carry one bounded OpenSSH public key",
        ));
    }
    Ok(text)
}

fn absolute_sftp_directory<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let directory = bounded_sftp_text(deserializer)?;
    if !directory.starts_with('/')
        || directory.contains('\\')
        || (directory != "/"
            && directory
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || matches!(part, "." | "..")))
        || (directory.len() > 1 && directory.ends_with('/'))
    {
        return Err(serde::de::Error::custom(
            "baseDirectory must be a normalized absolute POSIX directory",
        ));
    }
    Ok(directory)
}

fn required_true<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = bool::deserialize(deserializer)?;
    if !value {
        return Err(serde::de::Error::custom(
            "producerAtomicHandover must be true for completed-name readiness",
        ));
    }
    Ok(value)
}

fn required_sftp_done_file_name<'de, D>(deserializer: D) -> Result<DoneFileName, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let name = done_file_name(deserializer)?
        .ok_or_else(|| serde::de::Error::custom("the done-file completion name must be present"))?;
    let invalid = match &name {
        DoneFileName::Literal(literal) => {
            literal.len() > 1024
                || literal.starts_with('.')
                || literal.chars().any(char::is_control)
        }
        DoneFileName::Placeholder { prefix, suffix } => {
            prefix
                .len()
                .checked_add(suffix.len())
                .is_none_or(|fixed| fixed > 1023)
                || prefix.starts_with('.')
                || prefix.chars().chain(suffix.chars()).any(char::is_control)
        }
    };
    if invalid {
        return Err(serde::de::Error::custom(
            "the SFTP done-file name must produce one bounded visible flat name",
        ));
    }
    Ok(name)
}

#[cfg(feature = "job-sftp")]
impl SftpSourceConfig {
    pub(crate) fn host_binding(&self, endpoint: &str) -> SftpSourceBinding {
        let completion = match &self.completion {
            SftpCompletionConfig::DoneFile { name } => {
                crate::component::sftp::SftpCompletion::DoneFile {
                    pattern: name.clone(),
                }
            }
            SftpCompletionConfig::CompletedName {
                producer_atomic_handover,
            } => {
                debug_assert!(*producer_atomic_handover);
                crate::component::sftp::SftpCompletion::CompletedName
            }
        };
        let plan = crate::component::sftp::SftpPlan {
            namespace: self.namespace.clone(),
            include: self.include.clone(),
            completion,
            maximum_listing_entries: self.maximum_listing_entries.get(),
        };
        let credential = match &self.credential {
            SftpCredentialConfig::Password { password_ref } => SftpCredentialBinding::Password {
                password_ref: password_ref.clone(),
            },
            SftpCredentialConfig::PrivateKey {
                private_key_ref,
                passphrase_ref,
            } => SftpCredentialBinding::PrivateKey {
                private_key_ref: private_key_ref.clone(),
                passphrase_ref: passphrase_ref.clone(),
            },
        };
        SftpSourceBinding {
            endpoint: endpoint.to_owned(),
            host: self.host.clone(),
            port: u16::try_from(self.port.get()).expect("the reader bounds the SFTP port"),
            user: self.user.clone(),
            base_directory: self.base_directory.clone(),
            pinned_host_key: self.pinned_host_key.clone(),
            credential,
            maximum_listing_entries: self.maximum_listing_entries.get(),
            plan,
        }
    }
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
    pub(crate) include: Option<FlatGlob>,
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
pub enum DoneFileName {
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
fn flat_include<'de, D>(deserializer: D) -> Result<Option<FlatGlob>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let pattern = Option::<String>::deserialize(deserializer)?;
    pattern
        .map(|pattern| FlatGlob::compile(&pattern).map_err(serde::de::Error::custom))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_ingress_reads_closed_basic_bindings_and_shared_secret_providers() {
        let document = r#"{
            "id": "job-deployment",
            "endpoints": [],
            "secretProviders": {
                "environment": {},
                "file": { "root": "/run/secrets/adapter-job" }
            },
            "hookIngress": {
                "listener": {
                    "bind": "127.0.0.1:8091",
                    "tlsTermination": "operator-controlled-upstream",
                    "networkExposure": "private-address"
                },
                "sources": {
                    "kobo-submissions": {
                        "usernameRef": "secret:file/kobo-hook-username",
                        "passwordRef": "secret:env/KOBO_HOOK_PASSWORD",
                        "requestsPerMinute": 60,
                        "burst": 10
                    }
                }
            }
        }"#;

        let runtime: JobRuntimeConfig = serde_json::from_str(document).expect("hook runtime reads");
        let providers = runtime
            .secret_providers
            .as_ref()
            .expect("the shared secret provider block reads");
        assert!(providers.environment.is_some());
        assert_eq!(
            providers.file.as_ref().expect("the file provider").root,
            std::path::Path::new("/run/secrets/adapter-job")
        );
        let ingress = runtime.hook_ingress.expect("the hook ingress block reads");
        assert_eq!(ingress.listener.bind.socket_addr().port(), 8091);
        let source = ingress
            .sources
            .get(&"kobo-submissions".parse().expect("a local id"))
            .expect("the source binding");
        assert_eq!(source.requests_per_minute.get(), 60);
        assert_eq!(source.burst.get(), 10);
        assert_eq!(
            source.username_ref.as_str(),
            "secret:file/kobo-hook-username"
        );
        assert_eq!(
            source.password_ref.as_str(),
            "secret:env/KOBO_HOOK_PASSWORD"
        );
    }

    #[test]
    fn hook_ingress_refuses_empty_unbounded_and_nonloopback_shapes() {
        let runtime = |hook_ingress: &str| {
            format!(
                r#"{{
                    "id": "job-deployment",
                    "endpoints": [],
                    "hookIngress": {hook_ingress}
                }}"#
            )
        };
        for refused in [
            r#"{
                "listener": {
                    "bind": "127.0.0.1:8091",
                    "tlsTermination": "operator-controlled-upstream"
                },
                "sources": {}
            }"#,
            r#"{
                "listener": {
                    "bind": "127.0.0.1:8091",
                    "tlsTermination": "operator-controlled-upstream"
                },
                "sources": {
                    "kobo": {
                        "usernameRef": "secret:env/U",
                        "passwordRef": "secret:env/P",
                        "requestsPerMinute": 10,
                        "burst": 11
                    }
                }
            }"#,
            r#"{
                "listener": {
                    "bind": "10.0.0.2:8091",
                    "tlsTermination": "operator-controlled-upstream"
                },
                "sources": {
                    "kobo": {
                        "usernameRef": "secret:env/U",
                        "passwordRef": "secret:env/P",
                        "requestsPerMinute": 10,
                        "burst": 1
                    }
                }
            }"#,
        ] {
            assert!(
                serde_json::from_str::<JobRuntimeConfig>(&runtime(refused)).is_err(),
                "the hook ingress shape must refuse: {refused}"
            );
        }
    }

    #[test]
    fn hook_ingress_refuses_unknown_members_at_each_owned_depth() {
        let base = r#"{
            "id": "job-deployment",
            "endpoints": [],
            "hookIngress": {
                "listener": {
                    "bind": "127.0.0.1:8091",
                    "tlsTermination": "operator-controlled-upstream"
                },
                "sources": {
                    "kobo": {
                        "usernameRef": "secret:env/U",
                        "passwordRef": "secret:env/P",
                        "requestsPerMinute": 10,
                        "burst": 1,
                        "unknownCredentialMode": true
                    }
                }
            }
        }"#;
        assert!(serde_json::from_str::<JobRuntimeConfig>(base).is_err());
    }

    #[test]
    fn flat_glob_collapses_duplicate_stars_once_at_load() {
        let glob = FlatGlob::compile("***résumé-??**.csv").expect("bounded flat glob");
        assert_eq!(
            glob.tokens
                .iter()
                .filter(|token| matches!(token, FlatGlobToken::Many))
                .count(),
            2
        );
        assert!(glob.matches("résumé-東京.csv"));
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

    /// The job host's store block sits beside the engine's members and
    /// reads under the same member discipline: an undeclared store
    /// member refuses. Destination bindings remain a host-owned typed
    /// seam outside the route engine.
    #[test]
    fn the_store_reads_typed_while_destinations_remain_host_owned() {
        let with_store = r#"{
                "id": "job-deployment",
                "endpoints": [],
                "sources": { "file": {} },
                "store": { "runtimeUrlRef": "secret:env/JOB_DB" },
                "destinations": {
                    "registry": {
                        "type": "host-owned",
                        "a_member_only_the_host_knows": true
                    }
                }
            }"#;
        let read: JobRuntimeConfig =
            serde_json::from_str(with_store).expect("the store block reads");
        assert!(read.sources.is_some(), "the sources block still reads");
        let store = read.store.expect("the store block reads typed");
        assert!(!store.test_only_plaintext);
        assert!(store.trusted_root_certificate_ref.is_none());
        assert!(
            read.core.allowed_private_cidrs.is_empty(),
            "a listener-free job with no network endpoint keeps an empty allowlist"
        );
        assert_eq!(
            read.destinations
                .as_ref()
                .and_then(|value| value.get("registry"))
                .and_then(|value| value.get("type"))
                .and_then(serde_json::Value::as_str),
            Some("host-owned")
        );
        let undeclared_store_member = r#"{
                "id": "job-deployment",
                "endpoints": [],
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

    fn document(extra: &str) -> String {
        format!(
            r#"apiVersion: {ADAPTER_JOB_RUNTIME_API_VERSION}
kind: {ADAPTER_JOB_RUNTIME_KIND}
id: job-deployment
endpoints: []
{extra}"#
        )
    }

    /// The job runtime config reads through the shared loader.
    #[test]
    fn the_loader_reads_the_job_runtime_config() {
        let loader = registry_platform_config::RuntimeConfigLoader::new(
            registry_platform_config::RuntimeEnvelope {
                api_version: ADAPTER_JOB_RUNTIME_API_VERSION,
                kind: ADAPTER_JOB_RUNTIME_KIND,
            },
        );
        let read = loader.parse_str::<JobRuntimeConfig>(&document(""), |_| None);
        assert!(read.is_ok(), "{read:?}");
    }

    /// An undeclared member refuses at every engine-owned depth with the
    /// reader's own code, pointer, and source position.
    #[test]
    fn an_undeclared_member_refuses_with_its_pointer_at_every_depth() {
        let loader = registry_platform_config::RuntimeConfigLoader::new(
            registry_platform_config::RuntimeEnvelope {
                api_version: ADAPTER_JOB_RUNTIME_API_VERSION,
                kind: ADAPTER_JOB_RUNTIME_KIND,
            },
        );
        for (text, pointer, line) in [
            (document("conformanceFirst: 1\n"), "/conformanceFirst", 5),
            (
                document("store:\n  runtimeUrlRef: secret:env/JOB_DB\n  conformanceUnknown: 1\n"),
                "/store/conformanceUnknown",
                7,
            ),
        ] {
            let refused = loader
                .parse_str::<JobRuntimeConfig>(&text, |_| None)
                .expect_err("an undeclared member refuses");
            assert!(
                refused.diagnostics().iter().any(|diagnostic| {
                    diagnostic.code == "config.unknown-key"
                        && diagnostic.path == pointer
                        && diagnostic.source.as_ref().and_then(|source| source.line) == Some(line)
                }),
                "{pointer}: {:?}",
                refused.diagnostics()
            );
        }
    }

    /// The job and facade runtime documents are two formats: the job
    /// loader refuses the facade envelope, and the facade envelope
    /// refuses a job document, so neither schema describes the other's
    /// shape.
    #[test]
    fn the_job_and_facade_envelopes_refuse_each_other() {
        let job = registry_platform_config::RuntimeConfigLoader::new(
            registry_platform_config::RuntimeEnvelope {
                api_version: ADAPTER_JOB_RUNTIME_API_VERSION,
                kind: ADAPTER_JOB_RUNTIME_KIND,
            },
        );
        let facade_document = format!(
            "apiVersion: {ADAPTER_RUNTIME_API_VERSION}\nkind: {ADAPTER_RUNTIME_KIND}\nid: job-deployment\nendpoints: []\n"
        );
        assert!(
            job.parse_str::<JobRuntimeConfig>(&facade_document, |_| None)
                .is_err(),
            "the job loader refuses the facade envelope"
        );
        let facade = registry_platform_config::RuntimeConfigLoader::new(
            registry_platform_config::RuntimeEnvelope {
                api_version: ADAPTER_RUNTIME_API_VERSION,
                kind: ADAPTER_RUNTIME_KIND,
            },
        );
        assert!(
            facade
                .parse_str::<serde_json::Value>(&document(""), |_| None)
                .is_err(),
            "the facade envelope refuses a job document"
        );
    }
}
