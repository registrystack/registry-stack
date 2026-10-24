// SPDX-License-Identifier: Apache-2.0

use std::{
    fs,
    io::{self, IsTerminal as _, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::{Args, Subcommand};
use registry_platform_config::{
    AuthoredExpressions, EnvironmentSecretProviderConfig, FileSecretProviderConfig,
    SecretProvidersConfig, SecretReference,
};
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::client::{
    valid_resource_uri, validate_requested_scopes, PrivateKeyJwt, PrivateKeyJwtConfig,
};
use registry_platform_yaml::{
    ApiVersion, Diagnostic, EnvelopeRule, Expect, ExternalId, FormatSpec, LocalId, Reader, Report,
    Source, UniqueList, Url as ConfigUrl,
};
use serde::{ser::SerializeMap as _, Deserialize, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::{
    api::read_trusted_root_certificates, project::find_project, ApiError, LocalConnection,
};

pub const CONNECTIONS_API_VERSION: &str =
    "id.registrystack.org/formats/platform/cli-connections/v1alpha1";
pub const CONNECTIONS_KIND: &str = "PlatformCliConnections";
pub const CONNECTION_CHECK_REPORT_API_VERSION: &str =
    "id.registrystack.org/formats/platform/cli-connection-check-report/v1alpha1";
pub const CONNECTION_CHECK_REPORT_KIND: &str = "PlatformCliConnectionCheckReport";
const FORMAT: FormatSpec = FormatSpec {
    kind: CONNECTIONS_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(CONNECTIONS_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// Saved-connection management shared by product adapters.
#[derive(Clone, Debug, Subcommand)]
pub enum ConnectionCommand {
    /// Save one product-scoped remote connection.
    Add(Box<AddConnectionArgs>),
    /// List saved connections for this product.
    List(ListConnectionArgs),
    /// Show one saved connection without resolving its credential.
    Show(ShowConnectionArgs),
    /// Select a saved connection for one exact product project.
    Use(UseConnectionArgs),
    /// Check one saved-connections file without resolving credentials or contacting endpoints.
    Check(CheckConnectionArgs),
}

#[derive(Clone, Debug, Args)]
pub struct AddConnectionArgs {
    /// Local connection name used by `--connection` and project selections.
    pub name: String,
    /// API service base URL. Prompted when omitted in an interactive terminal.
    #[arg(long)]
    pub url: Option<String>,
    /// PEM certificate authority bundle for a private-institution endpoint.
    #[arg(long)]
    pub ca_file: Option<PathBuf>,
    /// Casework only: stable caller access profile applied to its profile headers.
    #[arg(long)]
    pub access_profile: Option<String>,
    /// Save a connection that sends no Authorization header.
    #[arg(long)]
    pub anonymous: bool,
    /// File holding a bearer token. The configuration stores only a secret reference.
    #[arg(long, conflicts_with_all = ["anonymous", "token_env", "private_key_jwt"])]
    pub token_file: Option<PathBuf>,
    /// Environment variable holding a bearer token. The configuration stores only a secret reference.
    #[arg(long, conflicts_with_all = ["anonymous", "token_file", "private_key_jwt"])]
    pub token_env: Option<String>,
    /// Acquire renewable bearer tokens with OAuth private_key_jwt.
    #[arg(long, conflicts_with_all = ["anonymous", "token_file", "token_env"])]
    pub private_key_jwt: bool,
    /// OAuth token endpoint used for private_key_jwt authentication.
    #[arg(long, requires = "private_key_jwt")]
    pub token_endpoint: Option<String>,
    /// OAuth client identifier registered at the token endpoint.
    #[arg(long, requires = "private_key_jwt")]
    pub client_id: Option<String>,
    /// Owner-only file containing the private client JWK.
    #[arg(long, requires = "private_key_jwt")]
    pub private_key_file: Option<PathBuf>,
    /// OAuth scope to request; repeat the option for multiple scopes.
    #[arg(long, requires = "private_key_jwt")]
    pub scope: Vec<String>,
    /// Optional RFC 8707 resource indicator for the requested token.
    #[arg(long, requires = "private_key_jwt")]
    pub resource: Option<String>,
    /// Optional assertion audience; defaults to the token endpoint.
    #[arg(long, requires = "private_key_jwt")]
    pub assertion_audience: Option<String>,
}

#[derive(Clone, Debug, Default, Args)]
pub struct ListConnectionArgs {}

#[derive(Clone, Debug, Args)]
pub struct ShowConnectionArgs {
    /// Local name of the connection to show.
    pub name: String,
}

#[derive(Clone, Debug, Args)]
pub struct UseConnectionArgs {
    /// Local name of the connection to select for the project.
    pub name: String,
    /// Project directory, or a descendant from which the exact product root is found.
    #[arg(long)]
    pub project: Option<PathBuf>,
}

#[derive(Clone, Debug, Args)]
pub struct CheckConnectionArgs {
    /// Saved-connections YAML file to validate offline.
    #[arg(long)]
    pub file: PathBuf,
    /// Exit 1 when the check reports a warning.
    #[arg(long)]
    pub deny_warnings: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Store {
    api_version: String,
    kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    connections: Vec<SavedConnection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    selections: Vec<ProjectSelection>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            api_version: CONNECTIONS_API_VERSION.to_owned(),
            kind: CONNECTIONS_KIND.to_owned(),
            connections: Vec::new(),
            selections: Vec::new(),
        }
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedConnection {
    /// Product command whose remote endpoint this connection names.
    product: LocalId,
    /// Local name used by `--connection` and project selections.
    name: LocalId,
    /// API service base URL. HTTPS is required except for a loopback development endpoint.
    base_url: ConfigUrl,
    /// Stable caller profile for product-owned access-profile headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_profile: Option<LocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trusted_root_certificates_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret_providers: Option<SecretProvidersConfig>,
    auth: SavedAuth,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "schema",
    schemars(!remote, tag = "type", rename_all = "kebab-case", rename_all_fields = "camelCase")
)]
#[derive(Clone, Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum SavedAuth {
    Anonymous {},
    Bearer {
        token_ref: SecretReference,
    },
    PrivateKeyJwt {
        /// OAuth token endpoint. HTTPS is required except for a loopback development endpoint.
        token_endpoint: ConfigUrl,
        /// Client identifier registered by the authorization server.
        client_id: ExternalId,
        private_key_ref: SecretReference,
        #[serde(default, skip_serializing_if = "unique_list_is_empty")]
        /// OAuth scope identifiers requested as a set.
        scopes: UniqueList<ExternalId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        /// Optional RFC 8707 resource identifier.
        resource: Option<ExternalId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        /// Optional private_key_jwt audience; the token endpoint is the default.
        assertion_audience: Option<ExternalId>,
    },
}

registry_platform_yaml::tagged_union!(SavedAuth);

#[cfg(feature = "schema")]
fn unique_list_is_empty<T>(items: &UniqueList<T>) -> bool {
    items.is_empty()
}

impl Serialize for SavedAuth {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Anonymous {} => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("type", "anonymous")?;
                map.end()
            }
            Self::Bearer { token_ref } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("type", "bearer")?;
                map.serialize_entry("tokenRef", token_ref)?;
                map.end()
            }
            Self::PrivateKeyJwt {
                token_endpoint,
                client_id,
                private_key_ref,
                scopes,
                resource,
                assertion_audience,
            } => {
                let mut count = 4;
                count += usize::from(!scopes.is_empty());
                count += usize::from(resource.is_some());
                count += usize::from(assertion_audience.is_some());
                let mut map = serializer.serialize_map(Some(count))?;
                map.serialize_entry("type", "private-key-jwt")?;
                map.serialize_entry("tokenEndpoint", token_endpoint)?;
                map.serialize_entry("clientId", client_id)?;
                map.serialize_entry("privateKeyRef", private_key_ref)?;
                if !scopes.is_empty() {
                    map.serialize_entry("scopes", scopes)?;
                }
                if let Some(resource) = resource {
                    map.serialize_entry("resource", resource)?;
                }
                if let Some(audience) = assertion_audience {
                    map.serialize_entry("assertionAudience", audience)?;
                }
                map.end()
            }
        }
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectSelection {
    product: LocalId,
    project: PathBuf,
    connection: LocalId,
}

pub fn run_connection(product: &str, command: ConnectionCommand) -> Result<(), ApiError> {
    if let ConnectionCommand::Check(args) = &command {
        return check_connections_file(&args.file);
    }
    let path = store_path()?;
    match command {
        ConnectionCommand::Add(args) => add(&path, product, *args),
        ConnectionCommand::List(_) => list(&path, product),
        ConnectionCommand::Show(args) => show(&path, product, &args.name),
        ConnectionCommand::Use(args) => select(&path, product, args),
        ConnectionCommand::Check(_) => unreachable!("the check command returned above"),
    }
}

/// Validate a saved-connections document without reading secrets or contacting endpoints.
pub fn check_connections_file(path: &Path) -> Result<(), ApiError> {
    let report = inspect_connections_file(path)?;
    if report.has_errors() {
        Err(ApiError::Configuration(format!(
            "the saved connections file is invalid:\n{}",
            report.render_human()
        )))
    } else {
        Ok(())
    }
}

/// Check one saved-connections file and retain structured, positioned diagnostics.
pub fn inspect_connections_file(path: &Path) -> Result<Report, ApiError> {
    let bytes = fs::read(path).map_err(|_| ApiError::Io)?;
    let mut report = match decode_store(path, &bytes) {
        Ok(store) => match validate_store(store) {
            Ok(_) => Report::default(),
            Err(error) => {
                let mut diagnostic = Diagnostic::error(
                    "platform.cli-connections.invalid",
                    "",
                    error.to_string(),
                    "Correct the saved connection settings, then run connection check again.",
                );
                diagnostic.artifact = Some(CONNECTIONS_KIND.to_owned());
                diagnostic.source = Some(Source {
                    file: path.display().to_string(),
                    line: None,
                    column: None,
                });
                Report::new(vec![diagnostic])
            }
        },
        Err(report) => report,
    };
    report.set_files_checked(1);
    Ok(report)
}

/// Render one offline connection check using the shared typed report envelope.
pub fn run_connection_check(
    path: &Path,
    json_output: bool,
    deny_warnings: bool,
) -> Result<u8, ApiError> {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    write_connection_check(path, json_output, deny_warnings, &mut stdout, &mut stderr)
}

fn write_connection_check(
    path: &Path,
    json_output: bool,
    deny_warnings: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<u8, ApiError> {
    let (report, exit) = match inspect_connections_file(path) {
        Ok(report) => {
            let exit =
                u8::from(report.has_errors() || (deny_warnings && report.warning_count() > 0));
            (report, exit)
        }
        Err(ApiError::Io) if json_output => {
            let mut diagnostic = Diagnostic::error(
                "platform.cli-connections.unavailable",
                "",
                "the saved connections file could not be read",
                "Check that the file exists and is readable, then run connection check again.",
            );
            diagnostic.artifact = Some(CONNECTIONS_KIND.to_owned());
            diagnostic.source = Some(Source {
                file: path.display().to_string(),
                line: None,
                column: None,
            });
            let mut report = Report::new(vec![diagnostic]);
            report.set_files_checked(0);
            (report, 3)
        }
        Err(error) => return Err(error),
    };
    if json_output {
        let envelope = PlatformCliConnectionCheckReport {
            ok: exit == 0,
            command: "connection check".to_owned(),
            status: match exit {
                0 => ConnectionCheckStatus::Complete,
                3 => ConnectionCheckStatus::OperationalFailure,
                _ => ConnectionCheckStatus::DomainRefusal,
            },
            api_version: CONNECTION_CHECK_REPORT_API_VERSION.to_owned(),
            kind: CONNECTION_CHECK_REPORT_KIND.to_owned(),
            files_checked: report.files_checked().unwrap_or(0),
            errors: report.error_count(),
            warnings: report.warning_count(),
            diagnostics: report.diagnostics().to_vec(),
        };
        serde_json::to_writer_pretty(&mut *stdout, &envelope).map_err(|_| ApiError::Io)?;
        writeln!(stdout).map_err(|_| ApiError::Io)?;
    } else if exit == 0 {
        write!(stdout, "{}", report.render_human()).map_err(|_| ApiError::Io)?;
    } else {
        write!(
            stderr,
            "connection check refused the input.\n{}",
            report.render_human()
        )
        .map_err(|_| ApiError::Io)?;
    }
    Ok(exit)
}

/// Machine-readable result of `connection check` for every product adapter.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlatformCliConnectionCheckReport {
    ok: bool,
    command: String,
    status: ConnectionCheckStatus,
    api_version: String,
    kind: String,
    files_checked: usize,
    errors: usize,
    warnings: usize,
    diagnostics: Vec<Diagnostic>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ConnectionCheckStatus {
    Complete,
    DomainRefusal,
    OperationalFailure,
}

pub(crate) fn resolve_saved(
    product: &str,
    named: Option<&str>,
    project: Option<&Path>,
) -> Result<LocalConnection, ApiError> {
    let path = store_path()?;
    let store = read_store(&path)?;
    let name = match named {
        Some(name) => name,
        None => {
            let start = project
                .map(Path::to_path_buf)
                .map_or_else(std::env::current_dir, Ok)
                .map_err(|_| ApiError::Io)?;
            let root = find_project(product, &start)?;
            store
                .selections
                .iter()
                .find(|selected| selected.product.as_str() == product && selected.project == root)
                .map(|selected| selected.connection.as_str())
                .ok_or_else(|| {
                    ApiError::Configuration(
                        "no remote connection is selected for this project; name --connection, --client, or --url"
                            .to_owned(),
                    )
                })?
        }
    };
    let saved = store
        .connections
        .iter()
        .find(|saved| saved.product.as_str() == product && saved.name.as_str() == name)
        .ok_or_else(|| ApiError::Configuration("the named connection does not exist".to_owned()))?;
    materialize(&store, saved)
}

fn add(path: &Path, product: &str, mut args: AddConnectionArgs) -> Result<(), ApiError> {
    validate_name(&args.name)?;
    if product != "casework" && args.access_profile.is_some() {
        return Err(ApiError::Usage(
            "--access-profile is supported only by the casework product adapter".to_owned(),
        ));
    }
    if args.url.is_none() && io::stdin().is_terminal() {
        args.url = Some(prompt("Endpoint URL: ")?);
    }
    let base_url = args.url.take().ok_or_else(|| {
        ApiError::Usage("connection add requires --url outside a terminal".to_owned())
    })?;
    LocalConnection::anonymous(base_url.clone())?;
    if !args.anonymous
        && args.token_file.is_none()
        && args.token_env.is_none()
        && !args.private_key_jwt
        && io::stdin().is_terminal()
    {
        match prompt("Authentication [anonymous, bearer-file, bearer-env, private-key-jwt]: ")?
            .as_str()
        {
            "anonymous" => args.anonymous = true,
            "bearer-file" => args.token_file = Some(PathBuf::from(prompt("Bearer token file: ")?)),
            "bearer-env" => args.token_env = Some(prompt("Bearer token environment variable: ")?),
            "private-key-jwt" => args.private_key_jwt = true,
            _ => {
                return Err(ApiError::Usage(
                    "the authentication choice is not recognized".to_owned(),
                ))
            }
        }
    }
    if product == "casework" && args.access_profile.is_none() && io::stdin().is_terminal() {
        args.access_profile = prompt_optional("Casework access profile (optional): ")?;
    }
    let mut store = read_store(path)?;
    if store
        .connections
        .iter()
        .any(|saved| saved.product.as_str() == product && saved.name.as_str() == args.name)
    {
        return Err(ApiError::Usage(
            "a connection with this name already exists for the product".to_owned(),
        ));
    }
    let name = args.name.clone();
    let access_profile = args
        .access_profile
        .as_deref()
        .map(|profile| local_id(profile, "--access-profile"))
        .transpose()?;
    let trusted_root_certificates_file = args
        .ca_file
        .as_deref()
        .map(canonical_public_file)
        .transpose()?;
    let mut secret_providers = None;
    let auth = saved_auth(&mut secret_providers, args)?;
    store.connections.push(SavedConnection {
        product: local_id(product, "product")?,
        name: local_id(&name, "connection NAME")?,
        base_url: config_url(base_url, "--url")?,
        access_profile,
        trusted_root_certificates_file,
        secret_providers,
        auth,
    });
    store
        .connections
        .sort_by(|left, right| (&left.product, &left.name).cmp(&(&right.product, &right.name)));
    write_store(path, &store)
}

fn saved_auth(
    secret_providers: &mut Option<SecretProvidersConfig>,
    mut args: AddConnectionArgs,
) -> Result<SavedAuth, ApiError> {
    let choices = usize::from(args.anonymous)
        + usize::from(args.token_file.is_some())
        + usize::from(args.token_env.is_some())
        + usize::from(args.private_key_jwt);
    if choices != 1 {
        return Err(ApiError::Usage(
            "choose exactly one of --anonymous, --token-file, --token-env, or --private-key-jwt"
                .to_owned(),
        ));
    }
    if args.anonymous {
        return Ok(SavedAuth::Anonymous {});
    }
    if let Some(path) = args.token_file {
        let token_ref = file_reference(secret_providers, &path)?;
        resolve_secret(secret_providers.as_ref(), &token_ref)?;
        return Ok(SavedAuth::Bearer { token_ref });
    }
    if let Some(name) = args.token_env {
        let token_ref = environment_reference(secret_providers, &name)?;
        return Ok(SavedAuth::Bearer { token_ref });
    }
    if io::stdin().is_terminal() {
        prompt_missing(&mut args.token_endpoint, "Token endpoint: ")?;
        prompt_missing(&mut args.client_id, "OAuth client ID: ")?;
        if args.private_key_file.is_none() {
            args.private_key_file = Some(PathBuf::from(prompt("Private JWK file: ")?));
        }
        prompt_optional_missing(
            &mut args.assertion_audience,
            "Assertion audience (optional; blank uses token endpoint): ",
        )?;
        prompt_optional_missing(&mut args.resource, "OAuth resource indicator (optional): ")?;
        if args.scope.is_empty() {
            if let Some(scopes) = prompt_optional("OAuth scopes (optional; space-separated): ")? {
                args.scope = scopes.split_whitespace().map(str::to_owned).collect();
            }
        }
    }
    let token_endpoint = args
        .token_endpoint
        .ok_or_else(|| ApiError::Usage("--private-key-jwt requires --token-endpoint".to_owned()))?;
    let client_id = args
        .client_id
        .ok_or_else(|| ApiError::Usage("--private-key-jwt requires --client-id".to_owned()))?;
    let private_key_ref = file_reference(
        secret_providers,
        &args.private_key_file.ok_or_else(|| {
            ApiError::Usage("--private-key-jwt requires --private-key-file".to_owned())
        })?,
    )?;
    let private_key = resolve_secret(secret_providers.as_ref(), &private_key_ref)?;
    let private_key_json = Zeroizing::new(
        String::from_utf8(private_key.expose_secret().to_vec())
            .map_err(|_| ApiError::Credential)?,
    );
    PrivateJwk::parse(private_key_json.as_str()).map_err(|_| ApiError::Credential)?;
    let token_endpoint = config_url(token_endpoint, "--token-endpoint")?;
    let client_id = external_id(client_id, "--client-id")?;
    let scopes = args
        .scope
        .into_iter()
        .map(|scope| external_id(scope, "--scope"))
        .collect::<Result<Vec<_>, _>>()?;
    let scopes = UniqueList::new(scopes)
        .map_err(|_| ApiError::Usage("--scope values must not repeat".to_owned()))?;
    let resource = args
        .resource
        .map(|value| external_id(value, "--resource"))
        .transpose()?;
    let assertion_audience = args
        .assertion_audience
        .map(|value| external_id(value, "--assertion-audience"))
        .transpose()?;
    PrivateKeyJwtConfig::check_identity(
        &token_endpoint.to_url(),
        client_id.as_str(),
        assertion_audience.as_ref().map(ExternalId::as_str),
    )
    .map_err(|_| ApiError::Usage("the private_key_jwt identity settings are invalid".to_owned()))?;
    validate_oauth_request(&scopes, resource.as_ref()).map_err(ApiError::Usage)?;
    Ok(SavedAuth::PrivateKeyJwt {
        token_endpoint,
        client_id,
        private_key_ref,
        scopes,
        resource,
        assertion_audience,
    })
}

fn list(path: &Path, product: &str) -> Result<(), ApiError> {
    let store = read_store(path)?;
    for saved in store
        .connections
        .iter()
        .filter(|saved| saved.product.as_str() == product)
    {
        println!(
            "{}\t{}\t{}",
            saved.name,
            auth_name(&saved.auth),
            saved.base_url
        );
    }
    Ok(())
}

fn show(path: &Path, product: &str, name: &str) -> Result<(), ApiError> {
    let store = read_store(path)?;
    let saved = store
        .connections
        .iter()
        .find(|saved| saved.product.as_str() == product && saved.name.as_str() == name)
        .ok_or_else(|| ApiError::Configuration("the named connection does not exist".to_owned()))?;
    println!("name: {}", saved.name);
    println!("product: {}", saved.product);
    println!("url: {}", saved.base_url);
    println!("authentication: {}", auth_name(&saved.auth));
    if let Some(profile) = &saved.access_profile {
        println!("access profile: {profile}");
    }
    Ok(())
}

fn select(path: &Path, product: &str, args: UseConnectionArgs) -> Result<(), ApiError> {
    let mut store = read_store(path)?;
    if !store
        .connections
        .iter()
        .any(|saved| saved.product.as_str() == product && saved.name.as_str() == args.name)
    {
        return Err(ApiError::Configuration(
            "the named connection does not exist".to_owned(),
        ));
    }
    let start = args
        .project
        .map_or_else(std::env::current_dir, Ok)
        .map_err(|_| ApiError::Io)?;
    let project = find_project(product, &start)?;
    store
        .selections
        .retain(|selected| !(selected.product.as_str() == product && selected.project == project));
    store.selections.push(ProjectSelection {
        product: local_id(product, "product")?,
        project,
        connection: local_id(&args.name, "connection NAME")?,
    });
    store.selections.sort_by(|left, right| {
        (&left.product, &left.project).cmp(&(&right.product, &right.project))
    });
    write_store(path, &store)
}

fn materialize(_store: &Store, saved: &SavedConnection) -> Result<LocalConnection, ApiError> {
    let trusted_root_certificates = saved
        .trusted_root_certificates_file
        .as_deref()
        .map(read_trusted_root_certificates)
        .transpose()?;
    let connection = match &saved.auth {
        SavedAuth::Anonymous {} => LocalConnection::anonymous(saved.base_url.as_str().to_owned()),
        SavedAuth::Bearer { token_ref } => {
            let secret = secret(saved, token_ref)?;
            let mut token = String::from_utf8(secret.expose_secret().to_vec())
                .map_err(|_| ApiError::Credential)?;
            trim_one_line_ending(&mut token);
            LocalConnection::bearer(saved.base_url.as_str().to_owned(), Zeroizing::new(token))
        }
        SavedAuth::PrivateKeyJwt {
            token_endpoint,
            client_id,
            private_key_ref,
            scopes,
            resource,
            assertion_audience,
        } => {
            let secret = secret(saved, private_key_ref)?;
            let json = Zeroizing::new(
                String::from_utf8(secret.expose_secret().to_vec())
                    .map_err(|_| ApiError::Credential)?,
            );
            let key = PrivateJwk::parse(json.as_str()).map_err(|_| ApiError::Credential)?;
            let endpoint = token_endpoint.to_url();
            let mut config = PrivateKeyJwtConfig::new(endpoint, client_id.as_str(), key);
            if !scopes.is_empty() {
                config = config.with_scopes(scopes.iter().map(|scope| scope.as_str().to_owned()));
            }
            if let Some(resource) = resource {
                config = config.with_resource(resource.as_str());
            }
            if let Some(audience) = assertion_audience {
                config = config.with_audience(audience.as_str());
            }
            if let Some(pem) = &trusted_root_certificates {
                config = config.with_trusted_root_certificates(pem.clone());
            }
            let provider = PrivateKeyJwt::new(config).map_err(|_| ApiError::Credential)?;
            LocalConnection::with_token_provider(
                saved.base_url.as_str().to_owned(),
                Arc::new(provider),
            )
        }
    }?;
    let connection = connection.with_access_profile(
        saved
            .access_profile
            .as_ref()
            .map(|profile| profile.as_str().to_owned()),
    );
    match trusted_root_certificates {
        Some(pem) => connection.with_trusted_root_certificates(pem),
        None => Ok(connection),
    }
}

fn secret(
    saved: &SavedConnection,
    reference: &SecretReference,
) -> Result<registry_platform_config::ProtectedSecret, ApiError> {
    resolve_secret(saved.secret_providers.as_ref(), reference)
}

fn resolve_secret(
    providers: Option<&SecretProvidersConfig>,
    reference: &SecretReference,
) -> Result<registry_platform_config::ProtectedSecret, ApiError> {
    let providers = providers.ok_or(ApiError::Credential)?;
    providers.check().map_err(|_| ApiError::Credential)?;
    providers
        .check_reference("auth", reference.as_str())
        .map_err(|_| ApiError::Credential)?;
    providers
        .resolver()
        .and_then(|resolver| resolver.resolve_reference(reference))
        .map_err(|_| ApiError::Credential)
}

fn file_reference(
    secret_providers: &mut Option<SecretProvidersConfig>,
    path: &Path,
) -> Result<SecretReference, ApiError> {
    let canonical = path
        .canonicalize()
        .map_err(|_| ApiError::Usage("the named secret file is unavailable".to_owned()))?;
    let root = canonical
        .parent()
        .ok_or_else(|| ApiError::Usage("the named secret file has no parent directory".to_owned()))?
        .to_path_buf();
    let name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ApiError::Usage("the secret file name is not supported".to_owned()))?;
    let reference = SecretReference::parse(format!("secret:file/{name}")).map_err(|_| {
        ApiError::Usage(
            "the secret file name must use lowercase letters, digits, '.', '_' or '-'".to_owned(),
        )
    })?;
    let providers = secret_providers.get_or_insert_with(SecretProvidersConfig::default);
    match &providers.file {
        Some(existing) if existing.root != root => {
            return Err(ApiError::Usage(
                "saved file credentials must share the configured secretProviders.file.root"
                    .to_owned(),
            ));
        }
        Some(_) => {}
        None => providers.file = Some(FileSecretProviderConfig { root }),
    }
    Ok(reference)
}

fn canonical_public_file(path: &Path) -> Result<PathBuf, ApiError> {
    let canonical = path
        .canonicalize()
        .map_err(|_| ApiError::Usage("the named CA file is unavailable".to_owned()))?;
    if canonical.is_file() {
        Ok(canonical)
    } else {
        Err(ApiError::Usage(
            "the named CA path must be a regular file".to_owned(),
        ))
    }
}

fn environment_reference(
    secret_providers: &mut Option<SecretProvidersConfig>,
    name: &str,
) -> Result<SecretReference, ApiError> {
    let reference = SecretReference::parse(format!("secret:env/{name}")).map_err(|_| {
        ApiError::Usage("the token environment variable name is invalid".to_owned())
    })?;
    secret_providers
        .get_or_insert_with(SecretProvidersConfig::default)
        .environment = Some(EnvironmentSecretProviderConfig::default());
    Ok(reference)
}

fn auth_name(auth: &SavedAuth) -> &'static str {
    match auth {
        SavedAuth::Anonymous {} => "anonymous",
        SavedAuth::Bearer { .. } => "bearer",
        SavedAuth::PrivateKeyJwt { .. } => "private_key_jwt",
    }
}

fn validate_name(name: &str) -> Result<(), ApiError> {
    local_id(name, "connection NAME").map(drop)
}

fn local_id(value: impl Into<String>, field: &str) -> Result<LocalId, ApiError> {
    LocalId::new(value).map_err(|_| {
        ApiError::Usage(format!(
            "{field} must start with a lowercase letter and contain at most 64 lowercase letters, digits, '_' or '-'"
        ))
    })
}

fn external_id(value: impl Into<String>, field: &str) -> Result<ExternalId, ApiError> {
    ExternalId::new(value).map_err(|_| {
        ApiError::Usage(format!(
            "{field} must contain 1 to 512 characters and no control characters"
        ))
    })
}

fn config_url(value: impl Into<String>, field: &str) -> Result<ConfigUrl, ApiError> {
    ConfigUrl::new(value)
        .map_err(|_| ApiError::Usage(format!("{field} must be a valid absolute HTTP(S) URL")))
}

fn validate_oauth_request(
    scopes: &UniqueList<ExternalId>,
    resource: Option<&ExternalId>,
) -> Result<(), String> {
    if !scopes.is_empty() {
        let values = scopes
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect::<Vec<_>>();
        validate_requested_scopes(&values)
            .map_err(|_| "the OAuth scopes are invalid".to_owned())?;
    }
    if resource.is_some_and(|resource| !valid_resource_uri(resource.as_str())) {
        return Err(
            "the OAuth resource must be an absolute URI without a fragment or userinfo".to_owned(),
        );
    }
    Ok(())
}

fn store_path() -> Result<PathBuf, ApiError> {
    if let Some(root) = std::env::var_os("XDG_CONFIG_HOME") {
        if root.is_empty() {
            return Err(ApiError::Configuration(
                "XDG_CONFIG_HOME must not be empty".to_owned(),
            ));
        }
        return Ok(PathBuf::from(root).join("registrystack/connections.yaml"));
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| ApiError::Configuration("HOME is unavailable".to_owned()))?;
    Ok(PathBuf::from(home).join(".config/registrystack/connections.yaml"))
}

fn read_store(path: &Path) -> Result<Store, ApiError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Store::default()),
        Err(_) => return Err(ApiError::Io),
    };
    let decoded = decode_store(path, &bytes).map_err(|report| {
            ApiError::Configuration(format!(
                "the saved connections file is invalid:\n{report}\nFix the reported field, then run the command again"
            ))
        })?;
    validate_store(decoded)
}

fn decode_store(path: &Path, bytes: &[u8]) -> Result<Store, Report> {
    let mut expressions = AuthoredExpressions;
    Reader::new(path.display().to_string())
        .with_hook(&mut expressions)
        .decode::<Store>(bytes, &Expect::one(&FORMAT))
        .map(|decoded| decoded.value)
}

fn validate_store(store: Store) -> Result<Store, ApiError> {
    for saved in &store.connections {
        LocalConnection::anonymous(saved.base_url.as_str().to_owned())?;
        if saved.product.as_str() != "casework" && saved.access_profile.is_some() {
            return Err(ApiError::Configuration(
                "accessProfile is supported only on casework connections".to_owned(),
            ));
        }
        if saved
            .trusted_root_certificates_file
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(ApiError::Configuration(
                "trustedRootCertificatesFile must be an absolute path".to_owned(),
            ));
        }
        if let Some(providers) = &saved.secret_providers {
            providers.check().map_err(|_| {
                ApiError::Configuration("a connection's secretProviders is invalid".to_owned())
            })?;
        }
        match &saved.auth {
            SavedAuth::Anonymous {} => {}
            SavedAuth::Bearer { token_ref } => validate_reference(saved, token_ref)?,
            SavedAuth::PrivateKeyJwt {
                token_endpoint,
                client_id,
                private_key_ref,
                scopes,
                resource,
                assertion_audience,
            } => {
                validate_reference(saved, private_key_ref)?;
                PrivateKeyJwtConfig::check_identity(
                    &token_endpoint.to_url(),
                    client_id.as_str(),
                    assertion_audience.as_ref().map(ExternalId::as_str),
                )
                .map_err(|_| {
                    ApiError::Configuration("saved private_key_jwt settings are invalid".to_owned())
                })?;
                validate_oauth_request(scopes, resource.as_ref()).map_err(|message| {
                    ApiError::Configuration(format!(
                        "saved private_key_jwt settings are invalid: {message}"
                    ))
                })?;
            }
        }
    }
    for (index, left) in store.connections.iter().enumerate() {
        if store.connections[index + 1..]
            .iter()
            .any(|right| left.product == right.product && left.name == right.name)
        {
            return Err(ApiError::Configuration(
                "saved connection names must be unique within a product".to_owned(),
            ));
        }
    }
    for selection in &store.selections {
        if !selection.project.is_absolute() {
            return Err(ApiError::Configuration(
                "a project selection's project must be an absolute path".to_owned(),
            ));
        }
        if !store
            .connections
            .iter()
            .any(|saved| saved.product == selection.product && saved.name == selection.connection)
        {
            return Err(ApiError::Configuration(
                "a project selection must name a matching saved connection in the same product"
                    .to_owned(),
            ));
        }
    }
    for (index, left) in store.selections.iter().enumerate() {
        if store.selections[index + 1..]
            .iter()
            .any(|right| left.product == right.product && left.project == right.project)
        {
            return Err(ApiError::Configuration(
                "project selections must be unique within a product".to_owned(),
            ));
        }
    }
    Ok(store)
}

fn validate_reference(
    saved: &SavedConnection,
    reference: &SecretReference,
) -> Result<(), ApiError> {
    saved
        .secret_providers
        .as_ref()
        .ok_or_else(|| {
            ApiError::Configuration("a credential has no secretProviders block".to_owned())
        })?
        .check_reference("auth", reference.as_str())
        .map_err(|_| ApiError::Configuration("a credential reference is invalid".to_owned()))
}

fn write_store(path: &Path, store: &Store) -> Result<(), ApiError> {
    let parent = path.parent().ok_or(ApiError::Io)?;
    fs::create_dir_all(parent).map_err(|_| ApiError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|_| ApiError::Io)?;
    }
    let document = serde_norway::to_string(store).map_err(|_| ApiError::Io)?;
    let temporary = parent.join(format!(".connections.yaml.{}.tmp", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|_| ApiError::Io)?;
    file.write_all(document.as_bytes())
        .map_err(|_| ApiError::Io)?;
    file.sync_all().map_err(|_| ApiError::Io)?;
    fs::rename(&temporary, path).map_err(|_| ApiError::Io)?;
    Ok(())
}

fn prompt(label: &str) -> Result<String, ApiError> {
    eprint!("{label}");
    io::stderr().flush().map_err(|_| ApiError::Io)?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|_| ApiError::Io)?;
    while answer.ends_with(['\r', '\n']) {
        answer.pop();
    }
    if answer.is_empty() {
        Err(ApiError::Usage(
            "an interactive answer must not be empty".to_owned(),
        ))
    } else {
        Ok(answer)
    }
}

fn prompt_missing(value: &mut Option<String>, label: &str) -> Result<(), ApiError> {
    if value.is_none() {
        *value = Some(prompt(label)?);
    }
    Ok(())
}

fn prompt_optional(label: &str) -> Result<Option<String>, ApiError> {
    eprint!("{label}");
    io::stderr().flush().map_err(|_| ApiError::Io)?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|_| ApiError::Io)?;
    while answer.ends_with(['\r', '\n']) {
        answer.pop();
    }
    Ok((!answer.is_empty()).then_some(answer))
}

fn prompt_optional_missing(value: &mut Option<String>, label: &str) -> Result<(), ApiError> {
    if value.is_none() {
        *value = prompt_optional(label)?;
    }
    Ok(())
}

fn trim_one_line_ending(value: &mut String) {
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') {
        value.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn anonymous(name: &str, product: &str) -> SavedConnection {
        SavedConnection {
            product: LocalId::new(product).unwrap(),
            name: LocalId::new(name).unwrap(),
            base_url: ConfigUrl::new("https://registry.example.test/prefix").unwrap(),
            access_profile: None,
            trusted_root_certificates_file: None,
            secret_providers: None,
            auth: SavedAuth::Anonymous {},
        }
    }

    #[test]
    fn strict_reader_refuses_unknown_members() {
        let yaml = format!(
            "apiVersion: {CONNECTIONS_API_VERSION}\nkind: {CONNECTIONS_KIND}\nconnections: []\nunexpected: true\n"
        );
        let error = Reader::new("connections.yaml")
            .decode::<Store>(yaml.as_bytes(), &Expect::one(&FORMAT))
            .unwrap_err();
        assert!(error
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "config.unknown-key"));
    }

    #[test]
    fn structured_connection_check_preserves_diagnostics_without_scalar_values() {
        let temporary = TempDir::new().unwrap();
        let valid = temporary.path().join("valid.yaml");
        fs::write(
            &valid,
            format!(
                "apiVersion: {CONNECTIONS_API_VERSION}\nkind: {CONNECTIONS_KIND}\nconnections: []\n"
            ),
        )
        .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = write_connection_check(&valid, true, false, &mut stdout, &mut stderr).unwrap();
        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["command"], "connection check");
        assert_eq!(report["status"], "complete");
        assert_eq!(report["apiVersion"], CONNECTION_CHECK_REPORT_API_VERSION);
        assert_eq!(report["kind"], CONNECTION_CHECK_REPORT_KIND);
        assert_eq!(report["filesChecked"], 1);
        assert_eq!(report["diagnostics"], serde_json::json!([]));

        let invalid = temporary.path().join("invalid.yaml");
        fs::write(
            &invalid,
            format!(
                "apiVersion: {CONNECTIONS_API_VERSION}\nkind: {CONNECTIONS_KIND}\nconnections: []\nunexpected: scalar-value-canary\n"
            ),
        )
        .unwrap();
        stdout.clear();
        let exit = write_connection_check(&invalid, true, false, &mut stdout, &mut stderr).unwrap();
        assert_eq!(exit, 1);
        assert!(stderr.is_empty());
        let text = std::str::from_utf8(&stdout).unwrap();
        assert!(!text.contains("scalar-value-canary"));
        let report: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(report["ok"], false);
        assert_eq!(report["status"], "domain-refusal");
        assert_eq!(report["errors"], 1);
        assert_eq!(report["diagnostics"][0]["code"], "config.unknown-key");
        assert_eq!(
            report["diagnostics"][0]["source"]["file"],
            invalid.display().to_string()
        );

        let missing = temporary.path().join("missing-file-name-canary.yaml");
        stdout.clear();
        let exit = write_connection_check(&missing, true, false, &mut stdout, &mut stderr).unwrap();
        assert_eq!(exit, 3);
        assert!(stderr.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(report["ok"], false);
        assert_eq!(report["status"], "operational-failure");
        assert_eq!(report["filesChecked"], 0);
        assert_eq!(report["errors"], 1);
        assert_eq!(
            report["diagnostics"][0]["code"],
            "platform.cli-connections.unavailable"
        );
        assert_eq!(
            report["diagnostics"][0]["source"]["file"],
            missing.display().to_string()
        );
        assert!(!report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("missing-file-name-canary"));

        let human_error =
            write_connection_check(&missing, false, false, &mut Vec::new(), &mut Vec::new())
                .expect_err("human output preserves the existing operational error path");
        assert_eq!(human_error.exit_code(), 3);
    }

    #[test]
    fn selection_is_scoped_by_product_and_canonical_project() {
        let project = PathBuf::from("/tmp/project");
        let store = Store {
            connections: vec![anonymous("production", "breg")],
            selections: vec![ProjectSelection {
                product: LocalId::new("breg").unwrap(),
                project: project.clone(),
                connection: LocalId::new("production").unwrap(),
            }],
            ..Store::default()
        };
        assert!(store.selections.iter().any(|selected| {
            selected.product.as_str() == "breg" && selected.project == project
        }));
        assert!(!store
            .selections
            .iter()
            .any(|selected| selected.product.as_str() == "casework"));
        assert!(validate_store(store).is_ok());
    }

    #[test]
    fn selections_require_absolute_unique_projects_and_matching_connections() {
        let valid = Store {
            connections: vec![
                anonymous("production", "breg"),
                anonymous("review", "casework"),
            ],
            selections: vec![ProjectSelection {
                product: LocalId::new("breg").unwrap(),
                project: PathBuf::from("/srv/registries/businesses"),
                connection: LocalId::new("production").unwrap(),
            }],
            ..Store::default()
        };
        assert!(validate_store(valid.clone()).is_ok());

        let mut relative = valid.clone();
        relative.selections[0].project = PathBuf::from("registries/businesses");
        let error = validate_store(relative).unwrap_err();
        assert!(error.to_string().contains("absolute path"));

        let mut dangling = valid.clone();
        dangling.selections[0].connection = LocalId::new("missing").unwrap();
        let error = validate_store(dangling).unwrap_err();
        assert!(error.to_string().contains("matching saved connection"));

        let mut cross_product = valid.clone();
        cross_product.selections[0].connection = LocalId::new("review").unwrap();
        let error = validate_store(cross_product).unwrap_err();
        assert!(error.to_string().contains("matching saved connection"));

        let mut duplicate = valid;
        duplicate.selections.push(ProjectSelection {
            product: LocalId::new("breg").unwrap(),
            project: PathBuf::from("/srv/registries/businesses"),
            connection: LocalId::new("production").unwrap(),
        });
        let error = validate_store(duplicate).unwrap_err();
        assert!(error.to_string().contains("unique within a product"));
    }

    #[test]
    fn saved_bearer_configuration_contains_a_reference_not_the_value() {
        let temporary = TempDir::new().unwrap();
        let token = temporary.path().join("operator-token");
        fs::write(&token, "secret-canary-value").unwrap();
        let mut store = Store::default();
        let mut secret_providers = None;
        let token_ref = file_reference(&mut secret_providers, &token).unwrap();
        store.connections.push(SavedConnection {
            product: LocalId::new("breg").unwrap(),
            name: LocalId::new("production").unwrap(),
            base_url: ConfigUrl::new("https://registry.example.test").unwrap(),
            access_profile: None,
            trusted_root_certificates_file: None,
            secret_providers,
            auth: SavedAuth::Bearer { token_ref },
        });
        let yaml = serde_norway::to_string(&store).unwrap();
        assert!(yaml.contains("secret:file/operator-token"));
        assert!(!yaml.contains("secret-canary-value"));
    }

    #[test]
    fn file_credentials_are_scoped_per_connection() {
        let temporary = TempDir::new().unwrap();
        let staging = temporary.path().join("staging");
        let production = temporary.path().join("production");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&production).unwrap();
        let staging_token = staging.join("token");
        let production_token = production.join("token");
        fs::write(&staging_token, "staging").unwrap();
        fs::write(&production_token, "production").unwrap();

        let mut staging_providers = None;
        let staging_ref = file_reference(&mut staging_providers, &staging_token).unwrap();
        let mut production_providers = None;
        let production_ref = file_reference(&mut production_providers, &production_token).unwrap();
        let store = Store {
            connections: vec![
                SavedConnection {
                    product: LocalId::new("breg").unwrap(),
                    name: LocalId::new("staging").unwrap(),
                    base_url: ConfigUrl::new("https://staging.example.test").unwrap(),
                    access_profile: None,
                    trusted_root_certificates_file: None,
                    secret_providers: staging_providers,
                    auth: SavedAuth::Bearer {
                        token_ref: staging_ref,
                    },
                },
                SavedConnection {
                    product: LocalId::new("breg").unwrap(),
                    name: LocalId::new("production").unwrap(),
                    base_url: ConfigUrl::new("https://production.example.test").unwrap(),
                    access_profile: None,
                    trusted_root_certificates_file: None,
                    secret_providers: production_providers,
                    auth: SavedAuth::Bearer {
                        token_ref: production_ref,
                    },
                },
            ],
            ..Store::default()
        };
        validate_store(store).expect("different connection roots are independent");
    }

    #[test]
    fn duplicate_product_names_are_rejected() {
        let store = Store {
            connections: vec![
                anonymous("production", "breg"),
                anonymous("production", "breg"),
            ],
            ..Store::default()
        };
        assert!(validate_store(store).is_err());
    }
}
