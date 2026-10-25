// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt, fs,
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use clap::Args;
use http::{header, HeaderMap, HeaderName, HeaderValue, Method};
use registry_platform_httputil::{
    client::{read_failure_kind, send_failure_kind, ServiceBaseUrl, StaticToken, TokenProvider},
    read_bounded, OutboundClientBuilder, MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
};
use reqwest::StatusCode;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::{connection, project::find_project, ApiError};

const MAXIMUM_REQUEST_BYTES: u64 = 8 * 1024 * 1024;
const MAXIMUM_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const MAXIMUM_HEADER_FILE_BYTES: u64 = 64 * 1024;

/// Product-neutral arguments for `rstack <product> api PATH`.
#[derive(Clone, Args)]
pub struct ApiArgs {
    /// Relative API path. A leading slash is accepted without discarding a deployment prefix.
    pub path: String,
    /// Project directory, or a descendant from which the exact product root is found.
    #[arg(long)]
    pub project: Option<PathBuf>,
    /// Named local development client resolved by the product adapter.
    #[arg(long, conflicts_with_all = ["connection", "url"])]
    pub client: Option<String>,
    /// Named saved remote connection.
    #[arg(long, conflicts_with_all = ["client", "url"])]
    pub connection: Option<String>,
    /// Explicit service base URL for an advanced one-off request.
    #[arg(long, conflicts_with_all = ["client", "connection"])]
    pub url: Option<String>,
    /// Bearer credential file used only with `--url`.
    #[arg(long, requires = "url")]
    pub token_file: Option<PathBuf>,
    /// PEM certificate authority bundle for an explicit private-institution endpoint.
    #[arg(long, requires = "url")]
    pub ca_file: Option<PathBuf>,
    /// HTTP method. Defaults to GET, or POST when `--input` is present.
    #[arg(long)]
    pub method: Option<String>,
    /// Request body file, or `-` for standard input.
    #[arg(long)]
    pub input: Option<PathBuf>,
    /// Request header as `NAME: VALUE`; use `NAME: @FILE` for a value or `@FILE` for complete lines.
    #[arg(long = "header")]
    pub header: Vec<String>,
    /// Value of the HTTP Accept header.
    #[arg(long)]
    pub accept: Option<String>,
    /// Write response bytes to this file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Include the HTTP status and response headers before the response body.
    #[arg(long)]
    pub include: bool,
    /// Value of the Idempotency-Key header.
    #[arg(long)]
    pub idempotency_key: Option<String>,
    /// Literal HTTP If-Match value, including quotes when the endpoint requires them.
    #[arg(long)]
    pub if_match: Option<String>,
}

impl fmt::Debug for ApiArgs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiArgs")
            .field("has_path", &!self.path.is_empty())
            .field("project", &self.project)
            .field("client", &self.client)
            .field("connection", &self.connection)
            .field("has_url", &self.url.is_some())
            .field("token_file", &self.token_file)
            .field("has_ca_file", &self.ca_file.is_some())
            .field("method", &self.method)
            .field("input", &self.input)
            .field("header_count", &self.header.len())
            .field("has_accept", &self.accept.is_some())
            .field("output", &self.output)
            .field("include", &self.include)
            .field("has_idempotency_key", &self.idempotency_key.is_some())
            .field("has_if_match", &self.if_match.is_some())
            .finish()
    }
}

/// A validated local or remote API connection.
pub struct LocalConnection {
    base_url: ServiceBaseUrl,
    token_provider: Option<Arc<dyn TokenProvider>>,
    headers: HeaderMap,
    trusted_root_certificates: Option<Zeroizing<Vec<u8>>>,
    access_profile: Option<String>,
    reserved_headers: Vec<HeaderName>,
}

impl LocalConnection {
    pub fn bearer(base_url: String, token: Zeroizing<String>) -> Result<Self, ApiError> {
        let provider =
            StaticToken::new(token.as_str().to_owned()).map_err(|_| ApiError::Credential)?;
        Self::with_provider(base_url, Some(Arc::new(provider)))
    }

    pub fn anonymous(base_url: String) -> Result<Self, ApiError> {
        Self::with_provider(base_url, None)
    }

    pub fn with_header(
        mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, ApiError> {
        let name = parse_header_name(name.as_ref())?;
        if name == header::AUTHORIZATION || name == header::HOST {
            return Err(ApiError::Usage(
                "Authorization and Host are owned by the selected connection".to_owned(),
            ));
        }
        if self.headers.contains_key(&name) || self.reserved_headers.contains(&name) {
            return Err(ApiError::Usage(
                "a connection-owned header was supplied more than once".to_owned(),
            ));
        }
        let value = parse_header_value(value.as_ref())?;
        self.headers.insert(name.clone(), value);
        self.reserved_headers.push(name);
        Ok(self)
    }

    /// Trust exactly this bounded PEM certificate authority bundle for this connection.
    pub fn with_trusted_root_certificates(mut self, pem: Vec<u8>) -> Result<Self, ApiError> {
        if pem.is_empty() || pem.len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES {
            return Err(ApiError::Configuration(
                "the trusted certificate bundle is empty or exceeds its accepted size".to_owned(),
            ));
        }
        self.trusted_root_certificates = Some(Zeroizing::new(pem));
        Ok(self)
    }

    pub(crate) fn with_token_provider(
        base_url: String,
        token_provider: Arc<dyn TokenProvider>,
    ) -> Result<Self, ApiError> {
        Self::with_provider(base_url, Some(token_provider))
    }

    fn with_provider(
        base_url: String,
        token_provider: Option<Arc<dyn TokenProvider>>,
    ) -> Result<Self, ApiError> {
        let url = Url::parse(&base_url)
            .map_err(|_| ApiError::Configuration("the service base URL is invalid".to_owned()))?;
        let base_url = ServiceBaseUrl::new(url).map_err(|error| {
            ApiError::Configuration(format!("the service base URL is not usable: {error}"))
        })?;
        Ok(Self {
            base_url,
            token_provider,
            headers: HeaderMap::new(),
            trusted_root_certificates: None,
            access_profile: None,
            reserved_headers: Vec::new(),
        })
    }

    pub(crate) fn with_access_profile(mut self, profile: Option<String>) -> Self {
        self.access_profile = profile;
        self
    }

    fn apply_access_profile(mut self, header_names: &[&str]) -> Result<Self, ApiError> {
        let Some(profile) = self.access_profile.clone() else {
            return Ok(self);
        };
        if header_names.is_empty() {
            return Err(ApiError::Configuration(
                "the saved connection has an access profile, but this product adapter defines no profile headers"
                    .to_owned(),
            ));
        }
        for raw_name in header_names {
            let name = parse_header_name(raw_name)?;
            if name == header::AUTHORIZATION || name == header::HOST {
                return Err(ApiError::Configuration(
                    "a product adapter supplied an invalid access-profile header".to_owned(),
                ));
            }
            if self.headers.contains_key(&name) || self.reserved_headers.contains(&name) {
                return Err(ApiError::Configuration(
                    "a product adapter supplied a duplicate access-profile header".to_owned(),
                ));
            }
            self.headers
                .insert(name.clone(), parse_header_value(&profile)?);
            self.reserved_headers.push(name);
        }
        Ok(self)
    }
}

impl fmt::Debug for LocalConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalConnection")
            .field("base_url", &self.base_url)
            .field("authenticated", &self.token_provider.is_some())
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field(
                "has_trusted_root_certificates",
                &self.trusted_root_certificates.is_some(),
            )
            .field("has_access_profile", &self.access_profile.is_some())
            .finish()
    }
}

/// Resolve a connection, execute one bounded request, and write its raw response.
pub fn run_api(
    product: &str,
    args: ApiArgs,
    resolver: impl FnOnce(&Path, &str) -> Result<LocalConnection, String>,
) -> Result<(), ApiError> {
    run_api_with_profile_headers(product, args, resolver, &[])
}

/// Execute one request, applying a saved caller profile to the adapter-owned header names.
pub fn run_api_with_profile_headers(
    product: &str,
    args: ApiArgs,
    resolver: impl FnOnce(&Path, &str) -> Result<LocalConnection, String>,
    profile_headers: &[&str],
) -> Result<(), ApiError> {
    let connection =
        resolve_connection(product, &args, resolver)?.apply_access_profile(profile_headers)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ApiError::Exchange)?;
    runtime.block_on(execute(args, connection))
}

fn resolve_connection(
    product: &str,
    args: &ApiArgs,
    resolver: impl FnOnce(&Path, &str) -> Result<LocalConnection, String>,
) -> Result<LocalConnection, ApiError> {
    if let Some(client) = &args.client {
        let start = args
            .project
            .clone()
            .map_or_else(std::env::current_dir, Ok)
            .map_err(|_| ApiError::Io)?;
        let project = find_project(product, &start)?;
        return resolver(&project, client).map_err(ApiError::Configuration);
    }
    if let Some(url) = &args.url {
        let connection = match &args.token_file {
            Some(path) => LocalConnection::bearer(url.clone(), read_token_file(path)?),
            None => LocalConnection::anonymous(url.clone()),
        }?;
        return apply_ca_file(connection, args.ca_file.as_deref());
    }
    connection::resolve_saved(product, args.connection.as_deref(), args.project.as_deref())
}

async fn execute(args: ApiArgs, connection: LocalConnection) -> Result<(), ApiError> {
    let method = request_method(&args)?;
    let url = request_url(&connection.base_url, &args.path)?;
    let mut client_builder = OutboundClientBuilder::new()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("registry-stack-cli-api");
    if let Some(pem) = &connection.trusted_root_certificates {
        client_builder = client_builder.trusted_root_certificates(pem.as_slice().to_vec());
    }
    let client = client_builder
        .try_build()
        .map_err(|_| ApiError::Configuration("the HTTP client could not be built".to_owned()))?;
    let mut headers = connection.headers;
    append_cli_headers(
        &mut headers,
        &args,
        connection.token_provider.is_some(),
        &connection.reserved_headers,
    )?;
    if let Some(provider) = connection.token_provider {
        let token = provider
            .bearer_token()
            .await
            .map_err(|_| ApiError::Credential)?;
        headers.insert(header::AUTHORIZATION, token.authorization_header_value());
    }
    let mut request = client.request(method, url).headers(headers);
    if let Some(path) = &args.input {
        let body = read_input(path)?;
        request = request.body(body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| match send_failure_kind(&error) {
            registry_platform_httputil::client::TransportKind::Connect => ApiError::Connect,
            registry_platform_httputil::client::TransportKind::Timeout => ApiError::Timeout,
            _ => ApiError::Exchange,
        })?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let body = read_bounded(response, MAXIMUM_RESPONSE_BYTES)
        .await
        .map_err(|error| match read_failure_kind(&error) {
            registry_platform_httputil::client::TransportKind::ResponseTooLarge => {
                ApiError::ResponseTooLarge
            }
            registry_platform_httputil::client::TransportKind::Timeout => ApiError::Timeout,
            _ => ApiError::Exchange,
        })?;
    write_response(
        args.output.as_deref(),
        args.include,
        status,
        &response_headers,
        &body,
    )?;
    if status.is_success() {
        Ok(())
    } else {
        Err(ApiError::HttpStatus(status.as_u16()))
    }
}

pub(crate) fn apply_ca_file(
    connection: LocalConnection,
    path: Option<&Path>,
) -> Result<LocalConnection, ApiError> {
    match path {
        Some(path) => {
            connection.with_trusted_root_certificates(read_trusted_root_certificates(path)?)
        }
        None => Ok(connection),
    }
}

pub(crate) fn read_trusted_root_certificates(path: &Path) -> Result<Vec<u8>, ApiError> {
    read_bounded_file(
        path,
        u64::try_from(MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES)
            .map_err(|_| ApiError::Configuration("the CA bundle bound is invalid".to_owned()))?,
    )
}

fn request_method(args: &ApiArgs) -> Result<Method, ApiError> {
    match &args.method {
        Some(value) => Method::from_bytes(value.to_ascii_uppercase().as_bytes())
            .map_err(|_| ApiError::Usage("--method must be a valid HTTP method".to_owned())),
        None if args.input.is_some() => Ok(Method::POST),
        None => Ok(Method::GET),
    }
}

fn request_url(base: &ServiceBaseUrl, raw_path: &str) -> Result<Url, ApiError> {
    let path_only = raw_path.split('?').next().unwrap_or_default();
    let relative = path_only.trim_start_matches('/');
    let first_segment = relative.split('/').next().unwrap_or_default();
    if raw_path.is_empty()
        || raw_path.starts_with("//")
        || raw_path.contains('\\')
        || raw_path.contains('#')
        || first_segment.contains(':')
        || relative
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(ApiError::Usage(
            "PATH must contain relative API segments and may include a query".to_owned(),
        ));
    }
    let mut base_url = base.as_url().clone();
    if !base_url.path().ends_with('/') {
        let mut path = base_url.path().to_owned();
        path.push('/');
        base_url.set_path(&path);
    }
    let required_origin = base_url.origin();
    let required_prefix = base_url.path().to_owned();
    let joined = base_url
        .join(raw_path.trim_start_matches('/'))
        .map_err(|_| ApiError::Usage("PATH is not a valid relative API URL".to_owned()))?;
    if joined.origin() != required_origin || !joined.path().starts_with(&required_prefix) {
        return Err(ApiError::Usage(
            "PATH must stay within the selected endpoint and deployment prefix".to_owned(),
        ));
    }
    Ok(joined)
}

fn append_cli_headers(
    headers: &mut HeaderMap,
    args: &ApiArgs,
    automatic_authorization: bool,
    reserved_headers: &[HeaderName],
) -> Result<(), ApiError> {
    for raw in &args.header {
        if let Some(path) = raw.strip_prefix('@') {
            let complete = read_header_file(Path::new(path))?;
            if complete.is_empty() {
                return Err(ApiError::Usage(
                    "a complete header file must contain at least one NAME: VALUE line".to_owned(),
                ));
            }
            for line in complete.lines() {
                if line.is_empty() {
                    return Err(ApiError::Usage(
                        "a complete header file must not contain blank lines".to_owned(),
                    ));
                }
                append_raw_header(headers, line, automatic_authorization, reserved_headers)?;
            }
        } else {
            let (name, value) = raw.split_once(':').ok_or_else(|| {
                ApiError::Usage(
                    "--header must use NAME: VALUE or @FILE with complete header lines".to_owned(),
                )
            })?;
            let owned;
            let value = if let Some(path) = value.trim_start().strip_prefix('@') {
                owned = read_header_file(Path::new(path))?;
                owned.as_str()
            } else {
                value.trim_start()
            };
            append_header(
                headers,
                name,
                value,
                automatic_authorization,
                reserved_headers,
            )?;
        }
    }
    append_unique(headers, header::ACCEPT, args.accept.as_deref())?;
    append_unique(
        headers,
        HeaderName::from_static("idempotency-key"),
        args.idempotency_key.as_deref(),
    )?;
    append_unique(headers, header::IF_MATCH, args.if_match.as_deref())?;
    if args.input.is_some() && !headers.contains_key(header::CONTENT_TYPE) {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    Ok(())
}

fn append_raw_header(
    headers: &mut HeaderMap,
    raw: &str,
    automatic_authorization: bool,
    reserved_headers: &[HeaderName],
) -> Result<(), ApiError> {
    let (name, value) = raw.split_once(':').ok_or_else(|| {
        ApiError::Usage("a complete header file line must use NAME: VALUE".to_owned())
    })?;
    append_header(
        headers,
        name,
        value.trim_start(),
        automatic_authorization,
        reserved_headers,
    )
}

fn append_header(
    headers: &mut HeaderMap,
    name: &str,
    value: &str,
    automatic_authorization: bool,
    reserved_headers: &[HeaderName],
) -> Result<(), ApiError> {
    let name = parse_header_name(name.trim())?;
    if name == header::HOST {
        return Err(ApiError::Usage(
            "Host is owned by the selected connection".to_owned(),
        ));
    }
    if name == header::AUTHORIZATION && (automatic_authorization || headers.contains_key(&name)) {
        return Err(ApiError::Usage(
            "Authorization was supplied by more than one source".to_owned(),
        ));
    }
    if reserved_headers.contains(&name) {
        return Err(ApiError::Usage(format!(
            "{} is owned by the selected connection's access profile",
            name.as_str()
        )));
    }
    headers.append(name, parse_header_value(value)?);
    Ok(())
}

fn append_unique(
    headers: &mut HeaderMap,
    name: HeaderName,
    value: Option<&str>,
) -> Result<(), ApiError> {
    if let Some(value) = value {
        if headers.contains_key(&name) {
            return Err(ApiError::Usage(format!(
                "{} was supplied by more than one option",
                name.as_str()
            )));
        }
        headers.insert(name, parse_header_value(value)?);
    }
    Ok(())
}

fn parse_header_name(value: &str) -> Result<HeaderName, ApiError> {
    HeaderName::from_bytes(value.as_bytes())
        .map_err(|_| ApiError::Usage("a request header name is invalid".to_owned()))
}

fn parse_header_value(value: &str) -> Result<HeaderValue, ApiError> {
    HeaderValue::from_str(value)
        .map_err(|_| ApiError::Usage("a request header value is invalid".to_owned()))
}

fn read_input(path: &Path) -> Result<Vec<u8>, ApiError> {
    if path == Path::new("-") {
        let mut body = Vec::new();
        io::stdin()
            .take(MAXIMUM_REQUEST_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| ApiError::Io)?;
        if body.len() as u64 > MAXIMUM_REQUEST_BYTES {
            body.zeroize();
            return Err(ApiError::Usage(
                "the request body exceeds the 8 MiB limit".to_owned(),
            ));
        }
        return Ok(body);
    }
    read_bounded_file(path, MAXIMUM_REQUEST_BYTES)
}

fn read_token_file(path: &Path) -> Result<Zeroizing<String>, ApiError> {
    let bytes = Zeroizing::new(read_bounded_file(path, 8 * 1024)?);
    let mut value = String::from_utf8(bytes.to_vec()).map_err(|_| ApiError::Credential)?;
    trim_one_line_ending(&mut value);
    Ok(Zeroizing::new(value))
}

fn read_header_file(path: &Path) -> Result<String, ApiError> {
    let bytes = read_bounded_file(path, MAXIMUM_HEADER_FILE_BYTES)?;
    let mut value = String::from_utf8(bytes)
        .map_err(|_| ApiError::Usage("a header file must contain UTF-8 text".to_owned()))?;
    trim_one_line_ending(&mut value);
    Ok(value)
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ApiError> {
    let file = fs::File::open(path).map_err(|_| ApiError::Io)?;
    if file.metadata().map_err(|_| ApiError::Io)?.len() > maximum {
        return Err(ApiError::Usage(
            "an input file exceeds its accepted size".to_owned(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ApiError::Io)?;
    if bytes.len() as u64 > maximum {
        return Err(ApiError::Usage(
            "an input file exceeds its accepted size".to_owned(),
        ));
    }
    Ok(bytes)
}

fn trim_one_line_ending(value: &mut String) {
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') {
        value.pop();
    }
}

fn write_response(
    output: Option<&Path>,
    include: bool,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), ApiError> {
    let mut bytes = Vec::new();
    if include {
        write!(&mut bytes, "HTTP {}\r\n", status.as_u16()).map_err(|_| ApiError::Io)?;
        for (name, value) in headers {
            bytes.extend_from_slice(name.as_str().as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(body);
    match output {
        Some(path) => fs::write(path, bytes).map_err(|_| ApiError::Io),
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(&bytes).map_err(|_| ApiError::Io)?;
            stdout.flush().map_err(|_| ApiError::Io)
        }
    }
}
