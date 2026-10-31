// SPDX-License-Identifier: Apache-2.0

//! `adapterctl verify --live`: drive one constant-determined send per
//! binding against the destination the runtime names, and judge the
//! answer against the send's declared range
//! (`products/adapter/CONCEPT.md` section 13.3).
//!
//! The command reads the workspace exactly as `check` does (project,
//! pinned profile and pack, runtime with environment substitution on),
//! then, per binding in declaration order, walks the route's linear
//! spine to its first upstream `to` send, follows `direct:` hops, and
//! renders the send from constants and the instantiation's parameters
//! alone. One probe send per binding rides the platform's frozen HTTP/HTTPS
//! destination transport (the [`send`] seam); the answer's status must
//! fall inside the send's `okStatusCodeRange` (Camel default
//! `200-299`). The response body is not validated against the compiled
//! contract: that comparison is the facade mapping the engine owns.
//!
//! What the command waits for instead of driving, as one warning per
//! binding and nothing more (the engine data path owns these): mTLS
//! destinations (`tls-transport`), token-kind credentials
//! (`token-credential`), `graphql:` sends (`graphql-transport`),
//! file-provider secrets (`secret-provider`), and any send whose inputs
//! the exchange, not the artifacts, decide: a header, exchange
//! property, JSONPath, or Rhai expression, an origin-pinned link, a
//! control-flow step ahead of the send, or an unbound optional
//! placeholder (`caller-sourced`). A run that only waits still completes,
//! but reports `drove: 0`; it is explicitly not live transport proof.
//!
//! Destinations and credentials come from the runtime configuration
//! only. Credentials resolve through the platform resolver with the
//! environment provider, and no resolved value ever reaches a report:
//! failures name the reference and endpoint, never the destination or
//! secret. The static credential composition mirrors the engine's own
//! rules (`crates/registry-adapter/src/auth/material.rs`) without
//! linking the engine, which this tooling crate never depends on.

mod send;

use base64::Engine as _;
use clap::Args;
use registry_adapter_core::{
    check_workspace, is_placeholder_name, AdapterPack, AdapterProfile, AdapterProject,
    AdapterRuntimeConfig, EndpointAuthentication, EndpointBinding, Expression, HttpMethod,
    RuntimeCredential, SendComponent, Step, ToParameters, ToStep, Workspace,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_httputil::destination::{
    DataDestinationPolicy, DestinationProfile, DestinationTlsMaterial,
    MAX_DESTINATION_CA_BUNDLE_BYTES,
};
use registry_platform_yaml::{Diagnostic, Report, SecretReference, Url};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::report::{DOMAIN_REFUSAL_EXIT, OPERATIONAL_FAILURE_EXIT};
use crate::verify::send::{send_once, TransportCredential, TransportFailure, WireRequest};

/// Why a binding waits rather than drives; the wait reasons the report
/// names, one family of `adapterctl.verify.wait-*` codes.
const TLS_TRANSPORT: &str = "tls-transport";
const TOKEN_CREDENTIAL: &str = "token-credential";
const CALLER_SOURCED: &str = "caller-sourced";
const GRAPHQL_TRANSPORT: &str = "graphql-transport";
const SECRET_PROVIDER: &str = "secret-provider";

/// The suggested action of each wait: what unblocks the binding.
fn wait_action(reason: &str) -> &'static str {
    match reason {
        TLS_TRANSPORT => "Run the engine runtime, whose TLS layer presents this binding's client identity.",
        TOKEN_CREDENTIAL => "Run the engine runtime, whose token acquisition drives this binding.",
        GRAPHQL_TRANSPORT => "Run the engine runtime, whose graphql component drives this send.",
        SECRET_PROVIDER => "Expose the secret through the environment provider, or run the engine runtime with the file provider configured.",
        _ => "Drive this binding with the engine runtime, whose exchange supplies the send's inputs.",
    }
}

/// Record one binding's wait: the value-free entry the report counts
/// and the warning the reader sees.
fn record_wait(
    index: usize,
    binding: &str,
    endpoint: &str,
    reason: &'static str,
    message: String,
    waits: &mut Vec<Value>,
    warnings: &mut Vec<Diagnostic>,
) {
    waits.push(json!({
        "binding": binding,
        "endpoint": endpoint,
        "reason": reason,
    }));
    warnings.push(Diagnostic::warning(
        format!("adapterctl.verify.wait-{reason}"),
        format!("/bindings/{index}"),
        message,
        wait_action(reason),
    ));
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Authored adapter project: its directory (holding `project.yaml`)
    /// or the `project.yaml` file itself. The profile and pack are read
    /// beside the project either way.
    #[arg(value_name = "PROJECT")]
    pub project: PathBuf,

    /// Operator runtime configuration: the destinations dialed and the
    /// credentials presented come from here and only here. Its `${NAME}`
    /// expressions are filled from the process environment.
    #[arg(long, value_name = "FILE", required = true)]
    pub runtime: PathBuf,

    /// Drive the destinations the runtime names. Live is the only mode
    /// today; the flag keeps the contract's spelling.
    #[arg(long, required = true)]
    pub live: bool,

    /// Profile file read instead of the `profile.yaml` beside the
    /// project.
    #[arg(long, value_name = "FILE")]
    pub profile: Option<PathBuf>,

    /// Pack file read instead of the `pack.yaml` beside the project.
    #[arg(long, value_name = "FILE")]
    pub pack: Option<PathBuf>,
}

/// One run's verdict: the project and runtime as given, how many sends
/// the command drove, the bindings that wait and why, the wait warnings
/// for the report, and how many files were read.
pub(crate) struct VerifyRun {
    pub project: String,
    pub runtime: String,
    pub drove: usize,
    pub waited: usize,
    pub waits: Vec<Value>,
    pub warnings: Vec<Diagnostic>,
    pub files_checked: usize,
}

/// Why the command could not run to a verdict: a file the environment
/// could not deliver, the authoring checks' refusal, or a live step
/// that stopped the run (an unresolvable secret, a refused credential
/// shape, an inadmissible destination, a transport failure, or an
/// answer outside its declared range).
pub(crate) enum VerifyFailure {
    Io {
        path: String,
        source: io::Error,
    },
    Refused {
        diagnostics: Vec<Diagnostic>,
        files_checked: usize,
    },
    Stopped {
        exit: u8,
        diagnostics: Vec<Value>,
    },
}

fn refused_now(report: Report, files: usize) -> VerifyFailure {
    VerifyFailure::Refused {
        diagnostics: report.into_diagnostics(),
        files_checked: files,
    }
}

/// Verify one project live. The reading half mirrors `check` exactly;
/// any refusal it reports stops before the first dial.
pub(crate) fn run(args: &VerifyArgs) -> Result<VerifyRun, VerifyFailure> {
    // `--live` is the only mode: clap refuses its absence, and a caller
    // reaching the library without it gets the same refusal, not a
    // silent offline pass.
    if !args.live {
        return Err(VerifyFailure::Refused {
            diagnostics: vec![Diagnostic::error(
                "adapterctl.usage-invalid",
                "arguments",
                "verify requires --live",
                "Run adapterctl verify --live with --runtime and a project.",
            )],
            files_checked: 0,
        });
    }
    let mut report = Report::new(Vec::new());
    let mut files = 0usize;

    // The project, profile, and pack read exactly as `check` reads
    // them; an artifact `check` accepts is the artifact this command
    // dials for.
    let (project_path, directory) = crate::check::resolve_project(&args.project);
    let io = |failure: crate::check::CheckFailure| match failure {
        crate::check::CheckFailure::Io { path, source } => VerifyFailure::Io { path, source },
    };
    let project_doc = crate::check::read::<AdapterProject>(
        &project_path,
        &crate::check::PROJECT_FORMAT,
        &mut report,
        &mut files,
    )
    .map_err(io)?;
    let profile_path = args
        .profile
        .clone()
        .unwrap_or_else(|| directory.join("profile.yaml"));
    let profile_doc = crate::check::read::<AdapterProfile>(
        &profile_path,
        &crate::check::PROFILE_FORMAT,
        &mut report,
        &mut files,
    )
    .map_err(io)?;
    let pack_path = args
        .pack
        .clone()
        .unwrap_or_else(|| directory.join("pack.yaml"));
    let pack_doc = crate::check::read::<AdapterPack>(
        &pack_path,
        &crate::check::PACK_FORMAT,
        &mut report,
        &mut files,
    )
    .map_err(io)?;

    // The runtime reads through the shared loader with substitution on:
    // the command dials real destinations, so `${NAME}` expressions
    // must hold real values before anything connects.
    let runtime =
        crate::check::read_runtime(&args.runtime, true, &mut report, &mut files).map_err(io)?;

    // A document the reader refuses stops the run: the drive needs
    // parsed values, and the report still names everything to fix.
    if report.has_errors() {
        return Err(refused_now(report, files));
    }
    let (project_decoded, _project_bytes) = project_doc.expect("the project decoded");
    let (profile_decoded, profile_bytes) = profile_doc.expect("the profile decoded");
    let (pack_decoded, pack_bytes) = pack_doc.expect("the pack decoded");
    let project = project_decoded.value;
    let profile = profile_decoded.value;
    let pack = pack_decoded.value;
    let runtime = runtime.expect("the runtime decoded");

    // The tool-side verifications `check` owns, over the same bytes.
    let pinned =
        crate::check::verify_digest_pins(&pack, &pack_path, &mut report, &mut files).map_err(io)?;
    crate::check::verify_entrypoints(&pack, &pack_path, &pinned, &mut report);
    crate::check::verify_query_files(&pack, &pack_path, &pinned, &mut report);
    crate::check::verify_graphql_operations(&pack, &pack_path, &pinned, &mut report);
    crate::check::verify_project_pins(
        &project,
        &profile,
        &profile_bytes,
        &pack,
        &pack_bytes,
        &mut report,
    );
    if report.has_errors() {
        return Err(refused_now(report, files));
    }

    // Compose the core's pure checks over the workspace. Fixture suites
    // are not read: their replay is `fixtures replay`'s question, not
    // this command's.
    let workspace = Workspace {
        profile: &profile,
        pack: &pack,
        project: &project,
        runtime: Some(&runtime),
        fixtures: &[],
    };
    for diagnostic in check_workspace(&workspace) {
        report.push(diagnostic);
    }
    if report.has_errors() {
        return Err(refused_now(report, files));
    }

    let resolver = SecretResolver::new([SecretProvider::Environment], std::path::Path::new(""))
        .expect("the environment provider needs no file root");
    let mut warnings = report.into_diagnostics();
    let (drove, waited, waits) = drive(&project, &pack, &runtime, &resolver, &mut warnings)?;

    Ok(VerifyRun {
        project: args.project.display().to_string(),
        runtime: args.runtime.display().to_string(),
        drove,
        waited,
        waits,
        warnings,
        files_checked: files,
    })
}

/// The steps a route id resolves to, and the parameters its template
/// placeholders substitute: a pack route carries none, an instantiated
/// template carries the instantiation's values over the template's
/// declared defaults.
fn route_of<'a>(
    pack: &'a AdapterPack,
    project: &'a AdapterProject,
    route: &str,
) -> Option<(&'a [Step], BTreeMap<String, Value>)> {
    if let Some(definition) = pack
        .routes
        .iter()
        .find(|definition| definition.id.as_str() == route)
    {
        return Some((definition.steps.as_slice(), BTreeMap::new()));
    }
    let instantiation = project
        .templated_routes
        .iter()
        .find(|instantiation| instantiation.route_id.as_str() == route)?;
    let template = pack
        .route_templates
        .iter()
        .find(|template| template.id.as_str() == instantiation.route_template.as_str())?;
    // The effective parameters: the instantiation's bindings over the
    // template's declared defaults, so a default-only parameter still
    // drives.
    let mut parameters = BTreeMap::new();
    for declared in &template.parameters {
        if let Some(default) = &declared.default_value {
            parameters.insert(declared.name.as_str().to_owned(), default.clone());
        }
    }
    for (name, value) in &instantiation.parameters {
        parameters.insert(name.clone(), value.clone());
    }
    Some((template.steps.as_slice(), parameters))
}

/// What the linear spine of a route reaches first: an upstream send to
/// drive, a graphql send, or a reason the exchange, not the artifacts,
/// decides.
enum Spine<'a> {
    Send(&'a ToStep),
    GraphQl,
    Caller(&'static str),
}

/// Walk a route's linear spine to its first upstream send, following
/// `direct:` hops; the first control-flow step ends the walk, because
/// which branch runs is the exchange's decision, not the artifacts'.
fn first_send<'a>(steps: &'a [Step], pack: &'a AdapterPack, depth: usize) -> Spine<'a> {
    if depth > 16 {
        // The checks refuse deeper chains; this is the same bound, held
        // defensively on a workspace they already accepted.
        return Spine::Caller("the direct chain exceeds the 16-deep bound");
    }
    for step in steps {
        match step {
            Step::To(to) => match to.uri.component {
                SendComponent::Direct => {
                    let Some(target) = pack
                        .routes
                        .iter()
                        .find(|definition| definition.id.as_str() == to.uri.id)
                    else {
                        return Spine::Caller("the send names no direct route");
                    };
                    return first_send(&target.steps, pack, depth + 1);
                }
                SendComponent::Http => return Spine::Send(to),
                SendComponent::GraphQl => return Spine::GraphQl,
            },
            Step::Choice(_)
            | Step::Split(_)
            | Step::Loop(_)
            | Step::Enrich(_)
            | Step::CircuitBreaker(_)
            | Step::Throttle(_)
            | Step::IdempotentConsumer(_)
            | Step::Filter(_)
            | Step::Validate(_)
            | Step::ThrowException(_)
            | Step::OnException(_)
            | Step::ErrorHandler(_)
            | Step::DoTry(_) => {
                return Spine::Caller("a control-flow step decides the path to the first send");
            }
            // Linear body, header, property, and script steps send
            // nothing; the walk continues past them.
            _ => {}
        }
    }
    Spine::Caller("the route reaches no upstream send")
}

/// Why a template could not be filled from constants alone.
#[derive(Debug)]
enum SubstitutionFault {
    #[allow(dead_code)]
    Unbound(String),
    #[allow(dead_code)]
    Malformed(String),
}

/// Fill every `{{name}}` and `{{?name}}` placeholder from `lookup`. A
/// required placeholder the lookup cannot fill refuses; an optional one
/// refuses too: an empty path segment or query value is not a state a
/// probe should dial. The checks own malformed placeholders; the
/// defensive refusal here keeps a broken text from reaching the wire.
fn substitute(
    text: &str,
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> Result<String, SubstitutionFault> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err(SubstitutionFault::Malformed(rest.to_owned()));
        };
        let token = &after[..end];
        let (optional, name) = match token.strip_prefix('?') {
            Some(name) => (true, name),
            None => (false, token),
        };
        if name.is_empty() || !is_placeholder_name(name) {
            return Err(SubstitutionFault::Malformed(format!("{{{{{token}}}}}")));
        }
        match lookup(name) {
            Some(value) => out.push_str(&value),
            None if optional => {
                return Err(SubstitutionFault::Unbound(format!("{{{{?{name}}}}}")));
            }
            None => return Err(SubstitutionFault::Unbound(format!("{{{{{name}}}}}"))),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The text one expression contributes to a send, when constants and
/// the template parameters alone decide it. Numbers and booleans render
/// as their JSON text; any exchange-reading language, and a null,
/// object, or array constant, are caller-sourced.
fn constant_text(
    expression: &Expression,
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> Result<String, &'static str> {
    match expression {
        Expression::Constant(value) => match value {
            Value::String(text) => substitute(text, lookup)
                .map_err(|_| "a placeholder in the send's constants is unbound or malformed"),
            Value::Number(number) => Ok(number.to_string()),
            Value::Bool(flag) => Ok(flag.to_string()),
            _ => Err("the send carries a null, object, or array constant"),
        },
        _ => Err(
            "the send reads the exchange: a header, property, JSONPath, or Rhai expression decides it",
        ),
    }
}

/// Percent-encode one path segment or query member: the RFC 3986
/// unreserved set stays, every other byte becomes two uppercase hex
/// digits, so no substituted value can add a segment, a query member,
/// or a header byte.
fn encode_component(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    for &byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            other => {
                out.push('%');
                out.push(HEX[usize::from(other >> 4)] as char);
                out.push(HEX[usize::from(other & 0x0f)] as char);
            }
        }
    }
    out
}

/// The inclusive status ranges a send's `okStatusCodeRange` declares.
/// The authoring checks refuse a range that will not parse; an entry
/// that still will not parse admits nothing, so a status outside it
/// refuses rather than silently passing.
fn parse_ranges(text: &str) -> Vec<(u16, u16)> {
    text.split(',')
        .filter_map(|part| match part.trim().split_once('-') {
            Some((low, high)) => match (low.trim().parse().ok(), high.trim().parse().ok()) {
                (Some(low), Some(high)) if low <= high => Some((low, high)),
                _ => None,
            },
            None => part.trim().parse().ok().map(|status| (status, status)),
        })
        .collect()
}

/// The text a JSON value contributes as a parameter binding.
fn value_text(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(Value::Bool(flag)) => Some(flag.to_string()),
        _ => None,
    }
}

/// The placeholder lookup of one send: a template parameter fills from
/// the instantiation's binding, then the template's declared default,
/// then the send's same-named parameter expression when that expression
/// is a constant (the corpus baseline shape: an optional parameter the
/// instantiation leaves unbound, filled per send).
fn send_lookup<'a>(
    send: &'a ToParameters,
    parameters: &'a BTreeMap<String, Value>,
) -> impl FnMut(&str) -> Option<String> + 'a {
    move |name: &str| {
        if let Some(text) = value_text(parameters.get(name)) {
            return Some(text);
        }
        let expression = send.path_parameters.get(name)?;
        constant_text(expression, &mut |nested: &str| {
            value_text(parameters.get(nested))
        })
        .ok()
    }
}

/// One rendered probe: everything the send seam needs, with the answer
/// judged against the range the send declares.
struct Rendered {
    method: &'static str,
    target: String,
    body: Option<Vec<u8>>,
    ok_range: String,
}

/// Render an `http:` send from constants and template parameters alone.
/// Every refusal names what is missing; none of them dials anything.
fn render_send(
    to: &ToStep,
    parameters: &BTreeMap<String, Value>,
) -> Result<Rendered, &'static str> {
    let send = to
        .parameters
        .as_ref()
        .ok_or("the send carries no parameters")?;
    if send.http_uri.is_some() {
        return Err("the send's destination is an origin-pinned link");
    }
    let method = match send.http_method {
        Some(HttpMethod::Get) => "GET",
        Some(HttpMethod::Post) => "POST",
        Some(HttpMethod::Put) => "PUT",
        Some(HttpMethod::Patch) => "PATCH",
        None => return Err("the send declares no method"),
    };
    let mut lookup = send_lookup(send, parameters);

    // The path: template placeholders filled, then encoded segment by
    // segment, so a substituted '/' cannot add a segment.
    let template = send.path.clone().unwrap_or_default();
    let filled = substitute(&template, &mut lookup)
        .map_err(|_| "a path placeholder in the send is unbound or malformed")?;
    let path = filled
        .split('/')
        .map(encode_component)
        .collect::<Vec<_>>()
        .join("/");
    let mut target = if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    };

    // The query: each member's key and constant value encoded as one
    // member, in map order.
    let mut query = Vec::new();
    for (key, value) in &send.query {
        let text = constant_text(value, &mut lookup)?;
        query.push(format!(
            "{}={}",
            encode_component(key.as_str()),
            encode_component(&text)
        ));
    }
    if !query.is_empty() {
        target.push('?');
        target.push_str(&query.join("&"));
    }

    let body = match &send.body {
        Some(expression) => Some(constant_text(expression, &mut lookup)?.into_bytes()),
        None => None,
    };
    Ok(Rendered {
        method,
        target,
        body,
        ok_range: send
            .ok_status_code_range
            .clone()
            .unwrap_or_else(|| "200-299".to_owned()),
    })
}

/// What the credential composition produced, or why it stopped.
enum CredentialOutcome {
    Credential(TransportCredential),
    Wait(&'static str, String),
    Secret { reference: String, fault: String },
    Refused(&'static str),
}

/// Resolve one secret reference through the environment provider. A
/// file-provider reference waits (the engine runs with the file
/// provider configured); anything else that fails is the environment's
/// failure, reported without the value.
fn resolved(
    reference: &SecretReference,
    resolver: &SecretResolver,
) -> Result<Zeroizing<Vec<u8>>, CredentialOutcome> {
    if reference.provider() == SecretProvider::File {
        return Err(CredentialOutcome::Wait(
            SECRET_PROVIDER,
            "the credential reads the file provider".to_owned(),
        ));
    }
    resolver
        .resolve(reference.as_str())
        .map(|secret| Zeroizing::new(secret.expose_secret().to_vec()))
        .map_err(|fault| CredentialOutcome::Secret {
            reference: reference.as_str().to_owned(),
            fault: fault.to_string(),
        })
}

/// Whether the bytes can travel as one header value: visible ASCII,
/// space, or an extension byte, never a control byte or DEL (the
/// engine's own rule, `crates/registry-adapter/src/auth/material.rs`).
fn is_header_value_bytes(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte >= 0x20 && *byte != 0x7f)
}

/// Whether the bytes are a credential that arrives exactly as declared:
/// header-value bytes with no leading or trailing space or tab, which
/// intermediaries strip and so would silently change.
fn is_credential_value_bytes(bytes: &[u8]) -> bool {
    let leading = matches!(bytes.first(), Some(b' ' | b'\t'));
    let trailing = matches!(bytes.last(), Some(b' ' | b'\t'));
    is_header_value_bytes(bytes) && !leading && !trailing
}

/// Compose the credential header the endpoint's declared kind and the
/// runtime's credential produce, mirroring the engine's static rules:
/// Basic refuses an empty username or password and a colon in the
/// username, then base64s the pair; a static token must be visible
/// ASCII; an API key must be header-value bytes with no stripped edge.
/// The OAuth2 kinds acquire tokens; only the engine does that.
fn credential_header(
    authentication: &EndpointAuthentication,
    credential: Option<&RuntimeCredential>,
    resolver: &SecretResolver,
) -> CredentialOutcome {
    let Some(credential) = credential else {
        return CredentialOutcome::Credential(TransportCredential::None);
    };
    if authentication.kind() != credential.kind() {
        // The checks refuse a kind mismatch; this is the same refusal,
        // held defensively on a workspace they already accepted.
        return CredentialOutcome::Wait(
            CALLER_SOURCED,
            "the credential kind does not match the endpoint's declared kind".to_owned(),
        );
    }
    match (authentication, credential) {
        (
            EndpointAuthentication::Basic {},
            RuntimeCredential::Basic {
                username_ref,
                password_ref,
            },
        ) => {
            let username = match resolved(username_ref, resolver) {
                Ok(bytes) => bytes,
                Err(outcome) => return outcome,
            };
            let password = match resolved(password_ref, resolver) {
                Ok(bytes) => bytes,
                Err(outcome) => return outcome,
            };
            if username.is_empty() || password.is_empty() {
                return CredentialOutcome::Refused(
                    "the resolved basic credential is empty in its username or password",
                );
            }
            if username.contains(&b':') {
                return CredentialOutcome::Refused("the resolved username carries a colon");
            }
            let mut joined = username;
            joined.push(b':');
            joined.extend_from_slice(&password);
            let value = base64::engine::general_purpose::STANDARD.encode(joined.as_slice());
            CredentialOutcome::Credential(TransportCredential::Basic(Zeroizing::new(
                value.into_bytes(),
            )))
        }
        (
            EndpointAuthentication::StaticAuthorization { scheme },
            RuntimeCredential::StaticAuthorization { token_ref },
        ) => {
            let token = match resolved(token_ref, resolver) {
                Ok(bytes) => bytes,
                Err(outcome) => return outcome,
            };
            if token.is_empty() {
                return CredentialOutcome::Refused("the resolved token is empty");
            }
            if !token.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
                return CredentialOutcome::Refused(
                    "the resolved token carries bytes outside visible ASCII",
                );
            }
            CredentialOutcome::Credential(TransportCredential::StaticAuthorization {
                scheme: scheme.clone().unwrap_or_else(|| "Bearer".to_owned()),
                token,
            })
        }
        (
            EndpointAuthentication::StaticApiKey { header_name },
            RuntimeCredential::StaticApiKey { value_ref },
        ) => {
            let key = match resolved(value_ref, resolver) {
                Ok(bytes) => bytes,
                Err(outcome) => return outcome,
            };
            if key.is_empty() {
                return CredentialOutcome::Refused("the resolved API key is empty");
            }
            if !is_credential_value_bytes(&key) {
                return CredentialOutcome::Refused(
                    "the resolved API key carries a control byte or a stripped edge",
                );
            }
            CredentialOutcome::Credential(TransportCredential::ApiKey {
                header_name: header_name.clone(),
                value: key,
            })
        }
        (
            EndpointAuthentication::Oauth2ClientCredentials {},
            RuntimeCredential::Oauth2ClientCredentials { .. },
        )
        | (
            EndpointAuthentication::Oauth2PrivateKeyJwt {},
            RuntimeCredential::Oauth2PrivateKeyJwt { .. },
        ) => CredentialOutcome::Wait(
            TOKEN_CREDENTIAL,
            "the endpoint's token grant is acquired by the engine's auth layer".to_owned(),
        ),
        (EndpointAuthentication::None {}, RuntimeCredential::None {}) => {
            CredentialOutcome::Credential(TransportCredential::None)
        }
        // Kind equality already matched the pairs above; this arm only
        // covers a shape the checks refused.
        _ => CredentialOutcome::Wait(
            CALLER_SOURCED,
            "the credential kind does not match the endpoint's declared kind".to_owned(),
        ),
    }
}

/// Why the frozen destination policy refuses a binding.
enum EgressFault {
    Refused(String),
}

/// Freeze the same class of fixed-origin policy the runtime uses. Default
/// builds apply production HTTPS rules; only the explicit `tls-test`
/// feature admits a pinned loopback TLS origin for the real handshake tests.
fn destination_policy(
    binding: &EndpointBinding,
    runtime: &AdapterRuntimeConfig,
) -> Result<DataDestinationPolicy, EgressFault> {
    let base = &binding.base_url;
    let parsed = base.to_url();
    #[cfg(not(feature = "tls-test"))]
    if parsed.scheme() == "https" && denotes_loopback(base) {
        return Err(EgressFault::Refused(
            "the destination is not admitted by the frozen policy".to_owned(),
        ));
    }
    let profile = destination_profile(base);
    let mut origin = parsed.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    let networks: Vec<_> = runtime
        .allowed_private_cidrs
        .iter()
        .map(registry_adapter_core::Cidr::network)
        .collect();
    let mut policy = DataDestinationPolicy::new(
        &binding.endpoint.as_str().to_ascii_lowercase(),
        origin.as_str(),
        profile,
        &networks,
    )
    .map_err(|_| {
        EgressFault::Refused("the destination is not admitted by the frozen policy".to_owned())
    })?;
    if let Some(profile) = &binding.tls_trust_profile {
        let bundle = resolve_ca_bundle(runtime, profile.as_str()).map_err(|_| {
            EgressFault::Refused(
                "the configured destination trust material is unavailable".to_owned(),
            )
        })?;
        let material =
            DestinationTlsMaterial::from_pem(Some(bundle.as_slice()), None).map_err(|_| {
                EgressFault::Refused(
                    "the configured destination trust material is invalid".to_owned(),
                )
            })?;
        policy = policy.require_configured_tls();
        policy.install_configured_tls(material).map_err(|_| {
            EgressFault::Refused("the configured destination trust material was refused".to_owned())
        })?;
    }
    Ok(policy)
}

fn destination_profile(base: &Url) -> DestinationProfile {
    let parsed = base.to_url();
    #[cfg(feature = "tls-test")]
    if parsed.scheme() == "https" && denotes_loopback(base) {
        return DestinationProfile::PinnedLoopbackHttpsTest;
    }
    match parsed.scheme() {
        "https" => DestinationProfile::ProductionHttps,
        _ if denotes_loopback(base) => DestinationProfile::LoopbackDevelopmentHttp,
        _ => DestinationProfile::PrivateServiceHttp,
    }
}

fn denotes_loopback(origin: &Url) -> bool {
    let parsed = origin.to_url();
    parsed.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

/// Read one declared CA bundle under the platform ceiling. Every failure is
/// value-free, and special files are refused before opening.
fn resolve_ca_bundle(
    runtime: &AdapterRuntimeConfig,
    profile: &str,
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let path = runtime
        .outbound_tls
        .as_ref()
        .and_then(|tls| tls.trust_profiles.get(profile))
        .map(|declared| declared.ca_bundle_file.as_str())
        .ok_or(())?;
    if !std::fs::metadata(path).map_err(|_| ())?.is_file() {
        return Err(());
    }
    let file = std::fs::File::open(path).map_err(|_| ())?;
    if !file.metadata().map_err(|_| ())?.is_file() {
        return Err(());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((MAX_DESTINATION_CA_BUNDLE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > MAX_DESTINATION_CA_BUNDLE_BYTES {
        return Err(());
    }
    Ok(bytes)
}

/// Drive one probe per binding, in declaration order. The first send
/// that cannot be driven from the artifacts waits; the first send that
/// was driven and refused stops the run with its finding.
fn drive(
    project: &AdapterProject,
    pack: &AdapterPack,
    runtime: &AdapterRuntimeConfig,
    resolver: &SecretResolver,
    warnings: &mut Vec<Diagnostic>,
) -> Result<(usize, usize, Vec<Value>), VerifyFailure> {
    let mut drove = 0usize;
    let mut waits: Vec<Value> = Vec::new();
    for (index, binding) in project.bindings.iter().enumerate() {
        let binding_id = binding.id.as_str().to_owned();
        let Some((steps, parameters)) = route_of(pack, project, binding.route.as_str()) else {
            record_wait(
                index,
                &binding_id,
                binding.route.as_str(),
                CALLER_SOURCED,
                "the binding's route is neither a pack route nor an instantiated template"
                    .to_owned(),
                &mut waits,
                warnings,
            );
            continue;
        };
        let to = match first_send(steps, pack, 0) {
            Spine::Send(to) => to,
            Spine::GraphQl => {
                record_wait(
                    index,
                    &binding_id,
                    binding.route.as_str(),
                    GRAPHQL_TRANSPORT,
                    "the first send is a graphql send the engine's graphql component drives"
                        .to_owned(),
                    &mut waits,
                    warnings,
                );
                continue;
            }
            Spine::Caller(why) => {
                record_wait(
                    index,
                    &binding_id,
                    binding.route.as_str(),
                    CALLER_SOURCED,
                    format!("the route's first send is not constant-determined: {why}"),
                    &mut waits,
                    warnings,
                );
                continue;
            }
        };
        let endpoint_id = to.uri.id.clone();
        let rendered = match render_send(to, &parameters) {
            Ok(rendered) => rendered,
            Err(why) => {
                record_wait(
                    index,
                    &binding_id,
                    &endpoint_id,
                    CALLER_SOURCED,
                    format!("the first send is not constant-determined: {why}"),
                    &mut waits,
                    warnings,
                );
                continue;
            }
        };
        let Some(runtime_binding) = runtime
            .endpoints
            .iter()
            .find(|binding| binding.endpoint.as_str() == endpoint_id)
        else {
            record_wait(
                index,
                &binding_id,
                &endpoint_id,
                CALLER_SOURCED,
                "the runtime binds no destination for the send's endpoint".to_owned(),
                &mut waits,
                warnings,
            );
            continue;
        };
        if runtime_binding.mtls_identity.is_some() {
            record_wait(
                index,
                &binding_id,
                &endpoint_id,
                TLS_TRANSPORT,
                "the binding carries an mTLS identity only the engine's transport presents"
                    .to_owned(),
                &mut waits,
                warnings,
            );
            continue;
        }
        let policy = match destination_policy(runtime_binding, runtime) {
            Ok(policy) => policy,
            Err(EgressFault::Refused(message)) => {
                return Err(VerifyFailure::Stopped {
                    exit: DOMAIN_REFUSAL_EXIT,
                    diagnostics: vec![json!({
                        "severity": "error",
                        "code": "adapterctl.verify.insecure-origin",
                        "artifact": "runtime",
                        "path": format!("/bindings/{index}"),
                        "message": message,
                        "suggestedAction":
                            "Bind the endpoint to an https origin, a loopback address, or a range allowedPrivateCidrs admits.",
                    })],
                });
            }
        };
        let Some(endpoint) = pack
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id.as_str() == endpoint_id)
        else {
            record_wait(
                index,
                &binding_id,
                &endpoint_id,
                CALLER_SOURCED,
                "the pack declares no endpoint for the send".to_owned(),
                &mut waits,
                warnings,
            );
            continue;
        };
        let credential = match credential_header(
            &endpoint.authentication,
            runtime_binding.credential.as_ref(),
            resolver,
        ) {
            CredentialOutcome::Credential(credential) => credential,
            CredentialOutcome::Wait(reason, message) => {
                record_wait(
                    index,
                    &binding_id,
                    &endpoint_id,
                    reason,
                    message,
                    &mut waits,
                    warnings,
                );
                continue;
            }
            CredentialOutcome::Secret { reference, fault } => {
                return Err(VerifyFailure::Stopped {
                    exit: OPERATIONAL_FAILURE_EXIT,
                    diagnostics: vec![json!({
                        "severity": "error",
                        "code": "adapterctl.verify.secret-unavailable",
                        "artifact": "runtime",
                        "path": format!("/bindings/{index}"),
                        "message": format!(
                            "the secret {reference} of endpoint {endpoint_id} could not be resolved: {fault}"
                        ),
                        "suggestedAction":
                            "Set the environment variable the reference names, then retry.",
                    })],
                });
            }
            CredentialOutcome::Refused(why) => {
                return Err(VerifyFailure::Stopped {
                    exit: OPERATIONAL_FAILURE_EXIT,
                    diagnostics: vec![json!({
                        "severity": "error",
                        "code": "adapterctl.verify.credential-refused",
                        "artifact": "runtime",
                        "path": format!("/bindings/{index}"),
                        "message": format!(
                            "the credential of endpoint {endpoint_id} is refused: {why}"
                        ),
                        "suggestedAction":
                            "Correct the credential the references resolve to, or re-author the endpoint's declared kind.",
                    })],
                });
            }
        };
        let parsed_base = runtime_binding.base_url.to_url();
        let mut target = parsed_base.path().trim_end_matches('/').to_owned();
        target.push_str(&rendered.target);
        let request = WireRequest {
            policy,
            method: rendered.method.to_owned(),
            target,
            credential,
            body: rendered.body,
        };
        let status = match send_once(request) {
            Ok(status) => status,
            Err(TransportFailure(fault)) => {
                return Err(VerifyFailure::Stopped {
                    exit: OPERATIONAL_FAILURE_EXIT,
                    diagnostics: vec![json!({
                        "severity": "error",
                        "code": "adapterctl.verify.transport",
                        "artifact": "runtime",
                        "path": format!("/bindings/{index}"),
                        "message": format!(
                            "the send to endpoint {endpoint_id} failed: {fault}"
                        ),
                        "suggestedAction":
                            "Check the destination is serving and reachable, then retry.",
                    })],
                });
            }
        };
        let ranges = parse_ranges(&rendered.ok_range);
        if ranges
            .iter()
            .any(|(low, high)| status >= *low && status <= *high)
        {
            drove += 1;
        } else {
            return Err(VerifyFailure::Stopped {
                exit: DOMAIN_REFUSAL_EXIT,
                diagnostics: vec![json!({
                    "severity": "error",
                    "code": "adapterctl.verify.status-outside-range",
                    "artifact": "upstream-answer",
                    "path": format!("/bindings/{index}"),
                    "message": format!(
                        "the endpoint {endpoint_id} answered {status}, outside the send's declared range {}",
                        rendered.ok_range
                    ),
                    "suggestedAction":
                        "Check the upstream's status contract, or re-author the send's okStatusCodeRange.",
                })],
            });
        }
    }
    let waited = waits.len();
    Ok((drove, waited, waits))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lookup over a fixed parameter set.
    fn parameters(pairs: &[(&str, &str)]) -> impl FnMut(&str) -> Option<String> {
        let mut owned: BTreeMap<String, String> = BTreeMap::new();
        for (name, value) in pairs {
            owned.insert((*name).to_owned(), (*value).to_owned());
        }
        move |name: &str| owned.get(name).cloned()
    }

    /// Placeholders fill from the lookup; a required gap, an optional
    /// gap, and a malformed token each refuse.
    #[test]
    fn placeholders_fill_or_refuse() {
        let mut lookup = parameters(&[("kind", "case"), ("region", "north")]);
        assert_eq!(
            substitute("/api/cases/{{kind}}/{{region}}", &mut lookup).expect("filled"),
            "/api/cases/case/north"
        );
        assert!(matches!(
            substitute("/api/cases/{{missing}}", &mut lookup),
            Err(SubstitutionFault::Unbound(token)) if token == "{{missing}}"
        ));
        assert!(matches!(
            substitute("/api/cases/{{?missing}}", &mut lookup),
            Err(SubstitutionFault::Unbound(token)) if token == "{{?missing}}"
        ));
        assert!(matches!(
            substitute("/api/cases/{{kind", &mut lookup),
            Err(SubstitutionFault::Malformed(_))
        ));
        assert!(matches!(
            substitute("/api/cases/{{bad name}}", &mut lookup),
            Err(SubstitutionFault::Malformed(_))
        ));
    }

    /// Encoding keeps the unreserved set and encodes everything else as
    /// uppercase hex, so a substituted value cannot add a segment or a
    /// query member.
    #[test]
    fn encoding_keeps_the_unreserved_set() {
        assert_eq!(encode_component("case"), "case");
        assert_eq!(encode_component("a-b.c_d~e"), "a-b.c_d~e");
        assert_eq!(encode_component("two words"), "two%20words");
        assert_eq!(encode_component("a/b"), "a%2Fb");
        assert_eq!(encode_component("q=v&r"), "q%3Dv%26r");
        assert_eq!(encode_component("é"), "%C3%A9");
    }

    /// The status-range parser reads single statuses, closed ranges,
    /// and comma-separated lists; a backwards range and anything else
    /// unparseable admit nothing.
    #[test]
    fn status_ranges_parse() {
        assert_eq!(parse_ranges("200-299"), vec![(200, 299)]);
        assert_eq!(parse_ranges("418"), vec![(418, 418)]);
        assert_eq!(parse_ranges("200-299, 304"), vec![(200, 299), (304, 304)]);
        assert!(parse_ranges("300-100").is_empty());
        assert!(parse_ranges("teapot").is_empty());
        assert!(parse_ranges("").is_empty());
    }

    /// A constant renders as text, with nested placeholders filled; an
    /// exchange-reading expression never renders.
    #[test]
    fn constant_text_renders_constants_only() {
        let mut lookup = parameters(&[("page-size", "1")]);
        assert_eq!(
            constant_text(
                &Expression::Constant(Value::String("{{page-size}}".into())),
                &mut lookup
            )
            .expect("filled"),
            "1"
        );
        assert_eq!(
            constant_text(&Expression::Constant(Value::Bool(false)), &mut lookup).expect("bool"),
            "false"
        );
        assert_eq!(
            constant_text(&Expression::Constant(json!(7)), &mut lookup).expect("number"),
            "7"
        );
        assert!(constant_text(&Expression::Header("token".into()), &mut lookup).is_err());
        assert!(constant_text(&Expression::JsonPath("$.id".into()), &mut lookup).is_err());
    }

    /// The credential hygiene mirrors the engine's rules byte for byte.
    #[test]
    fn credential_hygiene_matches_the_engine() {
        assert!(is_header_value_bytes(b"a value"));
        assert!(!is_header_value_bytes(b"a\r\nvalue"));
        assert!(!is_header_value_bytes(b"a\x7fv"));
        assert!(is_credential_value_bytes(b"key-1"));
        assert!(!is_credential_value_bytes(b" key-1"));
        assert!(!is_credential_value_bytes(b"key-1\t"));
    }
}
