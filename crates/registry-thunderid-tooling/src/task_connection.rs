//! The task connection file `dev grant` reads (`PlatformTaskConnection`): one
//! fixed Casework target and the registered clients that may acquire an
//! approved task grant through it.
//!
//! The file names no secret. Each client's private assertion key is a secret
//! reference resolved through the file's own `secretProviders` (CFG-SEC-1),
//! and only when a grant is acquired; reading and checking the file resolve
//! none (CFG-CHECK-1).

use std::collections::BTreeMap;

use registry_platform_config::{ConfigBlockErrorKind, SecretProvidersConfig, SecretReference};
use registry_platform_yaml::{
    escape_pointer_segment, ApiVersion, Decoded, Diagnostic, Document, EnvelopeRule, Expect,
    ExternalId, FormatSpec, Reader, RemovedKey, Report, Severity, UniqueList, Url,
};
use serde::Deserialize;

pub const API_VERSION: &str = "id.registrystack.org/formats/platform/task-connection/v1alpha1";
pub const KIND: &str = "PlatformTaskConnection";

/// The most clients one connection file registers.
pub const MAXIMUM_CLIENTS: usize = 32;
/// The most scopes one client requests.
pub const MAXIMUM_SCOPES: usize = 32;
/// The longest scope, in bytes.
pub const MAXIMUM_SCOPE_BYTES: usize = 128;
/// The longest client id, in bytes. A client id names the header file a
/// grant is written to, so it is also a file name.
pub const MAXIMUM_CLIENT_ID_BYTES: usize = 64;

const SECRET_REFERENCE_REPLACEMENT: &str = "Use `assertionKeyRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.";

/// A task connection file as the shared reader accepts it.
pub const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/version",
            replacement: "Delete `version`; the apiVersion header names the format version.",
        },
        RemovedKey {
            pointer: "/clients/*/assertionKeyFile",
            replacement: SECRET_REFERENCE_REPLACEMENT,
        },
    ],
};

/// A task connection file: the Casework target, the issuer that exchanges
/// tokens for it, and the clients registered to acquire grants.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct TaskConnection {
    // The envelope, which the reader checks before decoding; declared so
    // the closed struct accepts it.
    #[allow(dead_code)]
    pub(crate) api_version: String,
    #[allow(dead_code)]
    pub(crate) kind: String,
    /// The Casework base URL a grant assertion is requested from: `https`,
    /// or `http` to 127.0.0.1, localhost, or [::1]; no query or fragment.
    pub(crate) casework_url: Url,
    /// The OAuth token endpoint each client authenticates to with
    /// private_key_jwt: `https`, or `http` to 127.0.0.1, localhost, or
    /// [::1]; no query or fragment.
    pub(crate) token_endpoint: Url,
    /// The audience of each client's private_key_jwt assertion: an absolute
    /// URI without a fragment or user information.
    pub(crate) client_assertion_audience: ExternalId,
    /// The resource of the bootstrap token that asks Casework for a grant
    /// assertion: an absolute URI without a fragment or user information.
    pub(crate) bootstrap_resource: ExternalId,
    /// The providers that resolve each client's `assertionKeyRef`.
    pub(crate) secret_providers: SecretProvidersConfig,
    /// The registered clients, by client id: 1 to 32. A client id is 1 to
    /// 64 lowercase letters, digits, or `-`, since it also names the header
    /// file a grant is written to.
    pub(crate) clients: BTreeMap<ExternalId, TaskClient>,
}

/// One registered client.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct TaskClient {
    /// The client's private assertion key, one JWK, as a secret reference
    /// a provider under `secretProviders` resolves.
    pub(crate) assertion_key_ref: SecretReference,
    /// The resource the approved grant is exchanged for: an absolute URI
    /// without a fragment or user information.
    pub(crate) resource: ExternalId,
    /// The scope ceiling requested with the grant: 1 to 32 distinct OAuth
    /// scope tokens, each at most 128 bytes and without `*`.
    pub(crate) scopes: UniqueList<ExternalId>,
}

/// The pointer to a member of one client.
pub(crate) fn client_pointer(client: &str, member: &str) -> String {
    format!("/clients/{}/{member}", escape_pointer_segment(client))
}

/// A client id names the header file a grant is written to: 1 to 64
/// lowercase letters, digits, or `-`.
pub(crate) fn valid_client_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAXIMUM_CLIENT_ID_BYTES
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// `https`, or `http` to a loopback host, with no query or fragment.
fn valid_endpoint(url: &Url) -> bool {
    let parsed = url.to_url();
    parsed.query().is_none()
        && parsed.fragment().is_none()
        && (url.is_https()
            || matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")))
}

fn valid_scope(scope: &str) -> bool {
    scope.len() <= MAXIMUM_SCOPE_BYTES
        && !scope.contains('*')
        && registry_platform_httputil::valid_scope_token(scope)
}

/// Read one task connection document through the shared reader, refusing
/// every `${...}` expression (CFG-SEC-2), and check it. Resolves no secret.
/// `file` is the name every diagnostic carries.
pub(crate) fn read(file: &str, bytes: &[u8]) -> Result<Decoded<TaskConnection>, Report> {
    let mut hook = registry_platform_config::AuthoredExpressions;
    let decoded = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<TaskConnection>(bytes, &Expect::one(&FORMAT))?;
    let found = check(&decoded.document, &decoded.value);
    if found.is_empty() {
        return Ok(decoded);
    }
    let mut report = decoded.document.warnings();
    for diagnostic in found {
        report.push(diagnostic);
    }
    Err(report)
}

/// What the types do not check: the shared secret providers block, the
/// endpoint and resource rules, the client and scope bounds, and that each
/// key reference names a declared provider. Resolves no secret.
pub(crate) fn check(document: &Document, connection: &TaskConnection) -> Vec<Diagnostic> {
    let mut found = Vec::new();
    let mut error = |pointer: &str, code: &str, message: &str, action: &str| {
        found.push(document.diagnostic_at_value(Severity::Error, code, pointer, message, action));
    };
    if let Err(refusal) = connection.secret_providers.check() {
        match refusal.kind() {
            ConfigBlockErrorKind::RelativePath => error(
                "/secretProviders/file/root",
                "platform.task-connection.relative-path",
                "the file provider root is not an absolute path without . or .. segments",
                "Write the absolute path of the directory that holds the key files.",
            ),
            _ => error(
                "/secretProviders",
                "platform.task-connection.no-secret-provider",
                "secretProviders enables no provider, so no assertion key can be resolved",
                "Declare secretProviders.file with an absolute root, secretProviders.environment, or both.",
            ),
        }
    }
    for (pointer, url) in [
        ("/caseworkUrl", &connection.casework_url),
        ("/tokenEndpoint", &connection.token_endpoint),
    ] {
        if !valid_endpoint(url) {
            error(
                pointer,
                "platform.task-connection.invalid-endpoint",
                "the endpoint is neither https nor http to a loopback host, or carries a query or fragment",
                "Use an https URL, or http to 127.0.0.1, localhost, or [::1], without a query or fragment.",
            );
        }
    }
    for (pointer, resource) in [
        (
            "/clientAssertionAudience",
            &connection.client_assertion_audience,
        ),
        ("/bootstrapResource", &connection.bootstrap_resource),
    ] {
        if !registry_platform_httputil::valid_resource_uri(resource) {
            error(
                pointer,
                "platform.task-connection.invalid-resource",
                "the value is not an absolute URI without a fragment or user information",
                "Write the absolute URI the issuer expects, such as an https URL or a URN.",
            );
        }
    }
    if connection.clients.is_empty() {
        error(
            "/clients",
            "platform.task-connection.no-clients",
            "the file registers no client",
            "Register the client that acquires grants under clients.",
        );
    } else if connection.clients.len() > MAXIMUM_CLIENTS {
        error(
            "/clients",
            "platform.task-connection.too-many-clients",
            "the file registers more than 32 clients",
            "Register at most 32 clients in one file; split the rest into another file.",
        );
    }
    for (id, client) in &connection.clients {
        let pointer = |member: &str| client_pointer(id, member);
        if !valid_client_id(id) {
            found.push(document.diagnostic_at_key(
                Severity::Error,
                "platform.task-connection.invalid-client-id",
                &format!("/clients/{}", escape_pointer_segment(id)),
                "a client id is not 1 to 64 lowercase letters, digits, or `-`; it names the grant header file",
                "Register the client under an id of lowercase letters, digits, and `-`, at most 64 long.",
            ));
        }
        if let Err(refusal) = connection
            .secret_providers
            .check_reference("assertionKeyRef", client.assertion_key_ref.as_str())
        {
            if refusal.kind() == ConfigBlockErrorKind::SecretProviderDisabled {
                found.push(document.diagnostic_at_value(
                    Severity::Error,
                    "platform.task-connection.undeclared-secret-provider",
                    &pointer("assertionKeyRef"),
                    "the reference names a provider secretProviders does not declare",
                    "Declare the provider the reference names under secretProviders, or reference a declared one.",
                ));
            }
        }
        if !registry_platform_httputil::valid_resource_uri(&client.resource) {
            found.push(document.diagnostic_at_value(
                Severity::Error,
                "platform.task-connection.invalid-resource",
                &pointer("resource"),
                "the value is not an absolute URI without a fragment or user information",
                "Write the absolute URI the issuer expects, such as an https URL or a URN.",
            ));
        }
        if client.scopes.is_empty() {
            found.push(document.diagnostic_at_value(
                Severity::Error,
                "platform.task-connection.no-scopes",
                &pointer("scopes"),
                "the client requests no scope",
                "List the scopes the approved grant is exchanged for.",
            ));
        } else if client.scopes.len() > MAXIMUM_SCOPES {
            found.push(document.diagnostic_at_value(
                Severity::Error,
                "platform.task-connection.too-many-scopes",
                &pointer("scopes"),
                "the client requests more than 32 scopes",
                "Request at most 32 scopes.",
            ));
        }
        for (index, scope) in client.scopes.iter().enumerate() {
            if !valid_scope(scope) {
                found.push(document.diagnostic_at_value(
                    Severity::Error,
                    "platform.task-connection.invalid-scope",
                    &format!("{}/{index}", pointer("scopes")),
                    "the scope is not an OAuth scope token of at most 128 bytes without `*`",
                    "Write one exact scope, using printable ASCII without spaces, `\"`, `\\`, or `*`.",
                ));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "apiVersion: id.registrystack.org/formats/platform/task-connection/v1alpha1\nkind: PlatformTaskConnection\n";

    const VALID: &str = "apiVersion: id.registrystack.org/formats/platform/task-connection/v1alpha1
kind: PlatformTaskConnection
caseworkUrl: http://127.0.0.1:8090
tokenEndpoint: http://127.0.0.1:8091/oauth2/token
clientAssertionAudience: http://127.0.0.1:8091/oauth2/token
bootstrapResource: urn:registry:casework
secretProviders:
  file:
    root: /home/operator/.task-keys
clients:
  task-agent:
    assertionKeyRef: secret:file/task-agent.jwk
    resource: urn:registry:breg
    scopes:
      - records:get
";

    fn read(text: &str) -> Result<Vec<Diagnostic>, Report> {
        super::read("task-connection.yaml", text.as_bytes()).map(|_| Vec::new())
    }

    fn codes(text: &str) -> Vec<(String, String)> {
        let diagnostics = match read(text) {
            Ok(found) => found,
            Err(report) => report.into_diagnostics(),
        };
        diagnostics
            .into_iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.path))
            .collect()
    }

    fn pair(code: &str, path: &str) -> (String, String) {
        (code.to_owned(), path.to_owned())
    }

    #[test]
    fn a_complete_connection_is_accepted() {
        assert_eq!(read(VALID).unwrap(), Vec::new());
    }

    #[test]
    fn cfg_env_1_a_connection_without_its_envelope_is_refused() {
        let text = VALID.replace(HEAD, "");
        assert_eq!(codes(&text), [pair("config.missing-envelope", "")]);
    }

    #[test]
    fn removed_keys_name_their_replacement() {
        let text = VALID.replace(HEAD, &format!("{HEAD}version: 1\n")).replace(
            "    assertionKeyRef: secret:file/task-agent.jwk\n",
            "    assertionKeyFile: /home/operator/key.jwk\n",
        );
        let report = read(&text).unwrap_err();
        let removed = report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "config.removed-key")
            .map(|diagnostic| {
                (
                    diagnostic.path.as_str(),
                    diagnostic.suggested_action.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            removed,
            [
                (
                    "/version",
                    "Delete `version`; the apiVersion header names the format version."
                ),
                (
                    "/clients/task-agent/assertionKeyFile",
                    SECRET_REFERENCE_REPLACEMENT
                ),
            ]
        );
    }

    #[test]
    fn cfg_sec_2_an_environment_expression_is_refused() {
        let text = VALID.replace("urn:registry:breg", "${RESOURCE}");
        assert_eq!(
            codes(&text),
            [pair(
                "config.substitution-not-allowed",
                "/clients/task-agent/resource"
            )]
        );
    }

    #[test]
    fn a_key_reference_names_a_declared_provider() {
        let text = VALID.replace("secret:file/task-agent.jwk", "secret:env/TASK_AGENT_KEY");
        assert_eq!(
            codes(&text),
            [pair(
                "platform.task-connection.undeclared-secret-provider",
                "/clients/task-agent/assertionKeyRef"
            )]
        );
        let text = VALID.replace("secret:file/task-agent.jwk", "/home/operator/key.jwk");
        assert_eq!(
            codes(&text),
            [pair(
                "config.invalid-value",
                "/clients/task-agent/assertionKeyRef"
            )]
        );
    }

    #[test]
    fn secret_providers_are_checked_in_place() {
        let text = VALID.replace("    root: /home/operator/.task-keys\n", "    root: keys\n");
        assert_eq!(
            codes(&text),
            [pair(
                "platform.task-connection.relative-path",
                "/secretProviders/file/root"
            )]
        );
        let text = VALID.replace(
            "secretProviders:\n  file:\n    root: /home/operator/.task-keys\n",
            "secretProviders: {}\n",
        );
        assert_eq!(
            codes(&text),
            [
                pair(
                    "platform.task-connection.no-secret-provider",
                    "/secretProviders"
                ),
                pair(
                    "platform.task-connection.undeclared-secret-provider",
                    "/clients/task-agent/assertionKeyRef"
                ),
            ]
        );
    }

    #[test]
    fn endpoints_are_https_or_loopback_http_without_a_query() {
        for (endpoint, accepted) in [
            ("https://issuer.example/oauth2/token", true),
            ("http://localhost:8091/oauth2/token", true),
            ("http://[::1]:8091/oauth2/token", true),
            ("http://issuer.example/oauth2/token", false),
            ("https://issuer.example/oauth2/token?tenant=a", false),
            ("https://issuer.example/oauth2/token#a", false),
        ] {
            let text = VALID.replace(
                "tokenEndpoint: http://127.0.0.1:8091/oauth2/token",
                &format!("tokenEndpoint: {endpoint}"),
            );
            let expected = if accepted {
                Vec::new()
            } else {
                vec![pair(
                    "platform.task-connection.invalid-endpoint",
                    "/tokenEndpoint",
                )]
            };
            assert_eq!(codes(&text), expected, "{endpoint}");
        }
    }

    #[test]
    fn resources_are_absolute_uris_without_a_fragment() {
        let text = VALID.replace("resource: urn:registry:breg", "resource: records");
        assert_eq!(
            codes(&text),
            [pair(
                "platform.task-connection.invalid-resource",
                "/clients/task-agent/resource"
            )]
        );
        let text = VALID.replace(
            "bootstrapResource: urn:registry:casework",
            "bootstrapResource: https://casework.example/#a",
        );
        assert_eq!(
            codes(&text),
            [pair(
                "platform.task-connection.invalid-resource",
                "/bootstrapResource"
            )]
        );
    }

    #[test]
    fn client_ids_are_file_names() {
        let text = VALID.replace("  task-agent:\n", "  Task_Agent:\n");
        assert_eq!(
            codes(&text),
            [pair(
                "platform.task-connection.invalid-client-id",
                "/clients/Task_Agent"
            )]
        );
        let text = VALID.replace("  task-agent:\n", "  task/agent:\n");
        assert_eq!(
            codes(&text),
            [pair(
                "platform.task-connection.invalid-client-id",
                "/clients/task~1agent"
            )]
        );
    }

    #[test]
    fn clients_are_bounded() {
        let text = VALID.replace(&VALID[VALID.find("clients:\n").unwrap()..], "clients: {}\n");
        assert_eq!(
            codes(&text),
            [pair("platform.task-connection.no-clients", "/clients")]
        );
        let client = "    assertionKeyRef: secret:file/task-agent.jwk\n    resource: urn:registry:breg\n    scopes:\n      - records:get\n";
        let clients = (0..33)
            .map(|index| format!("  agent-{index}:\n{client}"))
            .collect::<String>();
        let text = format!(
            "{}clients:\n{clients}",
            &VALID[..VALID.find("clients:\n").unwrap()]
        );
        assert_eq!(
            codes(&text),
            [pair(
                "platform.task-connection.too-many-clients",
                "/clients"
            )]
        );
    }

    #[test]
    fn scopes_are_bounded_distinct_scope_tokens() {
        let text = VALID.replace(
            "      - records:get\n",
            "      - records:get\n      - records:get\n",
        );
        assert_eq!(
            codes(&text),
            [pair(
                "config.duplicate-item",
                "/clients/task-agent/scopes/1"
            )]
        );
        let text = VALID.replace("      - records:get\n", "      - records:*\n");
        assert_eq!(
            codes(&text),
            [pair(
                "platform.task-connection.invalid-scope",
                "/clients/task-agent/scopes/0"
            )]
        );
        let text = VALID.replace("    scopes:\n      - records:get\n", "    scopes: []\n");
        assert_eq!(
            codes(&text),
            [pair(
                "platform.task-connection.no-scopes",
                "/clients/task-agent/scopes"
            )]
        );
        let scopes = (0..33)
            .map(|index| format!("      - scope-{index}\n"))
            .collect::<String>();
        let text = VALID.replace("      - records:get\n", &scopes);
        assert_eq!(
            codes(&text),
            [pair(
                "platform.task-connection.too-many-scopes",
                "/clients/task-agent/scopes"
            )]
        );
    }

    #[test]
    fn cfg_sec_3_no_diagnostic_repeats_a_value() {
        let text = VALID
            .replace("urn:registry:breg", "planted-resource-value")
            .replace("records:get", "planted*scope")
            .replace("http://127.0.0.1:8090", "http://planted.example");
        let rendered = read(&text).unwrap_err().render_human();
        assert!(!rendered.contains("planted"), "{rendered}");
    }
}
