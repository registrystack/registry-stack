//! The client profile and reviewed contracts files, read through the shared
//! configuration reader.
//!
//! The types here describe the files as an author or a tool writes them.
//! Each refuses what it can judge alone with a positioned diagnostic, and the
//! readers below add the rules that relate members to one another. The
//! public [`EvidenceClientProfile`] and [`ReviewedContracts`] are built only
//! from a document that passed both.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::PathBuf,
};

use registry_evidence_verifier::AssuranceProfile;
use registry_platform_yaml::{
    tagged_union, ApiVersion, BoundedU64, Decoded, Diagnostic, Digest, Document, EnvelopeRule,
    Expect, ExternalId, FormatSpec, Invalid, Reader, RemovedKey, Report, Severity, UniqueList, Url,
};
use serde::{Deserialize, Deserializer};

use crate::{
    definitions::EVIDENCE_DEFINITIONS_SCHEMA_V1,
    prepare::MAXIMUM_IDENTIFIER_BYTES,
    profile::{
        strict_fetch_refuses_literal_origin, ContractsProfile, ExpectedDefinitionProfile,
        ExpectedServiceProfile, OauthProfile, PrivateKeyReference, TrustProfile,
        VerificationProfile, DEFAULT_METADATA_CACHE_SECONDS, EVIDENCE_CLIENT_CONTRACTS_API_VERSION,
        EVIDENCE_CLIENT_CONTRACTS_KIND, EVIDENCE_CLIENT_PROFILE_API_VERSION,
        EVIDENCE_CLIENT_PROFILE_KIND, MAXIMUM_METADATA_CACHE_SECONDS,
    },
    EvidenceClientProfile, EvidenceDefinition, EvidenceDefinitionsDocument, EvidenceResponseFormat,
    ReviewedContracts,
};

/// The published identifier of the client profile schema.
pub const EVIDENCE_CLIENT_PROFILE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/client-profile/client-profile.v1.schema.json";
/// The published identifier of the reviewed contracts schema.
pub const EVIDENCE_CLIENT_CONTRACTS_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/client-contracts/client-contracts.v1.schema.json";

/// The client profile format. A file opens with `apiVersion` and `kind`; the
/// `schema` header and the `source` tag it replaced are refused, each naming
/// what to write.
const PROFILE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: EVIDENCE_CLIENT_PROFILE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(EVIDENCE_CLIENT_PROFILE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/schema",
            replacement: "Write `apiVersion: \
                          id.registrystack.org/formats/evidence/client-profile/v1` and `kind: \
                          EvidenceClientProfile` in its place.",
        },
        RemovedKey {
            pointer: "/privateKey/source",
            replacement: "Write `privateKey.type` with the same value.",
        },
    ],
};

/// The reviewed contracts format. A file opens with `apiVersion` and `kind`;
/// the `schema` header it replaced is refused, naming what to write.
const CONTRACTS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: EVIDENCE_CLIENT_CONTRACTS_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(EVIDENCE_CLIENT_CONTRACTS_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[RemovedKey {
        pointer: "/schema",
        replacement: "Write `apiVersion: \
                      id.registrystack.org/formats/evidence/client-contracts/v1` and `kind: \
                      EvidenceClientContracts` in its place.",
    }],
};

const MAXIMUM_CLIENT_ID_BYTES: usize = 256;
const MAXIMUM_PROFILE_REFERENCE_BYTES: usize = 4096;
const MAXIMUM_ENVIRONMENT_VARIABLE_BYTES: usize = 128;
const MAXIMUM_DEFINITION_HANDLE_BYTES: usize = 128;
const MAXIMUM_PURPOSE_BYTES: usize = 128;
const MAXIMUM_DEFINITION_PINS: usize = 128;
const MAXIMUM_RESOURCE_BYTES: usize = 4096;
const MAXIMUM_CONTRACT_DEFINITIONS: usize = 16_384;

/// Read a client profile: the profile, or every finding with its position.
///
/// `file` is the name diagnostics carry. Relative file references in the
/// profile resolve against the current directory; read a profile from disk
/// with [`EvidenceClientProfile::from_file`] to resolve them against the
/// profile's own directory.
pub fn read_client_profile(file: &str, bytes: &[u8]) -> Result<EvidenceClientProfile, Report> {
    let Decoded { value, document } =
        Reader::new(file).decode::<ProfileDocument>(bytes, &Expect::one(&PROFILE_FORMAT))?;
    let findings = value.base_url_findings(&document);
    if !findings.is_empty() {
        return Err(report(findings));
    }
    let profile = value.into_profile();
    if profile.validate().is_err() {
        return Err(report(vec![document.diagnostic_at_value(
            Severity::Error,
            "evidence.client.profile-invalid",
            "",
            "the client profile does not satisfy the profile rules",
            "Compare the profile with the published client profile schema and correct it.",
        )]));
    }
    Ok(profile)
}

/// Read a reviewed contracts file: the contracts, or every finding with its
/// position.
///
/// Each definition is held to the rules a published definition meets before
/// a request is prepared from it.
pub fn read_reviewed_contracts(file: &str, bytes: &[u8]) -> Result<ReviewedContracts, Report> {
    let Decoded { value, document } =
        Reader::new(file).decode::<ContractsDocument>(bytes, &Expect::one(&CONTRACTS_FORMAT))?;
    let mut contracts = ReviewedContracts {
        api_version: EVIDENCE_CLIENT_CONTRACTS_API_VERSION.to_owned(),
        kind: EVIDENCE_CLIENT_CONTRACTS_KIND.to_owned(),
        assurance_profile: value.assurance_profile,
        audience: value.audience.0,
        issued_by: value.issued_by.0,
        provided_by: value.provided_by.0,
        definitions: Vec::with_capacity(value.definitions.0.len()),
    };
    let mut findings = Vec::new();
    let mut handles = BTreeSet::new();
    for (index, item) in value.definitions.0.into_iter().enumerate() {
        let pointer = format!("/definitions/{index}");
        let Ok(definition) = serde_json::from_value::<EvidenceDefinition>(item) else {
            findings.push(document.diagnostic_at_value(
                Severity::Error,
                "evidence.client.definition-shape",
                &pointer,
                "the definition does not have the shape of a published Evidence definition",
                "Fetch the contracts again with `evidencectl client contracts fetch` and review the new file.",
            ));
            continue;
        };
        if !handles.insert(definition.handle.clone()) {
            findings.push(document.diagnostic_at_value(
                Severity::Error,
                "evidence.client.duplicate-definition",
                &format!("{pointer}/handle"),
                "another definition in this file has the same handle",
                "Keep one definition per handle; fetch the contracts again if the file was edited.",
            ));
        } else if !definition_is_requestable(&contracts, &definition) {
            findings.push(document.diagnostic_at_value(
                Severity::Error,
                "evidence.client.definition-invalid",
                &pointer,
                "the definition is outside the bounds a published Evidence definition meets",
                "Fetch the contracts again with `evidencectl client contracts fetch` and review the new file.",
            ));
        }
        contracts.definitions.push(definition);
    }
    if !findings.is_empty() {
        return Err(report(findings));
    }
    if contracts.validate().is_err() {
        return Err(report(vec![document.diagnostic_at_value(
            Severity::Error,
            "evidence.client.contracts-invalid",
            "",
            "the contracts do not satisfy the contract rules",
            "Fetch the contracts again with `evidencectl client contracts fetch` and review the new file.",
        )]));
    }
    Ok(contracts)
}

fn report(diagnostics: Vec<Diagnostic>) -> Report {
    let mut report = Report::new(diagnostics);
    report.set_files_checked(1);
    report
}

/// Whether one definition passes the rules the whole catalog is held to,
/// checked alone so a failure names the definition.
fn definition_is_requestable(
    contracts: &ReviewedContracts,
    definition: &EvidenceDefinition,
) -> bool {
    EvidenceDefinitionsDocument {
        schema: EVIDENCE_DEFINITIONS_SCHEMA_V1.to_owned(),
        assurance_profile: contracts.assurance_profile,
        audience: contracts.audience.clone(),
        issued_by: contracts.issued_by.clone(),
        provided_by: contracts.provided_by.clone(),
        maximum_holder_bound_batch_size: 1,
        definitions: vec![definition.clone()],
    }
    .validate_for_request()
    .is_ok()
}

/// An Evidence relying-party client profile: where the Evidence service is,
/// how this client authenticates to it, which keys and contracts it trusts,
/// and what it expects the service to assert.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileDocument {
    /// The Evidence service origin: scheme, host, and port, with no path,
    /// query, fragment, or trailing slash, in lowercase. It uses `https`,
    /// except `http://127.0.0.1:<port>` under `local-loopback-discovery`
    /// trust. Under `https-discovery` and `pinned-jwks` trust the host is not
    /// a loopback, private, link-local, unspecified, or cloud metadata
    /// address.
    pub(crate) base_url: Url,
    /// The client identifier the Evidence service's token issuer knows this
    /// client by.
    pub(crate) client_id: ClientId,
    /// Where the client's private signing key, a JSON Web Key, is read from.
    pub(crate) private_key: PrivateKeyMember,
    /// How the client learns the keys that sign Evidence responses. Omitted,
    /// it fetches the service's published keys over https.
    #[serde(default)]
    pub(crate) trust: Option<TrustMember>,
    /// Which definitions the client may request. Omitted, it uses the
    /// definitions the service publishes for it.
    #[serde(default)]
    pub(crate) contracts: Option<ContractsMember>,
    /// Bounds on the assertions the client accepts.
    #[serde(default)]
    pub(crate) verification: Option<VerificationMember>,
    /// What the client expects the service to state about itself and about
    /// the definitions it requests.
    #[serde(default)]
    pub(crate) expected: Option<ExpectedMember>,
    /// Fixed OAuth request parameters for the token acquisition, for issuers
    /// whose client-assertion audience, resource indicator, or requested
    /// scopes are not derivable from discovery. Omitted members keep the
    /// discovery-driven behavior.
    #[serde(default)]
    pub(crate) oauth: Option<OauthMember>,
    /// How long the client keeps the service's discovery metadata, in
    /// seconds. Omitted, it is 600.
    #[serde(default)]
    pub(crate) maximum_metadata_cache_seconds:
        Option<BoundedU64<1, MAXIMUM_METADATA_CACHE_SECONDS>>,
}

impl ProfileDocument {
    /// The findings about `baseUrl` that depend on the trust type.
    fn base_url_findings(&self, document: &Document) -> Vec<Diagnostic> {
        let finding = |code: &str, message: &str, action: &str| {
            vec![document.diagnostic_at_value(Severity::Error, code, "/baseUrl", message, action)]
        };
        let parsed = self.base_url.to_url();
        if self.base_url.as_str() != parsed.origin().ascii_serialization() {
            return finding(
                "evidence.client.base-url-not-origin",
                "the base URL is not a bare origin",
                "Write only the scheme, host, and port, in lowercase, with no path, query, fragment, or trailing slash.",
            );
        }
        match self.trust {
            Some(TrustMember::LocalLoopbackDiscovery {}) => {
                let loopback = parsed.scheme() == "http"
                    && parsed.host_str() == Some("127.0.0.1")
                    && parsed.port().is_some_and(|port| port != 0);
                if loopback {
                    Vec::new()
                } else {
                    finding(
                        "evidence.client.base-url-not-loopback",
                        "local-loopback-discovery trust needs an http origin on 127.0.0.1 with an explicit port",
                        "Write http://127.0.0.1:<port>, or choose https-discovery trust for a remote service.",
                    )
                }
            }
            None | Some(TrustMember::HttpsDiscovery {}) | Some(TrustMember::PinnedJwks { .. }) => {
                if !self.base_url.is_https() {
                    finding(
                        "evidence.client.base-url-not-https",
                        "the base URL does not use https under this trust type",
                        "Use an https origin, or set trust.type to local-loopback-discovery for a service on http://127.0.0.1 during local development.",
                    )
                } else if strict_fetch_refuses_literal_origin(&parsed) {
                    finding(
                        "evidence.client.base-url-literal-address",
                        "the base URL names a loopback, private, link-local, unspecified, or cloud metadata address, which discovery refuses to fetch",
                        "Use the service's public host name, or set trust.type to local-loopback-discovery for a service on 127.0.0.1.",
                    )
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn into_profile(self) -> EvidenceClientProfile {
        let verification = self.verification.unwrap_or_default();
        let defaults = VerificationProfile::default();
        let expected = self.expected.unwrap_or_default();
        EvidenceClientProfile {
            api_version: EVIDENCE_CLIENT_PROFILE_API_VERSION.to_owned(),
            kind: EVIDENCE_CLIENT_PROFILE_KIND.to_owned(),
            base_url: self.base_url.into_string(),
            client_id: self.client_id.0,
            private_key: match self.private_key {
                PrivateKeyMember::File { path } => PrivateKeyReference::File { path: path.0 },
                PrivateKeyMember::Environment { variable } => PrivateKeyReference::Environment {
                    variable: variable.0,
                },
            },
            trust: match self.trust {
                None | Some(TrustMember::HttpsDiscovery {}) => TrustProfile::HttpsDiscovery,
                Some(TrustMember::LocalLoopbackDiscovery {}) => {
                    TrustProfile::LocalLoopbackDiscovery
                }
                Some(TrustMember::PinnedJwks { file }) => TrustProfile::PinnedJwks { file: file.0 },
            },
            contracts: match self.contracts {
                None | Some(ContractsMember::Published {}) => ContractsProfile::Published,
                Some(ContractsMember::Reviewed { file }) => {
                    ContractsProfile::Reviewed { file: file.0 }
                }
            },
            verification: VerificationProfile {
                maximum_assertion_lifetime_seconds: verification
                    .maximum_assertion_lifetime_seconds
                    .map_or(defaults.maximum_assertion_lifetime_seconds, BoundedU64::get),
                clock_skew_seconds: verification
                    .clock_skew_seconds
                    .map_or(defaults.clock_skew_seconds, BoundedU64::get),
            },
            expected: ExpectedServiceProfile {
                audience: expected.audience.map(|value| value.0),
                issuer: expected.issuer.map(|value| value.0),
                provider: expected.provider.map(|value| value.0),
                definitions: expected
                    .definitions
                    .map(|pins| pins.0)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(handle, pin)| (handle.0, pin.into_profile()))
                    .collect(),
            },
            oauth: self.oauth.map(|oauth| OauthProfile {
                client_assertion_audience: oauth.client_assertion_audience.map(|value| value.0),
                resource: oauth.resource.map(|value| value.0),
                scopes: oauth.scopes.map(|scopes| {
                    scopes
                        .0
                        .into_vec()
                        .into_iter()
                        .map(|scope| scope.0)
                        .collect()
                }),
            }),
            maximum_metadata_cache_seconds: self
                .maximum_metadata_cache_seconds
                .map_or(DEFAULT_METADATA_CACHE_SECONDS, BoundedU64::get),
            origin_directory: None,
        }
    }
}

/// Where the client's private signing key is read from: a file, or an
/// environment variable holding the JSON Web Key.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    deny_unknown_fields,
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub(crate) enum PrivateKeyMember {
    /// A file holding the key; a relative path resolves against the
    /// profile's directory.
    File { path: ProfilePath },
    /// An environment variable holding the key.
    Environment { variable: EnvironmentName },
}
tagged_union!(PrivateKeyMember);

/// How the client learns the keys that sign Evidence responses.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    deny_unknown_fields,
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub(crate) enum TrustMember {
    /// Fetch the service's published keys over https.
    HttpsDiscovery {},
    /// Fetch the published keys of a service on `http://127.0.0.1`, for
    /// local development only.
    LocalLoopbackDiscovery {},
    /// Trust only the keys in a reviewed JSON Web Key Set file; a relative
    /// path resolves against the profile's directory.
    PinnedJwks { file: ProfilePath },
}
tagged_union!(TrustMember);

/// Which definitions the client may request.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    deny_unknown_fields,
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub(crate) enum ContractsMember {
    /// The definitions the service publishes for this client.
    Published {},
    /// Only the definitions in a reviewed contracts file, written by
    /// `evidencectl client contracts fetch`; a relative path resolves against
    /// the profile's directory.
    Reviewed { file: ProfilePath },
}
tagged_union!(ContractsMember);

/// Bounds on the assertions the client accepts.
#[derive(Default, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VerificationMember {
    /// The longest validity an accepted assertion may state, in seconds.
    /// Omitted, it is 300.
    #[serde(default)]
    pub(crate) maximum_assertion_lifetime_seconds: Option<BoundedU64<1, 31_536_000>>,
    /// The clock difference tolerated when checking an assertion's times, in
    /// seconds. Omitted, it is 30.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "schema::clock_skew_seconds")
    )]
    pub(crate) clock_skew_seconds: Option<BoundedU64<0, 300>>,
}

/// What the client expects the service to state.
#[derive(Default, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExpectedMember {
    /// The audience an accepted assertion names.
    #[serde(default)]
    pub(crate) audience: Option<UriIdentity>,
    /// The issuer an accepted assertion names. It is an identity the service
    /// states, compared exactly, not a URL the client fetches.
    #[serde(default)]
    pub(crate) issuer: Option<UriIdentity>,
    /// The provider an accepted assertion names.
    #[serde(default)]
    pub(crate) provider: Option<UriIdentity>,
    /// Pins for selected definition handles. A service may publish other
    /// definitions without changing the meaning of this profile.
    #[serde(default)]
    pub(crate) definitions: Option<DefinitionPins>,
}

/// What the client expects of one definition it requests.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExpectedDefinitionMember {
    /// The definition's configuration revision.
    pub(crate) configuration_revision: Digest,
    /// The evidence type an assertion for the definition names.
    pub(crate) evidence_type: UriIdentity,
    /// The purpose the client states when it requests the definition.
    pub(crate) purpose: Purpose,
    /// The assurance profile the service states.
    pub(crate) assurance_profile: AssuranceProfile,
    /// The response format the client requests.
    pub(crate) response_format: ExpectedResponseFormat,
}

impl ExpectedDefinitionMember {
    fn into_profile(self) -> ExpectedDefinitionProfile {
        ExpectedDefinitionProfile {
            configuration_revision: self.configuration_revision.into_string(),
            evidence_type: self.evidence_type.0,
            purpose: self.purpose.0,
            assurance_profile: self.assurance_profile,
            response_format: match self.response_format {
                ExpectedResponseFormat::SignedJws => EvidenceResponseFormat::SignedJws,
                ExpectedResponseFormat::SdJwtVc => EvidenceResponseFormat::SdJwtVc,
            },
        }
    }
}

/// A response format the client verifies on its own.
#[derive(Clone, Copy, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ExpectedResponseFormat {
    /// A flattened JWS carrying the Evidence payload.
    SignedJws,
    /// A compact SD-JWT VC carrying the same payload.
    SdJwtVc,
}

/// Fixed OAuth request parameters for the token acquisition.
///
/// `clientAssertionAudience` is who checks the client's authentication JWT;
/// `resource` is the RFC 8707 resource indicator the token's audience must
/// name. Neither is `expected.audience`, the Evidence assertion's audience.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OauthMember {
    /// The audience of the client's authentication JWT.
    #[serde(default)]
    pub(crate) client_assertion_audience: Option<UriIdentity>,
    /// The resource indicator the token request carries.
    #[serde(default)]
    pub(crate) resource: Option<ResourceIndicator>,
    /// The scopes the token request asks for.
    #[serde(default)]
    pub(crate) scopes: Option<Scopes>,
}

/// A reviewed snapshot of the definitions an Evidence service publishes for
/// one requester, written by `evidencectl client contracts fetch` and
/// promoted after review. It holds no source plan, script, credential,
/// requester tag, authority profile, selector value, codelist, or internal
/// constraint.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContractsDocument {
    /// The assurance profile the service states.
    pub(crate) assurance_profile: AssuranceProfile,
    /// The audience the definitions are scoped to.
    pub(crate) audience: UriIdentity,
    /// The service that issues assertions for the definitions.
    pub(crate) issued_by: UriIdentity,
    /// The provider the definitions describe.
    pub(crate) provided_by: UriIdentity,
    /// The definitions, as the service published them.
    pub(crate) definitions: ContractDefinitions,
}

macro_rules! checked_text {
    ($name:ident, $check:expr, $expected:literal, $action:literal) => {
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                let check: fn(&str) -> bool = $check;
                if check(&text) {
                    Ok(Self(text.into()))
                } else {
                    Err(Invalid::expected($expected, $action).into_error())
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(stringify!($name))
            }
        }
    };
}

/// A client identifier: 1 to 256 bytes, no control characters.
pub(crate) struct ClientId(String);

checked_text!(
    ClientId,
    |text| ExternalId::new(text).is_ok() && text.len() <= MAXIMUM_CLIENT_ID_BYTES,
    "a client identifier of 1 to 256 bytes with no control characters",
    "Write the client identifier the token issuer registered for this client."
);

/// A file reference: 1 to 4096 bytes, no control characters.
pub(crate) struct ProfilePath(PathBuf);

checked_text!(
    ProfilePath,
    |text| !text.is_empty()
        && text.len() <= MAXIMUM_PROFILE_REFERENCE_BYTES
        && !text.chars().any(char::is_control),
    "a file path of 1 to 4096 bytes with no control characters",
    "Write the path of the file, relative to the profile's directory or absolute."
);

/// An environment variable name.
pub(crate) struct EnvironmentName(String);

checked_text!(
    EnvironmentName,
    |text| {
        let mut bytes = text.bytes();
        text.len() <= MAXIMUM_ENVIRONMENT_VARIABLE_BYTES
            && bytes
                .next()
                .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
            && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    },
    "an environment variable name: a letter or `_`, then letters, digits, or `_`, at most 128 bytes",
    "Write the name of the environment variable that holds the key, such as EVIDENCE_CLIENT_KEY."
);

/// An absolute URI the service states as an identity, compared exactly.
pub(crate) struct UriIdentity(String);

checked_text!(
    UriIdentity,
    |text| !text.is_empty()
        && text.len() <= MAXIMUM_IDENTIFIER_BYTES
        && url::Url::parse(text).is_ok_and(|url| !url.scheme().is_empty()),
    "an absolute URI of at most 512 bytes",
    "Write the identity exactly as the Evidence service publishes it, scheme included."
);

/// A definition handle.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DefinitionHandle(String);

checked_text!(
    DefinitionHandle,
    |text| !text.is_empty()
        && text.len() <= MAXIMUM_DEFINITION_HANDLE_BYTES
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        }),
    "a definition handle of 1 to 128 lowercase letters, digits, `.`, `_`, or `-`",
    "Write the handle exactly as the service's published definition names it."
);

/// A request purpose.
pub(crate) struct Purpose(String);

checked_text!(
    Purpose,
    |text| !text.is_empty()
        && text.len() <= MAXIMUM_PURPOSE_BYTES
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b':')
        }),
    "a purpose of 1 to 128 lowercase letters, digits, `.`, `_`, `:`, or `-`",
    "Write the purpose exactly as the service's published definition names it."
);

/// An RFC 8707 resource indicator.
pub(crate) struct ResourceIndicator(String);

checked_text!(
    ResourceIndicator,
    |text| text.len() <= MAXIMUM_RESOURCE_BYTES
        && registry_platform_httputil::valid_resource_uri(text),
    "an absolute URI of at most 4096 bytes with no fragment or user information",
    "Write the resource indicator the token issuer expects for the Evidence service."
);

/// An RFC 6749 scope token.
#[derive(PartialEq, Eq, Hash)]
pub(crate) struct ScopeToken(String);

checked_text!(
    ScopeToken,
    |text| text.len() <= registry_platform_httputil::MAXIMUM_REQUESTED_SCOPE_BYTES
        && registry_platform_httputil::valid_scope_token(text),
    "an OAuth scope token of 1 to 256 printable ASCII characters other than space, `\"`, and `\\`",
    "Write one scope per list item, without spaces."
);

/// The scopes a token request asks for: 1 to 32 distinct scope tokens.
pub(crate) struct Scopes(UniqueList<ScopeToken>);

impl<'de> Deserialize<'de> for Scopes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let scopes = UniqueList::<ScopeToken>::deserialize(deserializer)?;
        if scopes.is_empty() || scopes.len() > registry_platform_httputil::MAXIMUM_REQUESTED_SCOPES
        {
            return Err(Invalid::expected(
                "a list of 1 to 32 scopes",
                "List the scopes the token request asks for, or leave scopes out to ask for none.",
            )
            .into_error());
        }
        Ok(Self(scopes))
    }
}

/// Pins for at most 128 definition handles.
#[derive(Default)]
pub(crate) struct DefinitionPins(BTreeMap<DefinitionHandle, ExpectedDefinitionMember>);

impl<'de> Deserialize<'de> for DefinitionPins {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let pins =
            BTreeMap::<DefinitionHandle, ExpectedDefinitionMember>::deserialize(deserializer)?;
        if pins.len() > MAXIMUM_DEFINITION_PINS {
            return Err(Invalid::expected(
                "at most 128 pinned definitions",
                "Pin only the definitions this client requests.",
            )
            .into_error());
        }
        Ok(Self(pins))
    }
}

/// The definitions of a contracts file, each kept as written until it is
/// read as a published definition.
pub(crate) struct ContractDefinitions(Vec<serde_json::Value>);

impl<'de> Deserialize<'de> for ContractDefinitions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let definitions = Vec::<serde_json::Value>::deserialize(deserializer)?;
        if definitions.len() > MAXIMUM_CONTRACT_DEFINITIONS {
            return Err(Invalid::expected(
                "at most 16384 definitions",
                "Fetch the contracts again with `evidencectl client contracts fetch` and review the new file.",
            )
            .into_error());
        }
        Ok(Self(definitions))
    }
}

#[cfg(feature = "schema")]
mod schema {
    use std::borrow::Cow;

    use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};

    use super::*;

    macro_rules! text_schema {
        ($name:ident, $schema:tt) => {
            impl JsonSchema for $name {
                fn schema_name() -> Cow<'static, str> {
                    Cow::Borrowed(stringify!($name))
                }

                fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                    json_schema!($schema)
                }
            }
        };
    }

    impl JsonSchema for ClientId {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("ClientId")
        }

        fn json_schema(generator: &mut SchemaGenerator) -> Schema {
            let mut schema = generator.subschema_for::<ExternalId>();
            schema.insert(
                "description".to_owned(),
                "A client identifier of at most 256 bytes.".into(),
            );
            schema.insert("maxLength".to_owned(), MAXIMUM_CLIENT_ID_BYTES.into());
            schema
        }
    }

    text_schema!(ProfilePath, {
        "type": "string",
        "minLength": 1,
        "maxLength": MAXIMUM_PROFILE_REFERENCE_BYTES,
        "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        "description": "A file path, relative to the profile's directory or absolute.",
    });

    text_schema!(EnvironmentName, {
        "type": "string",
        "pattern": "^[A-Za-z_][A-Za-z0-9_]{0,127}$",
        "description": "An environment variable name.",
    });

    text_schema!(UriIdentity, {
        "type": "string",
        "format": "uri",
        "minLength": 1,
        "maxLength": MAXIMUM_IDENTIFIER_BYTES,
        "description": "An absolute URI the service states as an identity, compared exactly.",
    });

    text_schema!(Purpose, {
        "type": "string",
        "pattern": "^[a-z0-9._:-]{1,128}$",
        "description": "A request purpose.",
    });

    text_schema!(ResourceIndicator, {
        "type": "string",
        "format": "uri",
        "maxLength": MAXIMUM_RESOURCE_BYTES,
        "description": "An RFC 8707 resource indicator: an absolute URI with no fragment.",
    });

    text_schema!(ScopeToken, {
        "type": "string",
        "pattern": "^[!#-\\[\\]-~]{1,256}$",
        "description": "An RFC 6749 scope token.",
    });

    impl JsonSchema for Scopes {
        fn inline_schema() -> bool {
            true
        }

        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("Scopes")
        }

        fn json_schema(generator: &mut SchemaGenerator) -> Schema {
            let mut schema = generator.subschema_for::<UniqueList<ScopeToken>>();
            schema.insert("minItems".to_owned(), 1.into());
            schema.insert(
                "maxItems".to_owned(),
                registry_platform_httputil::MAXIMUM_REQUESTED_SCOPES.into(),
            );
            schema
        }
    }

    impl JsonSchema for DefinitionPins {
        fn inline_schema() -> bool {
            true
        }

        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("DefinitionPins")
        }

        fn json_schema(generator: &mut SchemaGenerator) -> Schema {
            let mut handle = generator.subschema_for::<ExternalId>();
            handle.insert("pattern".to_owned(), "^[a-z0-9._-]{1,128}$".into());
            let pin = generator.subschema_for::<ExpectedDefinitionMember>();
            json_schema!({
                "type": "object",
                "maxProperties": MAXIMUM_DEFINITION_PINS,
                "propertyNames": handle,
                "additionalProperties": pin,
            })
        }
    }

    /// A zero minimum is a stated bound here: no tolerance at all is a valid
    /// setting. The shared bounded type writes it beside the unsigned
    /// format, where it reads as the type's implicit bound, so the member's
    /// schema leaves the format out and keeps both bounds.
    pub(super) fn clock_skew_seconds(generator: &mut SchemaGenerator) -> Schema {
        let mut schema = <BoundedU64<0, 300>>::json_schema(generator);
        schema.remove("format");
        schema
    }

    impl JsonSchema for ContractDefinitions {
        fn inline_schema() -> bool {
            true
        }

        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("ContractDefinitions")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            // Each definition is held as the service published it, so its
            // shape is the published Evidence definitions contract's, which
            // owns it.
            json_schema!({
                "type": "array",
                "maxItems": MAXIMUM_CONTRACT_DEFINITIONS,
                "uniqueItems": true,
                "items": {"$ref": PUBLISHED_DEFINITION_SCHEMA},
            })
        }
    }

    /// The definition shape in the published Evidence definitions contract.
    pub(crate) const PUBLISHED_DEFINITION_SCHEMA: &str =
        "https://registrystack.org/schemas/evidence/definitions-v1.json#/$defs/definition";
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn profile() -> Value {
        json!({
            "apiVersion": EVIDENCE_CLIENT_PROFILE_API_VERSION,
            "kind": EVIDENCE_CLIENT_PROFILE_KIND,
            "baseUrl": "https://evidence.example.org",
            "clientId": "relying-party",
            "privateKey": {"type": "environment", "variable": "EVIDENCE_CLIENT_KEY"}
        })
    }

    fn definition(handle: &str) -> Value {
        json!({
            "handle": handle,
            "requirement": "https://example.org/requirements/adult-status",
            "configurationRevision": format!("sha256:{}", "a".repeat(64)),
            "kind": "criterion",
            "evidenceType": "https://example.org/evidence/adult-status",
            "purpose": "benefit.eligibility",
            "responseFormats": ["signed-jws"],
            "referenceFrameworks": ["https://example.org/frameworks/benefits"],
            "subjects": [{
                "role": "applicant",
                "cardinality": "one",
                "selector": {
                    "profile": "national-id",
                    "valueOrigin": "request",
                    "fields": [{"type": "string", "name": "id", "minimumBytes": 1, "maximumBytes": 32}]
                }
            }],
            "concepts": [{
                "handle": "adult",
                "concept": "https://example.org/concepts/adult",
                "required": true,
                "form": {"type": "boolean"}
            }]
        })
    }

    fn contracts(definitions: Vec<Value>) -> Value {
        json!({
            "apiVersion": EVIDENCE_CLIENT_CONTRACTS_API_VERSION,
            "kind": EVIDENCE_CLIENT_CONTRACTS_KIND,
            "assuranceProfile": "production",
            "audience": "https://relying-party.example.org",
            "issuedBy": "https://evidence.example.org",
            "providedBy": "https://registry.example.org",
            "definitions": definitions
        })
    }

    fn read_profile(document: &Value) -> Result<EvidenceClientProfile, Report> {
        read_client_profile(
            "profile.json",
            serde_json::to_string_pretty(document).unwrap().as_bytes(),
        )
    }

    /// The one finding a refused document carries, as (code, path).
    fn finding(result: Result<impl Sized, Report>) -> (String, String) {
        let Err(report) = result else {
            panic!("the document was accepted");
        };
        let diagnostics = report.into_diagnostics();
        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        let diagnostic = &diagnostics[0];
        assert!(diagnostic.source.is_some(), "the finding has a position");
        assert!(!diagnostic.suggested_action.is_empty());
        (diagnostic.code.clone(), diagnostic.path.clone())
    }

    #[test]
    fn a_minimal_profile_reads_with_its_documented_defaults() {
        let profile = read_profile(&profile()).unwrap();
        assert!(matches!(profile.trust, TrustProfile::HttpsDiscovery));
        assert!(matches!(profile.contracts, ContractsProfile::Published));
        assert_eq!(profile.verification.maximum_assertion_lifetime_seconds, 300);
        assert_eq!(profile.verification.clock_skew_seconds, 30);
        assert_eq!(
            profile.maximum_metadata_cache_seconds,
            DEFAULT_METADATA_CACHE_SECONDS
        );
        assert!(profile.oauth.is_none());
        assert!(profile.expected.definitions.is_empty());
    }

    #[test]
    fn base_url_findings_are_positioned_and_name_their_fix() {
        for (base_url, trust, code) in [
            (
                "https://evidence.example.org/",
                None,
                "evidence.client.base-url-not-origin",
            ),
            (
                "https://Evidence.example.org",
                None,
                "evidence.client.base-url-not-origin",
            ),
            (
                "http://evidence.example.org",
                None,
                "evidence.client.base-url-not-https",
            ),
            (
                "https://10.0.0.8",
                None,
                "evidence.client.base-url-literal-address",
            ),
            (
                "https://169.254.169.254",
                Some(json!({"type": "pinned-jwks", "file": "evidence.jwks.json"})),
                "evidence.client.base-url-literal-address",
            ),
            (
                "https://evidence.example.org",
                Some(json!({"type": "local-loopback-discovery"})),
                "evidence.client.base-url-not-loopback",
            ),
            (
                "http://127.0.0.1:0",
                Some(json!({"type": "local-loopback-discovery"})),
                "evidence.client.base-url-not-loopback",
            ),
        ] {
            let mut document = profile();
            document["baseUrl"] = Value::from(base_url);
            if let Some(trust) = trust {
                document["trust"] = trust;
            }
            let result = read_profile(&document);
            if let Err(report) = &result {
                for diagnostic in report.diagnostics() {
                    assert!(!diagnostic.message.contains(base_url), "{base_url}");
                    assert!(
                        !diagnostic.suggested_action.contains(base_url),
                        "{base_url}"
                    );
                }
            }
            assert_eq!(
                finding(result),
                (code.to_owned(), "/baseUrl".to_owned()),
                "{base_url}"
            );
        }
        let mut loopback = profile();
        loopback["baseUrl"] = Value::from("http://127.0.0.1:8080");
        loopback["trust"] = json!({"type": "local-loopback-discovery"});
        read_profile(&loopback).unwrap();
    }

    #[test]
    fn member_shapes_are_refused_where_they_are_written() {
        for (path, member, value) in [
            ("/clientId", "clientId", Value::from("a\u{7}b")),
            ("/clientId", "clientId", Value::from("a".repeat(257))),
            (
                "/privateKey/variable",
                "privateKey",
                json!({"type": "environment", "variable": "1KEY"}),
            ),
            (
                "/expected/issuer",
                "expected",
                json!({"issuer": "evidence.example.org"}),
            ),
            ("/oauth/scopes", "oauth", json!({"scopes": []})),
            (
                "/maximumMetadataCacheSeconds",
                "maximumMetadataCacheSeconds",
                Value::from(601),
            ),
            (
                "/verification/clockSkewSeconds",
                "verification",
                json!({"clockSkewSeconds": 301}),
            ),
        ] {
            let mut document = profile();
            document[member] = value;
            assert_eq!(finding(read_profile(&document)).1, path);
        }
    }

    #[test]
    fn the_reader_refuses_what_the_published_shape_does_not_allow() {
        let mut unknown = profile();
        unknown["version"] = Value::from(1);
        assert_eq!(finding(read_profile(&unknown)).1, "/version");

        let mut null = profile();
        null["oauth"] = Value::Null;
        assert_eq!(
            finding(read_profile(&null)),
            ("config.null-value".to_owned(), "/oauth".to_owned())
        );

        let mut batch = profile();
        batch["expected"] = json!({"definitions": {"adult-status": {
            "configurationRevision": format!("sha256:{}", "a".repeat(64)),
            "evidenceType": "https://example.org/evidence/adult-status",
            "purpose": "benefit.eligibility",
            "assuranceProfile": "production",
            "responseFormat": "sd-jwt-vc-batch"
        }}});
        assert_eq!(
            finding(read_profile(&batch)).1,
            "/expected/definitions/adult-status/responseFormat"
        );

        let duplicate =
            br#"{"apiVersion": "id.registrystack.org/formats/evidence/client-profile/v1",
            "kind": "EvidenceClientProfile",
            "baseUrl": "https://evidence.example.org", "clientId": "a", "clientId": "b",
            "privateKey": {"type": "environment", "variable": "KEY"}}"#;
        assert_eq!(
            finding(read_client_profile("profile.json", duplicate)).0,
            "yaml.duplicate-key"
        );
    }

    #[test]
    fn json_written_by_tools_and_people_reads_unchanged() {
        let compact = serde_json::to_vec(&profile()).unwrap();
        read_client_profile("profile.json", &compact).unwrap();

        let escaped =
            br#"{"apiVersion":"id.registrystack.org\/formats\/evidence\/client-profile\/v1",
            "kind":"EvidenceClientProfile",
            "baseUrl":"https:\/\/evidence.example.org","clientId":"rp",
            "privateKey":{"type":"file","path":"keys\/rp.jwk.json"}}"#;
        let profile = read_client_profile("profile.json", escaped).unwrap();
        assert_eq!(profile.client_id, "rp");

        let tabbed = b"{\n\t\"apiVersion\": \"id.registrystack.org/formats/evidence/client-profile/v1\",\n\t\"kind\": \"EvidenceClientProfile\",\n\t\"baseUrl\": \"https://evidence.example.org\",\n\t\"clientId\": \"rp\",\n\t\"privateKey\": {\"type\": \"environment\", \"variable\": \"KEY\"}\n}\n";
        read_client_profile("profile.json", tabbed).unwrap();

        let contracts = serde_json::to_vec(&contracts(vec![definition("adult-status")])).unwrap();
        let read = read_reviewed_contracts("evidence.contracts.json", &contracts).unwrap();
        assert_eq!(read.definitions.len(), 1);
        assert_eq!(read.definitions[0].handle, "adult-status");
    }

    #[test]
    fn contract_findings_name_the_definition() {
        let mut shapeless = definition("adult-status");
        shapeless["kind"] = Value::from("opinion");
        assert_eq!(
            finding(read_reviewed_contracts(
                "evidence.contracts.json",
                &serde_json::to_vec(&contracts(vec![definition("other"), shapeless])).unwrap()
            )),
            (
                "evidence.client.definition-shape".to_owned(),
                "/definitions/1".to_owned()
            )
        );

        assert_eq!(
            finding(read_reviewed_contracts(
                "evidence.contracts.json",
                &serde_json::to_vec(&contracts(vec![
                    definition("adult-status"),
                    definition("adult-status")
                ]))
                .unwrap()
            )),
            (
                "evidence.client.duplicate-definition".to_owned(),
                "/definitions/1/handle".to_owned()
            )
        );

        let mut unbounded = definition("adult-status");
        unbounded["purpose"] = Value::from("Benefit");
        assert_eq!(
            finding(read_reviewed_contracts(
                "evidence.contracts.json",
                &serde_json::to_vec(&contracts(vec![unbounded])).unwrap()
            )),
            (
                "evidence.client.definition-invalid".to_owned(),
                "/definitions/0".to_owned()
            )
        );

        let mut header = contracts(Vec::new());
        header["apiVersion"] = Value::from("id.registrystack.org/formats/evidence/definitions/v1");
        assert_eq!(
            finding(read_reviewed_contracts(
                "evidence.contracts.json",
                &serde_json::to_vec(&header).unwrap()
            ))
            .1,
            "/apiVersion"
        );
    }

    /// The removed-key finding at `path`, among the findings of a refused
    /// document.
    fn removed_key(result: Result<impl Sized, Report>, path: &str) -> Diagnostic {
        let Err(report) = result else {
            panic!("the document was accepted");
        };
        report
            .into_diagnostics()
            .into_iter()
            .find(|diagnostic| diagnostic.code == "config.removed-key" && diagnostic.path == path)
            .unwrap_or_else(|| panic!("no config.removed-key at {path}"))
    }

    #[test]
    fn the_client_files_open_with_the_envelope_and_refuse_the_schema_header() {
        let enveloped = json!({
            "apiVersion": "id.registrystack.org/formats/evidence/client-profile/v1",
            "kind": "EvidenceClientProfile",
            "baseUrl": "https://evidence.example.org",
            "clientId": "relying-party",
            "privateKey": {"type": "environment", "variable": "EVIDENCE_CLIENT_KEY"}
        });
        let read = read_profile(&enveloped).expect("the enveloped profile reads");
        assert_eq!(
            read.api_version,
            "id.registrystack.org/formats/evidence/client-profile/v1"
        );
        assert_eq!(read.kind, "EvidenceClientProfile");

        let mut headed = enveloped.clone();
        let members = headed.as_object_mut().unwrap();
        members.remove("apiVersion");
        members.remove("kind");
        members.insert(
            "schema".to_owned(),
            Value::from("registry.evidence-client-profile/v1"),
        );
        let refusal = removed_key(read_profile(&headed), "/schema");
        assert!(refusal.suggested_action.contains("apiVersion"));
        assert!(refusal.suggested_action.contains("EvidenceClientProfile"));
        assert!(!refusal.message.contains("registry.evidence-client-profile"));

        let mut tagged = enveloped.clone();
        tagged["privateKey"] = json!({"source": "environment", "variable": "EVIDENCE_CLIENT_KEY"});
        let refusal = removed_key(read_profile(&tagged), "/privateKey/source");
        assert!(refusal.suggested_action.contains("privateKey.type"));

        let mut other_kind = enveloped.clone();
        other_kind["kind"] = Value::from("EvidenceClientContracts");
        assert!(read_profile(&other_kind).is_err());

        let contracts = json!({
            "apiVersion": "id.registrystack.org/formats/evidence/client-contracts/v1",
            "kind": "EvidenceClientContracts",
            "assuranceProfile": "production",
            "audience": "https://relying-party.example.org",
            "issuedBy": "https://evidence.example.org",
            "providedBy": "https://registry.example.org",
            "definitions": [definition("adult-status")]
        });
        let read = read_reviewed_contracts(
            "evidence.contracts.json",
            &serde_json::to_vec(&contracts).unwrap(),
        )
        .expect("the enveloped contracts read");
        assert_eq!(
            read.api_version,
            "id.registrystack.org/formats/evidence/client-contracts/v1"
        );
        assert_eq!(read.kind, "EvidenceClientContracts");

        let mut headed = contracts.clone();
        let members = headed.as_object_mut().unwrap();
        members.remove("apiVersion");
        members.remove("kind");
        members.insert(
            "schema".to_owned(),
            Value::from("registry.evidence-client-contracts/v1"),
        );
        let refusal = removed_key(
            read_reviewed_contracts(
                "evidence.contracts.json",
                &serde_json::to_vec(&headed).unwrap(),
            ),
            "/schema",
        );
        assert!(refusal.suggested_action.contains("apiVersion"));
        assert!(refusal.suggested_action.contains("EvidenceClientContracts"));
    }

    #[test]
    fn the_stated_bounds_are_the_shared_bounds() {
        assert_eq!(registry_platform_httputil::MAXIMUM_REQUESTED_SCOPES, 32);
        assert_eq!(
            registry_platform_httputil::MAXIMUM_REQUESTED_SCOPE_BYTES,
            256
        );
        assert_eq!(MAXIMUM_IDENTIFIER_BYTES, 512);
    }
}
