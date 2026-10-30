// SPDX-License-Identifier: Apache-2.0

//! Upstream authentication: the six closed kinds of
//! `products/adapter/CONCEPT.md` section 10.2.
//!
//! The kind and spelling are copied from `SourceAuthentication` in
//! `crates/registry-evidence/src/config.rs`, so an operator who configured
//! an Evidence source configures an adapter endpoint the same way; this
//! crate holds no dependency on Evidence. The two artifacts split the
//! fields by ownership: the pack endpoint declares only the API-intrinsic
//! facts (the kind, plus `headerName` for `static-api-key` and `scheme`
//! for `static-authorization`), and the runtime config binds everything
//! that varies per deployment, field for field as Evidence's variant
//! carries it minus those two. Secret references never appear in a pack;
//! authored files carry no secrets (CFG-SEC-1). No caller token is ever
//! forwarded upstream.

use registry_platform_yaml::{BoundedU64, SecretReference, Url};
use serde::{Deserialize, Serialize};

pub(crate) use crate::model::serialize_tagged_union;

/// Where a shared client secret travels, Evidence's `CredentialPlacement`
/// spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum CredentialPlacement {
    /// `Authorization: Basic` on the token request.
    BasicHeader,
    /// A form parameter on the token request.
    FormBody,
}

/// The authentication kind a pack endpoint declares
/// (`products/adapter/CONCEPT.md` section 10.2): the kind tag itself, plus
/// only the API-intrinsic parameters (`headerName` for `static-api-key`,
/// `scheme` for `static-authorization`). Every credential value lives in
/// the runtime config, in [`RuntimeCredential`].
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum EndpointAuthentication {
    /// Nothing is sent. The checks admit it only for a numeric-loopback
    /// origin or an endpoint with an mTLS client identity.
    None {},
    /// `Authorization: Basic` from the runtime's `usernameRef` and
    /// `passwordRef`.
    Basic {},
    /// `Authorization: <scheme> <token>` from the runtime's `tokenRef`;
    /// `scheme` defaults to `Bearer`, Evidence's spelling.
    StaticAuthorization {
        /// The RFC 9110 scheme the resolved token is presented under.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
    },
    /// One declared header from the runtime's `valueRef`; reserved header
    /// names are refused.
    StaticApiKey {
        /// The header the key travels under.
        #[serde(rename = "headerName")]
        header_name: String,
    },
    /// The RFC 6749 client-credentials grant with a shared secret; the
    /// runtime binds `tokenEndpoint`, `clientIdRef`, and `clientSecretRef`.
    Oauth2ClientCredentials {},
    /// The RFC 7523 private-key-jwt grant; the runtime binds
    /// `tokenEndpoint`, `clientIdRef`, and `clientAssertionKeyRef`. The
    /// signed assertion always travels in the form body, as in Evidence,
    /// so this kind carries no placement parameter.
    Oauth2PrivateKeyJwt {},
}

registry_platform_yaml::tagged_union!(EndpointAuthentication, tag = "type");
serialize_tagged_union!(EndpointAuthentication, tag = "type");

impl EndpointAuthentication {
    /// The kind tag this authentication serializes with, matching
    /// Evidence's `SourceAuthentication` tags.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::None {} => "none",
            Self::Basic {} => "basic",
            Self::StaticAuthorization { .. } => "static-authorization",
            Self::StaticApiKey { .. } => "static-api-key",
            Self::Oauth2ClientCredentials { .. } => "oauth2-client-credentials",
            Self::Oauth2PrivateKeyJwt { .. } => "oauth2-private-key-jwt",
        }
    }

    /// Whether token requests happen under this kind; the runtime config
    /// then carries the fixed token endpoint, as Evidence's variants do.
    #[must_use]
    pub const fn needs_token_endpoint(&self) -> bool {
        matches!(
            self,
            Self::Oauth2ClientCredentials { .. } | Self::Oauth2PrivateKeyJwt { .. }
        )
    }
}

/// The credential binding of one endpoint in the runtime config
/// (`products/adapter/CONCEPT.md` section 10.2): Evidence's
/// `SourceAuthentication` variant field for field, minus the pack-side
/// `headerName` and `scheme`. The kind must match the endpoint's declared
/// kind; the checks refuse a mismatch.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RuntimeCredential {
    /// No credential; matches a `none` endpoint.
    None {},
    /// The Basic credential pair.
    Basic {
        /// The username secret reference.
        #[serde(rename = "usernameRef")]
        username_ref: SecretReference,
        /// The password secret reference.
        #[serde(rename = "passwordRef")]
        password_ref: SecretReference,
    },
    /// The static token, presented under the endpoint's declared `scheme`.
    StaticAuthorization {
        /// The token secret reference.
        #[serde(rename = "tokenRef")]
        token_ref: SecretReference,
    },
    /// The static API key, sent in the endpoint's declared header.
    StaticApiKey {
        /// The key secret reference.
        #[serde(rename = "valueRef")]
        value_ref: SecretReference,
    },
    /// The client-credentials binding, Evidence's fields: the token
    /// endpoint, the client id, and the shared secret, all as references
    /// or fixed strings.
    Oauth2ClientCredentials {
        /// The token endpoint, a fixed destination never derived from a
        /// response; an absolute `http`/`https` URL the origin check
        /// confines like any other destination.
        #[serde(rename = "tokenEndpoint")]
        token_endpoint: Url,
        /// The client id secret reference.
        #[serde(rename = "clientIdRef")]
        client_id_ref: SecretReference,
        /// The shared client secret reference.
        #[serde(rename = "clientSecretRef")]
        client_secret_ref: SecretReference,
        /// The token-request scope parameter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        /// Fixed `audience` form parameter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        /// RFC 8707 resource indicator sent as a token-request form
        /// parameter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource: Option<String>,
        /// Where the shared client secret travels.
        #[serde(rename = "credentialPlacement")]
        credential_placement: CredentialPlacement,
        /// The token cache ceiling, Evidence's bound.
        #[serde(rename = "maximumCacheSeconds")]
        maximum_cache_seconds: BoundedU64<0, 86_400>,
        /// Lifetime assumed when the provider omits `expires_in`.
        #[serde(
            rename = "assumedLifetimeSeconds",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        assumed_lifetime_seconds: Option<BoundedU64<1, 86_400>>,
    },
    /// The private-key-jwt binding, Evidence's fields. The signed
    /// assertion always travels in the form body; there is no placement
    /// parameter.
    Oauth2PrivateKeyJwt {
        /// The token endpoint, a fixed destination never derived from a
        /// response; an absolute `http`/`https` URL the origin check
        /// confines like any other destination.
        #[serde(rename = "tokenEndpoint")]
        token_endpoint: Url,
        /// The client id secret reference.
        #[serde(rename = "clientIdRef")]
        client_id_ref: SecretReference,
        /// The private JWK the client assertion is signed with.
        #[serde(rename = "clientAssertionKeyRef")]
        client_assertion_key_ref: SecretReference,
        /// Audience claim of the signed assertion, defaulting to the
        /// token endpoint.
        #[serde(
            rename = "clientAssertionAudience",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        client_assertion_audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource: Option<String>,
        #[serde(rename = "maximumCacheSeconds")]
        maximum_cache_seconds: BoundedU64<0, 86_400>,
        #[serde(
            rename = "assumedLifetimeSeconds",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        assumed_lifetime_seconds: Option<BoundedU64<1, 86_400>>,
    },
}

registry_platform_yaml::tagged_union!(RuntimeCredential, tag = "type");
serialize_tagged_union!(RuntimeCredential, tag = "type");

impl RuntimeCredential {
    /// The kind tag this credential serializes with; it must equal the
    /// endpoint's declared kind.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::None {} => "none",
            Self::Basic { .. } => "basic",
            Self::StaticAuthorization { .. } => "static-authorization",
            Self::StaticApiKey { .. } => "static-api-key",
            Self::Oauth2ClientCredentials { .. } => "oauth2-client-credentials",
            Self::Oauth2PrivateKeyJwt { .. } => "oauth2-private-key-jwt",
        }
    }
}

/// The mTLS client identity of an endpoint, orthogonal to the
/// authentication kind (`products/adapter/CONCEPT.md` section 10.2). It is
/// the only way a `none` endpoint reaches a non-loopback source.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MtlsIdentity {
    /// The client certificate secret reference.
    pub certificate_ref: SecretReference,
    /// The client private key secret reference.
    pub key_ref: SecretReference,
}

/// Header names the engine owns; a `static-api-key` endpoint may not
/// declare one of them as its `headerName`: the names never
/// allowlistable on the wire (`products/adapter/CONCEPT.md` section
/// 8.11.4), plus `expect` the engine writes itself. Sorted for the
/// membership test; the hop-by-hop `Proxy-*` headers are matched by
/// prefix.
pub const RESERVED_HEADER_NAMES: &[&str] = &[
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "expect",
    "host",
    "keep-alive",
    "proxy-authorization",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Whether a `static-api-key` header name is reserved by the engine,
/// compared without case.
#[must_use]
pub fn is_reserved_header_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    RESERVED_HEADER_NAMES
        .binary_search(&lowered.as_str())
        .is_ok()
        || lowered.starts_with("proxy-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(name: &str) -> SecretReference {
        SecretReference::new(format!("secret:env/{name}")).expect("secret reference")
    }

    /// The six kinds round-trip with Evidence's tags; a pack endpoint
    /// carries the kind and only the API-intrinsic parameters.
    #[test]
    fn endpoint_authentication_round_trips() {
        let cases: Vec<(&str, &str)> = vec![
            (r#"{"type": "none"}"#, "none"),
            (r#"{"type": "basic"}"#, "basic"),
            (
                r#"{"type": "static-authorization", "scheme": "ApiToken"}"#,
                "static-authorization",
            ),
            (
                r#"{"type": "static-api-key", "headerName": "X-Api-Key"}"#,
                "static-api-key",
            ),
            (
                r#"{"type": "oauth2-client-credentials"}"#,
                "oauth2-client-credentials",
            ),
            (
                r#"{"type": "oauth2-private-key-jwt"}"#,
                "oauth2-private-key-jwt",
            ),
        ];
        for (json, tag) in cases {
            let auth: EndpointAuthentication = serde_json::from_str(json).expect("parse");
            assert_eq!(auth.kind(), tag);
            let back = serde_json::to_string(&auth).expect("serialize");
            let reparsed: EndpointAuthentication = serde_json::from_str(&back).expect("reparse");
            assert_eq!(reparsed, auth);
        }
    }

    /// An unknown kind, a stray credential value, or a deployment-varying
    /// field in the pack artifact is refused: the pack declares only the
    /// kind and its API-intrinsic parameters.
    #[test]
    fn pack_side_fields_beyond_the_kind_are_refused() {
        assert!(serde_json::from_str::<EndpointAuthentication>(r#"{"type": "ntlm"}"#).is_err());
        assert!(
            serde_json::from_str::<EndpointAuthentication>(
                r#"{"type": "basic", "passwordRef": "secret:env/PW"}"#
            )
            .is_err(),
            "the pack endpoint carries no secret references"
        );
        assert!(
            serde_json::from_str::<EndpointAuthentication>(
                r#"{"type": "oauth2-client-credentials", "tokenEndpoint": "https://token.example.invalid"}"#
            )
            .is_err(),
            "the token endpoint varies per deployment and lives in the runtime config"
        );
        assert!(
            serde_json::from_str::<EndpointAuthentication>(
                r#"{"type": "oauth2-private-key-jwt", "credentialPlacement": "form-body"}"#
            )
            .is_err(),
            "private-key-jwt carries no placement, as in Evidence"
        );
    }

    /// Runtime credentials round-trip per kind with Evidence's field
    /// spelling minus the pack-side `headerName` and `scheme`; the
    /// OAuth2 token endpoint is required.
    #[test]
    fn runtime_credentials_round_trip() {
        let cases: Vec<(&str, &str)> = vec![
            (r#"{"type": "none"}"#, "none"),
            (
                r#"{"type": "basic", "usernameRef": "secret:env/USER", "passwordRef": "secret:env/PASS"}"#,
                "basic",
            ),
            (
                r#"{"type": "static-authorization", "tokenRef": "secret:env/TOKEN"}"#,
                "static-authorization",
            ),
            (
                r#"{"type": "static-api-key", "valueRef": "secret:env/KEY"}"#,
                "static-api-key",
            ),
            (
                r#"{"type": "oauth2-client-credentials", "tokenEndpoint": "https://token.example.invalid/oauth/token", "clientIdRef": "secret:env/CLIENT_ID", "clientSecretRef": "secret:env/SECRET", "credentialPlacement": "basic-header", "maximumCacheSeconds": 3600}"#,
                "oauth2-client-credentials",
            ),
            (
                r#"{"type": "oauth2-private-key-jwt", "tokenEndpoint": "https://token.example.invalid/oauth/token", "clientIdRef": "secret:env/CLIENT_ID", "clientAssertionKeyRef": "secret:file/assertion.pem", "clientAssertionAudience": "token.example.invalid", "maximumCacheSeconds": 0}"#,
                "oauth2-private-key-jwt",
            ),
        ];
        for (json, tag) in cases {
            let credential: RuntimeCredential = serde_json::from_str(json).expect("parse");
            assert_eq!(credential.kind(), tag);
            let back = serde_json::to_string(&credential).expect("serialize");
            let reparsed: RuntimeCredential = serde_json::from_str(&back).expect("reparse");
            assert_eq!(reparsed, credential);
        }
    }

    /// A credential kind outside the closed set, and an OAuth2 credential
    /// without its required token endpoint, are refused at the reader.
    #[test]
    fn unknown_credential_kinds_and_missing_token_endpoint_are_refused() {
        assert!(serde_json::from_str::<RuntimeCredential>(r#"{"type": "digest"}"#).is_err());
        assert!(
            serde_json::from_str::<RuntimeCredential>(
                r#"{"type": "oauth2-client-credentials", "clientIdRef": "secret:env/ID", "clientSecretRef": "secret:env/S", "credentialPlacement": "basic-header", "maximumCacheSeconds": 0}"#,
            )
            .is_err(),
            "the token endpoint is required, as in Evidence"
        );
    }

    /// Only the OAuth2 kinds need a token endpoint; the runtime config
    /// carries it.
    #[test]
    fn token_endpoint_kinds() {
        let oauth = EndpointAuthentication::Oauth2ClientCredentials {};
        let none = EndpointAuthentication::None {};
        assert!(oauth.needs_token_endpoint());
        assert!(!none.needs_token_endpoint());
        assert!(!EndpointAuthentication::Basic {}.needs_token_endpoint());
    }

    /// A token endpoint parses as an absolute `http`/`https` URL: prose
    /// and other schemes refuse at the reader.
    #[test]
    fn a_malformed_token_endpoint_is_refused_at_the_reader() {
        for json in [
            r#"{"type": "oauth2-client-credentials", "tokenEndpoint": "not a url at all", "clientIdRef": "secret:env/ID", "clientSecretRef": "secret:env/S", "credentialPlacement": "basic-header", "maximumCacheSeconds": 0}"#,
            r#"{"type": "oauth2-client-credentials", "tokenEndpoint": "ftp://token.example.invalid/token", "clientIdRef": "secret:env/ID", "clientSecretRef": "secret:env/S", "credentialPlacement": "basic-header", "maximumCacheSeconds": 0}"#,
            r#"{"type": "oauth2-private-key-jwt", "tokenEndpoint": "token.example.invalid/oauth/token", "clientIdRef": "secret:env/ID", "clientAssertionKeyRef": "secret:file/assertion.pem", "maximumCacheSeconds": 0}"#,
        ] {
            assert!(
                serde_json::from_str::<RuntimeCredential>(json).is_err(),
                "a malformed token endpoint refuses at the reader"
            );
        }
    }

    /// Reserved header names are refused, case-insensitively, including
    /// the hop-by-hop `Proxy-*` names; ordinary and custom
    /// Authorization-like names pass.
    #[test]
    fn reserved_header_names() {
        for name in RESERVED_HEADER_NAMES {
            assert!(is_reserved_header_name(name));
        }
        assert!(is_reserved_header_name("Authorization"));
        assert!(is_reserved_header_name("HOST"));
        assert!(is_reserved_header_name("Proxy-Session"));
        assert!(is_reserved_header_name("Set-Cookie"));
        assert!(!is_reserved_header_name("X-Api-Key"));
        assert!(!is_reserved_header_name("X-Authorization"));
        assert!(!is_reserved_header_name("x-correlation-id"));
    }

    /// The mTLS identity round-trips with its two secret references.
    #[test]
    fn mtls_identity_round_trips() {
        let identity = MtlsIdentity {
            certificate_ref: secret("CLIENT_CERT"),
            key_ref: secret("CLIENT_KEY"),
        };
        let json = serde_json::to_string(&identity).expect("serialize");
        assert_eq!(
            serde_json::from_str::<MtlsIdentity>(&json).ok(),
            Some(identity)
        );
    }
}
