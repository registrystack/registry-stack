// SPDX-License-Identifier: Apache-2.0
//! Bounded Python token verification over `registry-platform-oidc`.

#![deny(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use oidc_core::{
    access_token_typ_set, fetch_discovery_for_issuer, parse_static_jwks, AccessTokenAlgorithm,
    Audience, Claims, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, TokenVerifier,
    TokenVerifierConfig,
};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple, PyType};
use serde_json::Value;

const MAXIMUM_TOKEN_BYTES: usize = 128 * 1024;
const MAXIMUM_JWKS_BYTES: usize = 256 * 1024;
const MAXIMUM_IDENTIFIER_BYTES: usize = 2 * 1024;
const MAXIMUM_CLAIM_NAMES: usize = 32;
const MAXIMUM_CLAIM_NAME_BYTES: usize = 128;
const MAXIMUM_CLAIM_VALUE_BYTES: usize = 2 * 1024;
const MAXIMUM_AUDIENCES: usize = 16;
const MAXIMUM_SCOPES: usize = 256;
const MAXIMUM_SCOPE_BYTES: usize = 512;
const MAXIMUM_TOTAL_SCOPE_BYTES: usize = 32 * 1024;
const MAXIMUM_TOKEN_LIFETIME_SECONDS: u64 = 86_400;
const MAXIMUM_CLOCK_SKEW_SECONDS: u64 = 300;
const MAXIMUM_NONCE_BYTES: usize = 512;
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

pyo3::create_exception!(
    registry_platform_oidc,
    TokenVerificationError,
    PyException,
    "A stable token verification failure that contains no token or configured identity values."
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureKind {
    Configuration,
    Verification,
    Runtime,
}

impl FailureKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Verification => "verification",
            Self::Runtime => "runtime",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Configuration => "Token verifier configuration is invalid",
            Self::Verification => "Token verification failed",
            Self::Runtime => "Token verifier runtime failed",
        }
    }
}

fn py_error(py: Python<'_>, kind: FailureKind) -> PyErr {
    let error = TokenVerificationError::new_err(kind.message());
    error
        .value(py)
        .setattr("kind", kind.name())
        .expect("fresh exception accepts attributes");
    error
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Access,
    Id,
}

impl TokenKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Id => "id",
        }
    }
}

#[derive(Debug)]
struct Policy {
    issuer: String,
    resource: String,
    additional_audiences: Vec<String>,
    client_id: String,
    algorithm: AccessTokenAlgorithm,
    access_token_type: String,
    maximum_access_token_lifetime: Duration,
    maximum_id_token_lifetime: Duration,
    clock_skew: Duration,
    claim_names: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn policy(
    issuer: String,
    resource: String,
    client_id: String,
    algorithm_name: &str,
    access_token_type: String,
    maximum_access_token_lifetime_seconds: u64,
    maximum_id_token_lifetime_seconds: u64,
    clock_skew_seconds: u64,
    claim_names: Vec<String>,
    additional_audiences: Vec<String>,
) -> Result<Policy, FailureKind> {
    bounded_identifier(&issuer)?;
    bounded_identifier(&resource)?;
    if additional_audiences.len() > 3
        || additional_audiences
            .iter()
            .any(|value| bounded_identifier(value).is_err())
        || additional_audiences.iter().any(|value| value == &resource)
        || additional_audiences
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != additional_audiences.len()
    {
        return Err(FailureKind::Configuration);
    }
    bounded_identifier(&client_id)?;
    if access_token_type.is_empty()
        || access_token_type.len() > 64
        || !access_token_type
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
    {
        return Err(FailureKind::Configuration);
    }
    let algorithm = algorithm(algorithm_name)?;
    let maximum_access_token_lifetime = bounded_positive_seconds(
        maximum_access_token_lifetime_seconds,
        MAXIMUM_TOKEN_LIFETIME_SECONDS,
    )?;
    let maximum_id_token_lifetime = bounded_positive_seconds(
        maximum_id_token_lifetime_seconds,
        MAXIMUM_TOKEN_LIFETIME_SECONDS,
    )?;
    if clock_skew_seconds > MAXIMUM_CLOCK_SKEW_SECONDS {
        return Err(FailureKind::Configuration);
    }
    let claim_names = checked_claim_names(claim_names)?;
    Ok(Policy {
        issuer,
        resource,
        additional_audiences,
        client_id,
        algorithm,
        access_token_type,
        maximum_access_token_lifetime,
        maximum_id_token_lifetime,
        clock_skew: Duration::from_secs(clock_skew_seconds),
        claim_names,
    })
}

fn bounded_identifier(value: &str) -> Result<(), FailureKind> {
    if value.is_empty()
        || value.len() > MAXIMUM_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(FailureKind::Configuration);
    }
    Ok(())
}

fn bounded_positive_seconds(value: u64, maximum: u64) -> Result<Duration, FailureKind> {
    if value == 0 || value > maximum {
        return Err(FailureKind::Configuration);
    }
    Ok(Duration::from_secs(value))
}

fn algorithm(value: &str) -> Result<AccessTokenAlgorithm, FailureKind> {
    match value {
        "EdDSA" => Ok(AccessTokenAlgorithm::EdDSA),
        "ES256" => Ok(AccessTokenAlgorithm::ES256),
        "ES384" => Ok(AccessTokenAlgorithm::ES384),
        "RS256" => Ok(AccessTokenAlgorithm::RS256),
        "RS384" => Ok(AccessTokenAlgorithm::RS384),
        _ => Err(FailureKind::Configuration),
    }
}

fn checked_claim_names(names: Vec<String>) -> Result<Vec<String>, FailureKind> {
    if names.len() > MAXIMUM_CLAIM_NAMES {
        return Err(FailureKind::Configuration);
    }
    let mut unique = BTreeSet::new();
    for name in &names {
        if name.is_empty()
            || name.len() > MAXIMUM_CLAIM_NAME_BYTES
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
            })
            || matches!(
                name.as_str(),
                "iss"
                    | "aud"
                    | "sub"
                    | "exp"
                    | "iat"
                    | "nbf"
                    | "azp"
                    | "client_id"
                    | "scope"
                    | "nonce"
            )
            || !unique.insert(name.clone())
        {
            return Err(FailureKind::Configuration);
        }
    }
    Ok(names)
}

fn runtime() -> Result<tokio::runtime::Runtime, FailureKind> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| FailureKind::Runtime)
}

struct Verifiers {
    access: TokenVerifier,
    id: TokenVerifier,
}

fn verifiers(policy: &Policy, fetcher: Arc<JwksFetcher>) -> Verifiers {
    let common = || {
        TokenVerifierConfig::access_token_profile(
            policy.issuer.clone(),
            std::iter::once(policy.resource.clone())
                .chain(policy.additional_audiences.iter().cloned())
                .collect(),
            vec![policy.algorithm.to_jsonwebtoken()],
            access_token_typ_set(&policy.access_token_type),
        )
        .with_allowed_clients(vec![policy.client_id.clone()])
        .with_leeway(policy.clock_skew)
    };
    let access = TokenVerifier::new(
        common().with_max_token_lifetime(Some(policy.maximum_access_token_lifetime)),
        Arc::clone(&fetcher),
    );
    let id = TokenVerifier::new(
        common().with_max_token_lifetime(Some(policy.maximum_id_token_lifetime)),
        fetcher,
    );
    Verifiers { access, id }
}

#[pyclass(frozen, module = "registry_platform_oidc", skip_from_py_object)]
#[derive(Clone, Debug)]
struct VerifiedToken {
    kind: TokenKind,
    issuer: String,
    audiences: Vec<String>,
    subject: String,
    client_id: String,
    scopes: Vec<String>,
    expires_at: i64,
    issued_at: i64,
    not_before: Option<i64>,
    claims: BTreeMap<String, String>,
}

#[pymethods]
impl VerifiedToken {
    #[getter]
    fn kind(&self) -> &'static str {
        self.kind.name()
    }

    #[getter]
    fn issuer(&self) -> &str {
        &self.issuer
    }

    #[getter]
    fn audiences(&self, py: Python<'_>) -> PyResult<Py<PyTuple>> {
        Ok(PyTuple::new(py, &self.audiences)?.unbind())
    }

    #[getter]
    fn subject(&self) -> &str {
        &self.subject
    }

    #[getter]
    fn client_id(&self) -> &str {
        &self.client_id
    }

    #[getter]
    fn scopes(&self, py: Python<'_>) -> PyResult<Py<PyTuple>> {
        Ok(PyTuple::new(py, &self.scopes)?.unbind())
    }

    #[getter]
    const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    #[getter]
    const fn issued_at(&self) -> i64 {
        self.issued_at
    }

    #[getter]
    const fn not_before(&self) -> Option<i64> {
        self.not_before
    }

    #[getter]
    fn claims(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let claims = PyDict::new(py);
        for (name, value) in &self.claims {
            claims.set_item(name, value)?;
        }
        Ok(claims.unbind())
    }
}

#[pyclass(module = "registry_platform_oidc")]
struct AccessTokenVerifier {
    access: TokenVerifier,
    id: TokenVerifier,
    runtime: tokio::runtime::Runtime,
    policy: Policy,
}

impl AccessTokenVerifier {
    fn from_parts(policy: Policy, fetcher: Arc<JwksFetcher>) -> Result<Self, FailureKind> {
        let runtime = runtime()?;
        let Verifiers { access, id } = verifiers(&policy, fetcher);
        Ok(Self {
            access,
            id,
            runtime,
            policy,
        })
    }

    fn verify_access(&self, token: &str) -> Result<VerifiedToken, FailureKind> {
        bounded_token(token)?;
        let verified = self
            .runtime
            .block_on(self.access.verify(token))
            .map_err(|_| FailureKind::Verification)?;
        bounded_verified_token(
            TokenKind::Access,
            verified.claims,
            verified.scopes,
            &self.policy,
        )
    }

    fn verify_id(&self, token: &str, expected_nonce: &str) -> Result<VerifiedToken, FailureKind> {
        bounded_token(token)?;
        if expected_nonce.is_empty() || expected_nonce.len() > MAXIMUM_NONCE_BYTES {
            return Err(FailureKind::Verification);
        }
        let verified = self
            .runtime
            .block_on(self.id.verify_related_token(token))
            .map_err(|_| FailureKind::Verification)?;
        if verified.claims.extra.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
            return Err(FailureKind::Verification);
        }
        bounded_verified_token(
            TokenKind::Id,
            verified.claims,
            verified.scopes,
            &self.policy,
        )
    }
}

#[pymethods]
impl AccessTokenVerifier {
    #[new]
    #[pyo3(signature = (
        issuer,
        resource,
        client_id,
        *,
        algorithm,
        maximum_access_token_lifetime_seconds,
        access_token_type="at+jwt".to_owned(),
        maximum_id_token_lifetime_seconds=3600,
        clock_skew_seconds=60,
        claim_names=Vec::new(),
        additional_audiences=Vec::new(),
        jwks_uri=None,
        allow_insecure_http=false,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        issuer: String,
        resource: String,
        client_id: String,
        algorithm: String,
        maximum_access_token_lifetime_seconds: u64,
        access_token_type: String,
        maximum_id_token_lifetime_seconds: u64,
        clock_skew_seconds: u64,
        claim_names: Vec<String>,
        additional_audiences: Vec<String>,
        jwks_uri: Option<String>,
        allow_insecure_http: bool,
    ) -> PyResult<Self> {
        let policy = policy(
            issuer,
            resource,
            client_id,
            &algorithm,
            access_token_type,
            maximum_access_token_lifetime_seconds,
            maximum_id_token_lifetime_seconds,
            clock_skew_seconds,
            claim_names,
            additional_audiences,
        )
        .map_err(|kind| py_error(py, kind))?;
        if jwks_uri
            .as_deref()
            .is_some_and(|uri| bounded_identifier(uri).is_err())
        {
            return Err(py_error(py, FailureKind::Configuration));
        }
        let runtime = runtime().map_err(|kind| py_error(py, kind))?;
        let discovery = OidcDiscoveryConfig {
            issuer: policy.issuer.clone(),
            jwks_uri_override: jwks_uri,
            discovery_timeout: Duration::from_secs(5),
            max_doc_bytes: 1024 * 1024,
        };
        let (document, fetch_policy) = py
            .detach(|| {
                runtime.block_on(fetch_discovery_for_issuer(&discovery, allow_insecure_http))
            })
            .map_err(|_| py_error(py, FailureKind::Configuration))?;
        let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            document.jwks_uri,
            JwksFetcherConfig::defaults(),
            fetch_policy,
        ));
        let Verifiers { access, id } = verifiers(&policy, fetcher);
        Ok(Self {
            access,
            id,
            runtime,
            policy,
        })
    }

    #[classmethod]
    #[pyo3(signature = (
        jwks_json,
        issuer,
        resource,
        client_id,
        *,
        algorithm,
        maximum_access_token_lifetime_seconds,
        access_token_type="at+jwt".to_owned(),
        maximum_id_token_lifetime_seconds=3600,
        clock_skew_seconds=60,
        claim_names=Vec::new(),
        additional_audiences=Vec::new(),
    ))]
    #[allow(clippy::too_many_arguments)]
    fn from_static_jwks(
        _class: &Bound<'_, PyType>,
        py: Python<'_>,
        jwks_json: String,
        issuer: String,
        resource: String,
        client_id: String,
        algorithm: String,
        maximum_access_token_lifetime_seconds: u64,
        access_token_type: String,
        maximum_id_token_lifetime_seconds: u64,
        clock_skew_seconds: u64,
        claim_names: Vec<String>,
        additional_audiences: Vec<String>,
    ) -> PyResult<Self> {
        if jwks_json.len() > MAXIMUM_JWKS_BYTES {
            return Err(py_error(py, FailureKind::Configuration));
        }
        ensure_public_static_jwks(jwks_json.as_bytes()).map_err(|kind| py_error(py, kind))?;
        let policy = policy(
            issuer,
            resource,
            client_id,
            &algorithm,
            access_token_type,
            maximum_access_token_lifetime_seconds,
            maximum_id_token_lifetime_seconds,
            clock_skew_seconds,
            claim_names,
            additional_audiences,
        )
        .map_err(|kind| py_error(py, kind))?;
        let jwks = parse_static_jwks(jwks_json.as_bytes())
            .map_err(|_| py_error(py, FailureKind::Configuration))?;
        Self::from_parts(
            policy,
            Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())),
        )
        .map_err(|kind| py_error(py, kind))
    }

    fn verify(&self, py: Python<'_>, token: &str) -> PyResult<VerifiedToken> {
        py.detach(|| self.verify_access(token))
            .map_err(|kind| py_error(py, kind))
    }

    fn verify_access_token(&self, py: Python<'_>, token: &str) -> PyResult<VerifiedToken> {
        py.detach(|| self.verify_access(token))
            .map_err(|kind| py_error(py, kind))
    }

    fn verify_id_token(
        &self,
        py: Python<'_>,
        token: &str,
        expected_nonce: &str,
    ) -> PyResult<VerifiedToken> {
        py.detach(|| self.verify_id(token, expected_nonce))
            .map_err(|kind| py_error(py, kind))
    }
}

fn ensure_public_static_jwks(bytes: &[u8]) -> Result<(), FailureKind> {
    let document: Value = serde_json::from_slice(bytes).map_err(|_| FailureKind::Configuration)?;
    let keys = document
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(FailureKind::Configuration)?;
    for key in keys {
        let key = key.as_object().ok_or(FailureKind::Configuration)?;
        if PRIVATE_JWK_MEMBERS
            .iter()
            .any(|member| key.contains_key(*member))
        {
            return Err(FailureKind::Configuration);
        }
    }
    Ok(())
}

fn bounded_token(token: &str) -> Result<(), FailureKind> {
    if token.is_empty() || token.len() > MAXIMUM_TOKEN_BYTES {
        return Err(FailureKind::Verification);
    }
    Ok(())
}

fn bounded_verified_token(
    kind: TokenKind,
    claims: Claims,
    scopes: Vec<String>,
    policy: &Policy,
) -> Result<VerifiedToken, FailureKind> {
    if let (Some(azp), Some(client_id)) = (claims.azp.as_deref(), claims.client_id.as_deref()) {
        if azp != client_id {
            return Err(FailureKind::Verification);
        }
    }
    let issuer = required_bounded(claims.iss.as_deref())?;
    if issuer != policy.issuer {
        return Err(FailureKind::Verification);
    }
    let subject = required_bounded(claims.sub.as_deref())?;
    let audiences = bounded_audiences(claims.aud.as_ref())?;
    let expected_audiences = std::iter::once(policy.resource.as_str())
        .chain(policy.additional_audiences.iter().map(String::as_str))
        .collect::<std::collections::HashSet<_>>();
    match kind {
        TokenKind::Access
            if audiences.len() != expected_audiences.len()
                || audiences
                    .iter()
                    .map(String::as_str)
                    .collect::<std::collections::HashSet<_>>()
                    != expected_audiences =>
        {
            return Err(FailureKind::Verification);
        }
        TokenKind::Id
            if !audiences
                .iter()
                .any(|audience| audience == &policy.client_id) =>
        {
            return Err(FailureKind::Verification);
        }
        TokenKind::Access | TokenKind::Id => {}
    }
    let presented_client = claims.azp.as_deref().or(claims.client_id.as_deref());
    let client_id = match (kind, presented_client) {
        (_, Some(client)) if client == policy.client_id => client,
        (TokenKind::Id, None) => policy.client_id.as_str(),
        (TokenKind::Access | TokenKind::Id, _) => return Err(FailureKind::Verification),
    };
    let scopes = bounded_scopes(scopes)?;
    let expires_at = claims.exp.ok_or(FailureKind::Verification)?;
    let issued_at = claims.iat.ok_or(FailureKind::Verification)?;
    let selected = selected_claims(&claims.extra, &policy.claim_names)?;
    Ok(VerifiedToken {
        kind,
        issuer: issuer.to_owned(),
        audiences,
        subject: subject.to_owned(),
        client_id: client_id.to_owned(),
        scopes,
        expires_at,
        issued_at,
        not_before: claims.nbf,
        claims: selected,
    })
}

fn required_bounded(value: Option<&str>) -> Result<&str, FailureKind> {
    value
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAXIMUM_IDENTIFIER_BYTES
                && !value.chars().any(char::is_control)
        })
        .ok_or(FailureKind::Verification)
}

fn bounded_audiences(audience: Option<&Audience>) -> Result<Vec<String>, FailureKind> {
    let audiences = match audience {
        Some(Audience::One(value)) => vec![value.clone()],
        Some(Audience::Many(values)) => values.clone(),
        None => return Err(FailureKind::Verification),
    };
    if audiences.is_empty()
        || audiences.len() > MAXIMUM_AUDIENCES
        || audiences.iter().any(|value| {
            value.is_empty()
                || value.len() > MAXIMUM_IDENTIFIER_BYTES
                || value.chars().any(char::is_control)
        })
    {
        return Err(FailureKind::Verification);
    }
    Ok(audiences)
}

fn bounded_scopes(scopes: Vec<String>) -> Result<Vec<String>, FailureKind> {
    if scopes.len() > MAXIMUM_SCOPES
        || scopes.iter().any(|scope| {
            scope.is_empty()
                || scope.len() > MAXIMUM_SCOPE_BYTES
                || !scope.bytes().all(|byte| byte.is_ascii_graphic())
        })
        || scopes.iter().map(String::len).sum::<usize>() > MAXIMUM_TOTAL_SCOPE_BYTES
    {
        return Err(FailureKind::Verification);
    }
    Ok(scopes)
}

fn selected_claims(
    extra: &serde_json::Map<String, Value>,
    names: &[String],
) -> Result<BTreeMap<String, String>, FailureKind> {
    let mut selected = BTreeMap::new();
    for name in names {
        let Some(value) = extra.get(name) else {
            continue;
        };
        let value = value.as_str().ok_or(FailureKind::Verification)?;
        if value.is_empty() || value.len() > MAXIMUM_CLAIM_VALUE_BYTES {
            return Err(FailureKind::Verification);
        }
        selected.insert(name.clone(), value.to_owned());
    }
    Ok(selected)
}

#[cfg(test)]
mod tests;

#[pymodule]
fn registry_platform_oidc(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<AccessTokenVerifier>()?;
    module.add_class::<VerifiedToken>()?;
    module.add(
        "TokenVerificationError",
        module.py().get_type::<TokenVerificationError>(),
    )?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
