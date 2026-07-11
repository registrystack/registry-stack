use super::*;

/// Bench-internal: exposed only so `benches/auth_bench.rs` can construct
/// fixtures. Production code goes through `resolve_credentials`, which reads
/// the fingerprint from `EvidenceCredentialConfig::fingerprint`. Not part of the
/// public API; do not depend on this shape from outside the workspace.
#[doc(hidden)]
#[derive(Clone)]
pub struct ResolvedCredential {
    pub id: String,
    pub fingerprint: String,
    pub scopes: Vec<String>,
    pub authorization_details: Option<EvidenceAuthorizationDetails>,
}

impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("id", &self.id)
            .field("fingerprint", &"<redacted>")
            .field("scopes", &self.scopes)
            .field(
                "authorization_details",
                &self.authorization_details.as_ref().map(|_| "<configured>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub(in super::super) struct RequestCredentials {
    pub(in super::super) api_key: Option<String>,
    pub(in super::super) authorization_present: bool,
    pub(in super::super) bearer_token: Option<String>,
    pub(in super::super) id_token: Option<String>,
}

impl RequestCredentials {
    pub(in super::super) fn credential_type_count(&self) -> usize {
        usize::from(self.api_key.is_some())
            + usize::from(self.authorization_present || self.bearer_token.is_some())
    }

    pub(super) fn are_absent(&self) -> bool {
        self.api_key.is_none()
            && !self.authorization_present
            && self.bearer_token.is_none()
            && self.id_token.is_none()
    }
}

pub(super) fn resolve_credentials(
    credentials: &[EvidenceCredentialConfig],
) -> Result<Vec<ResolvedCredential>, StandaloneServerError> {
    credentials
        .iter()
        .map(|credential| {
            let secret_ref = credential
                .fingerprint
                .name
                .clone()
                .or_else(|| {
                    credential
                        .fingerprint
                        .path
                        .as_ref()
                        .map(|path| path.display().to_string())
                })
                .unwrap_or_else(|| credential.id.clone());
            let fingerprint = credential
                .fingerprint
                .resolve()
                .map_err(|error| match error {
                    CredentialFingerprintRefError::MissingSecret => {
                        StandaloneServerError::MissingCredentialEnv(secret_ref.clone())
                    }
                    CredentialFingerprintRefError::InvalidFingerprint(format_error) => {
                        StandaloneServerError::InvalidCredentialHash(
                            secret_ref.clone(),
                            format_error,
                        )
                    }
                    CredentialFingerprintRefError::EmptySecret => {
                        StandaloneServerError::MissingCredentialEnv(secret_ref.clone())
                    }
                    CredentialFingerprintRefError::InvalidShape => {
                        StandaloneServerError::InvalidCredentialHash(
                            secret_ref.clone(),
                            FingerprintFormatError::InvalidHex,
                        )
                    }
                    _ => StandaloneServerError::InvalidCredentialHash(
                        secret_ref.clone(),
                        FingerprintFormatError::InvalidHex,
                    ),
                })?;
            Ok(ResolvedCredential {
                id: credential.id.clone(),
                fingerprint,
                scopes: credential.scopes.clone(),
                authorization_details: credential.authorization_details.clone(),
            })
        })
        .collect()
}

pub(in super::super) fn request_credentials(request: &Request) -> RequestCredentials {
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(header_str);
    RequestCredentials {
        api_key: request
            .headers()
            .get("x-api-key")
            .and_then(header_str)
            .map(ToOwned::to_owned),
        authorization_present: authorization.is_some(),
        bearer_token: authorization
            .and_then(|raw| parse_bearer_token(raw).ok())
            .map(ToOwned::to_owned),
        id_token: request
            .headers()
            .get(OIDC_ID_TOKEN_HEADER)
            .and_then(header_str)
            .map(ToOwned::to_owned),
    }
}

pub(in super::super) fn authenticate_static(
    credentials: &RequestCredentials,
    api_keys: &[ResolvedCredential],
    bearer_tokens: &[ResolvedCredential],
) -> Result<EvidencePrincipal, EvidenceError> {
    if let Some(value) = credentials.api_key.as_deref() {
        if let Some(credential) = find_credential(api_keys, value) {
            return Ok(principal_from_credential(credential));
        }
    }
    if let Some(value) = credentials.bearer_token.as_deref() {
        if let Some(credential) = find_credential(bearer_tokens, value) {
            return Ok(principal_from_credential(credential));
        }
    }
    Err(EvidenceError::MissingCredential)
}

/// Bench-internal: exposed only for `benches/auth_bench.rs`. Not part of the
/// public API.
#[doc(hidden)]
pub fn find_credential<'a>(
    credentials: &'a [ResolvedCredential],
    token: &str,
) -> Option<&'a ResolvedCredential> {
    credentials
        .iter()
        .find(|credential| verify_api_key(token, &credential.fingerprint).unwrap_or(false))
}

fn principal_from_credential(credential: &ResolvedCredential) -> EvidencePrincipal {
    EvidencePrincipal {
        principal_id: credential.id.clone(),
        scopes: credential.scopes.clone(),
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: credential.authorization_details.clone(),
    }
}

fn header_str(value: &axum::http::HeaderValue) -> Option<&str> {
    value.to_str().ok()
}
