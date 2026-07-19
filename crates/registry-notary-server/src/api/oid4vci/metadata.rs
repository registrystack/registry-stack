// SPDX-License-Identifier: Apache-2.0
//! OID4VCI issuer, offer, and SD-JWT VC type metadata.

use super::super::*;

pub(in crate::api) async fn oid4vci_issuer_metadata(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
) -> Response {
    let Some(Extension(state)) = state else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    if !state.oid4vci.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    match oid4vci_metadata(&state.oid4vci, &state.evidence) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => oid4vci_error_response(error),
    }
}

pub(in crate::api) async fn oid4vci_type_metadata(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(Extension(state)) = state else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    let trust_forwarded = forwarded_host_trusted(&state, connect_info.as_deref());
    oid4vci_type_metadata_response(&state, &headers, &uri, uri.path(), trust_forwarded)
}

pub(in crate::api) async fn oid4vci_well_known_type_metadata(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(Extension(state)) = state else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    // Consumers dereference an HTTPS vct by inserting /.well-known/vct between the
    // host and the path. Strip that prefix so the candidate vct reconstructs to the
    // configured identifier (https://{host}/{vct_path}), not the well-known URL.
    let Some(vct_path) = uri.path().strip_prefix(WELL_KNOWN_VCT_PREFIX) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let trust_forwarded = forwarded_host_trusted(&state, connect_info.as_deref());
    oid4vci_type_metadata_response(&state, &headers, &uri, vct_path, trust_forwarded)
}

/// Whether `X-Forwarded-*` headers may be trusted for this request, i.e. the
/// socket peer is in the configured `trusted_proxy_ips`. Mirrors the gate in
/// `token_client_address_with_trusted_proxy_ips`.
pub(in crate::api) fn forwarded_host_trusted(
    state: &RegistryNotaryApiState,
    connect_info: Option<&axum::extract::ConnectInfo<SocketAddr>>,
) -> bool {
    let Some(axum::extract::ConnectInfo(addr)) = connect_info else {
        return false;
    };
    state
        .runtime_config()
        .map(|config| config.server.trusted_proxy_ips.contains(&addr.ip()))
        .unwrap_or(false)
}

pub(in crate::api) fn oid4vci_type_metadata_response(
    state: &RegistryNotaryApiState,
    headers: &HeaderMap,
    uri: &Uri,
    request_path: &str,
    trust_forwarded: bool,
) -> Response {
    if !state.oid4vci.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(request_vct) = oid4vci_requested_absolute_url_for_path(
        &state.oid4vci,
        headers,
        uri,
        request_path,
        trust_forwarded,
    ) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(configuration) = state
        .oid4vci
        .credential_configurations
        .values()
        .find(|configuration| configuration.vct == request_vct)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Json(oid4vci_type_metadata_document(
        &state.evidence,
        configuration,
    ))
    .into_response()
}

pub(in crate::api) fn oid4vci_metadata(
    config: &Oid4vciConfig,
    evidence: &EvidenceConfig,
) -> Result<CredentialIssuerMetadata, Oid4vciWireError> {
    let metadata = CredentialIssuerMetadata::new(
        config.credential_issuer.clone(),
        config.credential_endpoint.clone(),
        // The initial nonce is transaction-scoped and returned only by the
        // token endpoint. The 1.0 profile has no public nonce endpoint.
        None,
        config.authorization_servers.clone(),
        config
            .credential_configurations
            .iter()
            .map(|(id, configuration)| {
                oid4vci_configuration_metadata(configuration, evidence)
                    .map(|metadata| (id.clone(), metadata))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?,
    )
    .with_display(oid4vci_issuer_display_metadata(&config.display));
    // When the pre-authorized-code flow is enabled the Notary is its own
    // authorization server for that grant, so issuer metadata advertises its
    // token endpoint. Per OID4VCI, the credential offer's `grants` carries the
    // `urn:ietf:params:oauth:grant-type:pre-authorized_code` advertisement
    // per-offer (see the offer/callback handler); the `token_endpoint` is the
    // metadata signal that the issuer accepts that grant directly. When the
    // flow is disabled there is no token endpoint and metadata is unchanged.
    Ok(
        match (
            config.pre_authorized_code.enabled,
            oid4vci_token_endpoint_url(config),
        ) {
            (true, Some(token_endpoint)) => metadata.with_token_endpoint(token_endpoint),
            _ => metadata,
        },
    )
}

/// The Notary's own OID4VCI token endpoint URL: the credential-issuer base with
/// `oid4vci/token` appended (preserving any configured base subpath). Returns
/// `None` when the configured `credential_issuer` is not a usable absolute URL.
pub(in crate::api) fn oid4vci_token_endpoint_url(config: &Oid4vciConfig) -> Option<String> {
    let base = reqwest::Url::parse(config.credential_issuer.trim()).ok()?;
    registry_platform_httputil::url::append_path_segments(&base, &["oid4vci", "token"])
        .ok()
        .map(|url| url.to_string())
}

pub(in crate::api) fn oid4vci_configuration_metadata(
    configuration: &Oid4vciCredentialConfigurationConfig,
    evidence: &EvidenceConfig,
) -> Result<CredentialConfigurationMetadata, Oid4vciWireError> {
    let credential_signing_alg = oid4vci_credential_signing_alg(configuration, evidence)?;
    let mut metadata = CredentialConfigurationMetadata::sd_jwt_vc_with_algs(
        configuration.scope.clone(),
        configuration
            .cryptographic_binding_methods_supported
            .clone(),
        vec![credential_signing_alg],
        configuration.proof_signing_alg_values_supported.clone(),
        configuration.display_name.clone(),
        configuration.vct.clone(),
    );
    metadata.display = vec![oid4vci_credential_display_metadata(configuration)];
    Ok(metadata)
}

pub(in crate::api) fn oid4vci_credential_signing_alg(
    configuration: &Oid4vciCredentialConfigurationConfig,
    evidence: &EvidenceConfig,
) -> Result<String, Oid4vciWireError> {
    let profile = evidence
        .credential_profiles
        .get(&configuration.credential_profile)
        .ok_or(Oid4vciWireError::ServerError)?;
    let signing_key = evidence
        .signing_keys
        .get(&profile.signing_key)
        .ok_or(Oid4vciWireError::ServerError)?;
    Ok(signing_key.alg.clone())
}

pub(in crate::api) fn oid4vci_sd_jwt_projection(
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> Option<Vec<sd_jwt::SdJwtProjectionClaim>> {
    match configuration.credential_claim_mode() {
        Oid4vciCredentialClaimMode::LegacyClaimWrapper { .. } => None,
        Oid4vciCredentialClaimMode::FieldProjection { entries } => Some(
            entries
                .iter()
                .map(|entry| sd_jwt::SdJwtProjectionClaim {
                    claim_id: entry.id.clone(),
                    output_name: entry.output_path[0].clone(),
                })
                .collect(),
        ),
    }
}

pub(in crate::api) fn oid4vci_type_metadata_document(
    evidence: &EvidenceConfig,
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> Value {
    let display = oid4vci_credential_type_display_metadata(configuration);
    let locale = configuration.display.locale.as_deref().unwrap_or("en-US");
    let claims = match configuration.credential_claim_mode() {
        Oid4vciCredentialClaimMode::LegacyClaimWrapper { claim_id } => {
            vec![oid4vci_type_metadata_claim(
                evidence,
                claim_id,
                vec![claim_id.to_string()],
                &configuration.display_name,
                locale,
            )]
        }
        Oid4vciCredentialClaimMode::FieldProjection { entries } => entries
            .iter()
            .map(|entry| {
                oid4vci_type_metadata_claim(
                    evidence,
                    &entry.id,
                    entry.output_path.clone(),
                    &entry.display_name,
                    locale,
                )
            })
            .collect(),
    };
    let mut document = json!({
        "vct": configuration.vct,
        "name": configuration.display_name,
        "display": [display],
        "claims": claims,
    });
    if let Some(description) = configuration.display.description.as_deref() {
        document["description"] = json!(description);
    }
    document
}

pub(in crate::api) fn oid4vci_type_metadata_claim(
    evidence: &EvidenceConfig,
    claim_id: &str,
    path: Vec<String>,
    label: &str,
    locale: &str,
) -> Value {
    let mut claim = json!({
        "path": path,
        "display": [
            {
                "locale": locale,
                "label": label,
            }
        ],
        "sd": "always",
        "mandatory": true,
    });
    if let Some(semantics) = evidence
        .claims
        .iter()
        .find(|claim| claim.id == claim_id)
        .and_then(claim_semantics_metadata)
    {
        claim["registry_notary_semantics"] = semantics;
    }
    claim
}

pub(in crate::api) fn oid4vci_issuer_display_metadata(
    displays: &[Oid4vciIssuerDisplayConfig],
) -> Vec<DisplayMetadata> {
    displays
        .iter()
        .map(|display| {
            let mut metadata = DisplayMetadata::new(display.name.clone());
            metadata.locale = display.locale.clone();
            metadata.logo = display.logo.as_ref().map(oid4vci_display_image_metadata);
            metadata
        })
        .collect()
}

pub(in crate::api) fn oid4vci_credential_display_metadata(
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> DisplayMetadata {
    let mut metadata = DisplayMetadata::new(configuration.display_name.clone());
    metadata.locale = configuration.display.locale.clone();
    metadata.logo = configuration
        .display
        .logo
        .as_ref()
        .map(oid4vci_display_image_metadata);
    metadata.description = configuration.display.description.clone();
    metadata.background_color = configuration.display.background_color.clone();
    metadata.text_color = configuration.display.text_color.clone();
    metadata.background_image = configuration
        .display
        .background_image
        .as_ref()
        .map(oid4vci_display_image_metadata);
    metadata.secondary_image = configuration
        .display
        .secondary_image
        .as_ref()
        .map(oid4vci_display_image_metadata);
    metadata
}

pub(in crate::api) fn oid4vci_display_image_metadata(
    image: &Oid4vciDisplayImageConfig,
) -> DisplayImageMetadata {
    DisplayImageMetadata {
        uri: image.uri.clone().or_else(|| image.url.clone()),
        url: None,
        alt_text: image.alt_text.clone(),
    }
}

pub(in crate::api) fn oid4vci_credential_type_display_metadata(
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> Value {
    let display = oid4vci_credential_display_metadata(configuration);
    let mut value = serde_json::to_value(display).expect("display metadata serializes");
    if value
        .get("locale")
        .and_then(|value| value.as_str())
        .is_none()
    {
        value["locale"] = json!("en-US");
    }
    value
}

pub(in crate::api) fn oid4vci_requested_absolute_url_for_path(
    config: &Oid4vciConfig,
    headers: &HeaderMap,
    uri: &Uri,
    request_path: &str,
    trust_forwarded: bool,
) -> Option<String> {
    let (issuer_scheme, issuer_authority, issuer_path) =
        absolute_url_parts(&config.credential_issuer)?;
    // `X-Forwarded-*` headers are caller-controlled, so they are honored only
    // when the socket peer is a trusted proxy (mirrors `token_client_address`).
    // Otherwise fall back to the `Host` header / URI / configured issuer.
    let scheme = trust_forwarded
        .then(|| forwarded_header_value(headers, "x-forwarded-proto"))
        .flatten()
        .or_else(|| uri.scheme_str())
        .unwrap_or(issuer_scheme)
        .to_lowercase();
    let authority = trust_forwarded
        .then(|| forwarded_header_value(headers, "x-forwarded-host"))
        .flatten()
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .or_else(|| uri.authority().map(|authority| authority.as_str()))
        .unwrap_or(issuer_authority)
        .to_lowercase();
    let external_path = oid4vci_external_path(issuer_path, request_path);
    Some(format!("{scheme}://{authority}{external_path}"))
}

pub(in crate::api) fn absolute_url_parts(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest[..authority_end].trim();
    if scheme.is_empty() || authority.is_empty() {
        return None;
    }
    let path = if rest[authority_end..].starts_with('/') {
        rest[authority_end..]
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
    } else {
        ""
    };
    Some((scheme, authority, path))
}

pub(in crate::api) fn oid4vci_external_path(issuer_path: &str, path: &str) -> String {
    let issuer_path = issuer_path.trim_end_matches('/');
    if issuer_path.is_empty()
        || path.starts_with(&format!("{issuer_path}/"))
        || !path.starts_with("/credentials/")
    {
        path.to_string()
    } else {
        format!("{issuer_path}{path}")
    }
}

pub(in crate::api) fn forwarded_header_value<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
