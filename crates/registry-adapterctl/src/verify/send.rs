// SPDX-License-Identifier: Apache-2.0

//! The one network seam of `verify --live`: a frozen platform destination
//! policy and opaque request template drive one bounded HTTP or HTTPS send.
//! Redirects are returned, never followed, and transport failures remain
//! value-free.

use registry_platform_httputil::destination::{
    DataDestinationPolicy, DataDestinationRequestTemplate, DestinationAuthorizationScheme,
    DestinationAuthorizationTemplate, DestinationAuthorizationValue,
    QueryStringContentAcknowledgement, ScriptRequestBodyFormat, SideEffectingSendMethod,
    MAX_DESTINATION_HEADER_VALUE_BYTES, MAX_DESTINATION_REQUEST_BODY_BYTES,
    MAX_DESTINATION_REQUEST_HEADER_BYTES, MAX_DESTINATION_TARGET_BYTES,
};
use std::time::Duration;
use zeroize::Zeroizing;

/// Credential material retained only through one opaque platform request.
pub(crate) enum TransportCredential {
    None,
    Basic(Zeroizing<Vec<u8>>),
    StaticAuthorization {
        scheme: String,
        token: Zeroizing<Vec<u8>>,
    },
    ApiKey {
        header_name: String,
        value: Zeroizing<Vec<u8>>,
    },
}

/// One rendered probe request over an already frozen destination policy.
pub(crate) struct WireRequest {
    pub policy: DataDestinationPolicy,
    pub method: String,
    pub target: String,
    pub credential: TransportCredential,
    pub body: Option<Vec<u8>>,
}

/// Why the seam could not produce a status. Text is fixed and value-free.
pub(crate) struct TransportFailure(pub String);

const TIMEOUT: Duration = Duration::from_secs(10);

/// Send one request through the platform policy and return only its status.
pub(crate) fn send_once(request: WireRequest) -> Result<u16, TransportFailure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| failure("the transport runtime could not start"))?;
    runtime.block_on(send(request))
}

async fn send(request: WireRequest) -> Result<u16, TransportFailure> {
    let (authorization_template, authorization, api_key_header, api_key) =
        credential_parts(request.credential)?;
    let method = match request.method.as_str() {
        "GET" => SideEffectingSendMethod::Get(
            QueryStringContentAcknowledgement::acknowledge_content_in_access_logs(),
        ),
        "POST" => SideEffectingSendMethod::Post,
        _ => return Err(failure("the request method is not supported")),
    };
    let template = DataDestinationRequestTemplate::new_script_send(
        method,
        "/**",
        &[],
        authorization_template,
        api_key_header
            .as_ref()
            .map(|name| (name.as_str(), MAX_DESTINATION_HEADER_VALUE_BYTES)),
        None,
        MAX_DESTINATION_TARGET_BYTES
            + MAX_DESTINATION_REQUEST_HEADER_BYTES
            + MAX_DESTINATION_REQUEST_BODY_BYTES,
    )
    .map_err(|_| failure("the request template was refused"))?;
    let body_format = request.body.as_ref().map(|_| ScriptRequestBodyFormat::Json);
    let rendered = template
        .render_script(
            &request.target,
            &[],
            authorization,
            api_key,
            body_format,
            request.body.map(Zeroizing::new),
        )
        .map_err(|_| failure("the rendered request was refused"))?;
    let response = request
        .policy
        .send(rendered, TIMEOUT)
        .await
        .map_err(|_| failure("the destination exchange failed"))?;
    Ok(response.status().as_u16())
}

type CredentialParts = (
    DestinationAuthorizationTemplate,
    Option<DestinationAuthorizationValue>,
    Option<String>,
    Option<Zeroizing<Vec<u8>>>,
);

fn credential_parts(credential: TransportCredential) -> Result<CredentialParts, TransportFailure> {
    match credential {
        TransportCredential::None => Ok((
            DestinationAuthorizationTemplate::Forbidden,
            None,
            None,
            None,
        )),
        TransportCredential::Basic(encoded) => Ok((
            DestinationAuthorizationTemplate::Basic {
                max_value_bytes: MAX_DESTINATION_HEADER_VALUE_BYTES,
            },
            Some(
                DestinationAuthorizationValue::basic_zeroizing(encoded)
                    .map_err(|_| failure("the authorization value was refused"))?,
            ),
            None,
            None,
        )),
        TransportCredential::StaticAuthorization { scheme, token } => {
            let scheme = DestinationAuthorizationScheme::new(&scheme)
                .map_err(|_| failure("the authorization scheme was refused"))?;
            Ok((
                DestinationAuthorizationTemplate::Scheme {
                    scheme,
                    max_value_bytes: MAX_DESTINATION_HEADER_VALUE_BYTES,
                },
                Some(
                    DestinationAuthorizationValue::scheme_zeroizing(scheme, token)
                        .map_err(|_| failure("the authorization value was refused"))?,
                ),
                None,
                None,
            ))
        }
        TransportCredential::ApiKey { header_name, value } => Ok((
            DestinationAuthorizationTemplate::Forbidden,
            None,
            Some(header_name),
            Some(value),
        )),
    }
}

fn failure(message: &str) -> TransportFailure {
    TransportFailure(message.to_owned())
}
