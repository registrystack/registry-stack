// SPDX-License-Identifier: Apache-2.0

//! Test-only process boundary for proving that a bearer minted by the stock
//! institutional exchange is accepted by Scheduling's real authenticator.
//!
//! The complete input arrives on stdin so the credential never enters argv or
//! a process listing. Output is exactly `allowed` or `refused`; no input or
//! verifier detail is logged.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use jsonwebtoken::{jwk::JwkSet, Algorithm};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use registry_scheduling::auth::SchedulingAuthenticator;
use registry_scheduling::config::{OidcConfig, OidcJwksSource};
use serde::Deserialize;

const MAXIMUM_INPUT_BYTES: u64 = 1024 * 1024;
const MAXIMUM_VALUE_BYTES: usize = 512;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProbeInput {
    token: String,
    issuer: String,
    audience: String,
    client: String,
    assertion_issuer: String,
    jwks: serde_json::Value,
    service: String,
    location: String,
    action: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let allowed = match read_input() {
        Ok(input) if validate_input(&input) => authenticate(input).await.unwrap_or(false),
        _ => false,
    };
    if allowed {
        println!("allowed");
        std::process::ExitCode::SUCCESS
    } else {
        println!("refused");
        std::process::ExitCode::FAILURE
    }
}

fn read_input() -> Result<ProbeInput, ()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAXIMUM_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAXIMUM_INPUT_BYTES {
        return Err(());
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn validate_input(input: &ProbeInput) -> bool {
    !input.token.is_empty()
        && input.token.len() <= 64 * 1024
        && [
            &input.issuer,
            &input.audience,
            &input.client,
            &input.assertion_issuer,
            &input.service,
            &input.location,
            &input.action,
        ]
        .into_iter()
        .all(|value| {
            !value.is_empty()
                && value.len() <= MAXIMUM_VALUE_BYTES
                && !value.chars().any(char::is_control)
        })
}

async fn authenticate(input: ProbeInput) -> Result<bool, ()> {
    let keys: JwkSet = serde_json::from_value(input.jwks).map_err(|_| ())?;
    let assertion_issuers =
        BTreeMap::from([(input.client.clone(), vec![input.assertion_issuer.clone()])]);
    let oidc = OidcConfig {
        allowed_clients: vec![input.client.clone()],
        assertion_issuers: assertion_issuers.clone(),
        issuer: input.issuer.clone(),
        audience: input.audience.clone(),
        jwks_uri: None,
        jwks_source: OidcJwksSource::Discovery,
        scope_claim: "scope".to_owned(),
        reads_scope: "scheduling-read".to_owned(),
        explain_scope: "scheduling-explain".to_owned(),
    };
    let verifier = TokenVerifierConfig::access_token_profile(
        input.issuer,
        vec![input.audience],
        vec![Algorithm::RS256],
        vec!["at+jwt".to_owned()],
    )
    .with_scope_claim("scope")
    .with_allowed_clients(vec![input.client])
    .with_assertion_issuers(assertion_issuers);
    let authenticator = SchedulingAuthenticator::new(
        &oidc,
        verifier,
        Arc::new(JwksFetcher::new_static(keys, JwksFetcherConfig::defaults())),
    );
    let caller = authenticator
        .authenticate_mutate(&input.token)
        .await
        .map_err(|_| ())?;
    let Some(grant) = caller.grant else {
        return Ok(false);
    };
    Ok(grant
        .bounds()
        .scheduling_permissions()
        .is_some_and(|permissions| {
            permissions.iter().any(|permission| {
                permission.service() == input.service
                    && permission.location() == input.location
                    && permission
                        .actions()
                        .iter()
                        .any(|action| action == &input.action)
            })
        }))
}
