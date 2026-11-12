// SPDX-License-Identifier: Apache-2.0

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Uri},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use registry_adapter::payments::{
    g2p_model::{
        DisbursementInstruction, G2pAttempt, G2pConnectionSnapshot, G2pError, G2pHttpAuth,
        G2pProviderBinding, G2pRegistryBinding, PreparedG2pRegistryAction,
    },
    g2p_service::{G2pProviderError, G2pProviderPort, HttpG2pProvider},
    pack::ProviderPackPin,
    provider_mapping::{
        PaymentEndpointRole, PaymentHttpMethod, PreparedProviderRequest, ProviderAcceptance,
        ProviderObservation, ProviderObservationState, ProviderObservedMoney,
        ProviderObservedParty, ProviderPartyRole,
    },
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_yaml::SecretReference;
use serde_json::json;
use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SeenRequest {
    method: &'static str,
    path_and_query: String,
    tenant: Option<String>,
    authorization_ok: bool,
    body: Vec<u8>,
}

#[tokio::test]
async fn bearer_http_host_preserves_one_send_and_validates_wire_observations() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let router = Router::new()
        .route("/v2/payouts", post(capture_submit))
        .route("/v2/uncertain", post(capture_uncertain))
        .route("/v2/payouts/{reference}", get(capture_status))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let secrets = tempfile::tempdir().unwrap();
    write_secret(secrets.path().join("provider-token"), b"test-only-bearer");
    write_secret(secrets.path().join("signing-key"), b"test-only-signing-key");
    write_secret(
        secrets.path().join("response-key"),
        b"test-only-response-key",
    );
    let resolver = Arc::new(
        SecretResolver::new([SecretProvider::File], secrets.path()).expect("file resolver"),
    );
    let provider = HttpG2pProvider::new(resolver);
    let provider_binding = binding(&origin, G2pHttpAuth::Bearer);
    let pack = pin();
    let instruction = instruction();
    let snapshot = snapshot(provider_binding.clone(), pack.clone());
    let intent = snapshot.provider_intent(&instruction).unwrap();
    let exact_body = registry_platform_canonical_json::canonicalize_json(&json!({
        "amountMinor": "100000",
        "clientReference": intent.correlation_id
    }))
    .unwrap();
    let submit = PreparedProviderRequest {
        provider_pack: pack.clone(),
        role: PaymentEndpointRole::DisbursementSubmit,
        method: PaymentHttpMethod::Post,
        path: "/v2/payouts".to_owned(),
        query: BTreeMap::from([("channel".to_owned(), "benefits".to_owned())]),
        headers: BTreeMap::from([("x-provider-tenant".to_owned(), "pilot-beta".to_owned())]),
        body: Some(exact_body.clone()),
    };
    let prepared_send = provider
        .preflight_submit(&provider_binding, &submit)
        .await
        .unwrap();
    let accepted = prepared_send.send().await.unwrap();
    assert_eq!(accepted.status, 202);
    let attempt = G2pAttempt::new(
        Uuid::new_v4(),
        "second-provider".to_owned(),
        "coordinator".to_owned(),
        instruction,
        snapshot,
        submit.clone(),
        PreparedG2pRegistryAction {
            action: "bind-payout-attempt".to_owned(),
            key: "bind-test".to_owned(),
            inputs: Default::default(),
            evidence: "prepared".to_owned(),
        },
    )
    .unwrap();
    let acceptance = ProviderAcceptance {
        correlation_id: attempt.provider_intent.correlation_id.clone(),
        references: BTreeMap::from([("payoutId".to_owned(), "provider-001".to_owned())]),
    };

    let status = PreparedProviderRequest {
        provider_pack: pack,
        role: PaymentEndpointRole::DisbursementStatus,
        method: PaymentHttpMethod::Get,
        path: "/v2/payouts/provider-001".to_owned(),
        query: BTreeMap::from([("view".to_owned(), "settlement".to_owned())]),
        headers: BTreeMap::new(),
        body: None,
    };
    let observed = provider.observe(&provider_binding, &status).await.unwrap();
    assert_eq!(observed.status, 200);
    let exact_observation = observation(&attempt.provider_intent.correlation_id);
    attempt
        .validate_mapped_observation(&acceptance, &exact_observation)
        .unwrap();
    for mismatched in [
        {
            let mut value = exact_observation.clone();
            value.money.minor_units = "99999".to_owned();
            value
        },
        {
            let mut value = exact_observation.clone();
            value.parties[0].value = "other-funding".to_owned();
            value
        },
        {
            let mut value = exact_observation.clone();
            value.parties[1].value = "other-recipient".to_owned();
            value
        },
    ] {
        assert!(matches!(
            attempt.validate_mapped_observation(&acceptance, &mismatched),
            Err(G2pError::Conflict)
        ));
    }

    {
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0],
            SeenRequest {
                method: "POST",
                path_and_query: "/v2/payouts?channel=benefits".to_owned(),
                tenant: Some("pilot-beta".to_owned()),
                authorization_ok: true,
                body: exact_body,
            }
        );
        assert_eq!(
            requests[1],
            SeenRequest {
                method: "GET",
                path_and_query: "/v2/payouts/provider-001?view=settlement".to_owned(),
                tenant: None,
                authorization_ok: true,
                body: Vec::new(),
            }
        );
    }

    let legacy = binding(
        &origin,
        G2pHttpAuth::MifosLegacySignature {
            signing_key_identity: "test-signing-key".to_owned(),
            signing_key_ref: SecretReference::new("secret:file/signing-key").unwrap(),
            response_key_identity: "test-response-key".to_owned(),
            response_key_ref: SecretReference::new("secret:file/response-key").unwrap(),
        },
    );
    assert!(matches!(
        provider.preflight_submit(&legacy, &submit).await,
        Err(G2pProviderError::Unavailable)
    ));
    assert_eq!(seen.lock().unwrap().len(), 2);

    let mut uncertain = submit.clone();
    uncertain.path = "/v2/uncertain".to_owned();
    let uncertain_send = provider
        .preflight_submit(&provider_binding, &uncertain)
        .await
        .unwrap();
    assert!(matches!(
        uncertain_send.send().await,
        Err(G2pProviderError::OutcomeUnknown)
    ));
    assert_eq!(
        provider
            .recover_acceptance(&provider_binding, &uncertain)
            .await
            .unwrap(),
        None
    );
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.path_and_query.starts_with("/v2/uncertain"))
            .count(),
        1
    );
    server.abort();
}

async fn capture_submit(
    State(seen): State<Arc<Mutex<Vec<SeenRequest>>>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    capture(&seen, "POST", uri, headers, body);
    (axum::http::StatusCode::ACCEPTED, r#"{"accepted":true}"#)
}

async fn capture_status(
    State(seen): State<Arc<Mutex<Vec<SeenRequest>>>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    capture(&seen, "GET", uri, headers, body);
    (axum::http::StatusCode::OK, r#"{"state":"complete"}"#)
}

async fn capture_uncertain(
    State(seen): State<Arc<Mutex<Vec<SeenRequest>>>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    capture(&seen, "POST", uri, headers, body);
    vec![b'x'; 131_073]
}

fn capture(
    seen: &Mutex<Vec<SeenRequest>>,
    method: &'static str,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) {
    seen.lock().unwrap().push(SeenRequest {
        method,
        path_and_query: uri
            .path_and_query()
            .expect("request target")
            .as_str()
            .to_owned(),
        tenant: headers
            .get("x-provider-tenant")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        authorization_ok: headers
            .get(axum::http::header::AUTHORIZATION)
            .is_some_and(|value| value.as_bytes() == b"Bearer test-only-bearer"),
        body: body.to_vec(),
    });
}

fn binding(origin: &str, auth: G2pHttpAuth) -> G2pProviderBinding {
    G2pProviderBinding::Http {
        revision: "second-provider-v1".to_owned(),
        submit_base_url: origin.to_owned(),
        status_base_url: origin.to_owned(),
        credential_identity: "second-provider-operator".to_owned(),
        credential_ref: SecretReference::new("secret:file/provider-token").unwrap(),
        auth,
        settings: json!({"tenant": "pilot-beta"}),
    }
}

fn pin() -> ProviderPackPin {
    ProviderPackPin {
        id: "second-provider".to_owned(),
        version: "1".to_owned(),
        digest: format!("sha256:{}", "a".repeat(64)),
    }
}

fn instruction() -> DisbursementInstruction {
    DisbursementInstruction {
        record_id: Uuid::parse_str("00000000-0000-4000-8000-000000000200").unwrap(),
        instruction_id: Uuid::parse_str("00000000-0000-4000-8000-000000000201").unwrap(),
        instruction_version: 1,
        instruction_digest: "a".repeat(64),
        institution_id: "ministry-social-protection".to_owned(),
        service_id: "cash-transfer".to_owned(),
        programme_id: "cash-programme".to_owned(),
        cycle_id: "cycle-2026-11".to_owned(),
        beneficiary_id: "beneficiary-001".to_owned(),
        beneficiary_destination: "254700000002".to_owned(),
        funding_account_id: "programme-account".to_owned(),
        amount_minor: 100_000,
        currency: "KES".to_owned(),
        currency_scale: 2,
    }
}

fn snapshot(provider: G2pProviderBinding, provider_pack: ProviderPackPin) -> G2pConnectionSnapshot {
    G2pConnectionSnapshot {
        institution_id: "ministry-social-protection".to_owned(),
        service_id: "cash-transfer".to_owned(),
        programme_id: "cash-programme".to_owned(),
        funding_account_id: "programme-account".to_owned(),
        currency: "KES".to_owned(),
        currency_scale: 2,
        provider_pack,
        funding_party_key: "ACCOUNT_ID".to_owned(),
        recipient_party_key: "MSISDN".to_owned(),
        provider,
        registry: G2pRegistryBinding {
            base_url: "https://breg.invalid/".to_owned(),
            credential_identity: "g2p-adapter".to_owned(),
            credential_ref: SecretReference::new("secret:file/provider-token").unwrap(),
            record_route: "disbursement-instructions".to_owned(),
            record_type: "disbursement-instruction".to_owned(),
            read_profile: "g2p-adapter-read".to_owned(),
            bind_action: "bind-payout-attempt".to_owned(),
            bind_profile: "g2p-adapter-bind".to_owned(),
            report_action: "record-provider-confirmation".to_owned(),
            report_profile: "g2p-adapter-report".to_owned(),
        },
    }
}

fn observation(correlation_id: &str) -> ProviderObservation {
    ProviderObservation {
        correlation_id: correlation_id.to_owned(),
        provider_reference: "provider-001".to_owned(),
        state: ProviderObservationState::ProviderConfirmed,
        money: ProviderObservedMoney {
            minor_units: "100000".to_owned(),
            currency: "KES".to_owned(),
            scale: 2,
        },
        parties: vec![
            ProviderObservedParty {
                role: ProviderPartyRole::Funding,
                key: "ACCOUNT_ID".to_owned(),
                value: "programme-account".to_owned(),
            },
            ProviderObservedParty {
                role: ProviderPartyRole::Recipient,
                key: "MSISDN".to_owned(),
                value: "254700000002".to_owned(),
            },
        ],
    }
}

fn write_secret(path: std::path::PathBuf, value: &[u8]) {
    std::fs::write(&path, value).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
