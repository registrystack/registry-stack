// SPDX-License-Identifier: Apache-2.0

use registry_adapter::payments::g2p_model::{
    DisbursementInstruction, G2pAttempt, G2pConnectionSnapshot, G2pError, G2pHttpAuth,
    G2pProviderBinding, G2pRegistryBinding, G2pTransitRsaNoOidKeyBinding,
    PreparedG2pRegistryAction,
};
use registry_adapter::payments::pack::{PaymentProviderAuth, ProviderPackPin};
use registry_adapter::payments::provider_mapping::{
    PaymentEndpointRole, PaymentHttpMethod, PreparedProviderRequest, ProviderAcceptance,
    ProviderObservation, ProviderObservationState, ProviderObservedMoney, ProviderObservedParty,
    ProviderPartyRole,
};
use registry_platform_yaml::SecretReference;
use serde_json::{json, Map};
use std::collections::BTreeMap;
use uuid::Uuid;

#[test]
fn attempt_freezes_the_pack_settings_and_exact_prepared_submit_bytes() {
    let binding = binding();
    let intent = binding.provider_intent(&instruction()).unwrap();
    let prepared = PreparedProviderRequest {
        provider_pack: binding.provider_pack.clone(),
        role: PaymentEndpointRole::DisbursementSubmit,
        method: PaymentHttpMethod::Post,
        path: "/bulk/transactions".to_owned(),
        query: BTreeMap::new(),
        headers: BTreeMap::from([("x-tenant".to_owned(), "default".to_owned())]),
        body: Some(br#"{"amount":"1000.00","requestId":"exact"}"#.to_vec()),
    };
    let attempt = G2pAttempt::new(
        Uuid::new_v4(),
        "g2p".to_owned(),
        "coordinator".to_owned(),
        instruction(),
        binding,
        prepared.clone(),
        action(),
    )
    .unwrap();
    let recovered: G2pAttempt =
        serde_json::from_value(serde_json::to_value(&attempt).unwrap()).unwrap();
    recovered.validate_integrity().unwrap();
    assert_eq!(recovered.provider_intent, intent);
    assert_eq!(recovered.prepared_submit, prepared);
    assert_eq!(recovered.prepared_submit.body, prepared.body);
}

#[test]
fn mapped_observation_must_match_the_independent_breg_tuple() {
    let binding = binding();
    let intent = binding.provider_intent(&instruction()).unwrap();
    let attempt = G2pAttempt::new(
        Uuid::new_v4(),
        "g2p".to_owned(),
        "coordinator".to_owned(),
        instruction(),
        binding.clone(),
        prepared_submit(&binding, &intent.correlation_id),
        action(),
    )
    .unwrap();
    let acceptance = ProviderAcceptance {
        correlation_id: intent.correlation_id.clone(),
        references: BTreeMap::from([("batchId".to_owned(), "batch-001".to_owned())]),
    };
    let exact = observation(&intent.correlation_id);
    attempt
        .validate_mapped_observation(&acceptance, &exact)
        .unwrap();

    let mut wrong_funding = exact.clone();
    wrong_funding.parties[0].value = "other-account".to_owned();
    assert_eq!(
        attempt
            .validate_mapped_observation(&acceptance, &wrong_funding)
            .unwrap_err(),
        G2pError::Conflict
    );
    let mut wrong_money = exact;
    wrong_money.money.minor_units = "99999".to_owned();
    assert_eq!(
        attempt
            .validate_mapped_observation(&acceptance, &wrong_money)
            .unwrap_err(),
        G2pError::Conflict
    );
}

#[test]
fn custody_accepts_two_provider_wire_shapes_without_changing_the_breg_tuple() {
    let binding = binding();
    let instruction = instruction();
    let intent = binding.provider_intent(&instruction).unwrap();
    let first_request = prepared_submit(&binding, &intent.correlation_id);
    let mut second_request = first_request.clone();
    second_request.path = "/v2/payouts".to_owned();
    second_request.query = BTreeMap::from([("channel".to_owned(), "benefits".to_owned())]);
    second_request.headers = BTreeMap::from([("x-provider-profile".to_owned(), "v2".to_owned())]);
    second_request.body = Some(
        registry_platform_canonical_json::canonicalize_json(&json!({
            "transfer": {
                "clientReference": intent.correlation_id,
                "debit": intent.funding,
                "credit": intent.recipient,
                "money": intent.money
            }
        }))
        .unwrap(),
    );

    let first = G2pAttempt::new(
        Uuid::new_v4(),
        "g2p-first".to_owned(),
        "coordinator".to_owned(),
        instruction.clone(),
        binding.clone(),
        first_request,
        action(),
    )
    .unwrap();
    let second = G2pAttempt::new(
        Uuid::new_v4(),
        "g2p-second".to_owned(),
        "coordinator".to_owned(),
        instruction,
        binding,
        second_request,
        action(),
    )
    .unwrap();
    assert_eq!(first.provider_intent, second.provider_intent);
    assert_ne!(first.prepared_submit, second.prepared_submit);
    assert_ne!(first.binding_revision, second.binding_revision);
}

#[test]
fn provider_correlation_is_stable_and_namespace_bound() {
    let instruction = instruction();
    let binding = binding();
    let first = binding.provider_intent(&instruction).unwrap();
    let second = binding.provider_intent(&instruction).unwrap();
    assert_eq!(first, second);
    assert!(first.correlation_id.starts_with("g2p_"));

    let mut other = binding.clone();
    let G2pProviderBinding::Http { settings, .. } = &mut other.provider;
    *settings = json!({"tenant": "other-tenant"});
    assert_ne!(
        first.correlation_id,
        other.provider_intent(&instruction).unwrap().correlation_id
    );
    let mut other_revision = binding.clone();
    let G2pProviderBinding::Http { revision, .. } = &mut other_revision.provider;
    *revision = "mifos-test-v2".to_owned();
    assert_ne!(
        first.correlation_id,
        other_revision
            .provider_intent(&instruction)
            .unwrap()
            .correlation_id
    );

    let prepared = prepared_submit(&binding, &first.correlation_id);
    let attempt = G2pAttempt::new(
        Uuid::new_v4(),
        "g2p".to_owned(),
        "coordinator".to_owned(),
        instruction,
        binding,
        prepared,
        action(),
    )
    .unwrap();
    let recovered: G2pAttempt =
        serde_json::from_value(serde_json::to_value(&attempt).unwrap()).unwrap();
    recovered.validate_integrity().unwrap();
    assert_eq!(attempt.provider_intent, recovered.provider_intent);
    assert_eq!(attempt.prepared_submit, recovered.prepared_submit);
}

#[test]
fn correlation_separates_authoritative_sources_and_full_instruction_revisions() {
    let first_instruction = instruction();
    let first_binding = binding();
    let first_intent = first_binding.provider_intent(&first_instruction).unwrap();
    let first = G2pAttempt::new(
        Uuid::new_v4(),
        "g2p".to_owned(),
        "coordinator".to_owned(),
        first_instruction,
        first_binding.clone(),
        prepared_submit(&first_binding, &first_intent.correlation_id),
        action(),
    )
    .unwrap()
    .provider_intent;

    let mut other_source = binding();
    other_source.registry.base_url = "https://other-breg.invalid/".to_owned();
    other_source.registry.credential_identity = "other-g2p-adapter".to_owned();
    other_source.registry.record_route = "other-disbursement-instructions".to_owned();
    let other_intent = other_source.provider_intent(&instruction()).unwrap();
    let from_other_source = G2pAttempt::new(
        Uuid::new_v4(),
        "g2p".to_owned(),
        "coordinator".to_owned(),
        instruction(),
        other_source.clone(),
        prepared_submit(&other_source, &other_intent.correlation_id),
        action(),
    )
    .unwrap()
    .provider_intent;

    let mut revised_instruction = instruction();
    revised_instruction.record_id =
        Uuid::parse_str("00000000-0000-4000-8000-000000000199").unwrap();
    revised_instruction.instruction_digest = "b".repeat(64);
    revised_instruction.cycle_id = "cycle-2026-12".to_owned();
    revised_instruction.beneficiary_id = "beneficiary-002".to_owned();
    let revised_binding = binding();
    let revised_intent = revised_binding
        .provider_intent(&revised_instruction)
        .unwrap();
    let from_revised_instruction = G2pAttempt::new(
        Uuid::new_v4(),
        "g2p".to_owned(),
        "coordinator".to_owned(),
        revised_instruction,
        revised_binding.clone(),
        prepared_submit(&revised_binding, &revised_intent.correlation_id),
        action(),
    )
    .unwrap()
    .provider_intent;

    for distinct in [&from_other_source, &from_revised_instruction] {
        assert_eq!(first.money, distinct.money);
        assert_eq!(first.recipient, distinct.recipient);
        assert_eq!(first.funding, distinct.funding);
        assert_ne!(first.correlation_id, distinct.correlation_id);
    }
}

#[test]
fn correlation_canonicalizes_equivalent_provider_and_source_origins() {
    let mut first_binding = binding();
    first_binding.registry.base_url = "https://BREG.EXAMPLE:443/".to_owned();
    let G2pProviderBinding::Http {
        submit_base_url,
        status_base_url,
        ..
    } = &mut first_binding.provider;
    *submit_base_url = "https://BULK.EXAMPLE:443/".to_owned();
    *status_base_url = "https://OPERATIONS.EXAMPLE:443/".to_owned();
    let first_intent = first_binding.provider_intent(&instruction()).unwrap();
    let first = G2pAttempt::new(
        Uuid::new_v4(),
        "g2p".to_owned(),
        "coordinator".to_owned(),
        instruction(),
        first_binding.clone(),
        prepared_submit(&first_binding, &first_intent.correlation_id),
        action(),
    )
    .unwrap()
    .provider_intent;

    let mut second_binding = binding();
    second_binding.registry.base_url = "https://breg.example/".to_owned();
    let G2pProviderBinding::Http {
        submit_base_url,
        status_base_url,
        ..
    } = &mut second_binding.provider;
    *submit_base_url = "https://bulk.example/".to_owned();
    *status_base_url = "https://operations.example/".to_owned();
    let second_intent = second_binding.provider_intent(&instruction()).unwrap();
    let second = G2pAttempt::new(
        Uuid::new_v4(),
        "g2p".to_owned(),
        "coordinator".to_owned(),
        instruction(),
        second_binding.clone(),
        prepared_submit(&second_binding, &second_intent.correlation_id),
        action(),
    )
    .unwrap()
    .provider_intent;

    assert_eq!(first, second);
}

#[test]
fn connection_refuses_wrong_programme_and_funding_before_attempt_custody() {
    let binding = binding();
    let mut wrong_programme = instruction();
    wrong_programme.programme_id = "other-programme".to_owned();
    assert_eq!(
        binding.validate_instruction(&wrong_programme).unwrap_err(),
        G2pError::Conflict
    );

    let mut wrong_funding = instruction();
    wrong_funding.funding_account_id = "other-funding".to_owned();
    assert_eq!(
        binding.validate_instruction(&wrong_funding).unwrap_err(),
        G2pError::Conflict
    );

    assert_eq!(
        G2pAttempt::new(
            Uuid::new_v4(),
            "g2p".to_owned(),
            "coordinator".to_owned(),
            wrong_funding,
            binding.clone(),
            prepared_submit(
                &binding,
                &binding
                    .provider_intent(&instruction())
                    .unwrap()
                    .correlation_id,
            ),
            action(),
        )
        .err(),
        Some(G2pError::Conflict)
    );
}

#[test]
fn provider_binding_exposes_the_exact_pack_auth_profile() {
    let mut provider = binding().provider;
    assert_eq!(provider.auth_profile(), PaymentProviderAuth::Bearer);
    let G2pProviderBinding::Http { auth, .. } = &mut provider;
    *auth = G2pHttpAuth::MifosLegacySignature {
        tenant: "default".to_owned(),
        signing_key_identity: "mifos-signing-key".to_owned(),
        signing_key: Box::new(transit_key("mifos-request", 7, 'a')),
        response_key_identity: "mifos-response-key".to_owned(),
        response_key: Box::new(transit_key("mifos-response", 4, 'b')),
        operations_credential_identity: "mifos-operations-client".to_owned(),
        operations_credential_ref: SecretReference::new("secret:env/MIFOS_OPERATIONS_TOKEN")
            .unwrap(),
    };
    assert_eq!(
        provider.auth_profile(),
        PaymentProviderAuth::MifosLegacySignature
    );
}

#[test]
fn provider_identity_freezes_transit_versions_and_logical_operations_identity() {
    let mut first = binding();
    let G2pProviderBinding::Http { auth, .. } = &mut first.provider;
    *auth = G2pHttpAuth::MifosLegacySignature {
        tenant: "default".to_owned(),
        signing_key_identity: "mifos-signing-key".to_owned(),
        signing_key: Box::new(transit_key("mifos-request", 7, 'a')),
        response_key_identity: "mifos-response-key".to_owned(),
        response_key: Box::new(transit_key("mifos-response", 4, 'b')),
        operations_credential_identity: "mifos-operations-client".to_owned(),
        operations_credential_ref: SecretReference::new("secret:env/MIFOS_OPERATIONS_TOKEN")
            .unwrap(),
    };
    let instruction = instruction();
    let first_correlation = first.provider_intent(&instruction).unwrap().correlation_id;

    let mut rotated_secret = first.clone();
    let G2pProviderBinding::Http {
        auth:
            G2pHttpAuth::MifosLegacySignature {
                operations_credential_ref,
                ..
            },
        ..
    } = &mut rotated_secret.provider
    else {
        unreachable!()
    };
    *operations_credential_ref =
        SecretReference::new("secret:env/MIFOS_OPERATIONS_TOKEN_NEXT").unwrap();
    assert_eq!(
        rotated_secret
            .provider_intent(&instruction)
            .unwrap()
            .correlation_id,
        first_correlation
    );

    let mut new_signing_version = first.clone();
    let G2pProviderBinding::Http {
        auth: G2pHttpAuth::MifosLegacySignature { signing_key, .. },
        ..
    } = &mut new_signing_version.provider
    else {
        unreachable!()
    };
    **signing_key = transit_key("mifos-request", 8, 'a');
    assert_ne!(
        new_signing_version
            .provider_intent(&instruction)
            .unwrap()
            .correlation_id,
        first_correlation
    );

    let mut other_operations_identity = first.clone();
    let G2pProviderBinding::Http {
        auth:
            G2pHttpAuth::MifosLegacySignature {
                operations_credential_identity,
                ..
            },
        ..
    } = &mut other_operations_identity.provider
    else {
        unreachable!()
    };
    *operations_credential_identity = "other-operations-client".to_owned();
    assert_ne!(
        other_operations_identity
            .provider_intent(&instruction)
            .unwrap()
            .correlation_id,
        first_correlation
    );
}

#[test]
fn provider_auth_and_binding_use_strict_camel_case_authored_fields() {
    let signature = json!({
        "type": "mifos-legacy-signature",
        "tenant": "default",
        "signingKeyIdentity": "mifos-signing-key",
        "signingKey": {
            "socketPath": "/run/registry/transit.sock",
            "mount": "transit",
            "key": "mifos-request",
            "version": 7,
            "publicKeyDigest": format!("sha256:{}", "a".repeat(64)),
            "attemptTimeoutMilliseconds": 2000
        },
        "responseKeyIdentity": "mifos-response-key",
        "responseKey": {
            "socketPath": "/run/registry/transit.sock",
            "mount": "transit",
            "key": "mifos-response",
            "version": 4,
            "publicKeyDigest": format!("sha256:{}", "b".repeat(64)),
            "attemptTimeoutMilliseconds": 2000
        },
        "operationsCredentialIdentity": "mifos-operations-client",
        "operationsCredentialRef": "secret:env/MIFOS_OPERATIONS_TOKEN"
    });
    let auth: G2pHttpAuth = serde_json::from_value(signature.clone()).unwrap();
    assert_eq!(serde_json::to_value(&auth).unwrap(), signature);
    let mut invalid_tenant = signature.clone();
    invalid_tenant["tenant"] = json!("pilot-🙂");
    let invalid_tenant: G2pHttpAuth = serde_json::from_value(invalid_tenant).unwrap();
    assert_eq!(invalid_tenant.validate(), Err(G2pError::Unavailable));
    assert!(serde_json::from_value::<G2pHttpAuth>(json!({
        "type": "mifos-legacy-signature",
        "signing_key_identity": "mifos-signing-key",
        "tenant": "default",
        "signingKey": signature["signingKey"].clone(),
        "responseKeyIdentity": "mifos-response-key",
        "responseKey": signature["responseKey"].clone(),
        "operationsCredentialIdentity": "mifos-operations-client",
        "operationsCredentialRef": "secret:env/MIFOS_OPERATIONS_TOKEN"
    }))
    .is_err());

    for invalid in [
        json!({
            "type": "mifos-legacy-signature",
            "tenant": "default",
            "signingKeyIdentity": "same-key",
            "signingKey": signature["signingKey"].clone(),
            "responseKeyIdentity": "same-key",
            "responseKey": signature["responseKey"].clone(),
            "operationsCredentialIdentity": "mifos-operations-client",
            "operationsCredentialRef": "secret:env/MIFOS_OPERATIONS_TOKEN"
        }),
        json!({
            "type": "mifos-legacy-signature",
            "tenant": "default",
            "signingKeyIdentity": "mifos-signing-key",
            "signingKey": {
                "socketPath": "run/registry/transit.sock",
                "mount": "transit",
                "key": "mifos-request",
                "version": 7,
                "publicKeyDigest": format!("sha256:{}", "a".repeat(64)),
                "attemptTimeoutMilliseconds": 2000
            },
            "responseKeyIdentity": "mifos-response-key",
            "responseKey": signature["responseKey"].clone(),
            "operationsCredentialIdentity": "mifos-operations-client",
            "operationsCredentialRef": "secret:env/MIFOS_OPERATIONS_TOKEN"
        }),
        json!({
            "type": "mifos-legacy-signature",
            "tenant": "default",
            "signingKeyIdentity": "mifos-signing-key",
            "signingKey": signature["signingKey"].clone(),
            "responseKeyIdentity": "mifos-response-key",
            "responseKey": {
                "socketPath": "/run/registry/transit.sock",
                "mount": "transit",
                "key": "mifos-response",
                "version": 4,
                "publicKeyDigest": format!("sha256:{}", "B".repeat(64)),
                "attemptTimeoutMilliseconds": 2000
            },
            "operationsCredentialIdentity": "mifos-operations-client",
            "operationsCredentialRef": "secret:env/MIFOS_OPERATIONS_TOKEN"
        }),
    ] {
        if let Ok(auth) = serde_json::from_value::<G2pHttpAuth>(invalid) {
            assert_eq!(auth.validate(), Err(G2pError::Unavailable));
        }
    }
    assert!(serde_json::from_value::<G2pHttpAuth>(json!({
        "type": "bearer",
        "credentialIdentity": "mifos-test-client"
    }))
    .is_err());

    let provider = binding().provider;
    let encoded = serde_json::to_value(&provider).unwrap();
    assert!(encoded.get("submitBaseUrl").is_some());
    assert!(encoded.get("statusBaseUrl").is_some());
    assert!(encoded.get("credentialIdentity").is_none());
    assert!(encoded.get("credentialRef").is_none());
    assert!(encoded["auth"].get("credentialIdentity").is_some());
    assert!(encoded["auth"].get("credentialRef").is_some());
    assert!(encoded.get("submit_base_url").is_none());
    let decoded: G2pProviderBinding = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.auth_profile(), PaymentProviderAuth::Bearer);
}

fn transit_key(key: &str, version: u32, digest_digit: char) -> G2pTransitRsaNoOidKeyBinding {
    serde_json::from_value(json!({
        "socketPath": "/run/registry/transit.sock",
        "mount": "transit",
        "key": key,
        "version": version,
        "publicKeyDigest": format!("sha256:{}", digest_digit.to_string().repeat(64)),
        "attemptTimeoutMilliseconds": 2000
    }))
    .unwrap()
}

fn instruction() -> DisbursementInstruction {
    DisbursementInstruction {
        record_id: Uuid::parse_str("00000000-0000-4000-8000-000000000100").unwrap(),
        instruction_id: Uuid::parse_str("00000000-0000-4000-8000-000000000101").unwrap(),
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

fn binding() -> G2pConnectionSnapshot {
    G2pConnectionSnapshot {
        institution_id: "ministry-social-protection".to_owned(),
        service_id: "cash-transfer".to_owned(),
        programme_id: "cash-programme".to_owned(),
        funding_account_id: "programme-account".to_owned(),
        currency: "KES".to_owned(),
        currency_scale: 2,
        provider_pack: ProviderPackPin {
            id: "g2p-test".to_owned(),
            version: "1".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
        },
        funding_party_key: "ACCOUNT_ID".to_owned(),
        recipient_party_key: "MSISDN".to_owned(),
        provider: G2pProviderBinding::Http {
            revision: "mifos-test-v1".to_owned(),
            submit_base_url: "http://127.0.0.1:31002/".to_owned(),
            status_base_url: "http://127.0.0.1:31003/".to_owned(),
            auth: G2pHttpAuth::Bearer {
                credential_identity: "mifos-test-client".to_owned(),
                credential_ref: SecretReference::new("secret:env/MIFOS_TEST_TOKEN").unwrap(),
            },
            settings: json!({"tenant": "default", "purpose": "GOVERNMENT_TRANSFER"}),
        },
        registry: G2pRegistryBinding {
            base_url: "https://breg.invalid/".to_owned(),
            credential_identity: "g2p-adapter".to_owned(),
            credential_ref: SecretReference::new("secret:env/BREG_TEST_TOKEN").unwrap(),
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

fn prepared_submit(
    binding: &G2pConnectionSnapshot,
    correlation_id: &str,
) -> PreparedProviderRequest {
    PreparedProviderRequest {
        provider_pack: binding.provider_pack.clone(),
        role: PaymentEndpointRole::DisbursementSubmit,
        method: PaymentHttpMethod::Post,
        path: "/bulk/transactions".to_owned(),
        query: BTreeMap::new(),
        headers: BTreeMap::new(),
        body: Some(
            registry_platform_canonical_json::canonicalize_json(&json!({
                "correlationId": correlation_id,
                "amountMinor": "100000"
            }))
            .unwrap(),
        ),
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

fn action() -> PreparedG2pRegistryAction {
    PreparedG2pRegistryAction {
        action: "bind-payout-attempt".to_owned(),
        key: "g2p-bind-test".to_owned(),
        inputs: Map::new(),
        evidence: "prepared".to_owned(),
    }
}
