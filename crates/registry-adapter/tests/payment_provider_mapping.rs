// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use registry_adapter::payments::pack::{PaymentProviderAuth, PaymentProviderPack};
use registry_adapter::payments::provider_mapping::{
    MappedProviderResponse, PaymentEndpointRole, PaymentHttpMethod, PaymentMappingError,
    PaymentMappingProgram, PreparedProviderRequest, ProviderAcceptance, ProviderHttpResponse,
    ProviderObservationState, ProviderPartyRole,
};
use serde_json::{json, Value};

const ALPHA: &str = r#"
fn alpha_submit_request(intent, settings, acceptance) {
    if acceptance != () { throw "submit accepts no prior acceptance"; }
    #{
        pathParameters: #{},
        query: #{},
        headers: #{"x-tenant": settings.tenant},
        body: #{
            payer: #{scheme: intent.source.scheme, identifier: intent.source.value},
            amount: #{minorUnits: intent.money.minorUnits, currency: intent.money.currency},
            clientReference: intent.correlationId
        }
    }
}

fn alpha_submit_response(intent, settings, acceptance, response) {
    if settings == () || acceptance != () || response.status != 202 {
        throw "unexpected submit response";
    }
    #{correlationId: intent.correlationId, references: #{transaction: response.body.transactionId}}
}

fn alpha_status_request(intent, settings, acceptance) {
    if settings == () || acceptance == () { throw "status needs acceptance"; }
    #{
        pathParameters: #{id: acceptance.references.transaction},
        query: #{},
        headers: #{},
        body: ()
    }
}

fn alpha_status_response(intent, settings, acceptance, response) {
    if settings == () || acceptance == () || response.body.clientReference != intent.correlationId {
        throw "correlation mismatch";
    }
    #{
        correlationId: response.body.clientReference,
        providerReference: response.body.transactionId,
        state: if response.body.status == "DONE" { "provider-confirmed" } else { "pending" },
        money: #{
            minorUnits: response.body.amount.minorUnits,
            currency: response.body.amount.currency,
            scale: 2
        },
        parties: [
            #{role: "payer", key: response.body.payer.scheme, value: response.body.payer.identifier},
            #{role: "payer", key: response.body.payerId.scheme, value: response.body.payerId.identifier}
        ]
    }
}
"#;

const BETA: &str = r#"
fn beta_submit_request(intent, settings, acceptance) {
    if acceptance != () { throw "submit accepts no prior acceptance"; }
    #{
        pathParameters: #{},
        query: #{channel: settings.channel},
        headers: #{},
        body: #{
            transfer: [intent.correlationId, intent.money.currency, intent.money.minorUnits],
            account: intent.source.value
        }
    }
}

fn beta_submit_response(intent, settings, acceptance, response) {
    if settings == () || acceptance != () || response.status != 200 {
        throw "unexpected submit response";
    }
    #{correlationId: intent.correlationId, references: #{ticket: response.body.result.ticket}}
}

fn beta_status_request(intent, settings, acceptance) {
    if intent == () || settings == () || acceptance == () { throw "status needs context"; }
    #{
        pathParameters: #{},
        query: #{ticket: acceptance.references.ticket},
        headers: #{},
        body: ()
    }
}

fn beta_status_response(intent, settings, acceptance, response) {
    if settings == () || acceptance == () || response.body.echo[0] != intent.correlationId {
        throw "correlation mismatch";
    }
    #{
        correlationId: response.body.echo[0],
        providerReference: response.body.result.ticket,
        state: if response.body.result.code == "7" { "provider-confirmed" } else { "pending" },
        money: #{
            minorUnits: response.body.echo[2],
            currency: response.body.echo[1],
            scale: 2
        },
        parties: [
            #{role: "payer", key: "account", value: response.body.account},
            #{role: "payer", key: "payer-id", value: response.body.payerId}
        ]
    }
}
"#;

const G2P: &str = r#"
fn submit_request(intent, settings, acceptance) {
    if settings == () || acceptance != () { throw "invalid submit context"; }
    #{
        pathParameters: #{}, query: #{}, headers: #{},
        body: #{
            correlation: intent.correlationId,
            debit: intent.funding.value,
            credit: intent.recipient.value,
            minorUnits: intent.money.minorUnits,
            currency: intent.money.currency
        }
    }
}
fn submit_response(intent, settings, acceptance, response) {
    if settings == () || acceptance != () { throw "invalid submit context"; }
    #{correlationId: intent.correlationId, references: #{transfer: response.body.id}}
}
fn status_request(intent, settings, acceptance) {
    if intent == () || settings == () || acceptance == () { throw "status needs context"; }
    #{pathParameters: #{}, query: #{id: acceptance.references.transfer}, headers: #{}, body: ()}
}
fn status_response(intent, settings, acceptance, response) {
    if settings == () || acceptance == () { throw "status needs context"; }
    #{
        correlationId: response.body.correlation,
        providerReference: response.body.id,
        state: "provider-confirmed",
        money: #{minorUnits: response.body.minorUnits, currency: response.body.currency, scale: 2},
        parties: [
            #{role: "funding", key: response.body.debit.scheme, value: response.body.debit.value},
            #{role: "recipient", key: response.body.credit.scheme, value: response.body.credit.value}
        ]
    }
}
"#;

fn provider_pack(id: &str, script_path: &str, script: &str, beta: bool) -> String {
    let prefix = if beta { "beta" } else { "alpha" };
    let (submit_path, status_path) = if beta {
        ("/transfers", "/lookup")
    } else {
        ("/collections", "/transactions/{{id}}")
    };
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1
kind: AdapterPaymentProviderPack
id: {id}
version: '1'
connector: adapter-payment-http/v1
capabilities: [collection]
mapping:
  collection:
    auth: bearer
    submit:
      path: {submit_path}
      request: {{file: {script_path}, entrypoint: {prefix}_submit_request}}
      response: {{file: {script_path}, entrypoint: {prefix}_submit_response}}
    status:
      path: {status_path}
      request: {{file: {script_path}, entrypoint: {prefix}_status_request}}
      response: {{file: {script_path}, entrypoint: {prefix}_status_response}}
  scripts:
    - path: {script_path}
      digest: {}
"#,
        registry_platform_config::sha256_uri(script.as_bytes())
    )
}

fn compile(yaml: &str, path: &str, script: &str) -> PaymentMappingProgram {
    let pack = PaymentProviderPack::from_yaml(yaml.as_bytes()).expect("pack decodes");
    pack.validate().expect("pack validates");
    PaymentMappingProgram::compile(
        &pack,
        yaml.as_bytes(),
        &BTreeMap::from([(path.to_owned(), script.as_bytes().to_vec())]),
    )
    .expect("mapping compiles")
}

fn disbursement_pack(script: &str) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1
kind: AdapterPaymentProviderPack
id: g2p-pay
version: '1'
connector: adapter-payment-http/v1
capabilities: [disbursement]
mapping:
  disbursement:
    auth: mifos-legacy-signature
    submit:
      path: /disbursements
      request: {{file: scripts/g2p.rhai, entrypoint: submit_request}}
      response: {{file: scripts/g2p.rhai, entrypoint: submit_response}}
    status:
      path: /disbursements/status
      request: {{file: scripts/g2p.rhai, entrypoint: status_request}}
      response: {{file: scripts/g2p.rhai, entrypoint: status_response}}
  scripts:
    - path: scripts/g2p.rhai
      digest: {}
"#,
        registry_platform_config::sha256_uri(script.as_bytes())
    )
}

fn intent() -> Value {
    json!({
        "correlationId": "collect_123",
        "money": {"minorUnits": 1250, "currency": "USD", "scale": 2},
        "source": {"scheme": "phone", "value": "+15550100"}
    })
}

fn acceptance(mapped: MappedProviderResponse) -> ProviderAcceptance {
    match mapped {
        MappedProviderResponse::Acceptance(acceptance) => acceptance,
        MappedProviderResponse::Observation(_) => panic!("submit returned an observation"),
    }
}

fn provider_response(status: u16, body: Value) -> ProviderHttpResponse {
    ProviderHttpResponse {
        status,
        body: serde_json::to_vec(&body).expect("provider response serializes"),
    }
}

#[test]
fn compiled_provider_packs_remain_mapping_free() {
    let simulator = PaymentProviderPack::from_yaml(
        b"apiVersion: id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1\nkind: AdapterPaymentProviderPack\nid: payment-simulator\nversion: '1'\nconnector: simulator-p2g/v1\ncapabilities: [collection]\n",
    )
    .expect("legacy simulator pack decodes");
    assert!(simulator.validate().is_ok());
    assert!(simulator.mapping.is_none());
}

#[test]
fn data_driven_operations_require_a_closed_auth_profile() {
    let collection_yaml = provider_pack("alpha-pay", "scripts/alpha.rhai", ALPHA, false);
    let collection = PaymentProviderPack::from_yaml(collection_yaml.as_bytes())
        .expect("collection pack decodes");
    assert_eq!(
        collection
            .mapping
            .as_ref()
            .and_then(|mapping| mapping.collection.as_ref())
            .map(|operation| operation.auth),
        Some(PaymentProviderAuth::Bearer)
    );

    let disbursement_yaml = disbursement_pack(G2P);
    let disbursement = PaymentProviderPack::from_yaml(disbursement_yaml.as_bytes())
        .expect("disbursement pack decodes");
    assert_eq!(
        disbursement
            .mapping
            .as_ref()
            .and_then(|mapping| mapping.disbursement.as_ref())
            .map(|operation| operation.auth),
        Some(PaymentProviderAuth::MifosLegacySignature)
    );

    let missing = collection_yaml.replace("    auth: bearer\n", "");
    assert!(PaymentProviderPack::from_yaml(missing.as_bytes()).is_err());
    let unknown = collection_yaml.replace("auth: bearer", "auth: provider-default");
    assert!(PaymentProviderPack::from_yaml(unknown.as_bytes()).is_err());
}

#[test]
fn two_provider_wire_shapes_run_through_the_same_mapping_program() {
    let alpha_yaml = provider_pack("alpha-pay", "scripts/alpha.rhai", ALPHA, false);
    let alpha = compile(&alpha_yaml, "scripts/alpha.rhai", ALPHA);
    let settings = json!({"tenant": "district-7"});
    let alpha_request = alpha
        .prepare(
            PaymentEndpointRole::CollectionSubmit,
            &intent(),
            &settings,
            None,
        )
        .expect("alpha request maps");
    assert_eq!(alpha_request.method, PaymentHttpMethod::Post);
    assert_eq!(alpha_request.path, "/collections");
    assert_eq!(
        alpha_request.provider_pack.digest,
        registry_platform_config::sha256_uri(alpha_yaml.as_bytes())
    );
    assert_eq!(alpha_request.headers["x-tenant"], "district-7");
    assert_eq!(
        serde_json::from_slice::<Value>(alpha_request.body.as_deref().expect("POST body"))
            .expect("canonical JSON body"),
        json!({
            "payer": {"scheme": "phone", "identifier": "+15550100"},
            "amount": {"minorUnits": 1250, "currency": "USD"},
            "clientReference": "collect_123"
        })
    );
    assert_eq!(
        alpha_request.body.as_deref(),
        Some(
            br#"{"amount":{"currency":"USD","minorUnits":1250},"clientReference":"collect_123","payer":{"identifier":"+15550100","scheme":"phone"}}"#
                .as_slice()
        ),
        "the retained bytes are canonical and need no remapping before send"
    );
    let retained = serde_json::to_vec(&alpha_request).expect("request serializes");
    assert_eq!(
        serde_json::from_slice::<PreparedProviderRequest>(&retained).expect("request deserializes"),
        alpha_request
    );
    let alpha_acceptance = acceptance(
        alpha
            .interpret(
                PaymentEndpointRole::CollectionSubmit,
                &intent(),
                &settings,
                None,
                &provider_response(202, json!({"transactionId": "alpha-77"})),
            )
            .expect("alpha acceptance maps"),
    );
    let alpha_status = alpha
        .prepare(
            PaymentEndpointRole::CollectionStatus,
            &intent(),
            &settings,
            Some(&alpha_acceptance),
        )
        .expect("alpha status maps");
    assert_eq!(alpha_status.method, PaymentHttpMethod::Get);
    assert_eq!(alpha_status.path, "/transactions/alpha-77");
    for dot_segment in [".", ".."] {
        let unsafe_acceptance = ProviderAcceptance {
            correlation_id: "collect_123".to_owned(),
            references: BTreeMap::from([("transaction".to_owned(), dot_segment.to_owned())]),
        };
        assert!(alpha
            .prepare(
                PaymentEndpointRole::CollectionStatus,
                &intent(),
                &settings,
                Some(&unsafe_acceptance),
            )
            .is_err());
    }

    let beta_yaml = provider_pack("beta-pay", "scripts/beta.rhai", BETA, true);
    let beta = compile(&beta_yaml, "scripts/beta.rhai", BETA);
    let beta_settings = json!({"channel": "cashier"});
    let beta_request = beta
        .prepare(
            PaymentEndpointRole::CollectionSubmit,
            &intent(),
            &beta_settings,
            None,
        )
        .expect("beta request maps");
    assert_eq!(beta_request.method, PaymentHttpMethod::Post);
    assert_eq!(beta_request.path, "/transfers");
    assert_eq!(beta_request.query["channel"], "cashier");
    assert_eq!(
        serde_json::from_slice::<Value>(beta_request.body.as_deref().expect("POST body"))
            .expect("canonical JSON body"),
        json!({
            "transfer": ["collect_123", "USD", 1250],
            "account": "+15550100"
        })
    );
    let beta_acceptance = acceptance(
        beta.interpret(
            PaymentEndpointRole::CollectionSubmit,
            &intent(),
            &beta_settings,
            None,
            &provider_response(200, json!({"result": {"ticket": "B-998"}})),
        )
        .expect("beta acceptance maps"),
    );
    let observed = beta
        .interpret(
            PaymentEndpointRole::CollectionStatus,
            &intent(),
            &beta_settings,
            Some(&beta_acceptance),
            &provider_response(
                200,
                json!({
                    "result": {"ticket": "B-998", "code": 7},
                    "echo": ["collect_123", "USD", 1250],
                    "account": "+15550100",
                    "payerId": "payer-42"
                }),
            ),
        )
        .expect("beta observation maps");
    let MappedProviderResponse::Observation(observed) = observed else {
        panic!("status returned an acceptance");
    };
    assert_eq!(observed.state, ProviderObservationState::ProviderConfirmed);
    assert_eq!(observed.provider_reference, "B-998");
    assert_eq!(observed.money.minor_units, "1250");
    assert_eq!(observed.parties[0].role, ProviderPartyRole::Payer);
    assert_eq!(observed.parties[1].role, ProviderPartyRole::Payer);

    let duplicate_keys = BETA.replace(
        r#"key: "payer-id", value: response.body.payerId"#,
        r#"key: "account", value: response.body.payerId"#,
    );
    assert_ne!(duplicate_keys, BETA, "fixture must duplicate the payer key");
    let duplicate_yaml = provider_pack(
        "duplicate-payer-keys",
        "scripts/beta.rhai",
        &duplicate_keys,
        true,
    );
    let duplicate = compile(&duplicate_yaml, "scripts/beta.rhai", &duplicate_keys);
    assert!(duplicate
        .interpret(
            PaymentEndpointRole::CollectionStatus,
            &intent(),
            &beta_settings,
            Some(&beta_acceptance),
            &provider_response(
                200,
                json!({
                    "result": {"ticket": "B-998", "code": 7},
                    "echo": ["collect_123", "USD", 1250],
                    "account": "+15550100",
                    "payerId": "payer-42"
                }),
            ),
        )
        .is_err());
}

#[test]
fn restored_prepared_request_refuses_tampered_serialized_authority() {
    let yaml = provider_pack("alpha-pay", "scripts/alpha.rhai", ALPHA, false);
    let program = compile(&yaml, "scripts/alpha.rhai", ALPHA);
    let request = program
        .prepare(
            PaymentEndpointRole::CollectionSubmit,
            &intent(),
            &json!({"tenant": "district-7"}),
            None,
        )
        .expect("request maps");
    request
        .validate_restored(
            PaymentEndpointRole::CollectionSubmit,
            program.provider_pack(),
        )
        .expect("untampered retained request validates");

    let serialized = serde_json::to_value(&request).expect("request serializes");
    let mut tampered = Vec::new();

    let mut path = serialized.clone();
    path["path"] = json!("/..");
    tampered.push(path);

    let mut header = serialized.clone();
    header["headers"]["x-http-method-override"] = json!("DELETE");
    tampered.push(header);

    let mut header_value = serialized.clone();
    header_value["headers"]["x-tenant"] = json!("district-7\r\ninjected: true");
    tampered.push(header_value);

    let mut query = serialized.clone();
    query["query"][""] = json!("invalid-name");
    tampered.push(query);

    let mut method = serialized.clone();
    method["method"] = json!("GET");
    tampered.push(method);

    let mut role = serialized.clone();
    role["role"] = json!("disbursement-submit");
    tampered.push(role);

    let mut body = serialized.clone();
    body["body"] =
        serde_json::to_value(br#"{ "amount": 1 }"#.to_vec()).expect("tampered bytes serialize");
    tampered.push(body);

    let mut pin = serialized;
    pin["providerPack"]["digest"] = json!(registry_platform_config::sha256_uri(b"other pack"));
    tampered.push(pin);

    for value in tampered {
        let restored: PreparedProviderRequest =
            serde_json::from_value(value).expect("tampered request remains structurally decodable");
        assert_eq!(
            restored.validate_restored(
                PaymentEndpointRole::CollectionSubmit,
                program.provider_pack(),
            ),
            Err(PaymentMappingError::RestoredRequestInvalid)
        );
    }
}

#[test]
fn the_mapping_boundary_refuses_unpinned_scripts_and_transport_authority() {
    let yaml = provider_pack("alpha-pay", "scripts/alpha.rhai", ALPHA, false);
    let pack = PaymentProviderPack::from_yaml(yaml.as_bytes()).expect("pack decodes");
    let changed = format!("{ALPHA}\n// changed after review");
    assert!(PaymentMappingProgram::compile(
        &pack,
        yaml.as_bytes(),
        &BTreeMap::from([("scripts/alpha.rhai".to_owned(), changed.into_bytes())]),
    )
    .is_err());

    let forbidden = r#"
fn request(intent, settings, acceptance) {
    #{
        pathParameters: #{}, query: #{},
        headers: #{"authorization": settings.secret},
        body: intent
    }
}

fn response(intent, settings, acceptance, response) {
    #{correlationId: intent.correlationId, references: #{id: response.body.id}}
}
"#;
    for header in [
        "authorization",
        "x-http-method-override",
        "x-method-override",
        "x-original-url",
        "x-rewrite-url",
        "te",
        "trailer",
        "keep-alive",
        "proxy-connection",
    ] {
        let forbidden = forbidden.replace("authorization", header);
        let forbidden_yaml = format!(
            r#"apiVersion: id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1
kind: AdapterPaymentProviderPack
id: forbidden-pay
version: '1'
connector: adapter-payment-http/v1
capabilities: [collection]
mapping:
  collection:
    auth: bearer
    submit:
      path: /collect
      request: {{file: scripts/forbidden.rhai, entrypoint: request}}
      response: {{file: scripts/forbidden.rhai, entrypoint: response}}
  scripts:
    - path: scripts/forbidden.rhai
      digest: {}
"#,
            registry_platform_config::sha256_uri(forbidden.as_bytes())
        );
        let program = compile(&forbidden_yaml, "scripts/forbidden.rhai", &forbidden);
        assert!(program
            .prepare(
                PaymentEndpointRole::CollectionSubmit,
                &intent(),
                &json!({"secret": "must-not-cross"}),
                None,
            )
            .is_err());
    }
}

#[test]
fn disbursement_observation_requires_funding_and_recipient_roles() {
    let yaml = disbursement_pack(G2P);
    let program = compile(&yaml, "scripts/g2p.rhai", G2P);
    let intent = json!({
        "correlationId": "g2p_123",
        "money": {"minorUnits": 9900, "currency": "USD", "scale": 2},
        "funding": {"scheme": "account", "value": "treasury"},
        "recipient": {"scheme": "wallet", "value": "beneficiary-7"}
    });
    let settings = json!({});
    let accepted = acceptance(
        program
            .interpret(
                PaymentEndpointRole::DisbursementSubmit,
                &intent,
                &settings,
                None,
                &provider_response(202, json!({"id": "transfer-7"})),
            )
            .expect("acceptance maps"),
    );
    let response = provider_response(
        200,
        json!({
            "id": "transfer-7",
            "correlation": "g2p_123",
            "minorUnits": 9900,
            "currency": "USD",
            "debit": {"scheme": "account", "value": "treasury"},
            "credit": {"scheme": "wallet", "value": "beneficiary-7"}
        }),
    );
    let mapped = program
        .interpret(
            PaymentEndpointRole::DisbursementStatus,
            &intent,
            &settings,
            Some(&accepted),
            &response,
        )
        .expect("role-complete observation maps");
    let MappedProviderResponse::Observation(observed) = mapped else {
        panic!("status returned acceptance");
    };
    assert_eq!(observed.parties[0].role, ProviderPartyRole::Funding);
    assert_eq!(observed.parties[1].role, ProviderPartyRole::Recipient);

    let missing_funding = G2P.replace("role: \"funding\"", "role: \"recipient\"");
    let refused_yaml = disbursement_pack(&missing_funding);
    let refused = compile(&refused_yaml, "scripts/g2p.rhai", &missing_funding);
    assert!(refused
        .interpret(
            PaymentEndpointRole::DisbursementStatus,
            &intent,
            &settings,
            Some(&accepted),
            &response,
        )
        .is_err());
}

#[test]
fn provider_json_numbers_reach_response_scripts_as_exact_strings() {
    let script = r#"
fn submit_request(intent, settings, acceptance) {
    if acceptance != () { throw "submit accepts no prior acceptance"; }
    #{pathParameters: #{}, query: #{}, headers: #{}, body: intent}
}
fn submit_response(intent, settings, acceptance, response) {
    if acceptance != () { throw "submit accepts no prior acceptance"; }
    #{
        correlationId: intent.correlationId,
        references: #{amount: response.body.amount, sequence: response.body.sequence}
    }
}
"#;
    let yaml = format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1
kind: AdapterPaymentProviderPack
id: exact-number-pay
version: '1'
connector: adapter-payment-http/v1
capabilities: [collection]
mapping:
  collection:
    auth: bearer
    submit:
      path: /collect
      request: {{file: scripts/exact.rhai, entrypoint: submit_request}}
      response: {{file: scripts/exact.rhai, entrypoint: submit_response}}
  scripts:
    - path: scripts/exact.rhai
      digest: {}
"#,
        registry_platform_config::sha256_uri(script.as_bytes())
    );
    let program = compile(&yaml, "scripts/exact.rhai", script);
    let mapped = program
        .interpret(
            PaymentEndpointRole::CollectionSubmit,
            &intent(),
            &json!({}),
            None,
            &ProviderHttpResponse {
                status: 202,
                body: br#"{"amount":12.50,"sequence":9007199254740993}"#.to_vec(),
            },
        )
        .expect("exact provider number spellings map");
    let accepted = acceptance(mapped);
    assert_eq!(accepted.references["amount"], "12.50");
    assert_eq!(accepted.references["sequence"], "9007199254740993");

    for invalid in [
        br#"{"amount":12.50,"amount":12.50}"#.as_slice(),
        br#"{"amount":12.50"#.as_slice(),
    ] {
        assert!(program
            .interpret(
                PaymentEndpointRole::CollectionSubmit,
                &intent(),
                &json!({}),
                None,
                &ProviderHttpResponse {
                    status: 202,
                    body: invalid.to_vec(),
                },
            )
            .is_err());
    }
}
