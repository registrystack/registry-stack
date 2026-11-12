// SPDX-License-Identifier: Apache-2.0
//! Offline replay of pinned provider request and response mappings.

use registry_adapter::payments::{
    pack::{ConnectorKind, PaymentProviderPack},
    provider_mapping::{
        MappedProviderResponse, PaymentEndpointRole, PaymentMappingProgram,
        PreparedProviderRequest, ProviderAcceptance, ProviderHttpResponse,
    },
};
use registry_payment_mifos_connector::{
    build_batch_request, build_collection_request, parse_batch_acceptance, parse_batch_status,
    parse_collection_acceptance, parse_collection_status, BatchAccepted, BatchCommand,
    BatchObservation, CollectionAccepted, CollectionCommand, CollectionObservation,
    CONNECTOR_PROFILE,
};
use registry_platform_yaml::{
    ApiVersion, BoundedU32, EnvelopeRule, Expect, FormatSpec, LocalId, Reader,
};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

pub(crate) const VERSION: &str =
    "id.registrystack.org/formats/adapter/payment-provider-fixture/v1alpha1";
pub(crate) const KIND: &str = "AdapterPaymentProviderFixture";
pub(crate) const SCHEMA_ID: &str = "https://id.registrystack.org/schemas/adapter/payment-provider-fixture/payment-provider-fixture.v1alpha1.schema.json";
const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};
const MAXIMUM_PROVIDER_RESPONSE_BYTES: usize = 65_536;

struct Fixture {
    connector_profile: String,
    direction: Direction,
    command: Value,
    expected_request: Value,
    acceptance: Exchange,
    status: Exchange,
}

/// Both the compiled legacy fixture and the reviewed pure-mapping fixture
/// share one authored envelope during the migration to generic providers.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[schemars(!remote, tag = "type")]
pub(crate) enum FixtureDocument {
    Compiled {
        connector_profile: String,
        direction: Direction,
        command: Value,
        expected_request: Value,
        acceptance: Exchange,
        status: Exchange,
    },
    Mapped {
        direction: Direction,
        intent: Value,
        settings: Value,
        submit: MappedExchange,
        status: MappedExchange,
    },
}
registry_platform_yaml::tagged_union!(FixtureDocument);

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Exchange {
    response: ProviderResponse,
    expected: Value,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderResponse {
    http_status: BoundedU32<100, 599>,
    body: Value,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Direction {
    P2gCollection,
    G2pDisbursement,
}

/// All errors are value-free so authored provider payloads never enter ctl reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FixtureError {
    Unavailable,
    Refused,
}

struct MappedFixture {
    direction: Direction,
    intent: Value,
    settings: Value,
    submit: MappedExchange,
    status: MappedExchange,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MappedExchange {
    #[serde(default)]
    acceptance: Option<FixtureAcceptance>,
    expected_request: Value,
    response: MappedResponse,
    expected: Value,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureAcceptance {
    correlation_id: String,
    #[schemars(schema_with = "local_id_string_map_schema")]
    references: BTreeMap<LocalId, String>,
}

fn local_id_string_map_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let names = generator.subschema_for::<LocalId>();
    schemars::json_schema!({
        "type": "object",
        "propertyNames": names,
        "additionalProperties": generator.subschema_for::<String>(),
    })
}

impl From<FixtureAcceptance> for ProviderAcceptance {
    fn from(value: FixtureAcceptance) -> Self {
        Self {
            correlation_id: value.correlation_id,
            references: value
                .references
                .into_iter()
                .map(|(key, value)| (key.into_string(), value))
                .collect(),
        }
    }
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MappedResponse {
    status: BoundedU32<100, 599>,
    #[schemars(length(min = 1, max = 65_536))]
    body_json: String,
}

/// Compile the exact pack closure and replay a provider-neutral fixture.
pub(crate) fn replay_mapped(
    fixture_path: &Path,
    pack_path: &Path,
    pack: &PaymentProviderPack,
    pack_bytes: &[u8],
) -> Result<(), FixtureError> {
    let program = compile_mapped_pack(pack_path, pack, pack_bytes)?;
    let bytes = std::fs::read(fixture_path).map_err(|_| FixtureError::Unavailable)?;
    let document = Reader::new(fixture_path.display().to_string())
        .decode::<FixtureDocument>(&bytes, &Expect::one(&FORMAT))
        .map_err(|_| FixtureError::Refused)?
        .value;
    let FixtureDocument::Mapped {
        direction,
        intent,
        settings,
        submit,
        status,
    } = document
    else {
        return Err(FixtureError::Refused);
    };
    let fixture = MappedFixture {
        direction,
        intent,
        settings,
        submit,
        status,
    };
    if fixture.submit.acceptance.is_some() || fixture.status.acceptance.is_none() {
        return Err(FixtureError::Refused);
    }
    let (submit_role, status_role) = match fixture.direction {
        Direction::P2gCollection => (
            PaymentEndpointRole::CollectionSubmit,
            PaymentEndpointRole::CollectionStatus,
        ),
        Direction::G2pDisbursement => (
            PaymentEndpointRole::DisbursementSubmit,
            PaymentEndpointRole::DisbursementStatus,
        ),
    };
    let submitted = program
        .prepare(submit_role, &fixture.intent, &fixture.settings, None)
        .map_err(|_| FixtureError::Refused)?;
    compare_request(&submitted, fixture.submit.expected_request)?;
    let response = provider_response(fixture.submit.response)?;
    let accepted = program
        .interpret(
            submit_role,
            &fixture.intent,
            &fixture.settings,
            None,
            &response,
        )
        .map_err(|_| FixtureError::Refused)?;
    let MappedProviderResponse::Acceptance(accepted) = accepted else {
        return Err(FixtureError::Refused);
    };
    matches_expected(&accepted, fixture.submit.expected)?;
    let retained: ProviderAcceptance = fixture
        .status
        .acceptance
        .ok_or(FixtureError::Refused)?
        .into();
    if retained != accepted {
        return Err(FixtureError::Refused);
    }
    let status_request = program
        .prepare(
            status_role,
            &fixture.intent,
            &fixture.settings,
            Some(&retained),
        )
        .map_err(|_| FixtureError::Refused)?;
    compare_request(&status_request, fixture.status.expected_request)?;
    let response = provider_response(fixture.status.response)?;
    let observed = program
        .interpret(
            status_role,
            &fixture.intent,
            &fixture.settings,
            Some(&retained),
            &response,
        )
        .map_err(|_| FixtureError::Refused)?;
    let MappedProviderResponse::Observation(observed) = observed else {
        return Err(FixtureError::Refused);
    };
    matches_expected(&observed, fixture.status.expected)
}

/// Check every reviewed script even when no fixture is supplied.
pub(crate) fn compile_mapped_pack(
    pack_path: &Path,
    pack: &PaymentProviderPack,
    pack_bytes: &[u8],
) -> Result<PaymentMappingProgram, FixtureError> {
    if pack.connector != ConnectorKind::AdapterPaymentHttpV1 {
        return Err(FixtureError::Refused);
    }
    let root = canonical_pack_root(pack_path)?;
    let scripts = pack
        .mapping
        .as_ref()
        .ok_or(FixtureError::Refused)?
        .scripts
        .iter()
        .map(|entry| {
            let path = std::fs::canonicalize(root.join(&entry.path))
                .map_err(|_| FixtureError::Unavailable)?;
            if !path.starts_with(&root) || !path.is_file() {
                return Err(FixtureError::Refused);
            }
            let bytes = std::fs::read(path).map_err(|_| FixtureError::Unavailable)?;
            Ok((entry.path.clone(), bytes))
        })
        .collect::<Result<BTreeMap<_, _>, FixtureError>>()?;
    PaymentMappingProgram::compile(pack, pack_bytes, &scripts).map_err(|_| FixtureError::Refused)
}

fn canonical_pack_root(pack_path: &Path) -> Result<std::path::PathBuf, FixtureError> {
    let pack_path = std::fs::canonicalize(pack_path).map_err(|_| FixtureError::Unavailable)?;
    pack_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or(FixtureError::Unavailable)
}

fn provider_response(response: MappedResponse) -> Result<ProviderHttpResponse, FixtureError> {
    if response.body_json.is_empty() || response.body_json.len() > MAXIMUM_PROVIDER_RESPONSE_BYTES {
        return Err(FixtureError::Refused);
    }
    Ok(ProviderHttpResponse {
        status: response.status.get() as u16,
        body: response.body_json.into_bytes(),
    })
}

fn compare_request(actual: &PreparedProviderRequest, expected: Value) -> Result<(), FixtureError> {
    let mut plan = serde_json::json!({
        "method": actual.method,
        "path": actual.path,
        "query": actual.query,
        "headers": actual.headers,
    });
    if let Some(bytes) = &actual.body {
        plan["body"] = serde_json::from_slice(bytes).map_err(|_| FixtureError::Refused)?;
    }
    if plan == expected {
        Ok(())
    } else {
        Err(FixtureError::Refused)
    }
}

pub(crate) fn replay(path: &Path, connector: ConnectorKind) -> Result<(), FixtureError> {
    if connector != ConnectorKind::MifosPhEeLegacyV1 {
        return Err(FixtureError::Refused);
    }
    let bytes = std::fs::read(path).map_err(|_| FixtureError::Unavailable)?;
    let decoded = Reader::new(path.display().to_string())
        .decode::<FixtureDocument>(&bytes, &Expect::one(&FORMAT))
        .map_err(|_| FixtureError::Refused)?;
    let FixtureDocument::Compiled {
        connector_profile,
        direction,
        command,
        expected_request,
        acceptance,
        status,
    } = decoded.value
    else {
        return Err(FixtureError::Refused);
    };
    let fixture = Fixture {
        connector_profile,
        direction,
        command,
        expected_request,
        acceptance,
        status,
    };
    if fixture.connector_profile != CONNECTOR_PROFILE
        || fixture.acceptance.response.http_status.get() != 200
        || fixture.status.response.http_status.get() != 200
    {
        return Err(FixtureError::Refused);
    }
    let expected_request = fixture.expected_request;
    let acceptance_body =
        serde_json::to_vec(&fixture.acceptance.response.body).map_err(|_| FixtureError::Refused)?;
    let status_body =
        serde_json::to_vec(&fixture.status.response.body).map_err(|_| FixtureError::Refused)?;
    match fixture.direction {
        Direction::P2gCollection => {
            let command: CollectionCommand =
                serde_json::from_value(fixture.command).map_err(|_| FixtureError::Refused)?;
            let request = build_collection_request(&command).map_err(|_| FixtureError::Refused)?;
            let request: Value =
                serde_json::from_slice(&request).map_err(|_| FixtureError::Refused)?;
            let accepted =
                parse_collection_acceptance(&acceptance_body).map_err(|_| FixtureError::Refused)?;
            let observed = parse_collection_status(&command, &accepted, &status_body)
                .map_err(|_| FixtureError::Refused)?;
            matches_expected::<CollectionAccepted>(&accepted, fixture.acceptance.expected)?;
            matches_expected::<CollectionObservation>(&observed, fixture.status.expected)?;
            if request != expected_request {
                return Err(FixtureError::Refused);
            }
        }
        Direction::G2pDisbursement => {
            let command: BatchCommand =
                serde_json::from_value(fixture.command).map_err(|_| FixtureError::Refused)?;
            let request = build_batch_request(&command).map_err(|_| FixtureError::Refused)?;
            let request: Value =
                serde_json::from_slice(&request).map_err(|_| FixtureError::Refused)?;
            let accepted = parse_batch_acceptance(
                &command,
                fixture.acceptance.response.http_status.get() as u16,
                &acceptance_body,
            )
            .map_err(|_| FixtureError::Refused)?;
            let observed = parse_batch_status(&command, &accepted, &status_body)
                .map_err(|_| FixtureError::Refused)?;
            matches_expected::<BatchAccepted>(&accepted, fixture.acceptance.expected)?;
            matches_expected::<BatchObservation>(&observed, fixture.status.expected)?;
            if request != expected_request {
                return Err(FixtureError::Refused);
            }
        }
    }
    Ok(())
}

fn matches_expected<T: serde::Serialize>(actual: &T, expected: Value) -> Result<(), FixtureError> {
    let actual = serde_json::to_value(actual).map_err(|_| FixtureError::Refused)?;
    if actual == expected {
        Ok(())
    } else {
        Err(FixtureError::Refused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COLLECTION: &str = r#"apiVersion: id.registrystack.org/formats/adapter/payment-provider-fixture/v1alpha1
kind: AdapterPaymentProviderFixture
type: compiled
connectorProfile: mifos-ph-ee-legacy/channel-v1.12.2+bulk-v1.12.1+operations-v1.17.1
direction: p2g-collection
command:
  correlationId: collection-1
  payer: [{key: MSISDN, value: '254700000001'}, {key: ACCOUNTID, value: bill-1}]
  money: {amount: '25.50', currency: KES}
  transactionType: {scenario: MPESA, subScenario: BUYGOODS, initiator: PAYEE, initiatorType: BUSINESS}
expectedRequest:
  payer: [{key: MSISDN, value: '254700000001'}, {key: ACCOUNTID, value: bill-1}]
  amount: {amount: '25.50', currency: KES}
  transactionType: {scenario: MPESA, subScenario: BUYGOODS, initiator: PAYEE, initiatorType: BUSINESS}
  customData: []
acceptance:
  response: {httpStatus: 200, body: {transactionId: tx-1}}
  expected: {transactionId: tx-1, state: accepted}
status:
  response:
    httpStatus: 200
    body: {content: [{transactionId: tx-1, state: SUCCESS, amount: '25.50', currency: KES, clientCorrelationId: collection-1}]}
  expected: {transactionId: tx-1, state: providerConfirmed, money: {amount: '25.50', currency: KES}}
"#;

    #[test]
    fn replay_proves_exact_request_and_status_and_refuses_changed_money() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), COLLECTION).unwrap();
        assert_eq!(
            replay(file.path(), ConnectorKind::MifosPhEeLegacyV1),
            Ok(())
        );
        let changed = COLLECTION.replace(
            "amount: '25.50', currency: KES, clientCorrelationId",
            "amount: '25.51', currency: KES, clientCorrelationId",
        );
        std::fs::write(file.path(), changed).unwrap();
        assert_eq!(
            replay(file.path(), ConnectorKind::MifosPhEeLegacyV1),
            Err(FixtureError::Refused)
        );
    }

    #[test]
    fn replay_refuses_unknown_members_and_wrong_connector() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            COLLECTION.replace(
                "direction: p2g-collection",
                "direction: p2g-collection\nsecret: exposed",
            ),
        )
        .unwrap();
        assert_eq!(
            replay(file.path(), ConnectorKind::MifosPhEeLegacyV1),
            Err(FixtureError::Refused)
        );
        std::fs::write(file.path(), COLLECTION).unwrap();
        assert_eq!(
            replay(file.path(), ConnectorKind::SimulatorP2gV1),
            Err(FixtureError::Refused)
        );
        std::fs::write(file.path(), COLLECTION.replace("type: compiled\n", "")).unwrap();
        assert_eq!(
            replay(file.path(), ConnectorKind::MifosPhEeLegacyV1),
            Err(FixtureError::Refused)
        );
    }

    #[test]
    fn mapped_fixture_checks_both_http_roles_and_observed_money() {
        let directory = tempfile::tempdir().unwrap();
        let scripts = directory.path().join("scripts");
        std::fs::create_dir(&scripts).unwrap();
        let script = r#"
fn submit_request(intent, settings, acceptance) {
    if settings == () || acceptance != () { throw "invalid submit"; }
    #{pathParameters: #{}, query: #{}, headers: #{}, body: #{id: intent.correlationId}}
}
fn submit_response(intent, settings, acceptance, response) {
    if settings == () || acceptance != () || response.status != 202 { throw "invalid response"; }
    #{correlationId: intent.correlationId, references: #{transfer: response.body.id}}
}
fn status_request(intent, settings, acceptance) {
    if intent == () || settings == () || acceptance == () { throw "invalid status"; }
    #{pathParameters: #{}, query: #{id: acceptance.references.transfer}, headers: #{}, body: ()}
}
fn status_response(intent, settings, acceptance, response) {
    if settings == () || acceptance == () { throw "invalid status"; }
    #{correlationId: intent.correlationId, providerReference: response.body.id,
      state: "provider-confirmed",
      money: #{minorUnits: if response.body.amount == "100.00" { "10000" } else { "1" }, currency: intent.money.currency, scale: 2},
      parties: [#{role: "funding", key: "account", value: intent.funding},
                #{role: "recipient", key: "phone", value: intent.recipient}]}
}
"#;
        std::fs::write(scripts.join("provider.rhai"), script).unwrap();
        let pack = format!(
            "apiVersion: {api}\nkind: {kind}\nid: mapped-pay\nversion: '1'\nconnector: adapter-payment-http/v1\ncapabilities: [disbursement]\nmapping:\n  disbursement:\n    auth: bearer\n    submit:\n      path: /send\n      request: {{file: scripts/provider.rhai, entrypoint: submit_request}}\n      response: {{file: scripts/provider.rhai, entrypoint: submit_response}}\n    status:\n      path: /read\n      request: {{file: scripts/provider.rhai, entrypoint: status_request}}\n      response: {{file: scripts/provider.rhai, entrypoint: status_response}}\n  scripts:\n    - path: scripts/provider.rhai\n      digest: {}\n",
            registry_platform_config::sha256_uri(script.as_bytes()),
            api = registry_adapter::payments::pack::API_VERSION,
            kind = registry_adapter::payments::pack::KIND,
        );
        let pack_path = directory.path().join("pack.yaml");
        std::fs::write(&pack_path, &pack).unwrap();
        let parsed = PaymentProviderPack::from_yaml(pack.as_bytes()).unwrap();
        let fixture = format!(
            "apiVersion: {VERSION}\nkind: {KIND}\ntype: mapped\ndirection: g2p-disbursement\nintent:\n  correlationId: transfer-1\n  funding: account-1\n  recipient: phone-1\n  money: {{minorUnits: 10000, currency: USD, scale: 2}}\nsettings: {{tenant: pilot}}\nsubmit:\n  expectedRequest:\n    method: POST\n    path: /send\n    query: {{}}\n    headers: {{}}\n    body: {{id: transfer-1}}\n  response: {{status: 202, bodyJson: '{{\"id\":\"tx-1\"}}'}}\n  expected: {{correlationId: transfer-1, references: {{transfer: tx-1}}}}\nstatus:\n  acceptance: {{correlationId: transfer-1, references: {{transfer: tx-1}}}}\n  expectedRequest:\n    method: GET\n    path: /read\n    query: {{id: tx-1}}\n    headers: {{}}\n  response: {{status: 200, bodyJson: '{{\"id\":\"tx-1\",\"amount\":100.00}}'}}\n  expected:\n    correlationId: transfer-1\n    providerReference: tx-1\n    state: provider-confirmed\n    money: {{minorUnits: '10000', currency: USD, scale: 2}}\n    parties:\n      - {{role: funding, key: account, value: account-1}}\n      - {{role: recipient, key: phone, value: phone-1}}\n"
        );
        let fixture_path = directory.path().join("fixture.yaml");
        std::fs::write(&fixture_path, &fixture).unwrap();
        assert_eq!(
            replay_mapped(&fixture_path, &pack_path, &parsed, pack.as_bytes()),
            Ok(())
        );
        for invalid_status in [99, 600] {
            std::fs::write(
                &fixture_path,
                fixture.replacen("status: 202", &format!("status: {invalid_status}"), 1),
            )
            .unwrap();
            assert_eq!(
                replay_mapped(&fixture_path, &pack_path, &parsed, pack.as_bytes()),
                Err(FixtureError::Refused)
            );
        }
        std::fs::write(
            &fixture_path,
            fixture.replace("\"amount\":100.00", "\"amount\":100.01"),
        )
        .unwrap();
        assert_eq!(
            replay_mapped(&fixture_path, &pack_path, &parsed, pack.as_bytes()),
            Err(FixtureError::Refused)
        );
        std::fs::write(
            &fixture_path,
            fixture.replace(
                "references: {transfer: tx-1}",
                "references: {Transfer.ID: tx-1}",
            ),
        )
        .unwrap();
        assert_eq!(
            replay_mapped(&fixture_path, &pack_path, &parsed, pack.as_bytes()),
            Err(FixtureError::Refused)
        );
        std::fs::write(
            scripts.join("provider.rhai"),
            format!("{script}\n// changed"),
        )
        .unwrap();
        assert!(compile_mapped_pack(&pack_path, &parsed, pack.as_bytes()).is_err());
    }

    #[test]
    fn mapped_response_body_and_bare_pack_path_are_bounded_without_normalization() {
        let raw = r#"{"amount":100.00}"#;
        let exact = provider_response(MappedResponse {
            status: BoundedU32::<100, 599>::new(200).unwrap(),
            body_json: raw.to_owned(),
        })
        .unwrap();
        assert_eq!(exact.body, raw.as_bytes());

        for body_json in [
            String::new(),
            "x".repeat(MAXIMUM_PROVIDER_RESPONSE_BYTES + 1),
        ] {
            let response = MappedResponse {
                status: BoundedU32::<100, 599>::new(200).unwrap(),
                body_json,
            };
            assert_eq!(provider_response(response), Err(FixtureError::Refused));
        }

        let file = tempfile::Builder::new()
            .prefix("mapped-payment-pack-")
            .suffix(".yaml")
            .tempfile_in(".")
            .unwrap();
        let bare = Path::new(file.path().file_name().unwrap());
        assert_eq!(
            canonical_pack_root(bare).unwrap(),
            std::fs::canonicalize(".").unwrap()
        );
    }
}
