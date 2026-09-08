//! Fixed-provider acquisition for governed immediate-action capabilities.
//!
//! This adapter uses the portable client for every protocol and verification
//! decision. It never discovers a contract or trust key while an action runs.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use registry_evidence_client::{
    EvidenceClient, EvidenceClientConfig, EvidenceClientError, EvidenceRequestSpec,
    EvidenceResponseFormat, RetainedEvidenceVerification, SubjectExpectations,
};
use serde_json::Value;

use crate::action_evidence_contracts::CompiledEvidenceCapability;

pub const MAXIMUM_ACTION_EVIDENCE_RESPONSE_BYTES: u64 = 256 * 1024;
pub const MAXIMUM_ACTION_EVIDENCE_RETAINED_BYTES: usize = 1024 * 1024;
pub const ACTION_EVIDENCE_RETENTION_SECONDS: i64 = 24 * 60 * 60;
pub const ACTION_EVIDENCE_MAXIMUM_LIFETIME_SECONDS: u64 = 300;

use crate::action_evidence_validation::validate_subjects;
pub use crate::action_evidence_validation::{
    validate_call_arguments, validate_selected_outputs, EvidenceAcquisitionFailure,
    EvidenceSubjects,
};

pub struct EvidenceProviderBinding {
    trust_binding_id: String,
    client: EvidenceClient,
}

impl EvidenceProviderBinding {
    /// Operator-owned credentials, endpoint and pinned trust only. The
    /// low-level configuration cannot enable progressive metadata substitution.
    pub fn new(
        trust_binding_id: String,
        config: EvidenceClientConfig,
    ) -> Result<Self, EvidenceAcquisitionFailure> {
        if trust_binding_id.is_empty() || trust_binding_id.len() > 512 || !config.verifies() {
            return Err(EvidenceAcquisitionFailure::Configuration);
        }
        let client = EvidenceClient::new(
            config.with_max_response_bytes(MAXIMUM_ACTION_EVIDENCE_RESPONSE_BYTES),
        )
        .map_err(|_| EvidenceAcquisitionFailure::Configuration)?;
        Ok(Self {
            trust_binding_id,
            client,
        })
    }
}

pub struct EvidenceActionClient {
    bindings: BTreeMap<String, EvidenceProviderBinding>,
}

impl EvidenceActionClient {
    pub fn new(bindings: BTreeMap<String, EvidenceProviderBinding>) -> Self {
        Self { bindings }
    }

    pub async fn resolve(
        &self,
        capability: &CompiledEvidenceCapability,
        subjects: &EvidenceSubjects,
        deadline: Instant,
        cancellation: Arc<AtomicBool>,
    ) -> Result<VerifiedAcquisition, EvidenceAcquisitionFailure> {
        check_active(deadline, &cancellation)?;
        // Exact origin, field and role checks precede even token acquisition.
        let subjects_for_request = validate_subjects(capability, subjects)?;
        let binding = self
            .bindings
            .get(&capability.provider)
            .ok_or(EvidenceAcquisitionFailure::Configuration)?;
        let definition = &capability.definition;
        let expected_outputs = definition
            .concepts
            .iter()
            .map(|concept| {
                concept
                    .scalar_expected_output()
                    .or_else(|| concept.list_expected_output())
                    .ok_or(EvidenceAcquisitionFailure::Configuration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let prepared = binding
            .client
            .prepare(EvidenceRequestSpec {
                response_format: EvidenceResponseFormat::SignedJws,
                requirement: definition.requirement.clone(),
                purpose: definition.purpose.clone(),
                audience: capability.audience.clone(),
                evidence_type: definition.evidence_type.clone(),
                issued_by: capability.issued_by.clone(),
                provided_by: capability.provided_by.clone(),
                configuration_revision: definition.configuration_revision.clone(),
                expected_assurance_profile: capability.assurance_profile,
                subjects: subjects_for_request,
                holder_keys: Vec::new(),
                expected_outputs,
                maximum_assertion_lifetime_seconds: ACTION_EVIDENCE_MAXIMUM_LIFETIME_SECONDS,
                clock_skew_seconds: 0,
                subject_expectations: SubjectExpectations::AcceptFirstUse,
            })
            .map_err(|_| EvidenceAcquisitionFailure::Configuration)?;
        // Capture the closed context before obtaining the response. Never infer
        // expectations from the bytes being verified.
        let verification = binding.client.retain_verification(&prepared);
        check_active(deadline, &cancellation)?;
        let response = tokio::select! {
            biased;
            _ = wait_cancelled(deadline, &cancellation) => return Err(EvidenceAcquisitionFailure::Cancelled),
            response = binding.client.send(&prepared) => response.map_err(map_client_failure)?,
        };
        check_active(deadline, &cancellation)?;
        let accepted_at = Utc::now();
        let verified = binding
            .client
            .verify_as_of(&prepared, &response, accepted_at)
            .map_err(map_client_failure)?;
        let evidence = verified.evidence();
        let mut outputs = BTreeMap::new();
        for handle in &capability.outputs {
            let concept = definition
                .concepts
                .iter()
                .find(|item| &item.handle == handle)
                .ok_or(EvidenceAcquisitionFailure::Configuration)?;
            if let Some(value) = evidence
                .supported_values
                .iter()
                .find(|value| value.provides_value_for == concept.concept)
            {
                outputs.insert(
                    handle.clone(),
                    serde_json::to_value(&value.value)
                        .map_err(|_| EvidenceAcquisitionFailure::Verification)?,
                );
            }
        }
        let acquisition = VerifiedAcquisition {
            outputs,
            verification,
            signed_response: response.body().to_vec(),
            capability_id: capability.id.clone(),
            contract_fingerprint: capability.contract_fingerprint.clone(),
            trust_binding_id: binding.trust_binding_id.clone(),
            evidence_id: evidence.id.clone(),
            issued_at: evidence.issued_at.clone(),
            observed_at: evidence.observed_at.clone(),
            valid_until: evidence.valid_until.clone(),
            accepted_at,
            maximum_observation_age_seconds: capability.maximum_observation_age_seconds,
            // This in-memory link is deliberately absent from retained JSON,
            // audit, events and receipts. Scoped subject bindings are already
            // retained inside the exact signed assertion.
            _subjects: subjects.clone(),
        };
        acquisition.validate_acceptance(accepted_at)?;
        if acquisition.retained_bytes()? > MAXIMUM_ACTION_EVIDENCE_RETAINED_BYTES {
            return Err(EvidenceAcquisitionFailure::BudgetExceeded);
        }
        check_active(deadline, &cancellation)?;
        Ok(acquisition)
    }
}

/// Host-owned material. No Debug rendering or public mutation surface can
/// accidentally expose or fabricate a verified acquisition.
#[derive(Clone)]
pub struct VerifiedAcquisition {
    outputs: BTreeMap<String, Value>,
    verification: RetainedEvidenceVerification,
    signed_response: Vec<u8>,
    capability_id: String,
    contract_fingerprint: String,
    trust_binding_id: String,
    evidence_id: String,
    issued_at: String,
    observed_at: String,
    valid_until: String,
    accepted_at: DateTime<Utc>,
    maximum_observation_age_seconds: u64,
    _subjects: EvidenceSubjects,
}

impl VerifiedAcquisition {
    pub(crate) fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn outputs(&self) -> &BTreeMap<String, Value> {
        &self.outputs
    }

    /// Re-run the portable verifier as well as the separately governed maximum
    /// evaluation age immediately before accepting the transaction candidate.
    pub fn validate_acceptance(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), EvidenceAcquisitionFailure> {
        self.verification
            .verify_as_of(&self.signed_response, now)
            .map_err(map_client_failure)?;
        validate_observation_age(&self.observed_at, self.maximum_observation_age_seconds, now)
    }

    pub fn retention_expires_at(&self) -> DateTime<Utc> {
        self.accepted_at + chrono::Duration::seconds(ACTION_EVIDENCE_RETENTION_SECONDS)
    }

    pub fn retained_serialization(&self) -> Result<Value, EvidenceAcquisitionFailure> {
        Ok(serde_json::json!({
            "schema": "registry.breg.action-evidence-use/v1",
            "capability": self.capability_id,
            "contractFingerprint": self.contract_fingerprint,
            "trustBinding": self.trust_binding_id,
            "evidenceId": self.evidence_id,
            "issuedAt": self.issued_at,
            "observedAt": self.observed_at,
            "validUntil": self.valid_until,
            "acceptedAt": self.accepted_at.to_rfc3339(),
            "retentionExpiresAt": self.retention_expires_at().to_rfc3339(),
            "maximumObservationAgeSeconds": self.maximum_observation_age_seconds,
            "subjectResolution": "trusted-provider-exact-selector",
            "signedResponse": std::str::from_utf8(&self.signed_response)
                .map_err(|_| EvidenceAcquisitionFailure::Verification)?,
            "verification": serde_json::to_value(&self.verification)
                .map_err(|_| EvidenceAcquisitionFailure::Verification)?,
        }))
    }

    pub fn retained_bytes(&self) -> Result<usize, EvidenceAcquisitionFailure> {
        serde_json::to_vec(&self.retained_serialization()?)
            .map(|bytes| bytes.len())
            .map_err(|_| EvidenceAcquisitionFailure::Verification)
    }
}

fn check_active(
    deadline: Instant,
    cancellation: &AtomicBool,
) -> Result<(), EvidenceAcquisitionFailure> {
    if cancellation.load(Ordering::Acquire) || Instant::now() >= deadline {
        Err(EvidenceAcquisitionFailure::Cancelled)
    } else {
        Ok(())
    }
}

async fn wait_cancelled(deadline: Instant, cancellation: &AtomicBool) {
    while check_active(deadline, cancellation).is_ok() {
        tokio::time::sleep(
            Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
        )
        .await;
    }
}

fn map_client_failure(error: EvidenceClientError) -> EvidenceAcquisitionFailure {
    match error {
        EvidenceClientError::Verification(_) => EvidenceAcquisitionFailure::Verification,
        EvidenceClientError::Configuration { .. } => EvidenceAcquisitionFailure::Configuration,
        _ => EvidenceAcquisitionFailure::Unavailable,
    }
}

fn validate_observation_age(
    observed: &str,
    maximum_age: u64,
    now: DateTime<Utc>,
) -> Result<(), EvidenceAcquisitionFailure> {
    let observed = DateTime::parse_from_rfc3339(observed)
        .map_err(|_| EvidenceAcquisitionFailure::Verification)?
        .with_timezone(&Utc);
    if maximum_age == 0
        || maximum_age > ACTION_EVIDENCE_MAXIMUM_LIFETIME_SECONDS
        || observed > now
        || now.signed_duration_since(observed) > chrono::Duration::seconds(maximum_age as i64)
    {
        return Err(EvidenceAcquisitionFailure::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_evidence_validation::validate_selector_field;
    use registry_evidence_client::definitions::{SelectorField, SelectorValueOrigin};

    #[test]
    fn selector_types_and_byte_bounds_are_exact_and_errors_redacted() {
        let string = SelectorField::String {
            name: "reference".into(),
            minimum_bytes: 2,
            maximum_bytes: 4,
        };
        assert!(validate_selector_field(&string, &Value::String("éé".into())).is_ok());
        for value in [
            serde_json::json!("secret-canary"),
            serde_json::json!(1),
            Value::Null,
        ] {
            let failure = validate_selector_field(&string, &value).unwrap_err();
            assert_eq!(failure, EvidenceAcquisitionFailure::InvalidArguments);
            assert!(!failure.to_string().contains("secret-canary"));
        }
        let integer = SelectorField::Integer {
            name: "number".into(),
            minimum: 1,
            maximum: 3,
        };
        assert!(validate_selector_field(&integer, &serde_json::json!(2)).is_ok());
        assert!(validate_selector_field(&integer, &serde_json::json!(2.0)).is_err());
        assert!(validate_selector_field(&integer, &serde_json::json!(4)).is_err());
        let date = SelectorField::Date { name: "day".into() };
        assert!(validate_selector_field(&date, &serde_json::json!("2026-02-29")).is_err());
    }

    #[test]
    fn observation_age_is_distinct_from_signature_lifetime() {
        let now = DateTime::parse_from_rfc3339("2026-09-08T00:01:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(validate_observation_age("2026-09-08T00:00:00Z", 60, now).is_ok());
        assert_eq!(
            validate_observation_age("2026-09-08T00:00:00Z", 59, now),
            Err(EvidenceAcquisitionFailure::Expired)
        );
        assert!(validate_observation_age("2026-09-08T00:01:01Z", 60, now).is_err());
    }

    #[tokio::test]
    async fn cancellation_wait_wakes_and_expired_work_is_refused() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(5);
        let signal = cancelled.clone();
        let waiter = tokio::spawn(async move {
            wait_cancelled(deadline, &signal).await;
        });
        cancelled.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_millis(100), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            check_active(deadline, &cancelled),
            Err(EvidenceAcquisitionFailure::Cancelled)
        );
        assert_eq!(
            check_active(Instant::now(), &AtomicBool::new(false)),
            Err(EvidenceAcquisitionFailure::Cancelled)
        );
    }

    fn capability() -> CompiledEvidenceCapability {
        serde_json::from_value(serde_json::json!({
            "id":"status", "provider":"provider", "contractFingerprint":"sha256:closed",
            "assuranceProfile":"local", "audience":"urn:example:audience", "issuedBy":"urn:example:issuer", "providedBy":"urn:example:provider",
            "outputs":["status"], "maximumObservationAgeSeconds":60, "subjectResolution":"trusted-provider-exact-selector",
            "definition": {
                "handle":"status", "requirement":"urn:example:requirement", "configurationRevision":format!("sha256:{}", "1".repeat(64)),
                "kind":"criterion", "evidenceType":"urn:example:type", "purpose":"registration",
                "responseFormats":["signed-jws"], "referenceFrameworks":[],
                "subjects":[{"role":"subject", "cardinality":"one", "selector":{"profile":"exact", "valueOrigin":"request", "fields":[{"type":"string","name":"reference","minimumBytes":1,"maximumBytes":64}]}}],
                "concepts":[{"handle":"status","concept":"urn:example:concept","required":true,"form":"boolean"}]
            }
        })).unwrap()
    }

    fn subjects() -> EvidenceSubjects {
        BTreeMap::from([(
            "subject".into(),
            BTreeMap::from([(
                "reference".into(),
                serde_json::json!("synthetic-selector-canary"),
            )]),
        )])
    }

    // Published synthetic test key, shared with the platform crypto fixture.
    fn signing_key() -> registry_platform_crypto::PrivateJwk {
        let mut key = registry_platform_crypto::PrivateJwk::parse(r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256"}"#).unwrap();
        key.kid = Some(key.public().jkt().unwrap());
        key
    }

    async fn test_provider(
        tamper: &'static str,
    ) -> (
        EvidenceActionClient,
        Arc<std::sync::Mutex<Vec<Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let key = Arc::new(signing_key());
        let public = serde_json::to_value(key.public()).unwrap();
        let revoked = if tamper == "revoked" {
            vec![key.kid.clone().unwrap()]
        } else {
            vec![]
        };
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = requests.clone();
        let app = axum::Router::new().route("/v1/evidence", axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let key = key.clone(); let captured = captured.clone();
            async move {
                captured.lock().unwrap().push(request.clone());
                if tamper == "paused" { std::future::pending::<()>().await; }
                let now = Utc::now() - chrono::Duration::seconds(1);
                let cap = capability();
                let mut payload = serde_json::json!({
                    "schema":registry_evidence_verifier::EVIDENCE_SCHEMA_V1,
                    "assuranceProfile":"local", "subjectBinding":"audience-scoped", "requestNonce":request["requestNonce"],
                    "id":"urn:example:evidence:00000000-0000-4000-8000-000000000001", "type":"Evidence",
                    "supportsRequirement":cap.definition.requirement, "isConformantTo":cap.definition.evidence_type,
                    "issuedBy":cap.issued_by, "providedBy":cap.provided_by, "purpose":cap.definition.purpose, "audience":cap.audience,
                    "configurationRevision":cap.definition.configuration_revision,
                    "issuedAt":now.to_rfc3339(), "observedAt":now.to_rfc3339(), "validUntil":(now + chrono::Duration::seconds(120)).to_rfc3339(),
                    "subjects":[{"role":"subject","binding":"urn:evidence:subject:v1_QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU"}],
                    "supportedValues":[{"providesValueFor":"urn:example:concept","value":true}]
                });
                match tamper {
                    "nonce" => payload["requestNonce"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                    "issuer" => payload["issuedBy"] = serde_json::json!("urn:example:wrong"),
                    "provider" => payload["providedBy"] = serde_json::json!("urn:example:wrong"),
                    "audience" => payload["audience"] = serde_json::json!("urn:example:wrong"),
                    "purpose" => payload["purpose"] = serde_json::json!("other-purpose"),
                    "revision" => payload["configurationRevision"] = serde_json::json!(format!("sha256:{}", "2".repeat(64))),
                    "subject" => payload["subjects"][0]["role"] = serde_json::json!("other"),
                    "output" => payload["supportedValues"][0]["value"] = serde_json::json!("true"),
                    "missing-output" => payload["supportedValues"] = serde_json::json!([]),
                    "expired" => payload["validUntil"] = serde_json::json!((now - chrono::Duration::seconds(1)).to_rfc3339()),
                    "stale" => payload["observedAt"] = serde_json::json!((now - chrono::Duration::seconds(61)).to_rfc3339()),
                    _ => {}
                }
                let kid = if tamper == "key" { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } else { key.kid.as_deref().unwrap() };
                let protected = URL_SAFE_NO_PAD.encode(serde_json::json!({"alg":"ES256","kid":kid,"typ":registry_evidence_verifier::EVIDENCE_JWS_TYP,"cty":registry_evidence_verifier::EVIDENCE_JWS_CTY}).to_string());
                let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
                let signature = registry_platform_crypto::sign(format!("{protected}.{payload}").as_bytes(), &key).unwrap();
                let body = serde_json::json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(signature)}).to_string();
                ([(axum::http::header::CONTENT_TYPE, registry_evidence_verifier::EVIDENCE_JWS_MEDIA_TYPE), (axum::http::header::HeaderName::from_static("traceparent"), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")], body)
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = EvidenceClientConfig::new(
            format!("http://{address}").parse().unwrap(),
            Arc::new(registry_evidence_client::StaticToken::new("synthetic-test-token").unwrap()),
            registry_evidence_client::JwksDocument { keys: vec![public] },
            revoked,
        );
        let binding = EvidenceProviderBinding::new("synthetic-trust-v1".into(), config).unwrap();
        (
            EvidenceActionClient::new(BTreeMap::from([("provider".into(), binding)])),
            requests,
            server,
        )
    }

    #[tokio::test]
    async fn real_signed_acquisition_retains_exact_context_and_rechecks_freshness() {
        let (client, requests, server) = test_provider("").await;
        let acquired = client
            .resolve(
                &capability(),
                &subjects(),
                Instant::now() + Duration::from_secs(5),
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        assert_eq!(acquired.outputs()["status"], serde_json::json!(true));
        let retained = acquired.retained_serialization().unwrap();
        let serialized = retained.to_string();
        assert!(!serialized.contains("synthetic-selector-canary"));
        assert!(!serialized.contains("synthetic-test-token"));
        let context: RetainedEvidenceVerification =
            serde_json::from_value(retained["verification"].clone()).unwrap();
        let signed = retained["signedResponse"].as_str().unwrap().as_bytes();
        context.verify(signed).unwrap();
        assert_eq!(
            acquired.retained_bytes().unwrap(),
            serde_json::to_vec(&retained).unwrap().len()
        );
        assert!(acquired
            .validate_acceptance(Utc::now() + chrono::Duration::seconds(61))
            .is_err());
        let another = client
            .resolve(
                &capability(),
                &subjects(),
                Instant::now() + Duration::from_secs(5),
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        assert_eq!(another.outputs()["status"], serde_json::json!(true));
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_ne!(requests[0]["requestNonce"], requests[1]["requestNonce"]);
        assert!(requests[0]
            .to_string()
            .contains("synthetic-selector-canary"));
        server.abort();
    }

    #[tokio::test]
    async fn real_signed_wrong_expectations_fail_without_a_verified_acquisition() {
        for tamper in [
            "nonce",
            "issuer",
            "provider",
            "audience",
            "purpose",
            "revision",
            "subject",
            "output",
            "missing-output",
            "expired",
            "stale",
            "key",
            "revoked",
        ] {
            let (client, requests, server) = test_provider(tamper).await;
            let result = client
                .resolve(
                    &capability(),
                    &subjects(),
                    Instant::now() + Duration::from_secs(5),
                    Arc::new(AtomicBool::new(false)),
                )
                .await;
            let expected = if tamper == "stale" {
                EvidenceAcquisitionFailure::Expired
            } else {
                EvidenceAcquisitionFailure::Verification
            };
            assert!(
                matches!(result, Err(actual) if actual == expected),
                "{tamper}: expected {expected:?}"
            );
            assert_eq!(
                requests.lock().unwrap().len(),
                1,
                "{tamper}: no implicit retry"
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn wrong_selector_origins_roles_and_shapes_make_zero_requests() {
        let (client, requests, server) = test_provider("").await;
        for origin in [
            SelectorValueOrigin::AuthenticatedContext,
            SelectorValueOrigin::AuthenticatedGrant,
        ] {
            let mut cap = capability();
            cap.definition.subjects[0].selector.value_origin = origin;
            assert!(client
                .resolve(
                    &cap,
                    &subjects(),
                    Instant::now() + Duration::from_secs(5),
                    Arc::new(AtomicBool::new(false))
                )
                .await
                .is_err());
        }
        for values in [
            BTreeMap::new(),
            BTreeMap::from([("other".into(), subjects().remove("subject").unwrap())]),
            BTreeMap::from([(
                "subject".into(),
                BTreeMap::from([("reference".into(), serde_json::json!(1))]),
            )]),
        ] {
            assert!(client
                .resolve(
                    &capability(),
                    &values,
                    Instant::now() + Duration::from_secs(5),
                    Arc::new(AtomicBool::new(false))
                )
                .await
                .is_err());
        }
        assert!(requests.lock().unwrap().is_empty());
        server.abort();
    }
    #[tokio::test]
    async fn cancellation_drops_an_inflight_client_await_without_a_late_acquisition() {
        let (client, requests, server) = test_provider("paused").await;
        let cancellation = Arc::new(AtomicBool::new(false));
        let signal = cancellation.clone();
        let worker = tokio::spawn(async move {
            client
                .resolve(
                    &capability(),
                    &subjects(),
                    Instant::now() + Duration::from_secs(5),
                    signal,
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cancellation.store(true, Ordering::Release);
        let result = tokio::time::timeout(Duration::from_millis(100), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(EvidenceAcquisitionFailure::Cancelled)));
        assert_eq!(requests.lock().unwrap().len(), 1);
        server.abort();
    }

    #[test]
    fn fixture_outputs_preserve_required_optional_and_exact_types() {
        let mut cap = capability();
        assert!(validate_selected_outputs(
            &cap,
            &BTreeMap::from([("status".into(), serde_json::json!(true))])
        )
        .is_ok());
        assert!(validate_selected_outputs(&cap, &BTreeMap::new()).is_err());
        assert!(validate_selected_outputs(
            &cap,
            &BTreeMap::from([("status".into(), serde_json::json!("true"))])
        )
        .is_err());
        cap.definition.concepts[0].required = false;
        assert!(validate_selected_outputs(&cap, &BTreeMap::new()).is_ok());
        assert!(
            validate_selected_outputs(&cap, &BTreeMap::from([("status".into(), Value::Null)]))
                .is_err()
        );
    }
}
