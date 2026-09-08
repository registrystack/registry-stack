// SPDX-License-Identifier: Apache-2.0
//! Synthetic signed provider over explicitly permitted loopback HTTP.
use super::breg::action_evidence_client::{EvidenceActionClient, EvidenceProviderBinding};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use registry_evidence_client::{EvidenceClientConfig, JwksDocument, StaticToken};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

pub struct EvidenceProvider {
    client: Arc<EvidenceActionClient>,
    requests: Arc<Mutex<Vec<Value>>>,
    paused: Arc<AtomicBool>,
    mode: Arc<Mutex<String>>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for EvidenceProvider {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl EvidenceProvider {
    pub async fn start() -> Self {
        let mut key = registry_platform_crypto::PrivateJwk::parse(r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256"}"#).unwrap();
        key.kid = Some(key.public().jkt().unwrap());
        let key = Arc::new(key);
        let public = serde_json::to_value(key.public()).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let paused = Arc::new(AtomicBool::new(false));
        let gate = paused.clone();
        let mode = Arc::new(Mutex::new(String::new()));
        let behavior = mode.clone();
        let app = axum::Router::new().route("/v1/evidence", axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let key = key.clone(); let captured = captured.clone(); let gate = gate.clone(); let behavior = behavior.clone();
            async move {
                captured.lock().unwrap().push(request.clone());
                while gate.load(Ordering::Acquire) { tokio::time::sleep(Duration::from_millis(5)).await; }
                let mode = behavior.lock().unwrap().clone();
                let now = Utc::now() - chrono::Duration::seconds(1);
                let requirement = request["requirement"].as_str().unwrap();
                let category = requirement.ends_with("category-v1");
                let mut payload = json!({
                    "schema":registry_evidence_verifier::EVIDENCE_SCHEMA_V1,
                    "assuranceProfile":"local", "subjectBinding":"audience-scoped", "requestNonce":request["requestNonce"],
                    "id":format!("urn:example:evidence:{}", uuid::Uuid::new_v4()), "type":"Evidence",
                    "supportsRequirement":requirement, "isConformantTo":if category {"urn:example:farmer:category-evidence"} else {"urn:example:farmer:status-evidence"},
                    "issuedBy":"urn:example:farmer-authority", "providedBy":"urn:example:farmer-registry", "purpose":"land-registration", "audience":"urn:example:landholding",
                    "configurationRevision":format!("sha256:{}", "1".repeat(64)),
                    "issuedAt":now.to_rfc3339(), "observedAt":now.to_rfc3339(), "validUntil":(now + chrono::Duration::seconds(120)).to_rfc3339(),
                    "subjects":[{"role":"farmer","binding":"urn:evidence:subject:v1_QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU"}],
                    "supportedValues":[{"providesValueFor":if category {"urn:example:farmer:category"} else {"urn:example:farmer:active"}, "value":if category {json!("smallholder")} else {json!(mode != "inactive")}}]
                });
                if mode == "nonce" { payload["requestNonce"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); }
                if mode == "expired" { payload["validUntil"] = json!((now - chrono::Duration::seconds(1)).to_rfc3339()); }
                let protected = URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":key.kid,"typ":registry_evidence_verifier::EVIDENCE_JWS_TYP,"cty":registry_evidence_verifier::EVIDENCE_JWS_CTY}).to_string());
                let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
                let signature = registry_platform_crypto::sign(format!("{protected}.{payload}").as_bytes(), &key).unwrap();
                ([(axum::http::header::CONTENT_TYPE, registry_evidence_verifier::EVIDENCE_JWS_MEDIA_TYPE), (axum::http::HeaderName::from_static("traceparent"), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")], json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(signature)}).to_string())
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = EvidenceClientConfig::new(
            format!("http://{address}").parse().unwrap(),
            Arc::new(StaticToken::new("synthetic-test-token").unwrap()),
            JwksDocument { keys: vec![public] },
            vec![],
        );
        let binding = EvidenceProviderBinding::new("synthetic-trust-v1".into(), config).unwrap();
        Self {
            client: Arc::new(EvidenceActionClient::new(BTreeMap::from([(
                "farmer-registry".into(),
                binding,
            )]))),
            requests,
            paused,
            mode,
            server,
        }
    }
    pub fn client(&self) -> Arc<EvidenceActionClient> {
        self.client.clone()
    }
    pub fn calls(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    pub fn requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Release);
    }
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
    }
    pub fn mode(&self, mode: &str) {
        *self.mode.lock().unwrap() = mode.into();
    }
    pub async fn wait_for_calls(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.calls() < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("provider receives expected request");
    }
}
