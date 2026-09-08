// SPDX-License-Identifier: Apache-2.0
//! Real Evidence service + synthetic authoritative source, supervised by the
//! fixture's ordinary adopter runner. No Evidence server library dependency.
use registry_breg::action_evidence_client::{EvidenceActionClient, EvidenceProviderBinding};
use registry_evidence_client::{EvidenceClientConfig, JwksDocument, StaticToken};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::Write,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

pub struct RealEvidenceProvider {
    _child: FixtureChild,
    _scratch: tempfile::TempDir,
    ready: Value,
    client: Arc<EvidenceActionClient>,
}
struct FixtureChild(Child);
impl Drop for FixtureChild {
    fn drop(&mut self) {
        if let Some(mut stdin) = self.0.stdin.take() {
            let _ = stdin.write_all(b"stop\n");
        }
        // The runner owns graceful service/source cleanup on its stdin signal.
        let _ = self.0.wait();
    }
}
impl RealEvidenceProvider {
    pub async fn start() -> Self {
        let binary = std::env::var("BREG_TEST_EVIDENCE_BINARY")
            .expect("BREG_TEST_EVIDENCE_BINARY is required for real Evidence/PG proof");
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance/farmer-landholding-evidence/evidence");
        let scratch = tempfile::tempdir().unwrap();
        let mut child = FixtureChild(
            Command::new("python3")
                .arg(root.join("run-provider.py"))
                .arg("--evidence")
                .arg(binary)
                .arg("--output")
                .arg(scratch.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let ready_path = scratch.path().join("ready.json");
        tokio::time::timeout(Duration::from_secs(30), async {
            while !ready_path.is_file() {
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "real Evidence provider runner exited before ready"
                );
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .expect("real Evidence fixture becomes ready");
        let ready: Value = serde_json::from_slice(&std::fs::read(ready_path).unwrap()).unwrap();
        let token = std::fs::read_to_string(ready["tokenFile"].as_str().unwrap()).unwrap();
        let jwks: JwksDocument =
            serde_json::from_slice(&std::fs::read(ready["jwksFile"].as_str().unwrap()).unwrap())
                .unwrap();
        let config = EvidenceClientConfig::new(
            ready["baseUrl"].as_str().unwrap().parse().unwrap(),
            Arc::new(StaticToken::new(token.trim()).unwrap()),
            jwks,
            vec![],
        );
        let binding =
            EvidenceProviderBinding::new("real-fixture-pinned-trust-v1".into(), config).unwrap();
        Self {
            _child: child,
            _scratch: scratch,
            ready,
            client: Arc::new(EvidenceActionClient::new(BTreeMap::from([(
                "farmer-registry".into(),
                binding,
            )]))),
        }
    }
    pub fn client(&self) -> Arc<EvidenceActionClient> {
        self.client.clone()
    }
    pub fn unauthorized_client(&self) -> Arc<EvidenceActionClient> {
        let token =
            std::fs::read_to_string(self.ready["unauthorizedTokenFile"].as_str().unwrap()).unwrap();
        let jwks: JwksDocument = serde_json::from_slice(
            &std::fs::read(self.ready["jwksFile"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let config = EvidenceClientConfig::new(
            self.ready["baseUrl"].as_str().unwrap().parse().unwrap(),
            Arc::new(StaticToken::new(token.trim()).unwrap()),
            jwks,
            vec![],
        );
        let binding =
            EvidenceProviderBinding::new("real-fixture-pinned-trust-v1".into(), config).unwrap();
        Arc::new(EvidenceActionClient::new(BTreeMap::from([(
            "farmer-registry".into(),
            binding,
        )])))
    }
    pub fn contracts(&self) -> Vec<u8> {
        std::fs::read(self.ready["contractsFile"].as_str().unwrap()).unwrap()
    }
    pub fn requests(&self) -> Vec<Value> {
        std::fs::read_to_string(self.ready["requestsFile"].as_str().unwrap())
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    pub fn control(&self, control: &Value) {
        std::fs::write(
            self.ready["controlFile"].as_str().unwrap(),
            serde_json::to_vec(control).unwrap(),
        )
        .unwrap();
    }
}
