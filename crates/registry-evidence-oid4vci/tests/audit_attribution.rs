use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

use registry_evidence_oid4vci::{
    audit::{CredentialDeliveryOutcome, DeliveryAudit, DeliveryAuditError},
    authorizer::AuthorizedOffer,
};
use registry_platform_audit::AuditWriter;
use serde_json::Value;

const CLIENT_CANARY: &str = "private-offer-client-canary";
const SUBJECT_CANARY: &str = "private-offer-subject-canary";
const EXCHANGE_ID: &str = "exchange-correlation-123";

#[derive(Clone, Default)]
struct CapturedLines(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLines {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl CapturedLines {
    fn entries(&self) -> Vec<Value> {
        let bytes = self.0.lock().expect("capture lock").clone();
        String::from_utf8(bytes)
            .expect("audit is UTF-8 JSON Lines")
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit entry is JSON"))
            .collect()
    }
}

#[tokio::test]
async fn offer_audit_refuses_an_exchange_without_a_verified_identity() {
    let captured = CapturedLines::default();
    let audit = DeliveryAudit::with_writer(
        AuditWriter::from_line_sink(Box::new(captured.clone())),
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("the audit profile is valid");

    assert!(matches!(
        audit
            .begin_offer_creation("unattributed-exchange", &AuthorizedOffer::default())
            .await,
        Err(DeliveryAuditError::InvalidIdentity)
    ));
    assert!(captured.entries().is_empty());
}

#[tokio::test]
async fn offer_and_delivery_audit_is_correlated_and_privacy_safe() {
    let captured = CapturedLines::default();
    let audit = DeliveryAudit::with_writer(
        AuditWriter::from_line_sink(Box::new(captured.clone())),
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("the audit profile is valid");

    audit
        .begin_offer_creation(
            EXCHANGE_ID,
            &AuthorizedOffer {
                client: Some(CLIENT_CANARY.to_owned()),
                subject: Some(SUBJECT_CANARY.to_owned()),
            },
        )
        .await
        .expect("offer audit request is accepted")
        .created()
        .await
        .expect("offer audit response is accepted");
    audit
        .begin_credential_delivery(EXCHANGE_ID)
        .await
        .expect("delivery audit request is accepted")
        .finish(CredentialDeliveryOutcome::Released)
        .await
        .expect("delivery audit response is accepted");

    let entries = captured.entries();
    assert_eq!(entries.len(), 4);
    assert!(entries
        .iter()
        .all(|entry| entry["correlation"] == EXCHANGE_ID));
    assert_eq!(entries[0]["record"]["operation"], "offer_creation");
    assert_eq!(entries[1]["record"]["outcome"], "created");
    assert_eq!(entries[2]["record"]["operation"], "credential_delivery");
    assert_eq!(entries[3]["record"]["outcome"], "released");

    let rendered = serde_json::to_string(&entries).expect("audit entries render");
    assert!(!rendered.contains(CLIENT_CANARY));
    assert!(!rendered.contains(SUBJECT_CANARY));
    assert!(entries[0]["record"]["clientPseudonym"]
        .as_str()
        .is_some_and(|value| value.starts_with("hmac-sha256:")));
    assert!(entries[0]["record"]["subjectPseudonym"]
        .as_str()
        .is_some_and(|value| value.starts_with("hmac-sha256:")));
}
