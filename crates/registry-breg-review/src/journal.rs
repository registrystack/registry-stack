// SPDX-License-Identifier: Apache-2.0

//! The minimized audit stream for browser review operations. It names people
//! and the page's client only by keyed pseudonyms, and never holds a token, a
//! cookie, a CSRF value, a record value, or a network address.

use registry_platform_audit::{AuditKeyHasher, AuditRequest, AuditUnavailable, AuditWriter};
use serde_json::{json, Value};
use uuid::Uuid;

const AUDIT_SCHEMA: &str = "registry-breg-review-audit/v1";
const PRINCIPAL_CLASS: &str = "breg-review-principal-v1";
const CLIENT_CLASS: &str = "breg-review-client-v1";

#[derive(Clone, Copy, Debug)]
pub(crate) enum Action {
    SignIn,
    Read,
    Submit,
    SignOut,
}

impl Action {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign-in",
            Self::Read => "read",
            Self::Submit => "submit",
            Self::SignOut => "sign-out",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Outcome {
    Ok,
    Conflicted,
    Refused,
}

impl Outcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Conflicted => "conflicted",
            Self::Refused => "refused",
        }
    }
}

pub(crate) struct Journal {
    writer: AuditWriter,
    hasher: AuditKeyHasher,
    client: String,
}

/// One accepted request entry whose terminal response is still owed.
#[must_use = "dropping an audit operation records an unfinished outcome"]
pub(crate) struct Operation {
    request: AuditRequest,
    action: Action,
    client: String,
    citizen: Option<String>,
    change_request_id: Option<String>,
}

/// A pseudonym could not be derived.
#[derive(Debug)]
pub(crate) struct PseudonymError;

impl Journal {
    pub(crate) fn new(
        writer: AuditWriter,
        hasher: AuditKeyHasher,
        issuer: &str,
        client_id: &str,
    ) -> Result<Self, PseudonymError> {
        let client = pseudonym(&hasher, CLIENT_CLASS, &json!([issuer, client_id]))?;
        Ok(Self {
            writer,
            hasher,
            client,
        })
    }

    /// The stable pseudonym of one signed-in person at one provider.
    pub(crate) fn citizen(&self, issuer: &str, subject: &str) -> Result<String, PseudonymError> {
        pseudonym(&self.hasher, PRINCIPAL_CLASS, &json!([issuer, subject]))
    }

    /// Record an operation before provider or registry I/O starts.
    pub(crate) async fn begin(
        &self,
        action: Action,
        citizen: Option<&str>,
        change_request_id: Option<&str>,
    ) -> Result<Operation, AuditUnavailable> {
        let citizen = citizen.map(str::to_owned);
        let change_request_id = change_request_id.map(str::to_owned);
        let request_record = record(
            action,
            None,
            &self.client,
            citizen.as_deref(),
            change_request_id.as_deref(),
        );
        let unfinished = record(
            action,
            Some("unfinished"),
            &self.client,
            citizen.as_deref(),
            change_request_id.as_deref(),
        );
        let request = self
            .writer
            .begin(
                AUDIT_SCHEMA,
                Uuid::new_v4().to_string(),
                request_record,
                unfinished,
            )
            .await?;
        Ok(Operation {
            request,
            action,
            client: self.client.clone(),
            citizen,
            change_request_id,
        })
    }

    pub(crate) async fn ready(&self) -> bool {
        self.writer.ready().await
    }
}

impl Operation {
    /// Append the terminal response before the protected result is released.
    /// `citizen` supplies the principal learned during sign-in.
    pub(crate) async fn finish(
        self,
        outcome: Outcome,
        citizen: Option<&str>,
    ) -> Result<(), AuditUnavailable> {
        let citizen = citizen.or(self.citizen.as_deref());
        let response = record(
            self.action,
            Some(outcome.as_str()),
            &self.client,
            citizen,
            self.change_request_id.as_deref(),
        );
        self.request.finish(response).await
    }
}

fn record(
    action: Action,
    outcome: Option<&str>,
    client: &str,
    citizen: Option<&str>,
    change_request_id: Option<&str>,
) -> Value {
    let mut record = json!({
        "event": "breg-review",
        "action": action.as_str(),
        "clientPseudonym": client,
    });
    if let Some(outcome) = outcome {
        record["outcome"] = Value::from(outcome);
    }
    if let Some(citizen) = citizen {
        record["principalPseudonym"] = Value::from(citizen);
    }
    if let Some(change_request_id) = change_request_id {
        record["changeRequestId"] = Value::from(change_request_id);
    }
    record
}

fn pseudonym(
    hasher: &AuditKeyHasher,
    class: &str,
    input: &Value,
) -> Result<String, PseudonymError> {
    hasher
        .audit_reference_hash(class, "", &input.to_string())
        .map_err(|_| PseudonymError)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use registry_platform_audit::{AuditProfile, AuditWriter};

    use super::*;

    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);

    impl Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Lines {
        fn entries(&self) -> Vec<Value> {
            let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
            text.lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
    }

    fn journal(lines: &Lines) -> (Journal, AuditWriter) {
        let writer = AuditWriter::from_line_sink(Box::new(lines.clone()));
        let journal = Journal::new(
            writer.clone(),
            AuditProfile::unkeyed_dev_only().key_hasher(),
            "https://issuer.example",
            "review-page",
        )
        .unwrap();
        (journal, writer)
    }

    #[tokio::test]
    async fn a_cancelled_operation_gets_a_minimized_unfinished_response() {
        let lines = Lines::default();
        let (journal, writer) = journal(&lines);
        let operation = journal
            .begin(
                Action::Submit,
                Some("principal-pseudonym"),
                Some("request-1"),
            )
            .await
            .unwrap();

        drop(operation);
        writer.wait_for_detached_entries();

        let entries = lines.entries();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[1]["record"]["outcome"], "unfinished");
        assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
        for entry in &entries {
            let record = entry["record"].as_object().unwrap();
            assert!(record.keys().all(|key| matches!(
                key.as_str(),
                "event"
                    | "action"
                    | "outcome"
                    | "clientPseudonym"
                    | "principalPseudonym"
                    | "changeRequestId"
            )));
        }
    }

    #[tokio::test]
    async fn concurrent_access_to_one_draft_keeps_success_and_cancellation_correlations_independent(
    ) {
        let lines = Lines::default();
        let (journal, writer) = journal(&lines);
        let (first, second) = tokio::join!(
            journal.begin(Action::Read, Some("principal"), Some("request-1")),
            journal.begin(Action::Read, Some("principal"), Some("request-1")),
        );
        let (first, second) = (first.unwrap(), second.unwrap());
        let first_correlation = first.request.correlation().to_owned();
        let second_correlation = second.request.correlation().to_owned();
        assert_ne!(first_correlation, second_correlation);

        first.finish(Outcome::Ok, None).await.unwrap();
        drop(second);
        writer.wait_for_detached_entries();

        let entries = lines.entries();
        for (correlation, outcome) in [
            (first_correlation, "ok"),
            (second_correlation, "unfinished"),
        ] {
            let paired: Vec<_> = entries
                .iter()
                .filter(|entry| entry["correlation"] == correlation)
                .collect();
            assert_eq!(paired.len(), 2, "{entries:?}");
            assert!(paired.iter().any(|entry| entry["phase"] == "request"));
            assert!(paired.iter().any(|entry| {
                entry["phase"] == "response" && entry["record"]["outcome"] == outcome
            }));
        }
    }
}
