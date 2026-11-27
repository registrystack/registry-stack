// SPDX-License-Identifier: Apache-2.0

//! The minimized audit stream for sign-in and sign-out. It names people and
//! the sign-in clients only by keyed pseudonyms, and never holds a token, a
//! cookie, a state value, or a network address. The gateway check writes
//! nothing here: only a session's start and its ends are recorded.

use std::collections::HashMap;

use registry_platform_audit::{AuditKeyHasher, AuditRequest, AuditUnavailable, AuditWriter};
use serde_json::{json, Value};

const AUDIT_SCHEMA: &str = "registry-session-audit/v1";
const PRINCIPAL_CLASS: &str = "session-principal-v1";
const CLIENT_CLASS: &str = "session-client-v1";

#[derive(Clone, Copy, Debug)]
pub enum Action {
    SignIn,
    SignOut,
    /// A renewal the issuer refused ended the session.
    SessionEnded,
}

impl Action {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign-in",
            Self::SignOut => "sign-out",
            Self::SessionEnded => "session-ended",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    Ok,
    Refused,
    /// A sign-out ended the session but the issuer did not confirm every
    /// revocation.
    RevocationFailed,
}

impl Outcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Refused => "refused",
            Self::RevocationFailed => "revocation-failed",
        }
    }
}

/// A pseudonym could not be derived.
#[derive(Debug)]
pub struct PseudonymError;

pub struct Journal {
    writer: AuditWriter,
    hasher: AuditKeyHasher,
    issuer: String,
    /// The pseudonym of each kind's client at the issuer.
    clients: HashMap<String, String>,
}

/// One accepted request entry whose terminal response is still owed.
#[must_use = "dropping an audit operation records an unfinished outcome"]
pub struct Operation {
    request: AuditRequest,
    action: Action,
    kind: String,
    client: String,
    person: Option<String>,
}

impl Journal {
    /// `clients` pairs each kind of sign-in with its client identifier at
    /// `issuer`.
    pub fn new<'a>(
        writer: AuditWriter,
        hasher: AuditKeyHasher,
        issuer: &str,
        clients: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, PseudonymError> {
        let clients = clients
            .into_iter()
            .map(|(kind, client_id)| {
                pseudonym(&hasher, CLIENT_CLASS, &json!([issuer, client_id]))
                    .map(|client| (kind.to_owned(), client))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            writer,
            hasher,
            issuer: issuer.to_owned(),
            clients,
        })
    }

    /// The stable pseudonym of one person at the issuer.
    pub fn person(&self, subject: &str) -> Result<String, PseudonymError> {
        self.person_at(&self.issuer, subject)
    }

    /// The stable pseudonym of one person at `issuer`.
    pub fn person_at(&self, issuer: &str, subject: &str) -> Result<String, PseudonymError> {
        pseudonym(&self.hasher, PRINCIPAL_CLASS, &json!([issuer, subject]))
    }

    /// Record an operation before issuer I/O starts. The terminal response is
    /// owed through [`Operation::finish`].
    pub async fn begin(
        &self,
        action: Action,
        kind: &str,
        person: Option<&str>,
    ) -> Result<Operation, AuditUnavailable> {
        let client = self.clients.get(kind).cloned().unwrap_or_default();
        let person = person.map(str::to_owned);
        let request = self
            .writer
            .begin(
                AUDIT_SCHEMA,
                crate::store::random_token().unwrap_or_default(),
                record(action, None, kind, &client, person.as_deref()),
                record(action, Some("unfinished"), kind, &client, person.as_deref()),
            )
            .await?;
        Ok(Operation {
            request,
            action,
            kind: kind.to_owned(),
            client,
            person,
        })
    }

    /// Record one operation that has no I/O to wait for.
    pub async fn record(
        &self,
        action: Action,
        kind: &str,
        person: Option<&str>,
        outcome: Outcome,
    ) -> Result<(), AuditUnavailable> {
        self.begin(action, kind, person)
            .await?
            .finish(outcome, None)
            .await
    }

    pub async fn ready(&self) -> bool {
        self.writer.ready().await
    }
}

impl Operation {
    /// Append the terminal response before the protected result is released.
    /// `person` supplies the principal learned during sign-in.
    pub async fn finish(
        self,
        outcome: Outcome,
        person: Option<&str>,
    ) -> Result<(), AuditUnavailable> {
        let person = person.or(self.person.as_deref());
        let response = record(
            self.action,
            Some(outcome.as_str()),
            &self.kind,
            &self.client,
            person,
        );
        self.request.finish(response).await
    }
}

fn record(
    action: Action,
    outcome: Option<&str>,
    kind: &str,
    client: &str,
    person: Option<&str>,
) -> Value {
    let mut record = json!({
        "event": "session",
        "action": action.as_str(),
        "signIn": kind,
        "clientPseudonym": client,
    });
    if let Some(outcome) = outcome {
        record["outcome"] = Value::from(outcome);
    }
    if let Some(person) = person {
        record["principalPseudonym"] = Value::from(person);
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

    use registry_platform_audit::AuditProfile;

    use super::*;

    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);

    impl Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lines").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Lines {
        fn entries(&self) -> Vec<Value> {
            let text = String::from_utf8(self.0.lock().expect("lines").clone()).expect("utf-8");
            text.lines()
                .map(|line| serde_json::from_str(line).expect("json line"))
                .collect()
        }
    }

    fn journal(lines: &Lines) -> (Journal, AuditWriter) {
        let writer = AuditWriter::from_line_sink_without_posture(Box::new(lines.clone()));
        let journal = Journal::new(
            writer.clone(),
            AuditProfile::unkeyed_dev_only().key_hasher(),
            "https://issuer.example",
            [("citizen", "citizen-app")],
        )
        .expect("journal");
        (journal, writer)
    }

    #[tokio::test]
    async fn a_cancelled_operation_gets_a_minimized_unfinished_response() {
        let lines = Lines::default();
        let (journal, writer) = journal(&lines);
        let operation = journal
            .begin(Action::SignIn, "citizen", Some("person-pseudonym"))
            .await
            .expect("begin");

        drop(operation);
        writer.wait_for_detached_entries();

        let entries = lines.entries();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[1]["record"]["outcome"], "unfinished");
        assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
        for entry in &entries {
            let record = entry["record"].as_object().expect("record");
            assert!(record.keys().all(|key| matches!(
                key.as_str(),
                "event"
                    | "action"
                    | "outcome"
                    | "signIn"
                    | "clientPseudonym"
                    | "principalPseudonym"
            )));
        }
    }

    #[tokio::test]
    async fn a_person_appears_only_as_a_pseudonym() {
        let lines = Lines::default();
        let (journal, _writer) = journal(&lines);
        let person = journal.person("subject-canary").expect("pseudonym");
        assert_ne!(person, "subject-canary");
        journal
            .record(
                Action::SessionEnded,
                "citizen",
                Some(&person),
                Outcome::Refused,
            )
            .await
            .expect("record");
        let text = format!("{:?}", lines.entries());
        assert!(!text.contains("subject-canary"));
        assert!(text.contains(&person));
        assert!(text.contains("session-ended"));
    }
}
