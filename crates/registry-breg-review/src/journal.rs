// SPDX-License-Identifier: Apache-2.0

//! The hash-chained audit journal. It names people and the page's client only
//! by keyed pseudonyms, and never holds a token, a cookie, a CSRF value, a
//! record value, or a network address: behind a proxy every browser shares
//! one peer address, so it would name no one.

use registry_platform_audit::{AuditError, AuditKeyHasher, DurableSegmentedAuditLog};
use serde_json::{json, Value};

const PRINCIPAL_CLASS: &str = "breg-review-principal-v1";
const CLIENT_CLASS: &str = "breg-review-client-v1";

/// The largest a journal segment grows before the log rotates to the next.
pub(crate) const MAXIMUM_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

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
    Attempted,
    Succeeded,
    Conflicted,
    Refused,
    Failed,
}

impl Outcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Attempted => "attempted",
            Self::Succeeded => "succeeded",
            Self::Conflicted => "conflicted",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }
}

pub(crate) struct Journal {
    log: DurableSegmentedAuditLog,
    hasher: AuditKeyHasher,
    client: String,
}

/// A pseudonym could not be derived.
#[derive(Debug)]
pub(crate) struct PseudonymError;

impl Journal {
    pub(crate) fn new(
        log: DurableSegmentedAuditLog,
        hasher: AuditKeyHasher,
        issuer: &str,
        client_id: &str,
    ) -> Result<Self, PseudonymError> {
        let client = pseudonym(&hasher, CLIENT_CLASS, &json!([issuer, client_id]))?;
        Ok(Self {
            log,
            hasher,
            client,
        })
    }

    /// The stable pseudonym of one signed-in person at one provider.
    pub(crate) fn citizen(&self, issuer: &str, subject: &str) -> Result<String, PseudonymError> {
        pseudonym(&self.hasher, PRINCIPAL_CLASS, &json!([issuer, subject]))
    }

    pub(crate) async fn record(
        &self,
        action: Action,
        outcome: Outcome,
        citizen: Option<&str>,
        change_request_id: Option<&str>,
    ) -> Result<(), AuditError> {
        let mut record = json!({
            "event": "breg-review",
            "action": action.as_str(),
            "outcome": outcome.as_str(),
            "clientPseudonym": self.client,
        });
        if let Some(citizen) = citizen {
            record["principalPseudonym"] = Value::from(citizen);
        }
        if let Some(change_request_id) = change_request_id {
            record["changeRequestId"] = Value::from(change_request_id);
        }
        self.log.append_record(record).await.map(|_| ())
    }

    pub(crate) async fn ready(&self) -> bool {
        self.log.ready().await
    }
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
