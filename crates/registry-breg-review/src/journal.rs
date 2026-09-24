// SPDX-License-Identifier: Apache-2.0

//! The hash-chained audit journal. It names people, the page's client, and
//! remote addresses only by keyed pseudonyms, and never holds a token, a
//! cookie, a CSRF value, or a record value.

use registry_platform_audit::{AuditError, AuditKeyHasher, DurableSegmentedAuditLog};
use serde_json::{json, Value};

const PRINCIPAL_CLASS: &str = "breg-review-principal-v1";
const CLIENT_CLASS: &str = "breg-review-client-v1";
const ADDRESS_CLASS: &str = "breg-review-address-v1";

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

    /// The pseudonym of a remote address, which also keys its rate limit.
    pub(crate) fn address(&self, address: &str) -> Result<String, PseudonymError> {
        pseudonym(&self.hasher, ADDRESS_CLASS, &json!([address]))
    }

    pub(crate) async fn record(
        &self,
        action: Action,
        outcome: Outcome,
        citizen: Option<&str>,
        address: &str,
        request_id: Option<&str>,
    ) -> Result<(), AuditError> {
        let mut record = json!({
            "event": "breg-review",
            "action": action.as_str(),
            "outcome": outcome.as_str(),
            "clientPseudonym": self.client,
            "addressPseudonym": address,
        });
        if let Some(citizen) = citizen {
            record["citizenPseudonym"] = Value::from(citizen);
        }
        if let Some(request_id) = request_id {
            record["requestId"] = Value::from(request_id);
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
