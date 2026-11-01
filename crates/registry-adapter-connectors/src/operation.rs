// SPDX-License-Identifier: Apache-2.0
//! The connector operation contract (`products/adapter/CONCEPT.md`
//! section 17.3).
//!
//! Every native product operation is described before it runs, prepared
//! without I/O into an exact persistable form, sent once, and recovered
//! under its own rule. The shapes here are the contract between the
//! connector crate and the delivery runner: the runner holds the ledger
//! and derives the keys, the connector holds the typed client call.
//!
//! ```text
//! describe() -> descriptor
//! prepare(input, binding, key) -> prepared   // exact, persistable, no bearer token
//! send(prepared) -> outcome                  // accepted | pending | completed | refused | uncertain
//! recover(prepared) -> outcome               // this operation's rule; never a new key
//! observe(correlation) -> native lifecycle state, where the family has one
//! ```
//!
//! Diagnostics are value-free: an outcome names operations, problem codes,
//! and correlation identities, never a payload, credential, or selector
//! value, mirroring the engine's `adapter.*` discipline.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The closed set of shared reporting categories for one send. The
/// product's own lifecycle state stays available beneath the category
/// through [`SendOutcome::native_problem`] and the observation traits;
/// the category is a summary, never a replacement for the product's
/// state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutcomeCategory {
    /// The destination accepted the operation; any completion it still
    /// owes is tracked separately.
    Accepted,
    /// The destination holds the operation in its own lifecycle; the
    /// correlation identity observes it later.
    Pending,
    /// The destination committed the operation's effect and answered
    /// with its committed receipt.
    Completed,
    /// The destination refused the operation. A refusal never falls
    /// back to another mutation mode.
    Refused,
    /// The attempt's outcome is unknown (lost response, ambiguous
    /// exchange). Recovery applies this operation's rule; success is
    /// never inferred from silence.
    Uncertain,
}

impl OutcomeCategory {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Refused => "refused",
            Self::Uncertain => "uncertain",
        }
    }
}

/// Whether an operation changes destination state, and what it needs
/// before it may run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationBehavior {
    /// A read; it creates no write capability at the destination.
    ReadOnly,
    /// A mutation with declared preconditions the caller must hold
    /// (record ETags, observed revisions, target conditions).
    Preconditioned,
    /// A mutation without preconditions beyond its binding and key.
    Unconditional,
    /// A destructive operation; it needs a declared operation and an
    /// appropriate grant, and source disappearance never selects it.
    Destructive,
}

/// What the operation needs from the host before it may run.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialRequirements {
    /// The product credential kinds this operation accepts, by the
    /// client's own names (for example `private-key-jwt`). Credentials
    /// stay host-owned; a prepared form never carries a bearer token.
    pub credential_kinds: Vec<String>,
    /// Whether the operation additionally needs a host-supplied task
    /// grant (Scheduling capacity commands). A grant comes from a
    /// human-approved template through the host; the connector never
    /// mints one.
    pub requires_task_grant: bool,
    /// Whether the operation needs operator-opened authority (the BReg
    /// `import` ingestion profile).
    pub requires_operator_authority: bool,
}

/// How the operation's idempotency is established and replayed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum IdempotencyRule {
    /// The caller supplies a command key; the connector persists it in
    /// the prepared form and every retry reuses it. Only a success
    /// spends a key at the destination.
    CallerKeyed {
        /// The destination's idempotent receipt retention, in days,
        /// when the destination publishes one (BReg: 1 to 365). An
        /// uncertain attempt approaching this horizon alarms.
        receipt_retention_days: Option<u32>,
    },
    /// The operation is unkeyed and replay-safe by the destination's
    /// own protocol (BReg ingestion chunk resubmission, Document Store
    /// grant issue and erasure, Scheduling hold release).
    DestinationReplay,
    /// The operation is unkeyed and recoverable only by reading state
    /// back (Scheduling busy reconciliation by compare-and-swap
    /// revision).
    ReadBeforeRetry,
}

/// How an uncertain attempt of this operation recovers. One rule per
/// family, from the client's contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RecoveryRule {
    /// Recover by re-arming the exact prepared form and sending it
    /// again under the same key; the destination replays its retained
    /// receipt (BReg Start, Submit, and every keyed mutation).
    ExactSameKey,
    /// Recover by reading the destination's state for the correlation
    /// identity first, then acting on what the read proves; a new key
    /// after an unread outcome risks a duplicate (the receipt-horizon
    /// discipline after `410 idempotency.expired`).
    ReadThenDecide,
    /// Recover by sending the identical request again; the destination
    /// answers with the state as it stands now.
    IdempotentResend,
    /// Recover by starting a fresh attempt under a new key after the
    /// destination's own expiry semantics (Scheduling hold release:
    /// the hold expires; start a new request).
    FreshAttempt,
    /// The operation has no replay surface; its uncertainty is
    /// reported and observed, never retried blindly.
    ObserveOnly,
}

/// The body kind an operation carries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BodyKind {
    /// A JSON document validated against the descriptor's input
    /// schema.
    Json,
    /// Binary content through an opaque host-owned content reference
    /// with expected digest, length, and media type; never base64
    /// through a mapping.
    ContentReference {
        /// The digest algorithm the host pins (for example `sha-256`).
        digest_algorithm: String,
    },
    /// No body (releases and cancellations by identifier).
    None,
}

/// The products a connector targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Product {
    Breg,
    Scheduling,
    Documents,
}

impl Product {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Breg => "breg",
            Self::Scheduling => "scheduling",
            Self::Documents => "documents",
        }
    }
}

/// The input schema reference an operation validates against. The
/// product module that owns the operation owns its schema; the
/// descriptor names it so a runner can reason about an operation
/// without linking the product client.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum InputSchema {
    /// The destination's own published contract for the operation, as
    /// the client models it (a BReg metadata-selected binding, a
    /// Scheduling request document).
    DestinationContract {
        /// The destination's name for the contract the client selects.
        contract: String,
    },
    /// A closed JSON shape the connector itself defines and validates
    /// before preparing.
    ConnectorDefined {
        /// A stable name for the shape, documented in the product
        /// module.
        shape: String,
    },
}

/// The descriptor one operation publishes before anything runs. Only
/// implemented, enabled operations are advertised; an unsupported
/// operation fails during checking, and no descriptor exists for an
/// operation the crate cannot send.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationDescriptor {
    /// The operation's qualified name within its product connector, for
    /// example `breg.proposal.start`.
    pub name: &'static str,
    /// The product this operation targets.
    pub product: Product,
    /// The input schema the operation validates before preparing.
    pub input_schema: InputSchema,
    /// The body kind.
    pub body_kind: BodyKind,
    /// Mutation and precondition behavior.
    pub mutation: MutationBehavior,
    /// Credential and authority requirements.
    pub credentials: CredentialRequirements,
    /// The idempotency rule.
    pub idempotency: IdempotencyRule,
    /// The recovery rule for uncertain attempts.
    pub recovery: RecoveryRule,
    /// What completion means for this operation, in one sentence.
    pub completion: &'static str,
    /// Whether the family carries a native lifecycle an
    /// [`Observable::observe`] can read.
    pub observable: bool,
}

/// One send's result: the shared category, the product's own problem
/// code or lifecycle word where there is one, and the correlation
/// identity the runner uses for observation. Value-free.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SendOutcome {
    /// The shared reporting category.
    pub category: OutcomeCategory,
    /// The product's own code or state word (for example
    /// `idempotency.expired`, `lookup.unresolved`, `submitted`),
    /// present exactly when the product emitted one.
    pub native_problem: Option<String>,
    /// The operation's correlation identity at the destination, when
    /// the send produced or read one (a Proposal id, an application
    /// id, an appointment id, a run id). An opaque string the runner
    /// persists and passes back to [`Observable::observe`].
    pub correlation: Option<String>,
    /// A value-free note naming the operation's next step (for example
    /// which read settles an uncertain attempt). Never a payload
    /// value.
    pub note: Option<&'static str>,
}

impl fmt::Display for SendOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.category.name())?;
        if let Some(problem) = &self.native_problem {
            write!(formatter, " ({problem})")?;
        }
        if self.correlation.is_some() {
            formatter.write_str(" with correlation")?;
        }
        Ok(())
    }
}

/// The native lifecycle state an observation returns, where the family
/// has one. Value-free.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeState {
    /// The product's own state word for the tracked work (for example
    /// BReg's `submitted`, `applied`, `returned`).
    pub state: String,
    /// Further value-free facts the product publishes (turn, decision
    /// status, application state), as name and word pairs.
    pub details: Vec<(String, String)>,
}

/// A connector fault: value-free, typed, and closed. Product modules
/// surface their client's typed errors through this vocabulary and
/// never leak transport text.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectorFault {
    /// The prepared form does not match the current binding; the
    /// binding changed and the attempt must be re-prepared under the
    /// rules, never silently rebound.
    #[error("the binding changed under the prepared attempt")]
    BindingChanged,
    /// The prepared form's bytes are not this operation's form.
    #[error("the prepared form is not this operation's")]
    NotPrepared,
    /// The operation is not implemented and enabled in this build;
    /// advertising it was a build error.
    #[error("the operation is not enabled in this build")]
    NotEnabled,
    /// The input does not satisfy the operation's declared schema.
    #[error("the input does not satisfy the operation schema")]
    InvalidInput,
    /// The host did not supply an authority the operation requires
    /// (task grant, operator-opened import authority).
    #[error("a required host authority is absent")]
    AuthorityAbsent,
    /// The product's answer could not be honored under the operation's
    /// contract; the native code names the detail, value-free.
    #[error("the product refused or malformed the call: {code:?}")]
    Native { code: Option<String> },
}

/// A connector command key. The connector supplies and persists the
/// key; client libraries never invent one. The runner derives keys
/// from source identity, revision, mapping closure, and step, so a
/// restart recomputes the same key (`CONCEPT.md` section 17.2); the
/// key itself is opaque bytes here.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CommandKey(pub String);

impl CommandKey {
    /// Accept a key the runner derived. Refuses an empty key or one
    /// over 256 bytes, the widest bound the product clients accept.
    ///
    /// # Errors
    ///
    /// [`ConnectorFault::InvalidInput`] when the key is empty or over
    /// the byte bound.
    pub fn new(key: String) -> Result<Self, ConnectorFault> {
        if key.is_empty() || key.len() > 256 {
            return Err(ConnectorFault::InvalidInput);
        }
        Ok(Self(key))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The exact, persistable form of one attempt. It serializes through
/// `as_bytes` and restores through `from_bytes`, carries the command
/// key, and holds no bearer token, so the runner may seal it, store it,
/// and hand the same bytes back after a crash.
pub trait PreparedAttempt {
    /// The persistable bytes of this exact attempt.
    fn as_bytes(&self) -> &[u8];

    /// The operation's qualified name, so a stored form resolves to
    /// its operation.
    fn operation(&self) -> &'static str;

    /// The command key this attempt persists.
    fn key(&self) -> &CommandKey;
}

/// The connector operation contract. One implementor per operation
/// family member; the product modules own the typed client calls.
///
/// The runner's sequence is `describe` once at deployment check,
/// `prepare` before any remote effect, `send` once per attempt, and
/// `recover` for an uncertain attempt under the descriptor's rule.
/// `prepare` performs no I/O and holds no bearer token; `send` and
/// `recover` perform the client's bounded same-key retry where the
/// client's contract offers it, counted in the declared execution
/// budget.
pub trait Operation {
    /// The persistable attempt this operation prepares.
    type Prepared: PreparedAttempt;

    /// The descriptor: what this operation is, needs, and how it
    /// recovers. Stable for the life of the process.
    fn describe(&self) -> &OperationDescriptor;

    /// Validate the input against the descriptor's schema and prepare
    /// the exact attempt. No I/O: the destination is not contacted,
    /// the token provider is not consulted, and the returned form
    /// carries no credential.
    ///
    /// # Errors
    ///
    /// [`ConnectorFault::InvalidInput`] when the input does not
    /// satisfy the operation's declared schema.
    fn prepare(&self, input: &Value, key: CommandKey) -> Result<Self::Prepared, ConnectorFault>;

    /// Send the prepared attempt once, plus the client's own bounded
    /// same-key retry where the contract allows it.
    ///
    /// # Errors
    ///
    /// [`ConnectorFault`] when the call could not be made or honored.
    /// An uncertain outcome is a [`SendOutcome`] with
    /// [`OutcomeCategory::Uncertain`], not an error, so the runner
    /// applies the recovery rule instead of guessing.
    fn send(&self, prepared: &Self::Prepared) -> Result<SendOutcome, ConnectorFault>;

    /// Recover an uncertain attempt under this operation's rule: the
    /// same prepared form, never a new key.
    ///
    /// # Errors
    ///
    /// [`ConnectorFault`] as for [`Operation::send`].
    fn recover(&self, prepared: &Self::Prepared) -> Result<SendOutcome, ConnectorFault>;
}

/// A family that carries a native lifecycle the runner can observe
/// separately from delivery (BReg Proposals; Scheduling appointments).
pub trait Observable {
    /// Observe the native state of one correlation identity.
    ///
    /// # Errors
    ///
    /// [`ConnectorFault`] when the observation could not be made; an
    /// unavailable status endpoint is reported, never read as proof of
    /// rejection or application.
    fn observe(&self, correlation: &str) -> Result<NativeState, ConnectorFault>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_categories_use_the_contract_words() {
        assert_eq!(OutcomeCategory::Accepted.name(), "accepted");
        assert_eq!(OutcomeCategory::Pending.name(), "pending");
        assert_eq!(OutcomeCategory::Completed.name(), "completed");
        assert_eq!(OutcomeCategory::Refused.name(), "refused");
        assert_eq!(OutcomeCategory::Uncertain.name(), "uncertain");
    }

    #[test]
    fn product_names_are_stable() {
        assert_eq!(Product::Breg.name(), "breg");
        assert_eq!(Product::Scheduling.name(), "scheduling");
        assert_eq!(Product::Documents.name(), "documents");
    }

    #[test]
    fn command_keys_refuse_empty_and_oversized_forms() {
        assert_eq!(
            CommandKey::new(String::new()),
            Err(ConnectorFault::InvalidInput)
        );
        assert_eq!(
            CommandKey::new("a".repeat(257)),
            Err(ConnectorFault::InvalidInput)
        );
        let key = CommandKey::new("namespace/item-1/step-submit".to_owned())
            .expect("a derived key is accepted");
        assert_eq!(key.as_str(), "namespace/item-1/step-submit");
    }

    #[test]
    fn descriptors_serialize_without_values() {
        let descriptor = OperationDescriptor {
            name: "breg.proposal.start",
            product: Product::Breg,
            input_schema: InputSchema::DestinationContract {
                contract: "action/household-register".to_owned(),
            },
            body_kind: BodyKind::Json,
            mutation: MutationBehavior::Preconditioned,
            credentials: CredentialRequirements {
                credential_kinds: vec!["private-key-jwt".to_owned()],
                requires_task_grant: false,
                requires_operator_authority: false,
            },
            idempotency: IdempotencyRule::CallerKeyed {
                receipt_retention_days: Some(7),
            },
            recovery: RecoveryRule::ExactSameKey,
            completion: "the destination holds the started draft",
            observable: true,
        };
        let text = serde_json::to_string(&descriptor).expect("serializes");
        assert!(text.contains("\"breg.proposal.start\""));
        // The descriptor's static names cannot borrow from a local
        // buffer, so the round trip is asserted value-wise.
        let round: serde_json::Value = serde_json::from_str(&text).expect("parses back");
        assert_eq!(
            round.pointer("/input_schema/contract"),
            Some(&serde_json::json!("action/household-register"))
        );
        assert_eq!(
            round.pointer("/idempotency/receipt_retention_days"),
            Some(&serde_json::json!(7))
        );
        assert_eq!(
            round.pointer("/recovery/kind"),
            Some(&serde_json::json!("exact-same-key"))
        );
    }

    #[test]
    fn a_send_outcome_displays_value_free() {
        let outcome = SendOutcome {
            category: OutcomeCategory::Refused,
            native_problem: Some("idempotency.key-reused".to_owned()),
            correlation: None,
            note: None,
        };
        assert_eq!(outcome.to_string(), "refused (idempotency.key-reused)");
    }
}
