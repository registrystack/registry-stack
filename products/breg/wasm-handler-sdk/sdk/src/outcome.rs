//! The typed outcome tree: exactly the documents the BREG shared outcome
//! validator accepts.

use serde::Serialize;
use serde_json::{Map, Value};

/// A handler outcome: effects against declared write slots, or one declared
/// refusal. Never both; the serialized document carries exactly one arm.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum Outcome {
    /// `{"effects": [...]}`: one entry per emitted write slot.
    #[serde(rename = "effects")]
    Effects(Vec<Effect>),
    /// `{"refusal": {...}}`: one declared business refusal.
    #[serde(rename = "refusal")]
    Refusal(Refusal),
}

impl Outcome {
    /// An effects outcome. The shared validator requires at least one effect
    /// and at most the action's target bound; each effect names a declared
    /// write slot.
    pub fn effects(effects: Vec<Effect>) -> Self {
        Self::Effects(effects)
    }

    /// A declared refusal. The code must come from the handler's declared
    /// refusal catalogue, or the shared validator refuses the outcome.
    pub fn refusal(refusal: Refusal) -> Self {
        Self::Refusal(refusal)
    }

    /// Serialize to exactly one JSON document: the bytes the platform reads
    /// back from the result window. Infallible by construction: the tree
    /// holds strings, integers, booleans, and passthrough JSON values, and
    /// none of those can fail to serialize.
    pub fn to_document(&self) -> Vec<u8> {
        serde_json::to_vec(self)
            .expect("an outcome serializes: strings, integers, and passthrough JSON only")
    }
}

/// One write against a declared slot: `{"id": ..., "set": {...}}` with
/// optionally `"clear": [...]`. The declared slot fixes the target and the
/// operation; the effect only names the slot id and its mutations.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Effect {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    set: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    clear: Option<Vec<String>>,
}

impl Effect {
    /// An effect against the declared write slot `id`. At least one `set` or
    /// `clear` mutation must follow, or the shared validator refuses the
    /// effect.
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            set: None,
            clear: None,
        }
    }

    /// Set one declared field of the slot to a value. Values keep their exact
    /// kinds: integers stay integers, decimals stay strings, and reference
    /// fields take reference envelopes (JSON objects). A null value is
    /// refused by the shared validator; use `clear` on an optional patch
    /// field instead.
    pub fn set(mut self, field: &str, value: impl Into<Value>) -> Self {
        let set = self.set.get_or_insert_with(Map::new);
        set.insert(field.to_owned(), value.into());
        self
    }

    /// Clear one declared optional patch field. Create slots cannot clear.
    pub fn clear(mut self, field: &str) -> Self {
        self.clear
            .get_or_insert_with(Vec::new)
            .push(field.to_owned());
        self
    }
}

/// A declared business refusal: `{"code": ..., "field": ...}`.
///
/// The document shape is exactly what the BREG shared validator accepts: a
/// required string `code` from the handler's declared refusal catalogue and
/// an optional string `field` naming a declared input id. Any other member
/// is refused, so the builder cannot construct a document the validator
/// would reject on shape.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Refusal {
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
}

impl Refusal {
    /// A refusal with a code from the handler's declared refusal catalogue.
    pub fn new(code: &str) -> Self {
        Self {
            code: code.to_owned(),
            field: None,
        }
    }

    /// Name the declared input id the refusal is about; omit it for a
    /// refusal that is not about one input.
    pub fn field(mut self, field: &str) -> Self {
        self.field = Some(field.to_owned());
        self
    }
}
