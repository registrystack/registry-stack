//! The typed request envelope: exactly the `{"inputs": {...}}` JSON document
//! the platform executor sends as request bytes.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::HandlerFailure;

/// A handler request: the action's inputs keyed by authored input id.
///
/// Decoding keeps every value exactly as the registry admitted it. Integers
/// stay exact i64 (never rounded through a float), decimal values stay the
/// canonical strings the registry admits, reference envelopes stay JSON
/// objects, and an absent input stays distinguishable from an explicit
/// `null`: [`Request::input`] returns `None` for the first and
/// `Some(Value::Null)` for the second.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Request {
    inputs: Map<String, Value>,
}

/// The envelope is exactly one member: `inputs`. Anything else in the request
/// bytes is a drift from the platform contract and is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    inputs: Map<String, Value>,
}

impl Request {
    /// Decode a request from the platform's envelope bytes. Bad UTF-8, bad
    /// JSON, or a document that is not exactly the inputs envelope decodes as
    /// [`HandlerFailure::MalformedRequest`]; the caller maps that to the
    /// malformed-request status.
    pub fn from_envelope(bytes: &[u8]) -> Result<Self, HandlerFailure> {
        let text = std::str::from_utf8(bytes).map_err(|_| HandlerFailure::MalformedRequest)?;
        let envelope: Envelope =
            serde_json::from_str(text).map_err(|_| HandlerFailure::MalformedRequest)?;
        Ok(Self {
            inputs: envelope.inputs,
        })
    }

    /// Build a request directly from an inputs map (host-side callers and
    /// tests).
    pub fn from_inputs(inputs: Map<String, Value>) -> Self {
        Self { inputs }
    }

    /// The action's inputs, keyed by authored input id.
    pub fn inputs(&self) -> &Map<String, Value> {
        &self.inputs
    }

    /// One input's value with full fidelity: `None` when the input is
    /// absent, `Some(Value::Null)` when it is present and explicitly null.
    pub fn input(&self, id: &str) -> Option<&Value> {
        self.inputs.get(id)
    }

    /// A present, non-null string input. Returns `None` when the input is
    /// absent, null, or not a string; use [`Request::input`] when those
    /// cases must be told apart.
    pub fn input_str(&self, id: &str) -> Option<&str> {
        self.input(id).and_then(Value::as_str)
    }
}
