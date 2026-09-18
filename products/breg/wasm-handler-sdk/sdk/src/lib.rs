// SPDX-License-Identifier: Apache-2.0
//! The BREG WASM handler SDK: author a Base Registry Engine action handler as
//! one plain Rust function over typed request and outcome values, with no
//! pointer code and no byte handling of your own.
//!
//! The crate supplies everything the platform executor's guest byte ABI
//! needs. A handler module exports exactly `alloc`, `handle`, `result_ptr`,
//! `result_len` (and, for build-time pre-initialization, `init`), imports
//! nothing, and speaks one request envelope and one outcome document. The
//! [`handler!`] and [`handler_with_init!`] macros generate those exports from
//! your function; everything they generate lives in this crate.
//!
//! # The request
//!
//! The platform sends exactly the `{"inputs": {...}}` JSON document as bytes.
//! [`Request`] decodes it: inputs keyed by authored input id, values kept
//! exactly as the registry admitted them. Integers stay exact i64, decimals
//! stay strings, a reference envelope stays a JSON object, and an absent key
//! stays distinguishable from an explicit `null` ([`Request::input`] returns
//! `None` for the first and `Some(Value::Null)` for the second).
//!
//! # The outcome
//!
//! Your function returns [`Outcome`]: either effects against the handler's
//! declared write slots, or one declared refusal built with [`Refusal`].
//! The SDK serializes it to exactly one JSON document in the shape the BREG
//! shared outcome validator accepts: `{"effects": [...]}` or
//! `{"refusal": {"code": ..., "field": ...}}`, never both, no other members.
//!
//! # The handler function
//!
//! A handler module invokes [`handler!`] (or [`handler_with_init!`]) once, at
//! its crate root. The example wraps the same shape in a module because a
//! doctest body is a function:
//!
//! ```
//! mod phone_handler {
//!     use breg_wasm_sdk::{Effect, HandlerFailure, Outcome, Refusal, Request};
//!
//!     fn handle(request: Request) -> Result<Outcome, HandlerFailure> {
//!         let raw = request
//!             .input_str("raw-phone")
//!             .ok_or(HandlerFailure::MalformedRequest)?;
//!         if raw.is_empty() {
//!             return Ok(Outcome::refusal(
//!                 Refusal::new("invalid-phone").field("raw-phone"),
//!             ));
//!         }
//!         Ok(Outcome::effects(vec![Effect::new("phone").set("phone", "+22222123456")]))
//!     }
//!
//!     breg_wasm_sdk::handler!(handle);
//! }
//! # fn main() {}
//! ```
//!
//! One handler per module: the macros define the module's ABI exports once,
//! so a second invocation in one crate is a compile error (the production
//! shape is one handler per module, matching how the registry packages one
//! module path per action handler).
//!
//! # What the SDK guarantees
//!
//! - Exact values: numbers serialize as integers when they are integers, so
//!   i64 values beyond f64 precision survive the round trip; decimal strings
//!   and reference envelopes pass through untouched.
//! - No pointer code: `alloc`, `handle`, and the result window are generated
//!   for you, and a panic in your handler never crosses the boundary
//!   uncaught.
//! - Zero imports: the generated module imports nothing (std only, no WASI),
//!   which is what module admission requires.
//!
//! # What is out of scope
//!
//! Handler ABI v2 (Evidence resolvers) and change-request planners are not
//! authorable as WASM in this release; the SDK targets input-only v1 action
//! handlers only.

// The ABI module is public for the export macros (`$crate::abi::...`
// expands in the handler crate) and hidden from the docs: handler authors
// never call it directly.
#[doc(hidden)]
pub mod abi;
#[macro_use]
mod macros;
mod outcome;
mod request;

pub use outcome::{Effect, Outcome, Refusal};
pub use request::Request;
pub use serde_json::{Map, Value};

/// Why a handler could not produce an outcome.
///
/// Neither kind is a business decision: the platform reports both as a
/// handler fault with a static message. A business refusal is an [`Outcome`],
/// built with [`Refusal`] and a code from the handler's declared refusal
/// catalogue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandlerFailure {
    /// The request bytes violated the input contract the registry already
    /// admitted (absent required input, wrong value kind, or a malformed
    /// envelope). Reported as `guest rejected the request as malformed`.
    MalformedRequest,
    /// The handler failed for a reason unrelated to the request. Reported as
    /// `guest reported an internal error`.
    InternalError,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::{Value, json};

    use super::{Effect, HandlerFailure, Outcome, Refusal, Request};

    /// The result window and allocator are crate-global statics, so the tests
    /// that drive the byte ABI take turns.
    static ABI_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn i64_values_beyond_f64_precision_round_trip_exactly() {
        for exact in [
            9223372036854775807i64,
            -9223372036854775808i64,
            9007199254740993i64,
        ] {
            let outcome = Outcome::effects(vec![Effect::new("record").set("count", exact)]);
            let document = outcome.to_document();
            let parsed: Value = serde_json::from_slice(&document).unwrap();
            assert_eq!(
                parsed["effects"][0]["set"]["count"].as_i64(),
                Some(exact),
                "the integer changed in the document"
            );
            // The serialized number carries no fraction or exponent: it never
            // passed through a float.
            let text = String::from_utf8(document).unwrap();
            assert!(text.contains(&exact.to_string()));
            assert!(!text.contains(&format!("{exact}.0")));
        }
    }

    #[test]
    fn decimal_strings_stay_strings() {
        let outcome = Outcome::effects(vec![
            Effect::new("record").set("amount", "123456789012345678.90"),
        ]);
        assert_eq!(
            serde_json::to_value(&outcome).unwrap(),
            json!({"effects": [{"id": "record", "set": {"amount": "123456789012345678.90"}}]})
        );
    }

    #[test]
    fn reference_envelopes_pass_through_as_objects() {
        let envelope = json!({"fromField": "person"});
        let outcome = Outcome::effects(vec![
            Effect::new("person")
                .set("friend", envelope.clone())
                .set("friend2", json!({"fromEffect": "other"})),
        ]);
        let document: Value = serde_json::from_slice(&outcome.to_document()).unwrap();
        assert_eq!(document["effects"][0]["set"]["friend"], envelope);
        assert_eq!(
            document["effects"][0]["set"]["friend2"],
            json!({"fromEffect": "other"})
        );
    }

    #[test]
    fn absent_and_null_inputs_stay_distinct() {
        let request = Request::from_envelope(br#"{"inputs": {"present": null}}"#).unwrap();
        assert_eq!(request.input("present"), Some(&Value::Null));
        assert_eq!(request.input("absent"), None);
        // The convenience reader collapses both, like the Rhai guard idiom.
        assert_eq!(request.input_str("present"), None);
        assert_eq!(request.input_str("absent"), None);
    }

    #[test]
    fn the_envelope_is_exactly_the_inputs_document() {
        assert!(Request::from_envelope(br#"{"inputs": {}}"#).is_ok());
        for malformed in [
            &b""[..],
            b"{",
            b"\xff\xfe",
            br#"{"inputs": 7}"#,
            br#"{"inputs": {}, "extra": 1}"#,
            br#"{"context": {}}"#,
        ] {
            assert_eq!(
                Request::from_envelope(malformed),
                Err(HandlerFailure::MalformedRequest),
                "{malformed:?} must be a malformed request"
            );
        }
    }

    #[test]
    fn the_refusal_document_matches_the_shared_validator_shape() {
        let with_field = Outcome::refusal(Refusal::new("invalid-phone").field("raw-phone"));
        let document: Value = serde_json::from_slice(&with_field.to_document()).unwrap();
        assert_eq!(
            document,
            json!({"refusal": {"code": "invalid-phone", "field": "raw-phone"}})
        );
        // Exactly the two members the validator allows, nothing else.
        let members: Vec<&str> = document["refusal"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(members, ["code", "field"]);

        let without_field = Outcome::refusal(Refusal::new("blank-name"));
        let document: Value = serde_json::from_slice(&without_field.to_document()).unwrap();
        assert_eq!(document, json!({"refusal": {"code": "blank-name"}}));
        let members: Vec<&str> = document["refusal"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(members, ["code"]);
    }

    #[test]
    fn effect_documents_carry_only_id_set_and_clear() {
        let set_only = Outcome::effects(vec![Effect::new("phone").set("phone", "+33612345678")]);
        assert_eq!(
            serde_json::to_value(&set_only).unwrap(),
            json!({"effects": [{"id": "phone", "set": {"phone": "+33612345678"}}]})
        );
        let clear_only = Outcome::effects(vec![Effect::new("existing").clear("nickname")]);
        assert_eq!(
            serde_json::to_value(&clear_only).unwrap(),
            json!({"effects": [{"id": "existing", "clear": ["nickname"]}]})
        );
        let both = Outcome::effects(vec![
            Effect::new("existing")
                .set("name", "Mina")
                .clear("nickname"),
        ]);
        assert_eq!(
            serde_json::to_value(&both).unwrap(),
            json!({"effects": [{"id": "existing", "set": {"name": "Mina"}, "clear": ["nickname"]}]})
        );
    }

    #[test]
    fn the_outcome_document_is_exactly_one_json_document() {
        let outcome = Outcome::refusal(Refusal::new("invalid-phone").field("raw-phone"));
        let document = outcome.to_document();
        // A second document, or any trailing bytes, fail the parse.
        assert!(serde_json::from_slice::<Value>(&document).is_ok());
        let mut padded = document.clone();
        padded.extend_from_slice(b" {}");
        assert!(serde_json::from_slice::<Value>(&padded).is_err());
    }

    /// Drive the generated byte ABI on the host: allocate, copy the envelope
    /// in, call `handle`, read the result window back.
    fn run_through_abi(
        handler: fn(Request) -> Result<Outcome, HandlerFailure>,
        envelope: &[u8],
    ) -> (i32, Option<Vec<u8>>) {
        let _guard = ABI_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let pointer = super::abi::alloc(envelope.len());
        assert!(!pointer.is_null(), "host allocation succeeds");
        let buffer = unsafe { std::slice::from_raw_parts_mut(pointer, envelope.len()) };
        buffer.copy_from_slice(envelope);
        let status = super::abi::handle(pointer as *const u8, envelope.len(), handler);
        if status != 0 {
            return (status, None);
        }
        let len = super::abi::result_len();
        let pointer = super::abi::result_ptr() as *const u8;
        let bytes = unsafe { std::slice::from_raw_parts(pointer, len) }.to_vec();
        (status, Some(bytes))
    }

    fn echo_handler(request: Request) -> Result<Outcome, HandlerFailure> {
        let value = request
            .input("count")
            .cloned()
            .ok_or(HandlerFailure::MalformedRequest)?;
        Ok(Outcome::effects(vec![
            Effect::new("record").set("count", value),
        ]))
    }

    #[test]
    fn the_byte_abi_returns_the_outcome_document_on_the_host() {
        let envelope = br#"{"inputs": {"count": 9223372036854775807}}"#;
        let (status, document) = run_through_abi(echo_handler, envelope);
        assert_eq!(status, 0);
        let parsed: Value = serde_json::from_slice(&document.unwrap()).unwrap();
        assert_eq!(
            parsed,
            json!({"effects": [{"id": "record", "set": {"count": 9223372036854775807i64}}]})
        );
    }

    #[test]
    fn the_byte_abi_reports_status_one_for_malformed_requests() {
        let handler = |request: Request| -> Result<Outcome, HandlerFailure> {
            let _ = request;
            Ok(Outcome::effects(vec![
                Effect::new("record").set("count", 1),
            ]))
        };
        let (status, document) = run_through_abi(handler, b"{not json");
        assert_eq!(status, 1);
        assert!(document.is_none());
        // A failed handle clears the window: no stale outcome is readable.
        assert_eq!(super::abi::result_len(), 0);
    }

    #[test]
    fn the_byte_abi_reports_status_two_for_internal_failures() {
        let handler =
            |_: Request| -> Result<Outcome, HandlerFailure> { Err(HandlerFailure::InternalError) };
        let (status, document) = run_through_abi(handler, br#"{"inputs": {}}"#);
        assert_eq!(status, 2);
        assert!(document.is_none());
    }
}
