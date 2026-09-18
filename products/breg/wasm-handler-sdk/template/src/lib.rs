// SPDX-License-Identifier: Apache-2.0
//! The reference BREG WASM action handler: phone normalization.
//!
//! Copy this crate to start a handler module of your own. The pieces:
//!
//! 1. `normalize_phone_values`: the decision core, a pure function. Write
//!    your business logic here; host unit tests call it directly.
//! 2. `normalize_phone`: the input adapter, reading the action's declared
//!    inputs from the request envelope. Keep the exactness discipline shown
//!    here: read through [`breg_wasm_sdk::Request`] and never serialize
//!    numbers through floats.
//! 3. `handle_normalize_phone`: the one-argument dispatch entry the byte ABI
//!    calls, plus `warm`, the build-time pre-initialization hook.
//! 4. The [`breg_wasm_sdk::handler_with_init!`] invocation at the bottom:
//!    the only line that touches the module ABI. Use plain
//!    [`breg_wasm_sdk::handler!`] when your handler has no lazily
//!    initialized statics to warm.
//!
//! The authored project this module belongs to declares the same ids used
//! here: inputs `raw-phone` and `default-region`, write slot `phone` with
//! field `phone`, and the refusal catalogue `invalid-phone` and
//! `invalid-region` (see `fixtures/normalize-phone-cases.json` for the
//! outcome corpus and `admission/` for the compiled-project proof).

use std::str::FromStr;

use breg_wasm_sdk::{Effect, HandlerFailure, Outcome, Refusal, Request, Value};

/// The action's declared input ids, matching the authored project.
pub const INPUT_RAW_PHONE: &str = "raw-phone";
pub const INPUT_DEFAULT_REGION: &str = "default-region";

/// The single declared write slot and the field it writes, matching the
/// authored project.
pub const PHONE_SLOT: &str = "phone";
pub const PHONE_FIELD: &str = "phone";

/// The handler's declared refusal codes, matching the authored project's
/// refusal catalogue.
pub const REFUSAL_INVALID_PHONE: &str = "invalid-phone";
pub const REFUSAL_INVALID_REGION: &str = "invalid-region";

/// The handler entry: read the declared inputs, normalize, return one
/// outcome. A business rejection is a declared refusal; a violated input
/// contract is a malformed request (the registry admits input types before
/// the handler runs, so that path is defense, not business logic).
pub fn normalize_phone(request: &Request) -> Result<Outcome, HandlerFailure> {
    let raw_phone = required_string(request, INPUT_RAW_PHONE)?;
    let default_region = required_string(request, INPUT_DEFAULT_REGION)?;
    Ok(normalize_phone_values(raw_phone, default_region))
}

/// The decision core: normalize `raw_phone` against `default_region` to an
/// E.164 string and write it to the declared phone field.
///
/// An unusable region string refuses `invalid-region`; anything that fails
/// parsing or validity refuses `invalid-phone`. Both refusals name the
/// offending input as their field.
pub fn normalize_phone_values(raw_phone: &str, default_region: &str) -> Outcome {
    let Ok(country) = phonenumber::country::Id::from_str(default_region) else {
        return Outcome::refusal(Refusal::new(REFUSAL_INVALID_REGION).field(INPUT_DEFAULT_REGION));
    };
    let Ok(number) = phonenumber::parse(Some(country), raw_phone) else {
        return Outcome::refusal(Refusal::new(REFUSAL_INVALID_PHONE).field(INPUT_RAW_PHONE));
    };
    if !phonenumber::is_valid(&number) {
        return Outcome::refusal(Refusal::new(REFUSAL_INVALID_PHONE).field(INPUT_RAW_PHONE));
    }
    let e164 = phonenumber::format(&number)
        .mode(phonenumber::Mode::E164)
        .to_string();
    Outcome::effects(vec![Effect::new(PHONE_SLOT).set(PHONE_FIELD, e164)])
}

/// A declared required input: present, non-null, string. Anything else
/// violates the input contract the registry already admitted, so it is a
/// malformed request, never a business refusal.
fn required_string<'a>(request: &'a Request, id: &str) -> Result<&'a str, HandlerFailure> {
    match request.input(id) {
        Some(Value::String(text)) => Ok(text),
        _ => Err(HandlerFailure::MalformedRequest),
    }
}

/// The dispatch entry the byte ABI calls.
fn handle_normalize_phone(request: Request) -> Result<Outcome, HandlerFailure> {
    normalize_phone(&request)
}

/// Build-time pre-initialization warm-up: run one normalize-phone per region
/// so the phonenumber metadata and the MR/FR regular-expression statics are
/// initialized when the pre-initializer snapshots the module's memory. The
/// outcomes are discarded; only the warmed statics matter.
pub fn warm() {
    let _ = normalize_phone_values("22 12 34 56", "MR");
    let _ = normalize_phone_values("06 12 34 56 78", "FR");
}

breg_wasm_sdk::handler_with_init!(handle_normalize_phone, warm);
