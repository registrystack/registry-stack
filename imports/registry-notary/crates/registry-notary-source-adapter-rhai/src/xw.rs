// SPDX-License-Identifier: Apache-2.0
//! The `xw` helper namespace exposed to scripts with dotted syntax.
//!
//! Scripts call pure crosswalk helpers as `xw.text.slug(s)`,
//! `xw.date.add_days(d, 3)`, `xw.ids.clean_id(x)`, etc. To get this dotted
//! syntax in Rhai (where `a.b(args)` desugars to `b(a, args)`), each namespace
//! is a zero-sized marker type:
//!
//! * `xw` resolves to an [`XwNs`] constant in scope;
//! * `xw.text` is a property getter returning [`XwTextNs`];
//! * `xw.text.slug(s)` desugars to `slug(XwTextNs, s)`, a registered function.
//!
//! Only the deterministic, side-effect-free helpers below are registered.
//! Helpers that are intentionally *not* exposed (regex, code tables,
//! `date::today`, `parse_datetime`, phone, ...) are not registered, so a script
//! that references one fails: the unknown method resolves to nothing and the
//! execution is rejected with a function-not-found runtime error.
//!
//! Each fallible helper maps its `FunctionError` to a Rhai runtime error
//! carrying only the helper's stable code and message.

use rhai::{Dynamic, Engine, EvalAltResult, ImmutableString, Position, Scope};
use serde_json::Value;

use crosswalk_functions::{date, email, ids, json as cwjson, redaction, text, FunctionError};

/// Root namespace marker: the `xw` value in scope.
#[derive(Debug, Clone, Copy)]
pub struct XwNs;
/// `xw.text` namespace marker.
#[derive(Debug, Clone, Copy)]
pub struct XwTextNs;
/// `xw.date` namespace marker.
#[derive(Debug, Clone, Copy)]
pub struct XwDateNs;
/// `xw.ids` namespace marker.
#[derive(Debug, Clone, Copy)]
pub struct XwIdsNs;
/// `xw.json` namespace marker.
#[derive(Debug, Clone, Copy)]
pub struct XwJsonNs;
/// `xw.email` namespace marker.
#[derive(Debug, Clone, Copy)]
pub struct XwEmailNs;
/// `xw.redaction` namespace marker.
#[derive(Debug, Clone, Copy)]
pub struct XwRedactionNs;

/// Convert a crosswalk [`FunctionError`] into a Rhai error.
fn to_rhai_err(err: FunctionError) -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorRuntime(
        Dynamic::from(format!("{}: {}", err.code, err.message)),
        Position::NONE,
    ))
}

/// Push the `xw` namespace constant into a script scope.
pub fn push_into_scope(scope: &mut Scope) {
    scope.push_constant("xw", XwNs);
}

/// Register the `xw` type tree and all pure helper functions on `engine`.
pub fn register(engine: &mut Engine) {
    register_types(engine);
    register_navigation(engine);
    register_text(engine);
    register_date(engine);
    register_ids(engine);
    register_json(engine);
    register_email(engine);
    register_redaction(engine);
}

fn register_types(engine: &mut Engine) {
    engine.register_type_with_name::<XwNs>("XwNs");
    engine.register_type_with_name::<XwTextNs>("XwTextNs");
    engine.register_type_with_name::<XwDateNs>("XwDateNs");
    engine.register_type_with_name::<XwIdsNs>("XwIdsNs");
    engine.register_type_with_name::<XwJsonNs>("XwJsonNs");
    engine.register_type_with_name::<XwEmailNs>("XwEmailNs");
    engine.register_type_with_name::<XwRedactionNs>("XwRedactionNs");
}

/// Property getters turning `xw.<ns>` into the right marker.
fn register_navigation(engine: &mut Engine) {
    engine.register_get("text", |_: &mut XwNs| XwTextNs);
    engine.register_get("date", |_: &mut XwNs| XwDateNs);
    engine.register_get("ids", |_: &mut XwNs| XwIdsNs);
    engine.register_get("json", |_: &mut XwNs| XwJsonNs);
    engine.register_get("email", |_: &mut XwNs| XwEmailNs);
    engine.register_get("redaction", |_: &mut XwNs| XwRedactionNs);
}

fn register_text(engine: &mut Engine) {
    engine.register_fn("trim", |_: XwTextNs, s: ImmutableString| text::trim(&s));
    engine.register_fn("lower_ascii", |_: XwTextNs, s: ImmutableString| {
        text::lower_ascii(&s)
    });
    engine.register_fn("upper_ascii", |_: XwTextNs, s: ImmutableString| {
        text::upper_ascii(&s)
    });
    engine.register_fn("title_simple", |_: XwTextNs, s: ImmutableString| {
        text::title_simple(&s)
    });
    engine.register_fn("normalize_space", |_: XwTextNs, s: ImmutableString| {
        text::normalize_space(&s)
    });
    engine.register_fn("remove_accents", |_: XwTextNs, s: ImmutableString| {
        text::remove_accents(&s)
    });
    engine.register_fn("slug", |_: XwTextNs, s: ImmutableString| text::slug(&s));
}

fn register_date(engine: &mut Engine) {
    engine.register_fn("parse_date", |_: XwDateNs, s: ImmutableString| {
        date::parse_date(&s, None).map_err(to_rhai_err)
    });
    engine.register_fn(
        "parse_date",
        |_: XwDateNs, s: ImmutableString, pattern: ImmutableString| {
            date::parse_date(&s, Some(&pattern)).map_err(to_rhai_err)
        },
    );
    engine.register_fn(
        "format_date_or_datetime",
        |_: XwDateNs, s: ImmutableString, pattern: ImmutableString| {
            date::format_date_or_datetime(&s, &pattern).map_err(to_rhai_err)
        },
    );
    engine.register_fn(
        "age_on",
        |_: XwDateNs, birth: ImmutableString, reference: ImmutableString| {
            date::age_on(&birth, &reference).map_err(to_rhai_err)
        },
    );
    engine.register_fn(
        "years_between",
        |_: XwDateNs, start: ImmutableString, end: ImmutableString| {
            date::years_between(&start, &end).map_err(to_rhai_err)
        },
    );
    engine.register_fn(
        "days_between",
        |_: XwDateNs, start: ImmutableString, end: ImmutableString| {
            date::days_between(&start, &end).map_err(to_rhai_err)
        },
    );
    engine.register_fn("add_days", |_: XwDateNs, s: ImmutableString, days: i64| {
        date::add_days(&s, days).map_err(to_rhai_err)
    });
    engine.register_fn(
        "add_months",
        |_: XwDateNs, s: ImmutableString, months: i64| {
            date::add_months(&s, months).map_err(to_rhai_err)
        },
    );
    engine.register_fn("start_of_month", |_: XwDateNs, s: ImmutableString| {
        date::start_of_month(&s).map_err(to_rhai_err)
    });
    engine.register_fn("end_of_month", |_: XwDateNs, s: ImmutableString| {
        date::end_of_month(&s).map_err(to_rhai_err)
    });
    engine.register_fn(
        "min_date",
        |_: XwDateNs, a: ImmutableString, b: ImmutableString| {
            date::min_date(&a, &b).map_err(to_rhai_err)
        },
    );
    engine.register_fn(
        "max_date",
        |_: XwDateNs, a: ImmutableString, b: ImmutableString| {
            date::max_date(&a, &b).map_err(to_rhai_err)
        },
    );
}

fn register_ids(engine: &mut Engine) {
    engine.register_fn("stable_hash_sha256", |_: XwIdsNs, s: ImmutableString| {
        ids::stable_hash_sha256(&s, None)
    });
    engine.register_fn(
        "stable_hash_sha256",
        |_: XwIdsNs, s: ImmutableString, salt: ImmutableString| {
            ids::stable_hash_sha256(&s, Some(&salt))
        },
    );
    engine.register_fn(
        "prefixed_slug",
        |_: XwIdsNs, prefix: ImmutableString, s: ImmutableString| ids::prefixed_slug(&prefix, &s),
    );
    engine.register_fn("clean_id", |_: XwIdsNs, s: ImmutableString| {
        ids::clean_id(&s)
    });
}

fn register_json(engine: &mut Engine) {
    engine.register_fn(
        "parse_json",
        |_: XwJsonNs, s: ImmutableString| -> Result<Dynamic, Box<EvalAltResult>> {
            let value: Value = cwjson::parse_json(&s).map_err(to_rhai_err)?;
            rhai::serde::to_dynamic(value).map_err(|e| {
                Box::new(EvalAltResult::ErrorRuntime(
                    Dynamic::from(format!("JSON_PARSE: {e}")),
                    Position::NONE,
                ))
            })
        },
    );
    engine.register_fn(
        "stringify_json",
        |_: XwJsonNs, value: Dynamic| -> Result<String, Box<EvalAltResult>> {
            let json: Value = serde_json::to_value(&value).map_err(|e| {
                Box::new(EvalAltResult::ErrorRuntime(
                    Dynamic::from(format!("JSON_STRINGIFY: {e}")),
                    Position::NONE,
                ))
            })?;
            cwjson::stringify_json(&json).map_err(to_rhai_err)
        },
    );
}

fn register_email(engine: &mut Engine) {
    engine.register_fn("normalize_email", |_: XwEmailNs, s: ImmutableString| {
        email::normalize_email(&s)
    });
    engine.register_fn(
        "email_domain",
        |_: XwEmailNs, s: ImmutableString| -> Dynamic {
            match email::email_domain(&s) {
                Some(d) => Dynamic::from(d),
                None => Dynamic::UNIT,
            }
        },
    );
    engine.register_fn("is_valid_email", |_: XwEmailNs, s: ImmutableString| {
        email::is_valid_email(&s)
    });
}

fn register_redaction(engine: &mut Engine) {
    engine.register_fn(
        "mask",
        |_: XwRedactionNs, s: ImmutableString, visible_last: i64| {
            redaction::mask(&s, visible_last.max(0) as usize)
        },
    );
    engine.register_fn("redact", |_: XwRedactionNs| redaction::redact());
}
