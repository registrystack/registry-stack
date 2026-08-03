//! Raw shape observation from a sample response.
//!
//! `observe` walks a sample JSON document against a selection of extended
//! projection pointers (the same syntax `flatten` produces and the runtime's
//! `request.projection` accepts: RFC 6901 segments with `~0`/`~1` escapes and
//! the reserved segment `*` visiting every array element) and records what
//! shape each selected leaf had: integer extremes, maximum string byte
//! length, maximum array length, and whether an explicit null was seen. This
//! is bookkeeping only; no widening policy and no subset validation happen
//! here. That is the narrow stage's job, using these observations as one
//! input among several (spec bounds and formats outrank a sample).
//!
//! Privacy invariant: no function in this module stores, logs, or returns a
//! sample string *value*. Only its byte length crosses into an `Observed`.
//! The same holds for every other JSON value: only lengths, integer
//! extremes, array lengths, and a null flag are retained.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use super::types::{Observations, Observed};

/// Sample files larger than this are rejected outright: a sample is read
/// only to suggest bounds, never to carry bulk data through this tool.
const MAX_SAMPLE_BYTES: u64 = 4 * 1024 * 1024;

/// Read and parse a sample response document from `path`.
///
/// Rejects files over [`MAX_SAMPLE_BYTES`] with a clear message before
/// reading their contents, and rejects a file that is not valid JSON. The
/// parsed value is returned to the caller; this function does not log or
/// otherwise surface any of its contents.
pub fn load_sample(path: &Path) -> Result<Value> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to read sample file metadata at {}", path.display()))?;
    if metadata.len() > MAX_SAMPLE_BYTES {
        bail!(
            "sample file at {} is {} bytes, exceeding the {} byte limit",
            path.display(),
            metadata.len(),
            MAX_SAMPLE_BYTES
        );
    }
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read sample file at {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("sample file at {} is not valid JSON", path.display()))
}

/// Walk `sample` following each pointer in `selection`, recording raw shape
/// observations keyed by the pointer text exactly as given.
///
/// A pointer whose path is absent from the sample (a missing key, or a
/// wildcard segment landing on a non-array) is simply left unobserved: that
/// is not an error, since a sample need not exercise every selected leaf.
/// A pointer that is not a well-formed extended JSON Pointer (empty, or not
/// starting with `/`) is a caller error and returns `Err`.
///
/// Every array visited through a `*` segment is also recorded, keyed by the
/// array's own pointer (the selection prefix up to that segment), holding
/// the largest length seen across every occurrence of that array shape in
/// the sample. A selection pointer that itself resolves to an array (no
/// trailing `*`) is recorded the same way, keyed by the selection pointer.
pub fn observe(sample: &Value, selection: &[String]) -> Result<Observations> {
    let mut by_pointer: BTreeMap<String, Observed> = BTreeMap::new();
    for pointer in selection {
        observe_one(sample, pointer, &mut by_pointer)?;
    }
    Ok(Observations { by_pointer })
}

/// Parse one extended pointer and walk `root` with it, folding results into
/// `by_pointer`.
fn observe_one(
    root: &Value,
    pointer: &str,
    by_pointer: &mut BTreeMap<String, Observed>,
) -> Result<()> {
    if pointer.is_empty() || !pointer.starts_with('/') {
        bail!(
            "projection pointer {pointer:?} must be a non-empty extended JSON Pointer starting with \"/\""
        );
    }
    let tokens: Vec<&str> = pointer.split('/').skip(1).collect();
    walk(root, &tokens, String::new(), by_pointer);
    Ok(())
}

/// Follow `tokens` from `value`, tracking the pointer text already consumed
/// in `prefix` so recorded map keys are built from the same escaped text the
/// caller supplied rather than a re-derived (and possibly different)
/// rendering.
fn walk(
    value: &Value,
    tokens: &[&str],
    prefix: String,
    by_pointer: &mut BTreeMap<String, Observed>,
) {
    match tokens.split_first() {
        None => record(value, &prefix, by_pointer),
        Some((&"*", rest)) => {
            if let Value::Array(items) = value {
                // `prefix` here is the pointer to the array itself: the
                // selection text consumed so far, before this `*` segment.
                record(value, &prefix, by_pointer);
                let element_prefix = format!("{prefix}/*");
                for item in items {
                    walk(item, rest, element_prefix.clone(), by_pointer);
                }
            }
            // A non-array at a `*` segment is an unobserved mismatch, not
            // an error: schema/sample disagreement is validated elsewhere.
        }
        Some((token, rest)) => {
            if let Value::Object(members) = value {
                let key = unescape_segment(token);
                if let Some(child) = members.get(&key) {
                    let child_prefix = format!("{prefix}/{token}");
                    walk(child, rest, child_prefix, by_pointer);
                }
            }
            // A missing key or non-object here is likewise left unobserved.
        }
    }
}

/// Fold one visited JSON value into the observation entry at `pointer`,
/// widening extremes but never retaining the value itself.
fn record(value: &Value, pointer: &str, by_pointer: &mut BTreeMap<String, Observed>) {
    let entry = by_pointer.entry(pointer.to_owned()).or_default();
    match value {
        Value::Null => entry.saw_null = true,
        Value::Bool(_) | Value::Object(_) => {}
        Value::Number(number) => {
            if let Some(seen) = number.as_i64() {
                entry.min_integer =
                    Some(entry.min_integer.map_or(seen, |current| current.min(seen)));
                entry.max_integer =
                    Some(entry.max_integer.map_or(seen, |current| current.max(seen)));
            }
        }
        Value::String(text) => {
            let bytes = text.len() as u64;
            entry.max_string_bytes = Some(
                entry
                    .max_string_bytes
                    .map_or(bytes, |current| current.max(bytes)),
            );
        }
        Value::Array(items) => {
            let count = items.len() as u64;
            entry.max_array_items = Some(
                entry
                    .max_array_items
                    .map_or(count, |current| current.max(count)),
            );
        }
    }
}

/// Decode one RFC 6901 pointer segment: `~1` to `/`, then `~0` to `~`, in
/// that order, so a literal `~1` in a key (encoded `~01`) round-trips.
fn unescape_segment(raw: &str) -> String {
    if raw.contains('~') {
        raw.replace("~1", "/").replace("~0", "~")
    } else {
        raw.to_owned()
    }
}
