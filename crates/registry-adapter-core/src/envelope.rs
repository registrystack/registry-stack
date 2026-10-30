// SPDX-License-Identifier: Apache-2.0

//! The envelope template reader: one parse of a profile envelope text into
//! JSON, shared by the result-schema derivation, the checks, and the
//! runtime renderer so the three read a template the same way
//! (`products/adapter/CONCEPT.md` section 7).

use crate::checks::is_placeholder_name;
use serde_json::Value;

/// The sentinel opening (and closing) one slot in a parsed envelope
/// template. A control character real template text cannot carry opens
/// it, so no literal envelope string can decode as a slot.
pub const SLOT_MARK: char = '\u{1}';

/// The envelope grammar: a placeholder fills a whole member value or a
/// whole string member, never a part of a string; inside a longer string
/// it would never bind, so the derivation refuses.
pub const ENVELOPE_GRAMMAR_RULE: &str =
    "an envelope placeholder fills a whole member value or a whole string member, never a part of a string";

/// Parses an envelope template text into JSON: every `{{slot}}` or
/// `{{?slot}}` placeholder, whether it fills a quoted string member or a
/// whole JSON value, becomes one quoted sentinel string the walk decodes.
/// The scan follows JSON string syntax, so an escaped quote or backslash
/// inside a literal never changes which text is inside a string.
///
/// # Errors
///
/// Returns a value-free message when a placeholder is unterminated, sits
/// inside a longer string, or the text is not a JSON template.
pub fn parse_envelope_template(text: &str) -> Result<Value, String> {
    let bytes = text.as_bytes();
    let mut parsed: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut in_string = false;
    let mut string_start = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string && byte == b'\\' {
            parsed.push(byte);
            if let Some(next) = bytes.get(index + 1) {
                parsed.push(*next);
            }
            index += 2;
            continue;
        }
        if byte == b'"' {
            if !in_string {
                string_start = index;
            }
            in_string = !in_string;
            parsed.push(byte);
            index += 1;
            continue;
        }
        if byte == b'{' && bytes.get(index + 1) == Some(&b'{') {
            let Some(close) = text[index..].find("}}") else {
                return Err(
                    "the response envelope template carries an unterminated placeholder"
                        .to_string(),
                );
            };
            let inner = &text[index + 2..index + close];
            let (name, optional) = match inner.strip_prefix('?') {
                Some(stripped) => (stripped, true),
                None => (inner, false),
            };
            if is_placeholder_name(name) {
                let end = index + close + 2;
                if in_string {
                    // A quoted placeholder `"{{slot}}"` fills the whole
                    // string member; any other placement inside a string
                    // never binds.
                    let whole = string_start + 1 == index && bytes.get(end) == Some(&b'"');
                    if !whole {
                        return Err(ENVELOPE_GRAMMAR_RULE.to_string());
                    }
                    parsed.pop();
                    push_sentinel(&mut parsed, name, optional);
                    in_string = false;
                    index = end + 1;
                } else {
                    push_sentinel(&mut parsed, name, optional);
                    index = end;
                }
                continue;
            }
        }
        parsed.push(byte);
        index += 1;
    }
    let parsed = String::from_utf8(parsed)
        .map_err(|_| "the response envelope template is not valid text".to_string())?;
    serde_json::from_str(&parsed)
        .map_err(|error| format!("the response envelope template is not a JSON template: {error}"))
}

fn push_sentinel(parsed: &mut Vec<u8>, name: &str, optional: bool) {
    parsed.extend_from_slice(b"\"\\u0001");
    parsed.extend_from_slice(if optional { b"opt:" } else { b"req:" });
    parsed.extend_from_slice(name.as_bytes());
    parsed.extend_from_slice(b"\\u0001\"");
}

/// Decodes one sentinel string back to `(slot name, optional)`.
#[must_use]
pub fn decode_slot(text: &str) -> Option<(&str, bool)> {
    text.strip_prefix(SLOT_MARK)
        .and_then(|rest| rest.strip_suffix(SLOT_MARK))
        .map(|inner| match inner.strip_prefix("opt:") {
            Some(name) => (name, true),
            None => (inner.strip_prefix("req:").unwrap_or(inner), false),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_literal_with_an_escaped_quote_does_not_flip_the_string_state() {
        let parsed =
            parse_envelope_template(r#"{"label": "say \"hi\"", "data": {{record}}}"#).unwrap();
        assert_eq!(parsed["label"], json!("say \"hi\""));
        assert_eq!(
            decode_slot(parsed["data"].as_str().unwrap()),
            Some(("record", false))
        );
    }

    #[test]
    fn a_literal_ending_in_a_backslash_is_not_an_escape_of_its_closing_quote() {
        let parsed = parse_envelope_template(r#"{"path": "a\\", "data": "{{record}}"}"#).unwrap();
        assert_eq!(parsed["path"], json!("a\\"));
        assert_eq!(
            decode_slot(parsed["data"].as_str().unwrap()),
            Some(("record", false))
        );
    }

    #[test]
    fn a_placeholder_inside_a_longer_string_is_refused() {
        let refusal = parse_envelope_template(r#"{"a": "x {{record}} y"}"#).unwrap_err();
        assert_eq!(refusal, ENVELOPE_GRAMMAR_RULE);
    }
}
