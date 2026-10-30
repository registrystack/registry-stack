// SPDX-License-Identifier: Apache-2.0

//! Strict, bounded JSON reading for token responses
//! (`products/adapter/CONCEPT.md` section 10.2).
//!
//! Token responses are read as Evidence reads them: the document must be
//! one JSON object, duplicate members are refused, and unknown members are
//! ignored after their values are validated as JSON. This reader is
//! adapter-local over no JSON dependency: it accepts exactly the grammar
//! RFC 8259 defines, bounds the document before parsing, bounds nesting,
//! and hands back only the members a caller names. It never allocates for
//! a member it skips, and a skipped value's bytes are never copied into
//! an error, a diagnostic, or a `Debug` rendering.

/// Why a document is not one readable JSON object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonFault {
    /// The document is empty or only whitespace.
    Empty,
    /// The document exceeds the caller's byte bound.
    TooLarge,
    /// The document is not RFC 8259 JSON, nests deeper than the reader
    /// allows, or is not a top-level object.
    Invalid,
    /// Two members of one object carry the same name.
    DuplicateMember,
}

/// The members a caller reads out of one JSON object.
///
/// Numbers keep the distinction a token response depends on: RFC 8259
/// allows `3600.0` and `1e3`, and a caller that needs a count must be able
/// to refuse both rather than round them.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum JsonMember {
    /// A decoded JSON string.
    Text(String),
    /// A number with no sign, fraction, or exponent.
    Unsigned(u64),
    /// Any other value: a signed or fractional number, a boolean, null,
    /// or a nested object or array. The value was validated and skipped.
    Other,
}

/// Maximum nesting the reader accepts. A token response is flat; the
/// bound exists so hostile nesting cannot drive recursion.
pub(crate) const MAXIMUM_JSON_DEPTH: usize = 8;

/// Read one bounded JSON object, refusing duplicate members.
///
/// Member order is preserved as the document states it. This function is
/// total over arbitrary bytes: it returns [`JsonFault`] rather than
/// panicking, and it reads no more than `bound` bytes before refusing.
pub(crate) fn parse_object(
    bytes: &[u8],
    bound: usize,
) -> Result<Vec<(String, JsonMember)>, JsonFault> {
    if bytes.is_empty() || bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(JsonFault::Empty);
    }
    if bytes.len() > bound {
        return Err(JsonFault::TooLarge);
    }
    let mut cursor = 0;
    skip_whitespace(bytes, &mut cursor);
    if bytes.get(cursor) != Some(&b'{') {
        return Err(JsonFault::Invalid);
    }
    let members = read_object(bytes, &mut cursor, 0)?;
    skip_whitespace(bytes, &mut cursor);
    if cursor != bytes.len() {
        return Err(JsonFault::Invalid);
    }
    Ok(members)
}

/// Whether one byte may appear in a JSON string's raw form: any byte
/// above the controls except the quote and the backslash, which carry
/// meaning and must be escaped.
fn is_raw_string_byte(byte: u8) -> bool {
    byte >= 0x20 && byte != b'"' && byte != b'\\'
}

/// Whether the escape sequence starting at `cursor` (on the backslash)
/// is well formed, returning the index just past it.
fn escape_is_valid(bytes: &[u8], cursor: usize) -> Option<usize> {
    let escape = *bytes.get(cursor)? == b'\\';
    if !escape {
        return None;
    }
    match *bytes.get(cursor + 1)? {
        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => Some(cursor + 2),
        b'u' => {
            let digits = bytes.get(cursor + 2..cursor + 6)?;
            let all_hex = digits.iter().all(|digit| digit.is_ascii_hexdigit());
            if all_hex {
                Some(cursor + 6)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Decode a JSON string's contents, escapes included, into text; a lone
/// surrogate half or invalid UTF-8 refuses.
fn decode_string(raw: &[u8]) -> Option<String> {
    let mut text: Vec<u8> = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        let byte = raw[index];
        if byte != b'\\' {
            text.push(byte);
            index += 1;
            continue;
        }
        index += 1;
        match raw.get(index)? {
            b'"' => text.push(b'"'),
            b'\\' => text.push(b'\\'),
            b'/' => text.push(b'/'),
            b'b' => text.push(0x08),
            b'f' => text.push(0x0c),
            b'n' => text.push(b'\n'),
            b'r' => text.push(b'\r'),
            b't' => text.push(b'\t'),
            b'u' => {
                let digits = raw.get(index + 1..index + 5)?;
                let code = u16::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()?;
                index += 4;
                let character = match char::from_u32(u32::from(code)) {
                    Some(character) => character,
                    None => {
                        let high = (0xd800..=0xdbff).contains(&code);
                        if !high {
                            return None;
                        }
                        let paired = raw.get(index + 1..index + 7)?;
                        if paired[0] != b'\\' || paired[1] != b'u' {
                            return None;
                        }
                        let low_digits = raw.get(index + 3..index + 7)?;
                        let low =
                            u16::from_str_radix(std::str::from_utf8(low_digits).ok()?, 16).ok()?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return None;
                        }
                        let combined = 0x10000
                            + ((u32::from(code) - 0xd800) << 10)
                            + (u32::from(low) - 0xdc00);
                        index += 6;
                        char::from_u32(combined)?
                    }
                };
                let mut encoded = [0; 4];
                text.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
            _ => return None,
        }
        index += 1;
    }
    String::from_utf8(text).ok()
}

/// Skip JSON whitespace.
fn skip_whitespace(bytes: &[u8], cursor: &mut usize) {
    while matches!(
        bytes.get(*cursor),
        Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
    ) {
        *cursor += 1;
    }
}

/// Read one string, opening quote at `cursor`, validating as it goes.
fn read_string(bytes: &[u8], cursor: &mut usize) -> Result<String, JsonFault> {
    *cursor += 1;
    let mut raw: Vec<u8> = Vec::new();
    loop {
        let byte = bytes.get(*cursor).copied().ok_or(JsonFault::Invalid)?;
        if byte == b'"' {
            *cursor += 1;
            break;
        }
        if byte == b'\\' {
            let end = escape_is_valid(bytes, *cursor).ok_or(JsonFault::Invalid)?;
            raw.extend_from_slice(&bytes[*cursor..end]);
            *cursor = end;
            continue;
        }
        if !is_raw_string_byte(byte) {
            return Err(JsonFault::Invalid);
        }
        raw.push(byte);
        *cursor += 1;
    }
    decode_string(&raw).ok_or(JsonFault::Invalid)
}

/// Read one JSON number at `cursor`, classifying it as an unsigned count
/// only when it is a bare run of digits.
fn read_number(bytes: &[u8], cursor: &mut usize) -> Result<JsonMember, JsonFault> {
    let start = *cursor;
    let mut classified = true;
    if bytes.get(*cursor) == Some(&b'-') {
        classified = false;
        *cursor += 1;
    }
    match bytes.get(*cursor) {
        Some(b'0') => *cursor += 1,
        Some(b'1'..=b'9') => {
            while matches!(bytes.get(*cursor), Some(b'0'..=b'9')) {
                *cursor += 1;
            }
        }
        _ => return Err(JsonFault::Invalid),
    }
    if bytes.get(*cursor) == Some(&b'.') {
        classified = false;
        *cursor += 1;
        if !matches!(bytes.get(*cursor), Some(b'0'..=b'9')) {
            return Err(JsonFault::Invalid);
        }
        while matches!(bytes.get(*cursor), Some(b'0'..=b'9')) {
            *cursor += 1;
        }
    }
    if matches!(bytes.get(*cursor), Some(b'e') | Some(b'E')) {
        classified = false;
        *cursor += 1;
        if matches!(bytes.get(*cursor), Some(b'+') | Some(b'-')) {
            *cursor += 1;
        }
        if !matches!(bytes.get(*cursor), Some(b'0'..=b'9')) {
            return Err(JsonFault::Invalid);
        }
        while matches!(bytes.get(*cursor), Some(b'0'..=b'9')) {
            *cursor += 1;
        }
    }
    if !classified {
        return Ok(JsonMember::Other);
    }
    let digits = std::str::from_utf8(&bytes[start..*cursor]).map_err(|_| JsonFault::Invalid)?;
    digits
        .parse::<u64>()
        .map(JsonMember::Unsigned)
        .or(Ok(JsonMember::Other))
}

/// Read one JSON value at `cursor`.
fn read_value(bytes: &[u8], cursor: &mut usize, depth: usize) -> Result<JsonMember, JsonFault> {
    if depth > MAXIMUM_JSON_DEPTH {
        return Err(JsonFault::Invalid);
    }
    match bytes.get(*cursor) {
        Some(b'"') => Ok(JsonMember::Text(read_string(bytes, cursor)?)),
        Some(b'-') | Some(b'0'..=b'9') => read_number(bytes, cursor),
        Some(b't') => expect_literal(bytes, cursor, b"true"),
        Some(b'f') => expect_literal(bytes, cursor, b"false"),
        Some(b'n') => expect_literal(bytes, cursor, b"null"),
        Some(b'{') => {
            read_object(bytes, cursor, depth + 1)?;
            Ok(JsonMember::Other)
        }
        Some(b'[') => {
            read_array(bytes, cursor, depth + 1)?;
            Ok(JsonMember::Other)
        }
        _ => Err(JsonFault::Invalid),
    }
}

/// Read one object at `cursor`, on the opening brace, collecting its
/// members in document order and refusing duplicate names.
fn read_object(
    bytes: &[u8],
    cursor: &mut usize,
    depth: usize,
) -> Result<Vec<(String, JsonMember)>, JsonFault> {
    *cursor += 1;
    skip_whitespace(bytes, cursor);
    let mut members = Vec::new();
    if bytes.get(*cursor) == Some(&b'}') {
        *cursor += 1;
        return Ok(members);
    }
    loop {
        skip_whitespace(bytes, cursor);
        if bytes.get(*cursor) != Some(&b'"') {
            return Err(JsonFault::Invalid);
        }
        let name = read_string(bytes, cursor)?;
        skip_whitespace(bytes, cursor);
        if bytes.get(*cursor) != Some(&b':') {
            return Err(JsonFault::Invalid);
        }
        *cursor += 1;
        skip_whitespace(bytes, cursor);
        let value = read_value(bytes, cursor, depth)?;
        if members.iter().any(|(existing, _)| existing == &name) {
            return Err(JsonFault::DuplicateMember);
        }
        members.push((name, value));
        skip_whitespace(bytes, cursor);
        match bytes.get(*cursor) {
            Some(b',') => *cursor += 1,
            Some(b'}') => {
                *cursor += 1;
                return Ok(members);
            }
            _ => return Err(JsonFault::Invalid),
        }
    }
}

/// Read one array at `cursor`, on the opening bracket.
fn read_array(bytes: &[u8], cursor: &mut usize, depth: usize) -> Result<(), JsonFault> {
    *cursor += 1;
    skip_whitespace(bytes, cursor);
    if bytes.get(*cursor) == Some(&b']') {
        *cursor += 1;
        return Ok(());
    }
    loop {
        skip_whitespace(bytes, cursor);
        read_value(bytes, cursor, depth)?;
        skip_whitespace(bytes, cursor);
        match bytes.get(*cursor) {
            Some(b',') => *cursor += 1,
            Some(b']') => {
                *cursor += 1;
                return Ok(());
            }
            _ => return Err(JsonFault::Invalid),
        }
    }
}

/// Read one fixed literal at `cursor`.
fn expect_literal(
    bytes: &[u8],
    cursor: &mut usize,
    literal: &[u8],
) -> Result<JsonMember, JsonFault> {
    if bytes.get(*cursor..*cursor + literal.len()) == Some(literal) {
        *cursor += literal.len();
        Ok(JsonMember::Other)
    } else {
        Err(JsonFault::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(name: &str, value: &str) -> (String, JsonMember) {
        (name.to_owned(), JsonMember::Text(value.to_owned()))
    }

    /// The members a token response carries, read in document order, with
    /// unknown members ignored after validation.
    #[test]
    fn reads_an_object_and_preserves_member_order() {
        let members = parse_object(
            br#"{"access_token":"at","token_type":"Bearer","expires_in":3600,"refresh_expires_in":0,"not-before-policy":0}"#,
            16 * 1024,
        )
        .expect("a readable token response");
        assert_eq!(
            members,
            vec![
                text("access_token", "at"),
                text("token_type", "Bearer"),
                ("expires_in".to_owned(), JsonMember::Unsigned(3600)),
                ("refresh_expires_in".to_owned(), JsonMember::Unsigned(0)),
                ("not-before-policy".to_owned(), JsonMember::Unsigned(0)),
            ]
        );
    }

    /// Unknown members may nest arbitrarily within the depth bound; their
    /// values are validated as JSON and never surface.
    #[test]
    fn unknown_members_may_composite() {
        let members = parse_object(
            br#"{"known":"v","nested":{"a":[1,-2.5,true,null,"x"]},"tail":7}"#,
            16 * 1024,
        )
        .expect("composite unknown members are valid JSON");
        assert_eq!(
            members,
            vec![
                text("known", "v"),
                ("nested".to_owned(), JsonMember::Other),
                ("tail".to_owned(), JsonMember::Unsigned(7)),
            ]
        );
    }

    /// Fractional, signed, exponent, boolean, and null values are
    /// distinguishable from unsigned counts.
    #[test]
    fn number_kinds_do_not_round() {
        let members = parse_object(
            br#"{"a":1,"b":1.0,"c":-1,"d":1e3,"e":true,"f":null,"g":0}"#,
            16 * 1024,
        )
        .expect("all RFC 8259 value kinds parse");
        let map: Vec<(&str, &JsonMember)> = members
            .iter()
            .map(|(name, value)| (name.as_str(), value))
            .collect();
        assert_eq!(
            map,
            vec![
                ("a", &JsonMember::Unsigned(1)),
                ("b", &JsonMember::Other),
                ("c", &JsonMember::Other),
                ("d", &JsonMember::Other),
                ("e", &JsonMember::Other),
                ("f", &JsonMember::Other),
                ("g", &JsonMember::Unsigned(0)),
            ]
        );
    }

    /// Duplicate members are refused, wherever they sit.
    #[test]
    fn duplicate_members_are_refused() {
        assert_eq!(
            parse_object(br#"{"a":1,"a":2}"#, 1024),
            Err(JsonFault::DuplicateMember)
        );
        assert_eq!(
            parse_object(br#"{"a":{"x":1,"x":2}}"#, 1024),
            Err(JsonFault::DuplicateMember)
        );
    }

    /// A non-object document, truncated JSON, trailing content, and an
    /// empty document are all invalid, never a panic.
    #[test]
    fn non_objects_and_truncations_are_invalid() {
        for document in [
            &b""[..],
            b"   ",
            b"[]",
            b"1",
            br#"{"a":1"#,
            br#"{"a":1},"#,
            br#"{"a":1} trailing"#,
            b"{",
            br#"{"a"}"#,
            br#"{"a":}"#,
        ] {
            assert!(
                matches!(
                    parse_object(document, 1024),
                    Err(JsonFault::Invalid | JsonFault::Empty)
                ),
                "document {document:?} must not parse"
            );
        }
    }

    /// Hostile strings: raw control bytes, bad escapes, lone surrogates,
    /// truncated unicode escapes, and invalid UTF-8 all refuse.
    #[test]
    fn malformed_strings_refuse() {
        for document in [
            &b"{\"a\":\"\t\"}"[..],
            b"{\"a\":\"\\q\"}",
            b"{\"a\":\"\\u00\"}",
            b"{\"a\":\"\\ud800\"}",
            b"{\"a\":\"\\ud800\\u0061\"}",
            b"{\"a\":\"unterminated}",
            b"{\"a\":\"\xff\"}",
        ] {
            assert_eq!(
                parse_object(document, 1024),
                Err(JsonFault::Invalid),
                "document {document:?} must refuse"
            );
        }
    }

    /// String escapes decode, including surrogate pairs.
    #[test]
    fn string_escapes_decode() {
        let members = parse_object(
            b"{\"a\":\"line\\nbreak \\u0041\\ud83d\\ude00 \\/ \\\"q\\\"\"}",
            1024,
        )
        .expect("escapes decode");
        assert_eq!(
            members,
            vec![(
                "a".to_owned(),
                JsonMember::Text("line\nbreak A\u{1f600} / \"q\"".to_owned())
            )]
        );
    }

    /// The byte bound refuses before parsing.
    #[test]
    fn the_byte_bound_refuses_first() {
        assert_eq!(parse_object(br#"{"a":1}"#, 3), Err(JsonFault::TooLarge));
    }

    /// Nesting deeper than the bound refuses rather than recursing.
    #[test]
    fn depth_is_bounded() {
        let deep = format!("{}1{}", "[".repeat(64), "]".repeat(64));
        let document = format!("{{\"a\":{deep}}}");
        assert_eq!(
            parse_object(document.as_bytes(), 1024 * 1024),
            Err(JsonFault::Invalid)
        );
    }

    /// Malformed numbers refuse: leading zeros, plus signs, bare dots,
    /// and trailing letters.
    #[test]
    fn malformed_numbers_refuse() {
        for document in [
            &b"{\"a\":01}"[..],
            b"{\"a\":+1}",
            b"{\"a\":1.}",
            b"{\"a\":.5}",
            b"{\"a\":1e}",
            b"{\"a\":-}",
            b"{\"a\":Infinity}",
        ] {
            assert_eq!(
                parse_object(document, 1024),
                Err(JsonFault::Invalid),
                "{document:?}"
            );
        }
    }
}
