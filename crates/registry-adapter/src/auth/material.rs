// SPDX-License-Identifier: Apache-2.0

//! Credential material: the zeroizing buffers and encodings the auth
//! layer builds (`products/adapter/CONCEPT.md` section 10.2).
//!
//! Everything secret the layer holds lives in [`ProtectedText`], a
//! buffer the `zeroize` crate erases when dropped. Nothing outside
//! this module renders a secret: `Debug` is redacted, there is no
//! `Display`, and the only reader is the byte slice the outbound request
//! builder copies while marking the header sensitive. Resolved source
//! secrets stay in `registry-platform-config`'s `ProtectedSecret`, which
//! erases the same way.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use std::fmt;
use zeroize::Zeroizing;

/// Secret bytes the `zeroize` crate erases when dropped.
///
/// The buffer is [`Zeroizing`]: its drop writes zeros through volatile
/// stores the compiler cannot elide, behind barriers that defeat
/// copy-propagation, so the secret cannot be recovered from released
/// memory. Resolved source secrets additionally spend their whole
/// resolved life inside `registry-platform-config`'s zeroizing
/// `ProtectedSecret`. There is no `Display`, `Debug` never carries the
/// bytes, and there is no `PartialEq`: equality of secret bytes is never
/// asked, and a comparison would leak length by early exit.
#[derive(Clone)]
pub struct ProtectedText(Zeroizing<Vec<u8>>);

impl ProtectedText {
    /// Wrap text the layer will place in a request. The caller's source
    /// buffer is not erased.
    #[must_use]
    pub fn from_str_value(text: &str) -> Self {
        Self(Zeroizing::new(text.as_bytes().to_vec()))
    }

    /// Wrap bytes the layer will place in a request. The caller's source
    /// buffer is not erased.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    /// Take ownership of bytes built inside this layer, so a derived
    /// credential is never copied into an unprotected buffer on its way
    /// in; the buffer is already zeroizing.
    #[must_use]
    pub(crate) fn from_owned(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// The bytes the outbound request builder copies. This is the only
    /// reader; callers must not retain or render them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// The buffered byte count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no bytes are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ProtectedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedText([REDACTED])")
    }
}

/// One header the auth layer injects at send time: the fixed header name
/// and the credential value in a zeroizing buffer. The value is copied
/// into the outbound request and marked sensitive there; it never enters
/// an exchange, a property, a diagnostic, or the journal.
#[derive(Clone, Debug)]
pub struct AuthHeader {
    name: String,
    value: ProtectedText,
}

impl AuthHeader {
    /// Build one injected header from validated parts.
    #[must_use]
    pub fn new(name: &str, value: ProtectedText) -> Self {
        Self {
            name: name.to_owned(),
            value,
        }
    }

    /// The header name, never secret.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The credential value, readable only to be placed on the outbound
    /// request.
    #[must_use]
    pub fn value(&self) -> &ProtectedText {
        &self.value
    }
}

/// Why credential bytes cannot become header material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MaterialFault {
    /// A required credential value is empty.
    Empty,
    /// A username may not carry a colon, which would split the Basic
    /// credential at another point.
    UsernameColon,
    /// A bearer-style token must be visible ASCII so it cannot fold,
    /// escape, or inject.
    NotVisibleAscii,
}

/// Encode one `Authorization: Basic` value from the resolved pair, the
/// way Evidence does: refuse an empty username or password, refuse a
/// colon in the username, then base64 the `username:password` bytes.
/// Every intermediate that holds the pair or its encoding is zeroizing
/// and pre-sized, so no reallocation frees a copy.
pub(crate) fn basic_value(
    username: &[u8],
    password: &[u8],
) -> Result<ProtectedText, MaterialFault> {
    if username.is_empty() || password.is_empty() {
        return Err(MaterialFault::Empty);
    }
    if username.contains(&b':') {
        return Err(MaterialFault::UsernameColon);
    }
    let mut joined = Zeroizing::new(Vec::with_capacity(username.len() + 1 + password.len()));
    joined.extend_from_slice(username);
    joined.push(b':');
    joined.extend_from_slice(password);
    let mut encoded = Zeroizing::new(vec![0_u8; encoded_len(&joined)]);
    STANDARD
        .encode_slice(joined.as_slice(), encoded.as_mut_slice())
        .expect("the pre-sized buffer holds the standard encoding");
    let mut value = Zeroizing::new(Vec::with_capacity(6 + encoded.len()));
    value.extend_from_slice(b"Basic ");
    value.extend_from_slice(encoded.as_slice());
    Ok(ProtectedText::from_owned(value))
}

/// The standard-base64 length of `bytes` with padding, so the encoding
/// lands in one pre-sized buffer with no reallocation.
fn encoded_len(bytes: &[u8]) -> usize {
    bytes.len().div_ceil(3) * 4
}

/// Encode one `Authorization: <scheme> <token>` value; the token must be
/// visible ASCII, as a header-presented credential must be.
pub(crate) fn scheme_value(scheme: &str, token: &[u8]) -> Result<ProtectedText, MaterialFault> {
    if token.is_empty() {
        return Err(MaterialFault::Empty);
    }
    if !token.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return Err(MaterialFault::NotVisibleAscii);
    }
    let mut value = Zeroizing::new(Vec::with_capacity(scheme.len() + 1 + token.len()));
    value.extend_from_slice(scheme.as_bytes());
    value.push(b' ');
    value.extend_from_slice(token);
    Ok(ProtectedText::from_owned(value))
}

/// Encode one `application/x-www-form-urlencoded` body from ordered
/// pairs. Values are encoded so no credential byte can cross into the
/// request target or a header. The exact encoded length is computed
/// first, so the body is built in one zeroizing buffer and no
/// reallocation frees a copy of the client secret or assertion.
pub(crate) fn form_body(pairs: &[(&str, &str)]) -> ProtectedText {
    let mut capacity = 0;
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            capacity += 1;
        }
        capacity += form_encoded_len(name.as_bytes()) + 1 + form_encoded_len(value.as_bytes());
    }
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            body.push(b'&');
        }
        form_encode_into(&mut body, name.as_bytes());
        body.push(b'=');
        form_encode_into(&mut body, value.as_bytes());
    }
    ProtectedText::from_owned(body)
}

/// The percent-encoded length of one member: unreserved bytes and space
/// stay one byte, everything else becomes three hex bytes.
fn form_encoded_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .map(|&byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b' ' => 1,
            _ => 3,
        })
        .sum()
}

/// Percent-encode one form member: unreserved bytes as they are, space
/// as plus, everything else as two uppercase hex digits.
fn form_encode_into(out: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in bytes {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(byte),
            b' ' => out.push(b'+'),
            other => {
                out.push(b'%');
                out.push(HEX[usize::from(other >> 4)]);
                out.push(HEX[usize::from(other & 0x0f)]);
            }
        }
    }
}

/// Whether the bytes can travel as one header value: visible ASCII,
/// space, or an extension byte, never a control byte or DEL.
pub(crate) fn is_header_value_bytes(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte >= 0x20 && *byte != 0x7f)
}

/// Whether the bytes are a credential that arrives exactly as declared:
/// header-value bytes with no leading or trailing space or tab, which
/// intermediaries strip and so would silently change the credential.
pub(crate) fn is_credential_value_bytes(bytes: &[u8]) -> bool {
    let leading = matches!(bytes.first(), Some(b' ' | b'\t'));
    let trailing = matches!(bytes.last(), Some(b' ' | b'\t'));
    is_header_value_bytes(bytes) && !leading && !trailing
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The buffer is readable by the transport and never rendered; the
    /// inner buffer is `Zeroizing`, whose drop performs the volatile
    /// zeroize.
    #[test]
    fn protected_text_holds_and_redacts() {
        let text = ProtectedText::from_str_value("secret-canary");
        assert_eq!(text.as_bytes(), b"secret-canary");
        assert_eq!(text.len(), 13);
        assert!(!text.is_empty());
        assert!(!format!("{text:?}").contains("secret-canary"), "{text:?}");
        let clone = text.clone();
        assert_eq!(clone.as_bytes(), b"secret-canary");
        assert!(!format!("{clone:?}").contains("secret-canary"));
    }

    /// The Basic value is the standard encoding of `user:password`, with
    /// and without base64 padding, and the split is refused where it
    /// would be ambiguous.
    #[test]
    fn basic_values_encode_and_refuse() {
        let value = basic_value(b"user", b"pass").expect("a usable pair");
        assert_eq!(value.as_bytes(), b"Basic dXNlcjpwYXNz");
        // "user:password" is 13 bytes, so the encoding pads with `==`.
        let value = basic_value(b"user", b"password").expect("a usable pair");
        assert_eq!(value.as_bytes(), b"Basic dXNlcjpwYXNzd29yZA==");
        assert_eq!(
            basic_value(b"", b"pass").unwrap_err(),
            MaterialFault::Empty,
            "an empty username is unusable"
        );
        assert_eq!(
            basic_value(b"user", b"").unwrap_err(),
            MaterialFault::Empty,
            "an empty password is unusable"
        );
        assert_eq!(
            basic_value(b"us:er", b"pass").unwrap_err(),
            MaterialFault::UsernameColon,
            "a colon in the username would move the split"
        );
    }

    /// A scheme value joins with one space and refuses a token that could
    /// fold or inject.
    #[test]
    fn scheme_values_join_and_validate() {
        let value = scheme_value("ApiToken", b"abc123").expect("a usable token");
        assert_eq!(value.as_bytes(), b"ApiToken abc123");
        assert_eq!(
            scheme_value("Bearer", b"to ken").unwrap_err(),
            MaterialFault::NotVisibleAscii
        );
        assert_eq!(
            scheme_value("Bearer", b"").unwrap_err(),
            MaterialFault::Empty
        );
        assert_eq!(
            scheme_value("Bearer", b"line\nbreak").unwrap_err(),
            MaterialFault::NotVisibleAscii
        );
    }

    /// The form encoding percent-encodes everything but unreserved
    /// characters and maps space to plus, matching what a token endpoint
    /// reads from `application/x-www-form-urlencoded`.
    #[test]
    fn form_bodies_encode_reserved_bytes() {
        let body = form_body(&[("grant_type", "client_credentials"), ("scope", "a b&c=d")]);
        assert_eq!(
            body.as_bytes(),
            b"grant_type=client_credentials&scope=a+b%26c%3Dd"
        );
    }

    /// The first pass pre-sizes the body exactly: the built length is
    /// the length it computed, so the single zeroizing buffer never
    /// reallocates and never frees a copy of a credential byte.
    #[test]
    fn form_body_capacity_is_exact() {
        let pairs = [
            ("grant_type", "client_credentials"),
            ("client_secret", "s3cr3t & more=="),
            ("scope", "a b&c=d"),
        ];
        let expected: usize = pairs
            .iter()
            .enumerate()
            .map(|(index, (name, value))| {
                let separator = if index > 0 { 1 } else { 0 };
                separator
                    + form_encoded_len(name.as_bytes())
                    + 1
                    + form_encoded_len(value.as_bytes())
            })
            .sum();
        assert_eq!(form_body(&pairs).len(), expected);
    }

    /// Header-value bytes accept visible ASCII, space, and extension
    /// bytes, and refuse controls and DEL.
    #[test]
    fn header_value_bytes_classify() {
        assert!(is_header_value_bytes(b"token"));
        assert!(is_header_value_bytes(b"with space"));
        assert!(is_header_value_bytes(&[0x20, 0x41, 0x7e, 0xc3]));
        assert!(!is_header_value_bytes(b"\r\n"));
        assert!(!is_header_value_bytes(&[0x00]));
        assert!(!is_header_value_bytes(&[0x7f]));
        assert!(!is_header_value_bytes(&[0x1f]));
    }

    /// A credential value must arrive exactly as declared: leading or
    /// trailing space or tab, which intermediaries strip, refuses, while
    /// interior space stays.
    #[test]
    fn credential_values_refuse_edge_whitespace() {
        assert!(is_credential_value_bytes(b"key123"));
        assert!(is_credential_value_bytes(b"key 123"));
        assert!(!is_credential_value_bytes(b" key123"));
        assert!(!is_credential_value_bytes(b"key123 "));
        assert!(!is_credential_value_bytes(b"\tkey123"));
        assert!(!is_credential_value_bytes(b"key123\t"));
        assert!(!is_credential_value_bytes(b" key "));
        assert!(!is_credential_value_bytes(b" "));
        assert!(!is_credential_value_bytes(b"\r\nkey"));
    }

    /// An injected header shows its name and never its value.
    #[test]
    fn auth_headers_debug_the_name_only() {
        let header = AuthHeader::new("authorization", ProtectedText::from_str_value("canary"));
        assert_eq!(header.name(), "authorization");
        assert_eq!(header.value().as_bytes(), b"canary");
        let rendered = format!("{header:?}");
        assert!(rendered.contains("authorization"), "{rendered}");
        assert!(!rendered.contains("canary"), "{rendered}");
    }
}
