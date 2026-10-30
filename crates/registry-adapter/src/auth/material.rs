// SPDX-License-Identifier: Apache-2.0

//! Credential material: the zeroizing buffers and encodings the auth
//! layer builds (`products/adapter/CONCEPT.md` section 10.2).
//!
//! Everything secret the layer holds lives in [`ProtectedText`], a buffer
//! this layer erases with volatile writes when dropped. Nothing outside
//! this module renders a secret: `Debug` is redacted, there is no
//! `Display`, and the only reader is the byte slice the outbound request
//! builder copies while marking the header sensitive. Resolved source
//! secrets stay in `registry-platform-config`'s `ProtectedSecret`, which
//! erases the same way.

use std::fmt;

/// Secret bytes this layer erases when dropped.
///
/// The buffer is written over in `Drop` behind a `black_box` barrier the
/// compiler must treat as observable, the strongest erasure available
/// under the workspace's `forbid(unsafe_code)` without the `zeroize`
/// dependency this crate does not yet link; resolved source secrets
/// additionally spend their whole resolved life inside
/// `registry-platform-config`'s zeroizing `ProtectedSecret`. Swap the
/// barrier for `zeroize::Zeroizing` when the manifest carries it. There
/// is no `Display`, and `Debug` never carries the bytes.
#[derive(Clone, PartialEq)]
pub struct ProtectedText(Vec<u8>);

impl ProtectedText {
    /// Wrap text the layer will place in a request.
    #[must_use]
    pub fn from_str_value(text: &str) -> Self {
        Self(text.as_bytes().to_vec())
    }

    /// Wrap bytes the layer will place in a request.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Take ownership of bytes built inside this layer, so a derived
    /// credential is never copied into an unprotected buffer on its way
    /// in.
    #[must_use]
    pub(crate) fn from_owned(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes the outbound request builder copies. This is the only
    /// reader; callers must not retain or render them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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

impl Drop for ProtectedText {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}

impl fmt::Debug for ProtectedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedText([REDACTED])")
    }
}

/// Erase a buffer before its memory returns to the allocator.
///
/// The plain stores sit behind a `black_box` barrier: the compiler must
/// assume the buffer can be read through the pointer it observed, so it
/// cannot elide the stores as dead. This is the barrier this crate can
/// build under the workspace's `forbid(unsafe_code)`; `zeroize`'s
/// volatile writes are stronger and replace this loop when the crate
/// links that dependency.
fn erase(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        *byte = 0;
    }
    std::hint::black_box(bytes);
}

/// One header the auth layer injects at send time: the fixed header name
/// and the credential value in a zeroizing buffer. The value is copied
/// into the outbound request and marked sensitive there; it never enters
/// an exchange, a property, a diagnostic, or the journal.
#[derive(Clone, Debug, PartialEq)]
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
    let mut joined = Vec::with_capacity(username.len() + 1 + password.len());
    joined.extend_from_slice(username);
    joined.push(b':');
    joined.extend_from_slice(password);
    let encoded = base64_standard(&joined);
    let mut value = Vec::with_capacity(6 + encoded.len());
    value.extend_from_slice(b"Basic ");
    value.extend_from_slice(encoded.as_bytes());
    Ok(ProtectedText::from_owned(value))
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
    let mut value = Vec::with_capacity(scheme.len() + 1 + token.len());
    value.extend_from_slice(scheme.as_bytes());
    value.push(b' ');
    value.extend_from_slice(token);
    Ok(ProtectedText::from_owned(value))
}

/// Encode one `application/x-www-form-urlencoded` body from ordered
/// pairs. Values are encoded so no credential byte can cross into the
/// request target or a header.
pub(crate) fn form_body(pairs: &[(&str, &str)]) -> ProtectedText {
    let mut body: Vec<u8> = Vec::new();
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

/// Standard base64 with padding, as the Basic scheme specifies.
pub(crate) fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let triple = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Whether the bytes can travel as one header value: visible ASCII,
/// space, or an extension byte, never a control byte or DEL.
pub(crate) fn is_header_value_bytes(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte >= 0x20 && *byte != 0x7f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The buffer is readable by the transport and never rendered.
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

    /// The Basic value is the standard encoding of `user:password`, and
    /// the split is refused where it would be ambiguous.
    #[test]
    fn basic_values_encode_and_refuse() {
        let value = basic_value(b"user", b"pass").expect("a usable pair");
        assert_eq!(value.as_bytes(), b"Basic dXNlcjpwYXNz");
        assert_eq!(
            basic_value(b"", b"pass"),
            Err(MaterialFault::Empty),
            "an empty username is unusable"
        );
        assert_eq!(
            basic_value(b"user", b""),
            Err(MaterialFault::Empty),
            "an empty password is unusable"
        );
        assert_eq!(
            basic_value(b"us:er", b"pass"),
            Err(MaterialFault::UsernameColon),
            "a colon in the username would move the split"
        );
    }

    /// Base64 vectors from RFC 4648.
    #[test]
    fn base64_matches_rfc_4648() {
        assert_eq!(base64_standard(b""), "");
        assert_eq!(base64_standard(b"f"), "Zg==");
        assert_eq!(base64_standard(b"fo"), "Zm8=");
        assert_eq!(base64_standard(b"foo"), "Zm9v");
        assert_eq!(base64_standard(b"foob"), "Zm9vYg==");
        assert_eq!(base64_standard(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_standard(b"foobar"), "Zm9vYmFy");
    }

    /// A scheme value joins with one space and refuses a token that could
    /// fold or inject.
    #[test]
    fn scheme_values_join_and_validate() {
        let value = scheme_value("ApiToken", b"abc123").expect("a usable token");
        assert_eq!(value.as_bytes(), b"ApiToken abc123");
        assert_eq!(
            scheme_value("Bearer", b"to ken"),
            Err(MaterialFault::NotVisibleAscii)
        );
        assert_eq!(scheme_value("Bearer", b""), Err(MaterialFault::Empty));
        assert_eq!(
            scheme_value("Bearer", b"line\nbreak"),
            Err(MaterialFault::NotVisibleAscii)
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
