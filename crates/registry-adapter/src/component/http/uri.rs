// SPDX-License-Identifier: Apache-2.0

//! Origin-pinned links: the `httpUri` parameter on an `http` send
//! (`products/adapter/CONCEPT.md` section 8.11.5).
//!
//! Sources page and link by absolute URL (FHIR `link[relation=next]`,
//! HAL, JSON:API). Camel follows such a link through `CamelHttpUri`,
//! which replaces the endpoint URI wholesale; the Adapter keeps the
//! capability and pins it. A [`PinnedOrigin`] is built once from the
//! endpoint's configured base URL; [`PinnedOrigin::pin`] parses a link
//! once and refuses it with the uncatchable `egress.refused` unless its
//! scheme, host, and port equal the origin's, its path stays under the
//! base path after normalization, it carries no userinfo or fragment,
//! and it fits `MAX_DESTINATION_ORIGIN_URL_BYTES` as written and as
//! serialized.
//!
//! # One parse
//!
//! The link is parsed exactly once, by the WHATWG parser of the `url`
//! crate, and every comparison runs on that parse. [`PinnedLink`] holds
//! the parsed URL; the sender sends [`PinnedLink::target`] under the
//! endpoint's fixed origin, exactly that value and never a reparse of
//! the original string, so no second parser can read the link
//! differently from the check. Where the parser would silently repair
//! the input (dropping tabs and newlines, trimming spaces, reading `\`
//! as `/`, accepting `https:host` without `//`, rewriting the query),
//! the raw link is refused instead, so the value checked is the value
//! the source wrote.
//!
//! Hosts compare as the parser normalizes them: lowercase, IDNA mapped
//! to punycode, IPv4 in any numeric spelling read as one address, IPv6
//! compressed. A trailing-dot host is a different host and is refused.
//! Ports compare with the scheme's default filled in, so `:443` equals
//! no port on `https`.
//!
//! The path must be canonical as the platform transport defines it
//! (`registry-platform-httputil`'s fixed-destination target rule): no
//! empty segment, no `;`, and every percent escape uppercase and
//! decoding to a byte no server reads as structure or as an alias
//! (not `/`, `\`, `?`, `;`, `%`, `:`, an unreserved character, or a
//! control). A dot segment, literal or percent-escaped, is refused on
//! the raw text before any parse: the WHATWG parser collapses `.` and
//! `..` silently, so a link like `/base/x/../y` or `/base/%2e%2e/y`
//! would otherwise reach an undeclared path under the credential. The
//! transport additionally refuses a decoded path holding invisible
//! format characters; the `http` component maps that refusal of a
//! pinned target to `egress.refused` as well.
//!
//! The query the source wrote is sent as written: a link whose query the
//! parser would percent-encode differently is refused rather than
//! rewritten. Redirects are never followed; that is the `http`
//! component's transport policy, not this module's.
//!
//! # Errors
//!
//! Refusals are value-free (CFG-SEC-3): they name the rule a link
//! broke, never the link, its host, or its query.

use std::fmt;

use registry_adapter_core::ErrorClass;
use registry_platform_httputil::destination::{
    disallowed_path_scalar, MAX_DESTINATION_ORIGIN_URL_BYTES,
};
use url::{Position, Url};

/// Why an endpoint's base URL cannot be pinned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginError {
    /// Longer than `MAX_DESTINATION_ORIGIN_URL_BYTES`, as written or as
    /// serialized.
    TooLong,
    /// Whitespace, a control, or `\`.
    InvalidCharacter,
    /// Not written `scheme://authority`.
    NotAbsolute,
    /// The scheme is neither `http` nor `https`.
    UnsupportedScheme,
    /// The URL parser refused it.
    Unparseable,
    /// Userinfo, empty or not.
    Userinfo,
    /// A query, empty or not.
    Query,
    /// A fragment, empty or not.
    Fragment,
    /// The base path is not canonical.
    NonCanonicalPath,
}

impl fmt::Display for OriginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLong => "the base URL is longer than the URL bound",
            Self::InvalidCharacter => {
                "the base URL holds whitespace, a control character, or a backslash"
            }
            Self::NotAbsolute => "the base URL is not written scheme://authority",
            Self::UnsupportedScheme => "the base URL scheme is neither http nor https",
            Self::Unparseable => "the base URL does not parse",
            Self::Userinfo => "the base URL carries userinfo",
            Self::Query => "the base URL carries a query",
            Self::Fragment => "the base URL carries a fragment",
            Self::NonCanonicalPath => "the base URL path is not canonical",
        })
    }
}

impl std::error::Error for OriginError {}

/// Why a link was refused; always the uncatchable `egress.refused`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkRefusal {
    /// Longer than `MAX_DESTINATION_ORIGIN_URL_BYTES`, as written or as
    /// serialized.
    TooLong,
    /// Whitespace, a control, or `\` anywhere in the link: characters
    /// the parser would drop, trim, or reinterpret.
    InvalidCharacter,
    /// Not written `scheme://authority`: a relative reference, a
    /// scheme-relative `//host`, or a lenient `https:host` form.
    NotAbsolute,
    /// The URL parser refused it (an IPv6 zone identifier, an invalid
    /// host or port).
    Unparseable,
    /// The scheme is not the origin's.
    SchemeMismatch,
    /// Userinfo, empty or not.
    Userinfo,
    /// The host is not the origin's.
    HostMismatch,
    /// The port, with the scheme default filled in, is not the origin's.
    PortMismatch,
    /// A fragment, empty or not.
    Fragment,
    /// The parser would send a different query than the one written.
    QueryNotAsWritten,
    /// The path is not canonical: an empty segment, a `;`, a dot
    /// segment, or a percent escape that is malformed, lowercase, or
    /// decodes to an alias.
    NonCanonicalPath,
    /// The normalized path is not the base path or beneath it at a
    /// segment boundary.
    OutsideBasePath,
}

impl LinkRefusal {
    /// The error class the send raises: `egress.refused`.
    #[must_use]
    pub const fn class(&self) -> ErrorClass {
        ErrorClass::EgressRefused
    }
}

impl fmt::Display for LinkRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLong => "the link is longer than the URL bound",
            Self::InvalidCharacter => {
                "the link holds whitespace, a control character, or a backslash"
            }
            Self::NotAbsolute => "the link is not written scheme://authority",
            Self::Unparseable => "the link does not parse",
            Self::SchemeMismatch => "the link scheme is not the endpoint's",
            Self::Userinfo => "the link carries userinfo",
            Self::HostMismatch => "the link host is not the endpoint's",
            Self::PortMismatch => "the link port is not the endpoint's",
            Self::Fragment => "the link carries a fragment",
            Self::QueryNotAsWritten => "the link query would not be sent as written",
            Self::NonCanonicalPath => "the link path is not canonical",
            Self::OutsideBasePath => "the link path is outside the endpoint's base path",
        })
    }
}

impl std::error::Error for LinkRefusal {}

/// An endpoint's configured origin and base path, the pin every
/// `httpUri` link is checked against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedOrigin {
    /// `scheme://host[:port]/`, as the parser serializes it.
    origin: Url,
    /// The base path without its trailing `/`; empty for the root.
    base_path: String,
}

impl PinnedOrigin {
    /// Pin the endpoint's configured base URL.
    ///
    /// # Errors
    ///
    /// [`OriginError`] when the base URL is over the URL bound, holds
    /// whitespace, a control, or `\`, is not written
    /// `scheme://authority`, is not `http` or `https`, does not parse,
    /// carries userinfo, a query, a fragment, a dot segment, or a
    /// non-canonical path.
    pub fn new(base_url: &str) -> Result<Self, OriginError> {
        let (scheme, rest) = screen(base_url).map_err(|fault| match fault {
            RawFault::TooLong => OriginError::TooLong,
            RawFault::InvalidCharacter => OriginError::InvalidCharacter,
            RawFault::NotAbsolute => OriginError::NotAbsolute,
            RawFault::Userinfo => OriginError::Userinfo,
        })?;
        if scheme != "http" && scheme != "https" {
            return Err(OriginError::UnsupportedScheme);
        }
        screen_authority(rest).map_err(|fault| match fault {
            RawFault::Userinfo => OriginError::Userinfo,
            _ => OriginError::NotAbsolute,
        })?;
        // The base path is judged on its raw text for the same reason a
        // link is: a base the parser would collapse could silently
        // widen the pin.
        if has_dot_segment(raw_path(rest)) {
            return Err(OriginError::NonCanonicalPath);
        }
        let parsed = Url::parse(base_url).map_err(|_| OriginError::Unparseable)?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(OriginError::Userinfo);
        }
        if parsed.host().is_none() {
            return Err(OriginError::NotAbsolute);
        }
        if parsed.query().is_some() {
            return Err(OriginError::Query);
        }
        if parsed.fragment().is_some() {
            return Err(OriginError::Fragment);
        }
        if parsed.as_str().len() > MAX_DESTINATION_ORIGIN_URL_BYTES {
            return Err(OriginError::TooLong);
        }
        if !is_canonical_path(parsed.path()) {
            return Err(OriginError::NonCanonicalPath);
        }
        let base_path = parsed.path().trim_end_matches('/').to_owned();
        let mut origin = parsed;
        origin.set_path("/");
        Ok(Self { origin, base_path })
    }

    /// The origin alone, `scheme://host[:port]/`, as the parser
    /// serializes it: the fixed origin the transport's destination
    /// policy is built from.
    #[must_use]
    pub fn origin_url(&self) -> String {
        self.origin.as_str().to_owned()
    }

    /// The base path without its trailing `/`; empty for the root.
    #[must_use]
    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    /// Parse a source-returned link once and pin it to this origin.
    ///
    /// The returned [`PinnedLink`] is the value to send; the sender
    /// never sends or reparses `link` itself.
    ///
    /// # Errors
    ///
    /// [`LinkRefusal`], class `egress.refused`, for every rule of
    /// section 8.11.5 the link breaks, and for raw input the parser
    /// would repair rather than refuse: dropped tabs and newlines,
    /// trimmed spaces, `\` read as `/`, a collapsed dot segment, a
    /// rewritten query.
    pub fn pin(&self, link: &str) -> Result<PinnedLink, LinkRefusal> {
        let (scheme, rest) = screen(link).map_err(|fault| match fault {
            RawFault::TooLong => LinkRefusal::TooLong,
            RawFault::InvalidCharacter => LinkRefusal::InvalidCharacter,
            RawFault::NotAbsolute => LinkRefusal::NotAbsolute,
            RawFault::Userinfo => LinkRefusal::Userinfo,
        })?;
        if scheme != self.origin.scheme() {
            return Err(LinkRefusal::SchemeMismatch);
        }
        screen_authority(rest).map_err(|fault| match fault {
            RawFault::Userinfo => LinkRefusal::Userinfo,
            _ => LinkRefusal::NotAbsolute,
        })?;
        // A dot segment is judged on the raw text: the parser collapses
        // it before any rule below could see it, and the collapsed path
        // would land on a path nobody declared.
        if has_dot_segment(raw_path(rest)) {
            return Err(LinkRefusal::NonCanonicalPath);
        }
        let url = Url::parse(link).map_err(|_| LinkRefusal::Unparseable)?;
        if url.scheme() != self.origin.scheme() {
            return Err(LinkRefusal::SchemeMismatch);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(LinkRefusal::Userinfo);
        }
        if url.host().is_none() || url.host() != self.origin.host() {
            return Err(LinkRefusal::HostMismatch);
        }
        if url.port_or_known_default() != self.origin.port_or_known_default() {
            return Err(LinkRefusal::PortMismatch);
        }
        if url.fragment().is_some() {
            return Err(LinkRefusal::Fragment);
        }
        let written_query = link.split_once('?').map(|(_, query)| query);
        if url.query() != written_query {
            return Err(LinkRefusal::QueryNotAsWritten);
        }
        if url.as_str().len() > MAX_DESTINATION_ORIGIN_URL_BYTES {
            return Err(LinkRefusal::TooLong);
        }
        if !is_canonical_path(url.path()) {
            return Err(LinkRefusal::NonCanonicalPath);
        }
        if !is_under(url.path(), &self.base_path) {
            return Err(LinkRefusal::OutsideBasePath);
        }
        Ok(PinnedLink { url })
    }
}

/// A link that passed [`PinnedOrigin::pin`]: the one parse every check
/// ran on, and the value the sender sends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedLink {
    url: Url,
}

impl PinnedLink {
    /// The parsed link. Its scheme, host, and port are the pinned
    /// origin's, and it has no userinfo or fragment.
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.url
    }

    /// The origin-relative request target, the normalized path and the
    /// query as written: exactly what the sender sends under the
    /// endpoint's fixed origin.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.url[Position::BeforePath..]
    }
}

/// A raw-input refusal shared by the base URL and link screens.
enum RawFault {
    TooLong,
    InvalidCharacter,
    NotAbsolute,
    Userinfo,
}

/// Screen the raw text before any parse: the length bound, characters
/// the parser would silently drop or reinterpret, and the
/// `scheme://` form. Returns the lowercased scheme and the text after
/// `://`.
fn screen(raw: &str) -> Result<(String, &str), RawFault> {
    if raw.len() > MAX_DESTINATION_ORIGIN_URL_BYTES {
        return Err(RawFault::TooLong);
    }
    if raw
        .chars()
        .any(|character| character.is_whitespace() || character.is_control() || character == '\\')
    {
        return Err(RawFault::InvalidCharacter);
    }
    let (scheme, rest) = raw.split_once("://").ok_or(RawFault::NotAbsolute)?;
    let mut bytes = scheme.bytes();
    let valid_scheme = bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'));
    if !valid_scheme {
        return Err(RawFault::NotAbsolute);
    }
    Ok((scheme.to_ascii_lowercase(), rest))
}

/// Screen the raw authority, the text after `://` up to the first `/`,
/// `?`, or `#`: it must be present and must not carry userinfo, since
/// the parser accepts an empty userinfo (`https://@host`) and extra
/// slashes (`https:///host`) silently.
fn screen_authority(rest: &str) -> Result<(), RawFault> {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(RawFault::NotAbsolute);
    }
    if authority.contains('@') {
        return Err(RawFault::Userinfo);
    }
    Ok(())
}

/// The raw path text of a post-authority remainder: from the first `/`,
/// up to the `?` or `#` that ends the path. Empty when the link carries
/// no path at all.
fn raw_path(rest: &str) -> &str {
    let Some(start) = rest.find('/') else {
        return "";
    };
    let path_and_more = &rest[start..];
    let end = path_and_more
        .find(['?', '#'])
        .unwrap_or(path_and_more.len());
    &path_and_more[..end]
}

/// Whether the raw path carries a dot segment the WHATWG parser would
/// silently collapse: a segment that is, or percent-decodes to, `.`
/// or `..`. Malformed escapes are not dot segments; the canonical-path
/// rule refuses those later. Both hex cases decode, since the parser
/// reads `%2e` and `%2E` the same.
fn has_dot_segment(path: &str) -> bool {
    path.split('/')
        .any(|segment| is_dot_segment(segment.as_bytes()))
}

/// Whether one raw segment percent-decodes to exactly `.` or `..`.
fn is_dot_segment(segment: &[u8]) -> bool {
    let mut decoded = Vec::with_capacity(segment.len());
    let mut index = 0;
    while index < segment.len() {
        if segment[index] != b'%' {
            decoded.push(segment[index]);
            index += 1;
            continue;
        }
        let (Some(high), Some(low)) = (
            segment.get(index + 1).copied().and_then(hex_digit),
            segment.get(index + 2).copied().and_then(hex_digit),
        ) else {
            return false;
        };
        decoded.push((high << 4) | low);
        index += 3;
    }
    decoded == b"." || decoded == b".."
}

/// The value of one hexadecimal digit, either case.
fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Whether a serialized path is canonical: no empty segment, no `;`,
/// and every percent escape well formed, uppercase, and decoding to a
/// byte that is neither a control, an unreserved character, nor one of
/// `% / \ ? ; :`, with the decoded path valid UTF-8 free of controls.
/// This is the platform transport's canonical-target rule, so a pinned
/// target renders.
fn is_canonical_path(path: &str) -> bool {
    if path.contains("//") || path.contains(';') {
        return false;
    }
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let (Some(high), Some(low)) = (
            bytes.get(index + 1).copied().and_then(uppercase_hex),
            bytes.get(index + 2).copied().and_then(uppercase_hex),
        ) else {
            return false;
        };
        let byte = (high << 4) | low;
        if byte.is_ascii_control()
            || byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.' | b'_' | b'~' | b':' | b'%' | b'/' | b'\\' | b'?' | b';'
            )
        {
            return false;
        }
        decoded.push(byte);
        index += 3;
    }
    std::str::from_utf8(&decoded).is_ok_and(|text| !text.chars().any(char::is_control))
}

/// The value of one uppercase hexadecimal digit.
fn uppercase_hex(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Whether `path` is the base path or beneath it at a segment boundary.
fn is_under(path: &str, base_path: &str) -> bool {
    base_path.is_empty()
        || path == base_path
        || path
            .strip_prefix(base_path)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Percent-encode everything but the RFC 3986 unreserved set.
pub(crate) fn percent_encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// `text` percent-encoded as one path segment, when that encoding is a
/// segment [`PinnedOrigin::pin`] admits: not empty, not a dot segment,
/// canonical by the same rule the pin applies to a link's path, and free of
/// the scalars the outbound transport refuses in a path. `None` for a value
/// that cannot stand as one segment of a pinned link.
pub(crate) fn encode_path_segment(text: &str) -> Option<String> {
    let encoded = percent_encode(text);
    if encoded.is_empty()
        || is_dot_segment(encoded.as_bytes())
        || text.chars().any(disallowed_path_scalar)
    {
        return None;
    }
    is_canonical_path(&format!("/{encoded}")).then_some(encoded)
}

#[cfg(test)]
mod segment_tests {
    use super::*;

    #[test]
    fn a_value_that_would_leave_its_segment_or_alias_another_is_not_a_segment() {
        for hostile in [
            "a\u{200b}b",
            "a\u{202e}b",
            "a\u{feff}b",
            "",
            ".",
            "..",
            "a/b",
            "a%2Fb",
            "a\\b",
            "a?b",
            "a;b",
            "a:b",
            "a%b",
            "a\u{1}b",
            "a\u{7f}b",
            "a\nb",
        ] {
            assert_eq!(encode_path_segment(hostile), None, "{hostile:?}");
        }
    }

    #[test]
    fn a_value_with_a_space_or_a_non_ascii_character_is_one_encoded_segment() {
        assert_eq!(encode_path_segment("a b").as_deref(), Some("a%20b"));
        assert_eq!(
            encode_path_segment("caf\u{e9}").as_deref(),
            Some("caf%C3%A9")
        );
        assert_eq!(
            encode_path_segment("EeBJ3Sn9uLg").as_deref(),
            Some("EeBJ3Sn9uLg")
        );
        assert_eq!(
            encode_path_segment("a.b-c_d~e").as_deref(),
            Some("a.b-c_d~e")
        );
    }

    #[test]
    fn every_segment_it_admits_passes_the_pin() {
        let origin = PinnedOrigin::new("https://source.example.invalid/api").expect("origin");
        for value in [
            "a b",
            "caf\u{e9}",
            "x!y",
            "a'b",
            "a(b)",
            "a,b",
            "a=b",
            "a@b",
            "a#b",
        ] {
            let Some(segment) = encode_path_segment(value) else {
                continue;
            };
            origin
                .pin(&format!("https://source.example.invalid/api/{segment}"))
                .unwrap_or_else(|refusal| panic!("{value:?}: {refusal}"));
        }
    }
}
