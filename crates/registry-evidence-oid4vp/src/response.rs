//! The wallet's authorization response: parsing, decryption, and the protocol
//! checks the service owns.
//!
//! The service checks protocol facts only: the response decrypts under the
//! session's key, echoes the session's `state`, and carries exactly the
//! presentations the policy's DCQL query asked for. It never opens, verifies,
//! or interprets a credential. Evidence does that.
//!
//! A response is `direct_post.jwt` (OpenID4VP 1.0 section 8.3.1): an
//! `application/x-www-form-urlencoded` body whose `response` member is a
//! compact JWE of a JSON object holding the section 8.1 parameters (section
//! 8.3). A wallet that cannot encrypt may send an error unencrypted (section
//! 8.3.1); that is the only plaintext shape accepted, and it needs the
//! session's `state`.

use std::collections::BTreeMap;

use registry_platform_canonical_json::parse_json_strict;
use registry_platform_crypto::{
    constant_time_eq,
    jwe::{decrypt_compact_ecdh_es, JweEnc, JweLimits},
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    config::PolicyConfig,
    session::{Digest32, FailureCategory, Held, Presentation, Session},
};

/// The largest single presentation, in bytes: the SD-JWT presentation size
/// the platform's SD-JWT limits allow (256 KiB).
pub const MAX_PRESENTATION_BYTES: usize = 256 * 1024;

/// The largest decrypted response, in bytes. It holds every presentation the
/// policy asks for (at most 8 credential queries), so a policy of one or two
/// maximum-size presentations fits and a larger policy relies on presentations
/// being smaller than the per-presentation bound. The cap also bounds what one
/// session can hold in memory: it is multiplied by `maximumLiveSessions`.
pub const MAX_PLAINTEXT_BYTES: usize = 512 * 1024;

const MAX_HEADER_BYTES: usize = 4 * 1024;
const MAX_PARTY_INFO_BYTES: usize = 512;
/// A JWE has an empty encrypted-key segment, a 12-byte IV (16 base64url
/// characters), a 16-byte tag (22 characters), and four separators.
const JWE_FIXED_BYTES: usize = 16 + 22 + 4;
/// `response=`.
const FORM_NAME_BYTES: usize = 9;
/// Room for the other members a wallet may add to the form.
const FORM_SLACK_BYTES: usize = 1024;

const fn encoded(decoded: usize) -> usize {
    decoded.div_ceil(3) * 4
}

/// The longest compact JWE accepted: the base64url ciphertext of the largest
/// plaintext, the base64url header, and the fixed segments.
const MAX_COMPACT_BYTES: usize =
    encoded(MAX_PLAINTEXT_BYTES) + encoded(MAX_HEADER_BYTES) + JWE_FIXED_BYTES;

/// The longest response body the route reads, bounded before any parsing:
/// the largest JWE, the form member name, and slack for sibling members.
pub const MAX_BODY_BYTES: usize = MAX_COMPACT_BYTES + FORM_NAME_BYTES + FORM_SLACK_BYTES;

/// The JWE size bounds.
#[must_use]
pub const fn jwe_limits() -> JweLimits {
    JweLimits {
        max_compact_bytes: MAX_COMPACT_BYTES,
        max_header_bytes: MAX_HEADER_BYTES,
        max_party_info_bytes: MAX_PARTY_INFO_BYTES,
        max_plaintext_bytes: MAX_PLAINTEXT_BYTES,
    }
}

/// Why a response was refused, a closed set that audit records carry. Nothing
/// beyond OAuth's `invalid_request` reaches the wallet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The body is not a response form of an accepted shape.
    Malformed,
    /// The JWE did not decrypt under the session's key with an accepted `enc`
    /// and the key's `kid`.
    Decryption,
    /// The payload is not a JSON object of the section 8.1 shape.
    Payload,
    /// `state` is missing or is not the session's.
    State,
    /// The `vp_token` does not match the policy's query.
    VpToken,
    /// The session already took a different response.
    AlreadySettled,
}

impl Refusal {
    /// The category an audit record carries.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Decryption => "decryption",
            Self::Payload => "payload",
            Self::State => "state",
            Self::VpToken => "vp_token",
            Self::AlreadySettled => "already_settled",
        }
    }
}

/// What a wallet posted.
#[derive(Debug)]
pub enum Submission {
    /// A compact JWE (section 8.3.1).
    Encrypted(String),
    /// An error sent without encryption (section 8.3.1, 8.2).
    PlainError { code: String, state: String },
}

impl Submission {
    /// Parse a form body (section 8.2: `application/x-www-form-urlencoded`,
    /// UTF-8).
    pub fn parse(body: &[u8]) -> Result<Self, Refusal> {
        let mut response = None;
        let mut error = None;
        let mut state = None;
        let mut forbidden_alongside = false;
        for (name, value) in url::form_urlencoded::parse(body) {
            let slot = match name.as_ref() {
                "response" => &mut response,
                "error" => &mut error,
                "state" => &mut state,
                // Plaintext presentation parameters are never accepted.
                "vp_token" | "id_token" | "code" => {
                    forbidden_alongside = true;
                    continue;
                }
                // Section 8.1: unrecognized parameters are ignored, and
                // `error_description` is never read.
                _ => continue,
            };
            if slot.replace(value.into_owned()).is_some() {
                return Err(Refusal::Malformed);
            }
        }
        if forbidden_alongside {
            return Err(Refusal::Malformed);
        }
        match (response, error, state) {
            (Some(response), None, None) if !response.is_empty() => Ok(Self::Encrypted(response)),
            (None, Some(code), Some(state)) => Ok(Self::PlainError { code, state }),
            _ => Err(Refusal::Malformed),
        }
    }

    /// A digest of the submitted bytes, for telling a retry from a different
    /// response.
    #[must_use]
    pub fn digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        match self {
            Self::Encrypted(response) => {
                hasher.update(b"jwe\0");
                hasher.update(response.as_bytes());
            }
            Self::PlainError { code, state } => {
                hasher.update(b"error\0");
                hasher.update(code.as_bytes());
                hasher.update(b"\0");
                hasher.update(state.as_bytes());
            }
        }
        hasher.finalize().into()
    }
}

/// Check a submission against `session` and its `policy`, returning what the
/// session would hold.
pub fn evaluate(
    session: &Session,
    policy: &PolicyConfig,
    submission: &Submission,
) -> Result<Held, Refusal> {
    match submission {
        Submission::PlainError { code, state } => {
            check_state(session, Some(state))?;
            Ok(Held::WalletError(FailureCategory::from_error_code(code)))
        }
        Submission::Encrypted(token) => evaluate_encrypted(session, policy, token),
    }
}

fn evaluate_encrypted(
    session: &Session,
    policy: &PolicyConfig,
    token: &str,
) -> Result<Held, Refusal> {
    let allowed: Vec<JweEnc> = policy
        .accepted_response_encryption
        .iter()
        .map(|enc| enc.jwe_enc())
        .collect();
    // Section 8.3: an unauthenticated `enc`, a `kid` other than the key's, a
    // failed key agreement, and a failed tag all read as one failure.
    let jwe = decrypt_compact_ecdh_es(token, &session.encryption_key, &allowed, &jwe_limits())
        .map_err(|_| Refusal::Decryption)?;
    // Section 8.3: the JWE carries the chosen key's `kid`. The session key has
    // one, so a response without it did not follow the request.
    if jwe.kid.is_none() {
        return Err(Refusal::Decryption);
    }
    // A repeated member would let the last value win, so the payload is parsed
    // strictly: a repeat is a refusal, not a choice.
    let Ok(Value::Object(mut payload)) = parse_json_strict(&jwe.plaintext) else {
        return Err(Refusal::Payload);
    };
    let outcome = interpret(session, policy, &mut payload);
    if outcome.is_err() {
        scrub(Value::Object(payload));
    }
    outcome
}

fn interpret(
    session: &Session,
    policy: &PolicyConfig,
    payload: &mut Map<String, Value>,
) -> Result<Held, Refusal> {
    check_state(
        session,
        match payload.get("state") {
            Some(Value::String(state)) => Some(state),
            _ => None,
        },
    )?;
    match (payload.get("error"), payload.get("vp_token")) {
        // Section 8.5: a wallet error. `error_description` is never read.
        (Some(Value::String(code)), None) => {
            Ok(Held::WalletError(FailureCategory::from_error_code(code)))
        }
        // Section 8.1.
        (None, Some(Value::Object(vp_token))) => {
            validate_vp_token(policy, vp_token)?;
            let Some(Value::Object(vp_token)) = payload.remove("vp_token") else {
                return Err(Refusal::Payload);
            };
            Ok(Held::Presentation(take_presentation(vp_token)))
        }
        _ => Err(Refusal::Payload),
    }
}

/// Section 5.2 and 8.2: the response echoes the request's `state`, compared in
/// constant time.
fn check_state(session: &Session, offered: Option<&String>) -> Result<(), Refusal> {
    match offered {
        Some(state) if constant_time_eq(state.as_bytes(), session.state.as_bytes()) => Ok(()),
        _ => Err(Refusal::State),
    }
}

/// Section 8.1: the object is keyed by the `id` of a credential query, each
/// value one presentation (the queries never set `multiple`), and every query
/// the policy asks for is answered (the DCQL query has no `credential_sets`,
/// so none is optional).
fn validate_vp_token(policy: &PolicyConfig, vp_token: &Map<String, Value>) -> Result<(), Refusal> {
    let known = |id: &str| policy.credentials.iter().any(|query| query.id == id);
    if vp_token.keys().any(|id| !known(id)) {
        return Err(Refusal::VpToken);
    }
    for query in &policy.credentials {
        let Some(Value::Array(presentations)) = vp_token.get(&query.id) else {
            return Err(Refusal::VpToken);
        };
        match presentations.as_slice() {
            [Value::String(presentation)]
                if !presentation.is_empty() && presentation.len() <= MAX_PRESENTATION_BYTES => {}
            _ => return Err(Refusal::VpToken),
        }
    }
    Ok(())
}

/// Move the validated presentation strings into zeroizing holders.
fn take_presentation(vp_token: Map<String, Value>) -> Presentation {
    let entries: BTreeMap<String, Vec<Zeroizing<String>>> = vp_token
        .into_iter()
        .map(|(id, value)| {
            let Value::Array(values) = value else {
                unreachable!("validated as an array")
            };
            let held = values
                .into_iter()
                .map(|value| {
                    let Value::String(value) = value else {
                        unreachable!("validated as a string")
                    };
                    Zeroizing::new(value)
                })
                .collect();
            (id, held)
        })
        .collect();
    Presentation::new(entries)
}

/// Zeroize every string of a value before it is dropped.
fn scrub(value: Value) {
    match value {
        Value::String(mut text) => text.zeroize(),
        Value::Array(values) => values.into_iter().for_each(scrub),
        Value::Object(members) => members.into_iter().for_each(|(_, value)| scrub(value)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_bound_covers_the_largest_compact_jwe() {
        const { assert!(MAX_BODY_BYTES > MAX_COMPACT_BYTES + FORM_NAME_BYTES) };
        // 512 KiB of plaintext is 699,052 base64url characters.
        assert_eq!(encoded(MAX_PLAINTEXT_BYTES), 699_052);
        const { assert!(MAX_BODY_BYTES < 1024 * 1024) };
    }

    #[test]
    fn a_form_is_one_encrypted_response_or_one_plain_error() {
        assert!(matches!(
            Submission::parse(b"response=a.b.c.d.e"),
            Ok(Submission::Encrypted(_))
        ));
        assert!(matches!(
            Submission::parse(b"error=access_denied&state=s&error_description=x"),
            Ok(Submission::PlainError { .. })
        ));
        for body in [
            &b""[..],
            b"other=1",
            b"response=",
            b"response=a&response=b",
            b"response=a&state=s",
            b"response=a&error=access_denied",
            b"error=access_denied",
            b"state=s",
            b"vp_token=%7B%7D&state=s",
            b"error=a&state=s&state=t",
        ] {
            assert_eq!(
                Submission::parse(body).unwrap_err(),
                Refusal::Malformed,
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn error_codes_map_into_a_closed_category() {
        assert_eq!(
            FailureCategory::from_error_code("access_denied"),
            FailureCategory::AccessDenied
        );
        assert_eq!(
            FailureCategory::from_error_code("Maria Santos refused"),
            FailureCategory::Other
        );
    }

    #[test]
    fn digests_separate_the_two_shapes() {
        let encrypted = Submission::Encrypted("a".to_owned()).digest();
        let plain = Submission::PlainError {
            code: "a".to_owned(),
            state: String::new(),
        }
        .digest();
        assert_ne!(encrypted, plain);
    }
}
