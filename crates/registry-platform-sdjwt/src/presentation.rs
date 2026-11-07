// SPDX-License-Identifier: Apache-2.0
//! RFC 9901 presentation parsing and disclosure resolution.
//!
//! [`parse_presentation`] splits an SD-JWT or SD-JWT+KB into its parts after
//! bounding its size and disclosure count. [`resolve_disclosures`] rebuilds the
//! disclosed claim set from a payload whose issuer signature the caller has
//! already verified, following RFC 9901 section 7.1. Nothing here verifies a
//! signature or decides which claims a caller may rely on.
//!
//! Errors are a closed set of categories. They never contain the presentation,
//! a disclosure, a claim name, or a claim value.

use crate::SdJwtError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::parse_json_strict;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// The only digest algorithm accepted for `_sd_alg`, and the default when the
/// claim is absent (RFC 9901 section 4.1.1).
const SD_ALG_SHA_256: &str = "sha-256";

/// Claim names a Disclosure may never carry: the two reserved markers of
/// RFC 9901 section 4.2.2, and `_sd_alg`, which is consumed by the resolver and
/// removed from its output.
const RESERVED_CLAIM_NAMES: [&str; 3] = ["_sd", "...", "_sd_alg"];

/// Bounds applied to an untrusted presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdJwtLimits {
    /// Longest accepted serialized presentation, in bytes.
    pub max_serialized_bytes: usize,
    /// Most Disclosures accepted in one presentation.
    pub max_disclosures: usize,
    /// Longest accepted encoded Disclosure, in bytes.
    pub max_disclosure_bytes: usize,
    /// Deepest accepted claim nesting, counting recursive Disclosures.
    pub max_depth: usize,
    /// Most JSON values and digests visited while resolving.
    pub max_nodes: usize,
}

impl Default for SdJwtLimits {
    fn default() -> Self {
        Self {
            max_serialized_bytes: 256 * 1024,
            max_disclosures: 128,
            max_disclosure_bytes: 16 * 1024,
            max_depth: 16,
            max_nodes: 50_000,
        }
    }
}

/// Closed set of presentation failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PresentationError {
    #[error("presentation exceeds a size limit")]
    TooLarge,
    #[error("presentation carries too many disclosures")]
    TooManyDisclosures,
    #[error("malformed presentation")]
    Malformed,
    #[error("malformed disclosure")]
    MalformedDisclosure,
    #[error("malformed selective-disclosure marker in the payload")]
    MalformedPayload,
    #[error("unsupported selective-disclosure hash algorithm")]
    UnsupportedHashAlgorithm,
    #[error("a digest appears more than once")]
    DuplicateDigest,
    #[error("a disclosure appears more than once")]
    DuplicateDisclosure,
    #[error("a disclosure is not referenced by any digest")]
    UnreferencedDisclosure,
    #[error("a disclosed claim name already exists at that level")]
    ClaimNameCollision,
    #[error("a disclosure uses a reserved claim name")]
    ReservedClaimName,
    #[error("claim nesting exceeds the depth limit")]
    DepthExceeded,
}

/// A presentation split into its parts. The parts borrow the input and are not
/// yet trusted: nothing has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPresentation<'a> {
    /// The issuer-signed JWT, three non-empty compact segments.
    pub issuer_jwt: &'a str,
    /// The encoded Disclosures, in presentation order.
    pub disclosures: Vec<&'a str>,
    /// The key-binding JWT, when the presentation carries one.
    pub key_binding_jwt: Option<&'a str>,
    /// The presentation up to and including its last `~`: the bytes `sd_hash`
    /// covers (RFC 9901 section 4.3.1).
    pub sd_hash_input: &'a str,
}

impl ParsedPresentation<'_> {
    /// The `sd_hash` a key-binding JWT over this presentation must carry.
    #[must_use]
    pub fn sd_hash(&self) -> String {
        sd_hash(self.sd_hash_input)
    }
}

/// The `sd_hash` of the SD-JWT part of a presentation: the unpadded base64url
/// SHA-256 of `sd_hash_input`, which is the presentation up to and including
/// its last `~`.
#[must_use]
pub fn sd_hash(sd_hash_input: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(sd_hash_input.as_bytes()))
}

/// Split a presentation into issuer JWT, Disclosures, and optional key-binding
/// JWT.
///
/// The total size, the Disclosure count, and each Disclosure's size are bounded
/// before any Disclosure is decoded. A presentation always ends in `~`, so an
/// SD-JWT with no key-binding JWT has an empty final element; a compact JWT
/// with no `~` at all is refused.
pub fn parse_presentation<'a>(
    serialized: &'a str,
    limits: &SdJwtLimits,
) -> Result<ParsedPresentation<'a>, SdJwtError> {
    if serialized.len() > limits.max_serialized_bytes {
        return Err(PresentationError::TooLarge.into());
    }
    let last_tilde = serialized.rfind('~').ok_or(PresentationError::Malformed)?;
    let sd_hash_input = &serialized[..=last_tilde];
    let key_binding = &serialized[last_tilde + 1..];

    let mut parts = sd_hash_input[..last_tilde].split('~');
    let issuer_jwt = parts.next().ok_or(PresentationError::Malformed)?;
    if !is_compact_shape(issuer_jwt) {
        return Err(PresentationError::Malformed.into());
    }
    let mut disclosures = Vec::new();
    for disclosure in parts {
        if disclosures.len() == limits.max_disclosures {
            return Err(PresentationError::TooManyDisclosures.into());
        }
        if disclosure.is_empty() {
            return Err(PresentationError::Malformed.into());
        }
        if disclosure.len() > limits.max_disclosure_bytes {
            return Err(PresentationError::TooLarge.into());
        }
        if !disclosure
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(PresentationError::Malformed.into());
        }
        disclosures.push(disclosure);
    }
    let key_binding_jwt = if key_binding.is_empty() {
        None
    } else if is_compact_shape(key_binding) {
        Some(key_binding)
    } else {
        return Err(PresentationError::Malformed.into());
    };
    Ok(ParsedPresentation {
        issuer_jwt,
        disclosures,
        key_binding_jwt,
        sd_hash_input,
    })
}

/// Three non-empty dot-separated segments. Decoding is left to the JWS parser.
fn is_compact_shape(token: &str) -> bool {
    let mut segments = token.split('.');
    let shaped = (0..3).all(|_| segments.next().is_some_and(|segment| !segment.is_empty()));
    shaped && segments.next().is_none()
}

/// Rebuild the disclosed claim set from a verified issuer payload and the
/// presented Disclosures, per RFC 9901 section 7.1.
///
/// `_sd` and `_sd_alg` are removed from the result. Digests that match no
/// Disclosure are decoys and are ignored. A Disclosure may itself contain `_sd`
/// or `...` markers, and is resolved recursively.
///
/// Refused: an `_sd_alg` other than `sha-256`; a digest that appears more than
/// once anywhere in the payload or in a disclosed value, or a Disclosure
/// presented twice; a Disclosure no digest references; a disclosed claim name
/// that already exists at that level; the reserved names `_sd`, `...` and
/// `_sd_alg`; a Disclosure of the wrong arity, with a non-string salt or name,
/// or of the wrong kind for the marker that references it; nesting or work past
/// the limits.
pub fn resolve_disclosures(
    payload: &Map<String, Value>,
    disclosures: &[&str],
    limits: &SdJwtLimits,
) -> Result<Map<String, Value>, SdJwtError> {
    if disclosures.len() > limits.max_disclosures {
        return Err(PresentationError::TooManyDisclosures.into());
    }
    match payload.get("_sd_alg") {
        None => {}
        Some(Value::String(alg)) if alg == SD_ALG_SHA_256 => {}
        Some(_) => return Err(PresentationError::UnsupportedHashAlgorithm.into()),
    }
    let mut resolver = Resolver {
        limits,
        table: decode_disclosures(disclosures, limits)?,
        seen: HashSet::new(),
        nodes: 0,
    };
    let mut claims = resolver.walk_object(payload, 0)?;
    claims.remove("_sd_alg");
    if resolver.table.values().any(|entry| !entry.referenced) {
        return Err(PresentationError::UnreferencedDisclosure.into());
    }
    Ok(claims)
}

/// A decoded Disclosure. `name` is `None` for an array element Disclosure.
struct Disclosed {
    name: Option<String>,
    value: Value,
    referenced: bool,
}

fn decode_disclosures(
    disclosures: &[&str],
    limits: &SdJwtLimits,
) -> Result<HashMap<String, Disclosed>, PresentationError> {
    let mut table = HashMap::with_capacity(disclosures.len());
    for encoded in disclosures {
        if encoded.len() > limits.max_disclosure_bytes {
            return Err(PresentationError::TooLarge);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| PresentationError::MalformedDisclosure)?;
        let Ok(Value::Array(mut elements)) = parse_json_strict(&bytes) else {
            return Err(PresentationError::MalformedDisclosure);
        };
        let arity = elements.len();
        if !matches!(arity, 2 | 3) || !elements[0].is_string() {
            return Err(PresentationError::MalformedDisclosure);
        }
        let value = elements.pop().unwrap_or(Value::Null);
        let name = if arity == 3 {
            let Some(Value::String(name)) = elements.pop() else {
                return Err(PresentationError::MalformedDisclosure);
            };
            if RESERVED_CLAIM_NAMES.contains(&name.as_str()) {
                return Err(PresentationError::ReservedClaimName);
            }
            Some(name)
        } else {
            None
        };
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()));
        let entry = Disclosed {
            name,
            value,
            referenced: false,
        };
        if table.insert(digest, entry).is_some() {
            return Err(PresentationError::DuplicateDisclosure);
        }
    }
    Ok(table)
}

struct Resolver<'l> {
    limits: &'l SdJwtLimits,
    table: HashMap<String, Disclosed>,
    seen: HashSet<String>,
    nodes: usize,
}

impl Resolver<'_> {
    fn count_node(&mut self) -> Result<(), PresentationError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            return Err(PresentationError::TooLarge);
        }
        Ok(())
    }

    /// Record a digest, refusing one already seen anywhere in the payload.
    fn see(&mut self, digest: &str) -> Result<(), PresentationError> {
        self.count_node()?;
        if self.seen.insert(digest.to_owned()) {
            Ok(())
        } else {
            Err(PresentationError::DuplicateDigest)
        }
    }

    /// Claim the Disclosure `digest` names, if any, and hand back its parts.
    /// `want_name` is whether the referencing marker needs an object-property
    /// Disclosure (`_sd`) or an array-element one (`...`).
    fn take(
        &mut self,
        digest: &str,
        want_name: bool,
    ) -> Result<Option<(Option<String>, Value)>, PresentationError> {
        let Some(entry) = self.table.get_mut(digest) else {
            return Ok(None);
        };
        if entry.name.is_some() != want_name {
            return Err(PresentationError::MalformedDisclosure);
        }
        entry.referenced = true;
        Ok(Some((entry.name.take(), std::mem::take(&mut entry.value))))
    }

    fn walk(&mut self, value: &Value, depth: usize) -> Result<Value, PresentationError> {
        self.count_node()?;
        if depth > self.limits.max_depth {
            return Err(PresentationError::DepthExceeded);
        }
        match value {
            Value::Object(members) => self.walk_object(members, depth).map(Value::Object),
            Value::Array(items) => self.walk_array(items, depth).map(Value::Array),
            other => Ok(other.clone()),
        }
    }

    fn walk_object(
        &mut self,
        members: &Map<String, Value>,
        depth: usize,
    ) -> Result<Map<String, Value>, PresentationError> {
        if depth > self.limits.max_depth {
            return Err(PresentationError::DepthExceeded);
        }
        let mut out = Map::new();
        for (name, value) in members {
            if name != "_sd" {
                out.insert(name.clone(), self.walk(value, depth + 1)?);
            }
        }
        let Some(sd) = members.get("_sd") else {
            return Ok(out);
        };
        let Value::Array(digests) = sd else {
            return Err(PresentationError::MalformedPayload);
        };
        for digest in digests {
            let Value::String(digest) = digest else {
                return Err(PresentationError::MalformedPayload);
            };
            self.see(digest)?;
            let Some((Some(name), value)) = self.take(digest, true)? else {
                continue;
            };
            if out.contains_key(&name) {
                return Err(PresentationError::ClaimNameCollision);
            }
            out.insert(name, self.walk(&value, depth + 1)?);
        }
        Ok(out)
    }

    fn walk_array(
        &mut self,
        items: &[Value],
        depth: usize,
    ) -> Result<Vec<Value>, PresentationError> {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let Some(marker) = item.as_object().filter(|m| m.contains_key("...")) else {
                out.push(self.walk(item, depth + 1)?);
                continue;
            };
            let (1, Some(Value::String(digest))) = (marker.len(), marker.get("...")) else {
                return Err(PresentationError::MalformedPayload);
            };
            self.see(digest)?;
            if let Some((_, value)) = self.take(digest, false)? {
                out.push(self.walk(&value, depth + 1)?);
            }
        }
        Ok(out)
    }
}
