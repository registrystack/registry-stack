// SPDX-License-Identifier: Apache-2.0
//! The third-party SD-JWT VC verification pipeline.

use crate::policy::{ChannelPolicy, SessionContext};
use crate::refusal::PresentationRefusal as Refusal;
use crate::trust::{IssuerTrust, KeySource};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use registry_platform_crypto::jws::{parse_compact_jws, JwsError, JwsLimits};
use registry_platform_crypto::{parse_did_jwk, parse_json_strict, PublicJwk, SigningAlgorithm};
use registry_platform_sdjwt::{
    parse_presentation, resolve_disclosures, validate_key_binding_jwt_with_options,
    KeyBindingOptions, KeyBindingPolicy, PresentationError, SdJwtError, SdJwtLimits,
};
use registry_platform_x509::{verify_chain, VerifiedLeaf, X5cChain};
use serde_json::{Map, Value};
use std::fmt;
use std::time::Duration;

/// The only accepted issuer JWT `typ` (SD-JWT VC draft-13 section 3.2.1,
/// draft-25 section 2.2.1).
const ISSUER_TYP: &str = "dc+sd-jwt";

/// Header parameters through which a token nominates its own key or processing
/// rules. `crit` and `b64` are refused by the JWS parser.
const FORBIDDEN_HEADER_PARAMETERS: [&str; 4] = ["jku", "jwk", "x5u", "crit"];

/// Claims that SD-JWT VC forbids selectively disclosing (draft-25 section 2.2.2.2).
const NEVER_DISCLOSED: [&str; 6] = ["iss", "nbf", "exp", "cnf", "vct", "status"];

/// A credential that passed every check.
#[derive(Clone, PartialEq)]
pub struct VerifiedCredential {
    /// The id of the trust entry that matched.
    pub trust_entry: String,
    /// The credential's `iss`.
    pub issuer: String,
    /// The credential's `vct`.
    pub vct: String,
    /// The credential's `iat`; a credential without one is refused.
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    /// Whether a key-binding JWT was present and valid.
    pub key_bound: bool,
    /// Whether the credential carries a `status` reference. Status is not
    /// checked here.
    pub status_reference_present: bool,
    /// The disclosed claim set, without `_sd`, `_sd_alg` and `cnf`.
    pub claims: Map<String, Value>,
}

impl fmt::Debug for VerifiedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedCredential")
            .field("trust_entry", &self.trust_entry)
            .field("issuer", &self.issuer)
            .field("vct", &self.vct)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("key_bound", &self.key_bound)
            .field("status_reference_present", &self.status_reference_present)
            .field("claims", &"[redacted]")
            .finish()
    }
}

/// Verify a presented SD-JWT VC.
///
/// Checks run in a fixed order and stop at the first failure: bounds and
/// split; issuer JWT header; the deny-list; `iss` and its trust entry; issuer key; issuer
/// signature; `vct`; disclosures; validity times; holder key; key binding.
/// `now` is the evaluation instant in Unix seconds.
pub fn verify_sd_jwt_vc(
    presentation: &str,
    ctx: &SessionContext,
    trust: &IssuerTrust,
    policy: &ChannelPolicy,
    now: i64,
) -> Result<VerifiedCredential, Refusal> {
    let limits = SdJwtLimits::default();
    let parsed = parse_presentation(presentation, &limits).map_err(split_refusal)?;
    let jws =
        parse_compact_jws(parsed.issuer_jwt, &JwsLimits::default()).map_err(|err| match err {
            JwsError::TooLarge => Refusal::PresentationTooLarge,
            JwsError::UnsupportedHeader => Refusal::ForbiddenHeaderParameter,
            _ => Refusal::MalformedPresentation,
        })?;

    let header = jws.header();
    if header.get("typ").and_then(Value::as_str) != Some(ISSUER_TYP) {
        return Err(Refusal::IssuerTypeInvalid);
    }
    let allowed: Vec<SigningAlgorithm> = policy
        .issuer_algorithms
        .iter()
        .map(|algorithm| algorithm.signing_algorithm())
        .collect();
    // `algorithm` refuses `none` and anything unknown.
    let algorithm = jws
        .algorithm()
        .map_err(|_| Refusal::IssuerAlgorithmNotAllowed)?;
    if !allowed.contains(&algorithm) {
        return Err(Refusal::IssuerAlgorithmNotAllowed);
    }
    if FORBIDDEN_HEADER_PARAMETERS
        .iter()
        .any(|name| header.contains_key(*name))
    {
        return Err(Refusal::ForbiddenHeaderParameter);
    }

    // The unverified `iss` only selects which configured entry's key verifies
    // the signature.
    let selector = unverified_issuer(parsed.issuer_jwt)?;
    // The deny-list is consulted before the allow-list and before any key
    // lookup or signature check.
    if trust.deny_list().denies_issuer(&selector) || denied_certificate(header, trust) {
        return Err(Refusal::IssuerDenied);
    }
    let entry = trust
        .entry_for_issuer(&selector)
        .ok_or(Refusal::IssuerUntrusted)?;

    let issuer_key = match &entry.key_source {
        KeySource::X5c { anchors, policy } => {
            let x5c = header
                .get("x5c")
                .and_then(Value::as_array)
                .ok_or(Refusal::CertificateChainInvalid)?;
            let encoded: Vec<&str> = x5c
                .iter()
                .map(|cert| cert.as_str().ok_or(Refusal::CertificateChainInvalid))
                .collect::<Result<_, _>>()?;
            let chain = X5cChain::parse(&encoded).map_err(|_| Refusal::CertificateChainInvalid)?;
            let leaf = verify_chain(&chain, anchors, policy, now)
                .map_err(|_| Refusal::CertificateChainInvalid)?;
            if !issuer_bound_to_leaf(&selector, &leaf) {
                return Err(Refusal::IssuerNotBoundToCertificate);
            }
            leaf.public_jwk
        }
        KeySource::Jwks(keys) => {
            if header.contains_key("x5c") {
                return Err(Refusal::ForbiddenHeaderParameter);
            }
            let kid = header
                .get("kid")
                .and_then(Value::as_str)
                .ok_or(Refusal::IssuerKeyIdUnknown)?;
            keys.iter()
                .find(|key| key.kid.as_deref() == Some(kid))
                .cloned()
                .ok_or(Refusal::IssuerKeyIdUnknown)?
        }
    };

    let payload_bytes = jws
        .verify(&issuer_key, &allowed)
        .map_err(|_| Refusal::IssuerSignatureInvalid)?;
    // These are the bytes `selector` was read from, now authenticated.
    let Ok(Value::Object(payload)) = parse_json_strict(payload_bytes) else {
        return Err(Refusal::MalformedPresentation);
    };

    let vct = payload
        .get("vct")
        .and_then(Value::as_str)
        .ok_or(Refusal::CredentialTypeMissing)?;
    if !policy.vct.iter().any(|accepted| accepted == vct)
        || !entry.vct.iter().any(|allowed| allowed == vct)
    {
        return Err(Refusal::CredentialTypeNotAccepted);
    }

    let mut claims = resolve_disclosures(&payload, &parsed.disclosures, &limits)
        .map_err(|_| Refusal::DisclosureInvalid)?;
    // A claim in this list must come from the signed payload unchanged: the
    // resolved value differs when a disclosure supplied it or reached into it.
    if NEVER_DISCLOSED
        .iter()
        .any(|name| payload.get(*name) != claims.get(*name))
    {
        return Err(Refusal::ClaimNotDisclosable);
    }

    let expires_at = optional_time(&payload, "exp")?;
    let not_before = optional_time(&payload, "nbf")?;
    let skew = i64::from(policy.clock_skew_seconds);
    if expires_at.is_some_and(|exp| now.saturating_sub(skew) >= exp) {
        return Err(Refusal::CredentialExpired);
    }
    if not_before.is_some_and(|nbf| nbf.saturating_sub(skew) > now) {
        return Err(Refusal::CredentialNotYetValid);
    }
    let issued_at = optional_time(&payload, "iat")?.ok_or(Refusal::IssuedAtMissing)?;
    if issued_at.saturating_sub(skew) > now {
        return Err(Refusal::IssuedAtInFuture);
    }

    let holder_key = payload.get("cnf").map(holder_key).transpose()?;
    let key_bound = match parsed.key_binding_jwt {
        None if policy.key_binding_required => return Err(Refusal::KeyBindingRequired),
        None => false,
        Some(kb_jwt) => {
            let holder_key = holder_key.as_ref().ok_or(Refusal::HolderKeyInvalid)?;
            let kb_policy = KeyBindingPolicy {
                audience: ctx.client_id.clone(),
                nonce: ctx.nonce.clone(),
                max_age: Duration::from_secs(u64::from(policy.kb_iat_window_seconds)),
                max_future_skew: Duration::from_secs(u64::from(policy.clock_skew_seconds)),
            };
            validate_key_binding_jwt_with_options(
                kb_jwt,
                holder_key,
                parsed.sd_hash_input,
                &kb_policy,
                &KeyBindingOptions::third_party(),
                ctx.received_at,
            )
            .map_err(|_| Refusal::KeyBindingInvalid)?;
            true
        }
    };

    claims.remove("cnf");
    claims.remove("_sd");
    Ok(VerifiedCredential {
        trust_entry: entry.id.clone(),
        issuer: selector,
        vct: vct.to_owned(),
        issued_at,
        expires_at,
        key_bound,
        status_reference_present: payload.contains_key("status"),
        claims,
    })
}

/// Whether any certificate in the unverified `x5c` header is on the deny-list.
/// An entry that is not a decodable string is left for chain verification to
/// refuse.
fn denied_certificate(header: &Map<String, Value>, trust: &IssuerTrust) -> bool {
    header
        .get("x5c")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|encoded| STANDARD.decode(encoded).ok())
        .any(|der| trust.deny_list().denies_certificate(&der))
}

fn split_refusal(err: SdJwtError) -> Refusal {
    match err {
        SdJwtError::Presentation(
            PresentationError::TooLarge | PresentationError::TooManyDisclosures,
        ) => Refusal::PresentationTooLarge,
        _ => Refusal::MalformedPresentation,
    }
}

/// The `iss` of an issuer JWT whose signature is not yet verified. The segment
/// was bounded by the JWS parser.
fn unverified_issuer(issuer_jwt: &str) -> Result<String, Refusal> {
    let segment = issuer_jwt
        .split('.')
        .nth(1)
        .ok_or(Refusal::MalformedPresentation)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| Refusal::MalformedPresentation)?;
    let Ok(Value::Object(payload)) = parse_json_strict(&bytes) else {
        return Err(Refusal::MalformedPresentation);
    };
    match payload.get("iss") {
        None => Err(Refusal::IssuerMissing),
        Some(Value::String(iss)) => Ok(iss.clone()),
        Some(_) => Err(Refusal::IssuerUntrusted),
    }
}

/// Whether `iss` is bound to the verified leaf certificate through its
/// subjectAltName.
///
/// SD-JWT VC draft-13 section 3.5 makes the subject of the end-entity
/// certificate the issuer and defines no comparison with `iss`. Draft-25
/// section 2.5 says the `x5c` mechanism does not authenticate `iss`, and a
/// recipient treats it as identifying the issuer only when its policy binds it
/// to the end-entity certificate, for example through a Subject Alternative
/// Name (RFC 5280 section 4.2.1.6), and has verified that binding. The stricter
/// reading applies: the binding is required, and it holds when
///
/// - a `uniformResourceIdentifier` SAN equals `iss` exactly, or
/// - `iss` is an `https` URL and a `dNSName` SAN equals its host
///   (ASCII case-insensitive, no wildcard matching).
fn issuer_bound_to_leaf(iss: &str, leaf: &VerifiedLeaf) -> bool {
    if leaf.san_uris.iter().any(|uri| uri == iss) {
        return true;
    }
    https_host(iss).is_some_and(|host| {
        leaf.san_dns_names
            .iter()
            .any(|dns| dns.eq_ignore_ascii_case(host))
    })
}

/// The host of an `https` URL without userinfo, port, or brackets.
fn https_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains(['@', '[', ']']) {
        return None;
    }
    let host = match authority.split_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        Some(_) => return None,
        None => authority,
    };
    (!host.is_empty()).then_some(host)
}

fn optional_time(payload: &Map<String, Value>, name: &str) -> Result<Option<i64>, Refusal> {
    payload
        .get(name)
        .map(|value| value.as_i64().ok_or(Refusal::TimeClaimMalformed))
        .transpose()
}

/// The holder key a `cnf` names: exactly one of `jwk`, or `kid` holding a
/// `did:jwk` that is decoded locally. Nothing is resolved.
fn holder_key(cnf: &Value) -> Result<PublicJwk, Refusal> {
    let members = cnf.as_object().ok_or(Refusal::HolderKeyInvalid)?;
    if members.len() != 1 {
        return Err(Refusal::HolderKeyInvalid);
    }
    let key = if let Some(jwk) = members.get("jwk") {
        let mut jwk = jwk.clone();
        infer_p256_algorithm(&mut jwk);
        let text = serde_json::to_string(&jwk).map_err(|_| Refusal::HolderKeyInvalid)?;
        PublicJwk::parse(&text).map_err(|_| Refusal::HolderKeyInvalid)?
    } else if let Some(kid) = members.get("kid").and_then(Value::as_str) {
        if !kid.starts_with("did:jwk:") || kid.split_once('#').is_some_and(|(_, f)| f != "0") {
            return Err(Refusal::HolderKeyInvalid);
        }
        parse_did_jwk(kid).map_err(|_| Refusal::HolderKeyInvalid)?
    } else {
        return Err(Refusal::HolderKeyInvalid);
    };
    match key.algorithm() {
        Ok(SigningAlgorithm::Es256 | SigningAlgorithm::EdDsa) => Ok(key),
        _ => Err(Refusal::HolderKeyInvalid),
    }
}

/// Wallets and issuers publish P-256 JWKs without `alg`, while the platform
/// requires one for every key type but Ed25519. A P-256 key can only be ES256,
/// so name it. An explicit `alg` is left for the platform to check.
fn infer_p256_algorithm(jwk: &mut Value) {
    let Some(members) = jwk.as_object_mut() else {
        return;
    };
    if !members.contains_key("alg")
        && members.get("kty").and_then(Value::as_str) == Some("EC")
        && members.get("crv").and_then(Value::as_str) == Some("P-256")
    {
        members.insert("alg".to_owned(), Value::String("ES256".to_owned()));
    }
}
