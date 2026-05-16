// SPDX-License-Identifier: Apache-2.0
//! `Accept` header content negotiation for provenance issuance.
//!
//! The gateway only issues a signed VC when the caller explicitly asks
//! for one via `Accept`. Plain JSON paths are byte-equivalent to a
//! build without Wave 3 (see decision D6 / D11). The set of acceptable
//! media types comes from
//! [`crate::config::ProvenanceConfig::accepted_media_types`].
//!
//! ## Algorithm (RFC 9110 §12.5.1)
//!
//! 1. Parse the `Accept` header into a list of `(media_type, q)` pairs.
//!    The default q is 1.0; malformed q values are treated as if
//!    absent. q values outside `[0, 1]` are clamped (the upper bound is
//!    informational only since we only ever compare q values to each
//!    other).
//! 2. Find the highest q value among the offers that match one of the
//!    configured `accepted_types` (case-insensitive, full
//!    `type/subtype` only: wildcards never opt in to a signed VC since
//!    the wave-3 contract is explicit selection).
//! 3. Find the highest q value among all other offers (the plain-JSON
//!    fallback). A `q=0` on a VC offer is an explicit "not acceptable"
//!    and excludes that offer entirely.
//! 4. Return [`NegotiationOutcome::SignedVc`] iff the VC's best q is
//!    strictly greater than 0 AND at least as large as the best
//!    non-VC q. Ties resolve to `SignedVc` because the VC opt-in is
//!    a deliberate, explicit selection.
//! 5. When the header is absent we return
//!    [`NegotiationOutcome::PlainJson`] so legacy clients keep their
//!    wave-2 contract.
//!
//! We never mutate the Accept header; we only inspect it.

use axum::http::HeaderMap;

/// Result of inspecting a caller's `Accept` header against the
/// configured set of provenance media types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationOutcome {
    /// Caller wants the wave-2 plain-JSON shape (default).
    PlainJson,
    /// Caller wants a signed VC and the gateway can serve one.
    SignedVc,
}

/// One `(media_type, q)` pair parsed out of an `Accept` header.
struct AcceptOffer<'a> {
    media_type: &'a str,
    q: f32,
}

/// Parse a single entry from the comma-separated `Accept` header into
/// an [`AcceptOffer`]. Returns `None` when the entry is empty after
/// trimming.
fn parse_offer(raw: &str) -> Option<AcceptOffer<'_>> {
    let mut parts = raw.split(';');
    let media_type = parts.next()?.trim();
    if media_type.is_empty() {
        return None;
    }
    let mut q = 1.0_f32;
    for param in parts {
        let param = param.trim();
        // RFC 9110: parameter names are case-insensitive.
        let Some(rest) = param
            .strip_prefix("q=")
            .or_else(|| param.strip_prefix("Q="))
        else {
            continue;
        };
        let parsed: Result<f32, _> = rest.trim().parse();
        // Malformed q values are treated as absent (q stays at 1.0).
        if let Ok(value) = parsed {
            if value.is_finite() {
                q = value.clamp(0.0, 1.0);
            }
        }
    }
    Some(AcceptOffer { media_type, q })
}

/// Inspect the `Accept` header and return whether the caller is asking
/// for a signed VC.
///
/// `accepted_types` is the configured list (e.g.
/// `["application/vc+jwt", "application/jwt"]`). Media-type comparison
/// is case-insensitive on the literal `type/subtype` only; wildcards
/// (`*/*`, `application/*`) never opt in because the wave-3 contract
/// requires explicit selection. q values follow RFC 9110 §12.5.1.
#[must_use]
pub fn negotiate(headers: &HeaderMap, accepted_types: &[String]) -> NegotiationOutcome {
    let Some(accept) = headers.get(axum::http::header::ACCEPT) else {
        return NegotiationOutcome::PlainJson;
    };
    let Ok(accept) = accept.to_str() else {
        return NegotiationOutcome::PlainJson;
    };
    if accepted_types.is_empty() {
        return NegotiationOutcome::PlainJson;
    }

    let mut best_vc_q: Option<f32> = None;
    let mut best_other_q: Option<f32> = None;
    for raw in accept.split(',') {
        let Some(offer) = parse_offer(raw) else {
            continue;
        };
        let is_vc = accepted_types
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(offer.media_type));
        let target = if is_vc {
            &mut best_vc_q
        } else {
            &mut best_other_q
        };
        match *target {
            Some(current) if current >= offer.q => {}
            _ => *target = Some(offer.q),
        }
    }

    match (best_vc_q, best_other_q) {
        // q=0 is an explicit "not acceptable"; treat the offer as absent.
        (Some(vc_q), _) if vc_q <= 0.0 => NegotiationOutcome::PlainJson,
        (Some(vc_q), Some(other_q)) if vc_q + f32::EPSILON < other_q => {
            NegotiationOutcome::PlainJson
        }
        (Some(_), _) => NegotiationOutcome::SignedVc,
        (None, _) => NegotiationOutcome::PlainJson,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn accepted() -> Vec<String> {
        vec![
            "application/vc+jwt".to_string(),
            "application/jwt".to_string(),
        ]
    }

    #[test]
    fn absent_accept_returns_plain_json() {
        let headers = HeaderMap::new();
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::PlainJson
        );
    }

    #[test]
    fn exact_match_returns_signed_vc() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("application/vc+jwt"));
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::SignedVc
        );
    }

    #[test]
    fn parameters_are_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/vc+jwt; q=0.9"),
        );
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::SignedVc
        );
    }

    #[test]
    fn case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("Application/VC+JWT"));
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::SignedVc
        );
    }

    #[test]
    fn list_with_other_first_still_matches() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/json, application/vc+jwt"),
        );
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::SignedVc
        );
    }

    #[test]
    fn json_only_returns_plain_json() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("application/json"));
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::PlainJson
        );
    }

    #[test]
    fn empty_accepted_list_never_matches() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("application/vc+jwt"));
        assert_eq!(negotiate(&headers, &[]), NegotiationOutcome::PlainJson);
    }

    // ---- q-value coverage (RFC 9110 §12.5.1) ----

    #[test]
    fn q_zero_on_vc_jwt_means_plain_json_even_when_listed() {
        // RFC 9110: q=0 is an explicit "not acceptable". The caller
        // sending `application/vc+jwt;q=0` is telling us they do not
        // want the signed VC, so we must serve plain JSON.
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/vc+jwt;q=0, application/json"),
        );
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::PlainJson
        );
    }

    #[test]
    fn higher_q_on_vc_jwt_wins_over_lower_q_on_json() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/json;q=0.5, application/vc+jwt;q=0.9"),
        );
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::SignedVc
        );
    }

    #[test]
    fn higher_q_on_json_wins_over_lower_q_on_vc_jwt() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/json;q=0.9, application/vc+jwt;q=0.5"),
        );
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::PlainJson,
        );
    }

    #[test]
    fn missing_q_defaults_to_one() {
        // RFC 9110: omitted q defaults to 1. A bare `application/json`
        // listed alongside `application/vc+jwt;q=0.5` therefore beats
        // the VC offer and the response is plain JSON.
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/json, application/vc+jwt;q=0.5"),
        );
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::PlainJson,
        );
    }

    #[test]
    fn tie_breaks_by_accepted_list_order() {
        // Equal q on both vc+jwt and an unrelated json. The VC was
        // explicitly opted in, so the tie resolves to SignedVc.
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/json, application/vc+jwt"),
        );
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::SignedVc
        );
    }

    #[test]
    fn wildcard_does_not_opt_in_to_signed_vc() {
        // `*/*` is the curl default. Wave-3 is opt-in by explicit
        // selection, so a wildcard never matches an accepted VC media
        // type.
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("*/*"));
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::PlainJson
        );
    }

    #[test]
    fn malformed_q_value_is_ignored() {
        // RFC 9110 says servers SHOULD treat malformed q as if absent.
        // An `application/vc+jwt;q=not-a-number` therefore retains the
        // default q=1 and matches.
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/vc+jwt;q=not-a-number"),
        );
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::SignedVc
        );
    }

    #[test]
    fn q_above_one_is_clamped_to_one() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/vc+jwt;q=2.0"),
        );
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::SignedVc
        );
    }

    #[test]
    fn q_with_extra_params_after_is_honored() {
        // `;charset=utf-8;q=0.9` is the realistic shape from some
        // clients. We must still pick out the q value.
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/vc+jwt;charset=utf-8;q=0.9, application/json"),
        );
        assert_eq!(
            negotiate(&headers, &accepted()),
            NegotiationOutcome::PlainJson,
            "q=0.9 on vc+jwt loses to default q=1 on application/json"
        );
    }
}
