// SPDX-License-Identifier: Apache-2.0

//! The `http` component's two header allowlists, Camel's
//! `HeaderFilterStrategy` in both directions
//! (`products/adapter/CONCEPT.md` section 8.11.4).
//!
//! Camel filters by deny rules (`DefaultHeaderFilterStrategy`'s
//! `Camel`/`camel` prefix and `HttpHeaderFilterStrategy`'s common
//! filters); the Adapter ports the strategy as two allowlists with a
//! never-allowlistable set, so every case below is decided by the
//! allowlist first and by Camel only where Camel's rule still applies.

use http::{HeaderName, HeaderValue};
use registry_adapter::component::http::header_filter::{
    AllowlistError, HeaderFilter, HeaderSide, InboundHeaderError, OutboundHeaderError,
};
use registry_adapter_core::{Endpoint, ErrorClass};
use registry_platform_httputil::destination::{
    MAX_DESTINATION_HEADER_VALUE_BYTES, MAX_DESTINATION_REQUEST_HEADERS,
};

const NONE: &[&str] = &[];

fn filter(request: &[&str], response: &[&str], api_key: Option<&str>) -> HeaderFilter {
    HeaderFilter::new(request, response, api_key)
        .unwrap_or_else(|error| panic!("the allowlists are valid: {error}"))
}

fn sent(filter: &HeaderFilter, exchange: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
    filter
        .outbound(exchange.iter().copied())
        .unwrap_or_else(|error| panic!("the exchange headers are sendable: {error}"))
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect()
}

fn copied(filter: &HeaderFilter, upstream: &[(&str, &[u8])]) -> Vec<(String, String)> {
    filter
        .inbound(upstream.iter().copied())
        .unwrap_or_else(|error| panic!("the upstream headers are copyable: {error}"))
        .iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

// Request side.

/// Only listed names go out, compared without case, and a listed header
/// absent from the exchange is not sent. Camel sends every exchange
/// header its filter does not drop
/// (`camel-4.23.0:components/camel-http/src/main/java/org/apache/camel/component/http/HttpProducer.java#process`,
/// the `strategy.applyFilterToCamelHeaders` loop); the Adapter inverts
/// that into an allowlist.
#[test]
fn only_listed_request_headers_are_sent() {
    let filter = filter(&["Accept", "Prefer", "If-None-Exist"], NONE, None);
    let headers = sent(
        &filter,
        &[
            ("accept", "application/fhir+json"),
            ("X-Debug", "1"),
            ("PREFER", "return=minimal"),
        ],
    );
    assert_eq!(
        headers,
        vec![
            ("accept".to_owned(), b"application/fhir+json".to_vec()),
            ("prefer".to_owned(), b"return=minimal".to_vec()),
        ]
    );
}

/// Engine headers and facade inputs are exchange headers like any other:
/// never sent unless listed. Camel drops `Camel*` by prefix
/// (`camel-4.23.0:core/camel-support/src/main/java/org/apache/camel/support/DefaultHeaderFilterStrategy.java#doFiltering`);
/// the allowlist drops them because they are not listed.
#[test]
fn engine_headers_and_facade_inputs_are_not_sent_unless_listed() {
    let unlisted = filter(&["Accept"], NONE, None);
    let exchange = [
        ("CamelHttpResponseCode", "200"),
        ("CamelSplitIndex", "0"),
        ("recordId", "abc"),
        ("Idempotency-Key", "k-1"),
    ];
    assert!(sent(&unlisted, &exchange).is_empty());

    let listed = filter(&["CamelSplitIndex"], NONE, None);
    assert_eq!(
        sent(&listed, &exchange),
        vec![("camelsplitindex".to_owned(), b"0".to_vec())]
    );
}

#[test]
fn an_empty_allowlist_sends_nothing() {
    let filter = filter(NONE, NONE, None);
    assert!(sent(&filter, &[("Accept", "text/plain")]).is_empty());
}

/// RFC 9110 section 5.5: a field value is visible ASCII with internal
/// spaces and tabs. CR, LF, NUL, and the other controls would split or
/// truncate the request; a value carrying one is refused, never sent and
/// never trimmed.
#[test]
fn a_request_header_value_with_a_control_is_refused_as_egress() {
    let filter = filter(&["Accept", "Prefer"], NONE, None);
    for value in [
        "a\r\nX-Injected: 1",
        "a\nb",
        "a\rb",
        "a\0b",
        "a\u{7f}b",
        "a\u{1b}b",
    ] {
        let error = filter
            .outbound([("Accept", "ok"), ("Prefer", value)])
            .expect_err("a control in a field value is refused");
        assert_eq!(error, OutboundHeaderError::InvalidValue { index: 1 });
        assert_eq!(error.class(), ErrorClass::EgressRefused);
        assert!(error.class().is_uncatchable());
    }
}

/// Non-ASCII and leading or trailing whitespace are refused rather than
/// re-encoded or trimmed: obs-text is read as Latin-1 by some upstreams
/// and UTF-8 by others, and a trimmed value is not the value the route
/// set.
#[test]
fn a_request_header_value_outside_visible_ascii_is_refused() {
    let filter = filter(&["Accept"], NONE, None);
    for value in ["caf\u{e9}", " leading", "trailing ", "\ttab"] {
        assert_eq!(
            filter.outbound([("Accept", value)]),
            Err(OutboundHeaderError::InvalidValue { index: 0 })
        );
    }
}

#[test]
fn internal_spaces_and_an_empty_value_are_sent() {
    let filter = filter(&["Prefer", "If-None-Exist"], NONE, None);
    assert_eq!(
        sent(
            &filter,
            &[
                ("Prefer", "return=minimal,\thandling=strict"),
                ("If-None-Exist", "")
            ]
        ),
        vec![
            (
                "prefer".to_owned(),
                b"return=minimal,\thandling=strict".to_vec()
            ),
            ("if-none-exist".to_owned(), Vec::new()),
        ]
    );
}

#[test]
fn a_request_header_value_over_the_transport_bound_is_refused() {
    let filter = filter(&["Prefer"], NONE, None);
    let at_bound = "a".repeat(MAX_DESTINATION_HEADER_VALUE_BYTES);
    assert_eq!(sent(&filter, &[("Prefer", &at_bound)]).len(), 1);
    let over = "a".repeat(MAX_DESTINATION_HEADER_VALUE_BYTES + 1);
    let error = filter
        .outbound([("Prefer", over.as_str())])
        .expect_err("an over-long value is refused");
    assert_eq!(error, OutboundHeaderError::ValueTooLong { index: 0 });
    assert_eq!(error.class(), ErrorClass::EgressRefused);
}

/// Two exchange entries for one listed name, in any case, are never
/// resolved by picking one. Camel would join them as `[a, b]`
/// (`camel-4.23.0:components/camel-http/src/main/java/org/apache/camel/component/http/HttpProducer.java#applyHeader`);
/// the Adapter refuses.
#[test]
fn two_exchange_entries_for_one_listed_name_are_refused() {
    let filter = filter(&["Accept"], NONE, None);
    let error = filter
        .outbound([("Accept", "a"), ("ACCEPT", "b")])
        .expect_err("an ambiguous header is refused");
    assert_eq!(error, OutboundHeaderError::Duplicate { index: 0 });
    assert_eq!(error.class(), ErrorClass::EgressRefused);
}

/// A refusal names the allowlist position, never the value: values may
/// carry personal data or credentials.
#[test]
fn an_outbound_refusal_is_value_free() {
    let filter = filter(&["Accept"], NONE, None);
    let error = filter
        .outbound([("Accept", "secret-value\r\n")])
        .expect_err("refused");
    let text = format!("{error} {error:?}");
    assert!(!text.contains("secret-value"), "{text}");
}

// Construction.

/// Every never-allowlistable name of section 8.11.4 is refused in either
/// list at construction, in any case, so a filter that exists can never
/// emit one. The credential injected after the filter therefore cannot
/// be shadowed or replaced by an exchange header.
#[test]
fn every_reserved_name_is_refused_in_either_list() {
    for name in [
        "Authorization",
        "proxy-authorization",
        "Cookie",
        "Set-Cookie",
        "HOST",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Upgrade",
        "TE",
        "Trailer",
        "Keep-Alive",
        "Expect",
        "Proxy-Connection",
        "Proxy-Anything",
    ] {
        assert_eq!(
            HeaderFilter::new(["Accept", name], NONE, None).err(),
            Some(AllowlistError::Reserved {
                side: HeaderSide::Request,
                index: 1,
            }),
            "{name}"
        );
        assert_eq!(
            HeaderFilter::new(NONE, [name], None).err(),
            Some(AllowlistError::Reserved {
                side: HeaderSide::Response,
                index: 0,
            }),
            "{name}"
        );
    }
}

#[test]
fn the_endpoint_api_key_header_is_refused_in_either_list() {
    assert_eq!(
        HeaderFilter::new(["x-api-key"], NONE, Some("X-Api-Key")).err(),
        Some(AllowlistError::ApiKeyHeader {
            side: HeaderSide::Request,
            index: 0,
        })
    );
    assert_eq!(
        HeaderFilter::new(NONE, ["ETag", "X-API-KEY"], Some("X-Api-Key")).err(),
        Some(AllowlistError::ApiKeyHeader {
            side: HeaderSide::Response,
            index: 1,
        })
    );
}

#[test]
fn a_header_name_that_is_not_a_token_is_refused() {
    for name in ["", "Bad Name", "a:b", "a\r\nb", "caf\u{e9}", "a/b", "(x)"] {
        assert_eq!(
            HeaderFilter::new([name], NONE, None).err(),
            Some(AllowlistError::NotAToken {
                side: HeaderSide::Request,
                index: 0,
            }),
            "{name:?}"
        );
    }
}

/// `UniqueList` refuses exact repeats; names compare without case, so a
/// repeat that differs only in case is refused here.
#[test]
fn a_name_listed_twice_in_any_case_is_refused() {
    assert_eq!(
        HeaderFilter::new(["Accept", "ACCEPT"], NONE, None).err(),
        Some(AllowlistError::Duplicate {
            side: HeaderSide::Request,
            index: 1,
        })
    );
    assert_eq!(
        HeaderFilter::new(NONE, ["etag", "ETag"], None).err(),
        Some(AllowlistError::Duplicate {
            side: HeaderSide::Response,
            index: 1,
        })
    );
}

#[test]
fn an_allowlist_over_the_transport_header_bound_is_refused() {
    let names: Vec<String> = (0..=MAX_DESTINATION_REQUEST_HEADERS)
        .map(|index| format!("X-H{index}"))
        .collect();
    assert_eq!(
        HeaderFilter::new(&names, NONE, None).err(),
        Some(AllowlistError::TooMany {
            side: HeaderSide::Request,
            maximum: MAX_DESTINATION_REQUEST_HEADERS,
        })
    );
    assert!(HeaderFilter::new(&names[..MAX_DESTINATION_REQUEST_HEADERS], NONE, None).is_ok());
}

/// An upstream may not write a header the engine places on the exchange:
/// Camel's `Camel`/`camel` prefix rule applies to inbound headers too
/// (`camel-4.23.0:core/camel-support/src/main/java/org/apache/camel/support/DefaultHeaderFilterStrategy.java#applyFilterToExternalHeaders`,
/// `CAMEL_FILTER_STARTS_WITH` with `lowerCase` on).
#[test]
fn a_camel_engine_header_is_refused_as_a_response_header() {
    for name in ["CamelHttpResponseCode", "camelSplitIndex", "CAMELFOO"] {
        assert_eq!(
            HeaderFilter::new(NONE, ["ETag", name], None).err(),
            Some(AllowlistError::EngineHeader { index: 1 }),
            "{name}"
        );
    }
}

/// The platform transport owns `Content-Type` and the forwarding,
/// encoding, and signing headers on a request, and never exposes
/// authentication challenges, infrastructure, or tracing headers from a
/// response; a filter refuses them when built rather than at send time.
#[test]
fn a_name_the_transport_never_carries_is_refused_at_construction() {
    for name in [
        "Content-Type",
        "Accept-Encoding",
        "Forwarded",
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Amz-Date",
    ] {
        assert_eq!(
            HeaderFilter::new([name], NONE, None).err(),
            Some(AllowlistError::TransportRefused {
                side: HeaderSide::Request,
                index: 0,
            }),
            "{name}"
        );
    }
    for name in [
        "WWW-Authenticate",
        "Server",
        "Via",
        "Traceparent",
        "X-Api-Key",
        "CF-Ray",
        "X-Forwarded-Host",
    ] {
        assert_eq!(
            HeaderFilter::new(NONE, [name], None).err(),
            Some(AllowlistError::TransportRefused {
                side: HeaderSide::Response,
                index: 0,
            }),
            "{name}"
        );
    }
}

#[test]
fn an_allowlist_refusal_is_value_free_and_names_the_side() {
    let error = HeaderFilter::new(["Accept", "Authorization"], NONE, None).expect_err("refused");
    let text = error.to_string();
    assert!(text.contains("requestHeaders"), "{text}");
    assert!(text.contains("1"), "{text}");
}

#[test]
fn a_filter_reads_an_endpoint_declaration() {
    let endpoint: Endpoint = serde_json::from_value(serde_json::json!({
        "id": "fhir",
        "component": "http",
        "authentication": {"type": "static-api-key", "headerName": "X-Api-Key"},
        "requestHeaders": ["Accept"],
        "responseHeaders": ["ETag", "Location"],
    }))
    .expect("the endpoint parses");
    let filter = HeaderFilter::for_endpoint(&endpoint).expect("the endpoint is valid");
    assert_eq!(
        filter.response_header_names().collect::<Vec<_>>(),
        vec!["ETag", "Location"]
    );

    let leaking: Endpoint = serde_json::from_value(serde_json::json!({
        "id": "fhir",
        "component": "http",
        "authentication": {"type": "static-api-key", "headerName": "X-Api-Key"},
        "requestHeaders": ["X-API-Key"],
    }))
    .expect("the endpoint parses");
    assert_eq!(
        HeaderFilter::for_endpoint(&leaking).err(),
        Some(AllowlistError::ApiKeyHeader {
            side: HeaderSide::Request,
            index: 0,
        })
    );
}

/// The filtered set is the only thing C4a's credential injector extends:
/// its names are exactly the allowlisted ones, so the injected
/// `Authorization` or api-key header is never already present.
#[test]
fn the_outbound_set_never_carries_a_credential_name() {
    let filter = filter(&["Accept"], NONE, Some("X-Api-Key"));
    let outbound = filter
        .outbound([
            ("Authorization", "Bearer forged"),
            ("X-Api-Key", "forged"),
            ("Accept", "application/json"),
        ])
        .expect("sendable");
    let names: Vec<&HeaderName> = outbound.iter().map(|(name, _)| name).collect();
    assert_eq!(names, vec![&HeaderName::from_static("accept")]);
    assert_eq!(
        outbound.iter().map(|(_, value)| value).collect::<Vec<_>>(),
        vec![&HeaderValue::from_static("application/json")]
    );
    assert_eq!(outbound.len(), 1);
    assert!(!outbound.is_empty());
}

// Response side.

/// Only declared names are copied, under their declared spelling, in
/// declaration order. Camel copies every response header its filter
/// does not drop
/// (`camel-4.23.0:components/camel-http/src/main/java/org/apache/camel/component/http/HttpProducer.java#populateResponse`).
#[test]
fn only_declared_response_headers_are_copied_under_their_declared_names() {
    let filter = filter(NONE, &["ETag", "Location"], None);
    let headers = copied(
        &filter,
        &[
            ("location", b"https://fhir.example.org/Patient/1/_history/2"),
            ("set-cookie", b"session=abc"),
            ("etag", b"W/\"2\""),
            ("server", b"nginx"),
        ],
    );
    assert_eq!(
        headers,
        vec![
            ("ETag".to_owned(), "W/\"2\"".to_owned()),
            (
                "Location".to_owned(),
                "https://fhir.example.org/Patient/1/_history/2".to_owned()
            ),
        ]
    );
}

#[test]
fn an_absent_declared_response_header_is_not_copied() {
    let filter = filter(NONE, &["ETag"], None);
    assert!(copied(&filter, &[("content-type", b"application/json")]).is_empty());
}

/// A repeated upstream field for a declared name fails closed as
/// `upstream.malformed`. Camel turns the second occurrence into a list
/// (`camel-4.23.0:components/camel-http/src/main/java/org/apache/camel/component/http/HttpProducer.java#populateResponse`
/// through `camel-4.23.0:core/camel-util/src/main/java/org/apache/camel/util/CollectionHelper.java#appendEntry`),
/// so the header's type depends on the upstream; the Adapter keeps a
/// header a single string and matches the platform transport's
/// duplicate refusal.
#[test]
fn a_repeated_declared_response_header_is_upstream_malformed() {
    let filter = filter(NONE, &["Link", "ETag"], None);
    let error = filter
        .inbound([
            ("etag", b"\"1\"".as_slice()),
            ("Link", b"<a>; rel=next".as_slice()),
            ("LINK", b"<b>; rel=prev".as_slice()),
        ])
        .expect_err("a repeated declared field is refused");
    assert_eq!(error, InboundHeaderError::Repeated { index: 0 });
    assert_eq!(error.class(), ErrorClass::UpstreamMalformed);
    assert!(!error.class().is_uncatchable());
}

#[test]
fn a_repeated_undeclared_response_header_is_ignored() {
    let filter = filter(NONE, &["ETag"], None);
    assert_eq!(
        copied(
            &filter,
            &[("vary", b"accept"), ("vary", b"origin"), ("etag", b"\"1\"")]
        ),
        vec![("ETag".to_owned(), "\"1\"".to_owned())]
    );
}

#[test]
fn an_invalid_declared_response_header_value_is_upstream_malformed() {
    let filter = filter(NONE, &["ETag"], None);
    for value in [
        b"a\r\nb".as_slice(),
        b"a\0b",
        b"\xe9t\xe9",
        b"\xff",
        b" padded",
    ] {
        let error = filter
            .inbound([("etag", value)])
            .expect_err("an invalid value is refused");
        assert_eq!(error, InboundHeaderError::InvalidValue { index: 0 });
        assert_eq!(error.class(), ErrorClass::UpstreamMalformed);
        assert!(!format!("{error} {error:?}").contains('\u{e9}'));
    }
}

#[test]
fn an_over_long_declared_response_header_is_upstream_too_large() {
    let filter = filter(NONE, &["ETag"], None);
    let over = vec![b'a'; MAX_DESTINATION_HEADER_VALUE_BYTES + 1];
    let error = filter
        .inbound([("etag", over.as_slice())])
        .expect_err("an over-long value is refused");
    assert_eq!(error, InboundHeaderError::ValueTooLong { index: 0 });
    assert_eq!(error.class(), ErrorClass::UpstreamTooLarge);
}

#[test]
fn an_invalid_undeclared_response_header_is_ignored() {
    let filter = filter(NONE, &["ETag"], None);
    assert!(copied(&filter, &[("x-junk", b"\xff\r\n")]).is_empty());
}
