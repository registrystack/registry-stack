// SPDX-License-Identifier: Apache-2.0

//! Origin-pinned links: the `httpUri` parameter on an `http` send
//! (`products/adapter/CONCEPT.md` section 8.11.5).
//!
//! Camel follows a source-returned link through the `CamelHttpUri`
//! header, which replaces the endpoint URI wholesale
//! (`camel-4.23.0:components/camel-http-base/src/main/java/org/apache/camel/http/base/HttpHelper.java#createURI`,
//! read by
//! `camel-4.23.0:components/camel-http/src/main/java/org/apache/camel/component/http/HttpProducer.java#createMethod`);
//! nothing pins it to the endpoint's origin. The Adapter keeps the
//! capability and refuses, with the uncatchable `egress.refused`, every
//! link that leaves the configured origin or base path.

use registry_adapter::component::http::uri::{LinkRefusal, OriginError, PinnedOrigin};
use registry_adapter_core::ErrorClass;
use registry_platform_httputil::destination::{
    DataDestinationRequestTemplate, DestinationAuthorizationTemplate,
    QueryStringContentAcknowledgement, SideEffectingSendMethod, MAX_DESTINATION_ORIGIN_URL_BYTES,
};

fn pinned(base: &str) -> PinnedOrigin {
    PinnedOrigin::new(base).unwrap_or_else(|error| panic!("{base} is a valid base URL: {error}"))
}

fn fhir() -> PinnedOrigin {
    pinned("https://fhir.example.org/fhir/R4")
}

fn refused(origin: &PinnedOrigin, link: &str) -> LinkRefusal {
    let refusal = origin.pin(link).expect_err("the link must be refused");
    assert_eq!(refusal.class(), ErrorClass::EgressRefused, "{link}");
    assert!(refusal.class().is_uncatchable(), "{link}");
    refusal
}

fn target(origin: &PinnedOrigin, link: &str) -> String {
    origin
        .pin(link)
        .unwrap_or_else(|refusal| panic!("{link} must be accepted: {refusal}"))
        .target()
        .to_owned()
}

// Accepted links.

#[test]
fn a_next_link_under_the_base_path_is_pinned() {
    let origin = fhir();
    let pinned = origin
        .pin("https://fhir.example.org/fhir/R4/Patient?_count=50&_getpages=abc&_page=2")
        .expect("a same-origin next link is accepted");
    assert_eq!(
        pinned.target(),
        "/fhir/R4/Patient?_count=50&_getpages=abc&_page=2"
    );
    assert_eq!(
        pinned.as_url().as_str(),
        "https://fhir.example.org/fhir/R4/Patient?_count=50&_getpages=abc&_page=2"
    );
}

#[test]
fn the_base_path_itself_and_its_slash_form_are_under_the_base_path() {
    let origin = fhir();
    assert_eq!(
        target(&origin, "https://fhir.example.org/fhir/R4?_page=2"),
        "/fhir/R4?_page=2"
    );
    assert_eq!(
        target(&origin, "https://fhir.example.org/fhir/R4/"),
        "/fhir/R4/"
    );
}

/// The query the source wrote is sent as written: FHIR search
/// parameters carry `|`, `:`, `,`, and percent escapes in any case.
#[test]
fn the_query_is_sent_as_written() {
    let origin = fhir();
    let query = "identifier=urn:oid:1.2%7cabc&_sort=-date,name&x=%2f%2F&code=a|b";
    assert_eq!(
        target(
            &origin,
            &format!("https://fhir.example.org/fhir/R4/Observation?{query}")
        ),
        format!("/fhir/R4/Observation?{query}")
    );
}

/// A query the URL parser would rewrite (it percent-encodes `'`, `"`,
/// `<`, `>`, and non-ASCII in a special scheme's query) is refused, so
/// what goes out is always byte for byte what the source wrote.
#[test]
fn a_query_the_parser_would_rewrite_is_refused() {
    let origin = fhir();
    for link in [
        "https://fhir.example.org/fhir/R4/Patient?name=o'brien",
        "https://fhir.example.org/fhir/R4/Patient?name=\"x\"",
        "https://fhir.example.org/fhir/R4/Patient?name=<x>",
        "https://fhir.example.org/fhir/R4/Patient?name=Jos\u{e9}",
    ] {
        assert_eq!(
            refused(&origin, link),
            LinkRefusal::QueryNotAsWritten,
            "{link}"
        );
    }
}

#[test]
fn a_root_base_accepts_any_same_origin_path() {
    let origin = pinned("https://fhir.example.org");
    assert_eq!(
        target(&origin, "https://fhir.example.org/anything/at/all"),
        "/anything/at/all"
    );
    assert_eq!(target(&origin, "https://fhir.example.org"), "/");
    let slash = origin_with_slash();
    assert_eq!(target(&slash, "https://fhir.example.org/x"), "/x");
}

fn origin_with_slash() -> PinnedOrigin {
    pinned("https://fhir.example.org/")
}

#[test]
fn the_origin_url_has_no_base_path() {
    assert_eq!(fhir().origin_url(), "https://fhir.example.org/");
    assert_eq!(fhir().base_path(), "/fhir/R4");
    assert_eq!(
        pinned("http://127.0.0.1:8080/api/").origin_url(),
        "http://127.0.0.1:8080/"
    );
    assert_eq!(pinned("http://127.0.0.1:8080/api/").base_path(), "/api");
    assert_eq!(pinned("https://fhir.example.org").base_path(), "");
}

// Scheme.

#[test]
fn scheme_case_is_not_significant() {
    assert_eq!(
        target(&fhir(), "HTTPS://fhir.example.org/fhir/R4/Patient"),
        "/fhir/R4/Patient"
    );
}

#[test]
fn another_scheme_is_refused() {
    let origin = fhir();
    for link in [
        "http://fhir.example.org/fhir/R4/Patient",
        "ftp://fhir.example.org/fhir/R4/Patient",
        "file://fhir.example.org/fhir/R4/Patient",
        "ws://fhir.example.org/fhir/R4/Patient",
    ] {
        assert_eq!(
            refused(&origin, link),
            LinkRefusal::SchemeMismatch,
            "{link}"
        );
    }
}

/// The parser accepts `https:host/path` and `https:///host/path` for a
/// special scheme; a link must be written as an absolute URL with its
/// authority, so neither lenient form passes.
#[test]
fn a_link_that_is_not_written_scheme_slash_slash_authority_is_refused() {
    let origin = fhir();
    for link in [
        "https:fhir.example.org/fhir/R4/Patient",
        "https:/fhir.example.org/fhir/R4/Patient",
        "https:///fhir.example.org/fhir/R4/Patient",
        "/fhir/R4/Patient",
        "//fhir.example.org/fhir/R4/Patient",
        "Patient?_page=2",
        "javascript:alert(1)",
        "data:text/plain,x",
        "",
        "https://",
    ] {
        assert_eq!(refused(&origin, link), LinkRefusal::NotAbsolute, "{link:?}");
    }
}

// Host.

#[test]
fn host_case_is_not_significant() {
    assert_eq!(
        target(&fhir(), "https://FHIR.Example.ORG/fhir/R4/Patient"),
        "/fhir/R4/Patient"
    );
}

#[test]
fn another_host_is_refused() {
    let origin = fhir();
    for link in [
        "https://evil.example.org/fhir/R4/Patient",
        "https://fhir.example.org.evil.example/fhir/R4/Patient",
        "https://example.org/fhir/R4/Patient",
        "https://169.254.169.254/fhir/R4/Patient",
        "https://localhost/fhir/R4/Patient",
    ] {
        assert_eq!(refused(&origin, link), LinkRefusal::HostMismatch, "{link}");
    }
}

/// A trailing dot names the same DNS zone but is a different host
/// string to TLS name checks and virtual hosting; it is refused, never
/// stripped.
#[test]
fn a_trailing_dot_host_is_refused() {
    assert_eq!(
        refused(&fhir(), "https://fhir.example.org./fhir/R4/Patient"),
        LinkRefusal::HostMismatch
    );
}

/// IDNA: the parser maps a Unicode host to its punycode form, so both
/// spellings of one name compare equal and a lookalike does not.
#[test]
fn idna_and_punycode_spellings_of_the_origin_compare_equal() {
    let origin = pinned("https://xn--bcher-kva.example/api");
    assert_eq!(
        target(&origin, "https://b\u{fc}cher.example/api/x"),
        "/api/x"
    );
    assert_eq!(
        target(&origin, "https://XN--BCHER-KVA.example/api/x"),
        "/api/x"
    );
    assert_eq!(
        refused(&origin, "https://bucher.example/api/x"),
        LinkRefusal::HostMismatch
    );
    // Fullwidth full stop maps to `.` under UTS 46, so this is the same
    // host, not a lookalike that slips past a string comparison.
    assert_eq!(
        target(&origin, "https://xn--bcher-kva\u{ff0e}example/api/x"),
        "/api/x"
    );
}

#[test]
fn a_cyrillic_lookalike_host_is_refused() {
    // U+0430 is Cyrillic small a.
    assert_eq!(
        refused(&fhir(), "https://fhir.ex\u{0430}mple.org/fhir/R4/Patient"),
        LinkRefusal::HostMismatch
    );
}

#[test]
fn ipv6_literals_compare_by_address() {
    let origin = pinned("https://[2001:db8::1]/api");
    assert_eq!(
        target(&origin, "https://[2001:0db8:0:0:0:0:0:1]/api/x"),
        "/api/x"
    );
    assert_eq!(
        refused(&origin, "https://[2001:db8::2]/api/x"),
        LinkRefusal::HostMismatch
    );
}

/// RFC 6874 zone identifiers are not part of a WHATWG URL; the parser
/// refuses them, so a link carrying one never reaches comparison.
#[test]
fn an_ipv6_zone_id_is_refused() {
    let origin = pinned("https://[fe80::1]/api");
    for link in [
        "https://[fe80::1%25eth0]/api/x",
        "https://[fe80::1%eth0]/api/x",
    ] {
        assert_eq!(refused(&origin, link), LinkRefusal::Unparseable, "{link}");
    }
}

/// The parser reads every IPv4 spelling as one address, so an integer
/// or hex host equals the dotted origin it names and differs from any
/// other.
#[test]
fn ipv4_spellings_compare_by_address() {
    let origin = pinned("http://127.0.0.1:8080/api");
    assert_eq!(target(&origin, "http://2130706433:8080/api/x"), "/api/x");
    assert_eq!(target(&origin, "http://0x7f.0.0.1:8080/api/x"), "/api/x");
    assert_eq!(
        refused(&origin, "http://127.0.0.2:8080/api/x"),
        LinkRefusal::HostMismatch
    );
    assert_eq!(
        refused(&fhir(), "https://2130706433/fhir/R4/x"),
        LinkRefusal::HostMismatch
    );
}

// Port.

#[test]
fn an_explicit_default_port_equals_no_port() {
    let origin = fhir();
    assert_eq!(
        target(&origin, "https://fhir.example.org:443/fhir/R4/Patient"),
        "/fhir/R4/Patient"
    );
    let explicit = origin_with_port();
    assert_eq!(
        target(&explicit, "https://fhir.example.org/fhir/R4/Patient"),
        "/fhir/R4/Patient"
    );
}

fn origin_with_port() -> PinnedOrigin {
    pinned("https://fhir.example.org:443/fhir/R4")
}

#[test]
fn another_port_is_refused() {
    let origin = fhir();
    for link in [
        "https://fhir.example.org:8443/fhir/R4/Patient",
        "https://fhir.example.org:80/fhir/R4/Patient",
        "https://fhir.example.org:0/fhir/R4/Patient",
    ] {
        assert_eq!(refused(&origin, link), LinkRefusal::PortMismatch, "{link}");
    }
    let plain = pinned("http://127.0.0.1:8080/api");
    assert_eq!(
        refused(&plain, "http://127.0.0.1/api/x"),
        LinkRefusal::PortMismatch
    );
}

// Userinfo and fragment.

#[test]
fn userinfo_in_any_form_is_refused() {
    let origin = fhir();
    for link in [
        "https://user:pass@fhir.example.org/fhir/R4/Patient",
        "https://user@fhir.example.org/fhir/R4/Patient",
        "https://:pass@fhir.example.org/fhir/R4/Patient",
        "https://@fhir.example.org/fhir/R4/Patient",
        "https://:@fhir.example.org/fhir/R4/Patient",
        "https://fhir.example.org@evil.example/fhir/R4/Patient",
        "https://evil.example@fhir.example.org/fhir/R4/Patient",
    ] {
        assert_eq!(refused(&origin, link), LinkRefusal::Userinfo, "{link}");
    }
}

#[test]
fn a_fragment_in_any_form_is_refused() {
    let origin = fhir();
    for link in [
        "https://fhir.example.org/fhir/R4/Patient#x",
        "https://fhir.example.org/fhir/R4/Patient#",
        "https://fhir.example.org/fhir/R4/Patient?_page=2#x",
    ] {
        assert_eq!(refused(&origin, link), LinkRefusal::Fragment, "{link}");
    }
}

// Path.

#[test]
fn a_path_outside_the_base_path_is_refused() {
    let origin = fhir();
    for link in [
        "https://fhir.example.org/",
        "https://fhir.example.org/fhir",
        "https://fhir.example.org/fhir/R5/Patient",
        "https://fhir.example.org/admin",
        "https://fhir.example.org/fhir/r4/Patient",
    ] {
        assert_eq!(
            refused(&origin, link),
            LinkRefusal::OutsideBasePath,
            "{link}"
        );
    }
}

/// `/api` is not a prefix of `/apix` at a segment boundary.
#[test]
fn a_base_path_prefix_that_is_not_a_segment_boundary_is_refused() {
    let origin = pinned("https://fhir.example.org/api");
    for link in [
        "https://fhir.example.org/apix",
        "https://fhir.example.org/apix/Patient",
        "https://fhir.example.org/api-internal/x",
    ] {
        assert_eq!(
            refused(&origin, link),
            LinkRefusal::OutsideBasePath,
            "{link}"
        );
    }
    assert_eq!(target(&origin, "https://fhir.example.org/api"), "/api");
}

/// Dot segments are resolved by the one parse before the base-path
/// comparison, and the resolved path is the one sent.
#[test]
fn dot_segments_are_resolved_before_the_base_path_comparison() {
    let origin = fhir();
    for link in [
        "https://fhir.example.org/fhir/R4/../../admin",
        "https://fhir.example.org/fhir/R4/..",
        "https://fhir.example.org/fhir/R4/%2e%2e/%2E%2E/admin",
        "https://fhir.example.org/fhir/R4/.%2e/x",
        "https://fhir.example.org/fhir/R4/Patient/../../R5",
    ] {
        assert_eq!(
            refused(&origin, link),
            LinkRefusal::OutsideBasePath,
            "{link}"
        );
    }
    assert_eq!(
        target(&origin, "https://fhir.example.org/fhir/R4/x/../Patient/./1"),
        "/fhir/R4/Patient/1"
    );
    assert_eq!(
        target(&origin, "https://fhir.example.org/fhir/R5/../R4/Patient"),
        "/fhir/R4/Patient"
    );
}

/// An escape that decodes to a delimiter, a dot, `%`, `;`, or an
/// unreserved character is an alias a server may decode before or after
/// routing (`%2f` as `/`, `%5c` as `\`, `%252e` decoded twice as `.`);
/// the rule matches the platform transport's canonical-target rule, so
/// a pinned link always renders.
#[test]
fn an_encoded_delimiter_or_alias_in_the_path_is_refused() {
    let origin = fhir();
    for link in [
        "https://fhir.example.org/fhir/R4/Patient%2f..%2f..%2fadmin",
        "https://fhir.example.org/fhir/R4/Patient%2F1",
        "https://fhir.example.org/fhir/R4/Patient%5c1",
        "https://fhir.example.org/fhir/R4/Patient%5C1",
        "https://fhir.example.org/fhir/R4/%252e%252e/admin",
        "https://fhir.example.org/fhir/R4/a%2eb",
        "https://fhir.example.org/fhir/R4/Patient%3b1",
        "https://fhir.example.org/fhir/R4/Patient%3F1",
        "https://fhir.example.org/fhir/R4/Patient%00",
        "https://fhir.example.org/fhir/R4/Patient%0d%0a",
        "https://fhir.example.org/fhir/R4/%50atient",
        "https://fhir.example.org/fhir/R4/Patient%e9",
        "https://fhir.example.org/fhir/R4/Patient%",
        "https://fhir.example.org/fhir/R4/Patient%2",
        "https://fhir.example.org/fhir/R4/Patient%zz",
    ] {
        assert_eq!(
            refused(&origin, link),
            LinkRefusal::NonCanonicalPath,
            "{link}"
        );
    }
    assert_eq!(
        target(&origin, "https://fhir.example.org/fhir/R4/Patient%20Name"),
        "/fhir/R4/Patient%20Name"
    );
    assert_eq!(
        target(&origin, "https://fhir.example.org/fhir/R4/Jos%C3%A9"),
        "/fhir/R4/Jos%C3%A9"
    );
}

/// The parser silently drops tab and newline and trims surrounding
/// spaces and controls, and reads `\` as `/` in a special scheme; any of
/// them in the raw link is refused before parsing, so the parsed value
/// is never something the source did not write.
#[test]
fn whitespace_controls_and_backslashes_are_refused_before_parsing() {
    let origin = fhir();
    for link in [
        "https://fhir.example.org/fhir/R4/Pat\tient",
        "https://fhir.example.org/fhir/R4/Pat\nient",
        "https://fhir.example.org/fhir/R4/Pat\rient",
        " https://fhir.example.org/fhir/R4/Patient",
        "https://fhir.example.org/fhir/R4/Patient ",
        "https://fhir.example.org/fhir/R4/Pat ient",
        "\u{0}https://fhir.example.org/fhir/R4/Patient",
        "https://fhir.example.org/fhir/R4/Patient\u{7f}",
        "https://fhir.example.org\\@evil.example/fhir/R4/Patient",
        "https://fhir.example.org/fhir/R4\\..\\..\\admin",
        "https:\\\\fhir.example.org/fhir/R4/Patient",
    ] {
        assert_eq!(
            refused(&origin, link),
            LinkRefusal::InvalidCharacter,
            "{link:?}"
        );
    }
}

/// Matrix parameters (`..;/` on Tomcat) and empty segments are aliases
/// some servers collapse; both are refused in the path.
#[test]
fn semicolons_and_empty_segments_in_the_path_are_refused() {
    let origin = fhir();
    for link in [
        "https://fhir.example.org/fhir/R4/..;/admin",
        "https://fhir.example.org/fhir/R4/Patient;jsessionid=1",
        "https://fhir.example.org/fhir/R4//Patient",
        "https://fhir.example.org/fhir/R4/Patient//",
    ] {
        assert_eq!(
            refused(&origin, link),
            LinkRefusal::NonCanonicalPath,
            "{link}"
        );
    }
    // A `;` in the query is ordinary query text.
    assert_eq!(
        target(&origin, "https://fhir.example.org/fhir/R4/Patient?a=1;b=2"),
        "/fhir/R4/Patient?a=1;b=2"
    );
}

#[test]
fn path_case_is_significant() {
    assert_eq!(
        refused(&fhir(), "https://fhir.example.org/FHIR/R4/Patient"),
        LinkRefusal::OutsideBasePath
    );
}

// Length.

#[test]
fn a_link_over_the_url_bound_is_refused() {
    let origin = fhir();
    let prefix = "https://fhir.example.org/fhir/R4/Patient?q=";
    let at_bound = format!(
        "{prefix}{}",
        "a".repeat(MAX_DESTINATION_ORIGIN_URL_BYTES - prefix.len())
    );
    assert_eq!(at_bound.len(), MAX_DESTINATION_ORIGIN_URL_BYTES);
    assert!(origin.pin(&at_bound).is_ok());
    let over = format!("{at_bound}a");
    assert_eq!(refused(&origin, &over), LinkRefusal::TooLong);
    let huge = format!("{prefix}{}", "a".repeat(1 << 20));
    assert_eq!(refused(&origin, &huge), LinkRefusal::TooLong);
}

/// A link under the bound as written can serialize longer (the parser
/// percent-encodes non-ASCII path text); the serialized form is the one
/// sent, so it is measured too.
#[test]
fn a_link_that_serializes_over_the_url_bound_is_refused() {
    let origin = fhir();
    let prefix = "https://fhir.example.org/fhir/R4/";
    // Each U+00E9 is two bytes raw and six serialized (`%C3%A9`).
    let count = (MAX_DESTINATION_ORIGIN_URL_BYTES - prefix.len()) / 2;
    let link = format!("{prefix}{}", "\u{e9}".repeat(count));
    assert!(link.len() <= MAX_DESTINATION_ORIGIN_URL_BYTES);
    assert_eq!(refused(&origin, &link), LinkRefusal::TooLong);
}

// Refusals and the sent value.

#[test]
fn a_refusal_is_value_free() {
    let refusal = refused(
        &fhir(),
        "https://secret-host.example/fhir/R4/Patient?token=s3cr3t",
    );
    let text = format!("{refusal} {refusal:?}");
    assert!(!text.contains("secret-host"), "{text}");
    assert!(!text.contains("s3cr3t"), "{text}");
}

/// The sender sends the pinned value, never the original string: the
/// pinned URL's origin is the configured one byte for byte, whatever
/// spelling the link used.
#[test]
fn the_pinned_url_carries_the_configured_origin_spelling() {
    let origin = fhir();
    let pinned = origin
        .pin("HTTPS://FHIR.EXAMPLE.ORG:443/fhir/R4/Patient")
        .expect("accepted");
    assert_eq!(
        pinned.as_url().as_str(),
        "https://fhir.example.org/fhir/R4/Patient"
    );
    assert!(pinned.as_url().as_str().starts_with(&origin.origin_url()));
}

/// Every target the pin accepts is one the platform transport's
/// canonical-target rule accepts too, so a pinned link never fails at
/// render for a reason the pin did not already decide.
#[test]
fn a_pinned_target_passes_the_transport_target_rule() {
    let template = DataDestinationRequestTemplate::new_script_send(
        SideEffectingSendMethod::Get(
            QueryStringContentAcknowledgement::acknowledge_content_in_access_logs(),
        ),
        "/fhir/R4/**",
        &[],
        DestinationAuthorizationTemplate::Forbidden,
        None,
        None,
        4_096,
    )
    .expect("the template is valid");
    let origin = fhir();
    for link in [
        "https://fhir.example.org/fhir/R4",
        "https://fhir.example.org/fhir/R4/",
        "https://fhir.example.org/fhir/R4/Patient?_count=50&_getpages=abc&_page=2",
        "https://fhir.example.org/fhir/R4/Observation?identifier=urn:oid:1.2%7cabc&code=a|b",
        "https://fhir.example.org/fhir/R4/Patient?a=1;b=2",
        "https://fhir.example.org/fhir/R4/x/../Patient/./1",
        "HTTPS://FHIR.EXAMPLE.ORG:443/fhir/R4/Patient",
        "https://fhir.example.org/fhir/R4/Patient%20Name",
        "https://fhir.example.org/fhir/R4/Jos%C3%A9",
        "https://fhir.example.org/fhir/R4/Jos\u{e9}",
    ] {
        let pinned = origin
            .pin(link)
            .unwrap_or_else(|refusal| panic!("{link} must be accepted: {refusal}"));
        template
            .validate_script_request_shape(pinned.target(), &[], None)
            .unwrap_or_else(|error| panic!("{link} must render: {error:?}"));
    }
}

// Base URL.

#[test]
fn a_base_url_outside_the_pinnable_shape_is_refused() {
    for (base, expected) in [
        ("ftp://fhir.example.org/", OriginError::UnsupportedScheme),
        ("file:///etc/passwd", OriginError::UnsupportedScheme),
        ("https://user@fhir.example.org/", OriginError::Userinfo),
        ("https://fhir.example.org/?a=1", OriginError::Query),
        ("https://fhir.example.org/?", OriginError::Query),
        ("https://fhir.example.org/#x", OriginError::Fragment),
        ("https:fhir.example.org/", OriginError::NotAbsolute),
        (
            "https://fhir.example.org/a b",
            OriginError::InvalidCharacter,
        ),
        (
            "https://fhir.example.org/a\\b",
            OriginError::InvalidCharacter,
        ),
        (
            "https://fhir.example.org/a%2fb",
            OriginError::NonCanonicalPath,
        ),
        (
            "https://fhir.example.org/a//b",
            OriginError::NonCanonicalPath,
        ),
        (
            "https://fhir.example.org/a;b",
            OriginError::NonCanonicalPath,
        ),
        ("https://[fe80::1%25eth0]/", OriginError::Unparseable),
    ] {
        assert_eq!(PinnedOrigin::new(base).err(), Some(expected), "{base}");
    }
    let long = format!(
        "https://fhir.example.org/{}",
        "a".repeat(MAX_DESTINATION_ORIGIN_URL_BYTES)
    );
    assert_eq!(PinnedOrigin::new(&long).err(), Some(OriginError::TooLong));
}
