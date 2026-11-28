#![cfg(feature = "token-fixtures")]
//! The token fixture corpus under `products/platform/conformance/tokens`: every
//! fixture loads and validates, signs and verifies, every expectation row names
//! a real fixture and product, and nothing in the corpus is a key or a live token.
//! The driver is exercised with stand-in authenticators.

use std::collections::BTreeSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_testing::{
    Against, Binding, Comparison, Configuration, ExpectedCell, FixtureClass, Outcome, Stage,
    TokenCorpus, TokenFixture, TokenSigner,
};
use serde_json::{json, Value};

const ISSUER: &str = "https://issuer.example.test/realms/journey";
const AUDIENCE: &str = "https://api.example.test";
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];

#[test]
fn the_private_member_list_is_the_platform_list() {
    assert_eq!(
        PRIVATE_JWK_MEMBERS.into_iter().collect::<BTreeSet<_>>(),
        registry_platform_crypto::PRIVATE_JWK_MEMBERS
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
}

fn corpus() -> TokenCorpus {
    TokenCorpus::load().expect("the corpus loads and validates")
}

fn binding() -> Binding {
    Binding {
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
    }
}

fn decode_segment(segment: &str) -> Value {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .expect("segment is base64url");
    serde_json::from_slice(&bytes).expect("segment is JSON")
}

fn minimal_fixture(extra: Value) -> String {
    let mut base = json!({
        "schema": "registry.token-fixture/v1",
        "id": "unit-fixture",
        "class": "positive",
        "provider": "synthetic",
        "kind": "user-access",
        "tokenUse": "access",
        "subjectKind": "user",
        "source": { "basis": "constructed", "reason": "a unit test" },
        "header": { "alg": "ES256", "typ": "at+jwt", "kid": { "generated": true } },
        "claims": {
            "iss": { "bind": "issuer" },
            "aud": { "bind": "audience" },
            "sub": "subject-1",
            "iat": { "offsetSeconds": 0 },
            "exp": { "offsetSeconds": 300 }
        }
    });
    for (key, value) in extra.as_object().expect("extra is an object") {
        base[key] = value.clone();
    }
    base.to_string()
}

fn parse_error(extra: Value) -> String {
    TokenFixture::parse("unit-fixture", &minimal_fixture(extra))
        .expect_err("the fixture is refused")
        .to_string()
}

fn fixture_with_claims(claims: Value) -> TokenFixture {
    let mut full = json!({
        "iss": { "bind": "issuer" },
        "aud": { "bind": "audience" },
        "sub": "subject-1",
        "iat": { "offsetSeconds": 0 },
        "exp": { "offsetSeconds": 300 }
    });
    for (key, value) in claims.as_object().expect("claims is an object") {
        full[key] = value.clone();
    }
    TokenFixture::parse("unit-fixture", &minimal_fixture(json!({ "claims": full })))
        .expect("the fixture parses")
}

#[test]
fn read_scope_skips_openid_connect_scopes() {
    let mixed = fixture_with_claims(json!({ "scope": "openid records:get" }));
    assert_eq!(mixed.read_scope("scope").as_deref(), Some("records:get"));
    let only_openid = fixture_with_claims(json!({ "scope": "openid email profile" }));
    assert_eq!(only_openid.read_scope("scope"), None);
    let none = fixture_with_claims(json!({}));
    assert_eq!(none.read_scope("scope"), None);
    let list = fixture_with_claims(json!({ "scp": ["openid", "records:get", "records:write"] }));
    assert_eq!(list.read_scope("scp").as_deref(), Some("records:get"));
    assert_eq!(list.read_scope("scope"), None);
}

// ---------------------------------------------------------------------------
// The corpus as written
// ---------------------------------------------------------------------------

#[test]
fn every_fixture_loads_and_validates() {
    let corpus = corpus();
    assert_eq!(corpus.fixtures().len(), 29, "16 positive and 13 negative");
    let positive = corpus
        .fixtures()
        .iter()
        .filter(|fixture| fixture.class == FixtureClass::Positive)
        .count();
    assert_eq!(positive, 16);
    let ids: BTreeSet<&str> = corpus.fixtures().iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids.len(), corpus.fixtures().len(), "ids are unique");
}

#[test]
fn every_fixture_signs_and_its_signature_verifies() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    for fixture in corpus.fixtures() {
        let signed = signer
            .sign(fixture, &binding())
            .unwrap_or_else(|error| panic!("{} signs: {error}", fixture.id));
        signer
            .verify_signature(&signed)
            .unwrap_or_else(|error| panic!("{} verifies: {error}", fixture.id));
    }
}

#[test]
fn a_signed_token_carries_the_declared_header_and_the_bound_claims() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    let fixture = corpus
        .fixture("thunderid-user-access")
        .expect("the fixture exists");
    let signed = signer.sign(fixture, &binding()).expect("signs");
    let segments: Vec<&str> = signed.expose().split('.').collect();
    assert_eq!(segments.len(), 3);
    let header = decode_segment(segments[0]);
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "at+jwt");
    assert!(header["kid"].as_str().is_some_and(|kid| !kid.is_empty()));
    let claims = decode_segment(segments[1]);
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["aud"], AUDIENCE);
    let iat = claims["iat"].as_i64().expect("iat is an integer");
    let exp = claims["exp"].as_i64().expect("exp is an integer");
    assert_eq!(exp - iat, 3600, "the lifetime is the fixture's offset");
}

#[test]
fn a_fixture_without_typ_signs_a_header_without_typ() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    let fixture = corpus.fixture("esignet-id-token").expect("exists");
    let signed = signer.sign(fixture, &binding()).expect("signs");
    let header = decode_segment(signed.expose().split('.').next().expect("header"));
    assert!(header.get("typ").is_none());
}

#[test]
fn each_declared_algorithm_signs_with_its_own_key() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    let mut seen = BTreeSet::new();
    for fixture in corpus.fixtures() {
        let Some(header) = &fixture.header else {
            continue;
        };
        let signed = signer.sign(fixture, &binding()).expect("signs");
        let signed_header = decode_segment(signed.expose().split('.').next().expect("header"));
        assert_eq!(signed_header["alg"], header.alg.as_str());
        seen.insert(header.alg.clone());
    }
    assert_eq!(
        seen,
        ["ES256", "HS256", "HS512", "RS256"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
}

#[test]
fn the_opaque_fixture_signs_to_its_synthetic_string() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    let fixture = corpus.fixture("supabase-api-key-opaque").expect("exists");
    let signed = signer.sign(fixture, &binding()).expect("signs");
    assert!(signed.is_opaque());
    assert!(!signed.expose().contains('.'));
    signer.verify_signature(&signed).expect("nothing to verify");
}

#[test]
fn the_public_key_set_holds_asymmetric_public_members_only() {
    let signer = TokenSigner::new();
    let set = signer.public_key_set();
    let keys = set["keys"].as_array().expect("keys is an array");
    let algs: BTreeSet<&str> = keys.iter().filter_map(|k| k["alg"].as_str()).collect();
    assert_eq!(algs, BTreeSet::from(["ES256", "EdDSA", "RS256"]));
    for key in keys {
        for member in PRIVATE_JWK_MEMBERS {
            assert!(key.get(member).is_none(), "public key set has `{member}`");
        }
    }
}

#[test]
fn two_signers_hold_different_keys() {
    let corpus = corpus();
    let fixture = corpus.fixture("thunderid-user-access").expect("exists");
    let first = TokenSigner::new();
    let second = TokenSigner::new();
    assert_ne!(first.public_key_set(), second.public_key_set());
    let signed = first.sign(fixture, &binding()).expect("signs");
    assert!(
        second.verify_signature(&signed).is_err(),
        "a token from one run does not verify under another run's key"
    );
}

#[test]
fn a_tampered_token_fails_verification() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    for id in ["thunderid-user-access", "supabase-api-key-anon"] {
        let fixture = corpus.fixture(id).expect("exists");
        let signed = signer.sign(fixture, &binding()).expect("signs");
        let mut segments: Vec<String> = signed.expose().split('.').map(str::to_owned).collect();
        let mut claims = decode_segment(&segments[1]);
        claims["sub"] = json!("someone-else");
        segments[1] = URL_SAFE_NO_PAD.encode(claims.to_string());
        let tampered = signed.with_text(segments.join("."));
        assert!(signer.verify_signature(&tampered).is_err(), "{id}");
    }
}

#[test]
fn a_debug_print_of_a_signed_token_does_not_show_it() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    let fixture = corpus.fixture("thunderid-user-access").expect("exists");
    let signed = signer.sign(fixture, &binding()).expect("signs");
    let shown = format!("{signed:?}");
    assert!(!shown.contains(signed.expose()));
    assert!(!shown.contains("eyJ"));
}

#[test]
fn every_expectation_row_names_an_existing_fixture_and_a_known_product() {
    let corpus = corpus();
    let expectations = corpus.expectations();
    let products: BTreeSet<&str> = expectations.products.iter().map(String::as_str).collect();
    assert_eq!(products.len(), 11);
    let ids: BTreeSet<&str> = corpus.fixtures().iter().map(|f| f.id.as_str()).collect();
    assert!(!expectations.rows.is_empty());
    for row in &expectations.rows {
        assert!(
            ids.contains(row.fixture.as_str()),
            "row names unknown fixture `{}`",
            row.fixture
        );
        for product in row.products.keys() {
            assert!(
                products.contains(product.as_str()),
                "row for `{}` names unknown product `{product}`",
                row.fixture
            );
        }
        let row_products: BTreeSet<&str> = row.products.keys().map(String::as_str).collect();
        assert_eq!(row_products, products, "row for `{}`", row.fixture);
    }
}

#[test]
fn every_fixture_has_a_row_and_no_row_repeats() {
    let corpus = corpus();
    let rows = &corpus.expectations().rows;
    let with_row: BTreeSet<&str> = rows.iter().map(|r| r.fixture.as_str()).collect();
    for fixture in corpus.fixtures() {
        assert!(with_row.contains(fixture.id.as_str()), "{}", fixture.id);
    }
    let keys: BTreeSet<(String, Against, Configuration)> = rows
        .iter()
        .map(|r| (r.fixture.clone(), r.against, r.configuration))
        .collect();
    assert_eq!(
        keys.len(),
        rows.len(),
        "a (fixture, against, configuration) repeats"
    );
}

#[test]
fn no_negative_fixture_is_expected_to_be_admitted() {
    let corpus = corpus();
    for row in &corpus.expectations().rows {
        let fixture = corpus.fixture(&row.fixture).expect("exists");
        if fixture.class != FixtureClass::Negative {
            continue;
        }
        for (product, cell) in &row.products {
            for outcome in [&cell.main, &cell.target] {
                assert!(
                    !matches!(outcome, Outcome::Admitted(_)),
                    "negative `{}` is admitted by `{product}`",
                    row.fixture
                );
            }
        }
    }
}

fn cell_with_changed_by(changed_by: &str) -> Result<ExpectedCell, serde_json::Error> {
    serde_json::from_value(json!({
        "main": "refused/scope",
        "target": "admitted",
        "basis": "observed",
        "changedBy": changed_by,
        "landed": false,
    }))
}

#[test]
fn changed_by_is_a_change_name_or_none() {
    for accepted in ["caller-contract", "posture", "none"] {
        cell_with_changed_by(accepted)
            .unwrap_or_else(|error| panic!("`{accepted}` is refused: {error}"));
    }
    for refused in [
        "M7",
        "Caller-Contract",
        "caller_contract",
        "-caller",
        "caller-",
        "7th",
        "",
    ] {
        let error = cell_with_changed_by(refused)
            .expect_err(&format!("`{refused}` is accepted"))
            .to_string();
        assert!(error.contains("changedBy"), "unhelpful error: {error}");
    }
}

#[test]
fn landed_appears_exactly_when_a_change_alters_the_cell() {
    let corpus = corpus();
    for row in &corpus.expectations().rows {
        for (product, cell) in &row.products {
            assert_eq!(
                cell.landed.is_some(),
                cell.changed_by.is_some(),
                "`{}` / `{product}`",
                row.fixture
            );
        }
    }
}

#[test]
fn no_fixture_file_holds_a_private_jwk_member_or_a_live_looking_token() {
    let dir = TokenCorpus::directory().join("fixtures");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("fixtures directory reads") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("fixture reads");
        let value: Value = serde_json::from_str(&text).expect("fixture is JSON");
        walk(&value, &mut |node| match node {
            Value::Object(map) => {
                for member in PRIVATE_JWK_MEMBERS {
                    assert!(
                        !map.contains_key(member),
                        "{} holds member `{member}`",
                        path.display()
                    );
                }
            }
            Value::String(text) => {
                assert!(
                    !text.starts_with("eyJ"),
                    "{} holds a string shaped like a JWT",
                    path.display()
                );
                assert!(
                    !text.contains("PRIVATE KEY"),
                    "{} holds key material",
                    path.display()
                );
            }
            _ => {}
        });
        checked += 1;
    }
    assert_eq!(checked, 29);
}

fn walk(value: &Value, visit: &mut impl FnMut(&Value)) {
    visit(value);
    match value {
        Value::Array(items) => items.iter().for_each(|item| walk(item, visit)),
        Value::Object(map) => map.values().for_each(|item| walk(item, visit)),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Validation refuses a bad fixture
// ---------------------------------------------------------------------------

#[test]
fn validation_accepts_the_minimal_fixture() {
    TokenFixture::parse("unit-fixture", &minimal_fixture(json!({}))).expect("valid");
}

#[test]
fn validation_refuses_an_id_that_differs_from_the_file_name() {
    let error = TokenFixture::parse("other-name", &minimal_fixture(json!({})))
        .expect_err("refused")
        .to_string();
    assert!(error.contains("file name"), "{error}");
}

#[test]
fn validation_refuses_a_private_jwk_member() {
    let error = parse_error(json!({ "notes": "x", "extra": { "kty": "EC", "d": "abc" } }));
    assert!(
        error.contains("private") || error.contains("unknown"),
        "{error}"
    );
    let mut text = minimal_fixture(json!({}));
    text = text.replace(
        "\"sub\":\"subject-1\"",
        "\"sub\":\"subject-1\",\"jwk\":{\"kty\":\"oct\",\"k\":\"c2VjcmV0\"}",
    );
    let error = TokenFixture::parse("unit-fixture", &text)
        .expect_err("refused")
        .to_string();
    assert!(error.contains("private"), "{error}");
}

#[test]
fn validation_refuses_a_string_shaped_like_a_jwt() {
    let text = minimal_fixture(json!({})).replace(
        "\"subject-1\"",
        "\"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl\"",
    );
    let error = TokenFixture::parse("unit-fixture", &text)
        .expect_err("refused")
        .to_string();
    assert!(error.contains("JWT"), "{error}");
}

#[test]
fn validation_refuses_a_claim_named_in_omits() {
    let error = parse_error(json!({ "omits": ["sub"] }));
    assert!(error.contains("omits"), "{error}");
}

#[test]
fn validation_refuses_a_fixture_with_both_opaque_and_claims() {
    let error = parse_error(json!({ "opaque": "synthetic-value" }));
    assert!(error.contains("opaque"), "{error}");
}

#[test]
fn validation_refuses_missing_exp() {
    let text = minimal_fixture(json!({})).replace(",\"exp\":{\"offsetSeconds\":300}", "");
    let error = TokenFixture::parse("unit-fixture", &text)
        .expect_err("refused")
        .to_string();
    assert!(error.contains("exp"), "{error}");
}

#[test]
fn validation_refuses_an_algorithm_outside_the_signer_set() {
    let error = parse_error(json!({ "header": { "alg": "none", "kid": { "generated": true } } }));
    assert!(error.contains("alg"), "{error}");
}

#[test]
fn validation_refuses_an_unknown_directive_member() {
    let text = minimal_fixture(json!({}))
        .replace("{\"bind\":\"issuer\"}", "{\"bind\":\"issuer\",\"extra\":1}");
    let error = TokenFixture::parse("unit-fixture", &text)
        .expect_err("refused")
        .to_string();
    assert!(error.contains("iss"), "{error}");
}

#[test]
fn validation_refuses_an_unknown_top_level_member() {
    let error = parse_error(json!({ "surprise": true }));
    assert!(error.contains("surprise"), "{error}");
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

#[test]
fn the_driver_runs_every_applicable_row_and_hands_the_closure_a_verifiable_token() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    let mut calls = 0usize;
    let report = corpus
        .run_product("breg", &signer, ISSUER, AUDIENCE, |case| {
            calls += 1;
            signer
                .verify_signature(&case.token)
                .expect("token verifies");
            Outcome::Refused(Stage::Header)
        })
        .expect("the run completes");
    assert_eq!(report.product, "breg");
    assert_eq!(report.rows.len(), corpus.expectations().rows.len());
    let skipped = report
        .rows
        .iter()
        .filter(|row| matches!(row.comparison, Comparison::NotApplicable))
        .count();
    assert_eq!(calls + skipped, report.rows.len());
    assert!(calls > 0);
    assert!(
        !report.mismatches().is_empty(),
        "a stand-in refusing everything differs"
    );
}

#[test]
fn the_driver_compares_against_main_unless_the_cell_has_landed() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    // Answer each case with exactly what the expectation says, then compare.
    let expected = corpus.expectations().clone();
    let report = corpus
        .run_product("casework", &signer, ISSUER, AUDIENCE, |case| {
            let row = expected
                .rows
                .iter()
                .find(|row| {
                    row.fixture == case.fixture.id
                        && row.against == case.against
                        && row.configuration == case.configuration
                })
                .expect("row exists");
            row.products["casework"].expected().clone()
        })
        .expect("the run completes");
    assert!(report.mismatches().is_empty(), "{:?}", report.mismatches());
    // The report never carries a token.
    assert!(!format!("{report:?}").contains("eyJ"));
}

#[test]
fn a_literal_audience_is_the_configured_audience_only_for_a_positive_recipe_row() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    let mut observed: Vec<(String, Configuration, String)> = Vec::new();
    corpus
        .run_product("breg", &signer, ISSUER, AUDIENCE, |case| {
            if case.fixture.id == "supabase-user-access" || case.fixture.id == "keycloak-id-token" {
                observed.push((
                    case.fixture.id.clone(),
                    case.configuration,
                    case.audience.clone(),
                ));
            }
            Outcome::None
        })
        .expect("the run completes");
    assert!(observed.contains(&(
        "supabase-user-access".to_owned(),
        Configuration::Default,
        AUDIENCE.to_owned()
    )));
    assert!(observed.contains(&(
        "supabase-user-access".to_owned(),
        Configuration::Recipe,
        "authenticated".to_owned()
    )));
    assert!(observed
        .iter()
        .filter(|(id, ..)| id == "keycloak-id-token")
        .all(|(_, _, audience)| audience == AUDIENCE));
}

#[test]
fn the_driver_refuses_an_unknown_product() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    let error = corpus
        .run_product("nonesuch", &signer, ISSUER, AUDIENCE, |_| Outcome::None)
        .expect_err("refused")
        .to_string();
    assert!(error.contains("nonesuch"), "{error}");
}

#[test]
fn outcomes_parse_and_print_the_values_expected_yaml_uses() {
    for text in [
        "admitted",
        "admitted/human",
        "admitted/unspecified",
        "refused/token-type",
        "refused/claims",
        "none",
        "n-a",
        "unknown",
    ] {
        let outcome: Outcome = text.parse().expect("parses");
        assert_eq!(outcome.to_string(), text);
    }
    for text in ["refused", "refused/nowhere", "admitted/", "yes", ""] {
        assert!(text.parse::<Outcome>().is_err(), "`{text}`");
    }
}

#[test]
fn the_async_driver_gives_the_same_report_as_the_sync_driver() {
    let corpus = corpus();
    let signer = TokenSigner::new();
    let answer = |case: &registry_platform_testing::FixtureCase| {
        if case.fixture.class == FixtureClass::Negative {
            Outcome::Refused(Stage::Header)
        } else {
            Outcome::Admitted(None)
        }
    };
    let sync = corpus
        .run_product("messaging", &signer, ISSUER, AUDIENCE, |case| answer(case))
        .expect("sync run");
    let asynchronous = futures::executor::block_on(corpus.run_product_async(
        "messaging",
        &signer,
        ISSUER,
        AUDIENCE,
        |case| async move { answer(&case) },
    ))
    .expect("async run");
    assert_eq!(sync, asynchronous);
}
