// SPDX-License-Identifier: Apache-2.0
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

use registry_coordinator::{access::Action, runtime::RuntimeConfig};
use registry_platform_authcommon::FailedCheck;
use registry_platform_oidc::CallerKind;
use registry_platform_testing::{Binding, ClaimValue, TokenCorpus, TokenFixture, TokenSigner};
use serde_json::{json, Value};

const MAIN: &str = "https://main.example.test";
const PARTNER: &str = "https://partner.example.test";
const PRIMARY_CLIENT: &str = "institution-producer";
const PARTNER_CLIENT: &str = "institution-operator";
const ISSUERS: &str = "/deployment/authentication/issuers";

fn issuer(url: &str, audience: &str, key: &str, clients: Value) -> Value {
    json!({
        "issuer": url, "audience": audience,
        "jwksSource": {"type": "static", "documentRef": format!("secret:file/{key}.json")},
        "allowedClients": clients
    })
}

struct Runtime {
    root: tempfile::TempDir,
    document: Value,
}

impl Runtime {
    fn new(main_clients: Value) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut document = registry_platform_yaml::Reader::new("runtime.yaml")
            .scan(include_bytes!(
                "../../../products/coordinator/examples/single-flow-runtime.yaml"
            ))
            .unwrap()
            .unwrap()
            .to_json_value();
        document["secretProviders"]["file"]["root"] = json!(root.path());
        let auth = &mut document["deployment"]["authentication"];
        auth.as_object_mut()
            .unwrap()
            .retain(|key, _| key == "policies");
        auth["issuers"] = json!({"main": issuer(MAIN, "urn:main", "main", main_clients)});
        Self { root, document }
    }

    fn main(&mut self) -> &mut Value {
        self.document
            .pointer_mut(&format!("{ISSUERS}/main"))
            .unwrap()
    }

    fn partner(&mut self, clients: Value) {
        self.document.pointer_mut(ISSUERS).unwrap()["partner"] =
            issuer(PARTNER, "urn:partner", "partner", clients);
    }

    fn write(&self) -> std::path::PathBuf {
        let path = self.root.path().join("runtime.yaml");
        fs::write(&path, self.document.to_string()).unwrap();
        path
    }

    fn key(&self, name: &str) -> TokenSigner {
        let signer = TokenSigner::new();
        let mut keys = signer.public_key_set();
        keys["keys"]
            .as_array_mut()
            .unwrap()
            .retain(|key| key["kty"] != "OKP");
        let file = self.root.path().join(format!("{name}.json"));
        fs::write(&file, keys.to_string()).unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
        signer
    }

    async fn auth(&self) -> registry_coordinator::access::Authenticator {
        let cfg = RuntimeConfig::load(&self.write()).unwrap();
        cfg.deployment
            .unwrap()
            .authentication
            .authenticator(&cfg.secret_providers)
            .await
            .unwrap()
    }

    fn codes(&self) -> Vec<String> {
        RuntimeConfig::check_file(&self.write(), false)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect()
    }
}

fn token(client: &str, subject: &str, scope: &str) -> TokenFixture {
    let corpus = TokenCorpus::load().unwrap();
    let mut fixture = corpus
        .fixture("keycloak-client-credentials")
        .unwrap()
        .clone();
    fixture.header.as_mut().unwrap().typ = Some("at+jwt".into());
    for (claim, value) in [
        ("client_id", client),
        ("azp", client),
        ("sub", subject),
        ("scope", scope),
    ] {
        claim_value(&mut fixture, claim, json!(value));
    }
    fixture
}

fn claim_value(fixture: &mut TokenFixture, name: &str, value: Value) {
    fixture
        .claims
        .insert(name.into(), ClaimValue::Literal(value));
}

fn primary() -> TokenFixture {
    token(
        PRIMARY_CLIENT,
        "institution-producer-service-account",
        "coordinator:start",
    )
}

fn signed(signer: &TokenSigner, fixture: &TokenFixture, issuer: &str, audience: &str) -> String {
    signer
        .sign(
            fixture,
            &Binding {
                issuer: issuer.into(),
                audience: audience.into(),
            },
        )
        .unwrap()
        .expose()
        .into()
}

async fn refused(auth: &registry_coordinator::access::Authenticator, token: &str) -> FailedCheck {
    let Err(error) = auth.authenticate(token).await else {
        panic!("token was admitted")
    };
    assert_eq!(error.code, "access.unauthenticated");
    error.check.unwrap()
}

#[tokio::test]
async fn a_token_from_each_configured_issuer_is_verified_under_its_own_rules() {
    let mut r = Runtime::new(json!([PRIMARY_CLIENT]));
    r.partner(json!([PARTNER_CLIENT]));
    let main = r.key("main");
    let partner = r.key("partner");
    let auth = r.auth().await;
    let main_caller = auth
        .authenticate(&signed(&main, &primary(), MAIN, "urn:main"))
        .await
        .unwrap();
    assert_eq!(main_caller.actor.issuer, MAIN);
    main_caller
        .authorize(Action::Start, Some("delayed-follow-up"))
        .unwrap();
    let fixture = token(PARTNER_CLIENT, "operations-lead", "coordinator:operate");
    let partner_caller = auth
        .authenticate(&signed(&partner, &fixture, PARTNER, "urn:partner"))
        .await
        .unwrap();
    assert_eq!(partner_caller.actor.issuer, PARTNER);
    partner_caller.authorize_deployment(Action::Doctor).unwrap();
}

#[tokio::test]
async fn a_token_naming_one_issuer_signed_by_the_other_is_refused() {
    let mut r = Runtime::new(json!([PRIMARY_CLIENT]));
    r.partner(json!([PARTNER_CLIENT]));
    r.key("main");
    let partner = r.key("partner");
    assert_eq!(
        refused(
            &r.auth().await,
            &signed(&partner, &primary(), MAIN, "urn:main")
        )
        .await,
        FailedCheck::TokenKey
    );
}

#[tokio::test]
async fn a_token_from_an_unconfigured_issuer_is_refused() {
    let r = Runtime::new(json!("from-policies"));
    let main = r.key("main");
    assert_eq!(
        refused(
            &r.auth().await,
            &signed(&main, &primary(), PARTNER, "urn:main")
        )
        .await,
        FailedCheck::TokenIssuer
    );
}

#[test]
fn two_issuers_with_the_same_iss_refuse_at_startup() {
    let mut r = Runtime::new(json!([PRIMARY_CLIENT]));
    r.partner(json!([PARTNER_CLIENT]));
    r.document
        .pointer_mut(&format!("{ISSUERS}/partner"))
        .unwrap()["issuer"] = json!(MAIN);
    let Err(error) = RuntimeConfig::load(&r.write()) else {
        panic!("duplicate issuer was accepted")
    };
    assert!(error
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "platform.oidc.duplicate-issuer"));
}

#[test]
fn a_policy_client_as_a_jwt_audience_is_refused() {
    let mut r = Runtime::new(json!("from-policies"));
    r.main()["accessTokenType"] = json!("JWT");
    r.main()["audience"] = json!(PRIMARY_CLIENT);
    assert!(r
        .codes()
        .iter()
        .any(|code| code == "platform.oidc.audience-is-a-client"));
    assert_startup_refusal(&r, "platform.oidc.audience-is-a-client");
}

#[test]
fn a_kind_for_a_client_with_no_policy_is_refused() {
    let mut r = Runtime::new(json!("from-policies"));
    r.main()["clientActorKinds"] = json!({"unlisted": "service"});
    assert!(r
        .codes()
        .iter()
        .any(|code| code == "platform.oidc.actor-kind-for-unadmitted-client"));
    assert_startup_refusal(&r, "platform.oidc.actor-kind-for-unadmitted-client");
}

#[tokio::test]
async fn an_absent_scope_claim_reads_scope() {
    let r = Runtime::new(json!("from-policies"));
    let main = r.key("main");
    assert!(r
        .auth()
        .await
        .authenticate(&signed(&main, &primary(), MAIN, "urn:main"))
        .await
        .is_ok());
}

#[test]
fn each_client_rule_conflict_is_reported() {
    let mut r = Runtime::new(json!("from-policies"));
    r.partner(json!("from-policies"));
    r.document.pointer_mut(ISSUERS).unwrap()["third"] = issuer(
        "https://third.example.test",
        "urn:third",
        "third",
        json!([PRIMARY_CLIENT, PARTNER_CLIENT]),
    );
    let check = RuntimeConfig::check_file(&r.write(), false);
    let conflicts: Vec<_> = check
        .diagnostics
        .iter()
        .filter(|d| d.code == "platform.oidc.client-in-two-issuers")
        .collect();
    assert_eq!(conflicts.len(), 3, "{:?}", check.diagnostics);
    assert!(conflicts.iter().all(|d| d
        .related
        .iter()
        .any(|a| a.path == format!("{ISSUERS}/main/allowedClients"))));
}

#[test]
fn an_unfilled_issuer_does_not_hide_conflicts_and_an_unfilled_client_defers_them() {
    let mut r = Runtime::new(json!("from-policies"));
    r.partner(json!([PRIMARY_CLIENT]));
    let partner = format!("{ISSUERS}/partner");
    r.document.pointer_mut(&partner).unwrap()["issuer"] = json!("${UNSET_ISSUER}");
    assert!(r
        .codes()
        .contains(&"platform.oidc.client-in-two-issuers".to_owned()));
    r.document.pointer_mut(&partner).unwrap()["allowedClients"] =
        json!([PRIMARY_CLIENT, "${UNSET_CLIENT}"]);
    r.main()["clientActorKinds"] = json!({"unlisted":"service"});
    let codes = r.codes();
    assert!(!codes.contains(&"platform.oidc.client-in-two-issuers".to_owned()));
    assert!(codes.contains(&"platform.oidc.actor-kind-for-unadmitted-client".to_owned()));
}

#[test]
fn an_uncovered_policy_client_is_refused_and_defers_only_on_allowed_clients() {
    let mut r = Runtime::new(json!([PRIMARY_CLIENT]));
    r.main()["issuer"] = json!("${UNSET_ISSUER}");
    let code = "coordinator.access.policy-client-not-allowed".to_owned();
    let check = RuntimeConfig::check_file(&r.write(), false);
    let missing = check.diagnostics.iter().find(|d| d.code == code).unwrap();
    assert_eq!(
        missing.path,
        format!("/deployment/authentication/policies/{PARTNER_CLIENT}")
    );
    assert_eq!(
        missing.related[0].path,
        format!("{ISSUERS}/main/allowedClients")
    );
    r.main()["allowedClients"] = json!([PRIMARY_CLIENT, "${UNSET_CLIENT}"]);
    let check = RuntimeConfig::check_file(&r.write(), false);
    assert!(check.loaded.is_some());
    assert!(!check.diagnostics.iter().any(|d| d.code == code));
}

#[test]
fn each_removed_member_names_its_place_in_the_issuer_entry() {
    for (name, value) in [
        ("issuer", json!(MAIN)),
        ("audience", json!("urn:obsolete")),
        ("jwksSource", json!({"type": "discovery"})),
        ("allowInsecureHttp", json!(true)),
        ("assertionIssuers", json!({(PRIMARY_CLIENT): [MAIN]})),
        ("scopeClaim", json!("scope")),
    ] {
        let mut r = Runtime::new(json!("from-policies"));
        r.document["deployment"]["authentication"][name] = value;
        let check = RuntimeConfig::check_file(&r.write(), false);
        assert!(
            check.diagnostics.iter().any(|d| d.path
                == format!("/deployment/authentication/{name}")
                && d.suggested_action.contains(&format!(
                    "deployment.authentication.issuers.ISSUER_ID.{name}"
                ))),
            "{name}: {:?}",
            check.diagnostics
        );
    }
}

#[tokio::test]
async fn a_jwt_typed_token_is_admitted_when_the_issuer_states_it() {
    let mut r = Runtime::new(json!("from-policies"));
    r.main()["accessTokenType"] = json!("JWT");
    let signer = r.key("main");
    let mut fixture = primary();
    fixture.header.as_mut().unwrap().typ = Some("JWT".into());
    assert!(r
        .auth()
        .await
        .authenticate(&signed(&signer, &fixture, MAIN, "urn:main"))
        .await
        .is_ok());
}

#[tokio::test]
async fn an_unlisted_client_is_refused() {
    let r = Runtime::new(json!("from-policies"));
    let signer = r.key("main");
    let fixture = token(
        "unlisted",
        "institution-producer-service-account",
        "coordinator:start",
    );
    assert_eq!(
        refused(
            &r.auth().await,
            &signed(&signer, &fixture, MAIN, "urn:main")
        )
        .await,
        FailedCheck::TokenClient
    );
}

#[tokio::test]
async fn a_policy_client_in_a_token_from_another_issuer_is_refused() {
    let mut r = Runtime::new(json!([PRIMARY_CLIENT]));
    r.partner(json!([PARTNER_CLIENT]));
    r.key("main");
    let partner = r.key("partner");
    assert_eq!(
        refused(
            &r.auth().await,
            &signed(&partner, &primary(), PARTNER, "urn:partner")
        )
        .await,
        FailedCheck::TokenClient
    );
}

#[test]
fn a_refused_check_still_lists_the_explicit_production_settings() {
    let mut r = Runtime::new(json!("from-policies"));
    r.main()["accessTokenType"] = json!("JWT");
    r.document["deployment"]["packages"] = json!([]);
    let result = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["check", "--format", "json", "--runtime-config"])
        .arg(r.write())
        .output()
        .unwrap();
    assert!(!result.status.success());
    let stdout = String::from_utf8(result.stdout).unwrap();
    let posture = stdout.find("\"posture\"").unwrap();
    let explicit = stdout.find("\"explicitProductionSettings\"").unwrap();
    assert!(posture < explicit);
    let value: Value = serde_json::from_str(&stdout).unwrap();
    assert!(value["explicitProductionSettings"]
        .to_string()
        .contains("platform.posture.jwt-access-token"));
}

fn generate(runtime: &Runtime, output: &Path, issuer: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"));
    command
        .args(["generate", "identity-facts", "--runtime-config"])
        .arg(runtime.write())
        .arg("--output")
        .arg(output);
    if let Some(issuer) = issuer {
        command.args(["--issuer", issuer]);
    }
    command.output().unwrap()
}

#[test]
fn identity_facts_state_each_policy_client_its_scopes_and_sub() {
    let r = Runtime::new(json!("from-policies"));
    let output = r.root.path().join("facts.json");
    let result = generate(&r, &output, None);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let facts = fs::read(&output).unwrap();
    let read =
        |bytes| registry_thunderid_tooling::identity_facts::read("facts.yaml", bytes).unwrap();
    assert_eq!(
        read(&facts),
        read(include_bytes!("golden/identity_facts.yaml"))
    );
}

#[test]
fn identity_facts_require_an_issuer_when_two_entries_are_present() {
    let mut r = Runtime::new(json!([PRIMARY_CLIENT]));
    r.partner(json!([PARTNER_CLIENT]));
    let result = generate(&r, &r.root.path().join("facts.json"), None);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("identity.facts.issuer-required"));
}

#[test]
fn identity_facts_refuse_an_unknown_issuer() {
    let r = Runtime::new(json!("from-policies"));
    let result = generate(&r, &r.root.path().join("facts.json"), Some("absent"));
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("identity.facts.unknown-issuer"));
}

#[test]
fn identity_facts_leave_an_existing_output_untouched() {
    let r = Runtime::new(json!("from-policies"));
    let output = r.root.path().join("facts.json");
    fs::write(&output, "existing contents").unwrap();
    let result = generate(&r, &output, None);
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("the output file could not be created")
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains(output.to_str().unwrap()));
    assert_eq!(fs::read_to_string(output).unwrap(), "existing contents");
}

#[tokio::test]
async fn a_token_without_a_kind_authenticates_as_unspecified() {
    let r = Runtime::new(json!("from-policies"));
    let signer = r.key("main");
    let caller = r
        .auth()
        .await
        .authenticate(&signed(&signer, &primary(), MAIN, "urn:main"))
        .await
        .unwrap();
    assert_eq!(caller.kind, CallerKind::Unspecified);
}

#[tokio::test]
async fn a_declared_client_kind_admits_a_token_without_a_kind() {
    let mut r = Runtime::new(json!("from-policies"));
    r.main()["clientActorKinds"] = json!({(PRIMARY_CLIENT): "service"});
    let signer = r.key("main");
    let caller = r
        .auth()
        .await
        .authenticate(&signed(&signer, &primary(), MAIN, "urn:main"))
        .await
        .unwrap();
    assert_eq!(
        caller.kind,
        CallerKind::Declared(registry_platform_oidc::ActorKind::Service)
    );
}

#[tokio::test]
async fn the_same_token_reaches_the_same_profile_in_both_postures() {
    let r = Runtime::new(json!("from-policies"));
    let signer = r.key("main");
    let raw = signed(&signer, &primary(), MAIN, "urn:main");
    let path = r.write();
    for posture in ["production", "development"] {
        let declared = registry_platform_config::declared_from(Some(posture), None).unwrap();
        let config = RuntimeConfig::load_with_posture(&path, declared).unwrap();
        assert_eq!(config.posture().as_str(), posture);
        let auth = config
            .deployment
            .unwrap()
            .authentication
            .authenticator(&config.secret_providers)
            .await
            .unwrap();
        let caller = auth.authenticate(&raw).await.unwrap();
        assert_eq!(caller.actor.client_id, PRIMARY_CLIENT);
        assert_eq!(
            caller.authorized_workflows(Action::Start).unwrap(),
            ["delayed-follow-up"]
        );
    }
}

#[test]
fn an_unfilled_client_does_not_hide_another_pair_of_entries_in_conflict() {
    let mut r = Runtime::new(json!(["${UNSET_CLIENT}"]));
    r.partner(json!([PRIMARY_CLIENT]));
    r.document.pointer_mut(ISSUERS).unwrap()["third"] = issuer(
        "https://third.example.test",
        "urn:third",
        "third",
        json!([PRIMARY_CLIENT]),
    );
    let check = RuntimeConfig::check_file(&r.write(), false);
    assert!(
        check.diagnostics.iter().any(|d| {
            d.code == "platform.oidc.client-in-two-issuers"
                && d.path == format!("{ISSUERS}/third/allowedClients/0")
                && d.related[0].path == format!("{ISSUERS}/partner/allowedClients/0")
        }),
        "{:?}",
        check.diagnostics
    );
}

fn cli_check(r: &Runtime, posture: &str, format: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args([
            "check",
            "--posture",
            posture,
            "--format",
            format,
            "--runtime-config",
        ])
        .arg(r.write())
        .output()
        .unwrap()
}

#[test]
fn only_the_explicit_setting_at_the_refused_pointer_is_excluded() {
    let mut r = Runtime::new(json!("from-policies"));
    r.main()["accessTokenType"] = json!("JWT");
    r.main()["audience"] = json!(PRIMARY_CLIENT);
    r.main()["scopeClaim"] = json!("sub");
    let output = cli_check(&r, "production", "json");
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let diagnostics = report["diagnostics"].as_array().unwrap();
    for (code, setting) in [
        ("platform.oidc.audience-is-a-client", "audience"),
        ("platform.oidc.scope-claim-reserved", "scopeClaim"),
    ] {
        assert!(
            diagnostics
                .iter()
                .any(|d| d["code"] == code && d["path"] == format!("{ISSUERS}/main/{setting}")),
            "{report}"
        );
    }
    let explicit = report["explicitProductionSettings"].as_array().unwrap();
    assert_eq!(explicit.len(), 1, "{report}");
    assert_eq!(explicit[0]["code"], "platform.posture.jwt-access-token");
}

#[test]
fn human_check_prints_the_explicit_setting_with_its_pointer() {
    let mut r = Runtime::new(json!("from-policies"));
    r.main()["accessTokenType"] = json!("JWT");
    let output = cli_check(&r, "production", "human");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.lines().any(|line| line == format!(
        "Explicit production setting platform.posture.jwt-access-token at {ISSUERS}/main/accessTokenType. admits access tokens typed JWT. ID tokens stay refused."
    )), "{stdout}");
}

#[test]
fn facts_refusal_names_the_policy_and_the_reader_rule() {
    let mut r = Runtime::new(json!("from-policies"));
    let policies = r.document["deployment"]["authentication"]["policies"]
        .as_object_mut()
        .unwrap();
    let policy = policies.remove(PRIMARY_CLIENT).unwrap();
    policies.insert("Payments.Client".into(), policy);
    let output = r.root.path().join("facts.yaml");
    let result = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args([
            "generate",
            "identity-facts",
            "--format",
            "json",
            "--runtime-config",
        ])
        .arg(r.write())
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(
        report["diagnostics"].as_array().unwrap().iter().any(|d| {
            d["code"] == "identity.facts.invalid-id"
                && d["related"][0]["path"] == "/deployment/authentication/policies/Payments.Client"
                && d["message"].as_str().unwrap().contains("local identifier")
                && d["suggestedAction"]
                    .as_str()
                    .is_some_and(|text| text.contains("lowercase"))
        }),
        "{report}"
    );
}

#[tokio::test]
async fn production_refuses_the_test_issuer_key_source_and_development_loads_it() {
    let mut r = Runtime::new(json!("from-policies"));
    r.main()["jwksSource"]["type"] = json!("test-issuer");
    let signer = r.key("main");
    let code = "platform.posture.test-issuer";
    let path = r.write();
    assert_startup_refusal(&r, code);
    let production = cli_check(&r, "production", "json");
    assert!(!production.status.success());
    let output: Value = serde_json::from_slice(&production.stdout).unwrap();
    assert!(
        output["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == code),
        "{output}"
    );
    let development = registry_platform_config::declared_from(Some("development"), None).unwrap();
    let config = RuntimeConfig::load_with_posture(&path, development).unwrap();
    assert_eq!(config.posture().as_str(), "development");
    let auth = config
        .deployment
        .unwrap()
        .authentication
        .authenticator(&config.secret_providers)
        .await
        .unwrap();
    auth.authenticate(&signed(&signer, &primary(), MAIN, "urn:main"))
        .await
        .unwrap();
    let development = cli_check(&r, "development", "json");
    assert!(
        development.status.success(),
        "{}",
        String::from_utf8_lossy(&development.stdout)
    );
}

#[test]
fn a_listed_entry_cannot_be_used_beside_from_policies() {
    let mut r = Runtime::new(json!("from-policies"));
    r.partner(json!(["client-without-policy"]));
    let code = "coordinator.access.listed-clients-without-policy";
    assert_startup_refusal(&r, code);
    let result = cli_check(&r, "production", "json");
    assert!(!result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(
        report["diagnostics"].as_array().unwrap().iter().any(|d| {
            d["code"] == code && d["path"] == format!("{ISSUERS}/partner/allowedClients")
        }),
        "{report}"
    );
}

fn assert_startup_refusal(r: &Runtime, code: &str) {
    let Err(error) = RuntimeConfig::load(&r.write()) else {
        panic!("startup accepted a runtime that should report {code}");
    };
    assert!(error.diagnostics.iter().any(|d| d.code == code), "{error}");
}

#[test]
fn an_assertion_issuer_must_name_a_client_admitted_by_its_entry() {
    let mut r = Runtime::new(json!([PRIMARY_CLIENT]));
    r.partner(json!([PARTNER_CLIENT]));
    r.main()["assertionIssuers"] = json!({(PARTNER_CLIENT): [PARTNER]});
    let code = "coordinator.access.configuration";
    assert_startup_refusal(&r, code);
    let check = RuntimeConfig::check_file(&r.write(), false);
    assert!(
        check
            .diagnostics
            .iter()
            .any(|d| { d.code == code && d.path == format!("{ISSUERS}/main/assertionIssuers") }),
        "{:?}",
        check.diagnostics
    );
}

#[test]
fn startup_checks_policy_client_coverage() {
    let r = Runtime::new(json!([PRIMARY_CLIENT]));
    assert_startup_refusal(&r, "coordinator.access.policy-client-not-allowed");
}

#[test]
fn report_write_failure_returns_an_operational_error() {
    use std::{os::fd::OwnedFd, os::unix::net::UnixStream, process::Stdio};
    let r = Runtime::new(json!("from-policies"));
    let (writer, reader) = UnixStream::pair().unwrap();
    drop(reader);
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["check", "--format", "json", "--runtime-config"])
        .arg(r.write())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("the CLI report could not be written"));
}

#[tokio::test]
async fn an_openid_only_policy_requires_a_declared_client_kind_for_an_identity_only_token() {
    let mut r = Runtime::new(json!("from-policies"));
    r.document["deployment"]["authentication"]["policies"][PRIMARY_CLIENT]["requiredScopes"] =
        json!(["openid"]);
    let signer = r.key("main");
    let mut fixture = primary();
    claim_value(&mut fixture, "scope", json!("openid"));
    let raw = signed(&signer, &fixture, MAIN, "urn:main");
    assert_eq!(refused(&r.auth().await, &raw).await, FailedCheck::ActorKind);
    r.main()["clientActorKinds"] = json!({(PRIMARY_CLIENT): "service"});
    let caller = r.auth().await.authenticate(&raw).await.unwrap();
    caller
        .authorize(Action::Start, Some("delayed-follow-up"))
        .unwrap();
}

#[test]
fn a_refused_explicit_setting_stays_excluded_when_diagnostics_are_truncated() {
    let clients = json!((0..64).map(|n| format!("client-{n}")).collect::<Vec<_>>());
    let mut r = Runtime::new(clients.clone());
    r.partner(clients.clone());
    let issuers = r.document.pointer_mut(ISSUERS).unwrap();
    issuers["third"] = issuer("https://third.example.test", "urn:third", "third", clients);
    issuers["zzz"] = issuer(
        "https://last.example.test",
        "urn:last",
        "last",
        json!([PRIMARY_CLIENT, PARTNER_CLIENT]),
    );
    issuers["zzz"]["scopeClaim"] = json!("sub");
    issuers["zzz"]["accessTokenType"] = json!("JWT");
    let result = cli_check(&r, "production", "json");
    assert!(!result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    let diagnostics = report["diagnostics"].as_array().unwrap();
    assert!(diagnostics
        .iter()
        .any(|d| d["code"] == "config.too-many-problems"));
    assert!(!diagnostics
        .iter()
        .any(|d| d["code"] == "platform.oidc.scope-claim-reserved"));
    let explicit = report["explicitProductionSettings"].as_array().unwrap();
    assert_eq!(explicit.len(), 1, "{explicit:?}");
    assert_eq!(explicit[0]["code"], "platform.posture.jwt-access-token");
}
