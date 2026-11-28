use super::*;
use crate::{
    DeclaredPosture, Posture, PostureSource, RuntimeConfigLoader, RuntimeEnvelope, RuntimeFileCheck,
};
use registry_platform_yaml::Severity;
use serde::Deserialize;

const ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: "registry.registrystack.org/example-runtime/v1alpha1",
    kind: "ExampleRuntimeConfig",
};

const HEAD: &str =
    "apiVersion: registry.registrystack.org/example-runtime/v1alpha1\nkind: ExampleRuntimeConfig\n";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer-core"))]
    core: CallerIssuerCore<AllowedClients>,
}

impl CallerIssuerEntry for Entry {
    type Clients = AllowedClients;

    fn core(&self) -> &CallerIssuerCore<AllowedClients> {
        &self.core
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Oidc {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuers"))]
    set: CallerIssuers<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Authentication {
    oidc: Oidc,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Example {
    authentication: Authentication,
}

const FIELD: &str = "/authentication/oidc/issuers";

fn document(issuers: &str) -> String {
    format!("{HEAD}authentication:\n  oidc:\n    issuers:\n{issuers}")
}

fn staff(extra: &str) -> String {
    format!(
        "      staff:\n        issuer: https://id.example.org/realms/registry\n        audience: registry-api\n        allowedClients: [case-portal, nightly-sync]\n{extra}"
    )
}

fn partners(extra: &str) -> String {
    format!(
        "      partners:\n        issuer: https://login.partner.example/v2.0\n        audience: api://registry\n        allowedClients: [partner-batch]\n{extra}"
    )
}

fn load(text: &str) -> Example {
    RuntimeConfigLoader::new_without_posture(ENVELOPE)
        .parse_str::<Example>(text, |_| None)
        .unwrap_or_else(|error| panic!("loads: {:?}", error.diagnostics()))
        .config
}

fn check(text: &str) -> Vec<registry_platform_yaml::Diagnostic> {
    load(text).authentication.oidc.set.check(FIELD)
}

fn codes(diagnostics: &[registry_platform_yaml::Diagnostic]) -> Vec<(&str, &str)> {
    diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect()
}

#[test]
fn an_entry_with_no_optional_member_takes_the_strict_defaults() {
    let config = load(&document(&staff("")));
    let (id, entry) = config.authentication.oidc.set.iter().next().expect("one");
    assert_eq!(id.as_str(), "staff");
    let core = entry.core();
    assert_eq!(core.access_token_type.get(), &AccessTokenType::AtJwt);
    assert_eq!(core.scope_claim.get().as_str(), "scope");
    assert!(core.actor_kind.is_none());
    assert!(core.client_actor_kinds.is_none());
    assert_eq!(
        core.allowed_clients.admitted(),
        Admitted::Listed(&["case-portal".to_owned(), "nightly-sync".to_owned()])
    );
    assert!(config.authentication.oidc.set.check(FIELD).is_empty());
}

#[test]
fn access_token_type_is_closed_to_at_jwt_and_jwt() {
    for accepted in ["at+jwt", "JWT"] {
        load(&document(&staff(&format!(
            "        accessTokenType: {accepted}\n"
        ))));
    }
    for refused in ["at-jwt", "jwt", "id_token", "application/at+jwt"] {
        let text = document(&staff(&format!("        accessTokenType: {refused}\n")));
        assert!(
            RuntimeConfigLoader::new_without_posture(ENVELOPE)
                .parse_str::<Example>(&text, |_| None)
                .is_err(),
            "{refused}"
        );
    }
}

#[test]
fn an_unknown_member_of_an_entry_is_refused() {
    let text = document(&staff("        allowedAlgorithm: RS256\n"));
    assert!(RuntimeConfigLoader::new_without_posture(ENVELOPE)
        .parse_str::<Example>(&text, |_| None)
        .is_err());
}

#[test]
fn an_empty_issuer_map_is_refused_as_no_issuer() {
    let text = format!("{HEAD}authentication:\n  oidc:\n    issuers: {{}}\n");
    let diagnostics = check(&text);
    assert_eq!(codes(&diagnostics), [("platform.oidc.no-issuer", FIELD)]);
    assert_eq!(diagnostics[0].severity, Severity::Error);
}

#[test]
fn two_entries_naming_one_issuer_are_refused_at_the_second() {
    let second = partners("").replace(
        "https://login.partner.example/v2.0",
        "https://id.example.org/realms/registry",
    );
    let diagnostics = check(&document(&format!("{}{second}", staff(""))));
    assert_eq!(
        codes(&diagnostics),
        [(
            "platform.oidc.duplicate-issuer",
            "/authentication/oidc/issuers/staff/issuer"
        )]
    );
}

#[test]
fn two_issuers_that_differ_are_not_duplicates() {
    assert!(check(&document(&format!("{}{}", staff(""), partners("")))).is_empty());
}

#[test]
fn a_client_listed_by_two_entries_is_refused_at_the_second_listing() {
    let second = partners("").replace("[partner-batch]", "[partner-batch, nightly-sync]");
    let diagnostics = check(&document(&format!("{}{second}", staff(""))));
    assert_eq!(
        codes(&diagnostics),
        [(
            "platform.oidc.client-in-two-issuers",
            "/authentication/oidc/issuers/staff/allowedClients/1"
        )]
    );
}

#[test]
fn each_client_listed_by_two_entries_is_refused_at_its_own_listing() {
    let second = partners("").replace(
        "[partner-batch]",
        "[nightly-sync, partner-batch, case-portal]",
    );
    let diagnostics = check(&document(&format!("{}{second}", staff(""))));
    assert_eq!(
        codes(&diagnostics),
        [
            (
                "platform.oidc.client-in-two-issuers",
                "/authentication/oidc/issuers/staff/allowedClients/0"
            ),
            (
                "platform.oidc.client-in-two-issuers",
                "/authentication/oidc/issuers/staff/allowedClients/1"
            ),
        ]
    );
    assert!(diagnostics.iter().all(|d| d.message.contains("partners")));
}

fn check_offline(text: &str, stand_in: fn(&str) -> &'static str) -> RuntimeFileCheck<Example> {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let path = directory.path().join("runtime.yaml");
    std::fs::write(&path, text).unwrap();
    RuntimeConfigLoader::new_without_posture(ENVELOPE)
        .check_offline::<Example>(&path, false, stand_in)
}

fn checked_file(text: &str) -> Vec<registry_platform_yaml::Diagnostic> {
    let file = check_offline(text, |_| crate::DEFAULT_STAND_IN);
    let config = &file.loaded.as_ref().expect("loads").config;
    config
        .authentication
        .oidc
        .set
        .check_file(FIELD, &file, "ExampleRuntimeConfig")
}

/// The 1-based line and column of `needle` on the `line`th line of `text`.
fn at(text: &str, line: usize, needle: &str) -> (Option<usize>, Option<usize>) {
    let column = text.lines().nth(line - 1).unwrap().find(needle).unwrap() + 1;
    (Some(line), Some(column))
}

#[test]
fn the_file_check_positions_a_duplicate_issuer_and_relates_the_first_entry() {
    let second = partners("").replace(
        "https://login.partner.example/v2.0",
        "https://id.example.org/realms/registry",
    );
    let text = document(&format!("{}{second}", staff("")));
    let diagnostics = checked_file(&text);
    assert_eq!(
        codes(&diagnostics),
        [(
            "platform.oidc.duplicate-issuer",
            "/authentication/oidc/issuers/staff/issuer"
        )]
    );
    let found = &diagnostics[0];
    assert_eq!(found.artifact.as_deref(), Some("ExampleRuntimeConfig"));
    let source = found.source.as_ref().expect("positioned");
    assert_eq!((source.line, source.column), at(&text, 7, "https://"));
    assert_eq!(found.related.len(), 1, "{found:?}");
    let related = &found.related[0];
    assert_eq!(related.path, "/authentication/oidc/issuers/partners/issuer");
    assert_eq!((related.line, related.column), at(&text, 11, "https://"));
    assert_eq!(related.file, source.file);
    assert!(related.message.contains("partners"), "{}", related.message);
}

#[test]
fn the_file_check_positions_a_client_at_its_listing_and_relates_the_first_listing() {
    let second = partners("").replace("[partner-batch]", "[partner-batch, nightly-sync]");
    let text = document(&format!("{}{second}", staff("")));
    let diagnostics = checked_file(&text);
    assert_eq!(
        codes(&diagnostics),
        [(
            "platform.oidc.client-in-two-issuers",
            "/authentication/oidc/issuers/staff/allowedClients/1"
        )]
    );
    let found = &diagnostics[0];
    let source = found.source.as_ref().expect("positioned");
    assert_eq!((source.line, source.column), at(&text, 9, "nightly-sync"));
    let related = &found.related[0];
    assert_eq!(
        related.path,
        "/authentication/oidc/issuers/partners/allowedClients/1"
    );
    assert_eq!(
        (related.line, related.column),
        at(&text, 13, "nightly-sync")
    );
}

#[test]
fn the_file_check_skips_a_comparison_of_members_it_did_not_fill() {
    let first = staff("").replace("https://id.example.org/realms/registry", "${STAFF_ISSUER}");
    let second = partners("").replace("https://login.partner.example/v2.0", "${PARTNER_ISSUER}");
    let text = document(&format!("{first}{second}"));
    let one_stand_in = |pointer: &str| {
        if pointer.ends_with("/issuer") {
            "https://issuer.example.org"
        } else {
            crate::DEFAULT_STAND_IN
        }
    };
    let file = check_offline(&text, one_stand_in);
    let config = &file.loaded.as_ref().expect("loads").config;
    let set = &config.authentication.oidc.set;
    assert_eq!(
        codes(&set.check(FIELD)),
        [(
            "platform.oidc.duplicate-issuer",
            "/authentication/oidc/issuers/staff/issuer"
        )],
        "the two stand-ins are one issuer"
    );
    assert!(set
        .check_file(FIELD, &file, "ExampleRuntimeConfig")
        .is_empty());
}

#[test]
fn two_entries_whose_issuers_differ_only_in_form_are_refused() {
    for (first, second) in [
        (
            "https://login.partner.example/v2.0",
            "https://LOGIN.Partner.example/v2.0",
        ),
        (
            "https://login.partner.example",
            "https://login.partner.example/",
        ),
    ] {
        let one = partners("").replace("https://login.partner.example/v2.0", first);
        let two = staff("").replace("https://id.example.org/realms/registry", second);
        let diagnostics = check(&document(&format!("{one}{two}")));
        assert_eq!(
            codes(&diagnostics),
            [(
                "platform.oidc.duplicate-issuer",
                "/authentication/oidc/issuers/staff/issuer"
            )],
            "{first} and {second}"
        );
    }
}

#[test]
fn a_client_actor_kind_keyed_by_an_empty_client_is_refused() {
    let text = document(&staff("")).replace("[case-portal, nightly-sync]", "unrestricted");
    let text = format!("{text}        clientActorKinds:\n          \"\": agent\n");
    let refused = RuntimeConfigLoader::new_without_posture(ENVELOPE)
        .parse_str::<Example>(&text, |_| None)
        .expect_err("an empty client is not a client identifier");
    assert!(
        refused.diagnostics().iter().any(|diagnostic| diagnostic
            .path
            .starts_with("/authentication/oidc/issuers/staff/clientActorKinds")),
        "{:?}",
        refused.diagnostics()
    );
}

#[test]
fn an_unrestricted_entry_does_not_collide_with_a_listing() {
    let second = partners("").replace("[partner-batch]", "unrestricted");
    assert!(check(&document(&format!("{}{second}", staff("")))).is_empty());
}

#[test]
fn an_actor_kind_for_the_issuer_and_for_clients_together_is_refused() {
    let extra =
        "        actorKind: service\n        clientActorKinds:\n          case-portal: human\n";
    let diagnostics = check(&document(&staff(extra)));
    assert_eq!(
        codes(&diagnostics),
        [(
            "platform.oidc.actor-kind-twice",
            "/authentication/oidc/issuers/staff/clientActorKinds"
        )]
    );
}

#[test]
fn a_client_actor_kind_for_a_client_the_entry_does_not_admit_is_refused() {
    let extra =
        "        clientActorKinds:\n          case-portal: human\n          stranger: agent\n";
    let diagnostics = check(&document(&staff(extra)));
    assert_eq!(
        codes(&diagnostics),
        [(
            "platform.oidc.actor-kind-for-unadmitted-client",
            "/authentication/oidc/issuers/staff/clientActorKinds/stranger"
        )]
    );
}

#[test]
fn under_unrestricted_any_client_may_be_given_a_kind() {
    let text = document(&staff("")).replace("[case-portal, nightly-sync]", "unrestricted");
    let text = format!("{text}        clientActorKinds:\n          anyone: agent\n");
    assert!(check(&text).is_empty());
}

#[test]
fn a_jwt_issuer_whose_audience_is_one_of_its_clients_is_refused() {
    let text = document(&staff("        accessTokenType: JWT\n"))
        .replace("audience: registry-api", "audience: case-portal");
    let diagnostics = check(&text);
    assert_eq!(
        codes(&diagnostics),
        [(
            "platform.oidc.audience-is-a-client",
            "/authentication/oidc/issuers/staff/audience"
        )]
    );
}

#[test]
fn an_audience_equal_to_a_client_is_not_refused_under_the_default_token_type() {
    let text = document(&staff("")).replace("audience: registry-api", "audience: case-portal");
    assert!(check(&text).is_empty());
}

#[test]
fn a_scope_claim_that_names_an_identity_claim_is_refused() {
    for reserved in ["sub", "client_id", "azp", "aud"] {
        let diagnostics = check(&document(&staff(&format!(
            "        scopeClaim: {reserved}\n"
        ))));
        assert_eq!(
            codes(&diagnostics),
            [(
                "platform.oidc.scope-claim-reserved",
                "/authentication/oidc/issuers/staff/scopeClaim"
            )],
            "{reserved}"
        );
    }
}

#[test]
fn every_problem_is_reported_in_one_run() {
    let second = partners("        accessTokenType: JWT\n")
        .replace(
            "https://login.partner.example/v2.0",
            "https://id.example.org/realms/registry",
        )
        .replace("api://registry", "partner-batch");
    let diagnostics = check(&document(&format!(
        "{}{second}",
        staff("        scopeClaim: azp\n")
    )));
    let found: Vec<&str> = diagnostics.iter().map(|d| d.code.as_str()).collect();
    for code in [
        "platform.oidc.duplicate-issuer",
        "platform.oidc.audience-is-a-client",
        "platform.oidc.scope-claim-reserved",
    ] {
        assert!(found.contains(&code), "{code}: {found:?}");
    }
    assert!(diagnostics.iter().all(|d| !d.suggested_action.is_empty()));
}

/// An explicit setting's code, pointer, and line and column.
type ListedSetting<'a> = (&'a str, Option<&'a str>, Option<(usize, usize)>);

#[test]
fn the_explicit_settings_of_an_entry_reach_the_posture_report_with_pointers() {
    let extra =
        "        accessTokenType: JWT\n        scopeClaim: scp\n        actorKind: service\n";
    let text = document(&staff(extra)).replace("[case-portal, nightly-sync]", "unrestricted");
    let loader = RuntimeConfigLoader::new(
        ENVELOPE,
        DeclaredPosture {
            posture: Posture::Production,
            source: PostureSource::Flag,
        },
    );
    let loaded = loader
        .parse_str::<Example>(&text, |_| None)
        .expect("explicit settings never refuse");
    let mut listed: Vec<ListedSetting> = loaded
        .posture
        .explicit_settings()
        .iter()
        .map(|found| {
            (
                found.setting.code,
                found.pointer.as_deref(),
                found.position.map(|at| (at.line, at.column)),
            )
        })
        .collect();
    listed.sort_unstable();
    let base = "/authentication/oidc/issuers/staff";
    let expected = [
        (
            "platform.posture.issuer-actor-kind",
            format!("{base}/actorKind"),
            (12, 20),
        ),
        (
            "platform.posture.jwt-access-token",
            format!("{base}/accessTokenType"),
            (10, 26),
        ),
        (
            "platform.posture.scope-claim",
            format!("{base}/scopeClaim"),
            (11, 21),
        ),
        (
            "platform.posture.unrestricted-clients",
            format!("{base}/allowedClients"),
            (9, 25),
        ),
    ];
    let expected: Vec<ListedSetting> = expected
        .iter()
        .map(|(code, pointer, at)| (*code, Some(pointer.as_str()), Some(*at)))
        .collect();
    assert_eq!(listed, expected);
}

#[test]
fn client_actor_kinds_are_an_explicit_setting() {
    let extra = "        clientActorKinds:\n          case-portal: human\n";
    let loader = RuntimeConfigLoader::new(
        ENVELOPE,
        DeclaredPosture {
            posture: Posture::Production,
            source: PostureSource::Flag,
        },
    );
    let loaded = loader
        .parse_str::<Example>(&document(&staff(extra)), |_| None)
        .expect("loads");
    let listed: Vec<&str> = loaded
        .posture
        .explicit_settings()
        .iter()
        .map(|found| found.setting.code)
        .collect();
    assert_eq!(listed, ["platform.posture.client-actor-kinds"]);
}

#[test]
fn the_defaults_record_no_explicit_setting() {
    let loader = RuntimeConfigLoader::new(
        ENVELOPE,
        DeclaredPosture {
            posture: Posture::Production,
            source: PostureSource::Flag,
        },
    );
    let loaded = loader
        .parse_str::<Example>(&document(&staff("")), |_| None)
        .expect("loads");
    assert!(loaded.posture.explicit_settings().is_empty());
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PackageEntry {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer-core"))]
    core: CallerIssuerCore<crate::PackageClients>,
}

impl CallerIssuerEntry for PackageEntry {
    type Clients = crate::PackageClients;

    fn core(&self) -> &CallerIssuerCore<crate::PackageClients> {
        &self.core
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PackageOidc {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuers"))]
    set: CallerIssuers<PackageEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PackageExample {
    oidc: PackageOidc,
}

#[test]
fn at_most_one_entry_may_take_its_clients_from_the_package() {
    let text = format!(
        "{HEAD}oidc:\n  issuers:\n    staff:\n      issuer: https://id.example.org/a\n      audience: a\n      allowedClients: from-package\n    partners:\n      issuer: https://id.example.org/b\n      audience: b\n      allowedClients: from-package\n"
    );
    let config = RuntimeConfigLoader::new_without_posture(ENVELOPE)
        .parse_str::<PackageExample>(&text, |_| None)
        .expect("loads")
        .config;
    let diagnostics = config.oidc.set.check("/oidc/issuers");
    assert_eq!(
        codes(&diagnostics),
        [(
            "platform.oidc.client-in-two-issuers",
            "/oidc/issuers/staff/allowedClients"
        )]
    );
}

#[test]
fn policy_clients_read_from_policies_or_a_list_and_refuse_the_rest() {
    for (text, expected) in [
        ("from-policies", PolicyClients::FromPolicies),
        (
            "[a, b]",
            PolicyClients::Listed(vec!["a".into(), "b".into()]),
        ),
    ] {
        let parsed = RuntimeConfigLoader::new_without_posture(ENVELOPE)
            .parse_str::<PolicyDoc>(&format!("{HEAD}clients: {text}\n"), |_| None)
            .expect("loads")
            .config;
        assert_eq!(parsed.clients, expected);
    }
    for refused in ["unrestricted", "[]", "from-package"] {
        assert!(RuntimeConfigLoader::new_without_posture(ENVELOPE)
            .parse_str::<PolicyDoc>(&format!("{HEAD}clients: {refused}\n"), |_| None)
            .is_err());
    }
}

#[derive(Debug, Deserialize)]
struct PolicyDoc {
    clients: PolicyClients,
}

#[test]
fn a_list_only_client_rule_refuses_unrestricted_and_an_empty_list() {
    #[derive(Debug, Deserialize)]
    struct Doc {
        clients: ClientList,
    }
    let ok = RuntimeConfigLoader::new_without_posture(ENVELOPE)
        .parse_str::<Doc>(&format!("{HEAD}clients: [a]\n"), |_| None)
        .expect("loads")
        .config;
    assert_eq!(ok.clients.admitted(), Admitted::Listed(&["a".to_owned()]));
    for refused in ["unrestricted", "[]"] {
        assert!(RuntimeConfigLoader::new_without_posture(ENVELOPE)
            .parse_str::<Doc>(&format!("{HEAD}clients: {refused}\n"), |_| None)
            .is_err());
    }
}

#[test]
fn one_audience_holds_for_one_entry_and_for_entries_that_agree() {
    let set = load(&document(&staff(""))).authentication.oidc.set;
    assert!(set.check_one_audience(FIELD, "taskGrantStatus").is_empty());

    let agreeing = partners("").replace("api://registry", "registry-api");
    let set = load(&document(&format!("{}{agreeing}", staff(""))))
        .authentication
        .oidc
        .set;
    assert!(set.check_one_audience(FIELD, "taskGrantStatus").is_empty());
}

#[test]
fn entries_naming_different_audiences_are_refused_where_one_audience_is_needed() {
    let set = load(&document(&format!("{}{}", staff(""), partners(""))))
        .authentication
        .oidc
        .set;
    assert!(set.check(FIELD).is_empty(), "the set alone allows them");
    let diagnostics = set.check_one_audience(FIELD, "taskGrantStatus");
    assert_eq!(
        codes(&diagnostics),
        [(
            "platform.oidc.audiences-differ",
            "/authentication/oidc/issuers/staff/audience"
        )]
    );
    let found = &diagnostics[0];
    assert_eq!(found.severity, Severity::Error);
    assert!(found.message.contains("partners"), "{}", found.message);
    assert!(
        found.message.contains("taskGrantStatus"),
        "{}",
        found.message
    );
    assert!(!found.message.contains("registry-api"), "{}", found.message);
    assert!(
        !found.message.contains("api://registry"),
        "{}",
        found.message
    );
}

#[test]
fn the_file_check_positions_a_differing_audience_and_relates_the_first_entry() {
    let text = document(&format!("{}{}", staff(""), partners("")));
    let file = check_offline(&text, |_| crate::DEFAULT_STAND_IN);
    let config = &file.loaded.as_ref().expect("loads").config;
    let diagnostics = config.authentication.oidc.set.check_one_audience_file(
        FIELD,
        "taskGrantStatus",
        &file,
        "ExampleRuntimeConfig",
    );
    assert_eq!(
        codes(&diagnostics),
        [(
            "platform.oidc.audiences-differ",
            "/authentication/oidc/issuers/staff/audience"
        )]
    );
    let found = &diagnostics[0];
    let source = found.source.as_ref().expect("positioned");
    assert_eq!((source.line, source.column), at(&text, 8, "registry-api"));
    let related = &found.related[0];
    assert_eq!(
        related.path,
        "/authentication/oidc/issuers/partners/audience"
    );
    assert_eq!(
        (related.line, related.column),
        at(&text, 12, "api://registry")
    );
}

#[test]
fn the_file_check_skips_an_audience_it_did_not_fill() {
    let first = staff("").replace("audience: registry-api", "audience: ${STAFF_AUDIENCE}");
    let text = document(&format!("{first}{}", partners("")));
    let file = check_offline(&text, |_| crate::DEFAULT_STAND_IN);
    let config = &file.loaded.as_ref().expect("loads").config;
    assert!(config
        .authentication
        .oidc
        .set
        .check_one_audience_file(FIELD, "taskGrantStatus", &file, "ExampleRuntimeConfig")
        .is_empty());
}
