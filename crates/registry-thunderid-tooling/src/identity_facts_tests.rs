use super::*;

const BREG: &str = "apiVersion: id.registrystack.org/formats/platform/identity-facts/v1
kind: PlatformIdentityFacts
product: breg
issuer: https://id.registry.example
audience: urn:breg:example
allowedClients:
  - case-portal
  - field-agent
claims:
  registry_actor_kind: string
  registry_purpose: string
accessProfiles:
  - id: case-read
    scopes: [records:get, records:search]
    purposes: [eligibility]
  - id: case-write
    scopes: [records:patch]
";

const EVIDENCE: &str = "apiVersion: id.registrystack.org/formats/platform/identity-facts/v1
kind: PlatformIdentityFacts
product: evidence
issuer: https://id.registry.example
audience: urn:evidence:example
allowedClients: unrestricted
claims:
  registry_actor_kind: string
  evidence_tags: string-array
accessProfiles:
  - id: invoke
    scopes: [evidence:invoke]
    requesterClients: [field-agent]
assertionIssuers:
  - id: authority
    issuer: https://authority.example
    jwksUrl: https://authority.example/jwks
    mapping: institutional-grant
";

fn facts(text: &str) -> IdentityFacts {
    read("facts.yaml", text.as_bytes()).expect("facts read")
}

fn refusal(result: Result<MergedFacts, ToolingError>) -> &'static str {
    match result {
        Err(ToolingError::IdentityRefused { code, .. }) => code,
        other => panic!("expected an identity refusal, got {other:?}"),
    }
}

#[test]
fn a_facts_document_reads_and_round_trips() {
    let breg = facts(BREG);
    assert_eq!(breg.product, "breg");
    assert_eq!(
        breg.allowed_clients,
        Admission::Clients(vec!["case-portal".into(), "field-agent".into()])
    );
    assert_eq!(breg.access_profiles[0].purposes, ["eligibility"]);
    assert_eq!(facts(EVIDENCE).allowed_clients, Admission::Unrestricted);
    let written = breg.to_yaml().expect("facts write");
    assert_eq!(facts(&written), breg);
    assert!(written.starts_with("apiVersion: "));
}

#[test]
fn unknown_keys_wrong_kinds_and_empty_lists_are_refused() {
    for bad in [
        BREG.replace("kind: PlatformIdentityFacts", "kind: PlatformTaskConnection"),
        format!("{BREG}surprise: true\n"),
        BREG.replace(
            "allowedClients:\n  - case-portal\n  - field-agent\n",
            "allowedClients: []\n",
        ),
        BREG.replace("issuer: https://id.registry.example", "issuer: not-a-url"),
        BREG.replace("registry_purpose: string", "registry_purpose: number"),
    ] {
        assert!(
            read("facts.yaml", bad.as_bytes()).is_err(),
            "accepted:\n{bad}"
        );
    }
}

#[test]
fn protected_claims_and_dangling_exchange_issuers_are_refused() {
    let protected = BREG.replace("registry_purpose: string", "registry_grant_id: string");
    assert!(read("facts.yaml", protected.as_bytes()).is_err());
    let dangling = format!(
        "{BREG}    exchange:\n      assertionIssuerId: missing\n      bootstrapAudience: urn:casework:example\n      bootstrapScope: casework:grants:assert\n"
    );
    assert!(read("facts.yaml", dangling.as_bytes()).is_err());
}

#[test]
fn documents_merge_into_one_view() {
    let merged = merge(vec![facts(BREG), facts(EVIDENCE)]).expect("merge");
    assert_eq!(merged.issuer, "https://id.registry.example");
    assert_eq!(merged.products.len(), 2);
    assert_eq!(merged.products["breg"].audience, "urn:breg:example");
    assert_eq!(merged.claims["evidence_tags"], ClaimType::StringArray);
    assert_eq!(merged.claims["registry_actor_kind"], ClaimType::String);
    assert!(merged.assertion_issuers.contains_key("authority"));
}

#[test]
fn products_that_disagree_on_the_issuer_are_refused() {
    let other = EVIDENCE.replace(
        "issuer: https://id.registry.example",
        "issuer: https://other.example",
    );
    assert_eq!(
        refusal(merge(vec![facts(BREG), facts(&other)])),
        "identity.facts.issuer-mismatch"
    );
}

#[test]
fn a_claim_declared_with_two_types_is_refused() {
    let other = EVIDENCE.replace(
        "registry_actor_kind: string",
        "registry_actor_kind: string-array",
    );
    assert_eq!(
        refusal(merge(vec![facts(BREG), facts(&other)])),
        "identity.facts.claim-conflict"
    );
}

#[test]
fn a_product_or_audience_stated_twice_is_refused() {
    assert_eq!(
        refusal(merge(vec![facts(BREG), facts(BREG)])),
        "identity.facts.duplicate-product"
    );
    let same_audience = EVIDENCE
        .replace("product: evidence", "product: other")
        .replace("urn:evidence:example", "urn:breg:example");
    assert_eq!(
        refusal(merge(vec![facts(BREG), facts(&same_audience)])),
        "identity.facts.duplicate-audience"
    );
}

#[test]
fn an_assertion_issuer_is_shared_only_when_stated_identically() {
    let casework = EVIDENCE.replace("product: evidence", "product: casework").replace(
        "urn:evidence:example",
        "urn:casework:example",
    );
    assert!(merge(vec![facts(EVIDENCE), facts(&casework)]).is_ok());
    let different = casework.replace(
        "jwksUrl: https://authority.example/jwks",
        "jwksUrl: https://authority.example/other-jwks",
    );
    assert_eq!(
        refusal(merge(vec![facts(EVIDENCE), facts(&different)])),
        "identity.facts.assertion-issuer-conflict"
    );
    // Two products whose authorities derive one id are refused, never
    // merged: one entry would bind both products' exchanges to one issuer.
    let other_issuer = casework.replace(
        "issuer: https://authority.example\n",
        "issuer: https://authority.example/other\n",
    );
    assert_ne!(other_issuer, casework);
    assert_eq!(
        refusal(merge(vec![facts(EVIDENCE), facts(&other_issuer)])),
        "identity.facts.assertion-issuer-conflict"
    );
}

#[test]
fn merging_nothing_is_refused() {
    assert_eq!(refusal(merge(vec![])), "identity.facts.none");
}

const SELECTING: &str = "apiVersion: id.registrystack.org/formats/platform/identity-facts/v1
kind: PlatformIdentityFacts
product: evidence
issuer: https://id.registry.example
audience: urn:evidence:example
allowedClients: unrestricted
claims:
  registry_actor_kind: string
  evidence_tags: string-array
accessProfiles:
  - id: invoke
    scopes: [evidence:invoke]
    selectedBy:
      registry_actor_kind: [agent]
      evidence_tags: [field, audit]
  - id: unselected
    scopes: [evidence:read]
";

#[test]
fn a_profile_states_the_claim_values_that_select_it() {
    let evidence = facts(SELECTING);
    let selected = &evidence.access_profiles[0].selected_by;
    assert_eq!(selected["registry_actor_kind"], ["agent"]);
    assert_eq!(selected["evidence_tags"], ["field", "audit"]);
    assert!(evidence.access_profiles[1].selected_by.is_empty());
    let written = evidence.to_yaml().expect("facts write");
    assert_eq!(facts(&written), evidence);
}

#[test]
fn selectors_must_name_declared_claims_in_their_declared_shape() {
    for bad in [
        SELECTING.replace(
            "      registry_actor_kind: [agent]\n",
            "      undeclared_claim: [agent]\n",
        ),
        SELECTING.replace("registry_actor_kind: [agent]", "registry_actor_kind: [agent, human]"),
        SELECTING.replace("evidence_tags: [field, audit]", "evidence_tags: []"),
        SELECTING.replace("evidence_tags: [field, audit]", "evidence_tags: [field, field]"),
        SELECTING.replace("registry_actor_kind: [agent]", "registry_actor_kind: agent"),
        SELECTING.replace("registry_actor_kind: [agent]", "registry_actor_kind: [\"a b\\n\"]"),
    ] {
        assert!(
            read("facts.yaml", bad.as_bytes()).is_err(),
            "accepted:\n{bad}"
        );
    }
}

#[test]
fn an_actor_kind_selector_names_a_kind_the_runtime_parses() {
    for kind in ["robot", "Service"] {
        let bad = SELECTING.replace(
            "registry_actor_kind: [agent]",
            &format!("registry_actor_kind: [{kind}]"),
        );
        let Err(ToolingError::FileRefused { report, .. }) = read("facts.yaml", bad.as_bytes())
        else {
            panic!("accepted:\n{bad}");
        };
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "identity.facts.unknown-actor-kind"),
            "refused for another reason:\n{bad}"
        );
    }
}

#[test]
fn a_profile_states_the_actor_kind_it_requires_of_the_declared_claim() {
    let requiring = BREG.replace(
        "  - id: case-write\n",
        "  - id: case-write\n    actorKind: service\n",
    );
    let breg = facts(&requiring);
    assert_eq!(breg.access_profiles[1].actor_kind, Some(ActorKind::Service));
    assert_eq!(breg.access_profiles[0].actor_kind, None);
    let written = breg.to_yaml().expect("facts write");
    assert_eq!(facts(&written), breg);
    for bad in [
        requiring.replace("actorKind: service", "actorKind: robot"),
        requiring.replace("actorKind: service", "actorKind: [service]"),
        requiring.replace("  registry_actor_kind: string\n", ""),
    ] {
        assert!(
            read("facts.yaml", bad.as_bytes()).is_err(),
            "accepted:\n{bad}"
        );
    }
}

/// Codes the reader refuses `text` with.
fn refused_codes(text: &str) -> Vec<String> {
    let Err(ToolingError::FileRefused { report, .. }) = read("facts.yaml", text.as_bytes()) else {
        panic!("accepted:\n{text}");
    };
    report
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

#[test]
fn a_profile_states_the_actor_kinds_it_admits_and_the_claims_that_refuse_it() {
    let admitting = BREG
        .replace(
            "  registry_purpose: string\n",
            "  registry_purpose: string\n  registry_actor: string\n",
        )
        .replace(
            "  - id: case-write\n",
            "  - id: case-write\n    admittedActorKinds: [human, service]\n    refusedClaims: [registry_actor]\n",
        );
    let breg = facts(&admitting);
    assert_eq!(
        breg.access_profiles[1].admitted_actor_kinds,
        [ActorKind::Human, ActorKind::Service]
    );
    assert_eq!(breg.access_profiles[1].refused_claims, ["registry_actor"]);
    assert!(breg.access_profiles[0].admitted_actor_kinds.is_empty());
    assert!(breg.access_profiles[0].refused_claims.is_empty());
    let written = breg.to_yaml().expect("facts write");
    assert!(written.contains("admittedActorKinds:"));
    assert!(written.contains("refusedClaims:"));
    assert_eq!(facts(&written), breg);
    for (bad, code) in [
        (
            admitting.replace("[human, service]", "[human, robot]"),
            None,
        ),
        (
            admitting.replace("    admittedActorKinds: [human, service]\n", "    admittedActorKinds: [service]\n    actorKind: service\n"),
            Some("identity.facts.conflicting-actor-kinds"),
        ),
        (
            admitting.replace("  registry_actor_kind: string\n", ""),
            Some("identity.facts.undeclared-actor-kind"),
        ),
        (
            admitting.replace("refusedClaims: [registry_actor]", "refusedClaims: [undeclared]"),
            Some("identity.facts.invalid-refused-claims"),
        ),
        (
            admitting.replace(
                "refusedClaims: [registry_actor]",
                "refusedClaims: [registry_actor]\n    requiredClaims: [registry_actor]",
            ),
            Some("identity.facts.invalid-refused-claims"),
        ),
        (
            SELECTING.replace(
                "  - id: unselected\n",
                "    admittedActorKinds: [agent]\n  - id: unselected\n",
            ),
            Some("identity.facts.conflicting-actor-kinds"),
        ),
    ] {
        let codes = refused_codes(&bad);
        if let Some(code) = code {
            assert!(codes.contains(&code.to_owned()), "{codes:?}:\n{bad}");
        }
    }
}

#[test]
fn a_profile_states_the_declared_claims_every_token_for_it_must_carry() {
    let requiring = BREG
        .replace(
            "  registry_purpose: string\n",
            "  registry_purpose: string\n  registry_principal: string\n",
        )
        .replace(
            "  - id: case-write\n",
            "  - id: case-write\n    requiredClaims: [registry_principal]\n",
        );
    let breg = facts(&requiring);
    assert_eq!(breg.access_profiles[1].required_claims, ["registry_principal"]);
    assert!(breg.access_profiles[0].required_claims.is_empty());
    let written = breg.to_yaml().expect("facts write");
    assert!(written.contains("requiredClaims:"));
    assert_eq!(facts(&written), breg);
    for bad in [
        requiring.replace("  registry_principal: string\n", ""),
        requiring.replace("requiredClaims: [registry_principal]", "requiredClaims: [sub]"),
    ] {
        let Err(ToolingError::FileRefused { report, .. }) = read("facts.yaml", bad.as_bytes())
        else {
            panic!("accepted:\n{bad}");
        };
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "identity.facts.invalid-required-claims"),
            "refused for another reason:\n{bad}"
        );
    }
}

#[test]
fn one_product_may_require_a_claim_another_only_reads() {
    let breg = BREG
        .replace(
            "  registry_purpose: string\n",
            "  registry_purpose: string\n  evidence_audience: string\n",
        )
        .replace(
            "  - id: case-write\n",
            "  - id: case-write\n    requiredClaims: [evidence_audience]\n",
        );
    let evidence = EVIDENCE.replace(
        "  evidence_tags: string-array\n",
        "  evidence_tags: string-array\n  evidence_audience: string\n",
    );
    let merged = merge(vec![facts(&breg), facts(&evidence)]).expect("merges");
    assert_eq!(merged.claims["evidence_audience"], ClaimType::String);
    let conflicting = evidence.replace(
        "  evidence_audience: string\n",
        "  evidence_audience: string-array\n",
    );
    assert_eq!(
        refusal(merge(vec![facts(&breg), facts(&conflicting)])),
        "identity.facts.claim-conflict"
    );
}

#[test]
fn template_syntax_is_refused_wherever_a_string_is_copied() {
    for bad in [
        BREG.replace("purposes: [eligibility]", "purposes: [\"{{.SIGNING_KEY}}\"]"),
        BREG.replace("records:get", "records:{{get"),
        BREG.replace("urn:breg:example", "urn:breg:}}example"),
        // The same two characters spelled with YAML escapes.
        BREG.replace("purposes: [eligibility]", "purposes: [\"\\x7b\\x7bX\"]"),
        BREG.replace("case-portal", "case-{{portal"),
    ] {
        assert!(
            read("facts.yaml", bad.as_bytes()).is_err(),
            "accepted:\n{bad}"
        );
    }
}

#[test]
fn protocol_and_native_claim_names_are_refused() {
    for name in super::RESERVED_CLAIM_NAMES {
        let bad = BREG.replace("registry_purpose: string", &format!("{name}: string"));
        assert!(
            read("facts.yaml", bad.as_bytes()).is_err(),
            "accepted claim {name}"
        );
        assert!(!valid_claim_name(name), "{name}");
    }
    assert!(valid_claim_name("registry_purpose"));
}

#[test]
fn a_selector_carries_up_to_the_largest_product_list() {
    let values = |count: usize| {
        (0..count)
            .map(|index| format!("tag{index}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let with = |count: usize| {
        SELECTING.replace("evidence_tags: [field, audit]", &format!("evidence_tags: [{}]", values(count)))
    };
    assert!(read("facts.yaml", with(32).as_bytes()).is_ok());
    assert!(read("facts.yaml", with(33).as_bytes()).is_err());
}

/// The `config.duplicate-item` diagnostics the reader refuses `text` with,
/// as (path, related path) pairs.
fn duplicates(text: &str) -> Vec<(String, Vec<String>)> {
    let Err(ToolingError::FileRefused { report, .. }) = read("facts.yaml", text.as_bytes()) else {
        panic!("accepted:\n{text}");
    };
    report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "config.duplicate-item")
        .map(|diagnostic| {
            (
                diagnostic.path.clone(),
                diagnostic.related.iter().map(|related| related.path.clone()).collect(),
            )
        })
        .collect()
}

/// Every list the format states as a set refuses a repeat at the repeat,
/// naming the first, as every set does (CFG-ID-6).
#[test]
fn every_set_list_refuses_a_repeat_at_the_repeat() {
    let sets = BREG
        .replace(
            "  registry_purpose: string\n",
            "  registry_purpose: string\n  registry_role: string-array\n  registry_actor: string\n  registry_principal: string\n",
        )
        .replace(
            "    purposes: [eligibility]\n",
            "    purposes: [eligibility]\n    requesterClients: [case-portal]\n    selectedBy:\n      registry_role: [officer]\n    requiredClaims: [registry_principal]\n    admittedActorKinds: [human]\n    refusedClaims: [registry_actor]\n",
        );
    facts(&sets);
    for (from, to, at) in [
        ("  - field-agent\n", "  - field-agent\n  - case-portal\n", "/allowedClients/2"),
        (
            "scopes: [records:get, records:search]",
            "scopes: [records:get, records:search, records:get]",
            "/accessProfiles/0/scopes/2",
        ),
        ("purposes: [eligibility]", "purposes: [eligibility, eligibility]", "/accessProfiles/0/purposes/1"),
        (
            "requesterClients: [case-portal]",
            "requesterClients: [case-portal, case-portal]",
            "/accessProfiles/0/requesterClients/1",
        ),
        (
            "registry_role: [officer]",
            "registry_role: [officer, officer]",
            "/accessProfiles/0/selectedBy/registry_role/1",
        ),
        (
            "requiredClaims: [registry_principal]",
            "requiredClaims: [registry_principal, registry_principal]",
            "/accessProfiles/0/requiredClaims/1",
        ),
        (
            "admittedActorKinds: [human]",
            "admittedActorKinds: [human, human]",
            "/accessProfiles/0/admittedActorKinds/1",
        ),
        (
            "refusedClaims: [registry_actor]",
            "refusedClaims: [registry_actor, registry_actor]",
            "/accessProfiles/0/refusedClaims/1",
        ),
    ] {
        assert!(sets.contains(from), "{from}");
        let first = format!("{}/0", at.rsplit_once('/').expect("an index").0);
        assert_eq!(
            duplicates(&sets.replace(from, to)),
            [(at.to_owned(), vec![first])],
            "{at}"
        );
    }
}
