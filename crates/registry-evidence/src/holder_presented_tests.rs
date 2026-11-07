//! Holder-presented acquisition: the definition block, channel selection by
//! selector profile, and its startup refusals.

use crate::{
    config::{ConfigError, EvidenceConfig},
    model::ChannelKind,
};

const ACCEPTANCE: &str =
    include_str!("../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml");

/// Convert a fixture or contract document to JSON for comparison with the
/// reader's projection. The reader itself still parses through
/// `EvidenceConfig::parse_yaml`.
#[allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
fn yaml_as_json(document: &str) -> serde_json::Value {
    serde_json::to_value(
        serde_norway::from_str::<serde_norway::Value>(document).expect("document is YAML"),
    )
    .expect("document converts to JSON")
}

const SESSION_PROFILE: &str = r#"  session-reference-v1:
    maximumAggregateBytes: 80
    fields:
      session_reference:
        type: string
        minimumBytes: 1
        maximumBytes: 64
"#;

const WALLET_SOURCE: &str = r#"  wallet-source:
    pack:
      id: fixture-wallet
      version: "1"
      digest: sha256:c103a586cb16cc65d0a780e302b2369f568b8f0eec3027e6cfdf6e958ad7bb47
      artifactPrefix: adapter-packs/fixture-wallet/c103a586cb16cc65d0a780e302b2369f568b8f0eec3027e6cfdf6e958ad7bb47
    route: lookup
    connection: provider
    inputs:
      session_reference:
        selector:
          role: subject
          profile: session-reference-v1
          field: session_reference
    posture: field-projected
    factSchema: schemas/facts.schema.yaml
"#;

const WALLET_GRANT: &str = r#"      - requirement: urn:example:fixture:requirement:adult-status:v1
        purpose: fixture-eligibility
        audienceFrom: authenticated-requester
        responseFormats:
          - signed-jws
        subjects:
          - role: subject
            selectorProfile: session-reference-v1
            valueOrigin: request
"#;

fn edited(document: &str, from: &str, to: &str) -> String {
    assert_eq!(document.matches(from).count(), 1, "{from} is not unique");
    document.replace(from, to)
}

/// The acceptance bundle with a second, session-reference selector profile, a
/// Source bound to it, a grant for it, and both channels declared.
fn both_channels() -> String {
    let document = edited(
        ACCEPTANCE,
        "sources:\n",
        &format!("{SESSION_PROFILE}sources:\n"),
    );
    let document = edited(
        &document,
        "authorityProfiles:\n",
        &format!("{WALLET_SOURCE}authorityProfiles:\n"),
    );
    let document = edited(
        &document,
        "            valueOrigin: request\nrequirements:\n",
        &format!("            valueOrigin: request\n{WALLET_GRANT}requirements:\n"),
    );
    let document = edited(
        &document,
        "        selectorProfiles:\n          - person-demographics-v1\n",
        "        selectorProfiles:\n          - person-demographics-v1\n          - session-reference-v1\n",
    );
    edited(
        &document,
        "      source: source-a\n",
        "      source: source-a\n      holderPresented:\n        source: wallet-source\n        selectorProfiles: [session-reference-v1]\n",
    )
}

/// The acceptance bundle with its only Source read through the
/// holder-presented channel alone.
fn wallet_only() -> String {
    edited(
        ACCEPTANCE,
        "      source: source-a\n",
        "      holderPresented:\n        source: source-a\n        selectorProfiles: [person-demographics-v1]\n",
    )
}

/// The pointer and cause of the first diagnostic the reader reports.
const HOLDER_PRESENTED_SIGNED_ONLY: &str = "a definition with holder-presented acquisition must offer only the signed JWS representation (signed-jws)";

fn refusal(document: &str) -> (String, String) {
    match EvidenceConfig::parse_yaml(document.as_bytes()) {
        Err(ConfigError::Refused(report)) => {
            let first = report
                .diagnostics()
                .first()
                .expect("a refusal carries a diagnostic");
            (first.path.clone(), first.message.clone())
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn both_channels_parse_and_a_profile_selects_exactly_one() {
    let config = EvidenceConfig::parse_yaml(both_channels().as_bytes())
        .expect("a definition with both channels parses");
    let acquisition = &config.requirements[0].acquisition;

    assert_eq!(acquisition.source_channel_source(), Some("source-a"));
    assert_eq!(acquisition.holder_presented_source(), Some("wallet-source"));
    assert_eq!(acquisition.source_ids(), ["source-a", "wallet-source"]);
    assert!(acquisition.uses_source("wallet-source"));
    assert_eq!(acquisition.initial_source(), "source-a");

    assert_eq!(
        acquisition.channel_for_profile("person-demographics-v1"),
        Some(ChannelKind::Source)
    );
    assert_eq!(
        acquisition.source_for_profile("person-demographics-v1"),
        Some("source-a")
    );
    assert_eq!(
        acquisition.channel_for_profile("session-reference-v1"),
        Some(ChannelKind::HolderPresented)
    );
    assert_eq!(
        acquisition.source_for_profile("session-reference-v1"),
        Some("wallet-source")
    );
}

#[test]
fn a_wallet_only_definition_is_accepted_when_every_role_profile_is_listed() {
    let config = EvidenceConfig::parse_yaml(wallet_only().as_bytes())
        .expect("a wallet-only definition that lists every role profile parses");
    let acquisition = &config.requirements[0].acquisition;

    assert_eq!(acquisition.source_channel_source(), None);
    assert_eq!(acquisition.source_ids(), ["source-a"]);
    assert_eq!(acquisition.initial_source(), "source-a");
    assert_eq!(
        acquisition.channel_for_profile("person-demographics-v1"),
        Some(ChannelKind::HolderPresented)
    );
    assert_eq!(
        acquisition.channel_for_profile("an-unlisted-profile"),
        None,
        "with no source channel an unlisted profile selects no channel"
    );
    assert_eq!(acquisition.source_for_profile("an-unlisted-profile"), None);
}

#[test]
fn an_acquisition_with_neither_channel_is_refused() {
    let document = edited(ACCEPTANCE, "      source: source-a\n", "      {}\n");
    assert!(EvidenceConfig::parse_yaml(document.as_bytes()).is_err());
}

#[test]
fn the_projection_of_an_existing_definition_is_unchanged() {
    // Existing documents project to exactly the configuration they always
    // did, so their configurationRevision does not move: the new member is
    // absent from the projection unless the author wrote it.
    for example in ["adult-status", "legal-parent-relationship", "holder-bound"] {
        let path = format!(
            "{}/../../products/evidence/fixtures/acceptance/{example}/evidence.yaml",
            env!("CARGO_MANIFEST_DIR")
        );
        #[allow(
            clippy::disallowed_methods,
            reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
        )]
        let yaml = std::fs::read_to_string(path).expect("fixture reads");
        let config = EvidenceConfig::parse_yaml(yaml.as_bytes()).expect("fixture parses");
        let projected = serde_json::to_value(&config).expect("configuration projects");
        let authored: serde_json::Value = yaml_as_json(&yaml);
        for (index, requirement) in config.requirements.iter().enumerate() {
            assert_eq!(
                projected["requirements"][index]["acquisition"],
                authored["requirements"][index]["acquisition"],
                "{example}: {} changed its acquisition projection",
                requirement.id
            );
            assert_eq!(
                projected["requirements"][index]["acquisition"],
                serde_json::json!({"source": requirement.acquisition.initial_source()}),
            );
        }
    }
}

#[test]
fn the_projection_of_a_holder_presented_definition_round_trips() {
    for document in [both_channels(), wallet_only()] {
        let config = EvidenceConfig::parse_yaml(document.as_bytes()).expect("document parses");
        let projected = serde_json::to_value(&config).expect("configuration projects");
        let reread =
            EvidenceConfig::parse_projection(&projected).expect("the projection parses again");
        assert_eq!(
            config.requirements[0].acquisition,
            reread.requirements[0].acquisition
        );
        assert_eq!(projected, serde_json::to_value(&reread).unwrap());
    }
    let projected =
        serde_json::to_value(EvidenceConfig::parse_yaml(wallet_only().as_bytes()).unwrap())
            .unwrap();
    assert_eq!(
        projected["requirements"][0]["acquisition"],
        serde_json::json!({"holderPresented": {
            "source": "source-a",
            "selectorProfiles": ["person-demographics-v1"]
        }}),
        "a wallet-only definition projects no source member"
    );
}

#[test]
fn holder_presented_selector_profiles_must_be_non_empty_unique_and_allowed() {
    let listed = "selectorProfiles: [session-reference-v1]";
    for (replacement, pointer) in [
        (
            "selectorProfiles: []",
            "/requirements/0/acquisition/holderPresented/selectorProfiles",
        ),
        (
            "selectorProfiles: [session-reference-v1, session-reference-v1]",
            "/requirements/0/acquisition/holderPresented/selectorProfiles/1",
        ),
        (
            "selectorProfiles: [not-allowed-by-any-role-v1]",
            "/requirements/0/acquisition/holderPresented/selectorProfiles/0",
        ),
    ] {
        let document = edited(&both_channels(), listed, replacement);
        let (path, message) = refusal(&document);
        assert_eq!(path, pointer, "{replacement}: {message}");
    }
}

#[test]
fn a_definition_without_a_source_must_list_every_allowed_profile() {
    let document = edited(
        &both_channels(),
        "      source: source-a\n      holderPresented:",
        "      holderPresented:",
    );
    let (path, message) = refusal(&document);
    assert_eq!(path, "/requirements/0/acquisition", "{message}");
    assert!(message.contains("lists every allowed selector profile"));
}

#[test]
fn a_profile_cannot_select_both_channels() {
    // The source channel's Source reads person-demographics-v1; listing that
    // profile under holderPresented would select both channels.
    let document = edited(
        &both_channels(),
        "selectorProfiles: [session-reference-v1]",
        "selectorProfiles: [session-reference-v1, person-demographics-v1]",
    );
    let (path, _) = refusal(&document);
    assert_eq!(path, "/requirements/0/acquisition");

    // And the converse: the holder-presented Source reads a profile the
    // holder-presented block does not list.
    let document = edited(
        &both_channels(),
        "          profile: session-reference-v1\n          field: session_reference\n",
        "          profile: person-demographics-v1\n          field: given_name\n",
    );
    let (path, _) = refusal(&document);
    assert_eq!(path, "/requirements/0/acquisition");
}

#[test]
fn both_channels_cannot_name_one_source() {
    let document = edited(
        &both_channels(),
        "        source: wallet-source\n",
        "        source: source-a\n",
    );
    let (path, _) = refusal(&document);
    assert_eq!(path, "/requirements/0/acquisition/holderPresented/source");
}

#[test]
fn a_holder_presented_definition_offers_no_sd_jwt_vc_representation() {
    let with_sd_jwt = |document: String| {
        let document = edited(
            &document,
            "urn:example:fixture:provider:evidence",
            "https://provider.invalid",
        );
        edited(
            &document,
            "responseFormats:\n  - signed-jws\nselectorProfiles:",
            "responseFormats:\n  - signed-jws\n  - sd-jwt-vc\nselectorProfiles:",
        )
    };

    // Inheriting a package ceiling that offers SD-JWT VC is refused.
    let (path, _) = refusal(&with_sd_jwt(both_channels()));
    assert_eq!(path, "/requirements/0/representations");

    // So is declaring it on the definition.
    let declared = edited(
        &with_sd_jwt(both_channels()),
        "    purposes:\n",
        "    representations: [signed-jws, sd-jwt-vc]\n    purposes:\n",
    );
    let (path, message) = refusal(&declared);
    assert_eq!(path, "/requirements/0/representations");
    assert_eq!(message, HOLDER_PRESENTED_SIGNED_ONLY);

    // Narrowing the definition to signed JWS is accepted, and a source-only
    // definition on the same package is unaffected.
    let narrowed = edited(
        &with_sd_jwt(both_channels()),
        "    purposes:\n",
        "    representations: [signed-jws]\n    purposes:\n",
    );
    EvidenceConfig::parse_yaml(narrowed.as_bytes())
        .expect("a holder-presented definition narrowed to signed JWS parses");
    EvidenceConfig::parse_yaml(with_sd_jwt(ACCEPTANCE.to_owned()).as_bytes())
        .expect("a source-only definition may still inherit SD-JWT VC");
}

#[test]
fn a_holder_presented_definition_refuses_unsigned_json() {
    let with_formats = |formats: &str| {
        let document = edited(
            &both_channels(),
            "urn:example:fixture:provider:evidence",
            "https://provider.invalid",
        );
        edited(
            &document,
            "    purposes:\n",
            &format!("    representations: {formats}\n    purposes:\n"),
        )
    };
    // Wallet facts never travel unsigned, whether or not signed JWS is also
    // offered; the message is the one the SD-JWT VC refusal uses.
    for formats in ["[signed-jws, unsigned-json]", "[unsigned-json]"] {
        let (path, message) = refusal(&with_formats(formats));
        assert_eq!(path, "/requirements/0/representations", "{formats}");
        assert_eq!(message, HOLDER_PRESENTED_SIGNED_ONLY, "{formats}");
    }
    EvidenceConfig::parse_yaml(with_formats("[signed-jws]").as_bytes())
        .expect("signed JWS alone is accepted");
}

#[test]
fn a_grant_has_no_channels_member() {
    // Grants keep restricting callers by selector profile; a channel
    // restriction on a grant is not part of the grammar.
    let document = edited(
        &both_channels(),
        "        purpose: fixture-eligibility\n        audienceFrom: authenticated-requester\n        responseFormats:\n          - signed-jws\n        subjects:\n          - role: subject\n            selectorProfile: session-reference-v1\n",
        "        purpose: fixture-eligibility\n        channels: [holder-presented]\n        audienceFrom: authenticated-requester\n        responseFormats:\n          - signed-jws\n        subjects:\n          - role: subject\n            selectorProfile: session-reference-v1\n",
    );
    assert!(EvidenceConfig::parse_yaml(document.as_bytes()).is_err());
}

#[test]
fn the_published_bundle_contract_agrees_with_the_reader() {
    let schema = yaml_as_json(include_str!(
        "../../../products/evidence/contracts/bundle.schema.yaml"
    ));
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .expect("bundle contract compiles");
    let instance = |document: &str| yaml_as_json(document);

    for accepted in [both_channels(), wallet_only()] {
        assert!(EvidenceConfig::parse_yaml(accepted.as_bytes()).is_ok());
        assert!(validator.is_valid(&instance(&accepted)));
    }
    for rejected in [
        edited(ACCEPTANCE, "      source: source-a\n", "      {}\n"),
        edited(
            &both_channels(),
            "selectorProfiles: [session-reference-v1]",
            "selectorProfiles: []",
        ),
        edited(
            &both_channels(),
            "selectorProfiles: [session-reference-v1]",
            "selectorProfiles: [session-reference-v1, session-reference-v1]",
        ),
        edited(
            &both_channels(),
            "        selectorProfiles: [session-reference-v1]\n",
            "        selectorProfiles: [session-reference-v1]\n        status: required\n",
        ),
    ] {
        assert!(EvidenceConfig::parse_yaml(rejected.as_bytes()).is_err());
        assert!(!validator.is_valid(&instance(&rejected)));
    }
}

mod routing {
    use super::*;
    use crate::{
        config::{AuthorityKind, ValueOrigin},
        model::{AssertionChannel, PresentedCredential, SubjectLinkMode},
        pack_source::{require_channel_facts, PackSourceError},
        presented::{construction_channel, PresentedFacts},
        problem::ProblemCode,
        runtime::acquisition_source,
        selector::{ResolvedAuthorization, ResolvedSubject, ResolvedSubjectScope},
    };

    fn instant(text: &str) -> chrono::DateTime<chrono::Utc> {
        text.parse().expect("instant")
    }

    fn facts() -> PresentedFacts {
        PresentedFacts::new(
            PresentedCredential::new(
                "national-id",
                "https://issuer.example",
                "https://credentials.example/identity",
                instant("2026-11-01T00:00:00Z"),
                SubjectLinkMode::AttributeMatch,
            )
            .expect("members are in contract"),
            instant("2026-11-06T12:00:00Z"),
        )
    }

    fn resolved(profiles: &[&str]) -> ResolvedAuthorization {
        ResolvedAuthorization {
            authority_profile: "profile".to_owned(),
            authority_kind: AuthorityKind::Statutory,
            grant_id: None,
            requirement: "requirement".to_owned(),
            purpose: "purpose".to_owned(),
            subject_scope: ResolvedSubjectScope::Audience("audience".to_owned()),
            subjects: profiles
                .iter()
                .enumerate()
                .map(|(index, profile)| ResolvedSubject {
                    role: format!("role-{index}"),
                    selector_profile: (*profile).to_owned(),
                    value_origin: ValueOrigin::Request,
                    fields: Vec::new(),
                })
                .collect(),
        }
    }

    fn acquisition() -> crate::config::AcquisitionConfig {
        EvidenceConfig::parse_yaml(both_channels().as_bytes())
            .expect("both channels parse")
            .requirements[0]
            .acquisition
            .clone()
    }

    #[test]
    fn a_profile_routes_to_exactly_its_channels_source() {
        let acquisition = acquisition();
        assert_eq!(
            acquisition_source(&acquisition, &resolved(&["session-reference-v1"])).unwrap(),
            "wallet-source"
        );
        let source_profile = acquisition
            .source_channel_source()
            .expect("a source channel is declared");
        assert_eq!(source_profile, "source-a");
        let other = EvidenceConfig::parse_yaml(ACCEPTANCE.as_bytes())
            .unwrap()
            .requirements[0]
            .acquisition
            .clone();
        assert_eq!(
            acquisition_source(&other, &resolved(&["person-demographics-v1"])).unwrap(),
            "source-a"
        );
    }

    #[test]
    fn a_mixed_or_missing_profile_acquires_nothing() {
        let acquisition = acquisition();
        for profiles in [
            &["session-reference-v1", "person-demographics-v1"][..],
            &[][..],
        ] {
            let refusal = acquisition_source(&acquisition, &resolved(profiles))
                .expect_err("no single channel is selected");
            assert_eq!(refusal.problem(), ProblemCode::NotAuthorized);
            assert_eq!(refusal.category(), "acquisition-channel");
        }
    }

    #[test]
    fn the_channel_must_match_the_trusted_attachment() {
        assert_eq!(
            require_channel_facts(ChannelKind::HolderPresented, None),
            Err(PackSourceError::Dependency)
        );
        assert_eq!(
            require_channel_facts(ChannelKind::Source, Some(&facts())),
            Err(PackSourceError::Protocol)
        );
        assert_eq!(require_channel_facts(ChannelKind::Source, None), Ok(()));
        assert_eq!(
            require_channel_facts(ChannelKind::HolderPresented, Some(&facts())),
            Ok(())
        );
    }

    #[test]
    fn a_holder_presented_construction_carries_the_credential_and_caps_validity() {
        let (channel, valid_until) =
            construction_channel(Some(&facts()), Some(instant("2026-11-07T00:00:00Z")));
        assert_eq!(channel.kind(), ChannelKind::HolderPresented);
        assert!(matches!(channel, AssertionChannel::HolderPresented(_)));
        assert_eq!(valid_until, Some(instant("2026-11-06T12:00:00Z")));
    }

    /// `PresentedCredential::new` takes `issued_at` as a required argument and
    /// the only constructor of `AssertionChannel::HolderPresented` takes a
    /// `PresentedCredential`, so a holder-presented channel without a
    /// credential time cannot be built; the wire form refuses its absence.
    #[test]
    fn a_presented_credential_without_issued_at_is_refused() {
        let without = serde_json::json!({
            "trustEntry": "national-id",
            "issuer": "https://issuer.example",
            "credentialType": "https://credentials.example/identity",
            "subjectLink": "attribute-match",
        });
        assert!(serde_json::from_value::<PresentedCredential>(without).is_err());
    }
}
