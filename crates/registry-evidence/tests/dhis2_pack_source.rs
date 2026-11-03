use std::{collections::BTreeMap, fs, path::PathBuf};

use registry_evidence::{
    bundle::{evidence_package_limits, Bundle},
    fixture_source::{compile_sources, fixture_acquisition},
    model::LookupResult,
    selector::resolve_offline_fixture_authorization,
};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde_json::Value;

const ADAPTER_PACK_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: registry_adapter_core::ADAPTER_PACK_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(
            registry_adapter_core::ADAPTER_PACK_API_VERSION,
        )],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[tokio::test]
async fn dhis2_reference_reuses_the_maintained_pack_and_replays_both_routes() {
    let repository = repository_root();
    let bundle_root = repository.join(
        "products/evidence/reference/request-adapter/deployment-projects/dhis2-tracker-evidence/bundle",
    );
    let maintained_pack =
        fs::read(repository.join("products/adapter/packs/dhis2-tracker/pack.yaml"))
            .expect("the maintained DHIS2 pack is readable");
    Reader::new("products/adapter/packs/dhis2-tracker/pack.yaml")
        .decode::<registry_adapter_core::AdapterPack>(
            &maintained_pack,
            &Expect::one(&ADAPTER_PACK_FORMAT),
        )
        .expect("the maintained DHIS2 pack follows its typed envelope and grammar");
    let verified = registry_platform_config::verify_package(
        &bundle_root,
        &evidence_package_limits(),
        "evidencectl package",
    )
    .expect("the DHIS2 reference package has an exact checksum closure");
    let bundle = Bundle::load_as_found(&bundle_root, &verified)
        .expect("the DHIS2 reference uses current pack-source bindings");
    let programs = compile_sources(&bundle).expect("both DHIS2 pack routes compile purely");

    assert_eq!(bundle.config.sources.len(), 2);
    for (_, source) in bundle.config.sources.iter() {
        assert_eq!(source.pack.id.as_str(), "dhis2-tracker");
        assert_eq!(
            source.pack.digest.as_str(),
            registry_platform_config::sha256_uri(&maintained_pack)
        );
        assert_eq!(
            fs::read(
                bundle_root
                    .join(source.pack.artifact_prefix.as_str())
                    .join("pack.yaml")
            )
            .expect("the captured DHIS2 pack is readable"),
            maintained_pack,
            "the Evidence project must capture the maintained pack exactly"
        );
    }

    for requirement in &bundle.config.requirements {
        let fixture_path = requirement
            .fixtures
            .as_ref()
            .expect("the reference requirement declares fixtures")
            .as_str();
        let fixture = serde_json::to_value(&bundle.fixtures[fixture_path])
            .expect("the fixture value converts to JSON");
        let case = fixture["cases"]
            .as_array()
            .expect("the fixture cases are an array")
            .iter()
            .find(|case| case["id"] == "positive")
            .expect("each DHIS2 route preserves its positive case")
            .as_object()
            .expect("the positive case is an object");
        let resolved = resolve_offline_fixture_authorization(
            &bundle,
            requirement,
            fixture["common"].as_object(),
            case,
            "urn:registry-evidence:dhis2-pack-replay",
        )
        .expect("the fixture selectors resolve through the current authority boundary");
        let actual = programs
            .get(requirement.initial_source())
            .expect("the requirement source compiled")
            .execute(
                &resolved,
                fixture_acquisition(&case["acquisition"])
                    .expect("the case carries an exact acquisition transcript"),
                chrono::DateTime::parse_from_rfc3339("2026-08-02T00:00:00Z")
                    .expect("the fixture instant parses")
                    .with_timezone(&chrono::Utc),
            )
            .await
            .expect("the DHIS2 route replays its exact transcript");
        let LookupResult::Match(facts) = actual else {
            panic!("{} did not produce a matched fact set", requirement.id);
        };
        let expected: BTreeMap<String, Value> =
            serde_json::from_value(case["expected"]["facts"].clone())
                .expect("the existing positive fact expectation is a closed object");
        assert_eq!(
            facts, expected,
            "{} changed its reviewed facts",
            requirement.id
        );
    }
}
