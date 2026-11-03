use registry_evidence::{
    bundle::{evidence_package_limits, Bundle},
    fixture_source::compile_sources,
    kernel::OfflineKernel,
};
use serde_json::Value;
use std::{fs, path::PathBuf, sync::Arc};

const CASE_IDS: [&str; 24] = [
    "positive",
    "negative-false-is-success",
    "boundary-latest-recognized-union-wins",
    "boundary-unrecognized-union-ignored",
    "boundary-no-union-history",
    "missing-fact",
    "missing-record",
    "no-match",
    "ambiguous",
    "negative-search-namespace-mismatch",
    "negative-union-register-unresolved",
    "negative-death-register-unresolved",
    "negative-two-recognized-unions-share-the-latest-date",
    "negative-union-set-incomplete",
    "negative-death-record-incomplete",
    "negative-death-subject-mismatch",
    "negative-subject-deceased",
    "negative-unknown-union-end-reason",
    "negative-wrong-union-contract",
    "negative-wrong-death-contract",
    "negative-extra-source-field",
    "negative-extra-family-fact",
    "source-failure",
    "anti-reconstruction",
];

fn package_root() -> PathBuf {
    if let Some(root) = std::env::var_os("EVIDENCE_FETCH_SET_CANDIDATE_ROOT") {
        return PathBuf::from(root);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/fixtures/acceptance/surviving-spouse-status")
}

fn yaml(path: &str) -> Value {
    use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
    const PACK: FormatSpec<'static> = FormatSpec {
        kind: registry_adapter_core::ADAPTER_PACK_KIND,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current(
                registry_adapter_core::ADAPTER_PACK_API_VERSION,
            )],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };
    let format = match path {
        "evidence.yaml" => &registry_evidence::config::EVIDENCE_BUNDLE_FORMAT,
        "fixtures/cases.yaml" => &registry_evidence::fixture::EVIDENCE_FIXTURE_FORMAT,
        _ if path.ends_with("/pack.yaml") => &PACK,
        _ => panic!("the test helper reads only its maintained bundle, pack, and cases"),
    };
    Reader::new(path)
        .read(
            &fs::read(package_root().join(path)).unwrap(),
            &Expect::one(format),
        )
        .expect("maintained fixture follows its owning format")
        .to_json_value()
}

fn collect_sends<'a>(steps: &'a [Value], sends: &mut Vec<&'a Value>) {
    for step in steps {
        if let Some(send) = step.get("to") {
            sends.push(send);
        }
        if let Some(choice) = step.get("choice") {
            for when in choice["when"].as_array().into_iter().flatten() {
                collect_sends(when["steps"].as_array().unwrap(), sends);
            }
            if let Some(otherwise) = choice.get("otherwise") {
                collect_sends(otherwise["steps"].as_array().unwrap(), sends);
            }
        }
    }
}

#[test]
fn surviving_spouse_pack_closes_one_bounded_three_send_route_and_preserves_cases() {
    let root = package_root();
    let verified = registry_platform_config::verify_package(
        &root,
        &evidence_package_limits(),
        "evidencectl package",
    )
    .expect("the acceptance package has an exact checksum closure");
    let bundle = Arc::new(Bundle::load_as_found(&root, &verified).expect("package loads"));
    compile_sources(&bundle).expect("the reviewed source route compiles");
    OfflineKernel::compile(Arc::clone(&bundle)).expect("the Evidence kernel compiles");

    let authored = yaml("evidence.yaml");
    assert!(
        authored.get("acquisitionCapabilities").is_none(),
        "the retired fetch-set host switch is not a compatibility surface"
    );
    let sources = authored["sources"].as_object().unwrap();
    assert_eq!(sources.len(), 1);
    let source = &sources["survivorship-registers"];
    assert_eq!(source["route"], "lookup");
    assert_eq!(source["connection"], "registers");
    let prefix = source["pack"]["artifactPrefix"].as_str().unwrap();
    let pack = yaml(&format!("{prefix}/pack.yaml"));
    assert_eq!(pack["id"], "fixture-survivorship");
    assert_eq!(
        pack["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|endpoint| endpoint["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["civil-records", "union-register", "death-register"]
    );
    let route = &pack["sourceRoutes"][0];
    assert_eq!(route["id"], "lookup");
    assert_eq!(route["evidence"]["acquisitionPosture"], "field-projected");
    let mut sends = Vec::new();
    collect_sends(route["steps"].as_array().unwrap(), &mut sends);
    assert_eq!(
        sends
            .iter()
            .map(|send| send["uri"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "http:civil-records",
            "http:union-register",
            "http:death-register"
        ],
        "one search and two fixed members are the whole route closure"
    );

    let fixture = yaml("fixtures/cases.yaml");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(
        cases
            .iter()
            .map(|case| case["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        CASE_IDS
    );
    for case in cases {
        assert!(
            case.get("sources").is_none(),
            "{} must use an actual sealed route transcript",
            case["id"]
        );
        let Some(exchanges) = case
            .get("source")
            .and_then(|source| source.get("exchanges"))
            .and_then(Value::as_array)
        else {
            assert!(
                case.get("injectedDerivation").is_some()
                    || case.get("sourceFailure").is_some()
                    || case.get("companionBundle").is_some(),
                "{} must carry a transcript or an explicit non-acquisition case",
                case["id"]
            );
            continue;
        };
        let expected_sends = match case["id"].as_str().unwrap() {
            "missing-record" | "no-match" | "ambiguous" => 1,
            "negative-search-namespace-mismatch" => 1,
            "negative-union-register-unresolved"
            | "missing-fact"
            | "negative-unknown-union-end-reason"
            | "negative-wrong-union-contract" => 2,
            _ => 3,
        };
        assert_eq!(exchanges.len(), expected_sends, "{}", case["id"]);
        assert_eq!(exchanges[0]["request"]["endpoint"], "civil-records");
        if expected_sends > 1 {
            assert_eq!(exchanges[1]["request"]["endpoint"], "union-register");
        }
        if expected_sends > 2 {
            assert_eq!(exchanges[2]["request"]["endpoint"], "death-register");
        }
    }
}
