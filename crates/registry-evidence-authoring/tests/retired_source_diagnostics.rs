#![allow(
    clippy::disallowed_macros,
    reason = "the pure authoring reader test embeds the maintained canonical project"
)]

use registry_evidence_authoring::project::read_project;

const PROJECT: &str = include_str!("../../../products/evidence/examples/standalone/evidence.yaml");
const RETIRED_CODE: &str = "evidence.project.source-acquisition-retired";

#[test]
fn retired_acquisition_functions_name_the_pack_migration_instead_of_a_derivation_rewrite() {
    for interface in ["source-prepare/v1", "source-extract/v1"] {
        let input = PROJECT.replacen(
            "interface: assertion-derive/v1",
            &format!("interface: {interface}"),
            1,
        );
        assert_ne!(input, PROJECT, "the canonical derivation must be replaced");
        let report = read_project("old-project.yaml", input.as_bytes())
            .expect_err("retired acquisition functions remain refused");
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.path == "/functions/0/interface")
            .expect("the exact retired function interface is addressed");
        assert_eq!(diagnostic.code, RETIRED_CODE);
        assert!(diagnostic.message.contains("retired"));
        assert!(diagnostic.message.contains("Adapter pack"));
        assert!(diagnostic
            .suggested_action
            .contains("evidencectl source import"));
        assert!(!diagnostic
            .suggested_action
            .contains("Write assertion-derive/v1"));
        let location = diagnostic
            .source
            .as_ref()
            .expect("a located reader diagnostic");
        assert_eq!(location.file, "old-project.yaml");
        assert!(location.line.is_some() && location.column.is_some());
    }
}

#[test]
fn retired_source_transport_tags_name_the_same_current_pack_contract() {
    for transport in ["http-json", "sqlite-extract"] {
        let input = PROJECT.replacen(
            "  person-record:\n    pack:",
            &format!("  person-record:\n    type: {transport}\n    pack:"),
            1,
        );
        assert_ne!(input, PROJECT, "the retired transport must be inserted");
        let report = read_project("old-project.yaml", input.as_bytes())
            .expect_err("the old tagged transport form remains refused");
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.path == "/sources/person-record/type")
            .expect("the exact retired transport member is addressed");
        assert_eq!(diagnostic.code, RETIRED_CODE);
        assert!(diagnostic.message.contains("retired"));
        assert!(diagnostic.suggested_action.contains("pack"));
        assert!(diagnostic
            .suggested_action
            .contains("evidencectl source import"));
        assert!(diagnostic.suggested_action.contains("does not convert"));
    }
}

#[test]
fn unknown_interface_values_and_environment_expressions_keep_their_ordinary_refusals() {
    for (value, expected_code) in [
        ("PRIVATE-VALUE-CANARY", "config.unknown-variant"),
        ("${PRIVATE_VALUE_CANARY}", "config.substitution-not-allowed"),
    ] {
        let input = PROJECT.replacen(
            "interface: assertion-derive/v1",
            &format!("interface: {value}"),
            1,
        );
        let report = read_project("unknown-project.yaml", input.as_bytes())
            .expect_err("unknown and substituted interfaces remain refused");
        assert!(report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == expected_code));
        assert!(report
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code != RETIRED_CODE));
        assert!(!format!("{report:?}").contains("PRIVATE-VALUE-CANARY"));
        assert!(!format!("{report:?}").contains("PRIVATE_VALUE_CANARY"));
    }
    read_project("current-project.yaml", PROJECT.as_bytes())
        .expect("the current pack-based project is unchanged");
}
