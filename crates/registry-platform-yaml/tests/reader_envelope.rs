// SPDX-License-Identifier: Apache-2.0
//! The envelope and format changes (CFG-ENV-1, CFG-ENV-4, CFG-CHANGE-2).

mod common;

use common::*;
use registry_platform_yaml::{
    ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader, Refusal, RemovedKey, ScalarHook,
    ScalarSite, Severity,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Runtime {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    oidc: Option<Oidc>,
    #[serde(default)]
    clients: Option<std::collections::BTreeMap<String, Client>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Oidc {
    jwks_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Client {
    secret_ref: String,
}

// ----- CFG-ENV-1 -----

#[test]
fn cfg_env_1_envelope_members_may_appear_anywhere_at_the_top_level() {
    let text = format!("name: a\nkind: ExampleRuntimeConfig\noidc:\n  jwksUrl: https://a.example\napiVersion: {API_VERSION}\n");
    let decoded = Reader::new(FILE)
        .decode::<Runtime>(text.as_bytes(), &EXPECT)
        .unwrap_or_else(|report| panic!("{report}"));
    assert_eq!(decoded.value.name.as_deref(), Some("a"));
    assert_eq!(
        decoded.value.oidc.map(|oidc| oidc.jwks_url).as_deref(),
        Some("https://a.example")
    );
    let envelope = decoded.document.envelope();
    assert_eq!(envelope.kind, "ExampleRuntimeConfig");
    assert_eq!(envelope.api_version.as_deref(), Some(API_VERSION));
}

#[test]
fn cfg_env_1_a_missing_member_is_named_with_the_expected_envelope() {
    let report = read_refusal(&format!("apiVersion: {API_VERSION}\nname: a\n"));
    let diagnostic = only(&report);
    assert_diagnostic(
        diagnostic,
        "config.missing-envelope",
        "",
        (1, 1),
        "the top-level mapping has no kind",
        "Start the file with `apiVersion: id.registrystack.org/formats/example/runtime/v1alpha1` and `kind: ExampleRuntimeConfig`.",
    );
    assert_eq!(diagnostic.artifact.as_deref(), Some("ExampleRuntimeConfig"));
    let report = read_refusal("name: a\n");
    assert_eq!(
        only(&report).message,
        "the top-level mapping has no apiVersion or kind"
    );
}

#[test]
fn cfg_env_1_the_envelope_is_checked_before_any_other_member_is_decoded() {
    let report = Reader::new(FILE)
        .decode::<Runtime>(b"name: [not, text]\nunknown: 1\n", &EXPECT)
        .unwrap_err();
    assert_eq!(codes(&report), ["config.missing-envelope"]);
}

#[test]
fn cfg_env_1_another_kind_is_refused_naming_the_expected_kind_only() {
    let text = format!("apiVersion: {API_VERSION}\nkind: {MARKER}\n");
    let report = read_refusal(&text);
    assert_diagnostic(
        only(&report),
        "config.wrong-kind",
        "/kind",
        (2, 7),
        "kind is not one this command reads; it reads `ExampleRuntimeConfig`",
        "Give this command a `ExampleRuntimeConfig` file, or correct kind if the file is one.",
    );
    assert_no_marker(&report);
}

#[test]
fn cfg_env_1_an_unknown_api_version_is_refused_naming_the_accepted_ones() {
    let report = read_refusal(&format!(
        "apiVersion: {MARKER}\nkind: ExampleRuntimeConfig\n"
    ));
    assert_diagnostic(
        only(&report),
        "config.unsupported-api-version",
        "/apiVersion",
        (1, 13),
        "apiVersion is not one this command reads for kind `ExampleRuntimeConfig`; it reads `id.registrystack.org/formats/example/runtime/v1alpha1`, `id.registrystack.org/formats/example/runtime/v1alpha0`",
        "Set apiVersion to `id.registrystack.org/formats/example/runtime/v1alpha1`.",
    );
    assert_no_marker(&report);
}

#[test]
fn cfg_env_1_envelope_members_are_plain_text() {
    let report = read_refusal("apiVersion: 1\nkind: [ExampleRuntimeConfig]\n");
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            ("config.expected-string", "/apiVersion"),
            ("config.expected-string", "/kind"),
        ]
    );
}

#[test]
fn cfg_env_1_a_document_that_is_not_a_mapping_is_refused() {
    let report = read_refusal("- a\n- b\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "config.invalid-type");
    assert_eq!(
        diagnostic.message,
        "the document is a list; it must be a mapping that holds apiVersion and kind"
    );
}

/// Replaces every value with text, as a substitution would.
struct SubstituteEverything;

impl ScalarHook for SubstituteEverything {
    fn value(&mut self, _site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        Ok(Some("ExampleRuntimeConfig".to_string()))
    }
}

#[test]
fn cfg_env_1_envelope_members_never_come_from_substitution() {
    let mut hook = SubstituteEverything;
    let text = format!("apiVersion: {API_VERSION}\nkind: ExampleRuntimeConfig\n");
    let report = Reader::new(FILE)
        .with_hook(&mut hook)
        .read(text.as_bytes(), &EXPECT)
        .unwrap_err();
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            ("config.substitution-not-allowed", "/apiVersion"),
            ("config.substitution-not-allowed", "/kind"),
        ]
    );
    assert_eq!(
        report.diagnostics()[1].message,
        "kind is never filled by substitution"
    );
}

/// Refuses every `${...}` value, as a product hook refuses substitution in
/// an envelope member.
struct RefuseExpressions;

impl ScalarHook for RefuseExpressions {
    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        if !site.text.starts_with("${") {
            return Ok(None);
        }
        Err(Refusal {
            code: "config.substitution-not-allowed".to_string(),
            message: format!("{} is never filled by substitution", site.pointer),
            suggested_action: "Write it in the file as plain text.".to_string(),
        })
    }
}

#[test]
fn cfg_env_1_an_envelope_member_a_hook_refused_is_not_matched_against_the_format() {
    let refused = |text: &str| -> Vec<(String, String)> {
        let mut hook = RefuseExpressions;
        let report = Reader::new(FILE)
            .with_hook(&mut hook)
            .read(text.as_bytes(), &EXPECT)
            .unwrap_err();
        report
            .diagnostics()
            .iter()
            .map(|d| (d.code.clone(), d.path.clone()))
            .collect()
    };
    let not_allowed = |path: &str| {
        (
            "config.substitution-not-allowed".to_string(),
            path.to_string(),
        )
    };
    assert_eq!(
        refused("apiVersion: ${A}\nkind: ${B}\n"),
        [not_allowed("/apiVersion"), not_allowed("/kind")]
    );
    assert_eq!(
        refused(&format!("apiVersion: {API_VERSION}\nkind: ${{B}}\n")),
        [not_allowed("/kind")]
    );
    assert_eq!(
        refused("apiVersion: ${A}\nkind: ExampleRuntimeConfig\n"),
        [not_allowed("/apiVersion")]
    );

    // A number too large to read is refused once, as out of range.
    let text = format!("apiVersion: {API_VERSION}\nkind: 99999999999999999999999\n");
    let report = Reader::new(FILE)
        .decode::<Runtime>(text.as_bytes(), &EXPECT)
        .unwrap_err();
    let diagnostic = only(&report);
    assert_eq!(
        (diagnostic.code.as_str(), diagnostic.path.as_str()),
        ("config.out-of-range", "/kind")
    );
}

#[test]
fn cfg_env_1_a_reader_of_several_formats_dispatches_on_kind() {
    const OTHER: FormatSpec = FormatSpec {
        kind: "ExampleProject",
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current(
                "id.registrystack.org/formats/example/project/v1alpha1",
            )],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };
    const BOTH: Expect<'static> = Expect::new(&[FORMAT, OTHER]);
    let text =
        "apiVersion: id.registrystack.org/formats/example/project/v1alpha1\nkind: ExampleProject\n";
    let document = Reader::new(FILE).read(text.as_bytes(), &BOTH).unwrap();
    assert_eq!(document.envelope().kind, "ExampleProject");

    let report = Reader::new(FILE)
        .read(b"apiVersion: x\nkind: Other\n", &BOTH)
        .unwrap_err();
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "config.wrong-kind");
    assert_eq!(
        diagnostic.message,
        "kind is not one this command reads; it reads one of `ExampleRuntimeConfig`, `ExampleProject`"
    );
    assert_eq!(diagnostic.artifact, None);

    let report = Reader::new(FILE).read(b"name: a\n", &BOTH).unwrap_err();
    assert_eq!(
        only(&report).suggested_action,
        "Start the file with apiVersion and kind for one of `ExampleRuntimeConfig`, `ExampleProject`."
    );
}

#[test]
fn cfg_env_1_an_exempt_format_is_read_without_an_envelope() {
    const EXEMPT: FormatSpec = FormatSpec {
        kind: "ExampleForeignDocument",
        envelope: EnvelopeRule::Exempt {
            reason: "a document another specification defines",
        },
        removed_keys: &[],
    };
    let document = Reader::new("openapi.yaml")
        .read(b"openapi: 3.1.0\n", &Expect::one(&EXEMPT))
        .unwrap();
    assert_eq!(document.envelope().kind, "ExampleForeignDocument");
    assert_eq!(document.envelope().api_version, None);
    // The YAML subset still applies.
    let report = Reader::new("openapi.yaml")
        .read(b"a: &x 1\n", &Expect::one(&EXEMPT))
        .unwrap_err();
    assert_eq!(codes(&report), ["yaml.anchor"]);
    // An empty file is refused with a diagnostic, never an empty report.
    for empty in [&b""[..], b"# only a comment\n"] {
        let report = Reader::new("openapi.yaml")
            .read(empty, &Expect::one(&EXEMPT))
            .unwrap_err();
        let diagnostic = only(&report);
        assert_diagnostic(
            diagnostic,
            "config.invalid-type",
            "",
            (1, 1),
            "the document is empty; it must hold a `ExampleForeignDocument` document",
            "Write the document's content; an empty file is never read as one.",
        );
        assert_eq!(
            diagnostic.artifact.as_deref(),
            Some("ExampleForeignDocument")
        );
    }
}

// ----- CFG-CHANGE-2 -----

#[test]
fn cfg_change_2_the_replacement_keys_are_read() {
    let runtime: Runtime = decode("clients:\n  one:\n    secretRef: secret:env/A\n")
        .unwrap_or_else(|report| panic!("{report}"));
    let clients = runtime.clients.expect("clients are read");
    assert_eq!(clients["one"].secret_ref, "secret:env/A");
}

#[test]
fn cfg_change_2_a_removed_key_is_refused_at_the_key_with_its_replacement() {
    let report = read_refusal(&with_envelope("oidc:\n  jwksUri: https://a.example\n"));
    let diagnostic = only(&report);
    assert_diagnostic(
        diagnostic,
        "config.removed-key",
        "/oidc/jwksUri",
        (4, 3),
        "`jwksUri` is no longer accepted",
        JWKS_URI_REPLACEMENT,
    );
    assert_eq!(diagnostic.artifact.as_deref(), Some("ExampleRuntimeConfig"));
}

#[test]
fn cfg_change_2_a_file_without_an_envelope_also_names_its_removed_keys() {
    const LEGACY: FormatSpec = FormatSpec {
        kind: "ExampleRuntimeConfig",
        envelope: FORMAT.envelope,
        removed_keys: &[RemovedKey {
            pointer: "/schemaVersion",
            replacement: "Replace `schemaVersion` with apiVersion and kind.",
        }],
    };
    let report = Reader::new(FILE)
        .read(
            b"schemaVersion: example/v1\nname: a\n",
            &Expect::one(&LEGACY),
        )
        .unwrap_err();
    let found: Vec<(&str, &str, (usize, usize))> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str(), at(d)))
        .collect();
    assert_eq!(
        found,
        [
            ("config.missing-envelope", "", (1, 1)),
            ("config.removed-key", "/schemaVersion", (1, 1)),
        ]
    );
    assert_eq!(
        report.diagnostics()[1].suggested_action,
        "Replace `schemaVersion` with apiVersion and kind."
    );

    // A file of another kind is not an older layout: its keys are not
    // checked against this format's removed keys.
    let report = Reader::new(FILE)
        .read(
            format!("apiVersion: {API_VERSION}\nkind: Other\nschemaVersion: a\n").as_bytes(),
            &Expect::one(&LEGACY),
        )
        .unwrap_err();
    assert_eq!(codes(&report), ["config.wrong-kind"]);
}

#[test]
fn cfg_change_2_a_wildcard_removed_key_matches_every_member() {
    let body = "clients:\n  one:\n    secret: a\n  two:\n    secretRef: secret:env/B\n  three:\n    secret: c\n";
    let report = read_refusal(&with_envelope(body));
    let found: Vec<(&str, &str, (usize, usize))> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str(), at(d)))
        .collect();
    assert_eq!(
        found,
        [
            ("config.removed-key", "/clients/one/secret", (5, 5)),
            ("config.removed-key", "/clients/three/secret", (9, 5)),
        ]
    );
    assert_eq!(
        report.diagnostics()[0].suggested_action,
        CLIENT_SECRET_REPLACEMENT
    );
}

#[test]
fn cfg_change_2_decoding_reports_a_removed_key_once_beside_unknown_keys() {
    let body = "oidc:\n  jwksUri: https://a.example\n  jwksUrl: https://a.example\nnmae: a\n";
    let report = refusal::<Runtime>(body);
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            ("config.removed-key", "/oidc/jwksUri"),
            ("config.unknown-key", "/nmae"),
        ]
    );
}

#[test]
fn cfg_change_2_a_retired_api_version_names_the_current_one_and_the_fix() {
    let text = format!("apiVersion: {RETIRED_API_VERSION}\nkind: ExampleRuntimeConfig\n");
    let report = read_refusal(&text);
    assert_diagnostic(
        only(&report),
        "config.retired-api-version",
        "/apiVersion",
        (1, 13),
        "apiVersion `example.registrystack.org/v1` is retired; the current apiVersion is `id.registrystack.org/formats/example/runtime/v1alpha1`",
        RETIRED_REPLACEMENT,
    );
}

#[test]
fn cfg_diag_5_an_old_kind_with_a_retired_api_version_reports_both() {
    let text = format!("apiVersion: {RETIRED_API_VERSION}\nkind: Other\n");
    let report = read_refusal(&text);
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            ("config.retired-api-version", "/apiVersion"),
            ("config.wrong-kind", "/kind"),
        ]
    );
    let retired = report
        .diagnostics()
        .iter()
        .find(|d| d.code == "config.retired-api-version")
        .unwrap();
    assert_eq!(retired.suggested_action, RETIRED_REPLACEMENT);
}

#[test]
fn cfg_change_2_a_deprecated_api_version_is_read_with_a_warning() {
    let text =
        format!("apiVersion: {DEPRECATED_API_VERSION}\nkind: ExampleRuntimeConfig\nname: a\n");
    let decoded = Reader::new(FILE)
        .decode::<Runtime>(text.as_bytes(), &EXPECT)
        .unwrap();
    let warnings = decoded.document.warnings();
    let warning = only(&warnings);
    assert_eq!(warning.severity, Severity::Warning);
    assert_diagnostic(
        warning,
        "config.deprecated-api-version",
        "/apiVersion",
        (1, 13),
        "apiVersion `id.registrystack.org/formats/example/runtime/v1alpha0` is deprecated",
        "Change apiVersion to `id.registrystack.org/formats/example/runtime/v1alpha1`.",
    );
    assert_eq!(warnings.summary(), "0 errors, 1 warning in 1 file");

    // A refused document still carries the warning beside its errors.
    let text =
        format!("apiVersion: {DEPRECATED_API_VERSION}\nkind: ExampleRuntimeConfig\nnmae: a\n");
    let report = Reader::new(FILE)
        .decode::<Runtime>(text.as_bytes(), &EXPECT)
        .unwrap_err();
    assert_eq!(
        codes(&report),
        ["config.deprecated-api-version", "config.unknown-key"]
    );
    assert_eq!(report.summary(), "1 error, 1 warning in 1 file");
}
