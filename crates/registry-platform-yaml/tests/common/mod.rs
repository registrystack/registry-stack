// SPDX-License-Identifier: Apache-2.0
//! Helpers shared by the reader's integration tests.

#![allow(dead_code)]

use registry_platform_yaml::{
    ApiVersion, Diagnostic, EnvelopeRule, Expect, FormatSpec, Reader, RemovedKey, Report,
    RetiredApiVersion,
};
use serde::de::DeserializeOwned;

pub const FILE: &str = "runtime.yaml";
pub const API_VERSION: &str = "id.registrystack.org/formats/example/runtime/v1alpha1";
pub const DEPRECATED_API_VERSION: &str = "id.registrystack.org/formats/example/runtime/v1alpha0";
pub const RETIRED_API_VERSION: &str = "example.registrystack.org/v1";
pub const RETIRED_REPLACEMENT: &str =
    "Run `examplectl migrate` to rewrite the file for the current apiVersion.";
pub const JWKS_URI_REPLACEMENT: &str = "Rename `jwksUri` to `jwksUrl`.";
pub const CLIENT_SECRET_REPLACEMENT: &str = "Replace `secret` with `secretRef`.";

/// The two envelope lines every test document starts with, so a test's own
/// content starts on line 3.
pub const ENVELOPE: &str = "apiVersion: id.registrystack.org/formats/example/runtime/v1alpha1\nkind: ExampleRuntimeConfig\n";

pub const FORMAT: FormatSpec = FormatSpec {
    kind: "ExampleRuntimeConfig",
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[
            ApiVersion::current(API_VERSION),
            ApiVersion::deprecated(DEPRECATED_API_VERSION),
        ],
        retired_api_versions: &[RetiredApiVersion {
            api_version: RETIRED_API_VERSION,
            replacement: RETIRED_REPLACEMENT,
        }],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/oidc/jwksUri",
            replacement: JWKS_URI_REPLACEMENT,
        },
        RemovedKey {
            pointer: "/clients/*/secret",
            replacement: CLIENT_SECRET_REPLACEMENT,
        },
    ],
};

pub const EXPECT: Expect<'static> = Expect::one(&FORMAT);

/// A marker planted in scalar values; no diagnostic may repeat it
/// (CFG-SEC-3).
pub const MARKER: &str = "MARKER-7f3a9c";

pub fn with_envelope(body: &str) -> String {
    format!("{ENVELOPE}{body}")
}

/// Decode `body` placed after the envelope.
pub fn decode<T: DeserializeOwned>(body: &str) -> Result<T, Report> {
    decode_text(&with_envelope(body))
}

/// Decode a whole document.
pub fn decode_text<T: DeserializeOwned>(text: &str) -> Result<T, Report> {
    Reader::new(FILE)
        .decode::<T>(text.as_bytes(), &EXPECT)
        .map(|decoded| decoded.value)
}

/// The report for `body` placed after the envelope; the decode must fail.
pub fn refusal<T: DeserializeOwned + std::fmt::Debug>(body: &str) -> Report {
    match decode::<T>(body) {
        Ok(value) => panic!("expected a refusal, decoded {value:?}"),
        Err(report) => report,
    }
}

/// The report for a whole document; the read must fail.
pub fn read_refusal(text: &str) -> Report {
    match Reader::new(FILE).read(text.as_bytes(), &EXPECT) {
        Ok(document) => panic!("expected a refusal, read {:?}", document.root()),
        Err(report) => report,
    }
}

/// The report from scanning the YAML subset only; the scan must fail.
pub fn scan_refusal(text: &str) -> Report {
    match Reader::new(FILE).scan(text.as_bytes()) {
        Ok(root) => panic!("expected a refusal, scanned {root:?}"),
        Err(report) => report,
    }
}

pub fn codes(report: &Report) -> Vec<&str> {
    report
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

/// The report's only diagnostic.
pub fn only(report: &Report) -> &Diagnostic {
    assert_eq!(report.diagnostics().len(), 1, "{report}");
    &report.diagnostics()[0]
}

/// Line and column of a diagnostic.
pub fn at(diagnostic: &Diagnostic) -> (usize, usize) {
    let source = diagnostic
        .source
        .as_ref()
        .expect("the diagnostic has a source");
    (
        source.line.expect("the diagnostic has a line"),
        source.column.expect("the diagnostic has a column"),
    )
}

/// Assert the code, path, position, message, and action of a diagnostic.
pub fn assert_diagnostic(
    diagnostic: &Diagnostic,
    code: &str,
    path: &str,
    position: (usize, usize),
    message: &str,
    action: &str,
) {
    assert_eq!(diagnostic.code, code, "{diagnostic:?}");
    assert_eq!(diagnostic.path, path, "{diagnostic:?}");
    assert_eq!(at(diagnostic), position, "{diagnostic:?}");
    assert_eq!(diagnostic.message, message, "{diagnostic:?}");
    assert_eq!(diagnostic.suggested_action, action, "{diagnostic:?}");
}

/// Assert that neither the human nor the JSON rendering of `report`
/// repeats the marker (CFG-SEC-3).
pub fn assert_no_marker(report: &Report) {
    let human = report.render_human();
    assert!(!human.contains(MARKER), "{human}");
    let json = report.to_json_value().to_string();
    assert!(!json.contains(MARKER), "{json}");
}
