//! Formats, the substituting hook, and the report invariants shared by the
//! `yaml_reader` and `yaml_decode` targets.

use registry_platform_yaml::{
    ApiVersion, Diagnostic, EnvelopeRule, FormatSpec, Refusal, RemovedKey, Report,
    RetiredApiVersion, ScalarHook, ScalarSite, CODES, MAXIMUM_DIAGNOSTICS_PER_FILE,
};

pub const FILE: &str = "fuzz.yaml";

/// The most bytes one sentence of a diagnostic may take (its message, its
/// fix, or a related note): keys are shortened to 64 characters, and a
/// mapping lists its accepted keys once.
const MAXIMUM_SENTENCE_BYTES: usize = 2048;

/// What a rendering adds around a diagnostic's sentences and paths: the
/// severity, code, position, and member names.
const RENDERING_OVERHEAD_BYTES: usize = 256;

/// A rendering writes a control character as at most six bytes (`\u{9f}`
/// in human output, `\u001f` in JSON).
const ESCAPE_GROWTH: usize = 6;

/// What the hook substitutes. The input never contains it (a run whose
/// input does is not checked for it), so a diagnostic that repeats it
/// repeated a value (CFG-SEC-3).
pub const MARKER: &str = "FUZZ-SUBSTITUTED-VALUE-4b1d";

pub const FORMATS: &[FormatSpec] = &[
    FormatSpec {
        kind: "FuzzRuntimeConfig",
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[
                ApiVersion::current("id.registrystack.org/formats/fuzz/runtime/v1"),
                ApiVersion::deprecated("id.registrystack.org/formats/fuzz/runtime/v0"),
            ],
            retired_api_versions: &[RetiredApiVersion {
                api_version: "fuzz.registrystack.org/v1",
                replacement: "Run `fuzzctl migrate` to rewrite the file.",
            }],
        },
        removed_keys: &[
            RemovedKey {
                pointer: "/legacyPort",
                replacement: "Rename `legacyPort` to `port`.",
            },
            RemovedKey {
                pointer: "/steps/*/secret",
                replacement: "Replace `secret` with `secretRef`.",
            },
        ],
    },
    FormatSpec {
        kind: "FuzzPackage",
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current(
                "id.registrystack.org/formats/fuzz/package/v1",
            )],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    },
];

pub const EXEMPT: FormatSpec = FormatSpec {
    kind: "FuzzExempt",
    envelope: EnvelopeRule::Exempt {
        reason: "fuzzing the reader without an envelope",
    },
    removed_keys: &[],
};

/// Substitutes every text value that holds a `$`, and refuses a key that
/// holds `${`, the way runtime substitution does.
pub struct Substitute;

impl ScalarHook for Substitute {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        if site.text.contains("${") {
            return Err(Refusal {
                code: "config.substitution-not-allowed".to_owned(),
                message: "a key is never substituted".to_owned(),
                suggested_action: "Write the key without `${`.".to_owned(),
            });
        }
        Ok(())
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        if site.text.contains("${?") {
            return Err(Refusal {
                code: "config.substitution".to_owned(),
                message: "the variable is not set".to_owned(),
                suggested_action: "Set the variable.".to_owned(),
            });
        }
        Ok(site.text.contains('$').then(|| MARKER.to_owned()))
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Every report the reader returns: known two-segment codes, 1-based
/// positions, at most the bound of diagnostics plus the count of the rest,
/// renderable output of bounded size, and, when `forbid_marker`, no
/// substituted value anywhere in it.
pub fn check_report(report: &Report, forbid_marker: bool) {
    let diagnostics = report.diagnostics();
    assert!(
        diagnostics.len() <= MAXIMUM_DIAGNOSTICS_PER_FILE + 1,
        "{} diagnostics for one file",
        diagnostics.len()
    );
    let mut written = 0;
    for (index, diagnostic) in diagnostics.iter().enumerate() {
        check_diagnostic(diagnostic, forbid_marker);
        if diagnostic.code == "config.too-many-problems" {
            assert_eq!(index, MAXIMUM_DIAGNOSTICS_PER_FILE, "the count comes last");
        }
        written += RENDERING_OVERHEAD_BYTES
            + diagnostic.artifact.as_ref().map_or(0, String::len)
            + diagnostic.path.len()
            + diagnostic.message.len()
            + diagnostic.suggested_action.len();
        for related in &diagnostic.related {
            written += RENDERING_OVERHEAD_BYTES + related.path.len() + related.message.len();
        }
    }
    let human = report.render_human();
    let json = report.to_json_value().to_string();
    let bound = ESCAPE_GROWTH * written + RENDERING_OVERHEAD_BYTES;
    assert!(
        human.len() <= bound,
        "{} bytes of human output",
        human.len()
    );
    assert!(json.len() <= bound, "{} bytes of JSON output", json.len());
    if forbid_marker {
        assert!(!human.contains(MARKER), "human output repeats a value");
        assert!(!json.contains(MARKER), "JSON output repeats a value");
    }
}

fn check_diagnostic(diagnostic: &Diagnostic, forbid_marker: bool) {
    assert!(
        CODES.iter().any(|info| info.code == diagnostic.code),
        "unregistered code {}",
        diagnostic.code
    );
    assert_eq!(diagnostic.code.split('.').count(), 2, "{}", diagnostic.code);
    assert!(!diagnostic.message.is_empty(), "{}", diagnostic.code);
    assert!(
        !diagnostic.suggested_action.is_empty(),
        "{}",
        diagnostic.code
    );
    assert!(
        diagnostic.message.len() <= MAXIMUM_SENTENCE_BYTES
            && diagnostic.suggested_action.len() <= MAXIMUM_SENTENCE_BYTES
            && diagnostic
                .related
                .iter()
                .all(|related| related.message.len() <= MAXIMUM_SENTENCE_BYTES),
        "{}",
        diagnostic.code
    );
    assert!(
        diagnostic.path.is_empty() || diagnostic.path.starts_with('/'),
        "{}",
        diagnostic.code
    );
    if let Some(source) = &diagnostic.source {
        assert_eq!(source.file, FILE);
        assert!(source.line.is_none_or(|line| line >= 1));
        assert!(source.column.is_none_or(|column| column >= 1));
    }
    for related in &diagnostic.related {
        assert!(related.line.is_none_or(|line| line >= 1));
        assert!(related.column.is_none_or(|column| column >= 1));
    }
    if forbid_marker {
        assert!(!diagnostic.message.contains(MARKER), "{}", diagnostic.code);
        assert!(
            !diagnostic.suggested_action.contains(MARKER),
            "{}",
            diagnostic.code
        );
        for related in &diagnostic.related {
            assert!(!related.message.contains(MARKER), "{}", diagnostic.code);
        }
    }
}
