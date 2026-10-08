//! `registry-render check`: the plain-language authoring preflight. Verifies
//! structure, label-script font coverage, and per-locale label key sets.
//! The rendered file closure is governed where a render exists to capture
//! it: the golden suite pins each acceptance bundle's closure and proves
//! every file it reads is manifest-governed, and `compile --json` reports
//! `deps` for authors reviewing their own bundles.

use std::collections::BTreeSet;
use std::path::Path;

use registry_platform_audit::AuditDestination;
use registry_platform_yaml::{Diagnostic, Severity};

use crate::bundle::Bundle;
use crate::labels::labels_path;
use crate::problem::{ProblemKind, RenderProblem};

pub fn run(
    bundle_dir: &Path,
    seal: bool,
    runtime_path: Option<&Path>,
    require_audit_under: Option<&Path>,
) -> Result<i32, RenderProblem> {
    if let (Some(runtime_path), Some(root)) = (runtime_path, require_audit_under) {
        let (runtime, _) = crate::runtime::load(runtime_path)?;
        let AuditDestination::File(file) = runtime.audit.destination()? else {
            return Err(RenderProblem::new(
                ProblemKind::RuntimeInvalid,
                "audit.destination is stdout, which has no path to prove; \
                 --require-audit-under needs a file destination",
            ));
        };
        registry_platform_audit::require_audit_under(file.path(), root).map_err(|err| {
            RenderProblem::new(
                ProblemKind::RuntimeInvalid,
                format!("audit file fails the containment proof: {err}"),
            )
        })?;
        println!(
            "audit file {} resolves under {}",
            file.path().display(),
            root.display()
        );
    }
    if seal {
        return Err(RenderProblem::new(
            ProblemKind::InvalidArgument,
            "`registry-render check --seal` is no longer accepted; run `registry-render check`, then build a new directory with `registry-render package --bundle <source> --output <directory>`",
        ));
    }
    let bundle = Bundle::load_for_preview(bundle_dir)?;
    check_labels(&bundle)?;
    for document in bundle.documents.values() {
        let labels = document
            .spec
            .labels
            .iter()
            .map(|l| l.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "document {:<16} v{}  entry {}  labels [{}]  pdf {}",
            document.spec.id,
            document.spec.version,
            document.spec.entry.display(),
            labels,
            document
                .spec
                .pdf_standard
                .map(|s| s.to_string())
                .unwrap_or_else(|| "plain".to_owned())
        );
    }
    let governed = bundle.package_inputs().len();
    println!(
        "bundle {} v{} hash {} ({} fonts, {} documents, {} governed files)",
        bundle_dir.display(),
        bundle.manifest.bundle_version,
        &bundle.bundle_hash[..16.min(bundle.bundle_hash.len())],
        bundle.fonts.len(),
        bundle.documents.len(),
        governed
    );
    Ok(0)
}

/// Every label finding of the bundle at once (CFG-DIAG-5): the script
/// coverage of each label and the key set of each locale. A coverage
/// finding names the problem `font-invalid`; key sets alone name it
/// `labels-invalid`.
pub fn check_labels(bundle: &Bundle) -> Result<(), RenderProblem> {
    let coverage = check_script_coverage(bundle);
    let key_sets = check_label_key_sets(bundle);
    let kind = if !coverage.is_empty() {
        ProblemKind::FontInvalid
    } else if !key_sets.is_empty() {
        ProblemKind::LabelsInvalid
    } else {
        return Ok(());
    };
    let mut diagnostics = coverage;
    diagnostics.extend(key_sets);
    Err(
        RenderProblem::new(kind, "the bundle's label tables were refused")
            .with_diagnostics(diagnostics),
    )
}

/// Every character of every label value must be drawable by some bundle or
/// baseline font. This is the check-time half of the paper-safety rule: a
/// successful render that prints tofu is wrong on paper, so missing
/// coverage is a named problem here and glyph warnings fail `--strict` at
/// render time.
pub fn check_script_coverage(bundle: &Bundle) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for document in bundle.documents.values() {
        for (locale, table) in &document.labels {
            let Some(map) = table.as_object() else {
                continue;
            };
            for (key, value) in map {
                let Some(text) = value.as_str() else { continue };
                for ch in text.chars() {
                    if ch.is_ascii() || ch.is_whitespace() {
                        continue;
                    }
                    let covered = bundle.fonts.iter().any(|font| {
                        ttf_parser::Face::parse(font.data(), font.index())
                            .is_ok_and(|face| face.glyph_index(ch).is_some())
                    });
                    if !covered {
                        push_once(
                            &mut findings,
                            label_finding(
                                bundle,
                                locale,
                                "render.labels.uncovered-character",
                                &format!("/labels/{key}"),
                                &format!(
                                    "no bundle or baseline font draws the character U+{:04X} in this label",
                                    u32::from(ch)
                                ),
                                "Add a font that covers the label's script under fonts/, or change the label text.",
                                false,
                            ),
                        );
                        break;
                    }
                }
            }
        }
    }
    findings
}

/// Every locale of a document must define the same label key set: a key
/// missing from one locale fails only that locale's render, at template
/// runtime — the worst place to discover it. `check` (and serve startup)
/// name the divergence up front, so PAYLOAD.md's "a missing label key is a
/// `registry-render check` error, not a runtime surprise" holds.
pub fn check_label_key_sets(bundle: &Bundle) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for document in bundle.documents.values() {
        let mut reference: Option<(String, BTreeSet<String>)> = None;
        for (locale, table) in &document.labels {
            let keys: BTreeSet<String> = table
                .as_object()
                .map(|map| map.keys().cloned().collect())
                .unwrap_or_default();
            match &reference {
                None => reference = Some((locale.clone(), keys)),
                Some((reference_locale, reference_keys)) => {
                    for missing in reference_keys.difference(&keys) {
                        push_once(
                            &mut findings,
                            missing_key(bundle, locale, missing, reference_locale),
                        );
                    }
                    for undeclared in keys.difference(reference_keys) {
                        push_once(
                            &mut findings,
                            missing_key(bundle, reference_locale, undeclared, locale),
                        );
                    }
                }
            }
        }
    }
    findings
}

/// `locale`'s table lacks `key`, which `defined_in`'s table defines.
fn missing_key(bundle: &Bundle, locale: &str, key: &str, defined_in: &str) -> Diagnostic {
    label_finding(
        bundle,
        locale,
        "render.labels.missing-key",
        "/labels",
        &format!(
            "the table has no label {key}, which {} defines for the same document",
            labels_path(defined_in)
        ),
        &format!("Add {key} to this table, or remove it from every locale of the document."),
        true,
    )
}

/// An error in the label table of `locale`, at the member at `pointer`: its
/// key when `at_key`, otherwise its value.
fn label_finding(
    bundle: &Bundle,
    locale: &str,
    code: &str,
    pointer: &str,
    message: &str,
    action: &str,
    at_key: bool,
) -> Diagnostic {
    match bundle.label_sources.get(locale) {
        Some(document) if at_key => {
            document.diagnostic_at_key(Severity::Error, code, pointer, message, action)
        }
        Some(document) => {
            document.diagnostic_at_value(Severity::Error, code, pointer, message, action)
        }
        None => Diagnostic::error(code, pointer, message, action),
    }
}

/// Documents that share a locale share its table; report each finding once.
fn push_once(findings: &mut Vec<Diagnostic>, diagnostic: Diagnostic) {
    if !findings.contains(&diagnostic) {
        findings.push(diagnostic);
    }
}
