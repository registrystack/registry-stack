//! `render check`: the plain-language preflight. Verifies structure,
//! seals on request, proves label-script font coverage, and reports each
//! document's dependency closure so review surfaces are exact.

use std::path::Path;

use crate::bundle::Bundle;
use crate::problem::{ProblemKind, RenderProblem};

pub fn run(
    bundle_dir: &Path,
    seal: bool,
    runtime_path: Option<&Path>,
    require_audit_under: Option<&Path>,
) -> Result<i32, RenderProblem> {
    if let (Some(runtime_path), Some(root)) = (runtime_path, require_audit_under) {
        let (runtime, _) = crate::runtime::load(runtime_path)?;
        registry_platform_audit::require_audit_under(&runtime.audit.directory, root).map_err(
            |err| {
                RenderProblem::new(
                    ProblemKind::RuntimeInvalid,
                    format!("audit directory fails the containment proof: {err}"),
                )
            },
        )?;
        println!(
            "audit directory {} resolves under {}",
            runtime.audit.directory.display(),
            root.display()
        );
    }
    // Verify everything first; only a bundle that fully verifies gets
    // sealed. Sealing a broken bundle would lend it an unearned seal.
    let bundle = Bundle::load(bundle_dir)?;
    if seal && bundle.manifest.is_sealed() {
        return Err(RenderProblem::new(
            ProblemKind::InvalidArgument,
            "bundle is already sealed; edit, then run `render seal` to re-seal",
        ));
    }
    check_script_coverage(&bundle)?;
    check_label_key_sets(&bundle)?;
    if seal {
        Bundle::seal(bundle_dir)?;
        println!("sealed (bundle hashes written to manifest.yaml)");
    } else if !bundle.manifest.is_sealed() {
        println!("note: bundle is unsealed; compile works, serve does not (run `render seal`)");
    }
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
    let governed = bundle
        .manifest
        .hashes
        .as_ref()
        .map(|h| h.len())
        .unwrap_or(0);
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

/// Every character of every label value must be drawable by some bundle or
/// baseline font. This is the check-time half of the paper-safety rule: a
/// successful render that prints tofu is wrong on paper, so missing
/// coverage is a named problem here and glyph warnings fail `--strict` at
/// render time.
pub fn check_script_coverage(bundle: &Bundle) -> Result<(), RenderProblem> {
    let mut failures: Vec<String> = Vec::new();
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
                        failures.push(format!(
                            "labels/{locale}.yaml key {key:?}: no bundled font covers {ch:?}"
                        ));
                        break;
                    }
                }
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(RenderProblem::new(
            ProblemKind::FontInvalid,
            format!(
                "label text is not covered by the bundle fonts: {}",
                failures.join("; ")
            ),
        )
        .with_locations(failures))
    }
}

/// Every locale of a document must define the same label key set: a key
/// missing from one locale fails only that locale's render, at template
/// runtime — the worst place to discover it. `check` (and serve startup)
/// name the divergence up front, so PAYLOAD.md's "a missing label key is a
/// `render check` error, not a runtime surprise" holds.
pub fn check_label_key_sets(bundle: &Bundle) -> Result<(), RenderProblem> {
    let mut failures: Vec<String> = Vec::new();
    for document in bundle.documents.values() {
        let mut reference: Option<(String, std::collections::BTreeSet<String>)> = None;
        for (locale, table) in &document.labels {
            let keys: std::collections::BTreeSet<String> = table
                .as_object()
                .map(|map| map.keys().cloned().collect())
                .unwrap_or_default();
            match &reference {
                None => reference = Some((locale.clone(), keys)),
                Some((reference_locale, reference_keys)) => {
                    for missing in reference_keys.difference(&keys) {
                        failures.push(format!(
                            "labels/{locale}.yaml is missing key {missing:?} (present in labels/{reference_locale}.yaml)"
                        ));
                    }
                    for undeclared in keys.difference(reference_keys) {
                        failures.push(format!(
                            "labels/{reference_locale}.yaml is missing key {undeclared:?} (present in labels/{locale}.yaml)"
                        ));
                    }
                }
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(RenderProblem::new(
            ProblemKind::LabelsInvalid,
            format!(
                "label key sets diverge across locales: {}",
                failures.join("; ")
            ),
        )
        .with_locations(failures))
    }
}
