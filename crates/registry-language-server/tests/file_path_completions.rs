// SPDX-License-Identifier: Apache-2.0
//! Repairing authored file references from bounded, contained sibling names.

mod support;

use registry_language_server::{ProductKind, ProjectIndex};
use support::{file, EvidenceProject as Project};

const RENDER: &str = r#"apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1
kind: RenderBundle
bundleVersion: 1
documents:
  - id: receipt
    version: 1
    entryFile: <|entry|>templates/missing.typ
    schemaFile: <|schema|>templates/schema.json
    labels: [<|locale|>missing]
"#;

fn render_index(project: &Project) -> ProjectIndex {
    ProjectIndex::load_product(project.root(), ProductKind::Render).expect("Render project indexes")
}

#[test]
fn missing_render_template_offers_existing_unreferenced_sibling_as_authored_path() {
    let project = Project::new(&[
        file("manifest.yaml", RENDER),
        file("templates/receipt.typ", "#text(\"Receipt\")"),
        file("templates/schema.json", "{}"),
        file("templates/unrelated.json", "{}"),
        file("templates/nested/deep.typ", "#text(\"Other\")"),
    ]);
    let candidates = render_index(&project).completions_at(
        &project.path("manifest.yaml"),
        project.cursor("manifest.yaml", "entry"),
    );
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.filter_text.as_str())
            .collect::<Vec<_>>(),
        ["templates/receipt.typ"]
    );
    assert_eq!(candidates[0].new_text, "templates/receipt.typ");
}

#[test]
fn missing_render_locale_offers_raw_locale_names_without_path_or_suffix() {
    let project = Project::new(&[
        file("manifest.yaml", RENDER),
        file("labels/en.yaml", "title: Receipt\n"),
        file("labels/fr.yaml", "title: Reçu\n"),
        file("labels/other.json", "{}"),
    ]);
    let candidates = render_index(&project).completions_at(
        &project.path("manifest.yaml"),
        project.cursor("manifest.yaml", "locale"),
    );
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.filter_text.as_str())
            .collect::<Vec<_>>(),
        ["en", "fr"]
    );
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.new_text.as_str())
            .collect::<Vec<_>>(),
        ["en", "fr"]
    );
}

#[cfg(unix)]
#[test]
fn sibling_completions_refuse_symlink_files_and_symlink_parent_directories() {
    use std::{fs, os::unix::fs::symlink};
    let outside = tempfile::tempdir().unwrap();
    fs::write(
        outside.path().join("outside.typ"),
        "SYNTHETIC_OUTSIDE_CANARY",
    )
    .unwrap();
    let project = Project::new(&[
        file("manifest.yaml", RENDER),
        file("templates/receipt.typ", "#text(\"Receipt\")"),
    ]);
    symlink(
        outside.path().join("outside.typ"),
        project.path("templates/linked.typ"),
    )
    .unwrap();
    let candidates = render_index(&project).completions_at(
        &project.path("manifest.yaml"),
        project.cursor("manifest.yaml", "entry"),
    );
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.filter_text.as_str())
            .collect::<Vec<_>>(),
        ["templates/receipt.typ"]
    );

    fs::remove_file(project.path("templates/linked.typ")).unwrap();
    fs::remove_file(project.path("templates/receipt.typ")).unwrap();
    fs::remove_dir(project.path("templates")).unwrap();
    symlink(outside.path(), project.path("templates")).unwrap();
    assert!(render_index(&project)
        .completions_at(
            &project.path("manifest.yaml"),
            project.cursor("manifest.yaml", "entry"),
        )
        .is_empty());
}

#[test]
fn private_key_reference_does_not_enumerate_unrelated_key_roles() {
    let project = Project::new(&[
        file(
            ".registry-stack-editor/project.json",
            r#"{"product":"evidence-oid4vci","document":"wallet.yaml"}"#,
        ),
        file(
            "wallet.yaml",
            "apiVersion: id.registrystack.org/formats/evidence/oid4vci-runtime/v1alpha1\nkind: EvidenceOid4vciRuntimeConfig\ntokenClient:\n  privateKeyRef: secret:file/<|key|>keys/missing.pem\n",
        ),
        file("keys/token.pem", "SYNTHETIC_TOKEN_KEY_CANARY"),
        file("keys/issuer.pem", "SYNTHETIC_UNRELATED_KEY_CANARY"),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::EvidenceOid4vci).unwrap();
    assert!(index
        .completions_at(
            &project.path("wallet.yaml"),
            project.cursor("wallet.yaml", "key")
        )
        .is_empty());
}

#[test]
fn oversized_opaque_template_is_offered_without_indexing_its_contents() {
    use std::fs;
    let project = Project::new(&[
        file("manifest.yaml", RENDER),
        file("templates/receipt.typ", ""),
    ]);
    fs::OpenOptions::new()
        .write(true)
        .open(project.path("templates/receipt.typ"))
        .unwrap()
        .set_len(2 * 1024 * 1024)
        .unwrap();
    let index = render_index(&project);
    let candidates = index.completions_at(
        &project.path("manifest.yaml"),
        project.cursor("manifest.yaml", "entry"),
    );
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.filter_text.as_str())
            .collect::<Vec<_>>(),
        ["templates/receipt.typ"]
    );
    assert!(!index
        .document_paths()
        .any(|path| path == project.path("templates/receipt.typ")));
}

#[test]
fn sibling_completion_directory_exceeding_editor_ceiling_has_no_partial_candidates() {
    use std::fs;
    let project = Project::new(&[file("manifest.yaml", RENDER)]);
    fs::create_dir(project.path("templates")).unwrap();
    for number in 0..=1024 {
        fs::write(
            project.path(&format!("templates/candidate-{number:04}.typ")),
            "",
        )
        .unwrap();
    }
    assert!(render_index(&project)
        .completions_at(
            &project.path("manifest.yaml"),
            project.cursor("manifest.yaml", "entry")
        )
        .is_empty());
}
