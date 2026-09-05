// SPDX-License-Identifier: Apache-2.0
//! What an editor reports over the projects the adopter tooling scaffolds.
//!
//! Two of those projects are not Relay V2 and not an OpenAPI-backed Evidence project, and both used
//! to collect a diagnostic that named a rule their own build never applies. A Base Registry Engine
//! project root is a `registry.yaml`, the same file name Relay V2 marks its root with, so the
//! marker alone cannot say which product wrote the directory. An Evidence project whose questions
//! read a named source carries no `source.openapi.yaml`, which the description reading used to
//! require of every root.
//!
//! The projects here are the shapes those two commands write, held against the server an adopter
//! runs: `bregctl init` writes the registry project this file reads from the Base Registry Engine
//! acceptance material, and `evidencectl new --transport sqlite-extract` writes a referenced-form
//! project with no description. What the source declares as its transport is not read by the index
//! at all; the referenced form is what decides whether a description is a prerequisite, so the
//! fixture below writes the same question shape a SQLite or a fixed-HTTP project writes.

mod support;

use std::{fs, path::PathBuf};

use serde_json::Value;
use support::{lsp::LspSession, without, EvidenceProject, OPENAPI_PATH, QUESTION_PATH};

fn acceptance_project(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products")
        .join(relative)
        .canonicalize()
        .expect("the acceptance project exists")
}

#[tokio::test]
async fn a_breg_project_root_is_claimed_by_no_family_this_server_serves() {
    let root = acceptance_project("breg/acceptance/business");
    let registry = root.join("registry.yaml");
    let document = fs::read_to_string(&registry).expect("registry.yaml reads");
    let mut session = LspSession::start();
    session.initialize(&root).await;
    session.open(&registry, &document, 1).await;

    assert_eq!(
        session.published_diagnostics(&registry),
        None,
        "a Base Registry Engine project is not a Relay V2 project and gets no Relay V2 sentence"
    );
}

#[tokio::test]
async fn a_relay_v2_project_root_is_still_claimed_by_its_own_family() {
    let root = acceptance_project("relay-v2/acceptance/business-registry");
    let registry = root.join("registry.yaml");
    let document = fs::read_to_string(&registry).expect("registry.yaml reads");
    let mut session = LspSession::start();
    session.initialize(&root).await;
    session.open(&registry, &document, 1).await;

    assert_eq!(
        session.published_diagnostics(&registry),
        Some(Vec::<Value>::new()),
        "the accepted Relay V2 project is still indexed and still compiler-clean"
    );
}

#[tokio::test]
async fn an_evidence_project_with_no_description_is_indexed_clean() {
    let project = EvidenceProject::new(&without(&support::adult_status_project(), OPENAPI_PATH));
    let question = project.path(QUESTION_PATH);
    let document = fs::read_to_string(&question).expect("the question reads");
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    session.open(&question, &document, 1).await;

    assert_eq!(
        session.published_diagnostics(&project.path(OPENAPI_PATH)),
        None,
        "a project whose questions read named sources declares no OpenAPI transport, so the \
         description it never wrote is not a file anything reports about"
    );
    assert_eq!(
        session.published_diagnostics(&question),
        Some(Vec::<Value>::new()),
        "the question the author is editing is indexed and clean"
    );
}
