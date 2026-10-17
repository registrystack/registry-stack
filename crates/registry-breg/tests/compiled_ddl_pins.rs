// SPDX-License-Identifier: Apache-2.0

//! Pins the generated DDL and compiled revision of every authored fixture
//! that declares no consent record. Row-probe policies are one builder shared
//! by membership and consent boundaries, so a change to that builder must not
//! move the SQL or revision of a project that declares no consent. A
//! deliberate DDL or artifact change updates these digests in the same commit
//! that explains it.
//!
//! The cursor envelope bound in generated OpenAPI is part of the compiled
//! artifact revision. Increasing that bound preserves the SQL and action
//! fingerprints but deliberately moves the fixture revisions pinned below.
//!
//! BReg's record-type contract respelling changes serialized effect targets and
//! commit guards in `immediate_actions::definition_revision`. The resulting
//! Action revision is embedded in generated SQL contractFingerprint checks, so
//! the three Action fixtures deliberately receive new SQL digests as well as
//! Action pins. The membership-only fixture retains its exact SQL digest.
//! Updated BReg metadata/schema/event artifacts also move every fixture's
//! compiled artifact revision. These remain exact pins, not drift exemptions.
//! Removing the retired planner Problem and the attachment uploader member
//! from OpenAPI moves artifact revisions without changing SQL or Action pins.
//! The portable Action contract and its schema are now packaged alongside the
//! compiled inventory. Their addition changes the three Action fixture artifact
//! revisions while preserving their SQL and Action definition fingerprints.
//! The membershipRecordType spelling, optional exact Review policy selection in
//! the Action contract schema, and normalized Python SDK EOF also change artifact
//! revisions while preserving the exact SQL and Action fingerprints below.
//! Proposal and ingestion run paging, the closed application status recovery
//! vocabulary, and the per-version submission read with its
//! `proposal.submission_expired` Problem likewise move artifact revisions only.
//! The terminal `rejected` Proposal state, the derived `turn` and its list
//! filter, the served `decision`, and the `rejected` and `review-returned`
//! events likewise move artifact revisions only.
//! Declared row-local constraint locations in the Problem schema likewise move
//! artifact revisions only; the SQL and Action fingerprints remain unchanged.

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::CompiledRegistry;
use sha2::{Digest, Sha256};

struct Fixture {
    name: &'static str,
    project: &'static [u8],
    module: Option<&'static [u8]>,
    ddl_sha256: &'static str,
    revision: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "organization-membership-access",
        project: include_bytes!(
            "../../../products/breg/fixtures/organization-membership-access/registry.yaml"
        ),
        module: None,
        ddl_sha256: "da05fb62cb07ea689d7351c76d609a552a5a8fb9e1e5231877d103dd1e33fe88",
        revision: "sha256:be02d4f6bf22cc33d501c78a621944c399b1187743775edc2142f2fbd4372885",
    },
    Fixture {
        name: "asset-registration-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/modules/asset-registration-actions-core/module.yaml"
        )),
        ddl_sha256: "dfb8cefaa8059cda62c5d2d39bb14fcbf33f589061ca6fe81402e948048caaf6",
        revision: "sha256:0eb9224425b7553774a9023d92205f0035050c3227081d417bda189d9806c598",
    },
    Fixture {
        name: "facility-registry-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/modules/facility-registry-actions-core/module.yaml"
        )),
        ddl_sha256: "603a8c6c8ab8500fe5beff9b78657c667de7e90c91578700091086e2f1a82380",
        revision: "sha256:4c22016139a9c8126c331d341c5e86df81c74ec1ffc16ce6b6f671196d758b74",
    },
    Fixture {
        name: "household-contact-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/modules/household-contact-actions-core/module.yaml"
        )),
        ddl_sha256: "451d62c09089364c81f343acfbc175f82db449f00446886fedc6e8cc03ef86ad",
        revision: "sha256:b9d5ca50e524048f3e8f503243e28b567e8ee5a8c2d11f223a021c0ff567cb5d",
    },
];

fn compile(fixture: &Fixture) -> CompiledRegistry {
    let project = parse_project_yaml(fixture.project).expect("fixture project parses");
    let modules = fixture
        .module
        .map(|module| vec![parse_module_yaml(module).expect("fixture module parses")])
        .unwrap_or_default();
    compile_project(&project, &modules, CompileProfile::Authoring).expect("fixture compiles")
}

fn ddl_sha256(registry: &CompiledRegistry) -> String {
    let bytes = serde_json::to_vec(registry.ddl()).expect("DDL inventory serializes");
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn fixtures_without_consent_keep_their_exact_ddl_and_revision() {
    let mut drift = Vec::new();
    for fixture in FIXTURES {
        let registry = compile(fixture);
        let ddl = ddl_sha256(&registry);
        if ddl != fixture.ddl_sha256 || registry.revision() != fixture.revision {
            drift.push(format!(
                "{}: ddl_sha256 {ddl}, revision {}",
                fixture.name,
                registry.revision()
            ));
        }
    }
    assert!(drift.is_empty(), "{}", drift.join("\n"));
}

/// Idempotent retries match a stored request against its action's contract
/// fingerprint. These values are regression pins over the committed fixture
/// projects: a change that moves one orphans the retries stored under the
/// earlier value, so it is deliberate and updates the pin in the same commit
/// that explains it.
#[test]
fn fixtures_keep_their_action_contract_fingerprints() {
    let mut fingerprints = Vec::new();
    for fixture in FIXTURES {
        for action in &compile(fixture).actions().actions {
            fingerprints.push(format!(
                "{}/{}: {}",
                fixture.name, action.id, action.definition_revision
            ));
        }
    }
    assert_eq!(fingerprints, ACTION_FINGERPRINTS);
}

const ACTION_FINGERPRINTS: &[&str] = &[
    "asset-registration-actions/register-asset-with-inspection: sha256:5a9937ab9d8654a366e89e31a098b93312bbacddbe74a2dbff09915aedbc5fcb",
    "facility-registry-actions/register-facility: sha256:9aa777aea43dd8f2bdc43499bebae20fc5cd40d905ab614938a74da7652c243a",
    "facility-registry-actions/transfer-facility: sha256:5f346eabb7d4a8f9bf959432ae47de3aaecaa07962d6fec954452848a31e84d4",
    "household-contact-actions/register-household-contact: sha256:cb90f8518169dafc15d6d66ca467e9f1093b5d04afe68c970d91b966e7f7c905",
];
