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
//! The explicit cross-major PostgreSQL text collation, grouped immediate-action
//! policies, and policy definition markers deliberately move every fixture's
//! SQL digest and compiled artifact revision. Action contract fingerprints stay
//! unchanged because their authored contracts did not change.
//! The specific `proposal.review_result_mismatch` Problem likewise changes
//! artifact revisions without changing SQL or Action fingerprints.

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
        ddl_sha256: "b29dd51145e008de342526941bada68781b9d8067a8384643ede258e9471c28a",
        revision: "sha256:00e4bb6340694ee6f26a29d696e6ce93e9c452d9fc804fc42531c4b5ce83d660",
    },
    Fixture {
        name: "asset-registration-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/modules/asset-registration-actions-core/module.yaml"
        )),
        ddl_sha256: "19e503d71d515e5a9e2af9c109b91cce856eb041849d9d0208dfeb454365e7ba",
        revision: "sha256:4dd8291e1832019a2e03af19cab9541642315161492350a3cbf1a5565d4095c2",
    },
    Fixture {
        name: "facility-registry-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/modules/facility-registry-actions-core/module.yaml"
        )),
        ddl_sha256: "92c531b3cf49292bcbaa33b663fd2fc2fdd934d0f96635261f0f9d463ef914d8",
        revision: "sha256:75b102106ddc7bccd7b0b81be0bd4dacf0d5dff6b7f4e618498b8d0dcecf8eff",
    },
    Fixture {
        name: "household-contact-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/modules/household-contact-actions-core/module.yaml"
        )),
        ddl_sha256: "6699bf442105e684adbe6ca506cfbbef90700b0298decdd9ec3f7a3a90cf4e67",
        revision: "sha256:6902bfc35a1e5caef1d82fe0e68dea436590cf9092de854dd4960f62c351d817",
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
