// SPDX-License-Identifier: Apache-2.0

//! Pins the generated DDL and compiled revision of every authored fixture
//! that declares no consent record. Row-probe policies are one builder shared
//! by membership and consent boundaries; a project that declares no consent
//! must keep the exact SQL and revision it compiled to before that builder
//! existed. A deliberate DDL or artifact change updates these digests in the
//! same commit that explains it.

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
        ddl_sha256: "33dd380479e2c45354d1bd601f9eb6d9a9bca907bc90be8fd25236f675a7699e",
        revision: "sha256:4d10ccf07338a48c80c44a8775716edac66845880e2deb1510db6703f19f3538",
    },
    Fixture {
        name: "asset-registration-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/modules/asset-registration-actions-core/module.yaml"
        )),
        ddl_sha256: "d9c6bd0c2023586b73a1e97f352d72134668b1f6d4170dddfb46ae730657056a",
        revision: "sha256:a2599b040be111669914a2e2b89f14ad7e5fadbe84d7db255f06e38297c0e7dd",
    },
    Fixture {
        name: "facility-registry-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/modules/facility-registry-actions-core/module.yaml"
        )),
        ddl_sha256: "49eef3936bdfde9c9737cc8b81e2858d619431de9616c04e2256c57f73acfd6d",
        revision: "sha256:7d1f18f94bccee1d72805737762430890bc9fbc3ac272b622e08206b9d0ef1b5",
    },
    Fixture {
        name: "household-contact-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/modules/household-contact-actions-core/module.yaml"
        )),
        ddl_sha256: "b1dd61180f3101b4d0e768fc99906b5614f89000bc31145d1fb4855f0105f558",
        revision: "sha256:cc1bb37e85c9f16e37148fc94953aed33e9485aa0c93819bc33febbde5305f77",
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
/// fingerprint, so an engine upgrade that leaves a project unchanged must
/// leave every action fingerprint unchanged too.
#[test]
fn fixtures_keep_their_action_contract_fingerprints() {
    let mut fingerprints = Vec::new();
    for fixture in FIXTURES {
        for action in &compile(fixture).actions().actions {
            fingerprints.push(format!(
                "{}/{}: {}",
                fixture.name, action.id, action.contract_fingerprint
            ));
        }
    }
    assert_eq!(fingerprints, ACTION_FINGERPRINTS);
}

const ACTION_FINGERPRINTS: &[&str] = &[
    "asset-registration-actions/register-asset-with-inspection: sha256:3fa3f521dc91b83863d5afb93827fc6a85594d4af74b586afecd748a017402e1",
    "facility-registry-actions/register-facility: sha256:14179e571a8c08e1fb368972534e29143f084d2e858eafa4542963cb0da7fff8",
    "facility-registry-actions/transfer-facility: sha256:19df2b5b87d517e25815420acd0c3f8207575a2c48776eb451f62a2cd250c011",
    "household-contact-actions/register-household-contact: sha256:121d47d280e477162d48a4c41d4db80d1778c1a6ab2252c8bf638deae997caab",
];
