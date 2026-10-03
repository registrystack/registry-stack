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
        revision: "sha256:b1486964ee4e07382e836eb4f1ba72c5aea140be0bb7ade739c075b745212550",
    },
    Fixture {
        name: "asset-registration-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/modules/asset-registration-actions-core/module.yaml"
        )),
        ddl_sha256: "aecd19165df9a20532616537f3e407bcd279b06d99d57c26aad1b4cd35f4d884",
        revision: "sha256:c4f24bb039fa3c7abbeacb0a913bda9523357e003ae4201f8ac0cb68fab768f6",
    },
    Fixture {
        name: "facility-registry-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/modules/facility-registry-actions-core/module.yaml"
        )),
        ddl_sha256: "9bfd5199cc4b3e088eb1ca038a4cf107257412e7baea03c1bd2c077ed62c1587",
        revision: "sha256:6719805a68bac121c09c2a75b931b2b1f8574dfbefceb16a045030527a5371cc",
    },
    Fixture {
        name: "household-contact-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/modules/household-contact-actions-core/module.yaml"
        )),
        ddl_sha256: "c34618ef0c2050aa34f76de318fae87433beec9b71d89c0d371b0c0e301e8b28",
        revision: "sha256:a37dff67da9e2aecc0c110fc241944645bb12b96de6d4654d02a52ac18f0591f",
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
