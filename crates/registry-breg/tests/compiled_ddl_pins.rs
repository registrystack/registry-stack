// SPDX-License-Identifier: Apache-2.0

//! Pins the generated DDL and compiled revision of every authored fixture
//! that declares no consent record. Row-probe policies are one builder shared
//! by membership and consent boundaries; a project that declares no consent
//! must keep the exact SQL and revision it compiled to before that builder
//! existed. A deliberate DDL or artifact change updates these digests in the
//! same commit that explains it.

use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml, ModuleAssetSource};
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
        revision: "sha256:75e462b2ff92591c1bb88d6e6f928932ebf54fe1e116eb81502924d9d8e7d5d1",
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
        revision: "sha256:ae86bc2052c3d64b79ca55cf8c5afe6684c3da2e3701dd4080eef153a2ce3f71",
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
        revision: "sha256:2de0a7d6055ac926ac022d5f930425f2322a1e0fea9217017b36c0ec1a4f0321",
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
        revision: "sha256:72dd24db3ce2c3c2b20efabcddfcf74deb00e7d41ee53ed5a2d50ad50fa4face",
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

struct RequestFixture {
    name: &'static str,
    project: &'static [u8],
    modules: &'static [&'static [u8]],
    assets: &'static [(Option<&'static str>, &'static str, &'static [u8])],
}

const REQUEST_FIXTURES: &[RequestFixture] = &[
    RequestFixture {
        name: "asset-site-placement-change-requests",
        project: include_bytes!(
            "../../../products/breg/acceptance/asset-site-placement-change-requests/registry.yaml"
        ),
        modules: &[include_bytes!(
            "../../../products/breg/acceptance/asset-site-placement-change-requests/modules/asset-site-placement-core/module.yaml"
        )],
        assets: &[],
    },
    RequestFixture {
        name: "person-name-change-rhai",
        project: include_bytes!(
            "../../../products/breg/acceptance/person-name-change-rhai/registry.yaml"
        ),
        modules: &[],
        assets: &[(
            None,
            "scripts/person-name-change.rhai",
            include_bytes!(
                "../../../products/breg/acceptance/person-name-change-rhai/scripts/person-name-change.rhai"
            ),
        )],
    },
    RequestFixture {
        name: "publicschema-household-change-requests",
        project: include_bytes!(
            "../../../products/breg/acceptance/publicschema-household-change-requests/registry.yaml"
        ),
        modules: &[
            include_bytes!(
                "../../../products/breg/acceptance/publicschema-household-change-requests/modules/publicschema-household-core/module.yaml"
            ),
            include_bytes!(
                "../../../products/breg/acceptance/publicschema-household-change-requests/modules/publicschema-household-demographics/module.yaml"
            ),
        ],
        assets: &[(
            Some("publicschema-household-demographics"),
            "sql/household-demographics.sql",
            include_bytes!(
                "../../../products/breg/acceptance/publicschema-household-change-requests/modules/publicschema-household-demographics/sql/household-demographics.sql"
            ),
        )],
    },
    RequestFixture {
        name: "request-attachments",
        project: include_bytes!(
            "../../../products/breg/acceptance/request-attachments/registry.yaml"
        ),
        modules: &[],
        assets: &[],
    },
];

/// A submitted proposal is bound to its request type's contract fingerprint,
/// and a successor package activates only while every submitted proposal still
/// matches. These values are the ones the previous release compiled the same
/// projects to, so an engine upgrade that leaves a project unchanged must leave
/// every request fingerprint unchanged too.
#[test]
fn fixtures_keep_their_change_request_contract_fingerprints() {
    let mut fingerprints = Vec::new();
    for fixture in REQUEST_FIXTURES {
        let project = parse_project_yaml(fixture.project).expect("fixture project parses");
        let modules = fixture
            .modules
            .iter()
            .map(|module| parse_module_yaml(module).expect("fixture module parses"))
            .collect::<Vec<_>>();
        let assets = fixture
            .assets
            .iter()
            .map(|(module, path, bytes)| ModuleAssetSource {
                module: module.map(str::to_owned),
                path: (*path).to_owned(),
                bytes: bytes.to_vec(),
            })
            .collect::<Vec<_>>();
        let registry =
            compile_project_with_assets(&project, &modules, &assets, CompileProfile::Authoring)
                .expect("fixture compiles");
        for (entity_id, entity) in registry.entities() {
            if let Some(request) = &entity.change_request {
                fingerprints.push(format!(
                    "{}/{entity_id}: {}",
                    fixture.name, request.contract_fingerprint
                ));
            }
        }
    }
    assert_eq!(fingerprints, CHANGE_REQUEST_FINGERPRINTS);
}

const CHANGE_REQUEST_FINGERPRINTS: &[&str] = &[
    "asset-site-placement-change-requests/placement-correction-request: sha256:e95a1e3b26ecc0f7f816bc62772c54bba9fa136bfbc367ef72f4cf2486a54003",
    "person-name-change-rhai/person-name-change-request: sha256:141d45ada88aa8347bff812ebdeb6ac4bb45dd9aac3a4e9599119b6a4c3f4b61",
    "publicschema-household-change-requests/register-household-contact-request: sha256:652ae970f524cb0b2eea0d1368b6ccbd77a956009906cb5fb52ebd2f4af2ee0a",
    "request-attachments/correction-request: sha256:107cdf2dca9efad8858e6ec6541b5daacd2f7615256850279ca38105158aa761",
];
