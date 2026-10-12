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
        ddl_sha256: "da05fb62cb07ea689d7351c76d609a552a5a8fb9e1e5231877d103dd1e33fe88",
        revision: "sha256:5dcb57b44859dbd1ba11f54b1871f0d02096ac53d227d3acfc54ec71e12aa411",
    },
    Fixture {
        name: "asset-registration-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/modules/asset-registration-actions-core/module.yaml"
        )),
        ddl_sha256: "1e1a4761b86e48bc044de29acdbd3ef7fefa31535317ec07610974dd561dad3e",
        revision: "sha256:220ca8b263cfd0089d350a66db6ca36cb5ce345dc39132b673f2955280532569",
    },
    Fixture {
        name: "facility-registry-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/modules/facility-registry-actions-core/module.yaml"
        )),
        ddl_sha256: "d47a47845dddec232e9e4c5a8ed8758751d5931c4bf8144194fa3b3f95ebd6ac",
        revision: "sha256:dab3bbfc5842b4568a5af92c71a3b3021830a95d9ad9a643aa38e52277b82e20",
    },
    Fixture {
        name: "household-contact-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/modules/household-contact-actions-core/module.yaml"
        )),
        ddl_sha256: "7ff45c7097e199879e1191ac8f313c5c1ef582ad6ac0bb1d6f455887f1e62bbe",
        revision: "sha256:97a16943bab3c91ae92af5cfe56d61f51991ed6948ba37a558661caf4b3f7f31",
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
                fixture.name, action.id, action.contract_fingerprint
            ));
        }
    }
    assert_eq!(fingerprints, ACTION_FINGERPRINTS);
}

const ACTION_FINGERPRINTS: &[&str] = &[
    "asset-registration-actions/register-asset-with-inspection: sha256:e9bd42c7373430e6fe13d5d0a8a0cfa46fb77d05728e635610d1deb230668359",
    "facility-registry-actions/register-facility: sha256:a0433e560dbf1874c2b7fc74a1ee25c71e5604d0b7b527b717559febe5be850e",
    "facility-registry-actions/transfer-facility: sha256:1bf7d19ae85b660bed9f833e6f3f15fb97228a8ee97070416e9b55fcfaedab9b",
    "household-contact-actions/register-household-contact: sha256:4c9055ac68dfe2b745f75b2e538c277ed19ed2ae83b4f84c3f91fedb4812ad3e",
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
/// matches. These values are regression pins over the committed fixture
/// projects: a change that moves one blocks activation over the proposals
/// submitted under the earlier value, so it is deliberate and updates the pin
/// in the same commit that explains it.
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
    "asset-site-placement-change-requests/placement-correction-request: sha256:f5d7d62a27d58b0b4809ec330aace7300dde6a5c0300e825fc5576cd93b116be",
    "person-name-change-rhai/person-name-change-request: sha256:6a5c03890d429b98d9e88fd75ad03cefc09d93031fff6d368264f5525f56075e",
    "publicschema-household-change-requests/register-household-contact-request: sha256:455d7c75edc8e328c02a2c8148993de203e1f852b00f3f9905fc7019b188ba15",
    "request-attachments/correction-request: sha256:cb3b2bf47b4120c6b794da09cde9e40fcba7e23b1327ceaad88cd641c3f033f4",
];
