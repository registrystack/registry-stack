// SPDX-License-Identifier: Apache-2.0

//! Pins the generated DDL and compiled revision of every authored fixture
//! that declares no consent record. Row-probe policies are one builder shared
//! by membership and consent boundaries, so a change to that builder must not
//! move the SQL or revision of a project that declares no consent. A
//! deliberate DDL or artifact change updates these digests in the same commit
//! that explains it.

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
        revision: "sha256:77ce2e8b1e635b74608ca276480ce079577a722405bce6075a7753c61d4ea44d",
    },
    Fixture {
        name: "asset-registration-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/modules/asset-registration-actions-core/module.yaml"
        )),
        ddl_sha256: "4c890f2db3f02fd4d686bd4affd8900cf0374ecfc78f020042b53c12cd748d06",
        revision: "sha256:b0a8ab3887fad800767155cfe02a99bc5eb6287baf494f3bf8852358fdc33dd1",
    },
    Fixture {
        name: "facility-registry-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/modules/facility-registry-actions-core/module.yaml"
        )),
        ddl_sha256: "9bed3098641136e121665725ced8d58dc69b7f60692068e6000e6599e268636f",
        revision: "sha256:0e28782296d94c2be855dd49c9c2170ac1aa438c358ab0a98c76dcc9a8a291f0",
    },
    Fixture {
        name: "household-contact-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/modules/household-contact-actions-core/module.yaml"
        )),
        ddl_sha256: "106449513ed214ebb719db8bed6a4e992896c861a220a7f7fbdfcf8656b8ee87",
        revision: "sha256:dabe618531b357e17d39cc943dd1914dc11feab492796826fc92e3a64e2d7f52",
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
