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
        ddl_sha256: "dc1507a1ff75842283db34a1665e9c787435d1315bedf056164361e7cbae312e",
        revision: "sha256:501355dee6a415f91abdbea902f97d1dc123980a7d65762b70eec52d06e4d7b7",
    },
    Fixture {
        name: "asset-registration-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/asset-registration-actions/modules/asset-registration-actions-core/module.yaml"
        )),
        ddl_sha256: "65cd1da8f932b1e8e2dcbeaae51e00fa215db0cb9b03d5ca3b45a606f8eb9f78",
        revision: "sha256:2aa601611a8a4797797f1b345ce946e148c8396a87d5b9869ba78f98711687a9",
    },
    Fixture {
        name: "facility-registry-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/facility-registry-actions/modules/facility-registry-actions-core/module.yaml"
        )),
        ddl_sha256: "a35afb54d261b1016a8d2d22a1fa272791ea0c8a1fdaaa89826d42356f81024c",
        revision: "sha256:e0b729a29777c4e328b947018d94492035d5ceed3100b28d30719880128c1135",
    },
    Fixture {
        name: "household-contact-actions",
        project: include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "../../../products/breg/fixtures/household-contact-actions/modules/household-contact-actions-core/module.yaml"
        )),
        ddl_sha256: "ce04eb48c50651d06e5c29d95be4b8945ee1c51b9148b143d0943322921b0b81",
        revision: "sha256:d594038445209b125dfc7f5dd1a67e22fa0d8c6bbe7c5ef53ec09ac8aecd19a1",
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
