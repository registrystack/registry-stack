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

use registry_breg::CompiledRegistry;
use registry_breg::compiler::{CompileProfile, compile_project};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
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
            "fixtures/native-models/products/breg/fixtures/organization-membership-access/registry.yaml"
        ),
        module: None,
        ddl_sha256: "da05fb62cb07ea689d7351c76d609a552a5a8fb9e1e5231877d103dd1e33fe88",
        revision: "sha256:8e576d957aca815d99fab81127bdbaecebc5004364742c3bc43a8c56e02eef9c",
    },
    Fixture {
        name: "asset-registration-actions",
        project: include_bytes!(
            "fixtures/native-models/products/breg/fixtures/asset-registration-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "fixtures/native-models/products/breg/fixtures/asset-registration-actions/modules/asset-registration-actions-core/module.yaml"
        )),
        ddl_sha256: "eecd48ec822988a80abbd81aa79fd413037bd928af0223436451309c462d363b",
        revision: "sha256:51867c573789e157d30aa15aed9acd012daeda543b57b890df4fc400d048c6db",
    },
    Fixture {
        name: "facility-registry-actions",
        project: include_bytes!(
            "fixtures/native-models/products/breg/fixtures/facility-registry-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "fixtures/native-models/products/breg/fixtures/facility-registry-actions/modules/facility-registry-actions-core/module.yaml"
        )),
        ddl_sha256: "ad9ae22df3e94dd82b7485096b60d18d08bd6e4b560a9215fc83a4159e6a5686",
        revision: "sha256:ce17d54d37107e7c4af0e8818041310ad8c78c3890a79a785e162671e203110d",
    },
    Fixture {
        name: "household-contact-actions",
        project: include_bytes!(
            "fixtures/native-models/products/breg/fixtures/household-contact-actions/registry.yaml"
        ),
        module: Some(include_bytes!(
            "fixtures/native-models/products/breg/fixtures/household-contact-actions/modules/household-contact-actions-core/module.yaml"
        )),
        ddl_sha256: "4bc36a9b815c33b743423030b26e96d87eac218999699fccb199857246272897",
        revision: "sha256:08f17f3ba40fc524da2247156265bcd81ac23b471a1d652b9cb8d5f9479557ca",
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
    "asset-registration-actions/register-asset-with-inspection: sha256:d3bf2f2920a50c7f21ea8938921753ee7750a40fac9d9c0df781095b3b365137",
    "facility-registry-actions/register-facility: sha256:d856375f28ce2715c32fb442b2d35005c3cf0fecfaa41333084869aa18a82cdd",
    "facility-registry-actions/transfer-facility: sha256:ee16eb40856e6dd7914f14bba6d5c0b4347ef47315f9e4b8ca623ca95f60cba9",
    "household-contact-actions/register-household-contact: sha256:94a43555036a9922e390d31a7b81d7fe56e12c2d73fa668ab67c4b42e304096b",
];
