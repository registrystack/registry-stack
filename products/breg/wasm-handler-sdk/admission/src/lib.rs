// SPDX-License-Identifier: Apache-2.0
//! The admission-proof harness: the load-bearing test of the SDK product.
//!
//! It proves the two claims a handler author depends on, against the same
//! registry code paths a real deployment uses (path dependencies into the
//! repository's own crates):
//!
//! 1. A module built by `scripts/build.sh` passes BREG authoring admission:
//!    the compiler reads it, size-checks it, hashes it, validates it against
//!    the platform guest ABI through its own executor `prepare`, and captures
//!    it into the compiled handler and the package closure.
//! 2. The admitted module produces the exact fixture outcomes when the
//!    registry executes it: through `evaluate_action_detailed` (the real
//!    evaluation entry, the same decode layer and shared validator the Rhai
//!    path uses) and at the byte level through the platform executor under
//!    both execution backends.
//!
//! The proof is not a unit test of the SDK; it is a product test of the
//! built artifact, which is why it reads modules from `artifacts/` (written
//! by `scripts/build.sh`) rather than compiling anything itself. Generated
//! binaries are never committed: the documented generator is
//! `scripts/build.sh`, and `artifacts/module-sizes.tsv` records each run's
//! bytes and sha256.

use std::path::PathBuf;

use registry_breg::compiler::{CompileProfile, compile_project_with_assets};
use registry_breg::contract::{ModuleAssetSource, parse_project_json};
use registry_platform_script::wasm::{Backend, Budgets, Executor};
use serde_json::{Value, json};

/// Every module produced by `scripts/build.sh`, as `(file name, bytes)`.
/// Fails with instructions when no artifact exists.
pub fn built_modules() -> Vec<(String, Vec<u8>)> {
    let dir = artifacts_dir();
    let mut modules = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("no artifacts directory at {}: {error}", dir.display()));
    for entry in entries {
        let path = entry.expect("a readable artifacts directory entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "wasm")
        {
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            modules.push((
                path.file_name().unwrap().to_string_lossy().into_owned(),
                bytes,
            ));
        }
    }
    assert!(
        !modules.is_empty(),
        "no built modules under {}: run scripts/build.sh first",
        dir.display()
    );
    modules.sort();
    modules
}

fn artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../artifacts")
}

/// One fixture corpus case: the request inputs and the exact outcome
/// document the module must produce.
pub struct FixtureCase {
    pub name: String,
    pub inputs: Value,
    pub expected: Value,
}

/// The shared fixture corpus (`fixtures/normalize-phone-cases.json`).
pub fn corpus() -> Vec<FixtureCase> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/normalize-phone-cases.json");
    let document: Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .expect("the fixture corpus parses");
    document["cases"]
        .as_array()
        .expect("the corpus carries a cases array")
        .iter()
        .map(|case| FixtureCase {
            name: case["name"].as_str().expect("a case name").to_owned(),
            inputs: case["inputs"].clone(),
            expected: case["expected"].clone(),
        })
        .collect()
}

/// The registry project the template module belongs to: the same authored
/// shape the `wasm_handler_admission` tests compile, with the phone
/// handler's declared inputs, refusal catalogue, and write slot. The refusal
/// labels are pinned here so the proof asserts them too.
pub fn phone_project() -> Value {
    serde_json::from_str(
        r#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"wasm-template-proof","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"person","primaryDataset":"proof-dataset","route":"people","mutationMode":"mutable",
            "fields":[
              {"id":"phone","apiName":"phone","type":"string","maxLength":32,"required":true,"classification":"restricted"}
            ]
          }],
          "actions":[{
            "id":"normalize-phone",
            "inputs":[
              {"id":"raw-phone","apiName":"rawPhone","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"default-region","apiName":"defaultRegion","type":"string","maxLength":64,"required":true,"classification":"restricted"}
            ],
            "handler":{
              "kind":"wasm","module":"wasm/handler.wasm","abi":"registry.action-handler/v1",
              "refusals":[
                {"code":"invalid-phone","label":"The phone number is not a valid phone number."},
                {"code":"invalid-region","label":"The region is not a usable phone region."}
              ],
              "writes":[{
                "id":"phone","target":{"entity":"person"},"operation":"create",
                "fields":["phone"]
              }]
            }
          }],
          "accessProfiles":[{
            "id":"registrar","default":true,"principalClaim":"registry_principal",
            "permissions":[{
              "action":"normalize-phone","operations":["invoke"],
              "targets":[{"entity":"person","rowBoundaries":[]}],
              "results":["phone"]
            }]
          }]
        }"#,
    )
    .expect("the proof project shape parses")
}

/// Compile the proof project with `bytes` as its single handler module,
/// through the same authoring path the admission tests use.
pub fn compile_with_module(
    bytes: Vec<u8>,
) -> Result<registry_breg::CompiledRegistry, registry_breg::CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(&phone_project()).unwrap()).unwrap();
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "wasm/handler.wasm".to_owned(),
            bytes,
        }],
        CompileProfile::Authoring,
    )
}

/// sha256 of the module bytes, rendered the way the compiled handler stores
/// it (`sha256:` plus lowercase hex).
pub fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut rendered = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut rendered, "{byte:02x}").expect("digest writes");
    }
    rendered
}

/// The `{"inputs": ...}` request-envelope bytes for one fixture case, built
/// exactly the way the process runtime builds them.
pub fn envelope(case: &FixtureCase) -> Vec<u8> {
    serde_json::to_vec(&json!({"inputs": case.inputs})).expect("the envelope serializes")
}

/// Install the process WASM runtime with the default budgets and backend, once
/// per test binary. `evaluate_action_detailed` refuses to evaluate a WASM
/// handler before this.
pub fn install_runtime_once() {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALLED.get_or_init(|| {
        registry_breg::wasm_runtime::install_default()
            .expect("the default WASM runtime configuration is valid");
    });
}

/// One shared executor per (backend, module ceiling), once per test binary:
/// engines are expensive and every call already gets a fresh store and
/// instance, so the corpus reuses one prepared module per combination.
pub fn executor(backend: Backend, max_module_bytes: usize) -> &'static Executor {
    use std::sync::OnceLock;
    static NATIVE_DEFAULT: OnceLock<Executor> = OnceLock::new();
    static PULLEY_DEFAULT: OnceLock<Executor> = OnceLock::new();
    static NATIVE_PREINIT: OnceLock<Executor> = OnceLock::new();
    static PULLEY_PREINIT: OnceLock<Executor> = OnceLock::new();
    let budgets = Budgets {
        max_module_bytes,
        ..Budgets::default()
    };
    let cell = match (backend, max_module_bytes) {
        (Backend::Native, DEFAULT_MODULE_CEILING) => &NATIVE_DEFAULT,
        (Backend::Pulley, DEFAULT_MODULE_CEILING) => &PULLEY_DEFAULT,
        (Backend::Native, PREINIT_MODULE_CEILING) => &NATIVE_PREINIT,
        (Backend::Pulley, PREINIT_MODULE_CEILING) => &PULLEY_PREINIT,
        _ => panic!("no shared executor for {backend:?} at {max_module_bytes} bytes"),
    };
    cell.get_or_init(|| Executor::new(backend, budgets).expect("the engine configuration is valid"))
}

/// The module ceilings the proof runs under: the operator's default
/// execution ceiling, and the structural admission ceiling a pre-initialized
/// library module is executed under when the operator configures it.
pub const DEFAULT_MODULE_CEILING: usize = 2 * 1024 * 1024;
pub const PREINIT_MODULE_CEILING: usize = 5 * 1024 * 1024;
