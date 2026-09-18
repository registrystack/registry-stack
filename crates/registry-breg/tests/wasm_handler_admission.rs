// SPDX-License-Identifier: Apache-2.0

//! WASM action-handler admission through the compiler and the package.
//!
//! These tests run only under the `wasm-executor-prototype` feature, the only
//! build whose compiler can structurally validate guest modules: a WASM
//! handler module is admitted (read once, size-checked, hashed, structurally
//! validated against the platform ABI, captured into the compiled handler and
//! the package closure) or refused with a typed diagnostic naming the
//! violation. Execution stays refused everywhere; these tests never run a
//! guest.

use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{
    parse_project_json, ModuleAssetSource, ACTION_HANDLER_ABI_V1, ACTION_HANDLER_ABI_V2,
};
use registry_breg::model::CompiledActionHandlerKind;
use registry_breg::wasm_handler::{MAXIMUM_WASM_MODULE_BYTES, MAX_PACKAGE_WASM_MODULES};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// A minimal module satisfying the guest byte ABI: zero imports, the exact
/// export set with wasm32 signatures.
const MINIMAL_ABI_WAT: &str = r#"
    (module
      (memory (export "memory") 1)
      (func (export "alloc") (param i32) (result i32) i32.const 0)
      (func (export "handle") (param i32 i32) (result i32) i32.const 0)
      (func (export "result_ptr") (result i32) i32.const 0)
      (func (export "result_len") (result i32) i32.const 0)
    )
"#;

fn binary(wat_text: &str) -> Vec<u8> {
    wat::parse_str(wat_text).expect("the wat fixture assembles")
}

/// Unsigned LEB128 encoding, for hand-built section headers.
fn leb128(mut value: usize) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            encoded.push(byte);
            return encoded;
        }
        encoded.push(byte | 0x80);
    }
}

/// A structurally valid module padded to exactly `target_len` bytes: the
/// minimal ABI module plus one trailing custom section, which every
/// conforming consumer ignores. This is the shape of an oversized
/// pre-initialized module: real ABI, real payload, bytes past the default.
fn module_padded_to(target_len: usize) -> Vec<u8> {
    let mut bytes = binary(MINIMAL_ABI_WAT);
    assert!(
        target_len > bytes.len() + 4,
        "the target leaves room for the custom section"
    );
    // Section id 0x00, a one-byte name, then zero padding. The header length
    // depends on the payload length and vice versa, so resolve them together.
    for header_len in 1..=5 {
        let payload_len = target_len - bytes.len() - 1 - header_len;
        if leb128(payload_len).len() == header_len {
            bytes.push(0x00);
            bytes.extend(leb128(payload_len));
            bytes.extend(leb128(1));
            bytes.push(b'p');
            bytes.resize(target_len, 0);
            return bytes;
        }
    }
    panic!("no LEB128 header length fits {target_len}");
}

fn sha256(bytes: &[u8]) -> String {
    let value = Sha256::digest(bytes);
    let mut rendered = String::from("sha256:");
    for byte in value {
        use std::fmt::Write as _;

        write!(&mut rendered, "{byte:02x}").expect("digest writes");
    }
    rendered
}

fn wasm_project() -> Value {
    serde_json::from_str(
        r#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"wasm-admission","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable",
            "fields":[
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"}
            ]
          }],
          "actions":[{
            "id":"register-person",
            "inputs":[
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"}
            ],
            "handler":{
              "kind":"wasm","module":"wasm/handler.wasm","abi":"registry.action-handler/v1",
              "writes":[{
                "id":"person","target":{"entity":"person"},"operation":"create",
                "fields":["person-code","legal-name"]
              }]
            }
          }],
          "accessProfiles":[{
            "id":"registrar","default":true,"principalClaim":"registry_principal",
            "permissions":[{
              "action":"register-person","operations":["invoke"],
              "targets":[{"entity":"person","rowBoundaries":[]}],
              "results":["person"]
            }]
          }]
        }"#,
    )
    .expect("the wasm admission project shape parses")
}

fn compile_with_module(
    project: Value,
    module_path: &str,
    bytes: Vec<u8>,
) -> Result<registry_breg::CompiledRegistry, registry_breg::CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(&project).unwrap()).unwrap();
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: module_path.to_owned(),
            bytes,
        }],
        CompileProfile::Authoring,
    )
}

fn compiled_handler(
    registry: &registry_breg::CompiledRegistry,
) -> registry_breg::model::CompiledActionHandler {
    registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-person")
        .expect("the action compiled")
        .handler
        .clone()
        .expect("the action declares a handler")
}

fn first_code(
    failure: &registry_breg::CompileFailure,
    code: &str,
) -> registry_breg::diagnostics::Diagnostic {
    failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == code)
        .unwrap_or_else(|| {
            panic!(
                "expected diagnostic {code}, got {:?}",
                failure
                    .diagnostics()
                    .iter()
                    .map(|diagnostic| diagnostic.code.as_str())
                    .collect::<Vec<_>>()
            )
        })
        .clone()
}

#[test]
fn a_minimal_abi_module_compiles_into_the_handler_inventory() {
    let bytes = binary(MINIMAL_ABI_WAT);
    let registry = compile_with_module(wasm_project(), "wasm/handler.wasm", bytes.clone())
        .expect("a minimal ABI module is admitted");
    let handler = compiled_handler(&registry);
    assert_eq!(handler.kind, CompiledActionHandlerKind::Wasm);
    assert_eq!(handler.abi, ACTION_HANDLER_ABI_V1);
    assert_eq!(handler.module_path, "wasm/handler.wasm");
    assert_eq!(handler.module_bytes, bytes);
    assert_eq!(
        handler.module_sha256.as_deref(),
        Some(sha256(&bytes).as_str())
    );
    // The Rhai-shaped members carry nothing for a WASM handler: limit units
    // are not silently reinterpreted across backends.
    assert_eq!(handler.script_path, "");
    assert!(handler.script_bytes.is_empty());
    assert_eq!(handler.script_sha256, None);
    assert_eq!(handler.rhai_version, None);
    assert_eq!(handler.limits, None);
    assert!(handler.writes.iter().any(|write| write.id == "person"));

    // The wire form carries the hash and never the bytes, mirroring how Rhai
    // script bytes travel: serde-skipped in memory, hashed on the wire.
    let rendered = serde_json::to_value(&handler).unwrap();
    assert_eq!(rendered["kind"], "wasm");
    assert_eq!(rendered["moduleSha256"], sha256(&bytes).as_str());
    assert!(rendered.get("scriptSha256").is_none());
    assert!(rendered.get("rhaiVersion").is_none());
    assert!(rendered.get("limits").is_none());
    assert!(rendered.get("moduleBytes").is_none());
}

#[test]
fn a_missing_module_asset_reports_the_authored_path() {
    // The module is declared but its asset is never supplied to the compiler.
    let project = parse_project_json(&serde_json::to_vec(&wasm_project()).unwrap()).unwrap();
    let failure = compile_project_with_assets(&project, &[], &[], CompileProfile::Authoring)
        .map(|_| ())
        .expect_err("a declared module without its asset is refused");
    let diagnostic = first_code(&failure, "action.handler.module_asset_missing");
    assert_eq!(diagnostic.path, "actions[register-person].handler.module");
    assert!(
        diagnostic.message.contains("wasm/handler.wasm"),
        "the diagnostic names the authored path: {}",
        diagnostic.message
    );
}

#[test]
fn a_module_over_the_structural_ceiling_is_refused_before_validation() {
    let over_budget = vec![0u8; MAXIMUM_WASM_MODULE_BYTES + 1];
    let failure = compile_with_module(wasm_project(), "wasm/handler.wasm", over_budget)
        .map(|_| ())
        .expect_err("a module beyond the structural ceiling is refused");
    let diagnostic = first_code(&failure, "action.handler.module_bound");
    assert_eq!(diagnostic.path, "actions[register-person].handler.module");
    // The refusal names the structural ceiling: the ceiling every build and
    // package enforces, not an operator's execution-time configuration.
    assert_eq!(MAXIMUM_WASM_MODULE_BYTES, 5 * 1024 * 1024);
    assert!(
        diagnostic
            .message
            .contains(&MAXIMUM_WASM_MODULE_BYTES.to_string()),
        "the diagnostic names the ceiling: {}",
        diagnostic.message
    );
}

#[test]
fn a_module_between_the_default_and_structural_ceilings_is_admitted() {
    // Structurally valid, past the 2 MiB execution default, under the 5 MiB
    // structural ceiling: authoring admission is structural, so such a module
    // compiles, and an operator whose deployment raises the configured
    // ceiling can execute it.
    let bytes = module_padded_to(2 * 1024 * 1024 + 64 * 1024);
    assert_eq!(MAXIMUM_WASM_MODULE_BYTES, 5 * 1024 * 1024);
    compile_with_module(wasm_project(), "wasm/handler.wasm", bytes)
        .expect("a module under the structural ceiling is admitted");
}

#[test]
fn wat_text_is_not_admitted_as_a_module_binary() {
    let failure = compile_with_module(
        wasm_project(),
        "wasm/handler.wasm",
        MINIMAL_ABI_WAT.as_bytes().to_vec(),
    )
    .map(|_| ())
    .expect_err("WebAssembly text is not a module binary");
    let diagnostic = first_code(&failure, "action.handler.module_invalid");
    assert_eq!(diagnostic.path, "actions[register-person].handler.module");
}

#[test]
fn a_module_with_a_disallowed_import_is_refused_by_name() {
    let wat = r#"
        (module
          (import "env" "log" (func $log (param i32)))
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) i32.const 0)
          (func (export "handle") (param i32 i32) (result i32) i32.const 0)
          (func (export "result_ptr") (result i32) i32.const 0)
          (func (export "result_len") (result i32) i32.const 0)
        )
    "#;
    let failure = compile_with_module(wasm_project(), "wasm/handler.wasm", binary(wat))
        .map(|_| ())
        .expect_err("a module with an import is refused");
    let diagnostic = first_code(&failure, "action.handler.module_import_unsupported");
    assert_eq!(diagnostic.path, "actions[register-person].handler.module");
    assert!(
        diagnostic.message.contains("\"env\"") && diagnostic.message.contains("\"log\""),
        "the diagnostic names the disallowed import: {}",
        diagnostic.message
    );
}

#[test]
fn a_module_missing_a_required_export_is_refused_by_name() {
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) i32.const 0)
          (func (export "handle") (param i32 i32) (result i32) i32.const 0)
          (func (export "result_ptr") (result i32) i32.const 0)
        )
    "#;
    let failure = compile_with_module(wasm_project(), "wasm/handler.wasm", binary(wat))
        .map(|_| ())
        .expect_err("a module missing result_len is refused");
    let diagnostic = first_code(&failure, "action.handler.module_export_missing");
    assert_eq!(diagnostic.path, "actions[register-person].handler.module");
    assert!(
        diagnostic.message.contains("result_len"),
        "the diagnostic names the missing export: {}",
        diagnostic.message
    );
}

#[test]
fn a_module_with_an_unexpected_export_is_refused_by_name() {
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) i32.const 0)
          (func (export "handle") (param i32 i32) (result i32) i32.const 0)
          (func (export "result_ptr") (result i32) i32.const 0)
          (func (export "result_len") (result i32) i32.const 0)
          (func (export "helper"))
        )
    "#;
    let failure = compile_with_module(wasm_project(), "wasm/handler.wasm", binary(wat))
        .map(|_| ())
        .expect_err("a module with an extra export is refused");
    let diagnostic = first_code(&failure, "action.handler.module_export_unexpected");
    assert!(
        diagnostic.message.contains("helper"),
        "the diagnostic names the unexpected export: {}",
        diagnostic.message
    );
}

#[test]
fn a_module_with_a_wrong_export_signature_is_refused_by_name() {
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) i32.const 0)
          (func (export "handle") (result i32) i32.const 0)
          (func (export "result_ptr") (result i32) i32.const 0)
          (func (export "result_len") (result i32) i32.const 0)
        )
    "#;
    let failure = compile_with_module(wasm_project(), "wasm/handler.wasm", binary(wat))
        .map(|_| ())
        .expect_err("a wrong-signature handle export is refused");
    let diagnostic = first_code(&failure, "action.handler.module_export_type");
    assert!(
        diagnostic.message.contains("handle"),
        "the diagnostic names the mistyped export: {}",
        diagnostic.message
    );
}

#[test]
fn wasm_handler_field_discipline_is_reported_per_backend() {
    // A WASM handler declares its module, never a script.
    let mut with_script = wasm_project();
    with_script["actions"][0]["handler"]["script"] = json!("scripts/handler.rhai");
    let project = parse_project_json(&serde_json::to_vec(&with_script).unwrap()).unwrap();
    let failure = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "wasm/handler.wasm".to_owned(),
            bytes: binary(MINIMAL_ABI_WAT),
        }],
        CompileProfile::Authoring,
    )
    .map(|_| ())
    .expect_err("a WASM handler cannot declare a Rhai script");
    let diagnostic = first_code(&failure, "action.handler.script_forbidden");
    assert_eq!(diagnostic.path, "actions[register-person].handler.script");

    // A non-.wasm module path never reaches the asset lookup.
    let mut bad_path = wasm_project();
    bad_path["actions"][0]["handler"]["module"] = json!("wasm/handler.txt");
    let failure = compile_with_module(bad_path, "wasm/handler.wasm", binary(MINIMAL_ABI_WAT))
        .map(|_| ())
        .expect_err("a non-wasm module path is refused");
    let diagnostic = first_code(&failure, "action.handler.module_source_invalid");
    assert_eq!(diagnostic.path, "actions[register-person].handler.module");
}

#[test]
fn the_v2_abi_stays_refused_for_wasm_handlers_under_the_feature() {
    let mut project = wasm_project();
    project["actions"][0]["handler"]["abi"] = json!(ACTION_HANDLER_ABI_V2);
    let failure = compile_with_module(project, "wasm/handler.wasm", binary(MINIMAL_ABI_WAT))
        .map(|_| ())
        .expect_err("the Evidence-enabled v2 ABI stays out of scope for WASM");
    let diagnostic = first_code(&failure, "action.handler.wasm_abi_unsupported");
    assert_eq!(diagnostic.path, "actions[register-person].handler.kind");
}

#[test]
fn the_per_package_wasm_module_count_is_bounded() {
    let mut project = wasm_project();
    let mut actions = Vec::new();
    let mut permissions = Vec::new();
    for index in 0..=MAX_PACKAGE_WASM_MODULES {
        // Zero-padded so the compiler's lexicographic action order matches the
        // numeric order: the ceiling is hit by the 17th action.
        let id = format!("register-person-{index:02}");
        actions.push(json!({
            "id": id,
            "inputs":[
              {"id":"person-code","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","type":"string","maxLength":160,"required":true,"classification":"restricted"}
            ],
            "handler":{
              "kind":"wasm","module":"wasm/handler.wasm","abi":"registry.action-handler/v1",
              "writes":[{"id":"person","target":{"entity":"person"},"operation":"create","fields":["person-code","legal-name"]}]
            }
        }));
        permissions.push(json!({
            "action": id, "operations":["invoke"],
            "targets":[{"entity":"person","rowBoundaries":[]}],
            "results":["person"]
        }));
    }
    project["actions"] = Value::Array(actions);
    project["accessProfiles"][0]["permissions"] = Value::Array(permissions);
    let failure = compile_with_module(project, "wasm/handler.wasm", binary(MINIMAL_ABI_WAT))
        .map(|_| ())
        .expect_err("a package beyond the module-count ceiling is refused");
    let diagnostic = first_code(&failure, "action.handler.modules_bound");
    assert_eq!(
        diagnostic.path,
        "actions[register-person-16].handler.module"
    );
}

/// The package closure test needs the package module, which the runtime
/// feature owns; the admission tests above stay independent of it.
#[cfg(feature = "runtime")]
mod package_closure {
    use super::*;
    use registry_breg::package::{
        inspect_package_integrity, prepare_package_with_project_assets, PackageBuildRequest,
        PackageError, PackageMigrationPlanInput, PackageSourceFile, PreparedPackage,
        SignaturePolicy,
    };

    /// Build and prepare the wasm admission project as a package carrying
    /// `bytes` as its single handler module. The compiler admission inside
    /// `prepare_package_with_project_assets` refuses over-ceiling modules, so
    /// an oversized build fails here exactly as a real package build would.
    fn build_wasm_package(bytes: Vec<u8>) -> Result<PreparedPackage, PackageError> {
        let mut project = wasm_project();
        project["package"] = json!({
            "environment": "local",
            "instanceId": "wasm-admission",
            "sequence": 1,
            "sourceRevision": "wasm-admission-1"
        });
        let project_bytes = serde_json::to_vec(&project).unwrap();
        let request = PackageBuildRequest {
            environment: "local".to_owned(),
            instance_id: "wasm-admission".to_owned(),
            database_id: "wasm-admission".to_owned(),
            sequence: 1,
            prior_revision: None,
            compiler_source_revision: "wasm-admission-1".to_owned(),
            schema_fingerprint: sha256(&project_bytes),
            signature_policy: SignaturePolicy {
                threshold: 0,
                key_ids: vec![],
            },
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: project_bytes,
            },
            modules: vec![],
            fixture_journeys: PackageSourceFile {
                path: "tests/journeys.yaml".to_owned(),
                bytes: b"journeys: []\n".to_vec(),
            },
            migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        };
        prepare_package_with_project_assets(
            request,
            vec![PackageSourceFile {
                path: "wasm/handler.wasm".to_owned(),
                bytes,
            }],
        )
    }

    #[test]
    fn a_wasm_handler_module_travels_through_the_package_closure() {
        let bytes = binary(MINIMAL_ABI_WAT);
        let package = build_wasm_package(bytes.clone()).expect("the wasm handler package builds");
        let files = package.file_bytes();
        let module_file = files
            .get("source/project/wasm/handler.wasm")
            .expect("the module bytes are a package source file");
        assert_eq!(module_file, &bytes);
        let manifest = serde_json::to_value(package.manifest()).unwrap();
        let entry = manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["path"] == "source/project/wasm/handler.wasm")
            .expect("the module file is in the integrity manifest");
        assert_eq!(entry["sha256"], sha256(&bytes));
        assert_eq!(entry["size"], bytes.len());

        // The candidate-package path rederives the compiled handler from the
        // captured bytes and verifies every artifact byte-for-byte.
        let base = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let published = base.path().join("published");
        package
            .publish_to_directory(&published, vec![])
            .expect("the wasm handler package publishes");
        let inspected = inspect_package_integrity(&published)
            .expect("the wasm handler package verifies through rederivation");
        let handler = inspected
            .registry()
            .actions()
            .actions
            .iter()
            .find(|action| action.id == "register-person")
            .expect("the wasm action rederives")
            .handler
            .as_ref()
            .expect("the wasm handler rederives");
        assert_eq!(handler.kind, CompiledActionHandlerKind::Wasm);
        assert_eq!(handler.module_bytes, bytes);
        assert_eq!(
            handler.module_sha256.as_deref(),
            Some(sha256(&bytes).as_str())
        );
    }

    #[test]
    fn a_module_between_the_default_and_structural_ceilings_packages() {
        // The package closure enforces the same structural ceiling the
        // compiler does: a module past the 2 MiB execution default but under
        // the structural ceiling packages byte-for-byte.
        let bytes = module_padded_to(2 * 1024 * 1024 + 64 * 1024);
        let package =
            build_wasm_package(bytes.clone()).expect("the oversized module package builds");
        assert_eq!(
            package.file_bytes().get("source/project/wasm/handler.wasm"),
            Some(&bytes)
        );
    }

    #[test]
    fn a_module_over_the_structural_ceiling_is_refused_at_package_validation() {
        let error = build_wasm_package(vec![0u8; MAXIMUM_WASM_MODULE_BYTES + 1])
            .expect_err("a module beyond the structural ceiling never packages");
        assert_eq!(error, PackageError::Derivation);
    }
}
