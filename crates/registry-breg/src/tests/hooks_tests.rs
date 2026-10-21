// SPDX-License-Identifier: Apache-2.0
//! Base Registry Engine's binding of its compiled local hook programs onto
//! the shared executor. The engines, their budgets, and the canonical answer
//! are tested once in `registry-platform-hooks`; these tests pin what only
//! this crate decides: which programs the running package hands over, under
//! which identity, and that hook programs run on the bare platform engine.

use std::time::Duration;

use registry_platform_hooks::delivery::{HookHandler, HookHandlerBinding};
use registry_platform_hooks::{ErrorCategory, HookHandlerKind};
use serde_json::{json, Value};

use super::local_hook_handlers;
use crate::compiler::{compile_project_with_assets, CompileProfile, WEBHOOK_ATTEMPT_TIMEOUT_MS};
use crate::contract::{parse_project_json, ModuleAssetSource};
use crate::model::CompiledRegistry;

const PACKAGE_REVISION: &str = "hook-binding-tests";
const SCRIPT_PATH: &str = "hooks/case.rhai";
const NONE_ANSWER_SCRIPT: &str = r#"fn handle(ctx) { #{"answer": "none"} }"#;

/// A registry project whose one entity declares one `after` hook bound to the
/// Rhai program at [`SCRIPT_PATH`].
fn project_with_local_hook() -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {"id": "hook-binding", "version": "1", "defaultLanguage": "en",
                     "canonicalBaseIri": "https://hook-binding.example.test"},
        "datasets":[{"id":"test-dataset"}],"recordTypes":[{
            "id": "case",
            "primaryDataset": "test-dataset",
            "route": "cases",
            "mutationMode": "mutable",
            "tombstone": true,
            "classification": "internal",
            "fields": [
                {"id": "label", "type": "string", "maximumLength": 64, "classification": "public"}
            ],
            "hooks": [{
                "id": "case-created",
                "phase": "after",
                "trigger": "created",
                "projection": ["label"],
                "handler": {"type": "rhai", "script": SCRIPT_PATH, "abi": "registry.hook-handler/v1"}
            }]
        }]
    })
}

/// The compiled registry, its one delivery id, and the recorded digest.
fn compile_local_hook(script: &str) -> (CompiledRegistry, String, String) {
    let source = project_with_local_hook();
    let project = parse_project_json(&serde_json::to_vec(&source).expect("project serializes"))
        .expect("project parses");
    let compiled = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: SCRIPT_PATH.to_owned(),
            bytes: script.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .expect("a local hook handler compiles");
    let delivery = &compiled.event_deliveries().deliveries[0];
    let id = delivery.id.clone();
    let digest = delivery
        .handler_digest()
        .expect("a local delivery carries its handler digest")
        .to_owned();
    (compiled, id, digest)
}

fn binding<'a>(
    kind: HookHandlerKind,
    id: &'a str,
    package_revision: &'a str,
    digest: &'a str,
) -> HookHandlerBinding<'a> {
    HookHandlerBinding {
        kind,
        compiled_delivery_id: id,
        package_revision,
        handler_digest: digest,
    }
}

#[test]
fn a_local_delivery_binds_to_its_reviewed_program_under_its_compiled_budget() {
    let (compiled, id, digest) = compile_local_hook(NONE_ANSWER_SCRIPT);
    let handlers = local_hook_handlers(&compiled, PACKAGE_REVISION);
    let handler = handlers
        .handler(binding(
            HookHandlerKind::Rhai,
            &id,
            PACKAGE_REVISION,
            &digest,
        ))
        .expect("the running package holds the bound program");
    assert_eq!(digest, handler.handler_digest());
    assert_eq!(
        Duration::from_millis(u64::from(WEBHOOK_ATTEMPT_TIMEOUT_MS)),
        handler.attempt_timeout()
    );
    let answer = handler
        .run_blocking(br#"{"data":{}}"#, Duration::from_secs(30))
        .expect("the reviewed program runs on the shared executor");
    assert_eq!(br#"{"answer":"none"}"#.as_slice(), answer.as_slice());
}

#[test]
fn a_delivery_naming_another_revision_digest_or_kind_binds_to_nothing() {
    let (compiled, id, digest) = compile_local_hook(NONE_ANSWER_SCRIPT);
    let handlers = local_hook_handlers(&compiled, PACKAGE_REVISION);
    let other_digest = format!("sha256:{}", "0".repeat(64));
    for refused in [
        binding(HookHandlerKind::Rhai, &id, "some-other-revision", &digest),
        binding(HookHandlerKind::Rhai, &id, PACKAGE_REVISION, &other_digest),
        binding(HookHandlerKind::Wasm, &id, PACKAGE_REVISION, &digest),
        binding(
            HookHandlerKind::Rhai,
            "another-delivery",
            PACKAGE_REVISION,
            &digest,
        ),
    ] {
        assert!(handlers.handler(refused).is_none());
    }
}

/// Hook programs run on the bare platform engine: the change-request
/// planner's product helpers, `join` among them, are not registered, so a
/// program that calls one compiles and then fails as an execution error.
#[test]
fn a_hook_program_calling_a_planner_helper_fails_on_the_bare_engine() {
    let (compiled, id, digest) = compile_local_hook(
        r#"fn handle(ctx) { #{"answer": "none", "note": join(["a", "b"], ",")} }"#,
    );
    let handlers = local_hook_handlers(&compiled, PACKAGE_REVISION);
    let handler = handlers
        .handler(binding(
            HookHandlerKind::Rhai,
            &id,
            PACKAGE_REVISION,
            &digest,
        ))
        .expect("the running package holds the bound program");
    assert_eq!(
        Err(ErrorCategory::Execution),
        handler.run_blocking(br#"{"data":{}}"#, Duration::from_secs(30))
    );
}
