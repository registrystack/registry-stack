// SPDX-License-Identifier: Apache-2.0
//! Pure Relay V2 authoring checks shared by adopter tooling and editors.
//!
//! This module accepts complete document bytes already held by its caller. It
//! opens no file, database, socket, or process, which lets `relayctl check` and
//! an editor ask the same compiler about saved files or unsaved buffers.

use std::collections::BTreeSet;

use crate::{
    compiler::{compile_contract_with_governed_files, GovernedFileSet},
    contract::{
        contract_has_protected_access, runtime_cursor_configuration_is_valid, RegistryContract,
        RelayRuntime,
    },
    model::{CompileProfile, CompileReport, Diagnostic, DiagnosticSeverity},
};

/// Run the complete source-independent authoring check over documents already
/// read by the caller.
///
/// Source schema observation is deliberately absent. Authoring compilation
/// validates the governed shape and complete governed-file closure without
/// opening the deployment's SQLite sources. Production source observation
/// remains with `relayctl check --production` and package activation.
#[must_use]
pub fn check_project_documents(
    registry_yaml: &str,
    runtime_yaml: Option<&str>,
    governed_files: &GovernedFileSet,
) -> CompileReport {
    let contract = match RegistryContract::parse_yaml(registry_yaml) {
        Ok(contract) => contract,
        Err(_) => {
            return CompileReport {
                diagnostics: vec![diagnostic(
                    "contract.yaml_invalid",
                    "registry.yaml",
                    "the governed contract is not valid strict YAML",
                )],
            };
        }
    };

    let runtime = match runtime_yaml {
        Some(yaml) => match RelayRuntime::parse_yaml(yaml) {
            Ok(runtime) => Some(runtime),
            Err(_) => {
                return CompileReport {
                    diagnostics: vec![diagnostic(
                        "runtime.yaml_invalid",
                        "runtime.yaml",
                        "the deployment binding is not valid strict YAML",
                    )],
                };
            }
        },
        None => None,
    };

    let mut diagnostics = validate_runtime(&contract, runtime.as_ref());
    if let Err(mut report) = compile_contract_with_governed_files(
        &contract,
        &[],
        CompileProfile::Authoring,
        governed_files,
    ) {
        diagnostics.append(&mut report.diagnostics);
    }
    diagnostics.sort_by(|left, right| {
        left.location
            .cmp(&right.location)
            .then(left.code.cmp(&right.code))
            .then(left.message.cmp(&right.message))
    });
    diagnostics.dedup();
    CompileReport { diagnostics }
}

pub(crate) fn validate_runtime(
    contract: &RegistryContract,
    runtime: Option<&RelayRuntime>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let Some(runtime) = runtime else {
        return diagnostics;
    };
    if runtime.api_version != "relay.registrystack.org/v2alpha1" || runtime.kind != "RelayRuntime" {
        diagnostics.push(diagnostic(
            "runtime.identity_invalid",
            "runtime.yaml",
            "the deployment document identity is unsupported",
        ));
    }
    let governed = contract.sources.keys().collect::<BTreeSet<_>>();
    let bound = runtime.sources.keys().collect::<BTreeSet<_>>();
    if governed != bound {
        diagnostics.push(diagnostic(
            "runtime.source_binding_mismatch",
            "runtime.yaml.sources",
            "runtime sources must bind exactly the governed source identifiers",
        ));
    }
    if !runtime_cursor_configuration_is_valid(contract, runtime) {
        diagnostics.push(diagnostic(
            "runtime.cursor_missing",
            "runtime.yaml.cursor",
            "a Registry with a paginated data or resource-metadata list requires an opaque-cursor key and age bound",
        ));
    }
    if contract_has_protected_access(contract) && runtime.authentication.issuer.is_none() {
        diagnostics.push(diagnostic(
            "runtime.issuer_missing",
            "runtime.yaml.authentication.issuer",
            "a Registry with protected operations requires one configured issuer",
        ));
    }
    let has_lookup = contract
        .resources
        .iter()
        .any(|resource| !resource.operations.lookups.is_empty());
    if has_lookup && runtime.quotas.is_none() {
        diagnostics.push(diagnostic(
            "runtime.lookup_quota_missing",
            "runtime.yaml.quotas",
            "a Registry with an exact lookup requires a bounded operation quota",
        ));
    }
    diagnostics
}

fn diagnostic(code: &str, location: &str, message: &str) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Error,
        code: code.into(),
        location: location.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::tests::{governed_files, valid_contract};

    #[test]
    fn authoring_check_uses_the_shared_compiler_without_source_observation() {
        let report = check_project_documents(valid_contract(), None, &governed_files());
        assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    }

    #[test]
    fn runtime_source_bindings_are_checked_from_in_memory_documents() {
        let runtime = r#"apiVersion: relay.registrystack.org/v2alpha1
kind: RelayRuntime
server: {bind: '127.0.0.1:18080'}
packagePath: package
sources: {other: {path: fixture.sqlite}}
authentication: {issuer: null}
audit: {sink: var/audit.jsonl, integrityKeyRef: secret:env/KEY}
limits: {requestTimeoutMilliseconds: 1000, concurrentQueries: 1}
"#;
        let report = check_project_documents(valid_contract(), Some(runtime), &governed_files());
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "runtime.source_binding_mismatch"));
    }
}
