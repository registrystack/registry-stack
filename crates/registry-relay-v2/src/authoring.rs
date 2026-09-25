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
        RelayRuntime, RELAY_RUNTIME_API_VERSION, RELAY_RUNTIME_KIND,
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
        Err(error) => {
            return CompileReport {
                diagnostics: vec![error.diagnostic()],
            };
        }
    };

    let runtime = match runtime_yaml {
        Some(yaml) => match RelayRuntime::parse_yaml(yaml) {
            Ok(runtime) => Some(runtime),
            Err(refusal) => {
                return CompileReport {
                    diagnostics: vec![diagnostic(
                        "runtime.yaml_invalid",
                        &runtime_location(refusal.field()),
                        refusal.message(),
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
    if runtime.api_version != RELAY_RUNTIME_API_VERSION || runtime.kind != RELAY_RUNTIME_KIND {
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
    if contract_has_protected_access(contract) && runtime.authentication.oidc.is_none() {
        diagnostics.push(diagnostic(
            "runtime.issuer_missing",
            "runtime.yaml.authentication.oidc",
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

/// The diagnostic location of a refused runtime field: `runtime.yaml` for the
/// whole document, otherwise `runtime.yaml.<field>`.
pub(crate) fn runtime_location(field: &str) -> String {
    match field {
        "" | "/" => "runtime.yaml".to_owned(),
        field => format!("runtime.yaml.{field}"),
    }
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
        let runtime = r#"apiVersion: registry.registrystack.org/relay-runtime/v1alpha1
kind: RelayRuntimeConfig
listener: {bind: '127.0.0.1:18080'}
package: {root: /srv/relay/package}
secretProviders: {environment: {}}
sources: {other: {path: fixture.sqlite}}
audit: {path: var/audit.jsonl}
limits: {requestTimeoutMilliseconds: 1000, concurrentQueries: 1}
"#;
        let report = check_project_documents(valid_contract(), Some(runtime), &governed_files());
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "runtime.source_binding_mismatch"));
    }

    #[test]
    fn a_refused_runtime_reports_the_field_and_its_replacement() {
        let runtime = "apiVersion: registry.registrystack.org/relay-runtime/v1alpha1\nkind: RelayRuntimeConfig\nserver: {bind: '127.0.0.1:18080'}\n";
        let report = check_project_documents(valid_contract(), Some(runtime), &governed_files());
        let [diagnostic] = report.diagnostics.as_slice() else {
            panic!("one refusal expected: {:?}", report.diagnostics);
        };
        assert_eq!(diagnostic.code, "runtime.yaml_invalid");
        assert_eq!(diagnostic.location, "runtime.yaml.server");
        assert!(
            diagnostic.message.contains("listener.bind"),
            "{diagnostic:?}"
        );

        let secret_env = "apiVersion: registry.registrystack.org/relay-runtime/v1alpha1\nkind: RelayRuntimeConfig\nlistener: {bind: '127.0.0.1:18080'}\npackage: {root: /srv/relay/package}\nsecretProviders: {file: {root: /run/secrets/relay}}\nsources: {db: {path: fixture.sqlite}}\naudit: {path: var/audit.jsonl}\ncursor: {integrityKeyRef: secret:env/KEY, maximumAgeSeconds: 300}\nlimits: {requestTimeoutMilliseconds: 1000, concurrentQueries: 1}\n";
        let report = check_project_documents(valid_contract(), Some(secret_env), &governed_files());
        assert_eq!(
            report.diagnostics[0].location,
            "runtime.yaml.cursor.integrityKeyRef"
        );
    }
}
