// SPDX-License-Identifier: Apache-2.0
use crate::{access::AccessConfig, CoordinatorError, Result};
use registry_thunderid_tooling::identity_facts::{
    self, AccessProfile, Admission, ClaimType, IdentityFacts,
};
use std::{collections::BTreeMap, fs::OpenOptions, io::Write, path::Path};

pub(super) fn write(
    access: &AccessConfig,
    issuer: Option<&str>,
    runtime: &Path,
    output: &Path,
) -> Result<()> {
    let entry = match issuer {
        Some(wanted) => access
            .issuers
            .iter()
            .find(|(id, _)| id.as_str() == wanted)
            .map(|(_, entry)| entry)
            .ok_or_else(|| {
                CoordinatorError::new(
                    "identity.facts.unknown-issuer",
                    "--issuer names no configured issuer entry",
                )
                .suggest("Name an entry under deployment.authentication.issuers.")
            })?,
        None if access.issuers.len() == 1 => access
            .issuers
            .iter()
            .next()
            .map(|(_, entry)| entry)
            .ok_or_else(|| {
            CoordinatorError::new("access.configuration", "an issuer entry is required")
        })?,
        None => {
            return Err(CoordinatorError::new(
                "identity.facts.issuer-required",
                "the facts describe one configured issuer",
            )
            .suggest("Pass --issuer with the id of the entry to describe."));
        }
    };
    let clients = access.clients_for(entry);
    let core = &entry.core;
    let mut facts = IdentityFacts::new(
        "coordinator",
        core.provider.issuer.as_str(),
        &core.provider.audience,
        Admission::Clients(clients.clone()),
    );
    let scope_claim = core.scope_claim.get().as_str();
    if scope_claim != "scope" {
        facts
            .claims
            .insert(scope_claim.to_owned(), ClaimType::StringArray);
    }
    for (client, policy) in access
        .policies
        .iter()
        .filter(|(client, _)| clients.contains(client))
    {
        let selected_by = if scope_claim == "scope" {
            BTreeMap::new()
        } else {
            BTreeMap::from([(scope_claim.to_owned(), policy.required_scopes.clone())])
        };
        facts.access_profiles.push(AccessProfile {
            id: client.clone(),
            requester_clients: Some(vec![client.clone()]),
            scopes: policy.required_scopes.clone(),
            purposes: Vec::new(),
            exchange: None,
            selected_by,
            actor_kind: None,
            required_claims: Vec::new(),
            admitted_actor_kinds: Vec::new(),
            refused_claims: Vec::new(),
        });
    }
    let invalid = || {
        CoordinatorError::new(
            "access.configuration",
            "the issuer entry does not yield valid identity facts",
        )
        .suggest("Check the issuer entry and its policy client identifiers and scopes.")
    };
    let yaml = facts.to_yaml().map_err(|_| invalid())?;
    identity_facts::read("identity-facts", yaml.as_bytes()).map_err(|error| {
        let Some(report) = error.report() else {
            return CoordinatorError::new("access.configuration", error.to_string())
                .suggest("Check the issuer entry and its policy client identifiers and scopes.");
        };
        let mut diagnostics = report.diagnostics().to_vec();
        for diagnostic in &mut diagnostics {
            let profile = diagnostic
                .path
                .strip_prefix("/accessProfiles/")
                .and_then(|path| path.split('/').next())
                .and_then(|index| index.parse::<usize>().ok())
                .and_then(|index| facts.access_profiles.get(index));
            if let Some(profile) = profile {
                diagnostic.related.push(registry_platform_yaml::Related {
                    file: runtime.display().to_string(),
                    line: None,
                    column: None,
                    path: format!(
                        "/deployment/authentication/policies/{}",
                        registry_platform_yaml::escape_pointer_segment(&profile.id)
                    ),
                    message: "the policy used to generate this access profile".into(),
                });
            }
        }
        CoordinatorError::from_diagnostics(&diagnostics)
    })?;
    let unavailable = |error: std::io::Error| {
        CoordinatorError::new(
            "output-unavailable",
            format!(
                "the output file could not be created or written ({})",
                error.kind()
            ),
        )
        .at(output, "")
        .suggest("Name a writable path that does not exist with --output.")
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(unavailable)?;
    file.write_all(yaml.as_bytes()).map_err(unavailable)
}
