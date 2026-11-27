// SPDX-License-Identifier: Apache-2.0
//! The BReg facts the development runner reads from `bregctl explain`, the
//! owning tool's published description of a project. The runner never compiles
//! a BReg project itself.

use anyhow::{Context, Result};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path, sync::atomic::AtomicBool};

/// What `bregctl explain access` and `bregctl explain model` report about one
/// project, limited to the members the runner needs.
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct BregFacts {
    /// The principal claims the access profiles select.
    pub principal_claims: BTreeSet<String>,
    pub purpose_required: bool,
    /// Every client the project names: requesters and consent recipients.
    pub named_clients: BTreeSet<String>,
    pub requires_postgis: bool,
    /// Whether any record type declares an encrypted field.
    pub encrypts_fields: bool,
    pub access_profiles: BTreeSet<String>,
    pub actions: BTreeSet<String>,
    pub review_authorities: BTreeSet<String>,
    /// Whether any access profile, action permission or proposal permission
    /// declares a task grant, so the product checks task grants bound to its
    /// own audience.
    pub checks_task_grants: bool,
}

/// The owning tool refused the project. `findings` carries its own diagnostics
/// and `actions` its suggested actions.
#[derive(Debug, thiserror::Error)]
#[error("{findings}")]
pub(super) struct InvalidBregProject {
    pub findings: String,
    pub actions: String,
}

/// Runs `bregctl explain access` and `bregctl explain model` on `project`.
pub(super) fn breg_facts(
    bregctl: &Path,
    project: &Path,
    terminate: &AtomicBool,
) -> Result<BregFacts> {
    let access = explain(bregctl, "access", project, terminate)?;
    let model = explain(bregctl, "model", project, terminate)?;
    facts_from_reports(&access, &model)
}

fn explain(bregctl: &Path, view: &str, project: &Path, terminate: &AtomicBool) -> Result<Value> {
    let (status, report) = super::products::tool_report(
        bregctl,
        "bregctl",
        "explain",
        &[view.as_ref(), project.as_os_str()],
        terminate,
    )?;
    if status.success() && report["ok"] == true {
        return Ok(report);
    }
    Err(InvalidBregProject {
        findings: findings(&report),
        actions: suggested_actions(&report),
    }
    .into())
}

fn diagnostics(report: &Value) -> impl Iterator<Item = &Value> {
    report["diagnostics"].as_array().into_iter().flatten()
}

/// The diagnostics the tool printed, each at its source location when it has
/// one and at its project path when it does not.
fn findings(report: &Value) -> String {
    diagnostics(report)
        .map(|diagnostic| {
            let location = match (
                diagnostic["source"]["file"].as_str(),
                diagnostic["source"]["line"].as_u64(),
                diagnostic["source"]["column"].as_u64(),
            ) {
                (Some(file), Some(line), Some(column)) => format!("{file}:{line}:{column}"),
                (Some(file), Some(line), None) => format!("{file}:{line}"),
                (Some(file), None, _) => file.to_owned(),
                (None, ..) => format!(
                    "registry.yaml {}",
                    diagnostic["path"].as_str().unwrap_or_default()
                ),
            };
            format!(
                "{location}: {}",
                diagnostic["message"]
                    .as_str()
                    .unwrap_or_default()
                    .trim_end_matches('.')
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn suggested_actions(report: &Value) -> String {
    diagnostics(report)
        .filter_map(|diagnostic| diagnostic["suggestedAction"].as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ")
}

fn facts_from_reports(access: &Value, model: &Value) -> Result<BregFacts> {
    let access = &access["explanation"];
    let model = &model["explanation"];
    let contract = &access["claimContract"];
    let mut named_clients = strings(&contract["requesterClients"])
        .context("bregctl explain access did not report claimContract.requesterClients")?;
    // `consent` is null when the project declares no consent.
    for client in access["consent"]["clients"]
        .as_array()
        .into_iter()
        .flatten()
    {
        named_clients.insert(
            client["client"]
                .as_str()
                .context("a bregctl explain access consent client has no client")?
                .to_owned(),
        );
    }
    let encrypts_fields = model["recordTypes"]
        .as_array()
        .context("bregctl explain model did not report recordTypes")?
        .iter()
        .try_fold(false, |found, record| {
            Ok::<_, anyhow::Error>(
                found
                    || record["fields"]
                        .as_array()
                        .context("a bregctl explain model record type has no fields")?
                        .iter()
                        .any(|field| field["encrypted"] == true),
            )
        })?;
    Ok(BregFacts {
        principal_claims: strings(&contract["principalClaims"])
            .context("bregctl explain access did not report claimContract.principalClaims")?,
        purpose_required: contract["purposeRequired"]
            .as_bool()
            .context("bregctl explain access did not report claimContract.purposeRequired")?,
        named_clients,
        requires_postgis: model["requiresPostgis"]
            .as_bool()
            .context("bregctl explain model did not report requiresPostgis")?,
        encrypts_fields,
        access_profiles: ids(model, "accessProfiles")?,
        actions: ids(model, "actions")?,
        review_authorities: ids(model, "reviewAuthorities")?,
        checks_task_grants: declares_task_grant(access),
    })
}

/// Whether the access explanation carries a task grant anywhere: on a record
/// type's access profile, on an action's permission, or on a proposal's
/// permission. The report nests them in different members, so the whole
/// explanation is searched for a `taskGrant` object.
fn declares_task_grant(value: &Value) -> bool {
    match value {
        Value::Object(members) => members.iter().any(|(key, member)| {
            (key == "taskGrant" && member.is_object()) || declares_task_grant(member)
        }),
        Value::Array(items) => items.iter().any(declares_task_grant),
        _ => false,
    }
}

fn strings(value: &Value) -> Option<BTreeSet<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

fn ids(model: &Value, member: &str) -> Result<BTreeSet<String>> {
    model[member]
        .as_array()
        .with_context(|| format!("bregctl explain model did not report {member}"))?
        .iter()
        .map(|entry| {
            entry["id"]
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("a bregctl explain model {member} entry has no ID"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    /// The members of `bregctl explain access` and `explain model` the runner
    /// reads, as the tool prints them for the reviewed-evidence acceptance
    /// project (other members elided).
    fn reports() -> (Value, Value) {
        let access = json!({
            "ok": true, "command": "explain", "status": "complete",
            "explanation": {
                "claimContract": {
                    "directClaims": {}, "principalClaims": ["registry_principal"],
                    "purposeRequired": true,
                    "requesterClients": ["applier", "context-status", "staff"]
                },
                "consent": {"clients": [{"client": "recipient", "other": 1}]}
            }
        });
        let model = json!({
            "ok": true, "command": "explain", "status": "complete",
            "explanation": {
                "requiresPostgis": true,
                "accessProfiles": [{"id": "operator"}, {"id": "reviewer"}],
                "actions": [{"id": "correct-status"}],
                "reviewAuthorities": [{"id": "casework"}],
                "recordTypes": [
                    {"id": "plain", "fields": [{"id": "code", "encrypted": false}]},
                    {"id": "secret", "fields": [
                        {"id": "a", "encrypted": false}, {"id": "b", "encrypted": true}
                    ]}
                ]
            }
        });
        (access, model)
    }

    #[test]
    fn facts_come_from_the_published_explain_members() {
        let (access, model) = reports();
        assert_eq!(
            facts_from_reports(&access, &model).unwrap(),
            BregFacts {
                principal_claims: set(&["registry_principal"]),
                purpose_required: true,
                named_clients: set(&["applier", "context-status", "recipient", "staff"]),
                requires_postgis: true,
                encrypts_fields: true,
                access_profiles: set(&["operator", "reviewer"]),
                actions: set(&["correct-status"]),
                review_authorities: set(&["casework"]),
                checks_task_grants: false,
            }
        );
    }

    /// The access report with `grant` set as `taskGrant` at `place`, a JSON
    /// pointer into the explanation, over members that declare none.
    fn access_with_task_grant_at(place: &str) -> Value {
        let (mut access, _) = reports();
        access["explanation"]["recordTypes"] = json!([
            {"recordType": "plain", "profiles": [{"id": "operator", "taskGrant": null}]}
        ]);
        access["explanation"]["actions"] = json!({"actions": [{
            "id": "act",
            "permissions": [{"profileId": "operator", "taskGrant": null}],
            "execution": {"mode": "proposal", "proposal": {
                "permissions": [{"profileId": "operator", "taskGrant": null}]
            }}
        }]});
        *access["explanation"]
            .pointer_mut(place)
            .expect("the fixture has the place") =
            json!({"sourceIssuer": "https://casework.example"});
        access
    }

    /// The shape `bregctl explain access` prints for a project whose only task
    /// grant is on a profile that grants an action: the record types list no
    /// profiles and the grant sits on the action's permission.
    #[test]
    fn an_action_only_task_grant_is_reported() {
        let (mut access, model) = reports();
        access["explanation"]["recordTypes"] = json!([
            {"recordType": "household", "profiles": []},
            {"recordType": "person", "profiles": []}
        ]);
        access["explanation"]["actions"] = json!({"actions": [{
            "id": "register-household-contact",
            "permissions": [
                {"profileId": "contact-auditor", "taskGrant": null},
                {"profileId": "contact-registrar",
                 "taskGrant": {"sourceIssuer": "https://casework.example"}}
            ]
        }]});
        assert!(
            facts_from_reports(&access, &model)
                .unwrap()
                .checks_task_grants
        );
    }

    #[test]
    fn a_task_grant_is_reported_wherever_the_access_report_carries_one() {
        let (_, model) = reports();
        let none = {
            let (mut access, _) = reports();
            access["explanation"]["recordTypes"] = json!([{"profiles": [{"id": "operator"}]}]);
            access
        };
        assert!(
            !facts_from_reports(&none, &model)
                .unwrap()
                .checks_task_grants
        );
        for place in [
            "/recordTypes/0/profiles/0/taskGrant",
            "/actions/actions/0/permissions/0/taskGrant",
            "/actions/actions/0/execution/proposal/permissions/0/taskGrant",
        ] {
            let access = access_with_task_grant_at(place);
            assert!(
                facts_from_reports(&access, &model)
                    .unwrap()
                    .checks_task_grants,
                "{place}"
            );
        }
        // A null member declares none.
        let mut access = access_with_task_grant_at("/recordTypes/0/profiles/0/taskGrant");
        access["explanation"]["recordTypes"][0]["profiles"][0]["taskGrant"] = Value::Null;
        assert!(
            !facts_from_reports(&access, &model)
                .unwrap()
                .checks_task_grants
        );
    }

    #[test]
    fn absent_consent_and_plain_fields_report_no_extra_clients_or_encryption() {
        let (mut access, mut model) = reports();
        access["explanation"]["consent"] = Value::Null;
        model["explanation"]["recordTypes"] = json!([{"fields": [{"encrypted": false}]}]);
        let facts = facts_from_reports(&access, &model).unwrap();
        assert_eq!(
            facts.named_clients,
            set(&["applier", "context-status", "staff"])
        );
        assert!(!facts.encrypts_fields);
    }

    #[test]
    fn a_missing_member_is_an_error_naming_it() {
        let (access, mut model) = reports();
        model["explanation"]
            .as_object_mut()
            .unwrap()
            .remove("requiresPostgis");
        let error = facts_from_reports(&access, &model).unwrap_err().to_string();
        assert!(error.contains("requiresPostgis"), "{error}");
    }

    #[test]
    fn findings_use_the_tools_own_locations_and_messages() {
        let report = json!({"ok": false, "diagnostics": [
            {"message": "no closing bracket.", "path": "/a", "suggestedAction": "Fix it.",
             "source": {"file": "/p/registry.yaml", "line": 3, "column": 1}},
            {"message": "bad path", "path": "/b", "suggestedAction": "Fix it."}
        ]});
        assert_eq!(
            findings(&report),
            "/p/registry.yaml:3:1: no closing bracket; registry.yaml /b: bad path"
        );
        assert_eq!(suggested_actions(&report), "Fix it.");
    }
}
