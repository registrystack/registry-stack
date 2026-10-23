// SPDX-License-Identifier: Apache-2.0
//! Human summaries of the same compiled documents returned by JSON explain.
use serde_json::Value;

use crate::report::Lines;

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}

fn items(value: &Value) -> impl Iterator<Item = &Value> {
    value.as_array().into_iter().flatten()
}

fn names(value: &Value, key: &str) -> String {
    let names = items(value)
        .filter_map(|item| item.as_str().or_else(|| item[key].as_str()))
        .collect::<Vec<_>>();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

pub(crate) fn mutation_policy(value: &Value, depth: usize, lines: &mut Lines) {
    if let Some(policy) = value.as_object().filter(|policy| !policy.is_empty()) {
        let requirements = policy
            .iter()
            .map(|(operation, mode)| format!("{operation}: {}", text(mode)))
            .collect::<Vec<_>>()
            .join(", ");
        lines.pairs_at(depth, &[("change control", requirements)]);
    }
}

pub(crate) fn render(value: &Value, lines: &mut Lines) -> bool {
    match text(&value["kind"]) {
        "BRegModelExplanation" => model(value, lines),
        "BRegActionsExplanation" | "BRegProposalsExplanation" => actions(&value["actions"], lines),
        "BRegRoutesExplanation" => routes(value, lines),
        "BRegQueriesExplanation" => queries(value, lines),
        "BRegEventsExplanation" => events(value, lines),
        "BRegLifecycleExplanation" => lifecycle(value, lines),
        _ => return false,
    }
    lines.blank();
    lines.prose(1, "Use --format json for the complete compiled definition.");
    true
}

fn model(value: &Value, lines: &mut Lines) {
    lines.heading(&format!("Registry {}:", text(&value["registryId"])));
    for record in items(&value["recordTypes"]) {
        lines.blank();
        lines.item(&format!("record type {}", text(&record["id"])));
        lines.pairs_at(
            2,
            &[
                ("API name", text(&record["apiName"]).into()),
                ("mutation mode", text(&record["mutationMode"]).into()),
                ("classification", text(&record["classification"]).into()),
            ],
        );
        mutation_policy(&record["mutationPolicy"], 2, lines);
        for field in items(&record["fields"]) {
            lines.listed(
                2,
                &format!(
                    "{}: {}, {}",
                    text(&field["id"]),
                    text(&field["classification"]),
                    if field["required"] == true {
                        "required"
                    } else {
                        "optional"
                    }
                ),
            );
        }
        for (id, relation) in record["relationships"].as_object().into_iter().flatten() {
            lines.listed(
                2,
                &format!(
                    "relationship {id}: {} -> {}",
                    text(&relation["sourceRecordType"]),
                    text(&relation["targetRecordType"])
                ),
            );
        }
    }
    lines.pairs(&[
        ("actions", names(&value["actions"], "id")),
        (
            "statistical datasets",
            names(&value["statisticalDatasets"], "id"),
        ),
    ]);
}

pub(crate) fn actions(value: &Value, lines: &mut Lines) {
    lines.heading("Actions:");
    if items(value).next().is_none() {
        lines.bullet("No Actions declared.");
    }
    for action in items(value) {
        lines.blank();
        lines.item(&format!(
            "{} ({})",
            text(&action["id"]),
            text(&action["execution"]["mode"])
        ));
        lines.pairs_at(2, &[("inputs", names(&action["inputs"], "id"))]);
        let plan = &action["plan"];
        if plan["type"] == "function" {
            let function = &plan["function"];
            lines.pairs_at(2, &[("plan function", text(&function["source"]).into())]);
            if let Some(module) = function["sourceModule"].as_str() {
                lines.pairs_at(2, &[("source module", module.into())]);
            }
            for write in items(&function["writes"]) {
                lines.listed(
                    2,
                    &format!(
                        "write ceiling: {} {}, fields {}",
                        text(&write["operation"]),
                        text(&write["targetRecordType"]),
                        names(&write["fields"], "id")
                    ),
                );
            }
        } else {
            for effect in items(&plan["effects"]) {
                lines.listed(
                    2,
                    &format!(
                        "effect {}: {} {}, fields {}",
                        text(&effect["id"]),
                        text(&effect["operation"]),
                        text(&effect["target"]["recordType"]),
                        names(&effect["mutations"], "field")
                    ),
                );
            }
        }
        for guard in items(&action["commitGuards"]) {
            let mut terms = Vec::new();
            if let Some(input) = guard["equalsInput"].as_str() {
                terms.push(format!("equals input {input}"));
            }
            if guard["revisionUnchanged"] == true {
                terms.push("revision unchanged".into());
            }
            for (key, label) in [
                ("equals", "equals"),
                ("atLeast", "at least"),
                ("atMost", "at most"),
                ("currentDate", "current date"),
            ] {
                if let Some(value) = guard.get(key) {
                    terms.push(format!("{label} {value}"));
                }
            }
            lines.listed(
                2,
                &format!(
                    "commit guard {}{}: {}",
                    text(&guard["input"]),
                    guard["field"]
                        .as_str()
                        .map(|f| format!(".{f}"))
                        .unwrap_or_default(),
                    terms.join(", ")
                ),
            );
        }
        action_permissions(&action["permissions"], 2, lines);
        if action["execution"]["mode"] == "proposal" {
            let proposal = &action["execution"]["proposal"];
            let review = &proposal["review"];
            let review_description = if review["type"] == "none" {
                "none".into()
            } else {
                format!(
                    "{}; policy {}{}",
                    text(&review["authority"]),
                    text(&review["policy"]["id"]),
                    if review["policy"]["version"].is_string() {
                        " (exact pin)"
                    } else {
                        " (selected at acceptance)"
                    }
                )
            };
            lines.pairs_at(
                2,
                &[
                    ("review", review_description),
                    ("application", text(&proposal["application"]["mode"]).into()),
                ],
            );
            if proposal
                .get("systemApplyGrant")
                .is_some_and(Value::is_object)
            {
                lines.prose(
                    2,
                    "Restricted built-in executor holds the compiled system apply grant.",
                );
                system_apply_grant(&proposal["systemApplyGrant"], 2, lines);
            }
            proposal_permissions(&proposal["permissions"], &action["inputs"], 2, lines);
        }
    }
}

pub(crate) fn json_list_or(value: &Value, empty: &str) -> String {
    if value.as_array().is_some_and(|values| !values.is_empty()) {
        value.to_string()
    } else {
        empty.to_owned()
    }
}

fn row_restrictions(value: &Value) -> String {
    if value.is_null()
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_str() == Some("unrestricted")
    {
        "unrestricted".to_owned()
    } else {
        value.to_string()
    }
}

fn permission_gates(permission: &Value) -> Vec<(&'static str, String)> {
    let mut gates = vec![
        (
            "actor kind",
            permission["actorKind"]
                .as_str()
                .unwrap_or("not declared")
                .to_owned(),
        ),
        (
            "requester clients",
            json_list_or(&permission["requesterClients"], "any"),
        ),
        (
            "principal claim",
            permission["principalClaim"]
                .as_str()
                .unwrap_or("none")
                .to_owned(),
        ),
        (
            "required scopes (all)",
            json_list_or(&permission["requiredScopes"], "unrestricted"),
        ),
        (
            "allowed purposes (any)",
            json_list_or(&permission["requiredPurposes"], "unrestricted"),
        ),
    ];
    if permission["taskGrant"].is_object() {
        gates.push((
            "task grant source issuer",
            text(&permission["taskGrant"]["sourceIssuer"]).to_owned(),
        ));
        if permission["taskGrant"]["permissions"]
            .as_array()
            .is_some_and(|permissions| !permissions.is_empty())
        {
            let permissions = items(&permission["taskGrant"]["permissions"])
                .map(|grant| {
                    format!(
                        "{}: {}",
                        text(&grant["collection"]),
                        names(&grant["operations"], "id")
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            gates.push(("task grant permissions", permissions));
        }
    } else {
        gates.push(("task grant", "none".to_owned()));
    }
    gates
}

fn action_permissions(value: &Value, depth: usize, lines: &mut Lines) {
    for permission in items(value) {
        lines.listed(
            depth,
            &format!(
                "Action profile {}: {}{}",
                text(&permission["profileId"]),
                names(&permission["operations"], "id"),
                if permission["default"] == true {
                    " (default)"
                } else {
                    ""
                }
            ),
        );
        lines.pairs_at(depth + 1, &permission_gates(permission));
        lines.pairs_at(
            depth + 1,
            &[("results", names(&permission["results"], "id"))],
        );
        for target in items(&permission["targets"]) {
            lines.listed(
                depth + 1,
                &format!(
                    "target {}: {} from {}",
                    text(&target["recordType"]),
                    text(&target["operation"]),
                    target["source"]
                ),
            );
            lines.pairs_at(
                depth + 2,
                &[(
                    "row restrictions (all)",
                    row_restrictions(&target["rowBoundaries"]),
                )],
            );
        }
    }
}

fn proposal_permissions(value: &Value, action_inputs: &Value, depth: usize, lines: &mut Lines) {
    for permission in items(value) {
        lines.listed(
            depth,
            &format!(
                "Proposal profile {}: {}{}",
                text(&permission["profileId"]),
                names(&permission["operations"], "id"),
                if permission["default"] == true {
                    " (default)"
                } else {
                    ""
                }
            ),
        );
        let mut fields = permission_gates(permission);
        fields.extend([
            (
                "ownership",
                permission["ownership"]
                    .as_str()
                    .unwrap_or("unrestricted")
                    .to_owned(),
            ),
            (
                "readable context fields",
                names(&permission["readableContextFields"], "id"),
            ),
            (
                "readable inputs",
                names(&permission["readableInputs"], "id"),
            ),
            (
                "writable inputs",
                if permission.get("writableInputs").is_none()
                    || permission["writableInputs"].is_null()
                {
                    format!("all Action inputs ({})", names(action_inputs, "id"))
                } else {
                    names(&permission["writableInputs"], "id")
                },
            ),
            (
                "readable attachments",
                names(&permission["readableAttachments"], "id"),
            ),
            (
                "writable attachments",
                names(&permission["writableAttachments"], "id"),
            ),
        ]);
        lines.pairs_at(depth + 1, &fields);
        for target in items(&permission["targets"]) {
            lines.listed(
                depth + 1,
                &format!("target {}", text(&target["recordType"])),
            );
            lines.pairs_at(
                depth + 2,
                &[(
                    "row restrictions (all)",
                    row_restrictions(&target["rowBoundaries"]),
                )],
            );
        }
    }
}

fn system_apply_grant(grant: &Value, depth: usize, lines: &mut Lines) {
    lines.item_at(depth, "system apply grant");
    lines.pairs_at(
        depth + 1,
        &[
            ("action", text(&grant["actionId"]).to_owned()),
            ("action revision", text(&grant["actionRevision"]).to_owned()),
            ("grant revision", text(&grant["revision"]).to_owned()),
        ],
    );
    for target in items(&grant["targets"]) {
        lines.listed(
            depth + 1,
            &format!(
                "{} {}",
                text(&target["operation"]),
                text(&target["recordType"])
            ),
        );
        lines.pairs_at(
            depth + 2,
            &[
                ("writable fields", names(&target["fields"], "id")),
                ("readable fields", names(&target["readFields"], "id")),
            ],
        );
    }
}

pub(crate) fn datasets(value: &Value, lines: &mut Lines) {
    if items(value).next().is_none() {
        return;
    }
    lines.heading("Statistical dataset access:");
    for dataset in items(value) {
        lines.item(text(&dataset["dataset"]));
        lines.pairs_at(
            2,
            &[
                ("read live", names(&dataset["readLive"], "id")),
                ("publish", names(&dataset["publish"], "id")),
                ("read releases", names(&dataset["readReleases"], "id")),
            ],
        );
        // Access explanations retain the owning compiled profiles.
        for profile in items(&dataset["accessProfiles"]) {
            lines.pairs_at(
                2,
                &[
                    ("profile", text(&profile["id"]).into()),
                    ("principal claim", text(&profile["principalClaim"]).into()),
                    ("required scopes", names(&profile["requiredScopes"], "id")),
                    (
                        "required purposes",
                        names(&profile["requiredPurposes"], "id"),
                    ),
                ],
            );
        }
    }
}

fn routes(value: &Value, lines: &mut Lines) {
    lines.heading("Routes:");
    for route in items(&value["routes"]) {
        lines.item(&format!(
            "{} {}",
            text(&route["method"]),
            text(&route["path"])
        ));
        lines.pairs_at(
            2,
            &[
                ("operation", text(&route["id"]).into()),
                ("profiles", names(&route["accessProfiles"], "id")),
            ],
        );
        let headers = [
            ("requiresIdempotencyKey", "Idempotency-Key"),
            ("requiresIfMatch", "If-Match"),
        ]
        .into_iter()
        .filter_map(|(key, header)| (route[key] == true).then_some(header))
        .collect::<Vec<_>>();
        if !headers.is_empty() {
            lines.pairs_at(2, &[("required headers", headers.join(", "))]);
        }
    }
}

fn queries(value: &Value, lines: &mut Lines) {
    lines.heading("Queries:");
    if items(&value["operations"]).next().is_none() {
        lines.bullet("No query operations declared.");
    }
    for operation in items(&value["operations"]) {
        lines.item(text(&operation["id"]));
        lines.pairs_at(
            2,
            &[
                ("record type", text(&operation["recordType"]).into()),
                ("profile", text(&operation["profile"]).into()),
                ("readable fields", names(&operation["apiFields"], "field")),
                (
                    "filterable fields",
                    names(&operation["filterable"], "field"),
                ),
                ("sortable fields", names(&operation["sortable"], "field")),
            ],
        );
    }
}

fn events(value: &Value, lines: &mut Lines) {
    lines.heading("Event deliveries:");
    if items(&value["deliveries"]).next().is_none() {
        lines.bullet("No event deliveries declared.");
    }
    for delivery in items(&value["deliveries"]) {
        lines.item(text(&delivery["id"]));
        lines.pairs_at(
            2,
            &[
                ("phase", text(&delivery["phase"]).into()),
                ("handler type", text(&delivery["handlerType"]).into()),
                (
                    "destination",
                    delivery["destinationId"]
                        .as_str()
                        .unwrap_or("local handler")
                        .into(),
                ),
            ],
        );
        if delivery.get("transitions").is_some() {
            lines.pairs_at(2, &[("transitions", names(&delivery["transitions"], "id"))]);
        }
        if delivery["includesRecordValues"] == false {
            lines.prose(2, "Proposal metadata only; no Record values.");
            lines.pairs_at(
                2,
                &[("envelope fields", names(&delivery["envelopeFields"], "id"))],
            );
        } else {
            lines.pairs_at(
                2,
                &[(
                    "projected fields",
                    names(&delivery["projectionFields"], "id"),
                )],
            );
        }
        if let Some(condition) = delivery.get("when").filter(|value| !value.is_null()) {
            lines.pairs_at(2, &[("condition", condition.to_string())]);
        }
    }
}

fn lifecycle(value: &Value, lines: &mut Lines) {
    for lifecycle in items(&value["lifecycles"]) {
        lines.heading(text(&lifecycle["label"]));
        lines.heading("States:");
        for state in items(&lifecycle["states"]) {
            lines.item(text(&state["id"]));
            for turn in items(&state["turns"]) {
                lines.listed(
                    2,
                    &format!("turn {}: {}", text(&turn["turn"]), text(&turn["condition"])),
                );
            }
        }
        lines.heading("Transitions:");
        for transition in items(&lifecycle["transitions"]) {
            lines.item(&format!(
                "{}: {} -> {}",
                text(&transition["event"]),
                text(&transition["from"]),
                text(&transition["to"])
            ));
            lines.prose(2, text(&transition["guard"]));
            if transition["recoveryReasons"]
                .as_array()
                .is_some_and(|reasons| !reasons.is_empty())
            {
                lines.pairs_at(
                    2,
                    &[("recovers", names(&transition["recoveryReasons"], ""))],
                );
            }
        }
        lines.heading("Enforcement:");
        for layer in items(&lifecycle["enforcement"]) {
            lines.item(text(&layer["id"]));
            lines.prose(2, text(&layer["description"]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn permission_gates_quote_literal_identifiers_and_label_empty_lists() {
        for identifiers in [
            json!(["none"]),
            json!(["any"]),
            json!(["unrestricted"]),
            json!(["none", "any", "unrestricted"]),
        ] {
            let expected = identifiers.to_string();
            let literal = permission_gates(&json!({
                "requesterClients": identifiers.clone(),
                "requiredScopes": identifiers.clone(),
                "requiredPurposes": identifiers
            }));
            for label in [
                "requester clients",
                "required scopes (all)",
                "allowed purposes (any)",
            ] {
                assert_eq!(
                    literal.iter().find_map(
                        |(candidate, value)| (*candidate == label).then_some(value.as_str())
                    ),
                    Some(expected.as_str())
                );
            }
        }

        for empty in [
            permission_gates(&json!({
                "requesterClients": [],
                "requiredScopes": [],
                "requiredPurposes": []
            })),
            permission_gates(&json!({})),
        ] {
            for (label, expected) in [
                ("requester clients", "any"),
                ("required scopes (all)", "unrestricted"),
                ("allowed purposes (any)", "unrestricted"),
            ] {
                assert_eq!(
                    empty.iter().find_map(
                        |(candidate, value)| (*candidate == label).then_some(value.as_str())
                    ),
                    Some(expected)
                );
            }
        }
    }

    #[test]
    fn lifecycle_summary_renders_every_possible_turn_and_its_condition() {
        let value = json!({"lifecycles": [registry_breg::lifecycle::proposal_lifecycle()]});
        let mut lines = Lines::new();
        lifecycle(&value, &mut lines);
        let rendered = lines.finish();
        for expected in [
            "States:",
            "draft",
            "turn party: Always while the Proposal is in this state.",
            "submitted",
            "turn official:",
            "turn nobody:",
            "Transitions:",
            "recovers",
            "dependency-outage",
            "lease-expired",
            "Enforcement:",
        ] {
            assert!(
                rendered.contains(expected),
                "missing lifecycle detail {expected}: {rendered}"
            );
        }
    }

    #[test]
    fn event_summary_distinguishes_record_projection_from_proposal_metadata() {
        let schema = registry_breg::proposal_hooks::proposal_event_schema();
        let fields = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>();
        let value = json!({"deliveries":[
            {"id":"record-delivery", "phase":"after", "handlerType":"url", "destinationId":"record-observer",
                "projectionFields":["address-line"]},
            {"id":"proposal-delivery", "phase":"after", "handlerType":"url", "destinationId":"proposal-observer",
                "envelopeFields":fields, "includesRecordValues":false}
        ]});
        let mut lines = Lines::new();
        events(&value, &mut lines);
        let rendered = lines.finish();
        for expected in [
            "handler type",
            "url",
            "projected fields",
            "address-line",
            "Proposal metadata only; no Record values.",
            "envelope fields",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected}: {rendered}"
            );
        }
        for field in fields {
            assert!(rendered.contains(field), "missing envelope field {field}");
        }
    }
}
