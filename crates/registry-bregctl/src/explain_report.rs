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
        permissions(&action["permissions"], 2, lines);
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
            }
            permissions(&proposal["permissions"], 2, lines);
        }
    }
}

fn permissions(value: &Value, depth: usize, lines: &mut Lines) {
    for permission in items(value) {
        lines.listed(
            depth,
            &format!(
                "profile {}: {}{}",
                text(&permission["profileId"]),
                names(&permission["operations"], "id"),
                if permission["default"] == true {
                    " (default)"
                } else {
                    ""
                }
            ),
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
