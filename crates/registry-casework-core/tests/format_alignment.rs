//! The D18 format alignment: every renamed spelling reads, every old one is
//! refused with a fix that names its row in the format table of the Casework
//! CHANGELOG, and an identifier-keyed map is a configuration shape only.
use registry_casework_core::*;
use serde_json::json;

const EXAMPLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../products/casework/examples/multi-stage-routing-clocks/casework.yaml"
));

fn read(text: &str) -> Result<CaseworkProject, Vec<registry_platform_yaml::Diagnostic>> {
    CaseworkProject::read("casework.yaml", text.as_bytes())
        .map(|decoded| decoded.value)
        .map_err(|report| report.diagnostics().to_vec())
}

fn replaced(from: &str, to: &str) -> String {
    assert!(EXAMPLE.contains(from), "the example holds {from:?}");
    EXAMPLE.replacen(from, to, 1)
}

/// The old spelling is refused at `path`, and the fix names `replacement`
/// and the row of the format table that records it.
fn assert_refused(text: &str, path: &str, replacement: &str, row: &str) {
    let diagnostics = read(text).expect_err("the old spelling is refused");
    let row = format!("row {row} of the format table in the Casework CHANGELOG");
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.path == path
            && diagnostic.suggested_action.contains(replacement)
            && diagnostic.suggested_action.contains(&row)),
        "no diagnostic at {path} names {replacement:?} and {row:?}: {diagnostics:#?}"
    );
}

#[test]
fn the_aligned_example_reads_and_lists_named_items_in_id_order() {
    let project = read(EXAMPLE).expect("the aligned example reads");
    let ids = |items: Vec<&str>| items.join(",");
    assert_eq!(
        ids(project
            .queues
            .iter()
            .map(|queue| queue.id.as_str())
            .collect()),
        "northern-review,overdue-review,signoff,triage"
    );
    assert_eq!(
        ids(project.clocks.iter().map(ClockPolicy::id).collect()),
        "response-budget,review-deadline"
    );
    let ClockPolicy::Subject { after, .. } = &project.clocks[0] else {
        panic!("subject clock")
    };
    assert_eq!(after.seconds(), 48 * 60 * 60);
    assert_eq!(
        project.trusted_producers[0]
            .retention
            .receipt_retention_days,
        7
    );
    assert_eq!(
        project.review_policies[0].retention.terminal_retention_days,
        30
    );
}

#[test]
fn the_served_policy_takes_the_renamed_keys_and_lists_named_items_by_id() {
    let project = read(EXAMPLE).unwrap();
    let closure = project.compile_policy("regional-review").unwrap();
    let served = serde_json::to_value(&closure).unwrap();
    let policy = &served;
    assert_eq!(
        policy["retention"],
        json!({"terminalRetentionDays": 30, "accountabilityRetentionDays": 365})
    );
    let outcomes = policy["outcomes"].as_array().expect("outcomes are a list");
    assert_eq!(outcomes[0]["id"], "approved");
    assert_eq!(outcomes[1]["id"], "rejected");
    assert!(policy["routing"][0]["when"].get("activity").is_none());
    let clocks = served["dependencies"]["clocks"].as_array().unwrap();
    assert_eq!(clocks[0]["id"], "response-budget");
    assert_eq!(clocks[0]["anchor"], json!({"type": "request-accepted"}));
    assert_eq!(clocks[0]["after"], json!({"hours": 48}));
    assert!(clocks[0].get("completeOn").is_none());
    assert_eq!(clocks[1]["type"], "stage");
    assert_eq!(clocks[1]["anchor"], json!({"type": "stage-entered"}));
    assert_eq!(clocks[1]["atRisk"], json!({"before": {"workingDays": 1}}));
    assert_eq!(
        clocks[1]["reminders"],
        json!([{"id": "due-soon", "before": {"workingDays": 1}}])
    );
    let producers = served["dependencies"]["trustedProducers"]
        .as_array()
        .unwrap();
    assert_eq!(
        producers[0]["retention"],
        json!({"receiptRetentionDays": 7})
    );
    assert!(producers[0].get("recoveryDays").is_none());

    let restored: ReviewPolicyClosure = serde_json::from_value(served).unwrap();
    restored.verify().unwrap();
}

#[test]
fn reordering_a_named_map_changes_neither_the_served_policy_nor_its_digest() {
    let reordered = EXAMPLE
        .replacen(
            "      approved: {label: Approve, settlement: approved, reasonRequired: false, publicReason: optional}\n      rejected: {label: Return for correction, settlement: rejected, reasonRequired: true, publicReason: required}\n",
            "      rejected: {label: Return for correction, settlement: rejected, reasonRequired: true, publicReason: required}\n      approved: {label: Approve, settlement: approved, reasonRequired: false, publicReason: optional}\n",
            1,
        )
        .replacen(
            "  triage: {label: Regional triage}\n  northern-review: {label: Northern reviews}\n",
            "  northern-review: {label: Northern reviews}\n  triage: {label: Regional triage}\n",
            1,
        );
    assert_ne!(reordered, EXAMPLE);
    let original = read(EXAMPLE)
        .unwrap()
        .compile_policy("regional-review")
        .unwrap();
    let moved = read(&reordered)
        .unwrap()
        .compile_policy("regional-review")
        .unwrap();
    assert_eq!(moved.identity.digest, original.identity.digest);
    assert_eq!(
        serde_json::to_value(&moved).unwrap(),
        serde_json::to_value(&original).unwrap()
    );
}

/// A project with two review policies, two context providers and two task
/// templates, each map written in the order `order` gives.
fn two_of_each(order: [usize; 2]) -> String {
    let display = json!({"type":"object","additionalProperties":false,"required":["title"],"properties":{"title":{"type":"string","maxLength":160}}});
    let schema_digest = serde_json::to_string(&ContentDigest::for_bytes(
        &registry_platform_canonical_json::canonicalize_json(&display).unwrap(),
    ))
    .unwrap();
    let revision = serde_json::to_string(&ContentDigest::for_bytes(b"contract")).unwrap();
    let ordered = |entries: [String; 2]| format!("{}{}", entries[order[0]], entries[order[1]]);
    let policy = |id: &str| {
        format!(
            "  {id}:\n    version: \"1\"\n    purpose: approval\n    context: {{mode: current-source, provider: {id}-context, contract: {{id: {id}-context-v1, revision: {revision}, schemaDigest: {schema_digest}}}}}\n    stages: [{{id: review, queue: reviews, decidingProfiles: [reviewer], requiredApprovals: 1}}]\n    retention: {{terminalRetentionDays: 30, accountabilityRetentionDays: 90}}\n    outcomes: {{approved: {{label: Approve, settlement: approved, reasonRequired: false, publicReason: optional}}, rejected: {{label: Reject, settlement: rejected, reasonRequired: true, publicReason: required}}}}\n    displaySchema: {display}\n"
        )
    };
    let provider = |id: &str| {
        format!(
            "  {id}-context: {{capabilities: [human-display, service-status], sourceNamespace: notice-source, deploymentRef: notice-service, serviceProfiles: {{service-status: status-reader}}}}\n"
        )
    };
    let template = |id: &str| {
        format!(
            "  {id}-summary: {{version: \"1\", label: Prepare summary, eligibleTeams: [review-team], eligibleProfiles: [reviewer], source: notice-source, reviewPolicies: [alpha, beta], agent: {{issuer: \"https://agent.example\", subject: {id}-agent}}, client: {id}-client, resource: \"urn:registry:records\", scopes: [\"records:get\"], purpose: prepare-summary, bounds: {{type: breg, permissions: [{{collection: records, operations: [get]}}]}}, subjects: {{}}, lifetimeSeconds: 900}}\n"
        )
    };
    format!(
        "apiVersion: {CASEWORK_API_VERSION}\nkind: {CASEWORK_KIND}\nproject: {{id: review-project, version: \"1\"}}\n\
         accessProfiles:\n  reviewer: {{role: staff, principalClaim: principal, requiredScopes: [\"casework:review\"]}}\n  supervisor: {{role: supervisor, principalClaim: principal, requiredScopes: [\"casework:supervise\"]}}\n  administrator: {{role: administrator, principalClaim: principal, requiredScopes: [\"casework:admin\"]}}\n  producer: {{role: requester, principalClaim: principal, requiredScopes: [\"casework:request\"]}}\n\
         queues: {{reviews: {{label: Reviews}}}}\n\
         teams: {{review-team: {{label: Review team, serves: [reviews], memberProfiles: [reviewer], supervisorProfiles: [supervisor]}}}}\n\
         contextProviders:\n{}\
         reviewPolicies:\n{}\
         taskTemplates:\n{}\
         trustedProducers:\n  notice-service: {{profile: producer, issuer: \"https://issuer.example\", subject: notice-service, trustedInitiatorIssuer: \"https://people.example\", sourceNamespaces: [notice-source], reviewPolicies: [alpha, beta], retention: {{receiptRetentionDays: 7}}}}\n",
        ordered([provider("alpha"), provider("beta")]),
        ordered([policy("alpha"), policy("beta")]),
        ordered([template("alpha"), template("beta")]),
    )
}

#[test]
fn reordering_review_policies_context_providers_and_task_templates_changes_no_served_policy() {
    let forward = read(&two_of_each([0, 1])).expect("the forward project reads");
    let reversed = read(&two_of_each([1, 0])).expect("the reversed project reads");
    for project in [&forward, &reversed] {
        let ids = |items: Vec<&str>| items.join(",");
        assert_eq!(
            ids(project
                .review_policies
                .iter()
                .map(|p| p.id.as_str())
                .collect()),
            "alpha,beta"
        );
        assert_eq!(
            ids(project
                .context_providers
                .iter()
                .map(|p| p.id.as_str())
                .collect()),
            "alpha-context,beta-context"
        );
        assert_eq!(
            ids(project
                .task_templates
                .iter()
                .map(|t| t.id.as_str())
                .collect()),
            "alpha-summary,beta-summary"
        );
    }
    for policy in ["alpha", "beta"] {
        let before = forward.compile_policy(policy).unwrap();
        let after = reversed.compile_policy(policy).unwrap();
        assert_eq!(before.dependencies.task_templates.len(), 2);
        assert_eq!(after.identity.digest, before.identity.digest);
        assert_eq!(
            serde_json::to_value(&after).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
    }
}

#[test]
fn an_elapsed_budget_names_exactly_one_unit() {
    for (after, seconds) in [
        ("{minutes: 90}", 90 * 60),
        ("{hours: 48}", 48 * 60 * 60),
        ("{days: 2}", 2 * 24 * 60 * 60),
    ] {
        let project = read(&replaced("after: {hours: 48}", &format!("after: {after}"))).unwrap();
        let ClockPolicy::Subject { after, .. } = &project.clocks[0] else {
            panic!("subject clock")
        };
        assert_eq!(after.seconds(), seconds);
    }
    for after in ["{hours: 48, minutes: 30}", "{hours: 0}", "{}"] {
        assert!(
            read(&replaced("after: {hours: 48}", &format!("after: {after}"))).is_err(),
            "{after} is refused"
        );
    }
}

#[test]
fn every_old_spelling_is_refused_with_its_replacement_and_table_row() {
    assert_refused(
        &replaced("after: {hours: 48}", "after: {elapsed: PT48H}"),
        "/clocks/response-budget/after/elapsed",
        "after: {hours: 48}",
        "F1",
    );
    assert_refused(
        &replaced("terminalRetentionDays: 30", "terminalDays: 30"),
        "/reviewPolicies/regional-review/retention/terminalDays",
        "terminalRetentionDays",
        "F2",
    );
    assert_refused(
        &replaced(
            "accountabilityRetentionDays: 365",
            "accountabilityDays: 365",
        ),
        "/reviewPolicies/regional-review/retention/accountabilityDays",
        "accountabilityRetentionDays",
        "F2",
    );
    assert_refused(
        &replaced("retention: {receiptRetentionDays: 7}", "recoveryDays: 7"),
        "/trustedProducers/regional-service/recoveryDays",
        "retention: {receiptRetentionDays:",
        "F3",
    );
    assert_refused(
        &replaced(
            "queues:\n  triage: {label: Regional triage}\n  northern-review: {label: Northern reviews}\n  overdue-review: {label: Overdue reviews}\n  signoff: {label: Supervisor signoff}\n",
            "queues:\n  - {id: triage, label: Regional triage}\n  - {id: northern-review, label: Northern reviews}\n  - {id: overdue-review, label: Overdue reviews}\n  - {id: signoff, label: Supervisor signoff}\n",
        ),
        "/queues/0/id",
        "queues: {QUEUE_ID: {",
        "F4",
    );
    assert_refused(
        &replaced(
            "      approved: {label: Approve,",
            "      approved: {id: approved, label: Approve,",
        ),
        "/reviewPolicies/regional-review/outcomes/approved/id",
        "outcomes: {OUTCOME_ID: {",
        "F4",
    );
    assert_refused(
        &replaced(
            "reviewPolicies:\n  regional-review:\n",
            "reviewPolicies:\n  - id: regional-review\n",
        ),
        "/reviewPolicies/0/id",
        "reviewPolicies: {POLICY_ID: {",
        "F4",
    );
    assert_refused(
        &format!(
            "{EXAMPLE}contextProviders:\n  - {{id: regional-context, deploymentRef: regional}}\n"
        ),
        "/contextProviders/0/id",
        "contextProviders: {PROVIDER_ID: {",
        "F4",
    );
    assert_refused(
        &format!("{EXAMPLE}taskTemplates:\n  - {{id: regional-summary, version: \"1\"}}\n"),
        "/taskTemplates/0/id",
        "taskTemplates: {TEMPLATE_ID: {",
        "F4",
    );
    assert_refused(
        &replaced("    type: stage\n", "    type: activity\n"),
        "/clocks/review-deadline/type",
        "type: stage",
        "F5",
    );
    assert_refused(
        &replaced("anchor: {type: stage-entered}", "anchor: stage-entered-at"),
        "/clocks/review-deadline/anchor",
        "anchor: {type: stage-entered}",
        "F6",
    );
    assert_refused(
        &replaced(
            "anchor: {type: request-accepted}",
            "anchor: request-accepted-at",
        ),
        "/clocks/response-budget/anchor",
        "anchor: {type: request-accepted}",
        "F6",
    );
    assert_refused(
        &replaced(
            "    after: {hours: 48}\n",
            "    after: {hours: 48}\n    completeOn: result-terminal\n",
        ),
        "/clocks/response-budget/completeOn",
        "Remove completeOn",
        "F7",
    );
    assert_refused(
        &replaced(
            "atRisk: {before: {workingDays: 1}}",
            "atRisk: {workingDaysBefore: 1}",
        ),
        "/clocks/review-deadline/atRisk/workingDaysBefore",
        "atRisk: {before: {workingDays:",
        "F8",
    );
    assert_refused(
        &replaced(
            "due-soon: {before: {workingDays: 1}}",
            "due-soon: {workingDaysBefore: 1}",
        ),
        "/clocks/review-deadline/reminders/due-soon/workingDaysBefore",
        "{before: {workingDays:",
        "F8",
    );
    assert_refused(
        &replaced(
            "        when:\n          stage: technical\n",
            "        when:\n          activity: review\n          stage: technical\n",
        ),
        "/reviewPolicies/regional-review/routing/0/when/activity",
        "Remove activity",
        "F9",
    );
}

#[test]
fn a_receipt_window_is_at_most_a_year() {
    let refused = read(&replaced(
        "retention: {receiptRetentionDays: 7}",
        "retention: {receiptRetentionDays: 366}",
    ))
    .expect_err("a receipt window over 365 days is refused");
    assert!(refused.iter().any(|diagnostic| diagnostic.path
        == "/trustedProducers/regional-service/retention/receiptRetentionDays"));
}
