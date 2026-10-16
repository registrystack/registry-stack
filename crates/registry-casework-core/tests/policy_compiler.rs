//! Compiler proofs for the one ReviewPolicy model and immutable closure.
use registry_casework_core::*;
use serde_json::{json, Value};

fn project_value() -> Value {
    json!({
        "apiVersion":CASEWORK_API_VERSION,"kind":CASEWORK_KIND,
        "project":{"id":"review-project","version":"1"},
        "accessProfiles":{
            "reviewer":{"role":"staff","principalClaim":"principal","requiredScopes":["casework:review"]},
            "supervisor":{"role":"supervisor","principalClaim":"principal","requiredScopes":["casework:supervise"]},
            "administrator":{"role":"administrator","principalClaim":"principal","requiredScopes":["casework:admin"]},
            "producer":{"role":"requester","principalClaim":"principal","requiredScopes":["casework:request"]}
        },
        "queues":{"reviews":{"label":"Reviews"},"north":{"label":"North reviews"}},
        "teams":{"review-team":{"label":"Review team","serves":["reviews","north"],"memberProfiles":["reviewer"],"supervisorProfiles":["supervisor"]}},
        "clocks":{"decision-due":{"type":"subject","anchor":{"type":"request-accepted"},"after":{"hours":48}}},
        "reviewPolicies":{"notice-review":{
            "version":"1","purpose":"approval","context":{"mode":"submitted"},
            "stages":[{"id":"review","queue":"reviews","decidingProfiles":["reviewer"],"requiredApprovals":2,"excludeInitiator":true}],
            "clocks":["decision-due"],"retention":{"terminalRetentionDays":30,"accountabilityRetentionDays":90},
            "outcomes":{"approved":{"label":"Approve","settlement":"approved","reasonRequired":false,"publicReason":"optional"},"rejected":{"label":"Reject","settlement":"rejected","reasonRequired":true,"publicReason":"required"}},
            "displaySchema":{"type":"object","additionalProperties":false,"required":["title"],"properties":{"title":{"type":"string","maxLength":160},"region":{"type":"string","maxLength":20}}}
        }},
        "trustedProducers":{"notice-service":{"profile":"producer","issuer":"https://issuer.example","subject":"notice-service","trustedInitiatorIssuer":"https://people.example","sourceNamespaces":["notice-source"],"reviewPolicies":["notice-review"],"retention":{"receiptRetentionDays":7}}}
    })
}
fn decode(value: Value) -> CaseworkProject {
    CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap()
}
fn source_value() -> Value {
    let mut value = project_value();
    let digest = ContentDigest::for_bytes(b"contract");
    value["reviewPolicies"]["notice-review"]["context"] = json!({"mode":"current-source","provider":"notice-context","contract":{"id":"notice-context-v1","revision":digest,"schemaDigest":ContentDigest::for_bytes(&registry_platform_canonical_json::canonicalize_json(&value["reviewPolicies"]["notice-review"]["displaySchema"]).unwrap())}});
    value["contextProviders"] = json!({"notice-context":{"capabilities":["human-display","service-status"],"sourceNamespace":"notice-source","deploymentRef":"notice-service","serviceProfiles":{"service-status":"status-reader"}}});
    value
}
/// The template as the one entry of an id-keyed taskTemplates mapping.
fn templates(template: &Value) -> Value {
    let mut body = template.clone();
    let id = body.as_object_mut().unwrap().remove("id").unwrap();
    json!({ id.as_str().unwrap(): body })
}
fn task_template() -> Value {
    json!({"id":"summary","version":"1","label":"Prepare summary","eligibleTeams":["review-team"],"eligibleProfiles":["reviewer"],"source":"notice-source","reviewPolicies":["notice-review"],"agent":{"issuer":"https://agent.example","subject":"summary-agent"},"client":"summary-client","resource":"urn:registry:records","scopes":["records:get"],"purpose":"prepare-summary","bounds":{"type":"breg","permissions":[{"collection":"records","operations":["get"]}]},"subjects":{"region":"region"},"lifetimeSeconds":900})
}
#[test]
fn fixed_review_grants_need_status_without_disclosing_source_claims() {
    let mut value = source_value();
    let mut template = task_template();
    template["subjects"] = json!({});
    value["taskTemplates"] = templates(&template);
    let project = decode(value.clone());
    project.compile_policy("notice-review").unwrap();
    assert_eq!(
        project.required_context_capabilities(&project.review_policies[0]),
        std::collections::BTreeSet::from([
            ReviewContextCapability::HumanDisplay,
            ReviewContextCapability::ServiceStatus,
        ])
    );
    let decoded: TaskTemplate = serde_json::from_value(template.clone()).unwrap();
    assert!(decoded
        .disclosed_subjects(&Default::default())
        .unwrap()
        .is_empty());
    template["reviewPolicies"] = json!([]);
    let legacy: TaskTemplate = serde_json::from_value(template.clone()).unwrap();
    assert!(legacy
        .findings(&project)
        .iter()
        .any(|finding| finding.code == "casework.task-template.subjects-out-of-range"));
    template["reviewPolicies"] = json!(["notice-review"]);
    template["subjects"] = Value::Object(
        (0..32)
            .map(|index| (format!("claim-{index}"), json!("region")))
            .collect(),
    );
    let maximum: TaskTemplate = serde_json::from_value(template.clone()).unwrap();
    assert!(!maximum
        .findings(&project)
        .iter()
        .any(|finding| finding.code == "casework.task-template.subjects-out-of-range"));
    template["subjects"]["claim-32"] = json!("region");
    let oversized: TaskTemplate = serde_json::from_value(template).unwrap();
    assert!(oversized
        .findings(&project)
        .iter()
        .any(|finding| finding.code == "casework.task-template.subjects-out-of-range"));
}
#[test]
fn submitted_context_compiles_without_a_provider_and_pins_clocks_and_authority() {
    let project = decode(project_value());
    let closure = project.compile_policy("notice-review").unwrap();
    assert!(closure.dependencies.context_provider.is_none());
    assert_eq!(closure.dependencies.clocks.len(), 1);
    assert_eq!(closure.dependencies.trusted_producers.len(), 1);
    closure.verify().unwrap();
    let restored: ReviewPolicyClosure =
        serde_json::from_value(serde_json::to_value(&closure).unwrap()).unwrap();
    assert_eq!(restored.binding(), closure.binding());
    restored.verify().unwrap();
    let mut active = project.clone();
    let ClockPolicy::Subject { after, .. } = &mut active.clocks[0] else {
        panic!("elapsed clock")
    };
    *after = ElapsedDuration::Hours(24);
    assert_ne!(
        active
            .compile_policy("notice-review")
            .unwrap()
            .identity
            .digest,
        closure.identity.digest
    );
    closure.verify().unwrap();
    let mut tampered = closure;
    tampered.dependencies.access_profiles[0]
        .required_scopes
        .push("other:review".into());
    assert_eq!(tampered.verify(), Err(ReviewPolicyError::DigestMismatch));
}
#[test]
fn contract_identity_provider_authority_and_routing_are_in_the_digest() {
    let original = decode(source_value())
        .compile_policy("notice-review")
        .unwrap();
    for field in ["id", "revision"] {
        let mut value = source_value();
        value["reviewPolicies"]["notice-review"]["context"]["contract"][field] = if field == "id" {
            json!("changed-contract")
        } else {
            json!(ContentDigest::for_bytes(b"changed"))
        };
        assert_ne!(
            decode(value)
                .compile_policy("notice-review")
                .unwrap()
                .identity
                .digest,
            original.identity.digest
        );
    }
    let mut value = source_value();
    value["contextProviders"]["notice-context"]["serviceProfiles"]["service-status"] =
        json!("other-status-reader");
    assert_ne!(
        decode(value)
            .compile_policy("notice-review")
            .unwrap()
            .identity
            .digest,
        original.identity.digest
    );
}
#[test]
fn only_capabilities_used_by_the_policy_are_required() {
    decode(source_value())
        .compile_policy("notice-review")
        .unwrap();
    for capability in ["human-display", "service-status"] {
        let mut value = source_value();
        value["contextProviders"]["notice-context"]["capabilities"]
            .as_array_mut()
            .unwrap()
            .retain(|item| item != capability);
        assert!(CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut routed = source_value();
    routed["reviewPolicies"]["notice-review"]["routing"] = json!([{"id":"north","because":"Review north notices locally","when":{"fields":{"region":{"equals":"north"}}},"queue":"north"}]);
    assert!(CaseworkProject::from_slice(&serde_json::to_vec(&routed).unwrap()).is_err());
    routed["contextProviders"]["notice-context"]["capabilities"]
        .as_array_mut()
        .unwrap()
        .push(json!("routing-context"));
    routed["contextProviders"]["notice-context"]["serviceProfiles"]["routing-context"] =
        json!("routing-reader");
    let project = decode(routed);
    assert_eq!(project.review_policies[0].routing_fields(), vec!["region"]);
    project.compile_policy("notice-review").unwrap();
    let mut submitted = project_value();
    submitted["reviewPolicies"]["notice-review"]["routing"] = json!([{"id":"north","because":"Review north notices locally","when":{"fields":{"region":{"equals":"north"}}},"queue":"north"}]);
    decode(submitted).compile_policy("notice-review").unwrap();
}
#[test]
fn field_derived_grants_require_their_own_capability() {
    let mut value = source_value();
    value["taskTemplates"] = templates(&task_template());
    let Err(registry_casework_core::ConfigLoadError::Refused(report)) =
        CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap())
    else {
        panic!("subjects need the provider's task-grant-context capability");
    };
    let [finding] = report.diagnostics() else {
        panic!("one finding names the template: {report:?}");
    };
    assert_eq!(finding.code, "casework.task-template.provider-capability");
    assert_eq!(finding.path, "/taskTemplates/summary/subjects");
    assert_eq!(
        finding.message,
        "task template summary declares subjects, which need the task-grant-context \
         capability, and context provider notice-context does not declare it with a service \
         profile"
    );
    assert_eq!(
        finding.suggested_action,
        "Remove `subjects` from task template summary, or bind the template to review \
         policies whose source serves task-grant context."
    );
    value["contextProviders"]["notice-context"]["capabilities"]
        .as_array_mut()
        .unwrap()
        .push(json!("task-grant-context"));
    value["contextProviders"]["notice-context"]["serviceProfiles"]["task-grant-context"] =
        json!("grant-reader");
    let closure = decode(value).compile_policy("notice-review").unwrap();
    assert_eq!(closure.dependencies.task_templates.len(), 1);
    let mut invalid = task_template();
    invalid["itemKinds"] = json!(["request"]);
    assert!(serde_json::from_value::<TaskTemplate>(invalid).is_err());
    let template: TaskTemplate = serde_json::from_value(task_template()).unwrap();
    assert!(template
        .disclosed_subjects(&std::collections::BTreeMap::new())
        .is_err());
}
#[test]
fn local_schema_checks_exact_export_bytes_and_drift_before_compilation() {
    let directory = std::env::temp_dir().join(format!("casework-schema-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let mut value = source_value();
    let bytes =
        serde_json::to_vec_pretty(&value["reviewPolicies"]["notice-review"]["displaySchema"])
            .unwrap();
    value["reviewPolicies"]["notice-review"]["displaySchema"] =
        json!({"$ref":"display.schema.json"});
    value["reviewPolicies"]["notice-review"]["context"]["contract"]["schemaDigest"] =
        json!(ContentDigest::for_bytes(&bytes));
    std::fs::write(directory.join("display.schema.json"), &bytes).unwrap();
    std::fs::write(
        directory.join("casework.yaml"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    let project = CaseworkProject::load(directory.join("casework.yaml")).unwrap();
    project.compile_policy("notice-review").unwrap();
    assert!(project.review_policies[0]
        .display_schema
        .get("$ref")
        .is_none());
    let mut drifted = bytes;
    drifted.push(b'\n');
    std::fs::write(directory.join("display.schema.json"), drifted).unwrap();
    assert!(CaseworkProject::load(directory.join("casework.yaml")).is_err());
    value["reviewPolicies"]["notice-review"]["displaySchema"] = json!({"$ref":"../outside.json"});
    std::fs::write(
        directory.join("casework.yaml"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert!(CaseworkProject::load(directory.join("casework.yaml")).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}
#[test]
fn retired_authoring_shapes_and_invalid_approval_outcomes_are_refused() {
    for key in ["sources", "reviewKinds", "reviewProducers"] {
        let mut value = project_value();
        value[key] = json!([]);
        assert!(CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut value = project_value();
    value["reviewPolicies"]["notice-review"]["outcomes"]["approved"]["reasonRequired"] =
        json!(true);
    assert!(CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = project_value();
    value["reviewPolicies"]["notice-review"]["outcomes"]["approved"]["settlement"] =
        json!("rejected");
    assert!(CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = project_value();
    value["clocks"]["decision-due"]["pauseWhile"] = json!(["awaiting-applicant"]);
    assert!(CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn captured_schema_bytes_are_the_only_compiler_inputs() {
    let mut value = source_value();
    let bytes =
        serde_json::to_vec_pretty(&value["reviewPolicies"]["notice-review"]["displaySchema"])
            .unwrap();
    value["reviewPolicies"]["notice-review"]["displaySchema"] =
        json!({"$ref":"schemas/display.json"});
    value["reviewPolicies"]["notice-review"]["context"]["contract"]["schemaDigest"] =
        json!(ContentDigest::for_bytes(&bytes));
    let document = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        CaseworkProject::schema_references("casework.yaml", &document).unwrap(),
        vec!["schemas/display.json"]
    );
    let captured = std::collections::BTreeMap::from([("schemas/display.json".to_owned(), bytes)]);
    let parsed =
        CaseworkProject::read_with_schemas("/absent/project/casework.yaml", &document, &captured)
            .unwrap();
    parsed.value.compile_policy("notice-review").unwrap();
    assert!(CaseworkProject::read_with_schemas(
        "casework.yaml",
        &document,
        &std::collections::BTreeMap::new()
    )
    .is_err());
    let mut changed = captured;
    changed.get_mut("schemas/display.json").unwrap().push(b'\n');
    assert!(CaseworkProject::read_with_schemas("casework.yaml", &document, &changed).is_err());
}

#[test]
fn grants_refuse_unknown_fields_teams_namespaces_and_nonportable_subjects() {
    for (field, replacement) in [
        ("eligibleTeams", json!(["missing-team"])),
        ("source", json!("other-source")),
        ("subjects", json!({"region":"missing-field"})),
    ] {
        let mut value = project_value();
        let mut template = task_template();
        template[field] = replacement;
        value["taskTemplates"] = templates(&template);
        assert!(CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let template: TaskTemplate = serde_json::from_value(task_template()).unwrap();
    let disclosed = std::collections::BTreeMap::from([(
        "region".into(),
        json!(MAXIMUM_PORTABLE_JSON_INTEGER + 1),
    )]);
    assert!(template.disclosed_subjects(&disclosed).is_err());
    for bounds in [
        json!({"type":"evidence","requirement":"*"}),
        json!({"type":"breg","permissions":[]}),
        json!({"type":"breg","permissions":[{"collection":"records","operations":["get","get"]}]}),
        json!({"type":"scheduling","permissions":[{"service":"service","location":"office","actions":["*"]}]}),
    ] {
        assert!(serde_json::from_value::<TaskGrantBounds>(bounds)
            .unwrap()
            .check()
            .is_err());
    }
}

#[test]
fn decision_and_draft_bounds_are_checked_without_a_runtime() {
    let invalid = DecisionKind::Reject {
        outcome: "rejected".into(),
        reason: Some("x".repeat(MAXIMUM_REVIEW_REASON_BYTES + 1)),
        public_reason: None,
        result: None,
    };
    assert_eq!(
        invalid.check_input().unwrap_err().reason,
        ReviewValidationReason::MaximumBytesExceeded
    );
    let invalid = DecisionKind::Answer {
        outcome: "answered".into(),
        reason: None,
        public_reason: None,
        result: Some(json!(null)),
    };
    assert_eq!(
        invalid.check_input().unwrap_err().reason,
        ReviewValidationReason::ObjectRequired
    );
    let invalid = DecisionKind::Answer {
        outcome: "answered".into(),
        reason: None,
        public_reason: None,
        result: Some(json!({"value":MAXIMUM_PORTABLE_JSON_INTEGER+1})),
    };
    assert_eq!(
        invalid.check_input().unwrap_err().reason,
        ReviewValidationReason::SchemaMismatch
    );
    let draft = ReviewTaskDraftInput {
        body: json!({"text":"x".repeat(MAXIMUM_REVIEW_DRAFT_BYTES)}),
    };
    assert_eq!(
        draft.check().unwrap_err().reason,
        ReviewValidationReason::MaximumBytesExceeded
    );
    let mut nested = json!({});
    for _ in 0..MAXIMUM_REVIEW_VALUE_DEPTH {
        nested = json!({"child":nested});
    }
    assert_eq!(
        ReviewTaskDraftInput { body: nested }
            .check()
            .unwrap_err()
            .reason,
        ReviewValidationReason::MaximumDepthExceeded
    );
    assert!(DecisionKind::Approve {
        outcome: "approved".into(),
        public_reason: None,
    }
    .check_input()
    .is_ok());
    let invalid = DecisionKind::Approve {
        outcome: "approved".into(),
        public_reason: Some("x".repeat(MAXIMUM_PUBLIC_REASON_BYTES + 1)),
    };
    let error = invalid.check_input().unwrap_err();
    assert_eq!(
        (error.path.as_str(), error.reason),
        (
            "$.publicReason",
            ReviewValidationReason::MaximumBytesExceeded
        )
    );
    assert!(ReviewTaskDraftInput {
        body: json!({"note":"private draft"})
    }
    .check()
    .is_ok());
}

#[test]
fn routing_uses_selected_context_fields_and_accepts_native_property_names() {
    let mut value = project_value();
    value["reviewPolicies"]["notice-review"]["displaySchema"]["properties"]["display name"] =
        json!({"type":"string","maxLength":160});
    decode(value.clone());
    value["reviewPolicies"]["notice-review"]["routing"] = json!([{"id":"north","because":"Route by native display name","when":{"fields":{"display name":{"equals":"north"}}},"queue":"north"}]);
    let project = decode(value);
    assert_eq!(
        project.review_policies[0].routing_fields(),
        vec!["display name"]
    );
    project.compile_policy("notice-review").unwrap();
}

#[test]
fn presentation_changes_preserve_behavior_binding_and_closure_keeps_them() {
    let mut original = source_value();
    original["contextProviders"]["notice-context"]["description"] =
        json!("context-providers/original.json");
    let before = decode(original.clone())
        .compile_policy("notice-review")
        .unwrap();
    let mut renamed = original.clone();
    renamed["queues"]["reviews"]["label"] = json!("Decision queue");
    renamed["teams"]["review-team"]["label"] = json!("Decision team");
    renamed["reviewPolicies"]["notice-review"]["outcomes"]["approved"]["label"] = json!("Accept");
    renamed["contextProviders"]["notice-context"]["description"] =
        json!("context-providers/relocated.json");
    let after = decode(renamed.clone())
        .compile_policy("notice-review")
        .unwrap();
    assert_eq!(before.binding(), after.binding());
    assert_ne!(
        serde_json::to_value(&before).unwrap(),
        serde_json::to_value(&after).unwrap()
    );
    after.verify().unwrap();
    assert_eq!(after.outcomes[0].label, "Accept");
    assert_ne!(
        ContentDigest::for_bytes(&serde_json::to_vec(&original).unwrap()),
        ContentDigest::for_bytes(&serde_json::to_vec(&renamed).unwrap())
    );
    renamed["reviewPolicies"]["notice-review"]["stages"][0]["requiredApprovals"] = json!(1);
    assert_ne!(
        decode(renamed)
            .compile_policy("notice-review")
            .unwrap()
            .binding(),
        before.binding()
    );
}

#[test]
fn routing_explanation_and_grant_label_are_presentation_only() {
    let mut value = project_value();
    value["reviewPolicies"]["notice-review"]["routing"] = json!([{"id":"north","because":"Route notices locally","when":{"fields":{"region":{"equals":"north"}}},"queue":"north"}]);
    value["taskTemplates"] = templates(&task_template());
    let before = decode(value.clone())
        .compile_policy("notice-review")
        .unwrap();
    value["reviewPolicies"]["notice-review"]["routing"][0]["because"] =
        json!("Use the north queue");
    value["taskTemplates"]["summary"]["label"] = json!("Create a summary");
    let after = decode(value.clone())
        .compile_policy("notice-review")
        .unwrap();
    assert_eq!(before.binding(), after.binding());
    after.verify().unwrap();
    value["reviewPolicies"]["notice-review"]["routing"][0]["queue"] = json!("reviews");
    assert_ne!(
        before.binding(),
        decode(value)
            .compile_policy("notice-review")
            .unwrap()
            .binding()
    );
}

#[test]
fn clock_step_explanation_is_presentation_and_effect_is_behavior() {
    let mut value = project_value();
    value["calendars"] = json!({"office":{"timezone":"UTC","workingWeekdays":["monday"],"holidaySet":"office-holidays"}});
    value["clocks"] = json!({"decision-due":{"type":"stage","anchor":{"type":"stage-entered"},"calendar":"office","after":{"workingDays":1},"dueTime":"17:00","reminders":{},"steps":[{"id":"overdue","because":"Escalate an overdue review","at":"due","action":{"reassign":{"queue":"north"}}}]}});
    let before = decode(value.clone())
        .compile_policy("notice-review")
        .unwrap();
    value["clocks"]["decision-due"]["steps"][0]["because"] =
        json!("Move overdue reviews to the north queue");
    let after = decode(value.clone())
        .compile_policy("notice-review")
        .unwrap();
    assert_eq!(before.binding(), after.binding());
    assert_ne!(before.dependencies.clocks, after.dependencies.clocks);
    value["clocks"]["decision-due"]["steps"][0]["action"]["reassign"]["queue"] = json!("reviews");
    assert_ne!(
        before.binding(),
        decode(value)
            .compile_policy("notice-review")
            .unwrap()
            .binding()
    );
}

#[test]
fn every_outcome_states_whether_a_public_reason_is_given() {
    let mut value = project_value();
    value["reviewPolicies"]["notice-review"]["outcomes"]["approved"]
        .as_object_mut()
        .unwrap()
        .remove("publicReason");
    assert!(CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = project_value();
    value["reviewPolicies"]["notice-review"]["outcomes"]["approved"]["publicReason"] =
        json!("sometimes");
    assert!(CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    for rule in ["required", "optional", "none"] {
        let mut value = project_value();
        value["reviewPolicies"]["notice-review"]["outcomes"]["approved"]["publicReason"] =
            json!(rule);
        decode(value).compile_policy("notice-review").unwrap();
    }
}

#[test]
fn approval_decisions_name_an_approved_outcome_on_the_wire() {
    // A decision without `outcome` reaches the policy check, which refuses it
    // with the declared outcomes; the input check lets it through.
    let missing: ReviewTaskDecisionRequest =
        serde_json::from_value(json!({"decision":{"type":"approve"}})).unwrap();
    assert_eq!(
        missing.decision,
        DecisionKind::Approve {
            outcome: String::new(),
            public_reason: None,
        }
    );
    assert_eq!(missing.decision.check_input(), Ok(()));
    assert!(serde_json::from_value::<ReviewTaskDecisionRequest>(
        json!({"decision":{"type":"approve","outcome":"approved","reason":"private"}})
    )
    .is_err());
    let decoded: ReviewTaskDecisionRequest = serde_json::from_value(json!({
        "decision":{"type":"approve","outcome":"approved","publicReason":"Your registration is approved."}
    }))
    .unwrap();
    assert_eq!(
        decoded.decision,
        DecisionKind::Approve {
            outcome: "approved".into(),
            public_reason: Some("Your registration is approved.".into()),
        }
    );
    assert_eq!(
        serde_json::to_value(&decoded).unwrap(),
        json!({"decision":{"type":"approve","outcome":"approved","publicReason":"Your registration is approved."}})
    );
}

#[test]
fn a_producer_names_its_review_policies_in_its_findings() {
    let refused = |value: Value| {
        let Err(ConfigLoadError::Refused(report)) =
            CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap())
        else {
            panic!("the project must be refused");
        };
        report
    };
    let mut value = project_value();
    value["trustedProducers"]["notice-service"]["reviewPolicies"] = json!([]);
    assert!(refused(value)
        .diagnostics()
        .iter()
        .any(|item| item.code == "casework.review-producer.no-policies"
            && item.path == "/trustedProducers/notice-service/reviewPolicies"));
    let mut value = project_value();
    value["trustedProducers"]["notice-service"]["reviewPolicies"] =
        json!(["notice-review", "notice-review"]);
    assert!(refused(value)
        .diagnostics()
        .iter()
        .any(|item| item.code == "casework.review-producer.duplicate-policy"));
}

#[test]
fn a_producer_names_its_receipt_retention_in_its_findings() {
    let retention = "/trustedProducers/notice-service/retention/receiptRetentionDays";
    let mut project = CaseworkProject::from_slice(&serde_json::to_vec(&project_value()).unwrap())
        .expect("the fixture project loads");
    // The reader bounds the value first; the model check holds the same bound
    // for a project built in code.
    project.trusted_producers[0]
        .retention
        .receipt_retention_days = 0;
    assert!(project.findings().iter().any(|finding| finding.code
        == "casework.review-producer.receipt-retention-out-of-range"
        && finding.pointer == retention));
    let mut value = project_value();
    value["trustedProducers"]["notice-service"]["retention"]["receiptRetentionDays"] = json!(31);
    let Err(ConfigLoadError::Refused(report)) =
        CaseworkProject::from_slice(&serde_json::to_vec(&value).unwrap())
    else {
        panic!("the project must be refused");
    };
    assert!(report.diagnostics().iter().any(|item| item.code
        == "casework.review-producer.receipt-retention-exceeds-result-retention"
        && item.path == retention));
}
