// SPDX-License-Identifier: Apache-2.0
//! First-class Proposal operations derived from the compiled Action policies.
use super::*;
use crate::model::{CompiledActionExecution, ProposalOperation};
use crate::problem::ProblemCode;

pub(crate) fn append_proposal_openapi(
    paths: &mut Map<String, Value>,
    actions: &CompiledActionInventory,
    entities: &BTreeMap<String, CompiledEntity>,
    visible: Option<&BTreeSet<(String, String, ProposalOperation)>>,
) -> Result<(), Diagnostic> {
    let additions_enabled = actions.actions.iter().any(|action| {
        matches!(&action.execution,
        CompiledActionExecution::Proposal { proposal } if proposal.additions.is_some())
    });
    let mut permissions: BTreeMap<ProposalOperation, (BTreeSet<String>, Vec<Value>)> =
        BTreeMap::new();
    // A manual application writes as the applier, so the apply operation may
    // be refused when a profile it describes may apply a Proposal whose plan
    // can be refused as that profile.
    let mut apply_may_refuse_write = false;
    // Every record slot is write-once, so applying a Proposal that promotes
    // a file can meet a slot an earlier write already filled.
    let mut apply_may_fill_written_slot = false;
    let mut submit_problems = BTreeSet::new();
    let mut submit_refusals = BTreeMap::new();
    let mut submit_attachment_examples = BTreeMap::new();
    let mut apply_problems = BTreeSet::new();
    for action in &actions.actions {
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            continue;
        };
        for grant in &proposal.permissions {
            let permitted = |operation: ProposalOperation| {
                grant.operations.contains(&operation)
                    && visible.is_none_or(|keys| {
                        keys.contains(&(action.id.clone(), grant.profile_id.clone(), operation))
                    })
            };
            for operation in &grant.operations {
                if matches!(
                    operation,
                    ProposalOperation::GetApplicationActor
                        | ProposalOperation::Add
                        | ProposalOperation::Answer
                ) {
                    continue;
                }
                if !permitted(*operation) {
                    continue;
                }
                let (profiles, inputs) = permissions.entry(*operation).or_default();
                profiles.insert(grant.profile_id.clone());
                if matches!(
                    operation,
                    ProposalOperation::Edit | ProposalOperation::Revise | ProposalOperation::Rebase
                ) {
                    let input = openapi_action_input_schema(action);
                    if !inputs.contains(&input) {
                        inputs.push(input);
                    }
                }
            }
            apply_may_refuse_write |= permitted(ProposalOperation::Apply)
                && action_may_refuse_write(action, entities, &grant.profile_id);
            apply_may_fill_written_slot |=
                permitted(ProposalOperation::Apply) && !proposal.promotions.is_empty();
            let field_guard = action.requires.iter().any(|guard| !guard.field.is_empty());
            if permitted(ProposalOperation::Apply) {
                if field_guard {
                    apply_problems.insert(ProblemCode::ActionGuardFailed);
                }
                if matches!(
                    proposal.review,
                    crate::model::CompiledProposalReview::Required { .. }
                ) {
                    apply_problems.insert(ProblemCode::ProposalReviewResultMismatch);
                }
                if !action.evidence.is_empty() || !action.commit_evidence.is_empty() {
                    apply_problems.insert(ProblemCode::ActionEvidenceFailed);
                }
                if action
                    .target_uses
                    .iter()
                    .filter(|target| {
                        matches!(target.operation, Operation::Create | Operation::Patch)
                    })
                    .any(|target| {
                        entities.get(&target.entity_id).is_some_and(|entity| {
                            target.fields.iter().any(|field| {
                                entity
                                    .fields
                                    .get(field)
                                    .is_some_and(|field| field.encryption.is_some())
                            })
                        })
                    })
                {
                    apply_problems.insert(ProblemCode::RuntimeFieldEncryptionUnavailable);
                }
            }
            if permitted(ProposalOperation::Submit) {
                for (slot, definition) in &proposal.attachments {
                    submit_attachment_examples
                        .entry(ProblemCode::AttachmentVerificationPending)
                        .or_insert_with(|| slot.clone());
                    let code = if definition.required {
                        ProblemCode::AttachmentRequired
                    } else {
                        ProblemCode::AttachmentVerificationRejected
                    };
                    submit_attachment_examples
                        .entry(code)
                        .or_insert_with(|| slot.clone());
                }
                if field_guard {
                    submit_problems.insert(ProblemCode::ActionGuardFailed);
                }
                if !proposal.attachments.is_empty() {
                    submit_problems.insert(ProblemCode::AttachmentVerificationPending);
                }
                if proposal.attachments.values().any(|slot| !slot.required) {
                    submit_problems.insert(ProblemCode::AttachmentVerificationRejected);
                }

                if proposal.attachments.values().any(|slot| slot.required) {
                    submit_problems.insert(ProblemCode::AttachmentRequired);
                }
                if let Some(handler) = &action.handler {
                    submit_problems.insert(ProblemCode::ActionHandlerFailed);
                    if !handler.refusals.is_empty() {
                        submit_problems.insert(ProblemCode::ActionRefused);
                        submit_refusals.extend(handler.refusals.clone());
                    }
                }
            }
            let document_fields = proposal
                .review_context
                .as_ref()
                .into_iter()
                .flat_map(|context| context.fields.iter())
                .filter_map(|(field, source)| match source {
                    crate::contract::ProposalContextValueSource::Document { slot }
                        if permitted(ProposalOperation::GetReviewContext)
                            && grant.readable_context_fields.contains(field) =>
                    {
                        Some((field, slot))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            let slot_ids = grant
                .readable_attachments
                .iter()
                .chain(grant.writable_attachments.iter())
                .chain(document_fields.iter().map(|(_, slot)| *slot))
                .collect::<BTreeSet<_>>();
            for slot_id in slot_ids {
                let Some(slot) = proposal.attachments.get(slot_id) else {
                    continue;
                };
                let path = format!("/v1/proposals/{{proposal_id}}/attachments/{slot_id}");
                let methods = [
                    (
                        "get",
                        (permitted(ProposalOperation::Get)
                            && grant.readable_attachments.contains(slot_id))
                            || document_fields.iter().any(|(_, slot)| *slot == slot_id),
                    ),
                    (
                        "patch",
                        permitted(ProposalOperation::Edit)
                            && grant.writable_attachments.contains(slot_id),
                    ),
                    (
                        "delete",
                        permitted(ProposalOperation::Edit)
                            && grant.writable_attachments.contains(slot_id),
                    ),
                ];
                for (method, permitted) in methods {
                    if !permitted {
                        continue;
                    }
                    let mut operation = operation_document(
                        &format!("proposals.attachments.{slot_id}.{method}"),
                        method,
                        &BTreeSet::from([grant.profile_id.clone()]),
                        false,
                        additions_enabled,
                    );
                    if method == "get" {
                        operation["parameters"].as_array_mut().unwrap().push(json!({"name":"submissionVersion","in":"query","required":true,"schema":{"type":"integer","minimum":1,"maximum":u32::MAX}}));
                        for (name, schema) in [
                            (
                                "reviewContextField",
                                json!({"type":"string","pattern":"^[a-z][a-zA-Z0-9]{0,63}$"}),
                            ),
                            (
                                "effectDigest",
                                json!({"type":"string","pattern":"^sha256:[a-f0-9]{64}$"}),
                            ),
                            (
                                "contextSchemaDigest",
                                json!({"type":"string","pattern":"^sha256:[a-f0-9]{64}$"}),
                            ),
                        ] {
                            operation["parameters"].as_array_mut().unwrap().push(json!({"name":name,"in":"query","required":false,"schema":schema,
                                "description":"All three review-context query members are required together and select only get-review-context authority. Omit all three for ordinary get authority."}));
                        }
                        // Any type, unlike the record download's slot types: a carried-forward
                        // file keeps the type it was stored with.
                        operation["responses"]["200"]["content"] = json!({"*/*":{"schema":{"type":"string","contentMediaType":"application/octet-stream","maxLength":crate::contract::MAX_ATTACHMENT_BYTES}}});
                    } else if method == "patch" {
                        let content=slot.content_types.iter().map(|mime|(mime.clone(),json!({"schema":{"type":"string","format":"binary","maxLength":slot.maximum_bytes}}))).collect::<Map<_,_>>();
                        operation["requestBody"] = json!({"required":true,"content":content});
                    }
                    merge_operation(paths, path.clone(), method, operation)?;
                }
            }
            if permitted(ProposalOperation::Answer) {
                let mut document = operation_document(
                    "proposals.answer",
                    "post",
                    &BTreeSet::from([grant.profile_id.clone()]),
                    false,
                    additions_enabled,
                );
                document["parameters"].as_array_mut().expect("parameters").push(json!({
                    "name":"ask_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}));
                document["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
                    "type":"object","additionalProperties":false,
                    "anyOf":[{"required":["text"]},{"required":["additions"],"properties":{"additions":{"minItems":1}}}],
                    "properties":{
                        "text":{"type":"string","minLength":1,"maxLength":2000},
                        "additions":{"type":"array","maxItems":32,"uniqueItems":true,"items":{"type":"string","format":"uuid"}}}}}}});
                merge_operation(
                    paths,
                    "/v1/proposals/{proposal_id}/asks/{ask_id}/answer".to_owned(),
                    "post",
                    document,
                )?;
            }
            if let Some(slot) = &proposal.additions {
                let profiles = BTreeSet::from([grant.profile_id.clone()]);
                if permitted(ProposalOperation::Add)
                    && grant.writable_attachments.contains(&slot.id)
                {
                    let path = format!("/v1/proposals/{{proposal_id}}/additions/{}", slot.id);
                    let mut document = operation_document(
                        &format!("proposals.additions.{}.post", slot.id),
                        "post",
                        &profiles,
                        false,
                        true,
                    );
                    let content = slot.content_types.iter().map(|media|(media.clone(),json!({"schema":{"type":"string","format":"binary","maxLength":slot.maximum_bytes}}))).collect::<Map<_,_>>();
                    document["requestBody"] = json!({"required":true,"content":content});
                    document["responses"]["400"] =
                        json!({"description":"Empty file body (`request.invalid`)"});
                    document["responses"]["409"] = json!({"description":"The slot count limit was reached (`attachment.limit-reached`), the Proposal was rejected (`proposal.rejected`), or the idempotency key is bound to different bytes (`idempotency.key-reused`)"});
                    document["responses"]["413"] = json!({"description":"The file exceeds maximumBytes (`attachment.too-large`)"});
                    document["responses"]["415"] = json!({"description":"The slot does not accept this media type (`attachment.content-type`)"});
                    merge_operation(paths, path, "post", document)?;
                }
                let reviewer = permitted(ProposalOperation::GetReviewContext) && (matches!(proposal.review, crate::model::CompiledProposalReview::Required { .. }) || proposal.review_context.as_ref().is_some_and(|context|
                    context.fields.iter().any(|(name, field)| grant.readable_context_fields.contains(name)
                        && matches!(field, crate::contract::ProposalContextValueSource::Additions { slot: mapped } if mapped == &slot.id))));
                if (permitted(ProposalOperation::Get)
                    && grant.readable_attachments.contains(&slot.id))
                    || reviewer
                {
                    append_addition_download_path(paths, &profiles)?;
                }
            }
        }
    }
    for (operation, (profiles, inputs)) in permissions {
        let (path, method) = match operation {
            ProposalOperation::List => ("/v1/proposals".to_owned(), "get"),
            ProposalOperation::Get => ("/v1/proposals/{proposal_id}".to_owned(), "get"),
            ProposalOperation::GetReviewContext => (
                "/v1/proposals/{proposal_id}/review-context".to_owned(),
                "get",
            ),
            ProposalOperation::GetReviewStatus => (
                "/v1/proposals/{proposal_id}/review-status".to_owned(),
                "get",
            ),
            ProposalOperation::GetTaskGrantContext => (
                "/v1/proposals/{proposal_id}/task-grant-context".to_owned(),
                "post",
            ),
            ProposalOperation::GetApplicationActor => continue,
            _ => (
                format!("/v1/proposals/{{proposal_id}}/{}", operation.as_str()),
                "post",
            ),
        };
        let mut document = operation_document(
            &format!("proposals.{}", operation.as_str()),
            method,
            &profiles,
            operation == ProposalOperation::List,
            additions_enabled,
        );
        if operation == ProposalOperation::List {
            let parameters = document["parameters"].as_array_mut().unwrap();
            for name in [
                "action",
                "owner",
                "target",
                "state",
                "turn",
                "cursor",
                "limit",
                "pendingManualApplication",
            ] {
                let schema = match name {
                    "pendingManualApplication" => json!({"type":"boolean","default":false}),
                    "limit" => json!({"type":"integer","minimum":1,"maximum":100,"default":50}),
                    "owner" => json!({"const":"caller"}),
                    "target" => json!({"type":"string","format":"uuid"}),
                    "state" => {
                        json!({"enum":["draft","submitted","applied","cancelled","rejected"]})
                    }
                    "turn" => json!({"enum":["party","official","nobody"]}),
                    _ => json!({"type":"string"}),
                };
                let mut parameter = json!({"name":name,"in":"query","schema":schema});
                if name == "limit" {
                    parameter["description"] = json!("The most items a page holds. A page may hold fewer than `limit` items, so keep paging while `nextCursor` is present.");
                }
                parameters.push(parameter);
            }
            document["responses"]["200"]["content"]["application/json"]["schema"] = json!({"type":"object","additionalProperties":false,"required":["items"],"properties":{"items":{"type":"array","maxItems":100,"items":proposal_schema_with_additions(additions_enabled)},"nextCursor":{"type":"string"}}});
        } else if matches!(
            operation,
            ProposalOperation::GetReviewStatus | ProposalOperation::GetReviewContext
        ) {
            if operation == ProposalOperation::GetReviewStatus {
                document["parameters"].as_array_mut().unwrap().push(json!({
                    "name":"include","in":"query","required":false,
                    "schema":{"const":"progress"},
                    "description":"Request the institution's optional applicant-visible progress code. The code is returned only when the selected caller-owned grant enables readableReviewProgress."
                }));
            } else {
                document["parameters"].as_array_mut().unwrap().push(json!({
                    "name":"include","in":"query","required":false,
                    "schema":{"const":"answers"},
                    "description":"Request live applicant answers for a displayed human review context. Admission and preflight reads omit this option and receive no intrinsic asks."
                }));
            }
            document["responses"]["200"]["content"]["application/json"]["schema"] =
                review_document_schema(operation == ProposalOperation::GetReviewContext);
        } else if operation == ProposalOperation::GetTaskGrantContext {
            document["parameters"]
                .as_array_mut()
                .expect("operation parameters")
                .retain(|parameter| {
                    matches!(
                        parameter["name"].as_str(),
                        Some("accessProfile" | "proposal_id")
                    )
                });
            document["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":task_context_request_schema()}}});
            document["responses"]["200"]["content"]["application/json"]["schema"] = json!({"type":"object","additionalProperties":false,"required":["request","proposal"],"properties":{"request":task_context_request_schema(),"proposal":task_review_document_schema()}});
            document["responses"]
                .as_object_mut()
                .expect("operation responses")
                .remove("409");
        } else if method == "post" {
            if operation == ProposalOperation::Apply {
                append_problem_codes(
                    &mut document,
                    &apply_problems.iter().copied().collect::<Vec<_>>(),
                );
            }
            if operation == ProposalOperation::Apply && apply_may_refuse_write {
                document["responses"]["403"] = json!({"description":"The application writes outside what the selected access profile may write: a disclosure condition binds it on a record type the plan patches (`write.outside-boundary`)"});
                append_problem_codes(&mut document, &[ProblemCode::WriteOutsideBoundary]);
            }
            if operation == ProposalOperation::Apply && apply_may_fill_written_slot {
                document["responses"]["409"] = json!({"description":"The Proposal was rejected, the idempotency key was reused with a different request, or the plan promotes a file into a record slot that already holds one (`attachment.slot-write-once`)"});
                append_problem_codes(&mut document, &[ProblemCode::AttachmentSlotWriteOnce]);
            }
            let schema = match operation {
                ProposalOperation::Apply => proposal_apply_input_schema(),
                ProposalOperation::Edit | ProposalOperation::Rebase => json!({"anyOf":inputs}),
                ProposalOperation::Revise => {
                    let mut alternatives = inputs;
                    alternatives.push(json!({"type":"object","additionalProperties":false}));
                    json!({"anyOf":alternatives})
                }
                _ => json!({"type":"object","additionalProperties":false}),
            };
            document["requestBody"] =
                json!({"required":true,"content":{"application/json":{"schema":schema}}});
            if operation == ProposalOperation::Submit {
                append_problem_codes(
                    &mut document,
                    &submit_problems.iter().copied().collect::<Vec<_>>(),
                );
                for (code, slot) in &submit_attachment_examples {
                    document["responses"][code.status().to_string()]["content"]
                        ["application/problem+json"]["examples"][code.code()]["value"]
                        ["fieldPath"] = json!(format!("/attachments/{slot}"));
                }
                if !submit_refusals.is_empty() {
                    let examples = &mut document["responses"]["422"]["content"]
                        ["application/problem+json"]["examples"];
                    for (code, label) in &submit_refusals {
                        let mut example =
                            problem_example("422", ProblemCode::ActionRefused.code(), label);
                        example["refusalCode"] = json!(code);
                        examples[format!("action.refused/{code}")] = json!({"value":example});
                    }
                }
            }
        }
        if operation == ProposalOperation::Get {
            let mut submission = operation_document(
                "proposals.get-submission",
                "get",
                &profiles,
                false,
                additions_enabled,
            );
            submission["parameters"].as_array_mut().unwrap().push(json!({"name":"submission_version","in":"path","required":true,"schema":{"type":"integer","minimum":1,"maximum":u32::MAX}}));
            submission["responses"]["200"]["content"]["application/json"]["schema"] =
                proposal_submission_schema();
            submission["responses"]["410"] = json!({"description":"The submission's review result and application receipt are no longer retained"});
            merge_operation(
                paths,
                "/v1/proposals/{proposal_id}/submissions/{submission_version}".to_owned(),
                "get",
                submission,
            )?;
        }
        if operation == ProposalOperation::GetReviewContext {
            let mut batch = operation_document(
                "proposals.get-review-context-batch",
                "get",
                &profiles,
                true,
                additions_enabled,
            );
            batch["description"] = json!("One bounded transport exchange under each item's current get-review-context authority. Ordered visible or concealed results; operational failures refuse the whole batch. Maximum response is 8 MiB.");
            batch["parameters"].as_array_mut().unwrap().push(json!({"name":"ids","in":"query","required":true,
                "description":"One to 100 distinct canonical Proposal UUIDs, in response order.",
                "style":"form","explode":false,"schema":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,"items":{"type":"string","format":"uuid"}}}));
            batch["responses"]["200"]["content"]["application/json"]["schema"] = json!({
            "type":"object","additionalProperties":false,"required":["items"],"properties":{"items":{
                "type":"array","minItems":1,"maxItems":100,"items":{"oneOf":[
                    {"type":"object","additionalProperties":false,"required":["id","status","context"],"properties":{
                        "id":{"type":"string","format":"uuid"},"status":{"const":"visible"},"context":task_review_document_schema()}},
                    {"type":"object","additionalProperties":false,"required":["id","status"],"properties":{
                        "id":{"type":"string","format":"uuid"},"status":{"const":"concealed"}}}
                ]}}}});
            merge_operation(
                paths,
                "/v1/proposals/review-context".to_owned(),
                "get",
                batch,
            )?;
        }
        merge_operation(paths, path, method, document)?;
    }
    Ok(())
}

fn task_context_request_schema() -> Value {
    let digest = json!({"type":"string","pattern":"^sha256:[0-9a-f]{64}$"});
    json!({"type":"object","additionalProperties":false,
    "required":["expected","requestId","taskId","taskRevision","policy","purpose","fields"],
    "properties":{
        "expected":{"type":"object","additionalProperties":false,"required":["actionId","subject","contract"],"properties":{
            "actionId":{"type":"string"},
            "subject":{"type":"object","additionalProperties":false,"required":["source","subjectType","id","version","digest"],"properties":{
                "source":{"type":"string","maxLength":512},"subjectType":{"const":"proposal"},"id":{"type":"string","format":"uuid"},"version":{"type":"string","maxLength":128},"digest":digest.clone()}},
            "contract":{"type":"object","additionalProperties":false,"required":["id","revision","schemaDigest"],"properties":{
                "id":{"type":"string","pattern":"^urn:registry:breg:review-context:","maxLength":2048},"revision":digest.clone(),"schemaDigest":digest.clone()}}
        }},
        "requestId":{"type":"string","format":"uuid"},"taskId":{"type":"string","format":"uuid"},"taskRevision":{"type":"integer","minimum":1},
        "policy":{"type":"object","additionalProperties":false,"required":["id","version","digest"],"properties":{"id":{"type":"string"},"version":{"type":"string"},"digest":digest}},
        "purpose":{"type":"string","minLength":1,"maxLength":128},
        "fields":{"type":"array","minItems":1,"maxItems":128,"uniqueItems":true,"items":{"type":"string","pattern":"^[a-z][a-zA-Z0-9]{0,63}$"}}
    }})
}

fn proposal_submission_schema() -> Value {
    let review = json!({"type":"object","additionalProperties":false,"required":["state"],"properties":{
        "state":{"enum":["pending","approved","rejected","changes-requested","answered","cancelled","superseded","expired"]},
        "resultId":{"type":"string","format":"uuid"},"completedAt":{"type":"string","format":"date-time"},
        "availableUntil":{"type":"string","format":"date-time"}}});
    let mut application_status = proposal_schema()["properties"]["applicationStatus"].clone();
    application_status["properties"]["state"] = json!({"enum":[
        "awaiting-review","pending","applying","blocked","cancelled","rejected"
    ]});
    let mut applied_receipt = json!({"type":"object","additionalProperties":false,
    "required":["state","applicationId"],"properties":{
        "state":{"const":"applied"},
        "applicationId":{"type":"string","format":"uuid"}
    }});
    append_application_actor_schema(&mut applied_receipt);
    json!({"type":"object","additionalProperties":false,
        "required":["id","actionId","submissionVersion","current","effectDigest","review","application"],
        "properties":{"id":{"type":"string","format":"uuid"},"actionId":{"type":"string"},
            "submissionVersion":{"type":"integer","minimum":1,"maximum":u32::MAX},
            "current":{"type":"boolean"},
            "effectDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "review":{"anyOf":[review,{"type":"null"}]},
            "application":{"anyOf":[applied_receipt,application_status,{"type":"null"}]},
            "decision":crate::artifacts::proposal_decision_schema(),
            "handoffRefusal":crate::artifacts::proposal_handoff_refusal_schema()}})
}

fn proposal_get_schema() -> Value {
    let mut schema = proposal_schema();
    append_application_actor_schema(&mut schema["properties"]["application"]);
    schema
}

fn append_application_actor_schema(application: &mut Value) {
    application["properties"]["appliedBy"] = json!({"type":"string","pattern":"^hmac-sha256:[0-9a-f]{64}$","description":"Keyed actor pseudonym, present with appliedAt only when the selected profile holds get-application-actor."});
    application["properties"]["appliedAt"] = json!({"type":"string","format":"date-time","description":"Application time, present with appliedBy only when the selected profile holds get-application-actor."});
    application["dependentRequired"] = json!({"appliedBy":["appliedAt"],"appliedAt":["appliedBy"]});
}

fn openapi_merge_error() -> Diagnostic {
    Diagnostic::error(
        "breg.artifact.openapi-merge-failed",
        "artifacts.openapi",
        "the generated Proposal OpenAPI operations could not be merged",
    )
}

fn merge_operation(
    paths: &mut Map<String, Value>,
    path: String,
    method: &str,
    mut operation: Value,
) -> Result<(), Diagnostic> {
    append_operation_problems(&mut operation, method);
    let entry = paths.entry(path).or_insert_with(|| json!({}));
    let entry = entry.as_object_mut().ok_or_else(openapi_merge_error)?;
    if let Some(current) = entry.get(method) {
        let profiles = current["x-registry-accessProfiles"]
            .as_array()
            .ok_or_else(openapi_merge_error)?
            .iter()
            .chain(
                operation["x-registry-accessProfiles"]
                    .as_array()
                    .ok_or_else(openapi_merge_error)?,
            )
            .cloned()
            .collect::<Vec<_>>();
        let mut profiles = profiles
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect::<BTreeSet<_>>();
        operation["x-registry-accessProfiles"] = json!(&profiles);
        operation["parameters"][0]["schema"]["enum"] = json!(std::mem::take(&mut profiles));
        for pointer in ["/requestBody/content", "/responses/200/content"] {
            if let Some(previous) = current.pointer(pointer).and_then(Value::as_object) {
                if let Some(content) = operation
                    .pointer_mut(pointer)
                    .and_then(Value::as_object_mut)
                {
                    for (media_type, representation) in previous {
                        if let Some(next) = content.get_mut(media_type) {
                            if next["schema"] != representation["schema"] {
                                next["schema"] = json!({"anyOf":[next["schema"].clone(),representation["schema"].clone()]});
                            }
                        } else {
                            content.insert(media_type.clone(), representation.clone());
                        }
                    }
                }
            }
        }
        // Profile-specific Actions can contribute different refusal codes.
        // Preserve every response and example when the shared route is merged.
        for (status, previous) in current["responses"]
            .as_object()
            .ok_or_else(openapi_merge_error)?
        {
            if status.starts_with('2') {
                continue;
            }
            let responses = operation["responses"]
                .as_object_mut()
                .ok_or_else(openapi_merge_error)?;
            if let Some(next) = responses.get_mut(status) {
                if let Some(examples) =
                    previous["content"]["application/problem+json"]["examples"].as_object()
                {
                    next["content"]["application/problem+json"]["examples"]
                        .as_object_mut()
                        .ok_or_else(openapi_merge_error)?
                        .extend(examples.clone());
                }
            } else {
                responses.insert(status.clone(), previous.clone());
            }
        }
    }
    for (status, response) in operation["responses"]
        .as_object_mut()
        .ok_or_else(openapi_merge_error)?
    {
        if status.starts_with('2') {
            continue;
        }
        let problem = &mut response["content"]["application/problem+json"];
        let codes = problem["examples"]
            .as_object()
            .ok_or_else(openapi_merge_error)?
            .values()
            .map(|example| {
                example["value"]["code"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(openapi_merge_error)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if codes.is_empty() {
            return Err(openapi_merge_error());
        }
        problem["schema"] = problem_code_schema(&codes);
    }
    entry.insert(method.to_owned(), operation);
    Ok(())
}

fn problem_code_schema(codes: &BTreeSet<String>) -> Value {
    json!({"allOf":[{"$ref":"#/components/schemas/Problem"},
        {"type":"object","properties":{"code":{"enum":codes}}}]})
}

fn append_problem_codes(operation: &mut Value, codes: &[ProblemCode]) {
    for code in codes {
        let status = code.status().to_string();
        let response = operation["responses"]
            .as_object_mut()
            .expect("responses")
            .entry(status.clone())
            .or_insert_with(|| json!({"description":"Problem response"}));
        response["headers"] = json!({"traceparent":traceparent_header("Trace context for this problem response."),"Cache-Control":no_store_header()});
        let content = response
            .as_object_mut()
            .expect("response")
            .entry("content")
            .or_insert_with(|| json!({}));
        let problem = content
            .as_object_mut()
            .expect("content")
            .entry("application/problem+json")
            .or_insert_with(
                || json!({"schema":{"$ref":"#/components/schemas/Problem"},"examples":{}}),
            );
        let mut example = problem_example(&status, code.code(), code.description());
        let mut allowed = problem["schema"]["allOf"][1]["properties"]["code"]["enum"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect::<BTreeSet<_>>();
        allowed.insert(code.code().to_owned());
        problem["schema"] = problem_code_schema(&allowed);
        if matches!(
            code,
            ProblemCode::AttachmentRequired
                | ProblemCode::AttachmentVerificationPending
                | ProblemCode::AttachmentVerificationRejected
        ) {
            example["fieldPath"] = json!("/attachments/file");
        } else if *code == ProblemCode::ActionRefused {
            // The caller adds examples using the Action's declared codes and labels.
            continue;
        }
        problem["examples"][code.code()] = json!({"value":example});
    }
}

pub(super) fn append_operation_problems(operation: &mut Value, method: &str) {
    let id = operation["operationId"]
        .as_str()
        .expect("operation id")
        .to_owned();
    let upload = method == "patch" && id.starts_with("proposals.attachments.")
        || method == "post" && id.starts_with("proposals.additions.");
    let addition = method == "post" && id.starts_with("proposals.additions.");
    let start = id.ends_with(".start");
    let read_body = id == "proposals.get-task-grant-context";
    let mutation = method != "get" && !read_body;
    let mut codes = vec![
        ProblemCode::AuthenticationRefused,
        ProblemCode::ResourceNotFound,
        ProblemCode::ServiceUnavailable,
        ProblemCode::SourceUnavailable,
        ProblemCode::RequestTimeout,
    ];
    if id == "proposals.list" {
        codes.push(ProblemCode::QueryInvalid);
    }
    if read_body {
        codes.extend([
            ProblemCode::RequestInvalid,
            ProblemCode::UnsupportedMediaType,
        ]);
    }
    if mutation {
        codes.extend([
            ProblemCode::RequestInvalid,
            ProblemCode::PreconditionFailed,
            ProblemCode::MutationConflict,
            ProblemCode::IdempotencyConflict,
            ProblemCode::IdempotencyExpired,
        ]);
        if !start {
            codes.extend([
                ProblemCode::ProposalRejected,
                ProblemCode::PreconditionRequired,
            ]);
        }
        if upload {
            codes.extend([
                ProblemCode::AttachmentTooLarge,
                ProblemCode::AttachmentContentType,
            ]);
        } else if method != "delete" {
            codes.push(ProblemCode::UnsupportedMediaType);
        }
        if addition {
            codes.push(ProblemCode::AttachmentLimitReached);
        }
    }
    if id == "proposals.get-submission" {
        codes.push(ProblemCode::ProposalSubmissionExpired);
    }
    append_problem_codes(operation, &codes);
}

fn append_addition_download_path(
    paths: &mut Map<String, Value>,
    profiles: &BTreeSet<String>,
) -> Result<(), Diagnostic> {
    let mut operation =
        operation_document("proposals.additions.download", "get", profiles, false, true);
    operation["parameters"].as_array_mut().expect("parameters").push(json!({"name":"addition_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}));
    operation["parameters"].as_array_mut().expect("parameters").push(json!({"name":"submissionVersion","in":"query","required":true,"schema":{"type":"integer","minimum":1,"maximum":u32::MAX}}));
    for (name, schema) in [
        ("reviewAskId", json!({"type":"string","format":"uuid"})),
        (
            "reviewContextField",
            json!({"type":"string","pattern":"^[a-z][a-zA-Z0-9]{0,63}$"}),
        ),
        (
            "effectDigest",
            json!({"type":"string","pattern":"^sha256:[a-f0-9]{64}$"}),
        ),
        (
            "contextSchemaDigest",
            json!({"type":"string","pattern":"^sha256:[a-f0-9]{64}$"}),
        ),
    ] {
        operation["parameters"].as_array_mut().expect("parameters").push(json!({"name":name,"in":"query","required":false,"schema":schema,
            "description":"Use exactly one of reviewContextField or reviewAskId together with effectDigest and contextSchemaDigest for get-review-context authority. reviewAskId admits only a file cited by an answer in the current review binding. Omit all four for Get authority."}));
    }
    operation["responses"]["200"]["content"] = json!({"*/*":{"schema":{"type":"string","contentMediaType":"application/octet-stream","maxLength":crate::contract::MAX_ATTACHMENT_BYTES}}});
    merge_operation(
        paths,
        "/v1/proposals/{proposal_id}/additions/{addition_id}".to_owned(),
        "get",
        operation,
    )?;
    Ok(())
}

fn operation_document(
    id: &str,
    method: &str,
    profiles: &BTreeSet<String>,
    collection: bool,
    additions: bool,
) -> Value {
    let mut parameters = vec![
        json!({"name":"accessProfile","in":"query","required":true,"schema":{"type":"string","enum":profiles}}),
    ];
    if !collection {
        parameters.push(json!({"name":"proposal_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}));
    }
    if method != "get" {
        parameters.push(
            json!({"name":"If-Match","in":"header","required":true,"schema":{"type":"string"}}),
        );
        parameters.push(json!({"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string"}}));
    }
    let mut response_schema = if id == "proposals.get" {
        proposal_get_schema()
    } else {
        proposal_schema()
    };
    if additions {
        append_proposal_additions_schema(&mut response_schema);
    }
    let mut document = json!({"operationId":id,"x-registry-accessProfiles":profiles,"parameters":parameters,
        "responses":{"200":{"description":"Authorized Proposal operation","content":{"application/json":{"schema":response_schema}}},"404":{"description":"Resource unavailable to this caller"}}});
    if method != "get" && id != "proposals.get-task-grant-context" {
        document["responses"]["412"] =
            json!({"description":"Observed authority or lifecycle condition changed"});
    }
    if matches!(id, "proposals.submit" | "proposals.apply") {
        document["responses"]["412"]["description"] = json!("Observed authority or lifecycle condition changed, or a Record revision guard failed (`precondition.failed`); a failed field commit guard answers `action.guard_failed` when the selected profile can read it");
    }
    if method != "get" && !collection {
        document["responses"]["409"] = json!({"description":"The Proposal was rejected, or the idempotency key was reused with a different request"});
    }
    document
}

fn task_review_document_schema() -> Value {
    let mut schema = review_document_schema(true);
    schema["properties"]["context"]["properties"]
        .as_object_mut()
        .expect("context properties")
        .remove("asks");
    schema
}

fn review_document_schema(context: bool) -> Value {
    let mut properties = json!({"id":{"type":"string","format":"uuid"},"actionId":{"type":"string"},"actionRevision":{"type":"string"},"submissionVersion":{"type":"integer","minimum":1},"revision":{"type":"integer","minimum":1},"effectDigest":{"type":"string"},"subject":{"type":"object","additionalProperties":false,"required":["source","subjectType","id","version","digest"],"properties":{"source":{"type":"string"},"subjectType":{"const":"proposal"},"id":{"type":"string","format":"uuid"},"version":{"type":"string"},"digest":{"type":"string"}}},"context":{"type":"object","additionalProperties":false,"required":["reference"],"properties":{"reference":{"type":"string"}}},"authority":{"type":"string"},"policy":{"type":"object","additionalProperties":false,"required":["id","version","digest"],"properties":{"id":{"type":"string"},"version":{"type":"string"},"digest":{"type":"string"}}},"reviewable":{"type":"boolean"},"result":{"type":"object","additionalProperties":false,"required":["state"],"properties":{"state":{"enum":["pending","approved","rejected","changes-requested","answered","cancelled","superseded","expired"]},"resultId":{"type":"string","format":"uuid"},"completedAt":{"type":"string","format":"date-time"},"availableUntil":{"type":"string","format":"date-time"}}}});
    properties["context"]["properties"]["contract"] = json!({
        "type":"object","additionalProperties":false,
        "required":["id","revision","schemaDigest"],
        "properties":{
            "id":{"type":"string","pattern":"^urn:registry:breg:review-context:","maxLength":2048},
            "revision":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "schemaDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"}
        }
    });
    if context {
        properties["context"]["properties"]["fields"] = json!({"type":"object"});
        properties["context"]["properties"]["asks"] = proposal_asks_schema(true);
        properties["context"]["required"] = json!(["reference", "contract", "fields"]);
    } else {
        properties["requestId"] = json!({"type":"string","format":"uuid"});
        properties["progressCode"] = json!({
            "type":"string","pattern":"^[a-z][a-z0-9_-]{0,63}$","maxLength":64,
            "description":"Institution-defined applicant-visible progress. Absent when the institution conceals the current stage, progress was not requested or granted, the provider is unavailable, or the accepted review round is no longer live."
        });
        properties["handoff"] = json!({
            "type":"object","additionalProperties":false,"required":["state"],
            "properties":{
                "state":{"enum":["pending","accepted","failed","withdrawn"]},
                "reason":{"enum":["remote-refused","producer-identity-mismatch","review-acceptance-changed","review-policy-changed","submission-recovery-expired","operator-closed","unspecified"]}
            }
        });
    }
    json!({"type":"object","additionalProperties":false,"required":["id","actionId","actionRevision","submissionVersion","revision","effectDigest","subject","context","reviewable"],"properties":properties})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_problem_example_merge_returns_without_panicking() {
        let mut paths = Map::new();
        paths.insert(
            "/test".into(),
            json!({"post":{
                "x-registry-accessProfiles":["clerk"],
                "requestBody":{},"responses":{"422":{"content":{"application/problem+json":{
                    "examples":{"action.refused":{"value":{"code":"action.refused"}}}
                }}}}
            }}),
        );
        let mut incoming = operation_document(
            "proposals.edit",
            "post",
            &BTreeSet::from(["officer".into()]),
            false,
            false,
        );
        incoming["responses"]["422"] = json!({"description":"missing examples"});
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            merge_operation(&mut paths, "/test".into(), "post", incoming)
        }));
        assert!(
            result.is_ok(),
            "a malformed merge must return an error instead of panicking"
        );
        assert!(result.unwrap().is_err());
    }

    fn application_actor_document() -> Value {
        let digest = format!("sha256:{}", "a".repeat(64));
        json!({
            "id":"00000000-0000-4000-8000-000000000001",
            "actionId":"correct-name",
            "actionRevision":digest,
            "submissionVersion":1,
            "revision":2,
            "state":"applied",
            "turn":"nobody",
            "createdAt":"2026-10-16T01:00:00.000000Z",
            "effectDigest":digest,
            "application":{
                "applicationId":"00000000-0000-4000-8000-000000000002",
                "submissionVersion":1,
                "effectDigest":digest,
                "appliedBy":format!("hmac-sha256:{}", "b".repeat(64)),
                "appliedAt":"2026-10-16T01:02:03Z",
                "resultLinks":[],
            },
            "links":{},
        })
    }

    fn response_schema(operation: &Value) -> Value {
        operation["responses"]["200"]["content"]["application/json"]["schema"].clone()
    }

    fn accepts(schema: &Value, value: &Value) -> bool {
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(schema)
            .unwrap()
            .is_valid(value)
    }

    #[test]
    fn application_actor_schema_is_limited_to_get_and_submission() {
        let profiles = BTreeSet::from(["reader".to_owned()]);
        let disclosed = application_actor_document();
        let get = operation_document("proposals.get", "get", &profiles, false, false);
        let apply = operation_document("proposals.apply", "post", &profiles, false, false);

        assert!(accepts(&response_schema(&get), &disclosed));
        assert!(!accepts(&proposal_schema(), &disclosed));
        assert!(!accepts(&response_schema(&apply), &disclosed));

        for field in ["appliedBy", "appliedAt"] {
            let mut partial = disclosed.clone();
            partial["application"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                !accepts(&response_schema(&get), &partial),
                "missing {field}"
            );
        }
    }

    #[test]
    fn submission_application_actor_requires_an_applied_receipt() {
        let schema = &proposal_submission_schema()["properties"]["application"];
        let actor = format!("hmac-sha256:{}", "b".repeat(64));

        assert!(accepts(
            schema,
            &json!({
                "state":"applied",
                "applicationId":"00000000-0000-4000-8000-000000000002",
                "appliedBy":actor,
                "appliedAt":"2026-10-16T01:02:03Z",
            }),
        ));
        assert!(!accepts(
            schema,
            &json!({
                "state":"pending",
                "mode":"manual",
                "appliedBy":format!("hmac-sha256:{}", "b".repeat(64)),
                "appliedAt":"2026-10-16T01:02:03Z",
            }),
        ));
    }
}
