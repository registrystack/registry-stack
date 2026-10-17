// SPDX-License-Identifier: Apache-2.0
//! First-class Proposal operations derived from the compiled Action policies.
use super::*;
use crate::model::{CompiledActionExecution, ProposalOperation};

pub(crate) fn append_proposal_openapi(
    paths: &mut Map<String, Value>,
    actions: &CompiledActionInventory,
    visible: Option<&BTreeSet<(String, String, ProposalOperation)>>,
) {
    let mut permissions: BTreeMap<ProposalOperation, (BTreeSet<String>, Vec<Value>)> =
        BTreeMap::new();
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
                if *operation == ProposalOperation::GetApplicationActor {
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
                        operation["responses"]["200"]["content"] = json!({"application/octet-stream":{"schema":{"type":"string","format":"binary","maxLength":crate::contract::MAX_ATTACHMENT_BYTES}}});
                    } else if method == "patch" {
                        let content=slot.content_types.iter().map(|mime|(mime.clone(),json!({"schema":{"type":"string","format":"binary","maxLength":slot.maximum_bytes}}))).collect::<Map<_,_>>();
                        operation["requestBody"] = json!({"required":true,"content":content});
                    }
                    merge_operation(paths, path.clone(), method, operation);
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
        );
        if operation == ProposalOperation::List {
            let parameters = document["parameters"].as_array_mut().unwrap();
            for name in [
                "action", "owner", "target", "state", "turn", "cursor", "limit",
            ] {
                let schema = match name {
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
            document["responses"]["200"]["content"]["application/json"]["schema"] = json!({"type":"object","additionalProperties":false,"required":["items"],"properties":{"items":{"type":"array","maxItems":100,"items":proposal_schema()},"nextCursor":{"type":"string"}}});
        } else if matches!(
            operation,
            ProposalOperation::GetReviewStatus | ProposalOperation::GetReviewContext
        ) {
            document["responses"]["200"]["content"]["application/json"]["schema"] =
                review_document_schema(operation == ProposalOperation::GetReviewContext);
        } else if method == "post" {
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
        }
        if operation == ProposalOperation::Get {
            let mut submission =
                operation_document("proposals.get-submission", "get", &profiles, false);
            submission["parameters"].as_array_mut().unwrap().push(json!({"name":"submission_version","in":"path","required":true,"schema":{"type":"integer","minimum":1,"maximum":u32::MAX}}));
            submission["responses"]["200"]["content"]["application/json"]["schema"] =
                proposal_submission_schema();
            submission["responses"]["410"] = json!({"description":"The submission's review result and application receipt are no longer retained"});
            merge_operation(
                paths,
                "/v1/proposals/{proposal_id}/submissions/{submission_version}".to_owned(),
                "get",
                submission,
            );
        }
        if operation == ProposalOperation::GetReviewContext {
            let mut batch =
                operation_document("proposals.get-review-context-batch", "get", &profiles, true);
            batch["description"] = json!("One bounded transport exchange under each item's current get-review-context authority. Ordered visible or concealed results; operational failures refuse the whole batch. Maximum response is 8 MiB.");
            batch["parameters"].as_array_mut().unwrap().push(json!({"name":"ids","in":"query","required":true,
                "description":"One to 100 distinct canonical Proposal UUIDs, in response order.",
                "style":"form","explode":false,"schema":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,"items":{"type":"string","format":"uuid"}}}));
            batch["responses"]["200"]["content"]["application/json"]["schema"] = json!({
            "type":"object","additionalProperties":false,"required":["items"],"properties":{"items":{
                "type":"array","minItems":1,"maxItems":100,"items":{"oneOf":[
                    {"type":"object","additionalProperties":false,"required":["id","status","context"],"properties":{
                        "id":{"type":"string","format":"uuid"},"status":{"const":"visible"},"context":review_document_schema(true)}},
                    {"type":"object","additionalProperties":false,"required":["id","status"],"properties":{
                        "id":{"type":"string","format":"uuid"},"status":{"const":"concealed"}}}
                ]}}}});
            merge_operation(
                paths,
                "/v1/proposals/review-context".to_owned(),
                "get",
                batch,
            );
        }
        merge_operation(paths, path, method, document);
    }
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
            "decision":crate::artifacts::proposal_decision_schema()}})
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

fn merge_operation(
    paths: &mut Map<String, Value>,
    path: String,
    method: &str,
    mut operation: Value,
) {
    let entry = paths.entry(path).or_insert_with(|| json!({}));
    if let Some(current) = entry.get(method) {
        let profiles = current["x-registry-accessProfiles"]
            .as_array()
            .unwrap()
            .iter()
            .chain(operation["x-registry-accessProfiles"].as_array().unwrap())
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
    }
    entry[method] = operation;
}

fn operation_document(
    id: &str,
    method: &str,
    profiles: &BTreeSet<String>,
    collection: bool,
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
    let response_schema = if id == "proposals.get" {
        proposal_get_schema()
    } else {
        proposal_schema()
    };
    let mut document = json!({"operationId":id,"x-registry-accessProfiles":profiles,"parameters":parameters,
        "responses":{"200":{"description":"Authorized Proposal operation","content":{"application/json":{"schema":response_schema}}},"404":{"description":"Resource unavailable to this caller"},"412":{"description":"Observed authority or lifecycle condition changed"}}});
    if method != "get" && !collection {
        document["responses"]["409"] = json!({"description":"The Proposal was rejected, or the idempotency key was reused with a different request"});
    }
    document
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
        properties["context"]["required"] = json!(["reference", "contract", "fields"]);
    } else {
        properties["requestId"] = json!({"type":"string","format":"uuid"});
    }
    json!({"type":"object","additionalProperties":false,"required":["id","actionId","actionRevision","submissionVersion","revision","effectDigest","subject","context","reviewable"],"properties":properties})
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let get = operation_document("proposals.get", "get", &profiles, false);
        let apply = operation_document("proposals.apply", "post", &profiles, false);

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
