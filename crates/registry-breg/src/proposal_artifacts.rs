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
            for slot_id in grant
                .readable_attachments
                .iter()
                .chain(grant.writable_attachments.iter())
            {
                let Some(slot) = proposal.attachments.get(slot_id) else {
                    continue;
                };
                let path = format!("/v1/proposals/{{proposal_id}}/attachments/{slot_id}");
                let methods = [
                    (
                        "get",
                        permitted(ProposalOperation::Get)
                            && grant.readable_attachments.contains(slot_id),
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
                        operation["responses"]["200"]["content"] = json!({"application/octet-stream":{"schema":{"type":"string","format":"binary","maxLength":slot.maximum_bytes}}});
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
            for name in ["action", "owner", "target", "state", "cursor", "top"] {
                let schema = match name {
                    "top" => json!({"type":"integer","minimum":1,"maximum":100,"default":50}),
                    "owner" => json!({"const":"caller"}),
                    "target" => json!({"type":"string","format":"uuid"}),
                    "state" => json!({"enum":["draft","submitted","applied","cancelled"]}),
                    _ => json!({"type":"string"}),
                };
                parameters.push(json!({"name":name,"in":"query","schema":schema}));
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
        merge_operation(paths, path, method, document);
    }
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
    json!({"operationId":id,"x-registry-accessProfiles":profiles,"parameters":parameters,
        "responses":{"200":{"description":"Authorized Proposal operation","content":{"application/json":{"schema":proposal_schema()}}},"404":{"description":"Resource unavailable to this caller"},"412":{"description":"Observed authority or lifecycle condition changed"}}})
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
    }
    json!({"type":"object","additionalProperties":false,"required":["id","actionId","actionRevision","submissionVersion","revision","effectDigest","subject","context","reviewable"],"properties":properties})
}
