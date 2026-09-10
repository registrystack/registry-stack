// SPDX-License-Identifier: Apache-2.0
use serde_json::{json, Value};

pub fn lifecycle_metadata(revision: &str) -> Value {
    json!({
        "id":"test", "version":"1.0.0", "revision":revision, "metadataVersion":"1",
        "entities":[{"id":"correction","datasetIdentifier":"primary","route":"corrections",
            "operations":[{"operation":"apply_request","accessProfile":"reader"}],
            "readableFields":["value"],"schema":"/v1/schemas/correction"}],
        "operations":[{
            "id":"records.correction.request.apply","method":"POST",
            "path":"/v1/records/corrections/{record_id}/actions/apply","operation":"apply_request",
            "sourceEntity":"correction","responseEntity":"correction","accessProfile":"reader",
            "requiredCapabilities":["change_request_lifecycle"],"entityLabel":"Corrections",
            "identifier":{"apiName":"id","location":"envelope"},"titleFields":["value"],
            "fields":[{"id":"value","apiName":"value","label":"Value","schema":{"type":"string"},"required":true,"nullable":true,"readOnly":false,"removable":true}],
            "readableFields":["value"],"createWritableFields":[],"patchWritableFields":[],"selectors":[],"query":null,
            "request":{"fieldNames":"api","queryParameters":[],"body":"change_request_action","contentType":"application/json",
                "ifMatchRequired":true,"idempotencyKeyRequired":true,"mutationSemantics":"change_request_lifecycle",
                "schema":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
                    "required":["proposalVersion","effectDigest"],"properties":{
                        "proposalVersion":{"type":"integer","format":"int64","minimum":1,"maximum":4294967295_u64},
                        "effectDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","description":"Digest of the immutable proposal effects displayed to the actor."}}}}
        }]
    })
}
