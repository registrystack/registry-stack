// SPDX-License-Identifier: Apache-2.0
use serde_json::{json, Value};

pub fn source(hooks: Value) -> Value {
    json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"proposal-observers","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "datasets":[{"id":"directory"}],
        "recordTypes":[{"id":"target","primaryDataset":"directory","route":"targets","mutationMode":"mutable",
            "mutationPolicy":{"patch":"proposal-required"},"fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"restricted"}]}],
        "actions":[{"id":"correct-name","execution":{"mode":"proposal","proposal":{
            "review":{"type":"none"},"application":{"mode":"manual"},"retention":{"mode":"operator-erase"},
            "hooks":hooks,"attachments":[{"id":"support","required":false,"maximumBytes":4096,"contentTypes":["text/plain"],"classification":"restricted"}],
            "reviewContext":{"id":"observer-context","fields":{"value":{"type":"input","input":"value"}}}}},
            "inputs":[{"id":"target","type":"reference","target":"target","required":true,"classification":"restricted"},
                {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"restricted"}],
            "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{"id":"name","target":{"fromInput":"target"},"operation":"patch","set":{"name":{"fromInput":"value"}}}]}}],
        "accessProfiles":[{"id":"clerk","default":true,"principalClaim":"sub","requiredScopes":["proposal:manage"],"requiredPurposes":["registry-administration"],"permissions":{
            "records":[{"recordType":"target","operations":["create","get"],"readableFields":["name"],"writableFields":["name"],"rowBoundaries":"unrestricted"}],
            "actions":[{"action":"correct-name","operations":["start"],"targets":[{"recordType":"target","rowBoundaries":"unrestricted"}]}],
            "proposals":[{"action":"correct-name","operations":["get","edit","submit","cancel","apply"],"ownership":"caller",
                "readableAttachments":["support"],"writableAttachments":["support"],"targets":[{"recordType":"target","rowBoundaries":"unrestricted"}]}]}}]})
}

pub fn url_hook() -> Value {
    json!({"id":"notify-submitted","transitions":["submitted"],"handler":{"type":"url","destinationId":"observer"}})
}

pub fn local_hook(id: &str, transitions: Value) -> Value {
    json!({"id":id,"transitions":transitions,"handler":{"type":"rhai","script":format!("hooks/{id}.rhai"),"abi":"registry.hook-handler/v1"}})
}
