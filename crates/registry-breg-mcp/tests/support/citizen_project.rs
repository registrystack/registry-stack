// SPDX-License-Identifier: Apache-2.0
//! One authored native citizen journey shared by gateway and human review.

use serde_json::{json, Value};

pub fn project() -> Value {
    let fields = ["owner", "address-line", "locality", "postal-code"];
    let inputs = [
        "address",
        "new-address-line",
        "new-locality",
        "new-postal-code",
    ];
    let boundary = json!([{"field":"owner","claim":"sub","operator":"equals"}]);
    let targets = json!([{"recordType":"person-address","rowBoundaries":boundary}]);
    let mut profiles = vec![json!({"id":"writer","default":true,"principalClaim":"sub",
        "actorKind":"service","requesterClients":["application-reader"],"requiredScopes":["applications:read"],
        "permissions":{"records":[{"recordType":"person-address","operations":["create","get","list","patch"],
            "readableFields":fields,"writableFields":fields,"rowBoundaries":"unrestricted"}]}})];
    for (id, actor, client, operations) in [
        (
            "citizen-agent",
            "agent",
            "citizen-gateway",
            vec!["get", "list", "edit"],
        ),
        (
            "citizen-review",
            "human",
            "citizen-review-page",
            vec!["get", "list", "submit"],
        ),
    ] {
        let mut profile = json!({"id":id,"principalClaim":"sub","actorKind":actor,
            "requesterClients":[client],"requiredScopes":["address-correction:self"],
            "permissions":{"records":[{"recordType":"person-address","operations":["get","list"],
                "readableFields":["address-line","locality","postal-code"],"rowBoundaries":boundary}],
                "actions":[{"action":"correct-address","operations":["start"],"targets":targets}],
                "proposals":[{"action":"correct-address","operations":operations,"ownership":"caller",
                    "readableInputs":inputs,"targets":targets}]}});
        if actor == "agent" {
            profile["requiredPurposes"] = json!(["address-correction"]);
            profile["taskGrant"] = json!({"sourceIssuer":"https://tasks.example.test"});
        }
        profiles.push(profile);
    }
    json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"native-citizen-proof","canonicalBaseIri":"https://synthetic.example.invalid/citizen","version":"1","defaultLanguage":"en"},
        "package":{"sourceRevision":"native-citizen-proof"},"datasets":[{"id":"addresses"}],
        "recordTypes":[{"id":"person-address","route":"person-addresses","primaryDataset":"addresses","mutationMode":"mutable",
            "classification":"internal","fields":fields.into_iter().map(|id|json!({"id":id,"apiName":match id {"address-line"=>"addressLine", "postal-code"=>"postalCode", other=>other},"type":"string","required":true,"maximumLength":200,"classification":"internal"})).collect::<Vec<_>>()}],
        "actions":[{"id":"correct-address","execution":{"mode":"proposal","proposal":{
            "review":{"type":"none"},"application":{"mode":"manual"},"retention":{"mode":"operator-erase"}}},
            "inputs":[{"id":"address","type":"reference","target":"person-address","required":true,"classification":"internal"},
                {"id":"new-address-line","apiName":"newAddressLine","type":"string","required":true,"maximumLength":200,"classification":"internal"},
                {"id":"new-locality","apiName":"newLocality","type":"string","required":true,"maximumLength":200,"classification":"internal"},
                {"id":"new-postal-code","apiName":"newPostalCode","type":"string","required":true,"maximumLength":200,"classification":"internal"}],
            "commitGuards":{"targets":[{"input":"address","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{"id":"address","target":{"fromInput":"address"},"operation":"patch",
                "set":{"address-line":{"fromInput":"new-address-line"},"locality":{"fromInput":"new-locality"},"postal-code":{"fromInput":"new-postal-code"}}}]}}],
        "accessProfiles":profiles})
}
