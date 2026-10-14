// SPDX-License-Identifier: Apache-2.0

use serde_json::{Value, json};

pub fn project() -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1", "kind": "BRegProject",
        "project": {"id": "action-requirements", "version": "1", "defaultLanguage": "en", "canonicalBaseIri": "https://authoring.example.test"},
        "datasets": [{"id":"test-dataset"}],
        "vocabularies": [{"id":"status","values":["active","inactive"]}],
        "recordTypes": [
            {"id": "parent", "primaryDataset": "test-dataset", "route": "parents", "mutationMode": "mutable",
             "accessRequirements": {"requiredScopes": ["registry:parent:process"]},
             "fields": [
                {"id": "status", "type": "vocabulary-code", "vocabulary": "status", "values": ["active", "inactive"], "required": true, "classification": "restricted"},
                {"id": "zone", "type": "string", "maximumLength": 32, "required": true, "classification": "restricted"}
             ]},
            {"id": "child", "primaryDataset": "test-dataset", "route": "children", "mutationMode": "mutable",
             "fields": [
                {"id": "parent", "type": "reference", "target": "parent", "required": true, "classification": "restricted"},
                {"id": "label", "type": "string", "maximumLength": 32, "required": true, "classification": "restricted"}
             ],
             "hooks": [{"phase":"after","id": "child-created", "trigger": "created", "projection": ["label"]}]}
        ],
        "actions": [{"id": "register-child", "execution":{"mode":"immediate"},
            "inputs": [
                {"id": "parent", "apiName": "parentId", "type": "reference", "target": "parent", "required": true, "classification": "restricted"},
                {"id": "label", "type": "string", "maximumLength": 32, "required": true, "classification": "restricted"}
            ],
            "commitGuards": {"targets":[{"input": "parent", "field": "status", "equals": "active"}]},
            "plan":{"type":"fixed","effects": [{"id": "child", "target": {"recordType": "child"}, "operation": "create", "set": {"parent": {"fromInput": "parent"}, "label": {"fromInput": "label"}}}]}
        }],
        "accessProfiles": [{"id": "registrar", "default": true, "principalClaim": "registry_principal", "requiredScopes": ["registry:register", "registry:parent:process"],
            "permissions": {"actions": [{"action": "register-child", "operations": ["invoke"], "targets": [
                {"recordType": "parent", "rowBoundaries": [{"field": "zone", "claim": "zone", "operator": "equals"}]}, {"recordType": "child", "rowBoundaries": "unrestricted"}
            ], "results": ["child"]}]}
        }]
    })
}
