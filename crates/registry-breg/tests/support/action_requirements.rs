// SPDX-License-Identifier: Apache-2.0

use serde_json::{json, Value};

pub fn project() -> Value {
    json!({
        "apiVersion": "registry.registrystack.org/v1alpha1", "kind": "RegistryProject",
        "registry": {"id": "action-requirements", "version": "1", "defaultLanguage": "en", "canonicalBaseIri": "https://authoring.example.test"},
        "entities": [
            {"id": "parent", "primaryDataset": "test-dataset", "route": "parents", "mutationMode": "mutable",
             "accessRequirements": {"requiredScopes": ["registry:parent:process"]},
             "fields": [
                {"id": "status", "type": "vocabulary-code", "vocabulary": "status", "values": ["active", "inactive"], "required": true, "classification": "restricted"},
                {"id": "zone", "type": "string", "maxLength": 32, "required": true, "classification": "restricted"}
             ]},
            {"id": "child", "primaryDataset": "test-dataset", "route": "children", "mutationMode": "mutable",
             "fields": [
                {"id": "parent", "type": "reference", "target": "parent", "required": true, "classification": "restricted"},
                {"id": "label", "type": "string", "maxLength": 32, "required": true, "classification": "restricted"}
             ],
             "events": [{"id": "child-created", "trigger": "created", "projection": ["label"]}]}
        ],
        "actions": [{"id": "register-child",
            "inputs": [
                {"id": "parent", "apiName": "parentId", "type": "reference", "target": "parent", "required": true, "classification": "restricted"},
                {"id": "label", "type": "string", "maxLength": 32, "required": true, "classification": "restricted"}
            ],
            "requires": [{"input": "parent", "field": "status", "equals": "active"}],
            "effects": [{"id": "child", "target": {"entity": "child"}, "operation": "create", "set": {"parent": {"fromField": "parent"}, "label": {"fromField": "label"}}}]
        }],
        "accessProfiles": [{"id": "registrar", "default": true, "principalClaim": "registry_principal", "requiredScopes": ["registry:register", "registry:parent:process"],
            "grants": [{"action": "register-child", "operations": ["invoke"], "targets": [
                {"entity": "parent", "rowBoundaries": [{"field": "zone", "claim": "zone", "operator": "equals"}]}, {"entity": "child", "rowBoundaries": []}
            ], "results": ["child"]}]
        }]
    })
}
