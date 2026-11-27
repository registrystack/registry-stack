// SPDX-License-Identifier: Apache-2.0
//! Shared compiler fixture for provider activation and compiled-program binding.
pub(crate) fn registry(evidence: bool) -> crate::CompiledRegistry {
    use crate::{
        compiler::{compile_project_with_assets, CompileProfile},
        contract::{parse_project_json, ModuleAssetSource},
    };
    use serde_json::{json, Value};
    let mut source: Value = registry_platform_yaml::Reader::new("registry.yaml")
        .scan(include_bytes!(
            "../../../../products/breg/examples/facility/registry.yaml"
        ))
        .unwrap()
        .expect("canonical fixture is nonempty")
        .to_json_value();
    let mut assets = vec![ModuleAssetSource {
        module: None,
        path: "plans/correct-address.rhai".into(),
        bytes: include_bytes!(
            "../../../../products/breg/examples/facility/plans/correct-address.rhai"
        )
        .to_vec(),
    }];
    if evidence {
        source["evidenceProviders"] = json!({"farmer-registry": {"contracts":"evidence/contracts.json","subjectResolution":"trusted-provider-exact-selector"}});
        let action = &mut source["actions"]["correct-address"];
        action["inputs"].as_array_mut().unwrap().push(json!({"id":"subject","type":"string","required":true,"minimumLength":3,"maximumLength":77,"classification":"restricted"}));
        // The added input is writable through edit, so every grant that edits must read it.
        for profile in source["accessProfiles"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            let grants = profile
                .pointer_mut("/permissions/proposals")
                .and_then(Value::as_array_mut);
            for grant in grants.into_iter().flatten() {
                if grant["action"] != "correct-address" {
                    continue;
                }
                if let Some(readable) = grant
                    .get_mut("readableInputs")
                    .and_then(Value::as_array_mut)
                {
                    readable.push(json!("subject"));
                }
            }
        }
        let action = &mut source["actions"]["correct-address"];
        action["commitGuards"]["evidence"] = json!([{
            "id":"status","provider":"farmer-registry","requirement":"urn:example:farmer:status-v1",
            "subjects":{"farmer":{"profile":"farmer-number-v1","selectors":{"farmer-number":{"type":"input","input":"subject"}}}},
            "requires":[{"output":"active","equals":true}],"maximumObservationAgeSeconds":60
        }]);
        assets.push(ModuleAssetSource {module:None,path:"evidence/contracts.json".into(),bytes:include_bytes!("../../../../products/breg/acceptance/farmer-landholding-evidence/evidence/farmer-contracts.json").to_vec()});
    }
    compile_project_with_assets(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        &assets,
        CompileProfile::Authoring,
    )
    .unwrap()
}
