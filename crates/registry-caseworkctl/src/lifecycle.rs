// SPDX-License-Identifier: Apache-2.0

//! `caseworkctl lifecycle`: the two state machines the Casework runtime
//! enforces, reported as data.
//!
//! Both tables live in `registry-casework-core` beside the code that enforces
//! them, so this module only wraps them in the report shape every
//! `caseworkctl` command returns. It reads no project: neither machine varies
//! by policy, and asking for a project would both imply otherwise and let an
//! unrelated authoring error refuse an answer that never depended on one.

use anyhow::Result;
use serde_json::{json, Value};

pub(super) fn lifecycle() -> Result<Value> {
    Ok(json!({
        "ok": true,
        "command": "lifecycle",
        "lifecycles": [
            registry_casework_core::occurrence_lifecycle(),
            registry_casework_core::review_lifecycle(),
        ],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_both_runtime_state_machines() {
        let report = lifecycle().expect("lifecycle reports");
        assert_eq!(report["ok"], json!(true));
        assert_eq!(report["command"], json!("lifecycle"));

        let lifecycles = report["lifecycles"]
            .as_array()
            .expect("lifecycles is an array");
        let ids: Vec<&str> = lifecycles
            .iter()
            .map(|lifecycle| {
                lifecycle["id"]
                    .as_str()
                    .expect("each lifecycle names an id")
            })
            .collect();
        assert_eq!(ids, vec!["occurrence", "review_request"]);
    }

    /// The derived flags survive serialization, so a reader drawing the
    /// machine sees the same reachability the engine computed.
    #[test]
    fn every_reported_state_carries_its_derived_flags() {
        let report = lifecycle().expect("lifecycle reports");
        for lifecycle in report["lifecycles"]
            .as_array()
            .expect("lifecycles is an array")
        {
            let states = lifecycle["states"].as_array().expect("states is an array");
            assert!(!states.is_empty(), "{lifecycle:#?}");
            for state in states {
                for key in [
                    "id",
                    "initial",
                    "terminal",
                    "unreachable",
                    "incomingTransitions",
                    "outgoingTransitions",
                ] {
                    assert!(state.get(key).is_some(), "state {state:#?} names {key}");
                }
            }
            for transition in lifecycle["transitions"]
                .as_array()
                .expect("transitions is an array")
            {
                for key in ["from", "event", "to", "guard"] {
                    assert!(
                        transition.get(key).is_some(),
                        "transition {transition:#?} names {key}"
                    );
                }
            }
        }
    }

    /// The enforcement layers are the only place the report says what the
    /// runtime checks around a transition, so each machine carries them in
    /// order and every layer names the events it covers.
    #[test]
    fn every_reported_machine_carries_ordered_enforcement_layers() {
        let report = lifecycle().expect("lifecycle reports");
        for lifecycle in report["lifecycles"]
            .as_array()
            .expect("lifecycles is an array")
        {
            let layers = lifecycle["enforcement"]
                .as_array()
                .expect("enforcement is an array");
            assert!(!layers.is_empty(), "{lifecycle:#?}");
            for layer in layers {
                for key in ["id", "description", "events"] {
                    assert!(layer.get(key).is_some(), "layer {layer:#?} names {key}");
                }
                assert!(
                    !layer["events"]
                        .as_array()
                        .expect("events is an array")
                        .is_empty(),
                    "layer {layer:#?} applies to at least one event"
                );
            }
        }
    }
}
