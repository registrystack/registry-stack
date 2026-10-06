// SPDX-License-Identifier: Apache-2.0

//! Hook declarations: the project-side half of the hook configuration.
//!
//! A product's hooks are an ordered list. Nothing registers implicitly, every
//! hook carries an explicit `id`, and declaration order is the execution order
//! among hooks on one trigger; that is the answer to import-order signals.
//! `trigger`, `when`, `principal`, and `projection` are product vocabulary
//! carried opaquely: the library never validates them.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The one handler ABI defined in hook contract version one.
pub const HOOK_HANDLER_ABI_V1: &str = "registry.hook-handler/v1";

/// When the hook runs relative to the triggering transaction.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPhase {
    /// Runs inside the triggering transaction and may refuse or shape the
    /// change. Local handler kinds only.
    Before,
    /// Runs after commit in the post-commit worker and cannot affect the
    /// triggering transaction.
    After,
}

impl HookPhase {
    /// The declaration spelling of the phase.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
        }
    }
}

/// One declared hook: a product trigger bound to one handler.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HookDeclaration {
    /// Explicit, unique hook identity. Declaration order is the execution
    /// order among hooks on one trigger.
    pub id: String,
    /// When the hook runs relative to the triggering transaction.
    pub phase: HookPhase,
    /// The product's committed change or lifecycle transition. Product
    /// vocabulary: the library never defines or validates a trigger.
    pub trigger: String,
    /// The product's condition document, validated by the product against its
    /// own condition language. Carried opaquely so a product keeps the
    /// condition shape it already has unchanged on adoption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Value>,
    /// The principal a proposal from this hook is applied under. Product
    /// vocabulary: the library never resolves or validates it. A hook that
    /// declares none is complete; what a proposal from such a hook means is
    /// the product's delivery-time decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Declared field identifiers the product may project into `data`.
    /// Product-validated; carried opaquely.
    pub projection: BTreeSet<String>,
    /// Where the handler runs.
    pub handler: HookHandlerSource,
}

/// Where a hook's handler runs.
///
/// The pairing rule: `rhai` requires `script`, `wasm` requires `module`,
/// `url` requires `destinationId`, and each
/// kind requires exactly its own fields and nothing else. `abi` is required on
/// `rhai` and `wasm` and forbidden on `url`; its value is closed and checked at
/// compile time in [`crate::validate_hooks`].
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(
    remote = "Self",
    deny_unknown_fields,
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum HookHandlerSource {
    /// A reviewed Rhai script in the project.
    Rhai {
        /// Script path in the project.
        script: String,
        /// The handler ABI the script speaks.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        abi: Option<String>,
    },
    /// A reviewed WASM module in the project.
    Wasm {
        /// Module path in the project.
        module: String,
        /// The handler ABI the module speaks.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        abi: Option<String>,
    },
    /// A logical destination bound to a URL and a secret at runtime. The
    /// runtime names the binding it looks the key up in; the project carries
    /// no URL or secret.
    Url {
        /// Key in the runtime destination binding.
        destination_id: String,
    },
}

registry_platform_yaml::tagged_union!(HookHandlerSource);

impl Serialize for HookHandlerSource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let (kind, key, value, abi) = match self {
            Self::Rhai { script, abi } => ("rhai", "script", script, abi.as_ref()),
            Self::Wasm { module, abi } => ("wasm", "module", module, abi.as_ref()),
            Self::Url { destination_id } => ("url", "destinationId", destination_id, None),
        };
        let mut map = serializer.serialize_map(Some(2 + usize::from(abi.is_some())))?;
        map.serialize_entry("type", kind)?;
        map.serialize_entry(key, value)?;
        if let Some(abi) = abi {
            map.serialize_entry("abi", abi)?;
        }
        map.end()
    }
}

impl HookHandlerSource {
    /// The declared handler kind.
    #[must_use]
    pub const fn kind(&self) -> HookHandlerKind {
        match self {
            Self::Rhai { .. } => HookHandlerKind::Rhai,
            Self::Wasm { .. } => HookHandlerKind::Wasm,
            Self::Url { .. } => HookHandlerKind::Url,
        }
    }
}

/// The closed handler-kind vocabulary, carried by a declaration and by the
/// delivery row a declaration compiles into.
///
/// `rhai` and `wasm` are local kinds: the engine holds the reviewed program
/// and runs it in process. `url` is the remote kind: the engine holds no
/// program and the answer arrives over HTTP.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HookHandlerKind {
    /// A reviewed Rhai script in the project.
    Rhai,
    /// A reviewed WASM module in the project.
    Wasm,
    /// A logical destination bound to a URL and a secret at runtime.
    Url,
}

impl HookHandlerKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 3] = [Self::Rhai, Self::Wasm, Self::Url];

    /// The kind's stable spelling, shared by the declaration and the
    /// delivery row.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Rhai => "rhai",
            Self::Wasm => "wasm",
            Self::Url => "url",
        }
    }

    /// The kind named by `spelling`, or `None` when the spelling is outside
    /// the closed vocabulary.
    #[must_use]
    pub fn from_spelling(spelling: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == spelling)
    }

    /// Whether the engine itself holds and runs the handler program.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::Rhai | Self::Wasm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn wasm_handler() -> Value {
        json!({
            "type": "wasm",
            "module": "handlers/birth-followup.wasm",
            "abi": HOOK_HANDLER_ABI_V1,
        })
    }

    fn declaration_json(handler: Value) -> Value {
        json!({
            "id": "birth-registered-followup",
            "phase": "after",
            "trigger": "created",
            "projection": ["givenName", "familyName"],
            "handler": handler,
        })
    }

    #[test]
    fn parses_a_full_declaration_and_round_trips() {
        let declaration = json!({
            "id": "birth-registered-followup",
            "phase": "after",
            "trigger": "created",
            "when": {"type": "fields", "changed": ["familyName"]},
            "projection": ["givenName", "familyName"],
            "handler": wasm_handler(),
        });

        let hook: HookDeclaration = serde_json::from_value(declaration).expect("parses");
        assert_eq!(hook.id, "birth-registered-followup");
        assert_eq!(hook.phase, HookPhase::After);
        assert_eq!(hook.trigger, "created");
        assert_eq!(
            hook.when,
            Some(json!({"type": "fields", "changed": ["familyName"]}))
        );
        assert_eq!(
            hook.projection,
            BTreeSet::from(["givenName".to_owned(), "familyName".to_owned()])
        );
        assert_eq!(
            hook.handler,
            HookHandlerSource::Wasm {
                module: "handlers/birth-followup.wasm".to_owned(),
                abi: Some(HOOK_HANDLER_ABI_V1.to_owned()),
            }
        );
        assert_eq!(
            serde_json::to_value(&hook).expect("serializes"),
            json!({
                "id": "birth-registered-followup",
                "phase": "after",
                "trigger": "created",
                "when": {"type": "fields", "changed": ["familyName"]},
                // The projection is a set, so serialization order is sorted.
                "projection": ["familyName", "givenName"],
                "handler": wasm_handler(),
            })
        );
    }

    #[test]
    fn phase_spelling_is_snake_case() {
        let before: HookPhase = serde_json::from_value(json!("before")).expect("parses");
        let after: HookPhase = serde_json::from_value(json!("after")).expect("parses");
        assert_eq!(before, HookPhase::Before);
        assert_eq!(after, HookPhase::After);
        assert_eq!(before.as_str(), "before");
        assert_eq!(after.as_str(), "after");
        assert!(serde_json::from_value::<HookPhase>(json!("mid")).is_err());
    }

    #[test]
    fn rhai_handler_requires_script_and_nothing_else() {
        let missing: Result<HookHandlerSource, _> =
            serde_json::from_value(json!({"type": "rhai", "abi": HOOK_HANDLER_ABI_V1}));
        assert!(missing.is_err(), "missing script refused");

        let extra: Result<HookHandlerSource, _> = serde_json::from_value(json!({
            "type": "rhai",
            "script": "handlers/followup.rhai",
            "abi": HOOK_HANDLER_ABI_V1,
            "module": "handlers/followup.wasm",
        }));
        assert!(extra.is_err(), "extra module field refused");
    }

    #[test]
    fn wasm_handler_requires_module_and_nothing_else() {
        let missing: Result<HookHandlerSource, _> =
            serde_json::from_value(json!({"type": "wasm", "abi": HOOK_HANDLER_ABI_V1}));
        assert!(missing.is_err(), "missing module refused");

        for extra_field in ["script", "destinationId", "when"] {
            let mut handler = wasm_handler();
            handler[extra_field] = json!("extra");
            let extra: Result<HookHandlerSource, _> = serde_json::from_value(handler);
            assert!(extra.is_err(), "extra {extra_field} field refused");
        }
    }

    #[test]
    fn url_handler_requires_destination_id_and_nothing_else() {
        let missing: Result<HookHandlerSource, _> = serde_json::from_value(json!({"type": "url"}));
        assert!(missing.is_err(), "missing destinationId refused");

        let accepted: HookHandlerSource =
            serde_json::from_value(json!({"type": "url", "destinationId": "case-intake"}))
                .expect("parses");
        assert_eq!(
            accepted,
            HookHandlerSource::Url {
                destination_id: "case-intake".to_owned(),
            }
        );
        assert_eq!(accepted.kind(), HookHandlerKind::Url);

        for extra_field in ["module", "abi"] {
            let extra: Result<HookHandlerSource, _> = serde_json::from_value(json!({
                "type": "url",
                "destinationId": "case-intake",
                extra_field: "extra",
            }));
            assert!(extra.is_err(), "extra {extra_field} field refused");
        }
    }

    #[test]
    fn a_handler_tagged_by_kind_is_refused() {
        let retired: Result<HookHandlerSource, _> =
            serde_json::from_value(json!({"kind": "url", "destinationId": "case-intake"}));
        assert!(retired.is_err(), "a handler names its form under `type`");
    }

    #[test]
    fn unknown_handler_kind_is_refused() {
        let unknown: Result<HookHandlerSource, _> =
            serde_json::from_value(json!({"type": "lambda", "function": "followup"}));
        assert!(unknown.is_err(), "closed kind set refuses unknown kinds");
    }

    #[test]
    fn a_declaration_without_a_principal_round_trips() {
        // The library half of the proposing-hook contract: a hook that
        // declares no principal is a complete declaration. Absence is not an
        // authoring error, parse never refuses it, and the compile-time rules
        // never demand one; the product decides what a proposal from such a
        // hook means, at delivery time.
        let parsed: HookDeclaration = serde_json::from_value(declaration_json(wasm_handler()))
            .expect("a declaration without a principal parses");
        assert_eq!(parsed.principal, None);
        crate::validate_hooks(std::slice::from_ref(&parsed))
            .expect("a missing principal is not a compile-time refusal");
        let mut expected = declaration_json(wasm_handler());
        // The projection is a set, so serialization order is sorted.
        expected["projection"] = json!(["familyName", "givenName"]);
        assert_eq!(
            serde_json::to_value(&parsed).expect("serializes"),
            expected,
            "an absent principal is not written back as a member"
        );
    }

    #[test]
    fn a_declaration_carries_its_principal_opaquely() {
        let mut declaration = declaration_json(wasm_handler());
        declaration["principal"] = json!("case-operations-service");
        let parsed: HookDeclaration = serde_json::from_value(declaration).expect("parses");
        assert_eq!(parsed.principal.as_deref(), Some("case-operations-service"));
        // The value is product vocabulary: any string is carried unchanged,
        // never resolved or validated here, exactly as `trigger` is.
        let mut opaque = declaration_json(wasm_handler());
        opaque["principal"] = json!("not-a-profile-the-library-knows");
        let parsed: HookDeclaration = serde_json::from_value(opaque).expect("parses");
        assert_eq!(
            parsed.principal.as_deref(),
            Some("not-a-profile-the-library-knows")
        );
        let serialized = serde_json::to_value(&parsed).expect("serializes");
        assert_eq!(
            serialized["principal"],
            json!("not-a-profile-the-library-knows"),
            "the principal round-trips byte for byte"
        );
    }

    #[test]
    fn declaration_json_carries_the_abi_opaquely_until_validation() {
        // An unknown ABI string parses: the closed-set check is a compile-time
        // rule with a pinned diagnostic, not a parse accident.
        let mut handler = wasm_handler();
        handler["abi"] = json!("registry.action-handler/v1");
        let parsed: HookDeclaration =
            serde_json::from_value(declaration_json(handler)).expect("parses");
        assert_eq!(
            parsed.handler,
            HookHandlerSource::Wasm {
                module: "handlers/birth-followup.wasm".to_owned(),
                abi: Some("registry.action-handler/v1".to_owned()),
            }
        );
    }

    #[test]
    fn handler_kind_spelling_is_pinned() {
        let rhai: HookHandlerSource = serde_json::from_value(json!({
            "type": "rhai", "script": "handlers/followup.rhai", "abi": HOOK_HANDLER_ABI_V1,
        }))
        .expect("parses");
        assert_eq!(rhai.kind(), HookHandlerKind::Rhai);
        assert_eq!(wasm_handler_serialized().kind(), HookHandlerKind::Wasm);
    }

    fn wasm_handler_serialized() -> HookHandlerSource {
        serde_json::from_value(wasm_handler()).expect("parses")
    }
}
