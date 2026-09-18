// SPDX-License-Identifier: Apache-2.0

//! Compile-time (load-time) hook rules, in the "refuse what cannot run" style:
//! a declared hook that could never run is refused with a pinned diagnostic
//! instead of being accepted and silently doing nothing.
//!
//! These rules run when a product loads its project configuration, before any
//! transaction, delivery, or handler exists.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::declaration::{HookDeclaration, HookHandlerSource, HookPhase, HOOK_HANDLER_ABI_V1};

/// Refuse any declaration that could never run, in declaration order.
///
/// The rules, mirroring the design note's compile-time list:
///
/// - Every hook has an explicit, nonempty, unique `id`. Duplicate ids are
///   refused document-wide, across triggers.
/// - `phase: before` with a `url` handler is refused: a remote call inside the
///   triggering transaction holds row locks.
/// - `rhai` and `wasm` handlers must declare the one ABI version one defines;
///   `url` handlers must not declare an `abi` at all, which the declaration
///   shape already refuses at parse time.
///
/// Trigger validity, `when` validity, projection validity, and message
/// contents are product rules and are deliberately not here.
///
/// # Errors
///
/// Returns the first violation in declaration order.
pub fn validate_hooks(hooks: &[HookDeclaration]) -> Result<(), HookValidationError> {
    let mut seen_ids = BTreeSet::new();
    for (index, hook) in hooks.iter().enumerate() {
        if hook.id.is_empty() {
            return Err(HookValidationError::EmptyHookId { index });
        }
        if !seen_ids.insert(hook.id.as_str()) {
            return Err(HookValidationError::DuplicateHookId {
                index,
                id: hook.id.clone(),
            });
        }
        if hook.phase == HookPhase::Before && matches!(hook.handler, HookHandlerSource::Url { .. })
        {
            return Err(HookValidationError::BeforePhaseRemoteHandler {
                index,
                id: hook.id.clone(),
            });
        }
        let required_abi = match &hook.handler {
            HookHandlerSource::Rhai { abi, .. } | HookHandlerSource::Wasm { abi, .. } => abi,
            // A `url` handler carries no `abi`; the declaration shape refuses
            // one at parse time.
            HookHandlerSource::Url { .. } => continue,
        };
        match required_abi.as_deref() {
            None => {
                return Err(HookValidationError::AbiMissing {
                    index,
                    id: hook.id.clone(),
                    kind: hook.handler.kind(),
                    required_abi: HOOK_HANDLER_ABI_V1,
                });
            }
            Some(abi) if abi != HOOK_HANDLER_ABI_V1 => {
                return Err(HookValidationError::AbiUnknown {
                    index,
                    id: hook.id.clone(),
                    abi: abi.to_owned(),
                    required_abi: HOOK_HANDLER_ABI_V1,
                });
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// A compile-time refusal with a pinned, machine-readable code.
///
/// Codes are part of the contract: operators and products match on them, so
/// existing codes never change meaning and new refusals get new codes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum HookValidationError {
    /// A hook declared an empty `id`.
    #[error("hook {index}: hook id must not be empty")]
    EmptyHookId { index: usize },
    /// Two hooks declared the same `id`.
    #[error(
        "hook {index} ({id}): duplicate hook id; ids are unique document-wide and \
         declaration order is the execution order"
    )]
    DuplicateHookId { index: usize, id: String },
    /// `phase: before` with a `url` handler.
    #[error(
        "hook {index} ({id}): phase `before` refuses a `url` handler; a remote call \
         inside the triggering transaction holds row locks"
    )]
    BeforePhaseRemoteHandler { index: usize, id: String },
    /// A `rhai` or `wasm` handler declared no `abi`.
    #[error(
        "hook {index} ({id}): {kind} handler requires abi `{required_abi}`; version one \
         defines no other ABI"
    )]
    AbiMissing {
        index: usize,
        id: String,
        kind: &'static str,
        required_abi: &'static str,
    },
    /// A `rhai` or `wasm` handler declared an `abi` outside the closed set.
    #[error(
        "hook {index} ({id}): unknown handler abi `{abi}`; version one defines only \
         `{required_abi}`"
    )]
    AbiUnknown {
        index: usize,
        id: String,
        abi: String,
        required_abi: &'static str,
    },
}

impl HookValidationError {
    /// The stable diagnostic code for this refusal.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyHookId { .. } => "hook.id_empty",
            Self::DuplicateHookId { .. } => "hook.id_duplicate",
            Self::BeforePhaseRemoteHandler { .. } => "hook.before_phase_remote_handler",
            Self::AbiMissing { .. } => "hook.abi_missing",
            Self::AbiUnknown { .. } => "hook.abi_unknown",
        }
    }

    /// The hook index the refusal points at, if the refusal is about one hook.
    #[must_use]
    pub const fn index(&self) -> Option<usize> {
        match self {
            Self::EmptyHookId { index }
            | Self::DuplicateHookId { index, .. }
            | Self::BeforePhaseRemoteHandler { index, .. }
            | Self::AbiMissing { index, .. }
            | Self::AbiUnknown { index, .. } => Some(*index),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declaration::{HookHandlerSource, HookPhase};
    use serde_json::json;

    fn handler_with_abi(abi: Option<&str>) -> HookHandlerSource {
        HookHandlerSource::Wasm {
            module: "handlers/followup.wasm".to_owned(),
            abi: abi.map(str::to_owned),
        }
    }

    fn declaration(
        id: &str,
        phase: HookPhase,
        trigger: &str,
        handler: HookHandlerSource,
    ) -> HookDeclaration {
        serde_json::from_value(json!({
            "id": id,
            "phase": phase,
            "trigger": trigger,
            "projection": [],
            "handler": handler,
        }))
        .expect("declaration fixture parses")
    }

    fn valid_hook(id: &str) -> HookDeclaration {
        declaration(
            id,
            HookPhase::After,
            "created",
            handler_with_abi(Some(HOOK_HANDLER_ABI_V1)),
        )
    }

    #[test]
    fn accepts_an_ordered_document_of_runnable_hooks() {
        let hooks = [
            valid_hook("birth-registered-followup"),
            declaration(
                "name-patched",
                HookPhase::Before,
                "patched",
                HookHandlerSource::Rhai {
                    script: "handlers/guard.rhai".to_owned(),
                    abi: Some(HOOK_HANDLER_ABI_V1.to_owned()),
                },
            ),
            declaration(
                "case-intake",
                HookPhase::After,
                "request_lifecycle",
                HookHandlerSource::Url {
                    destination_id: "case-intake".to_owned(),
                },
            ),
        ];
        validate_hooks(&hooks).expect("all three kinds are runnable");
    }

    #[test]
    fn refuses_before_phase_with_a_url_handler() {
        let hooks = [declaration(
            "remote-guard",
            HookPhase::Before,
            "patched",
            HookHandlerSource::Url {
                destination_id: "case-intake".to_owned(),
            },
        )];
        let error = validate_hooks(&hooks).expect_err("remote call cannot hold row locks");
        assert_eq!(
            error,
            HookValidationError::BeforePhaseRemoteHandler {
                index: 0,
                id: "remote-guard".to_owned(),
            }
        );
        assert_eq!(error.code(), "hook.before_phase_remote_handler");
        assert!(error.to_string().contains("row locks"), "{error}");
    }

    #[test]
    fn allows_after_phase_with_a_url_handler() {
        let hooks = [declaration(
            "case-intake",
            HookPhase::After,
            "created",
            HookHandlerSource::Url {
                destination_id: "case-intake".to_owned(),
            },
        )];
        validate_hooks(&hooks).expect("after-phase url hooks run in the worker");
    }

    #[test]
    fn refuses_duplicate_ids_across_triggers() {
        let hooks = [
            valid_hook("followup"),
            valid_hook("followup"),
            declaration(
                "followup",
                HookPhase::Before,
                "patched",
                HookHandlerSource::Rhai {
                    script: "handlers/guard.rhai".to_owned(),
                    abi: Some(HOOK_HANDLER_ABI_V1.to_owned()),
                },
            ),
        ];
        let error = validate_hooks(&hooks).expect_err("duplicate id refused");
        assert_eq!(
            error,
            HookValidationError::DuplicateHookId {
                index: 1,
                id: "followup".to_owned(),
            }
        );
        assert_eq!(error.code(), "hook.id_duplicate");
        assert_eq!(error.index(), Some(1));
    }

    #[test]
    fn refuses_an_empty_hook_id() {
        let hooks = [valid_hook("")];
        let error = validate_hooks(&hooks).expect_err("empty id refused");
        assert_eq!(error, HookValidationError::EmptyHookId { index: 0 });
        assert_eq!(error.code(), "hook.id_empty");
    }

    #[test]
    fn refuses_rhai_and_wasm_handlers_without_an_abi() {
        for (kind, handler) in [
            (
                "rhai",
                HookHandlerSource::Rhai {
                    script: "handlers/guard.rhai".to_owned(),
                    abi: None,
                },
            ),
            ("wasm", handler_with_abi(None)),
        ] {
            let hooks = [declaration(
                "followup",
                HookPhase::After,
                "created",
                handler,
            )];
            let error = validate_hooks(&hooks).expect_err("missing abi refused");
            assert_eq!(
                error,
                HookValidationError::AbiMissing {
                    index: 0,
                    id: "followup".to_owned(),
                    kind,
                    required_abi: HOOK_HANDLER_ABI_V1,
                }
            );
            assert_eq!(error.code(), "hook.abi_missing");
        }
    }

    #[test]
    fn refuses_abi_values_outside_the_closed_set() {
        for abi in [
            "registry.action-handler/v1",
            "registry.hook-handler/v2",
            "registry.scheduling-hook/v1",
        ] {
            let hooks = [declaration(
                "followup",
                HookPhase::After,
                "created",
                handler_with_abi(Some(abi)),
            )];
            let error = validate_hooks(&hooks).expect_err("unknown abi refused");
            assert_eq!(
                error,
                HookValidationError::AbiUnknown {
                    index: 0,
                    id: "followup".to_owned(),
                    abi: abi.to_owned(),
                    required_abi: HOOK_HANDLER_ABI_V1,
                }
            );
            assert_eq!(error.code(), "hook.abi_unknown");
        }
    }

    #[test]
    fn the_one_abi_value_is_accepted_on_both_local_kinds() {
        let hooks = [
            declaration(
                "rhai-hook",
                HookPhase::Before,
                "patched",
                HookHandlerSource::Rhai {
                    script: "handlers/guard.rhai".to_owned(),
                    abi: Some(HOOK_HANDLER_ABI_V1.to_owned()),
                },
            ),
            valid_hook("wasm-hook"),
        ];
        validate_hooks(&hooks).expect("the version-one ABI is the supported one");
    }

    #[test]
    fn the_first_violation_in_declaration_order_is_the_one_reported() {
        // Two hooks violate two different rules. Declaration order decides
        // which refusal is reported, not the order the rules are checked in,
        // so the same pair reports the other hook when it comes first.
        let remote_before = declaration(
            "remote-guard",
            HookPhase::Before,
            "patched",
            HookHandlerSource::Url {
                destination_id: "case-intake".to_owned(),
            },
        );
        let unknown_abi = declaration(
            "stale-abi",
            HookPhase::After,
            "created",
            handler_with_abi(Some("registry.hook-handler/v2")),
        );

        let error = validate_hooks(&[
            valid_hook("runnable"),
            remote_before.clone(),
            unknown_abi.clone(),
        ])
        .expect_err("the second hook is refused");
        assert_eq!(error.code(), "hook.before_phase_remote_handler");
        assert_eq!(error.index(), Some(1));

        let error = validate_hooks(&[valid_hook("runnable"), unknown_abi, remote_before])
            .expect_err("the second hook is refused");
        assert_eq!(error.code(), "hook.abi_unknown");
        assert_eq!(error.index(), Some(1));
    }

    #[test]
    fn before_phase_accepts_a_wasm_handler() {
        let hooks = [declaration(
            "in-transaction-guard",
            HookPhase::Before,
            "patched",
            handler_with_abi(Some(HOOK_HANDLER_ABI_V1)),
        )];
        validate_hooks(&hooks).expect("a local kind runs inside the transaction");
    }

    #[test]
    fn every_validation_code_is_distinct_and_in_its_namespace() {
        let variants = [
            HookValidationError::EmptyHookId { index: 0 },
            HookValidationError::DuplicateHookId {
                index: 0,
                id: String::new(),
            },
            HookValidationError::BeforePhaseRemoteHandler {
                index: 0,
                id: String::new(),
            },
            HookValidationError::AbiMissing {
                index: 0,
                id: String::new(),
                kind: "wasm",
                required_abi: HOOK_HANDLER_ABI_V1,
            },
            HookValidationError::AbiUnknown {
                index: 0,
                id: String::new(),
                abi: String::new(),
                required_abi: HOOK_HANDLER_ABI_V1,
            },
        ];
        let codes: Vec<&str> = variants.iter().map(HookValidationError::code).collect();
        assert_eq!(
            codes.iter().collect::<BTreeSet<_>>().len(),
            codes.len(),
            "codes are distinct: {codes:?}"
        );
        for code in codes {
            assert!(code.starts_with("hook."), "{code} is outside the namespace");
        }
    }

    #[test]
    fn the_abi_constant_is_pinned() {
        assert_eq!(HOOK_HANDLER_ABI_V1, "registry.hook-handler/v1");
    }
}
