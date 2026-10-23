// SPDX-License-Identifier: Apache-2.0

//! The product-declared capability set: which parts of the shared declaration
//! a product can run.
//!
//! The declaration shape is shared, so a product that runs only part of it
//! must refuse the rest at load time instead of accepting a hook it would
//! silently ignore. A product states once which handler kinds it runs and
//! whether it evaluates `when` conditions and resolves a `principal`; this
//! module refuses a declared hook outside that set with one shared
//! diagnostic, so every product reports the same refusal for the same
//! declaration.

use thiserror::Error;

use crate::declaration::{HookDeclaration, HookHandlerKind};

/// One part of the shared declaration a product may or may not run.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HookCapability {
    /// A `rhai` handler.
    RhaiHandler,
    /// A `wasm` handler.
    WasmHandler,
    /// A `url` handler.
    UrlHandler,
    /// A `when` condition.
    When,
    /// A `principal` a proposal is applied under.
    Principal,
}

impl HookCapability {
    /// The capability's stable spelling, as it appears in the diagnostic.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RhaiHandler => "handler.rhai",
            Self::WasmHandler => "handler.wasm",
            Self::UrlHandler => "handler.url",
            Self::When => "when",
            Self::Principal => "principal",
        }
    }

    const fn for_kind(kind: HookHandlerKind) -> Self {
        match kind {
            HookHandlerKind::Rhai => Self::RhaiHandler,
            HookHandlerKind::Wasm => Self::WasmHandler,
            HookHandlerKind::Url => Self::UrlHandler,
        }
    }
}

/// The parts of the shared declaration one product runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct HookCapabilities {
    /// Runs `rhai` handlers.
    pub rhai: bool,
    /// Runs `wasm` handlers.
    pub wasm: bool,
    /// Runs `url` handlers.
    pub url: bool,
    /// Evaluates `when` conditions.
    pub when: bool,
    /// Resolves a `principal` for proposals.
    pub principal: bool,
}

impl HookCapabilities {
    /// `url` handlers only, with no conditions and no principals.
    pub const URL_ONLY: Self = Self {
        rhai: false,
        wasm: false,
        url: true,
        when: false,
        principal: false,
    };

    /// Whether this set includes `capability`.
    #[must_use]
    pub const fn includes(self, capability: HookCapability) -> bool {
        match capability {
            HookCapability::RhaiHandler => self.rhai,
            HookCapability::WasmHandler => self.wasm,
            HookCapability::UrlHandler => self.url,
            HookCapability::When => self.when,
            HookCapability::Principal => self.principal,
        }
    }

    /// Refuse the first shared declaration, in declaration order, that uses a
    /// part of the declaration outside this set. The handler kind is checked
    /// first, then `when`, then `principal`.
    ///
    /// # Errors
    ///
    /// Returns the first refusal in declaration order.
    pub fn check_declarations(
        self,
        declarations: &[HookDeclaration],
    ) -> Result<(), HookCapabilityError> {
        for (index, declaration) in declarations.iter().enumerate() {
            let used = [
                Some(HookCapability::for_kind(declaration.handler.kind())),
                declaration.when.is_some().then_some(HookCapability::When),
                declaration
                    .principal
                    .is_some()
                    .then_some(HookCapability::Principal),
            ];
            if let Some(capability) = used
                .into_iter()
                .flatten()
                .find(|capability| !self.includes(*capability))
            {
                return Err(HookCapabilityError {
                    index,
                    id: declaration.id.clone(),
                    capability,
                });
            }
        }
        Ok(())
    }
}

/// A declared hook uses a part of the shared declaration the product does not
/// run.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error(
    "hook {index} ({id}): `{}` is outside the hook capabilities this product runs",
    capability.as_str()
)]
pub struct HookCapabilityError {
    /// Position of the refused hook.
    pub index: usize,
    /// The refused hook's `id`.
    pub id: String,
    /// The capability the hook uses outside the product's set.
    pub capability: HookCapability,
}

impl HookCapabilityError {
    /// The one stable diagnostic code for every capability refusal.
    pub const CODE: &'static str = "hook.capability.unsupported";

    /// The stable diagnostic code for this refusal.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        Self::CODE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declaration::{HookHandlerSource, HookPhase, HOOK_HANDLER_ABI_V1};
    use serde_json::json;

    fn declaration(handler: HookHandlerSource, when: bool, principal: bool) -> HookDeclaration {
        HookDeclaration {
            id: "followup".to_owned(),
            phase: HookPhase::After,
            trigger: "created".to_owned(),
            when: when.then(|| json!({"type": "fields"})),
            principal: principal.then(|| "clerk".to_owned()),
            projection: std::collections::BTreeSet::new(),
            handler,
        }
    }

    fn url() -> HookHandlerSource {
        HookHandlerSource::Url {
            destination_id: "partner".to_owned(),
        }
    }

    fn rhai() -> HookHandlerSource {
        HookHandlerSource::Rhai {
            script: "hooks/followup.rhai".to_owned(),
            abi: Some(HOOK_HANDLER_ABI_V1.to_owned()),
        }
    }

    fn wasm() -> HookHandlerSource {
        HookHandlerSource::Wasm {
            module: "hooks/followup.wasm".to_owned(),
            abi: Some(HOOK_HANDLER_ABI_V1.to_owned()),
        }
    }

    #[test]
    fn the_url_only_set_admits_a_bare_url_hook() {
        assert_eq!(
            HookCapabilities::URL_ONLY.check_declarations(&[declaration(url(), false, false)]),
            Ok(())
        );
    }

    #[test]
    fn the_url_only_set_refuses_each_other_part_with_the_one_shared_diagnostic() {
        let cases = [
            (
                declaration(rhai(), false, false),
                HookCapability::RhaiHandler,
            ),
            (
                declaration(wasm(), false, false),
                HookCapability::WasmHandler,
            ),
            (declaration(url(), true, false), HookCapability::When),
            (declaration(url(), false, true), HookCapability::Principal),
        ];
        for (declaration, capability) in cases {
            let refusal = HookCapabilities::URL_ONLY
                .check_declarations(&[declaration])
                .expect_err("outside the set");
            assert_eq!(refusal.capability, capability);
            assert_eq!(refusal.code(), "hook.capability.unsupported");
            assert_eq!(refusal.index, 0);
            assert_eq!(refusal.id, "followup");
            assert_eq!(
                refusal.to_string(),
                format!(
                    "hook 0 (followup): `{}` is outside the hook capabilities this product runs",
                    capability.as_str()
                )
            );
        }
    }

    #[test]
    fn the_handler_kind_is_reported_before_the_condition_and_the_principal() {
        let refusal = HookCapabilities::URL_ONLY
            .check_declarations(&[
                declaration(url(), false, false),
                declaration(rhai(), true, true),
            ])
            .expect_err("second hook is outside the set");
        assert_eq!(refusal.index, 1);
        assert_eq!(refusal.capability, HookCapability::RhaiHandler);
    }
}
