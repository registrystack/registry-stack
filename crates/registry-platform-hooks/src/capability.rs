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

/// One declared hook as the capability check reads it: its position, its
/// identity, and which optional parts of the declaration it uses.
///
/// A product whose declaration type is not [`HookDeclaration`] builds one of
/// these per hook; `handler` is `None` when the product's shape lets a hook
/// declare no handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HookUse<'a> {
    /// Position of the hook in the product's ordered hook list.
    pub index: usize,
    /// The hook's declared `id`.
    pub id: &'a str,
    /// The declared handler kind, if any.
    pub handler: Option<HookHandlerKind>,
    /// Whether the hook declares a `when` condition.
    pub when: bool,
    /// Whether the hook declares a `principal`.
    pub principal: bool,
}

impl<'a> HookUse<'a> {
    /// The use a shared [`HookDeclaration`] makes, at `index`.
    #[must_use]
    pub fn of(index: usize, declaration: &'a HookDeclaration) -> Self {
        Self {
            index,
            id: &declaration.id,
            handler: Some(declaration.handler.kind()),
            when: declaration.when.is_some(),
            principal: declaration.principal.is_some(),
        }
    }
}

impl HookCapabilities {
    /// Every part of the shared declaration.
    pub const ALL: Self = Self {
        rhai: true,
        wasm: true,
        url: true,
        when: true,
        principal: true,
    };

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

    /// Refuse one declared hook that uses a part of the declaration outside
    /// this set. The handler kind is checked first, then `when`, then
    /// `principal`.
    ///
    /// # Errors
    ///
    /// Returns the first capability the hook uses outside this set.
    pub fn check(self, hook: HookUse<'_>) -> Result<(), HookCapabilityError> {
        let used = [
            hook.handler.map(HookCapability::for_kind),
            hook.when.then_some(HookCapability::When),
            hook.principal.then_some(HookCapability::Principal),
        ];
        match used
            .into_iter()
            .flatten()
            .find(|capability| !self.includes(*capability))
        {
            Some(capability) => Err(HookCapabilityError {
                index: hook.index,
                id: hook.id.to_owned(),
                capability,
            }),
            None => Ok(()),
        }
    }

    /// Refuse the first shared declaration, in declaration order, that uses a
    /// part of the declaration outside this set.
    ///
    /// # Errors
    ///
    /// Returns the first refusal in declaration order.
    pub fn check_declarations(
        self,
        declarations: &[HookDeclaration],
    ) -> Result<(), HookCapabilityError> {
        declarations
            .iter()
            .enumerate()
            .try_for_each(|(index, declaration)| self.check(HookUse::of(index, declaration)))
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
    fn the_full_set_admits_every_part_of_the_declaration() {
        let declarations = [
            declaration(rhai(), true, true),
            declaration(wasm(), true, true),
            declaration(url(), true, true),
        ];
        for declaration in &declarations {
            assert_eq!(
                HookCapabilities::ALL.check(HookUse::of(0, declaration)),
                Ok(())
            );
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
    fn a_hook_without_a_handler_is_checked_only_for_its_condition_and_principal() {
        let set = HookCapabilities {
            when: false,
            ..HookCapabilities::ALL
        };
        let bare = HookUse {
            index: 2,
            id: "silent",
            handler: None,
            when: false,
            principal: true,
        };
        assert_eq!(set.check(bare), Ok(()));
        let conditioned = HookUse { when: true, ..bare };
        assert_eq!(
            set.check(conditioned).map_err(|refusal| refusal.capability),
            Err(HookCapability::When)
        );
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
