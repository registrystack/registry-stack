// SPDX-License-Identifier: Apache-2.0

//! The call-plan AST (`products/adapter/CONCEPT.md` section 8.3).
//!
//! One facade operation binds to one declared plan: an ordered list of steps
//! the engine interprets within the request. There are no user-composed
//! pipelines; the plan is part of the reviewed pack, and its shape is
//! checkable offline. Each step names its output binding; later steps
//! reference earlier outputs. Every step kind and budget this module names
//! is a kind or budget the concept names; nothing here is engine logic.

use registry_platform_yaml::LocalId;
use serde::{Deserialize, Serialize};

use crate::model::{FieldMap, ScriptReference};

/// One declared call plan. `budgets` is optional in the authored document so
/// the authoring check can demand its presence explicitly rather than let a
/// silent default bound a deployment; see
/// [`CallPlan::budgets_or_refusal`].
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallPlan {
    /// The ordered steps, each producing a named output binding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<PlanStep>,
    /// The budgets every execution of this plan runs under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budgets: Option<PlanBudgets>,
}

impl CallPlan {
    /// The budgets the engine enforces, or `None` when the authored plan
    /// declared none; the check refuses that shape, so the runtime treats it
    /// as the explicit refusal case it is.
    #[must_use]
    pub const fn budgets_or_refusal(&self) -> Option<&PlanBudgets> {
        self.budgets.as_ref()
    }
}

/// The budgets a plan runs under (`products/adapter/CONCEPT.md` section
/// 8.3). Every member is required; the engine refuses at budget with the
/// bounded problem and the journal stays complete.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanBudgets {
    /// The most upstream calls one execution may make, counting every
    /// per-item execution an `iterate` split performs.
    pub maximum_upstream_calls: u32,
    /// The most upstream response bytes one execution may read.
    pub maximum_response_bytes: u64,
    /// The most wall-clock time one execution may take, in milliseconds.
    pub deadline_milliseconds: u64,
    /// The most time one upstream attempt may take, in milliseconds.
    pub attempt_timeout_milliseconds: u64,
}

/// One step of a call plan. The kind tag is the engine vocabulary; Camel
/// names are kept where a pattern is ported (`products/adapter/CONCEPT.md`
/// section 8.3).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PlanStep {
    /// One upstream request built from a declared call template of the pack.
    Call(CallStep),
    /// Declarative field mapping plus an optional script seam; the output is
    /// validated against the declared model before it can bind a name.
    Map(MapStep),
    /// A secondary call whose result merges into the working document by a
    /// declared reference. Content-enricher semantics: an enrichment failure
    /// is the operation's failure.
    Enrich(EnrichStep),
    /// Merge differently shaped upstream branches into the one declared
    /// model. Totality is checked offline.
    Normalize(NormalizeStep),
    /// Cursor walk over a declared page shape, bounded by the pagination
    /// plan the pack declares.
    Paginate(PaginateStep),
    /// Bounded split of one declared array, under a per-item policy.
    Iterate(IterateStep),
}

impl PlanStep {
    /// The binding name this step produces.
    #[must_use]
    pub fn output(&self) -> &str {
        match self {
            Self::Call(step) => &step.output,
            Self::Map(step) => &step.output,
            Self::Enrich(step) => &step.output,
            Self::Normalize(step) => &step.output,
            Self::Paginate(step) => &step.output,
            Self::Iterate(step) => &step.output,
        }
    }

    /// The earlier binding this step consumes, if it consumes one.
    #[must_use]
    pub fn input(&self) -> Option<&str> {
        match self {
            Self::Call(step) => step.input.as_deref(),
            Self::Map(step) => Some(&step.input),
            Self::Enrich(step) => Some(&step.input),
            Self::Normalize(step) => Some(&step.input),
            Self::Paginate(step) => Some(&step.input),
            Self::Iterate(step) => Some(&step.input),
        }
    }

    /// The call template this step names, if it makes an upstream call.
    #[must_use]
    pub const fn template(&self) -> Option<&LocalId> {
        match self {
            Self::Call(step) => Some(&step.template),
            Self::Enrich(step) => Some(&step.template),
            _ => None,
        }
    }

    /// The iterate step this step is, if it is one.
    #[must_use]
    pub const fn as_iterate(&self) -> Option<&IterateStep> {
        match self {
            Self::Iterate(step) => Some(step),
            _ => None,
        }
    }
}

/// One upstream request built from the pack's call template named
/// `template`. `input`, when declared, is the binding whose value fills the
/// template's placeholders; absent, the facade request's parameters fill
/// them.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallStep {
    /// The call template the request is built from.
    pub template: LocalId,
    /// The binding whose value fills the template's placeholders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    /// The binding name this step produces.
    pub output: String,
}

/// Declarative field mapping over the binding `input`, producing `output`.
/// The output is validated against the declared model before it binds.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MapStep {
    /// The binding this step maps.
    pub input: String,
    /// The declared field mappings.
    pub field_map: FieldMap,
    /// The binding name this step produces.
    pub output: String,
}

/// A secondary call over the template named `template`, whose result merges
/// into the working document `input` by the declared reference field `join`.
/// Content-enricher semantics: enrichment failure is the operation's
/// failure; there is no optional-skip enrichment in v1.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrichStep {
    /// The call template the secondary request is built from.
    pub template: LocalId,
    /// The declared reference field linking the working document to the
    /// secondary result.
    pub join: LocalId,
    /// The working document the result merges into.
    pub input: String,
    /// The binding name this step produces.
    pub output: String,
}

/// A selector script picks one declared branch; the branch merges the
/// differently shaped upstream document `input` into the one declared model
/// as `output`. Totality is checked offline: every declared branch must
/// produce the model.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizeStep {
    /// The binding this step normalizes.
    pub input: String,
    /// The script seam that names the branch the document took.
    pub selector: ScriptReference,
    /// The declared branches; at least one.
    pub branches: Vec<NormalizeBranch>,
    /// The binding name this step produces.
    pub output: String,
}

/// One declared branch of a normalize step. A branch produces the declared
/// model through its field map, its script seam, or both.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizeBranch {
    /// The branch identifier the selector script may name.
    pub id: LocalId,
    /// The declared field mappings this branch applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_map: Option<FieldMap>,
    /// The script seam this branch applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<ScriptReference>,
}

/// Cursor walk over the pagination plan the pack declares, bounded by the
/// plan's `maximumPages` and `maximumItems`. Duplicate or shifting pages
/// fail the operation rather than silently merging.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginateStep {
    /// The binding holding the first page.
    pub input: String,
    /// The pagination plan the walk follows.
    pub pagination_plan: LocalId,
    /// The binding name this step produces.
    pub output: String,
}

/// Bounded split of one declared array, under a per-item policy
/// (`products/adapter/CONCEPT.md` section 8.3). Per-item execution counts
/// against the plan budget. The policy is optional in the authored document
/// so the check can demand its explicit presence; the engine default is
/// [`ItemPolicy::StopOnFirstFailure`].
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IterateStep {
    /// The binding holding the declared array to split.
    pub input: String,
    /// The per-item policy. Absent in the document, the check refuses and
    /// the engine default applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<ItemPolicy>,
    /// The binding name this step produces.
    pub output: String,
}

impl IterateStep {
    /// The policy the engine runs this split under: the authored policy, or
    /// the default when the document declared none.
    #[must_use]
    pub fn policy_or_default(&self) -> ItemPolicy {
        self.policy.unwrap_or_default()
    }
}

/// What happens to the items after the first failing item of an iterate
/// split. `stopOnFirstFailure` is the default and the only policy for
/// writes; `continueAndReport` accounts every item in the response as
/// succeeded or failed with a bounded problem code.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemPolicy {
    #[default]
    StopOnFirstFailure,
    ContinueAndReport,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_steps_tag_their_kind() {
        let step = PlanStep::Iterate(IterateStep {
            input: "page".to_string(),
            policy: None,
            output: "results".to_string(),
        });
        let json = serde_json::to_string(&step).expect("serialize");
        assert!(json.contains("\"kind\":\"iterate\""));
        assert!(json.contains("\"input\":\"page\""));
        let round: PlanStep = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round, step);
    }

    #[test]
    fn iterate_defaults_to_stop_on_first_failure() {
        let step = IterateStep {
            input: "page".to_string(),
            policy: None,
            output: "results".to_string(),
        };
        assert_eq!(step.policy_or_default(), ItemPolicy::StopOnFirstFailure);
        let json = serde_json::to_string(&step).expect("serialize");
        assert!(!json.contains("policy"), "an absent policy stays absent");
    }

    #[test]
    fn budgets_carry_every_declared_bound() {
        let json = serde_json::json!({
            "maximumUpstreamCalls": 12,
            "maximumResponseBytes": 1_000_000,
            "deadlineMilliseconds": 5_000,
            "attemptTimeoutMilliseconds": 1_000
        });
        let budgets: PlanBudgets = serde_json::from_value(json).expect("deserialize");
        assert_eq!(budgets.maximum_upstream_calls, 12);
        assert_eq!(budgets.attempt_timeout_milliseconds, 1_000);
    }

    #[test]
    fn step_accessors_expose_declared_names() {
        let call = PlanStep::Call(CallStep {
            template: LocalId::new("search").expect("id"),
            input: None,
            output: "page".to_string(),
        });
        assert_eq!(call.output(), "page");
        assert_eq!(call.input(), None);
        assert!(call.template().is_some());
        assert!(call.as_iterate().is_none());
    }
}
