// SPDX-License-Identifier: Apache-2.0
//! Product-neutral Review admission and immutable outcome bindings. A request
//! runs the ordinary pinned Workflow; this module adds no execution engine.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use registry_review_protocol::{
    ContentDigest, PolicyBinding, ReviewCreateRequest, ReviewRequestAccepted, ReviewResult,
    ReviewResultStatus,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{definition::Workflow, CoordinatorError, Result};

mod http;
pub(crate) use http::router;

/// An authored terminal Workflow outcome has exactly one Review meaning.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewOutcome {
    /// Shared terminal Review status emitted for this completed Workflow outcome.
    pub status: ReviewResultStatus,
    /// Authored outcome code required for rejected, changes-requested and
    /// answered statuses; omit it for approved, cancelled and superseded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "crate::runtime::optional_external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::ExternalId>")
    )]
    pub outcome: Option<String>,
}

/// Fixed Review meanings and result availability for this Workflow revision.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewPolicy {
    /// Map every declared Workflow outcome exactly once to its Review status
    /// and optional outcome code. Workflow completion alone grants no approval.
    #[serde(deserialize_with = "outcome_keys")]
    #[cfg_attr(feature = "schema", schemars(with = "BTreeMap<registry_platform_yaml::LocalId, ReviewOutcome>", extend("minProperties" = 1, "maxProperties" = 64)))]
    pub outcomes: BTreeMap<String, ReviewOutcome>,
    /// Seconds a terminal Review result remains available after completion.
    /// Defaults to one day; reads and cancellation never renew this window.
    #[serde(default = "retention", deserialize_with = "retention_seconds")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::BoundedU32<1, 31536000>", extend("default" = 86400)))]
    pub result_retention_seconds: u32,
}

fn retention() -> u32 {
    86_400
}

fn retention_seconds<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<u32, D::Error> {
    registry_platform_yaml::BoundedU32::<1, 31536000>::deserialize(d)
        .map(registry_platform_yaml::BoundedU32::get)
}

fn outcome_keys<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<String, ReviewOutcome>, D::Error> {
    BTreeMap::<registry_platform_yaml::LocalId, ReviewOutcome>::deserialize(d).map(|map| {
        map.into_iter()
            .map(|(id, outcome)| (id.into_string(), outcome))
            .collect()
    })
}

impl ReviewPolicy {
    pub(crate) fn check(&self, workflow: &Workflow) -> Result<()> {
        if !(1..=31_536_000).contains(&self.result_retention_seconds)
            || self.outcomes.keys().ne(workflow.outcomes.keys())
        {
            return Err(invalid("map every declared Workflow outcome exactly once and bound resultRetentionSeconds to 1..=31536000"));
        }
        for outcome in self.outcomes.values() {
            let needs_code = matches!(
                outcome.status,
                ReviewResultStatus::Rejected
                    | ReviewResultStatus::ChangesRequested
                    | ReviewResultStatus::Answered
            );
            if needs_code != outcome.outcome.is_some()
                || outcome.outcome.as_ref().is_some_and(|code| {
                    code.trim().is_empty() || code.len() > 128 || code.chars().any(char::is_control)
                })
            {
                return Err(invalid("rejected, changes-requested and answered outcomes require one bounded outcome code; approved, cancelled and superseded outcomes carry none"));
            }
        }
        Ok(())
    }
}

pub fn policy_binding(workflow: &Workflow, revision: &str) -> Result<Option<PolicyBinding>> {
    workflow
        .review
        .as_ref()
        .map(|_| {
            Ok(PolicyBinding {
                id: workflow.id.clone(),
                version: workflow.version.clone(),
                digest: ContentDigest::parse(revision)
                    .map_err(|_| invalid("use the computed Workflow revision"))?,
            })
        })
        .transpose()
}

/// Only a verified client policy supplies producer identity and digest namespace.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewProducer {
    /// Logical producer identity bound to the verified client and included in
    /// the shared request submission digest.
    #[serde(deserialize_with = "crate::runtime::external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub id: String,
    /// Exact producer namespace used to compute the submission digest. This
    /// namespace is independent of the permitted subject source identifiers.
    #[serde(deserialize_with = "crate::runtime::external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub source_namespace: String,
    /// Exact Registry-Review-Profile header value this verified client must
    /// select when creating, reading or cancelling its Review requests.
    #[serde(deserialize_with = "crate::runtime::external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub profile: String,
    /// Subject source identifiers this producer may submit and continue to
    /// access. Removing a source conceals its retained requests and results.
    #[serde(deserialize_with = "crate::runtime::unique_strings")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<registry_platform_yaml::ExternalId>",
            length(min = 1, max = 64)
        )
    )]
    pub sources: Vec<String>,
}

impl ReviewProducer {
    pub(crate) fn check(&self) -> bool {
        [&self.id, &self.source_namespace, &self.profile]
            .iter()
            .all(|text| bounded(text))
            && !self.sources.is_empty()
            && self.sources.len() <= 64
            && self.sources.iter().all(|text| bounded(text))
            && self
                .sources
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.sources.len()
    }
}

fn bounded(text: &str) -> bool {
    !text.trim().is_empty() && text.len() <= 128 && !text.chars().any(char::is_control)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReviewAdmission {
    pub request: ReviewCreateRequest,
    pub producer: ReviewProducer,
    pub policy: ReviewPolicy,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RetainedReview {
    pub accepted: ReviewRequestAccepted,
    pub requester_reference: String,
    pub producer: ReviewProducer,
    pub policy: ReviewPolicy,
    pub result: Option<ReviewResult>,
    pub cancellation: Option<ReviewCancellation>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReviewCancellation {
    pub key_digest: String,
    pub request_digest: String,
}

impl ReviewAdmission {
    pub(crate) fn retain(&self, run: Uuid) -> Result<RetainedReview> {
        let digest = registry_review_protocol::submission_digest(
            &self.producer.id,
            &self.producer.source_namespace,
            &self.request,
        )
        .map_err(|_| invalid("supply a bounded Review request"))?;
        Ok(RetainedReview {
            accepted: ReviewRequestAccepted {
                request_id: run,
                subject: self.request.subject.clone(),
                policy: self.request.policy.clone(),
                submission_digest: digest,
            },
            requester_reference: self.request.requester_reference.clone(),
            producer: self.producer.clone(),
            policy: self.policy.clone(),
            result: None,
            cancellation: None,
        })
    }
}

impl RetainedReview {
    pub(crate) fn terminal(
        &self,
        outcome: &ReviewOutcome,
        completed_at: DateTime<Utc>,
    ) -> Result<ReviewResult> {
        let available_until = completed_at
            .checked_add_signed(Duration::seconds(i64::from(
                self.policy.result_retention_seconds,
            )))
            .ok_or_else(|| invalid("retain a bounded result availability window"))?;
        let result = ReviewResult {
            // The request's unique Run identity anchors its one immutable result.
            result_id: self.accepted.request_id,
            request_id: self.accepted.request_id,
            subject: self.accepted.subject.clone(),
            policy: self.accepted.policy.clone(),
            submission_digest: self.accepted.submission_digest.clone(),
            status: outcome.status,
            outcome: outcome.outcome.clone(),
            result: None,
            completed_at,
            available_until,
        };
        result
            .check()
            .map_err(|_| invalid("retain a protocol-valid terminal outcome"))?;
        Ok(result)
    }
}

fn invalid(advice: &str) -> CoordinatorError {
    CoordinatorError::new(
        "definition.review",
        "the Review provider binding is invalid",
    )
    .at("workflow.yaml", "/workflow/review")
    .suggest(advice)
}
