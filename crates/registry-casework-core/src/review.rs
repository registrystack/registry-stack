use std::{cmp::Ordering, collections::BTreeMap, fmt};

use chrono::{DateTime, Utc};
use jsonschema::{Draft, JSONSchema};
use registry_review_protocol::{
    check_public_reason, ContentDigest, PolicyBinding, ReviewResultStatus, SubjectBinding,
    MAXIMUM_PUBLIC_REASON_BYTES,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::finding::{ConfigFinding, Findings, IDENTIFIER_ACTION, IDENTIFIER_MESSAGE};
use crate::{ClockPolicy, IssuerPrincipal};

pub const MAXIMUM_REVIEW_POLICIES: usize = 64;
pub const MAXIMUM_REVIEW_RETENTION_DAYS: u32 = 3_650;
/// The longest a producer's submission receipt is kept for its recovery.
pub const MAXIMUM_RECEIPT_RETENTION_DAYS: u32 = 365;
pub const MAXIMUM_REVIEW_STAGES: usize = 32;
pub const MAXIMUM_REVIEW_PROFILES_PER_STAGE: usize = 32;
pub const MAXIMUM_REVIEW_APPROVALS_PER_STAGE: u16 = 32;
/// The canonical snapshot envelope stored with every accepted review request.
///
/// The closure includes bounded schemas, stage rules, and every behavioral
/// dependency. Its complete canonical encoding is limited to 256 KiB.
pub const MAXIMUM_REVIEW_POLICY_CLOSURE_BYTES: usize = 256 * 1024;

const MAXIMUM_REVIEW_OUTCOMES: usize = 16;
const MAXIMUM_REVIEW_POLICY_CLOCKS: usize = 32;
const MAXIMUM_REVIEW_SCHEMA_BYTES: usize = 64 * 1024;
/// The most bytes a review display holds, as canonical JSON.
pub const MAXIMUM_REVIEW_DISPLAY_BYTES: usize = 16 * 1024;
/// The deepest a review display or result nests.
pub const MAXIMUM_REVIEW_VALUE_DEPTH: usize = 16;
pub const MAXIMUM_REVIEW_REASON_BYTES: usize = 2_000;
pub const MAXIMUM_REVIEW_DRAFT_BYTES: usize = 16 * 1024;
const MAXIMUM_REVIEW_RESULT_BYTES: usize = 16 * 1024;
const MAXIMUM_REVIEW_RESULT_CONSTRAINTS_BYTES: usize = 16 * 1024;
const MAXIMUM_REVIEW_CONSTRAINT_CHOICES: usize = 64;
const MAXIMUM_REVIEW_CONSTRAINT_TITLE_CHARS: usize = 120;

const RESULT_PATH: &str = "$.result";
const PUBLIC_REASON_PATH: &str = "$.publicReason";
const RESULT_CONSTRAINTS_PATH: &str = "$.resultConstraints";

pub type ReviewPolicyDigest = ContentDigest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewRetentionPolicy {
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_REVIEW_RETENTION_DAYS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_REVIEW_RETENTION_DAYS>")
    )]
    pub terminal_retention_days: u32,
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_REVIEW_RETENTION_DAYS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_REVIEW_RETENTION_DAYS>")
    )]
    pub accountability_retention_days: u32,
}

impl ReviewRetentionPolicy {
    /// The reader refuses a file whose days are out of range; these findings
    /// hold the same bounds for a policy built in code.
    fn findings(&self, findings: &mut Findings) {
        let message =
            format!("expected a whole number of days from 1 to {MAXIMUM_REVIEW_RETENTION_DAYS}");
        if self.terminal_retention_days == 0
            || self.terminal_retention_days > MAXIMUM_REVIEW_RETENTION_DAYS
        {
            findings.push(
                "casework.review-policy.retention-out-of-range",
                "/retention/terminalRetentionDays",
                message.as_str(),
                "Write a number of days within the bound.",
            );
        }
        if self.accountability_retention_days > MAXIMUM_REVIEW_RETENTION_DAYS {
            findings.push(
                "casework.review-policy.retention-out-of-range",
                "/retention/accountabilityRetentionDays",
                message.as_str(),
                "Write a number of days within the bound.",
            );
        } else if self.accountability_retention_days < self.terminal_retention_days {
            findings.add(
                ConfigFinding::new(
                    "casework.review-policy.accountability-before-terminal",
                    "/retention/accountabilityRetentionDays",
                    "accountabilityRetentionDays is shorter than terminalRetentionDays",
                    "Make accountabilityRetentionDays at least as long as terminalRetentionDays.",
                )
                .with_related(
                    "/retention/terminalRetentionDays",
                    "terminalRetentionDays is written here",
                ),
            );
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "scope",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReviewClockCorrelation {
    /// A subject clock covers one request. The correlation names the subject
    /// the request reviews; the budget is the request's own, and a
    /// resubmission starts a new one.
    Subject {
        source: String,
        subject_type: String,
        id: String,
    },
    Activity {
        task_id: Uuid,
        stage_id: String,
    },
}

impl ReviewClockCorrelation {
    #[must_use]
    pub fn for_policy(
        policy: &ClockPolicy,
        subject: &SubjectBinding,
        task_id: Uuid,
        stage_id: &str,
    ) -> Self {
        match policy {
            ClockPolicy::Subject { .. } => Self::Subject {
                source: subject.source.clone(),
                subject_type: subject.subject_type.clone(),
                id: subject.id.clone(),
            },
            ClockPolicy::Stage { .. } => Self::Activity {
                task_id,
                stage_id: stage_id.to_owned(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewPurpose {
    Approval,
    Answer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewOutcomeSettlement {
    Approved,
    Rejected,
    ChangesRequested,
    Answered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewOutcomePolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[serde(deserialize_with = "registry_platform_yaml::display_text")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::DisplayText")
    )]
    pub label: String,
    pub settlement: ReviewOutcomeSettlement,
    pub reason_required: bool,
    /// Whether a decision with this outcome gives text for release to the
    /// subject's owner. There is no default: the policy author decides what
    /// an applicant is told.
    pub public_reason: ReviewPublicReasonRule,
    #[serde(default, skip_serializing_if = "is_false")]
    pub result_required: bool,
}

/// Whether a decision gives a public reason with an outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewPublicReasonRule {
    Required,
    Optional,
    None,
}

impl ReviewOutcomePolicy {
    fn label_is_valid(&self) -> bool {
        !self.label.trim().is_empty()
            && self.label.len() <= 120
            && self.label.chars().all(|character| !character.is_control())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewStagePolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub queue: String,
    pub deciding_profiles: Vec<String>,
    #[serde(
        deserialize_with = "crate::typed::bounded_u16::<_, 1, { MAXIMUM_REVIEW_APPROVALS_PER_STAGE as u32 }>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::BoundedU32<1, { MAXIMUM_REVIEW_APPROVALS_PER_STAGE as u32 }>"
        )
    )]
    pub required_approvals: u16,
    #[serde(default)]
    pub exclude_initiator: bool,
    #[serde(default)]
    pub exclude_previous_stage_reviewers: bool,
}

impl ReviewStagePolicy {
    /// Identity findings and threshold findings, relative to `at`. The
    /// reader refuses a file whose threshold is out of range; the threshold
    /// findings hold the same bound for a policy built in code.
    fn findings(&self, at: &str) -> (Findings, Findings) {
        let mut identity = Findings::default();
        if !valid_identifier(&self.id) {
            identity.push(
                "casework.review-policy.invalid-stage-id",
                format!("{at}/id"),
                IDENTIFIER_MESSAGE,
                IDENTIFIER_ACTION,
            );
        }
        if !valid_identifier(&self.queue) {
            identity.push(
                "casework.review-policy.invalid-stage-queue",
                format!("{at}/queue"),
                IDENTIFIER_MESSAGE,
                IDENTIFIER_ACTION,
            );
        }
        if self.deciding_profiles.is_empty() {
            identity.push(
                "casework.review-policy.no-deciding-profiles",
                format!("{at}/decidingProfiles"),
                "a stage needs at least one deciding access profile",
                "List the staff or supervisor access profiles that decide this stage.",
            );
        }
        if self.deciding_profiles.len() > MAXIMUM_REVIEW_PROFILES_PER_STAGE {
            identity.push(
                "casework.review-policy.too-many-deciding-profiles",
                format!("{at}/decidingProfiles"),
                format!(
                    "at most {MAXIMUM_REVIEW_PROFILES_PER_STAGE} deciding profiles may be listed on one stage"
                ),
                "Remove deciding profiles until no more than the bound remain.",
            );
        }
        identity.repeated(
            self.deciding_profiles
                .iter()
                .enumerate()
                .map(|(index, profile)| {
                    (format!("{at}/decidingProfiles/{index}"), profile.as_str())
                }),
            "casework.review-policy.duplicate-deciding-profile",
            "this access profile is already listed",
            "List each deciding profile once.",
        );
        for (index, profile) in self.deciding_profiles.iter().enumerate() {
            if !valid_identifier(profile) {
                identity.push(
                    "casework.review-policy.invalid-deciding-profile",
                    format!("{at}/decidingProfiles/{index}"),
                    IDENTIFIER_MESSAGE,
                    IDENTIFIER_ACTION,
                );
            }
        }
        let mut threshold = Findings::default();
        if self.required_approvals == 0
            || self.required_approvals > MAXIMUM_REVIEW_APPROVALS_PER_STAGE
        {
            threshold.push(
                "casework.review-policy.required-approvals-out-of-range",
                format!("{at}/requiredApprovals"),
                format!(
                    "expected a whole number of approvals from 1 to {MAXIMUM_REVIEW_APPROVALS_PER_STAGE}"
                ),
                "Write a number of approvals within the bound.",
            );
        }
        (identity, threshold)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewPolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub version: String,
    pub purpose: ReviewPurpose,
    pub context: crate::ReviewContextPolicy,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "crate::typed::unique_id_list"
    )]
    pub routing: Vec<crate::RoutingRule>,
    #[serde(deserialize_with = "crate::typed::unique_id_list")]
    pub stages: Vec<ReviewStagePolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clocks: Vec<String>,
    pub retention: ReviewRetentionPolicy,
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-foreign" = "json-schema-2020-12"))
    )]
    pub display_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-foreign" = "json-schema-2020-12"))
    )]
    pub result_schema: Option<Value>,
    /// Written in configuration as a mapping from each outcome id; served
    /// as a list by id.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "crate::typed::id_keyed_or_list"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::typed::id_keyed_or_list_schema::<ReviewOutcomePolicy>")
    )]
    pub outcomes: Vec<ReviewOutcomePolicy>,
}

impl registry_platform_yaml::Identified for ReviewStagePolicy {
    fn id(&self) -> &str {
        &self.id
    }
}

impl registry_platform_yaml::Identified for crate::RoutingRule {
    fn id(&self) -> &str {
        &self.id
    }
}

impl registry_platform_yaml::Identified for ReviewOutcomePolicy {
    fn id(&self) -> &str {
        &self.id
    }
}

/// The pointer to an outcome, which configuration keys by its id.
fn outcome_pointer(outcome: &ReviewOutcomePolicy) -> String {
    format!(
        "/outcomes/{}",
        registry_platform_yaml::escape_pointer_segment(&outcome.id)
    )
}

impl ReviewPolicy {
    pub fn check(&self) -> Result<(), ReviewPolicyError> {
        match self.tagged_findings().into_iter().next() {
            Some((error, _)) => Err(error),
            None => Ok(()),
        }
    }

    /// Every problem in this review policy, located by pointers relative to
    /// the review policy (CFG-DIAG-5).
    #[must_use]
    pub fn findings(&self) -> Vec<ConfigFinding> {
        self.tagged_findings()
            .into_iter()
            .map(|(_, finding)| finding)
            .collect()
    }

    /// Every finding beside the policy error it was reported as before
    /// findings were collected, in the order `check` reports them.
    fn tagged_findings(&self) -> Vec<(ReviewPolicyError, ConfigFinding)> {
        let mut out = Vec::new();
        let mut tag = |error: ReviewPolicyError, findings: Findings| {
            out.extend(
                findings
                    .into_vec()
                    .into_iter()
                    .map(|finding| (error, finding)),
            );
        };

        let mut identity = Findings::default();
        if !valid_identifier(&self.id) {
            identity.push(
                "casework.review-policy.invalid-id",
                "/id",
                IDENTIFIER_MESSAGE,
                IDENTIFIER_ACTION,
            );
        }
        if !valid_version(&self.version) {
            identity.push(
                "casework.review-policy.invalid-version",
                "/version",
                "expected 1 to 64 ASCII letters, digits, '.', '-', or '_'",
                "Write a version, such as 1 or 2026-09.",
            );
        }
        tag(ReviewPolicyError::Identity, identity);

        let mut stages = Findings::default();
        if self.stages.is_empty() {
            stages.push(
                "casework.review-policy.no-stages",
                "/stages",
                "a review policy needs at least one stage",
                "Declare a stage under stages.",
            );
        }
        if self.stages.len() > MAXIMUM_REVIEW_STAGES {
            stages.push(
                "casework.review-policy.too-many-stages",
                "/stages",
                format!("at most {MAXIMUM_REVIEW_STAGES} stages may be declared"),
                "Remove stages until no more than the bound remain.",
            );
        }
        tag(ReviewPolicyError::Stages, stages);

        let mut stage_ids = Findings::default();
        stage_ids.repeated(
            self.stages
                .iter()
                .enumerate()
                .map(|(index, stage)| (format!("/stages/{index}/id"), stage.id.as_str())),
            "casework.review-policy.duplicate-stage-id",
            "this stage id is already declared",
            "Give every stage of the review policy a unique id.",
        );
        tag(ReviewPolicyError::StageIdentity, stage_ids);

        let mut clocks = Findings::default();
        if self.clocks.len() > MAXIMUM_REVIEW_POLICY_CLOCKS {
            clocks.push(
                "casework.review-policy.too-many-clocks",
                "/clocks",
                format!("at most {MAXIMUM_REVIEW_POLICY_CLOCKS} clocks may be named"),
                "Remove clocks until no more than the bound remain.",
            );
        }
        clocks.repeated(
            self.clocks
                .iter()
                .enumerate()
                .map(|(index, clock)| (format!("/clocks/{index}"), clock.as_str())),
            "casework.review-policy.duplicate-clock",
            "this clock is already named",
            "Name each clock once.",
        );
        for (index, clock) in self.clocks.iter().enumerate() {
            if !valid_identifier(clock) {
                clocks.push(
                    "casework.review-policy.invalid-clock",
                    format!("/clocks/{index}"),
                    IDENTIFIER_MESSAGE,
                    IDENTIFIER_ACTION,
                );
            }
        }
        tag(ReviewPolicyError::ClockIdentity, clocks);

        for (index, stage) in self.stages.iter().enumerate() {
            let (identity, threshold) = stage.findings(&format!("/stages/{index}"));
            tag(ReviewPolicyError::StageIdentity, identity);
            tag(ReviewPolicyError::StageThreshold, threshold);
        }

        match self.purpose {
            ReviewPurpose::Approval => {
                let mut payload = Findings::default();
                for outcome in &self.outcomes {
                    if outcome.settlement == ReviewOutcomeSettlement::Answered {
                        payload.push(
                            "casework.review-policy.answered-outcome-in-approval",
                            format!("{}/settlement", outcome_pointer(outcome)),
                            "an approval review policy cannot settle with answered",
                            "Write settlement: rejected or changes-requested, or make the review policy's purpose answer.",
                        );
                    }
                }
                if !self
                    .outcomes
                    .iter()
                    .any(|outcome| outcome.settlement == ReviewOutcomeSettlement::Approved)
                {
                    payload.push(
                        "casework.review-policy.approval-without-approved-outcome",
                        "/outcomes",
                        "an approval review policy declares at least one approved outcome",
                        "Declare an outcome with settlement: approved.",
                    );
                }
                tag(ReviewPolicyError::ApprovalOutcomes, payload);
            }
            ReviewPurpose::Answer => {
                let mut answer_stages = Findings::default();
                if self.stages.len() > 1 {
                    answer_stages.push(
                        "casework.review-policy.answer-stage-count",
                        "/stages",
                        "an answer review policy has exactly one stage",
                        "Keep one stage.",
                    );
                } else if self
                    .stages
                    .first()
                    .is_some_and(|stage| stage.required_approvals != 1)
                {
                    answer_stages.push(
                        "casework.review-policy.answer-stage-approvals",
                        "/stages/0/requiredApprovals",
                        "the stage of an answer review policy takes exactly one decision",
                        "Write requiredApprovals: 1.",
                    );
                }
                tag(ReviewPolicyError::AnswerStages, answer_stages);
                let mut answer_outcomes = Findings::default();
                if self.outcomes.is_empty() {
                    answer_outcomes.push(
                        "casework.review-policy.answer-without-outcomes",
                        "/outcomes",
                        "an answer review policy declares at least one answered outcome",
                        "Declare an outcome with settlement: answered.",
                    );
                }
                for outcome in &self.outcomes {
                    if outcome.settlement != ReviewOutcomeSettlement::Answered {
                        answer_outcomes.push(
                            "casework.review-policy.unanswered-outcome-in-answer",
                            format!("{}/settlement", outcome_pointer(outcome)),
                            "an answer review policy settles only with answered",
                            "Write settlement: answered.",
                        );
                    }
                }
                tag(ReviewPolicyError::AnswerOutcomes, answer_outcomes);
            }
        }

        let mut retention = Findings::default();
        self.retention.findings(&mut retention);
        tag(ReviewPolicyError::Retention, retention);

        let mut schemas = Findings::default();
        if check_closed_object_schema(&self.display_schema).is_err() {
            schemas.push(
                "casework.review-policy.invalid-display-schema",
                "/displaySchema",
                closed_schema_message(),
                CLOSED_SCHEMA_ACTION,
            );
        }
        if self
            .result_schema
            .as_ref()
            .is_some_and(|schema| check_closed_object_schema(schema).is_err())
        {
            schemas.push(
                "casework.review-policy.invalid-result-schema",
                "/resultSchema",
                closed_schema_message(),
                CLOSED_SCHEMA_ACTION,
            );
        }
        tag(ReviewPolicyError::Schema, schemas);

        let mut outcomes = Findings::default();
        if self.outcomes.len() > MAXIMUM_REVIEW_OUTCOMES {
            outcomes.push(
                "casework.review-policy.too-many-outcomes",
                "/outcomes",
                format!("at most {MAXIMUM_REVIEW_OUTCOMES} outcomes may be declared"),
                "Remove outcomes until no more than the bound remain.",
            );
        }
        outcomes.repeated(
            self.outcomes
                .iter()
                .map(|outcome| (outcome_pointer(outcome), outcome.id.as_str())),
            "casework.review-policy.duplicate-outcome-id",
            "this outcome id is already declared",
            "Give every outcome of the review policy a unique id.",
        );
        for outcome in &self.outcomes {
            let at = outcome_pointer(outcome);
            if outcome.settlement == ReviewOutcomeSettlement::Approved
                && (outcome.reason_required || outcome.result_required)
            {
                outcomes.push(
                    "casework.review-policy.approval-payload",
                    at.clone(),
                    "approval outcomes cannot require a reason or result payload",
                    "Use a reason-free and payload-free approval outcome.",
                );
            }
            if !valid_identifier(&outcome.id) {
                outcomes.push(
                    "casework.review-policy.invalid-outcome-id",
                    at.clone(),
                    IDENTIFIER_MESSAGE,
                    IDENTIFIER_ACTION,
                );
            }
            if !outcome.label_is_valid() {
                outcomes.push(
                    "casework.review-policy.invalid-outcome-label",
                    format!("{at}/label"),
                    "expected a label of 1 to 120 bytes that is not only spaces and has no control characters",
                    "Write a short label for the outcome.",
                );
            }
            if self.result_schema.is_none() && outcome.result_required {
                outcomes.push(
                    "casework.review-policy.result-required-without-result-schema",
                    format!("{at}/resultRequired"),
                    "resultRequired needs a resultSchema on the review policy",
                    "Declare resultSchema on the review policy, or remove resultRequired.",
                );
            }
        }
        tag(ReviewPolicyError::Outcomes, outcomes);
        out
    }

    fn digest_with(
        &self,
        dependencies: &crate::ReviewPolicyDependencies,
    ) -> Result<ReviewPolicyDigest, ReviewPolicyError> {
        self.check()?;
        let mut policy = self.clone();
        // Authored presentation stays in the immutable closure and package, but
        // does not change the behavioral identity used for request admission.
        for outcome in &mut policy.outcomes {
            outcome.label.clear();
        }
        for rule in &mut policy.routing {
            rule.because.clear();
        }
        let mut dependencies = dependencies.clone();
        for queue in &mut dependencies.queues {
            queue.label.clear();
        }
        for team in &mut dependencies.teams {
            team.label.clear();
        }
        for template in &mut dependencies.task_templates {
            template.label.clear();
        }
        for clock in &mut dependencies.clocks {
            if let ClockPolicy::Stage { steps, .. } = clock {
                for step in steps {
                    step.because.clear();
                }
            }
        }
        if let Some(provider) = &mut dependencies.context_provider {
            provider.description = None;
        }
        let value = json!({"schema":"registry-casework-review-policy/v1","policy":policy,"dependencies":dependencies});
        let bytes = registry_platform_canonical_json::canonicalize_json(&value)
            .map_err(|_| ReviewPolicyError::Canonical)?;
        Ok(ContentDigest::for_bytes(&bytes))
    }

    pub fn compile(
        &self,
        project: &crate::CaseworkProject,
    ) -> Result<ReviewPolicyClosure, ReviewPolicyError> {
        project
            .check()
            .map_err(|_| ReviewPolicyError::Dependencies)?;
        if !project.review_policies.iter().any(|policy| policy == self) {
            return Err(ReviewPolicyError::Dependencies);
        }
        self.closure_with(project.policy_dependencies(self))
    }

    pub fn routing_fields(&self) -> Vec<String> {
        self.routing
            .iter()
            .flat_map(|rule| rule.when.fields.keys().cloned())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Check `display` against this kind's `displaySchema` and the display
    /// bounds, exactly as the runtime checks a display a producer submits.
    pub fn validate_display(&self, display: &Value) -> Result<(), ReviewValidationError> {
        validate_display(&self.display_schema, display)
    }

    fn closure_with(
        &self,
        dependencies: crate::ReviewPolicyDependencies,
    ) -> Result<ReviewPolicyClosure, ReviewPolicyError> {
        let snapshot = ReviewPolicyClosure {
            identity: ReviewPolicyIdentity {
                id: self.id.clone(),
                version: self.version.clone(),
                digest: self.digest_with(&dependencies)?,
            },
            dependencies,
            purpose: self.purpose,
            context: self.context.clone(),
            routing: self.routing.clone(),
            stages: self.stages.clone(),
            clocks: self.clocks.clone(),
            retention: self.retention.clone(),
            display_schema: self.display_schema.clone(),
            result_schema: self.result_schema.clone(),
            outcomes: self.outcomes.clone(),
        };
        snapshot.check_encoding_bound()?;
        Ok(snapshot)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewPolicyIdentity {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub version: String,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Digest"))]
    pub digest: ReviewPolicyDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewPolicyClosure {
    pub dependencies: crate::ReviewPolicyDependencies,
    pub identity: ReviewPolicyIdentity,
    pub purpose: ReviewPurpose,
    pub context: crate::ReviewContextPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routing: Vec<crate::RoutingRule>,
    pub stages: Vec<ReviewStagePolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clocks: Vec<String>,
    pub retention: ReviewRetentionPolicy,
    pub display_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<ReviewOutcomePolicy>,
}

impl ReviewPolicyClosure {
    pub fn binding(&self) -> PolicyBinding {
        PolicyBinding {
            id: self.identity.id.clone(),
            version: self.identity.version.clone(),
            digest: self.identity.digest.clone(),
        }
    }

    pub fn verify(&self) -> Result<(), ReviewPolicyError> {
        self.check_encoding_bound()?;
        let policy = self.as_policy();
        if policy.digest_with(&self.dependencies)? != self.identity.digest {
            return Err(ReviewPolicyError::DigestMismatch);
        }
        Ok(())
    }

    fn check_encoding_bound(&self) -> Result<(), ReviewPolicyError> {
        let value = serde_json::to_value(self).map_err(|_| ReviewPolicyError::Canonical)?;
        let bytes = registry_platform_canonical_json::canonicalize_json(&value)
            .map_err(|_| ReviewPolicyError::Canonical)?;
        if bytes.len() > MAXIMUM_REVIEW_POLICY_CLOSURE_BYTES {
            return Err(ReviewPolicyError::ClosureSize);
        }
        Ok(())
    }

    pub fn validate_display(&self, display: &Value) -> Result<(), ReviewDecisionValidationError> {
        self.verify()?;
        validate_display(&self.display_schema, display)?;
        Ok(())
    }

    pub fn validate_result_constraints(
        &self,
        constraints: &Value,
    ) -> Result<(), ReviewDecisionValidationError> {
        self.verify()?;
        validate_result_constraints(self.result_schema.as_ref(), constraints)?;
        Ok(())
    }

    fn validate_outcome(
        &self,
        outcome: &str,
        reason: Option<&str>,
        public_reason: Option<&str>,
        result: Option<&Value>,
        constraints: Option<&Value>,
    ) -> Result<(), ReviewDecisionValidationError> {
        self.verify()?;
        let outcome_policy = self
            .outcomes
            .iter()
            .find(|candidate| candidate.id == outcome)
            .ok_or_else(|| {
                ReviewValidationError::new("$.outcome", ReviewValidationReason::OutcomeNotDeclared)
            })?;
        // Length comes first so an oversized reason names the bound.
        if reason.is_some_and(|reason| reason.len() > MAXIMUM_REVIEW_REASON_BYTES) {
            return Err(ReviewValidationError::new(
                "$.reason",
                ReviewValidationReason::MaximumBytesExceeded,
            )
            .into());
        }
        if reason.is_some_and(|reason| !bounded_text(reason, MAXIMUM_REVIEW_REASON_BYTES)) {
            return Err(ReviewValidationError::new(
                "$.reason",
                ReviewValidationReason::TextInvalid,
            )
            .into());
        }
        if outcome_policy.reason_required && reason.is_none_or(|reason| reason.trim().is_empty()) {
            return Err(ReviewValidationError::new(
                "$.reason",
                ReviewValidationReason::ReasonRequired,
            )
            .into());
        }
        if public_reason.is_some_and(|text| text.len() > MAXIMUM_PUBLIC_REASON_BYTES) {
            return Err(ReviewValidationError::new(
                PUBLIC_REASON_PATH,
                ReviewValidationReason::MaximumBytesExceeded,
            )
            .into());
        }
        if public_reason.is_some_and(|text| check_public_reason(text).is_err()) {
            return Err(ReviewValidationError::new(
                PUBLIC_REASON_PATH,
                ReviewValidationReason::TextInvalid,
            )
            .into());
        }
        match (outcome_policy.public_reason, public_reason) {
            (ReviewPublicReasonRule::Required, None) => {
                return Err(ReviewValidationError::new(
                    PUBLIC_REASON_PATH,
                    ReviewValidationReason::PublicReasonRequired,
                )
                .into());
            }
            (ReviewPublicReasonRule::None, Some(_)) => {
                return Err(ReviewValidationError::new(
                    PUBLIC_REASON_PATH,
                    ReviewValidationReason::PublicReasonNotDeclared,
                )
                .into());
            }
            _ => {}
        }
        match (result, self.result_schema.as_ref()) {
            (Some(result), Some(schema)) => {
                validate_result(schema, result)?;
                if let Some(constraints) = constraints {
                    validate_result_narrowing(constraints, result)?;
                }
            }
            (Some(_), None) => {
                return Err(ReviewValidationError::new(
                    RESULT_PATH,
                    ReviewValidationReason::ResultNotDeclared,
                )
                .into());
            }
            (None, Some(_)) if outcome_policy.result_required => {
                return Err(ReviewValidationError::new(
                    RESULT_PATH,
                    ReviewValidationReason::ResultRequired,
                )
                .into());
            }
            (None, _) => {}
        }
        Ok(())
    }

    fn as_policy(&self) -> ReviewPolicy {
        ReviewPolicy {
            id: self.identity.id.clone(),
            version: self.identity.version.clone(),
            purpose: self.purpose,
            context: self.context.clone(),
            routing: self.routing.clone(),
            stages: self.stages.clone(),
            clocks: self.clocks.clone(),
            retention: self.retention.clone(),
            display_schema: self.display_schema.clone(),
            result_schema: self.result_schema.clone(),
            outcomes: self.outcomes.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewTaskState {
    Open,
    Held { holder: IssuerPrincipal },
    Decided,
}

/// Select active review tasks by their current holder. Selection never grants
/// reviewer eligibility or source authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewTaskOwnership {
    AssignedToMe,
    Unclaimed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewDecisionType {
    Approve,
    Reject,
    ChangesRequested,
    Answer,
}

/// A retained decision, interpreted under the task's pinned policy and released
/// through an own receipt or the explicit audited accountability read.
/// Private reasons and structured producer result data are never included.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewDecisionReceipt {
    pub policy: crate::PolicyBinding,
    pub decision: ReviewDecisionType,
    /// The policy outcome the decision selected; every decision names one.
    pub outcome: String,
    /// The configured label from the decision's immutable pinned policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_label: Option<String>,
    pub decided_at: DateTime<Utc>,
}

/// A current caller's retained decision reference, without context or reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnReviewDecision {
    pub task_id: Uuid,
    pub request_id: Uuid,
    pub queue: String,
    pub requester_reference: String,
    pub decision_receipt: ReviewDecisionReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnReviewDecisionPage {
    pub items: Vec<OwnReviewDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Uuid>,
    pub status: crate::PageStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTask {
    pub subject: SubjectBinding,
    pub requester_reference: String,
    pub deadline_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_reference: Option<String>,
    pub task_id: Uuid,
    pub request_id: Uuid,
    pub stage_index: u16,
    pub stage_id: String,
    pub queue: String,
    pub revision: i64,
    pub eligible_profiles: Vec<String>,
    pub state: ReviewTaskState,
    /// Bounded notice about unavailable cover or too few distinct approvers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "crate::StaffingDiagnostic"))]
    pub staffing_diagnostic: Option<crate::StaffingDiagnostic>,
    /// Whether the current caller recorded this task's decision. Present only
    /// on a single decided-task read, so a reviewer whose decide response was
    /// lost can confirm the outcome without learning who else decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by_caller: Option<bool>,
    /// Present only on a single decided-task read when `decidedByCaller` is
    /// true. Current task eligibility, membership, and result retention still
    /// apply. The receipt contains only Casework-owned decision state; source
    /// context remains subject to the source's current disclosure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_receipt: Option<ReviewDecisionReceipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskPage {
    pub items: Vec<ReviewTask>,
    /// Pass unchanged with the same caller, profiles and filters. A cursor
    /// after an undisclosed candidate is an opaque expiring scan checkpoint,
    /// not a task identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Uuid>,
    /// Whether the page stopped early: `budget-exhausted` when the source-read
    /// budget, candidate scan, or page deadline ran out before the page
    /// filled, and `source-unavailable` when a bound source did not answer in
    /// time. Either comes with a `nextCursor` to continue from.
    pub status: crate::PageStatus,
}

/// Operational discovery for a current supervisor of the task's serving team.
/// This reference grants neither review eligibility nor access to task content.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SupervisoryReviewTaskState {
    Open,
    Held,
    Decided,
}

/// A task reference without reviewer identity, content, or decision data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupervisoryReviewTask {
    pub task_id: Uuid,
    pub request_id: Uuid,
    pub queue: String,
    pub revision: i64,
    pub state: SupervisoryReviewTaskState,
    /// Bounded staffing status without holder or absence identities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "crate::StaffingDiagnostic"))]
    pub staffing_diagnostic: Option<crate::StaffingDiagnostic>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accountability_event_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupervisoryReviewTaskPage {
    pub items: Vec<SupervisoryReviewTask>,
    /// Pass unchanged with the same caller, profiles and queue. A cursor
    /// after an undisclosed candidate is an opaque expiring scan checkpoint,
    /// not a task identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Uuid>,
    pub status: crate::PageStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewSourceBindingStatus {
    Current,
    BindingChanged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewSourceProjection {
    pub binding: SubjectBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_reference: Option<String>,
    #[serde(default)]
    /// Exact source values from the current human caller's read, limited by
    /// the authored source context projection and the pinned kind schema.
    pub display: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "mode",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReviewTaskContextData {
    Submitted {
        snapshot: Value,
    },
    CurrentSource {
        reference: String,
        binding_status: ReviewSourceBindingStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        projection: Option<ReviewSourceProjection>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskContext {
    pub task_id: Uuid,
    pub request_id: Uuid,
    pub subject: SubjectBinding,
    pub requester_reference: String,
    pub policy: PolicyBinding,
    pub policy_closure: ReviewPolicyClosure,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_constraints: Option<Value>,
    pub context: ReviewTaskContextData,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewHistoryPage {
    pub items: Vec<ReviewHistoryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskDraftInput {
    pub body: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskDraft {
    pub task_id: Uuid,
    pub author: IssuerPrincipal,
    pub body: Value,
    pub revision: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewHistoryAudience {
    Reviewers,
    Requester,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewNoteRequest {
    pub audience: ReviewHistoryAudience,
    pub note: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewHistoryEntry {
    pub event_id: Uuid,
    pub request_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<Uuid>,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_ref: Option<String>,
    #[serde(default)]
    pub detail: Value,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewAccountabilityRecord {
    pub event_id: Uuid,
    pub request_id: Uuid,
    pub task_id: Uuid,
    pub actor_ref: String,
    pub actor: IssuerPrincipal,
    pub profile_id: String,
    pub decision: String,
    /// Unavailable for legacy selections no longer retained when upgraded.
    /// New selections are retained through the accountability window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_receipt: Option<ReviewDecisionReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<String>,
    pub occurred_at: DateTime<Utc>,
    pub retained_until: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewClockState {
    Running,
    Completed,
    Cancelled,
    SourceFactsMissing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewClockOccurrence {
    pub clock_occurrence_id: Uuid,
    pub clock_id: String,
    pub request_id: Uuid,
    pub correlation: ReviewClockCorrelation,
    pub state: ReviewClockState,
    pub policy_digest: ContentDigest,
    pub anchor_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_risk_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

/// A reviewer's decision. Every decision names a declared outcome. A missing
/// `outcome` reads as empty so the policy check refuses it with the outcomes
/// the policy declares for that decision, rather than as an unreadable body;
/// the published schema still requires the field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(transform = require_decision_outcome))]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DecisionKind {
    /// Approval names an approved outcome. It carries no private reason or
    /// result, which approved outcomes cannot require.
    Approve {
        #[serde(default)]
        outcome: String,
        #[serde(
            default,
            rename = "publicReason",
            skip_serializing_if = "Option::is_none"
        )]
        #[cfg_attr(feature="schema",schemars(length(min=1,max=MAXIMUM_PUBLIC_REASON_BYTES),extend("x-maximum-utf8-bytes"=MAXIMUM_PUBLIC_REASON_BYTES)))]
        public_reason: Option<String>,
    },
    Reject {
        #[serde(default)]
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(
            default,
            rename = "publicReason",
            skip_serializing_if = "Option::is_none"
        )]
        #[cfg_attr(feature="schema",schemars(length(min=1,max=MAXIMUM_PUBLIC_REASON_BYTES),extend("x-maximum-utf8-bytes"=MAXIMUM_PUBLIC_REASON_BYTES)))]
        public_reason: Option<String>,
        #[serde(
            default,
            deserialize_with = "deserialize_present_value",
            skip_serializing_if = "Option::is_none"
        )]
        #[cfg_attr(feature="schema",schemars(with="serde_json::Map<String,Value>",extend("x-maximum-canonical-bytes"=MAXIMUM_REVIEW_RESULT_BYTES)))]
        result: Option<Value>,
    },
    ChangesRequested {
        #[serde(default)]
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(
            default,
            rename = "publicReason",
            skip_serializing_if = "Option::is_none"
        )]
        #[cfg_attr(feature="schema",schemars(length(min=1,max=MAXIMUM_PUBLIC_REASON_BYTES),extend("x-maximum-utf8-bytes"=MAXIMUM_PUBLIC_REASON_BYTES)))]
        public_reason: Option<String>,
        #[serde(
            default,
            deserialize_with = "deserialize_present_value",
            skip_serializing_if = "Option::is_none"
        )]
        #[cfg_attr(feature="schema",schemars(with="serde_json::Map<String,Value>",extend("x-maximum-canonical-bytes"=MAXIMUM_REVIEW_RESULT_BYTES)))]
        result: Option<Value>,
    },
    Answer {
        #[serde(default)]
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(
            default,
            rename = "publicReason",
            skip_serializing_if = "Option::is_none"
        )]
        #[cfg_attr(feature="schema",schemars(length(min=1,max=MAXIMUM_PUBLIC_REASON_BYTES),extend("x-maximum-utf8-bytes"=MAXIMUM_PUBLIC_REASON_BYTES)))]
        public_reason: Option<String>,
        #[serde(
            default,
            deserialize_with = "deserialize_present_value",
            skip_serializing_if = "Option::is_none"
        )]
        #[cfg_attr(feature="schema",schemars(with="serde_json::Map<String,Value>",extend("x-maximum-canonical-bytes"=MAXIMUM_REVIEW_RESULT_BYTES)))]
        result: Option<Value>,
    },
}

/// Lists `outcome` as required in every decision variant of the published
/// schema, which `#[serde(default)]` would otherwise mark optional, and drops
/// the empty default that attribute would otherwise publish.
#[cfg(feature = "schema")]
fn require_decision_outcome(schema: &mut schemars::Schema) {
    let Some(variants) = schema
        .get_mut("oneOf")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for variant in variants {
        let Some(variant) = variant.as_object_mut() else {
            continue;
        };
        if let Some(outcome) = variant
            .get_mut("properties")
            .and_then(|properties| properties.get_mut("outcome"))
            .and_then(serde_json::Value::as_object_mut)
        {
            outcome.remove("default");
        }
        let required = variant
            .entry("required")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let Some(required) = required.as_array_mut() {
            if !required.iter().any(|name| name == "outcome") {
                required.push(serde_json::Value::from("outcome"));
            }
        }
    }
}

/// Preserve an explicitly present JSON `null` so semantic validation can
/// reject it as a non-object instead of treating it like an omitted field.
fn deserialize_present_value<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Decision {
    pub task_id: Uuid,
    pub request_id: Uuid,
    pub stage_id: String,
    pub reviewer: IssuerPrincipal,
    pub profile_id: String,
    pub decision: DecisionKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ReviewSettlement {
    Approved {
        outcome: String,
        #[serde(
            default,
            rename = "publicReason",
            skip_serializing_if = "Option::is_none"
        )]
        public_reason: Option<String>,
    },
    Rejected {
        outcome: String,
        #[serde(
            default,
            rename = "publicReason",
            skip_serializing_if = "Option::is_none"
        )]
        public_reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
    },
    ChangesRequested {
        outcome: String,
        #[serde(
            default,
            rename = "publicReason",
            skip_serializing_if = "Option::is_none"
        )]
        public_reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
    },
    Answered {
        outcome: String,
        #[serde(
            default,
            rename = "publicReason",
            skip_serializing_if = "Option::is_none"
        )]
        public_reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
    },
}

impl ReviewSettlement {
    #[must_use]
    pub fn result_status(&self) -> ReviewResultStatus {
        match self {
            Self::Approved { .. } => ReviewResultStatus::Approved,
            Self::Rejected { .. } => ReviewResultStatus::Rejected,
            Self::ChangesRequested { .. } => ReviewResultStatus::ChangesRequested,
            Self::Answered { .. } => ReviewResultStatus::Answered,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewProgress {
    pub request_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator: Option<IssuerPrincipal>,
    pub active_stage: u16,
    #[serde(default)]
    pub decisions: Vec<Decision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_constraints: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement: Option<ReviewSettlement>,
}

impl ReviewProgress {
    pub fn new(
        request_id: Uuid,
        initiator: Option<IssuerPrincipal>,
        result_constraints: Option<Value>,
        policy: &ReviewPolicyClosure,
    ) -> Result<Self, ReviewDecisionValidationError> {
        policy.verify()?;
        if let Some(constraints) = &result_constraints {
            policy.validate_result_constraints(constraints)?;
        }
        Ok(Self {
            request_id,
            initiator,
            active_stage: 0,
            decisions: Vec::new(),
            result_constraints,
            settlement: None,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ReviewTransition {
    Recorded {
        remaining_approvals: u16,
    },
    StageAdvanced {
        completed_stage: String,
        next_stage: String,
    },
    Settled {
        settlement: ReviewSettlement,
    },
}

/// Checks that `reviewer` currently holds a task, independent of policy
/// verification, stage matching, or any other decision validation. Both
/// [`record_review_decision`] and the store's task-fetch path call this first
/// so a non-holder is refused before any expensive policy re-verification.
pub fn check_task_holder(
    task_state: &ReviewTaskState,
    reviewer: &IssuerPrincipal,
) -> Result<(), ReviewDecisionError> {
    match task_state {
        ReviewTaskState::Open => Err(ReviewDecisionError::TaskNotHeld),
        ReviewTaskState::Held { holder } if holder == reviewer => Ok(()),
        ReviewTaskState::Held { .. } => Err(ReviewDecisionError::HolderMismatch),
        ReviewTaskState::Decided => Err(ReviewDecisionError::TaskAlreadyDecided),
    }
}

pub fn record_review_decision(
    policy: &ReviewPolicyClosure,
    progress: &mut ReviewProgress,
    task: &ReviewTask,
    decision: Decision,
) -> Result<ReviewTransition, ReviewDecisionError> {
    check_task_holder(&task.state, &decision.reviewer)?;
    policy.verify()?;
    if progress.settlement.is_some() {
        return Err(ReviewDecisionError::AlreadySettled);
    }
    let stage = policy
        .stages
        .get(usize::from(progress.active_stage))
        .ok_or(ReviewDecisionError::StageMismatch)?;
    if progress.request_id != task.request_id || progress.request_id != decision.request_id {
        return Err(ReviewDecisionError::RequestMismatch);
    }
    if task.stage_index != progress.active_stage
        || task.stage_id != stage.id
        || decision.stage_id != stage.id
        || decision.task_id != task.task_id
    {
        return Err(ReviewDecisionError::StageMismatch);
    }
    if !stage
        .deciding_profiles
        .iter()
        .any(|profile| profile == &decision.profile_id)
        || !task
            .eligible_profiles
            .iter()
            .any(|profile| profile == &decision.profile_id)
    {
        return Err(ReviewDecisionError::ProfileNotEligible);
    }
    if progress
        .decisions
        .iter()
        .any(|recorded| recorded.task_id == decision.task_id)
    {
        return Err(ReviewDecisionError::TaskAlreadyDecided);
    }
    if progress
        .decisions
        .iter()
        .any(|recorded| recorded.stage_id == stage.id && recorded.reviewer == decision.reviewer)
    {
        return Err(ReviewDecisionError::DuplicateReviewer);
    }
    if stage.exclude_initiator
        && progress
            .initiator
            .as_ref()
            .is_some_and(|initiator| *initiator == decision.reviewer)
    {
        return Err(ReviewDecisionError::InitiatorExcluded);
    }
    if stage.exclude_previous_stage_reviewers
        && progress
            .decisions
            .iter()
            .any(|recorded| recorded.stage_id != stage.id && recorded.reviewer == decision.reviewer)
    {
        return Err(ReviewDecisionError::PreviousStageReviewerExcluded);
    }

    let (expected, outcome, reason, public_reason, result) =
        match (&policy.purpose, &decision.decision) {
            (
                ReviewPurpose::Approval,
                DecisionKind::Approve {
                    outcome,
                    public_reason,
                },
            ) => (
                ReviewOutcomeSettlement::Approved,
                outcome,
                None,
                public_reason,
                None,
            ),
            (
                ReviewPurpose::Approval,
                DecisionKind::Reject {
                    outcome,
                    reason,
                    public_reason,
                    result,
                },
            ) => (
                ReviewOutcomeSettlement::Rejected,
                outcome,
                reason.as_deref(),
                public_reason,
                result.as_ref(),
            ),
            (
                ReviewPurpose::Approval,
                DecisionKind::ChangesRequested {
                    outcome,
                    reason,
                    public_reason,
                    result,
                },
            ) => (
                ReviewOutcomeSettlement::ChangesRequested,
                outcome,
                reason.as_deref(),
                public_reason,
                result.as_ref(),
            ),
            (
                ReviewPurpose::Answer,
                DecisionKind::Answer {
                    outcome,
                    reason,
                    public_reason,
                    result,
                },
            ) => (
                ReviewOutcomeSettlement::Answered,
                outcome,
                reason.as_deref(),
                public_reason,
                result.as_ref(),
            ),
            _ => return Err(ReviewDecisionError::DecisionNotAllowed),
        };
    validate_settlement_outcome(
        policy,
        expected,
        outcome,
        reason,
        public_reason.as_deref(),
        result,
        progress.result_constraints.as_ref(),
    )?;
    // Every approval in a stage names the same outcome, so the approval that
    // meets the threshold cannot release an outcome another approver did not
    // choose.
    if let DecisionKind::Approve { outcome, .. } = &decision.decision {
        let chosen = progress
            .decisions
            .iter()
            .find_map(|earlier| match &earlier.decision {
                DecisionKind::Approve { outcome, .. } if earlier.stage_id == stage.id => {
                    Some(outcome)
                }
                _ => None,
            });
        if let Some(chosen) = chosen.filter(|chosen| *chosen != outcome) {
            return Err(ReviewDecisionError::ApprovalOutcomeDiffers {
                chosen: chosen.clone(),
            });
        }
    }

    let (settlement, settles_on_record) = match &decision.decision {
        DecisionKind::Reject {
            outcome,
            public_reason,
            result,
            ..
        } => (
            ReviewSettlement::Rejected {
                outcome: outcome.clone(),
                public_reason: public_reason.clone(),
                result: result.clone(),
            },
            true,
        ),
        DecisionKind::ChangesRequested {
            outcome,
            public_reason,
            result,
            ..
        } => (
            ReviewSettlement::ChangesRequested {
                outcome: outcome.clone(),
                public_reason: public_reason.clone(),
                result: result.clone(),
            },
            true,
        ),
        DecisionKind::Answer {
            outcome,
            public_reason,
            result,
            ..
        } => (
            ReviewSettlement::Answered {
                outcome: outcome.clone(),
                public_reason: public_reason.clone(),
                result: result.clone(),
            },
            true,
        ),
        // The approval that meets the final stage's threshold settles the
        // request. Its stage's approvals agree on the outcome; its public
        // reason is the one released.
        DecisionKind::Approve {
            outcome,
            public_reason,
        } => (
            ReviewSettlement::Approved {
                outcome: outcome.clone(),
                public_reason: public_reason.clone(),
            },
            false,
        ),
    };

    progress.decisions.push(decision);
    if settles_on_record {
        progress.settlement = Some(settlement.clone());
        return Ok(ReviewTransition::Settled { settlement });
    }

    let approvals = progress
        .decisions
        .iter()
        .filter(|decision| {
            decision.stage_id == stage.id
                && matches!(&decision.decision, DecisionKind::Approve { .. })
        })
        .count();
    let approvals = u16::try_from(approvals).expect("review approval count is policy bounded");
    if approvals < stage.required_approvals {
        return Ok(ReviewTransition::Recorded {
            remaining_approvals: stage.required_approvals - approvals,
        });
    }

    if usize::from(progress.active_stage) + 1 == policy.stages.len() {
        progress.settlement = Some(settlement.clone());
        Ok(ReviewTransition::Settled { settlement })
    } else {
        let completed_stage = stage.id.clone();
        progress.active_stage += 1;
        Ok(ReviewTransition::StageAdvanced {
            completed_stage,
            next_stage: policy.stages[usize::from(progress.active_stage)].id.clone(),
        })
    }
}

fn validate_settlement_outcome(
    policy: &ReviewPolicyClosure,
    expected: ReviewOutcomeSettlement,
    outcome: &str,
    reason: Option<&str>,
    public_reason: Option<&str>,
    result: Option<&Value>,
    constraints: Option<&Value>,
) -> Result<(), ReviewDecisionError> {
    if policy
        .outcomes
        .iter()
        .find(|candidate| candidate.id == outcome)
        .is_none_or(|candidate| candidate.settlement != expected)
    {
        return Err(ReviewDecisionError::OutcomeNotAllowed {
            settlement: expected,
            declared: policy
                .outcomes
                .iter()
                .filter(|candidate| candidate.settlement == expected)
                .map(|candidate| candidate.id.clone())
                .collect(),
        });
    }
    policy.validate_outcome(outcome, reason, public_reason, result, constraints)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReviewPolicyError {
    #[error("the review policy dependencies are invalid")]
    Dependencies,
    #[error("the review policy identity is invalid")]
    Identity,
    #[error("a review policy must declare one to thirty-two ordered stages")]
    Stages,
    #[error("review stage identifiers, queues, or deciding profiles are invalid")]
    StageIdentity,
    #[error("review clock identifiers must be unique and bounded")]
    ClockIdentity,
    #[error("review stage approval counts must be positive and bounded")]
    StageThreshold,
    #[error("approval policies declare an approved outcome and cannot settle with answered")]
    ApprovalOutcomes,
    #[error("answer policies require exactly one single-decision stage")]
    AnswerStages,
    #[error("answer policies can declare only answered outcomes")]
    AnswerOutcomes,
    #[error("the review retention policy is invalid")]
    Retention,
    #[error("a review display or result schema is invalid or unbounded")]
    Schema,
    #[error("the review outcomes are invalid")]
    Outcomes,
    #[error("the review policy could not be canonically encoded")]
    Canonical,
    #[error("the review policy closure exceeds the bounded canonical encoding")]
    ClosureSize,
    #[error("the review policy closure digest does not match its contents")]
    DigestMismatch,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReviewDecisionValidationError {
    #[error(transparent)]
    Policy(#[from] ReviewPolicyError),
    #[error(transparent)]
    Structured(#[from] ReviewValidationError),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewValidationReason {
    PolicyNotAllowed,
    ReferenceInvalid,
    ObjectRequired,
    MaximumBytesExceeded,
    MaximumDepthExceeded,
    SchemaMismatch,
    OutcomeNotDeclared,
    ReasonRequired,
    TextInvalid,
    ResultNotDeclared,
    ResultRequired,
    FieldNotDeclared,
    ConstraintInvalid,
    ConstraintViolated,
    PublicReasonRequired,
    PublicReasonNotDeclared,
    ApprovalOutcomeDiffers,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewValidationError {
    pub path: String,
    pub reason: ReviewValidationReason,
    /// The declared identifiers the value at `path` may take, when the
    /// refusal can name them; empty otherwise. A boxed slice keeps client
    /// error types within the large-error size budget.
    pub allowed: Box<[String]>,
}

impl ReviewValidationError {
    pub fn new(path: impl Into<String>, reason: ReviewValidationReason) -> Self {
        Self::with_fallback(path, reason, "$.display")
    }

    fn result_error(path: impl Into<String>, reason: ReviewValidationReason) -> Self {
        Self::with_fallback(path, reason, RESULT_PATH)
    }

    fn with_fallback(
        path: impl Into<String>,
        reason: ReviewValidationReason,
        fallback: &str,
    ) -> Self {
        let path = path.into();
        Self {
            path: if path.len() <= 256 && path.bytes().all(valid_path_byte) {
                path
            } else {
                fallback.to_owned()
            },
            reason,
            allowed: Box::default(),
        }
    }

    /// Names the declared identifiers the value at `path` may take.
    pub fn allowing(mut self, allowed: Vec<String>) -> Self {
        self.allowed = allowed.into_boxed_slice();
        self
    }
}

impl fmt::Display for ReviewValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "review request validation failed at {}",
            self.path
        )?;
        if !self.allowed.is_empty() {
            write!(formatter, "; use one of: {}", self.allowed.join(", "))?;
        }
        Ok(())
    }
}

impl std::error::Error for ReviewValidationError {}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReviewDecisionError {
    #[error(transparent)]
    Policy(#[from] ReviewPolicyError),
    #[error(transparent)]
    Validation(#[from] ReviewDecisionValidationError),
    #[error("the review request is already settled")]
    AlreadySettled,
    #[error("the task and decision do not belong to this request")]
    RequestMismatch,
    #[error("the task and decision do not belong to the active stage")]
    StageMismatch,
    #[error("the task was already decided")]
    TaskAlreadyDecided,
    #[error("the task must be held before it can be decided")]
    TaskNotHeld,
    #[error("only the task holder may decide a held task")]
    HolderMismatch,
    #[error("the selected profile is not eligible for this task and stage")]
    ProfileNotEligible,
    #[error("one person cannot decide twice in the same stage")]
    DuplicateReviewer,
    #[error("the request initiator is excluded from this stage")]
    InitiatorExcluded,
    #[error("a reviewer from an earlier stage is excluded from this stage")]
    PreviousStageReviewerExcluded,
    #[error("the decision is not valid for this review policy")]
    DecisionNotAllowed,
    #[error(
        "outcome must name a declared {} outcome of this review policy; use one of: {}",
        settlement_name(*settlement),
        declared.join(", ")
    )]
    OutcomeNotAllowed {
        settlement: ReviewOutcomeSettlement,
        declared: Vec<String>,
    },
    #[error("an earlier approval in this stage chose {chosen}, and every approval in a stage names the same outcome; approve with {chosen}, or request changes or reject")]
    ApprovalOutcomeDiffers { chosen: String },
    #[error("rejection and changes-requested reasons must be bounded non-empty text")]
    ReasonInvalid,
}

const CLOSED_SCHEMA_ACTION: &str = "Write a JSON Schema with type: object and additionalProperties: false on every object, using only local $ref.";

fn closed_schema_message() -> String {
    format!(
        "expected a closed JSON Schema 2020-12 object: type object, additionalProperties false on every object, only local $ref, at most {MAXIMUM_REVIEW_SCHEMA_BYTES} canonical bytes and {MAXIMUM_REVIEW_VALUE_DEPTH} levels deep"
    )
}

fn check_closed_object_schema(schema: &Value) -> Result<(), ReviewPolicyError> {
    let root = schema.as_object().ok_or(ReviewPolicyError::Schema)?;
    if root.get("type") != Some(&Value::String("object".to_owned()))
        || root.get("additionalProperties") != Some(&Value::Bool(false))
        || !bounded_json(schema, MAXIMUM_REVIEW_VALUE_DEPTH)
        || !schema_refs_are_local(schema)
        || !object_schemas_are_closed(schema)
        || !registry_platform_canonical_json::canonicalize_json(schema)
            .is_ok_and(|bytes| bytes.len() <= MAXIMUM_REVIEW_SCHEMA_BYTES)
        || JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(schema)
            .is_err()
    {
        return Err(ReviewPolicyError::Schema);
    }
    Ok(())
}

fn check_review_json(
    value: &Value,
    path: &str,
    maximum_bytes: usize,
    object_required: bool,
) -> Result<(), ReviewValidationError> {
    if object_required && !value.is_object() {
        return Err(ReviewValidationError::new(
            path,
            ReviewValidationReason::ObjectRequired,
        ));
    }
    if !bounded_json(value, MAXIMUM_REVIEW_VALUE_DEPTH) {
        return Err(ReviewValidationError::new(
            path,
            ReviewValidationReason::MaximumDepthExceeded,
        ));
    }
    let bytes = registry_review_protocol::canonical_bytes(value).map_err(|error| {
        ReviewValidationError::new(
            path,
            match error {
                registry_review_protocol::ProtocolError::JsonComplexity => {
                    ReviewValidationReason::MaximumDepthExceeded
                }
                _ => ReviewValidationReason::SchemaMismatch,
            },
        )
    })?;
    if bytes.len() > maximum_bytes {
        return Err(ReviewValidationError::new(
            path,
            ReviewValidationReason::MaximumBytesExceeded,
        ));
    }
    Ok(())
}

impl DecisionKind {
    /// Policy-independent input bounds, safe to check before token acquisition or I/O.
    pub fn check_input(&self) -> Result<(), ReviewValidationError> {
        let (outcome, reason, public_reason, result) = match self {
            Self::Approve {
                outcome,
                public_reason,
            } => (outcome, &None, public_reason, &None),
            Self::Reject {
                outcome,
                reason,
                public_reason,
                result,
            }
            | Self::ChangesRequested {
                outcome,
                reason,
                public_reason,
                result,
            }
            | Self::Answer {
                outcome,
                reason,
                public_reason,
                result,
            } => (outcome, reason, public_reason, result),
        };
        // A missing outcome reads as empty and is refused by the policy
        // check, which names the outcomes the policy declares.
        if !outcome.is_empty() && !bounded_text(outcome, crate::MAXIMUM_IDENTIFIER_BYTES) {
            return Err(ReviewValidationError::new(
                "$.outcome",
                ReviewValidationReason::TextInvalid,
            ));
        }
        // Length comes first so an oversized reason names the bound.
        if reason
            .as_ref()
            .is_some_and(|reason| reason.len() > MAXIMUM_REVIEW_REASON_BYTES)
        {
            return Err(ReviewValidationError::new(
                "$.reason",
                ReviewValidationReason::MaximumBytesExceeded,
            ));
        }
        if reason
            .as_ref()
            .is_some_and(|reason| !bounded_text(reason, MAXIMUM_REVIEW_REASON_BYTES))
        {
            return Err(ReviewValidationError::new(
                "$.reason",
                ReviewValidationReason::TextInvalid,
            ));
        }
        if public_reason
            .as_ref()
            .is_some_and(|text| text.len() > MAXIMUM_PUBLIC_REASON_BYTES)
        {
            return Err(ReviewValidationError::new(
                PUBLIC_REASON_PATH,
                ReviewValidationReason::MaximumBytesExceeded,
            ));
        }
        if public_reason
            .as_ref()
            .is_some_and(|text| check_public_reason(text).is_err())
        {
            return Err(ReviewValidationError::new(
                PUBLIC_REASON_PATH,
                ReviewValidationReason::TextInvalid,
            ));
        }
        if let Some(result) = result {
            check_review_json(result, RESULT_PATH, MAXIMUM_REVIEW_RESULT_BYTES, true)?;
        }
        Ok(())
    }
}

impl ReviewTaskDraftInput {
    pub fn check(&self) -> Result<(), ReviewValidationError> {
        check_review_json(&self.body, "$.body", MAXIMUM_REVIEW_DRAFT_BYTES, false)
    }
}

fn validate_display(schema: &Value, display: &Value) -> Result<(), ReviewValidationError> {
    check_review_json(display, "$.display", MAXIMUM_REVIEW_DISPLAY_BYTES, true)?;
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .map_err(|_| {
            ReviewValidationError::new("$.display", ReviewValidationReason::SchemaMismatch)
        })?;
    if let Err(errors) = compiled.validate(display) {
        let path = errors
            .into_iter()
            .next()
            .map(|error| {
                let path = error.instance_path.to_string();
                if path.is_empty() {
                    "$.display".to_owned()
                } else {
                    format!("$.display{path}")
                }
            })
            .unwrap_or_else(|| "$.display".to_owned());
        return Err(ReviewValidationError::new(
            path,
            ReviewValidationReason::SchemaMismatch,
        ));
    }
    Ok(())
}

fn validate_result(schema: &Value, result: &Value) -> Result<(), ReviewValidationError> {
    check_review_json(result, RESULT_PATH, MAXIMUM_REVIEW_RESULT_BYTES, true)?;
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .map_err(|_| {
            ReviewValidationError::result_error(RESULT_PATH, ReviewValidationReason::SchemaMismatch)
        })?;
    if let Err(errors) = compiled.validate(result) {
        let path = errors
            .into_iter()
            .next()
            .map(|error| {
                let path = error.instance_path.to_string();
                if path.is_empty() {
                    RESULT_PATH.to_owned()
                } else {
                    format!("{RESULT_PATH}{path}")
                }
            })
            .unwrap_or_else(|| RESULT_PATH.to_owned());
        return Err(ReviewValidationError::result_error(
            path,
            ReviewValidationReason::SchemaMismatch,
        ));
    }
    Ok(())
}

/// A requester may only narrow a kind's declared result fields. Choice values
/// must satisfy the kind schema, and bounds must remain inside its bounds.
fn validate_result_constraints(
    schema: Option<&Value>,
    constraints: &Value,
) -> Result<(), ReviewValidationError> {
    let schema = schema.ok_or_else(|| {
        ReviewValidationError::new(
            RESULT_CONSTRAINTS_PATH,
            ReviewValidationReason::ResultNotDeclared,
        )
    })?;
    if !constraints.is_object() {
        return Err(ReviewValidationError::new(
            RESULT_CONSTRAINTS_PATH,
            ReviewValidationReason::ObjectRequired,
        ));
    }
    if !bounded_json(constraints, MAXIMUM_REVIEW_VALUE_DEPTH) {
        return Err(ReviewValidationError::new(
            RESULT_CONSTRAINTS_PATH,
            ReviewValidationReason::MaximumDepthExceeded,
        ));
    }
    if !registry_platform_canonical_json::canonicalize_json(constraints)
        .is_ok_and(|bytes| bytes.len() <= MAXIMUM_REVIEW_RESULT_CONSTRAINTS_BYTES)
    {
        return Err(ReviewValidationError::new(
            RESULT_CONSTRAINTS_PATH,
            ReviewValidationReason::MaximumBytesExceeded,
        ));
    }
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| constraint_invalid(RESULT_CONSTRAINTS_PATH))?;
    let mut relaxed = schema.clone();
    if let Some(object) = relaxed.as_object_mut() {
        object.remove("required");
    }
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&relaxed)
        .map_err(|_| constraint_invalid(RESULT_CONSTRAINTS_PATH))?;
    for (field, constraint) in constraints.as_object().expect("checked as an object above") {
        let field_path = result_field_path(RESULT_CONSTRAINTS_PATH, field);
        let subschema = properties.get(field).ok_or_else(|| {
            ReviewValidationError::new(field_path.clone(), ReviewValidationReason::FieldNotDeclared)
        })?;
        let constraint = constraint
            .as_object()
            .ok_or_else(|| constraint_invalid(&field_path))?;
        for keyword in constraint.keys() {
            if !matches!(
                keyword.as_str(),
                "enum" | "oneOf" | "minimum" | "maximum" | "minLength" | "maxLength"
            ) {
                return Err(constraint_invalid(&field_path));
            }
        }
        let has_enum = constraint.contains_key("enum");
        let has_one_of = constraint.contains_key("oneOf");
        if has_enum && has_one_of {
            return Err(constraint_invalid(&field_path));
        }
        if has_enum {
            let values = constraint["enum"]
                .as_array()
                .ok_or_else(|| constraint_invalid(&field_path))?;
            if values.is_empty() || values.len() > MAXIMUM_REVIEW_CONSTRAINT_CHOICES {
                return Err(constraint_invalid(&field_path));
            }
            for value in values {
                if !is_scalar(value) {
                    return Err(constraint_invalid(&field_path));
                }
                validate_constraint_value(&compiled, field, value)
                    .map_err(|()| constraint_invalid(&field_path))?;
            }
        }
        if has_one_of {
            let entries = constraint["oneOf"]
                .as_array()
                .ok_or_else(|| constraint_invalid(&field_path))?;
            if entries.is_empty() || entries.len() > MAXIMUM_REVIEW_CONSTRAINT_CHOICES {
                return Err(constraint_invalid(&field_path));
            }
            for entry in entries {
                let entry = entry
                    .as_object()
                    .ok_or_else(|| constraint_invalid(&field_path))?;
                let has_const = entry.contains_key("const");
                let has_title = entry.contains_key("title");
                if !has_const || entry.len() > 2 || (entry.len() == 2 && !has_title) {
                    return Err(constraint_invalid(&field_path));
                }
                let value = entry
                    .get("const")
                    .filter(|value| is_scalar(value))
                    .ok_or_else(|| constraint_invalid(&field_path))?;
                if let Some(title) = entry.get("title") {
                    let title = title
                        .as_str()
                        .ok_or_else(|| constraint_invalid(&field_path))?;
                    if title.chars().count() > MAXIMUM_REVIEW_CONSTRAINT_TITLE_CHARS
                        || title.chars().any(char::is_control)
                    {
                        return Err(ReviewValidationError::new(
                            field_path.clone(),
                            ReviewValidationReason::TextInvalid,
                        ));
                    }
                }
                validate_constraint_value(&compiled, field, value)
                    .map_err(|()| constraint_invalid(&field_path))?;
            }
        }
        check_constraint_bounds(&field_path, subschema, constraint)?;
    }
    Ok(())
}

fn check_constraint_bounds(
    field_path: &str,
    subschema: &Value,
    constraint: &serde_json::Map<String, Value>,
) -> Result<(), ReviewValidationError> {
    let declares_type = |wanted: &[&str]| {
        subschema.get("type").is_some_and(|value| match value {
            Value::String(name) => wanted.contains(&name.as_str()),
            Value::Array(names) => names
                .iter()
                .any(|name| name.as_str().is_some_and(|item| wanted.contains(&item))),
            _ => false,
        })
    };
    let minimum = constraint.get("minimum");
    let maximum = constraint.get("maximum");
    if minimum.is_some() || maximum.is_some() {
        if !declares_type(&["number", "integer"]) || !plain_inline_bounds(subschema) {
            return Err(constraint_invalid(field_path));
        }
        let minimum = minimum.filter(|value| value.is_number());
        let maximum = maximum.filter(|value| value.is_number());
        if constraint.contains_key("minimum") && minimum.is_none()
            || constraint.contains_key("maximum") && maximum.is_none()
            || minimum.zip(maximum).is_some_and(|(minimum, maximum)| {
                compare_json_numbers(minimum, maximum) == Some(Ordering::Greater)
            })
            || minimum
                .zip(subschema.get("minimum"))
                .is_some_and(|(minimum, schema_minimum)| {
                    compare_json_numbers(schema_minimum, minimum) == Some(Ordering::Greater)
                })
            || maximum
                .zip(subschema.get("maximum"))
                .is_some_and(|(maximum, schema_maximum)| {
                    compare_json_numbers(maximum, schema_maximum) == Some(Ordering::Greater)
                })
        {
            return Err(constraint_invalid(field_path));
        }
    }
    let min_length = constraint.get("minLength");
    let max_length = constraint.get("maxLength");
    if min_length.is_some() || max_length.is_some() {
        if !declares_type(&["string"]) || !plain_inline_bounds(subschema) {
            return Err(constraint_invalid(field_path));
        }
        let min_length = min_length
            .filter(|value| value.is_number())
            .and_then(Value::as_u64);
        let max_length = max_length
            .filter(|value| value.is_number())
            .and_then(Value::as_u64);
        if constraint.contains_key("minLength") && min_length.is_none()
            || constraint.contains_key("maxLength") && max_length.is_none()
            || min_length
                .zip(max_length)
                .is_some_and(|(minimum, maximum)| minimum > maximum)
            || min_length
                .zip(subschema.get("minLength").and_then(Value::as_u64))
                .is_some_and(|(minimum, schema_minimum)| schema_minimum > minimum)
            || max_length
                .zip(subschema.get("maxLength").and_then(Value::as_u64))
                .is_some_and(|(maximum, schema_maximum)| maximum > schema_maximum)
        {
            return Err(constraint_invalid(field_path));
        }
    }
    Ok(())
}

fn validate_constraint_value(compiled: &JSONSchema, field: &str, value: &Value) -> Result<(), ()> {
    let mut instance = serde_json::Map::new();
    instance.insert(field.to_owned(), value.clone());
    compiled.validate(&Value::Object(instance)).map_err(|_| ())
}

fn plain_inline_bounds(subschema: &Value) -> bool {
    subschema.as_object().is_some_and(|object| {
        !object.contains_key("$ref")
            && !object.contains_key("allOf")
            && !object.contains_key("anyOf")
            && !object.contains_key("oneOf")
    })
}

fn validate_result_narrowing(
    constraints: &Value,
    result: &Value,
) -> Result<(), ReviewValidationError> {
    let Some(fields) = constraints.as_object() else {
        return Ok(());
    };
    let result_fields = result.as_object().expect("result validated as an object");
    for (field, constraint) in fields {
        let Some(value) = result_fields.get(field) else {
            continue;
        };
        let field_path = result_field_path(RESULT_PATH, field);
        let violated = || {
            ReviewValidationError::result_error(
                field_path.clone(),
                ReviewValidationReason::ConstraintViolated,
            )
        };
        if constraint
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|choices| {
                !choices
                    .iter()
                    .any(|allowed| constraint_value_equals(allowed, value))
            })
            || constraint
                .get("oneOf")
                .and_then(Value::as_array)
                .is_some_and(|entries| {
                    !entries
                        .iter()
                        .filter_map(|entry| entry.get("const"))
                        .any(|allowed| constraint_value_equals(allowed, value))
                })
            || constraint
                .get("minimum")
                .is_some_and(|minimum| compare_json_numbers(value, minimum) == Some(Ordering::Less))
            || constraint.get("maximum").is_some_and(|maximum| {
                compare_json_numbers(value, maximum) == Some(Ordering::Greater)
            })
            || constraint
                .get("minLength")
                .and_then(Value::as_u64)
                .is_some_and(|minimum| {
                    value
                        .as_str()
                        .is_some_and(|text| character_count(text) < minimum)
                })
            || constraint
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|maximum| {
                    value
                        .as_str()
                        .is_some_and(|text| character_count(text) > maximum)
                })
        {
            return Err(violated());
        }
    }
    Ok(())
}

fn constraint_value_equals(allowed: &Value, actual: &Value) -> bool {
    if allowed.is_number() && actual.is_number() {
        compare_json_numbers(allowed, actual) == Some(Ordering::Equal)
    } else {
        allowed == actual
    }
}

fn compare_json_numbers(left: &Value, right: &Value) -> Option<Ordering> {
    let left = decimal_parts(left.as_number()?.to_string().as_str())?;
    let right = decimal_parts(right.as_number()?.to_string().as_str())?;
    if left.negative != right.negative {
        return Some(if left.negative {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    let magnitude = compare_decimal_magnitude(&left, &right);
    Some(if left.negative {
        magnitude.reverse()
    } else {
        magnitude
    })
}

struct DecimalParts {
    negative: bool,
    digits: Vec<u8>,
    scale: i64,
}

fn decimal_parts(value: &str) -> Option<DecimalParts> {
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |value| (true, value));
    let (coefficient, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or(Some((unsigned, 0_i64)), |(coefficient, exponent)| {
            Some((coefficient, exponent.parse().ok()?))
        })?;
    let (integer, fraction) = coefficient
        .split_once('.')
        .map_or((coefficient, ""), |(integer, fraction)| (integer, fraction));
    let combined = format!("{integer}{fraction}");
    let trimmed = combined.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(DecimalParts {
            negative: false,
            digits: vec![b'0'],
            scale: 0,
        });
    }
    if !trimmed.bytes().all(|digit| digit.is_ascii_digit()) {
        return None;
    }
    Some(DecimalParts {
        negative,
        digits: trimmed.as_bytes().to_vec(),
        scale: exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?,
    })
}

fn compare_decimal_magnitude(left: &DecimalParts, right: &DecimalParts) -> Ordering {
    let left_zero = left.digits == [b'0'];
    let right_zero = right.digits == [b'0'];
    match (left_zero, right_zero) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        (false, false) => {}
    }
    let left_extent = i64::try_from(left.digits.len())
        .unwrap_or(i64::MAX)
        .saturating_add(left.scale);
    let right_extent = i64::try_from(right.digits.len())
        .unwrap_or(i64::MAX)
        .saturating_add(right.scale);
    left_extent.cmp(&right_extent).then_with(|| {
        let width = left.digits.len().max(right.digits.len());
        (0..width)
            .map(|index| {
                left.digits
                    .get(index)
                    .copied()
                    .unwrap_or(b'0')
                    .cmp(&right.digits.get(index).copied().unwrap_or(b'0'))
            })
            .find(|ordering| *ordering != Ordering::Equal)
            .unwrap_or(Ordering::Equal)
    })
}

fn character_count(text: &str) -> u64 {
    u64::try_from(text.chars().count()).unwrap_or(u64::MAX)
}

fn is_scalar(value: &Value) -> bool {
    matches!(value, Value::Bool(_) | Value::Number(_) | Value::String(_))
}

fn result_field_path(prefix: &str, field: &str) -> String {
    if !field.bytes().all(valid_path_byte) {
        return prefix.to_owned();
    }
    let escaped_len = field.bytes().try_fold(0usize, |length, byte| {
        length.checked_add(if matches!(byte, b'/' | b'~') { 2 } else { 1 })
    });
    if escaped_len
        .and_then(|length| prefix.len().checked_add(length + 1))
        .is_none_or(|length| length > 256)
    {
        return prefix.to_owned();
    }
    let mut path = String::with_capacity(prefix.len() + escaped_len.unwrap_or_default() + 1);
    path.push_str(prefix);
    path.push('/');
    for byte in field.bytes() {
        match byte {
            b'~' => path.push_str("~0"),
            b'/' => path.push_str("~1"),
            _ => path.push(char::from(byte)),
        }
    }
    path
}

fn constraint_invalid(path: impl Into<String>) -> ReviewValidationError {
    ReviewValidationError::with_fallback(
        path,
        ReviewValidationReason::ConstraintInvalid,
        RESULT_CONSTRAINTS_PATH,
    )
}

fn bounded_json(value: &Value, maximum_depth: usize) -> bool {
    let mut pending = vec![(value, 1_usize)];
    while let Some((value, depth)) = pending.pop() {
        if depth > maximum_depth {
            return false;
        }
        match value {
            Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    true
}

fn schema_refs_are_local(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().all(|(key, value)| {
            if key == "$ref" {
                value
                    .as_str()
                    .is_some_and(|reference| reference == "#" || reference.starts_with("#/"))
            } else {
                schema_refs_are_local(value)
            }
        }),
        Value::Array(values) => values.iter().all(schema_refs_are_local),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => true,
    }
}

fn object_schemas_are_closed(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            let declares_object = object.get("type").is_some_and(|value| match value {
                Value::String(value) => value == "object",
                Value::Array(values) => values.iter().any(|value| value == "object"),
                _ => false,
            });
            let uses_object_keywords = [
                "properties",
                "patternProperties",
                "required",
                "minProperties",
                "maxProperties",
                "dependentRequired",
                "dependentSchemas",
                "propertyNames",
            ]
            .iter()
            .any(|keyword| object.contains_key(*keyword));
            let closed = if declares_object || uses_object_keywords {
                object.get("additionalProperties") == Some(&Value::Bool(false))
            } else {
                true
            };
            closed
                && object
                    .iter()
                    .all(|(keyword, value)| match keyword.as_str() {
                        "properties" | "patternProperties" | "dependentSchemas" | "$defs"
                        | "definitions" => value
                            .as_object()
                            .is_none_or(|schemas| schemas.values().all(object_schemas_are_closed)),
                        "allOf" | "anyOf" | "oneOf" | "prefixItems" => value
                            .as_array()
                            .is_none_or(|schemas| schemas.iter().all(object_schemas_are_closed)),
                        "additionalProperties"
                        | "unevaluatedProperties"
                        | "propertyNames"
                        | "contains"
                        | "items"
                        | "additionalItems"
                        | "unevaluatedItems"
                        | "not"
                        | "if"
                        | "then"
                        | "else"
                        | "contentSchema" => object_schemas_are_closed(value),
                        _ => true,
                    })
        }
        Value::Array(values) => values.iter().all(object_schemas_are_closed),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => true,
    }
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'-' | b'_')
        })
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn bounded_text(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum_bytes
        && value.chars().all(|character| !character.is_control())
}

fn valid_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'$' | b'.' | b'/' | b'_' | b'-' | b'~')
}

fn settlement_name(settlement: ReviewOutcomeSettlement) -> &'static str {
    match settlement {
        ReviewOutcomeSettlement::Approved => "approved",
        ReviewOutcomeSettlement::Rejected => "rejected",
        ReviewOutcomeSettlement::ChangesRequested => "changes-requested",
        ReviewOutcomeSettlement::Answered => "answered",
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "schema")]
    #[test]
    fn every_decision_variant_requires_an_outcome_with_no_default() {
        let schema = serde_json::to_value(schemars::schema_for!(DecisionKind)).unwrap();
        let variants = schema["oneOf"].as_array().unwrap();
        assert_eq!(variants.len(), 4);
        for variant in variants {
            assert!(
                variant["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|name| name == "outcome"),
                "{variant}"
            );
            let outcome = &variant["properties"]["outcome"];
            assert!(outcome.is_object(), "{variant}");
            assert!(outcome.get("default").is_none(), "{variant}");
        }
    }

    #[test]
    fn a_decision_receipt_names_the_outcome_its_decision_selected() {
        let policy = serde_json::json!({"id":"review","version":"1","digest":crate::ContentDigest::for_bytes(b"review")});
        let receipt = serde_json::json!({"policy":policy,"decision":"approve","outcome":"approved","outcomeLabel":"Approve","decidedAt":"2026-09-20T01:00:00Z"});
        let read: ReviewDecisionReceipt = serde_json::from_value(receipt.clone()).unwrap();
        assert_eq!(serde_json::to_value(&read).unwrap(), receipt);
        let mut without = receipt;
        without.as_object_mut().unwrap().remove("outcome");
        let refused = serde_json::from_value::<ReviewDecisionReceipt>(without).unwrap_err();
        assert!(
            refused.to_string().contains("missing field `outcome`"),
            "{refused}"
        );
    }

    #[test]
    fn cfg_id_1_an_identifier_follows_the_local_identifier_grammar() {
        assert!(valid_identifier("first_review-2"));
        assert!(valid_identifier(&format!("a{}", "b".repeat(63))));
        for refused in ["", "First", "1st", "_first", "first.review", "first review"] {
            assert!(!valid_identifier(refused));
        }
        assert!(!valid_identifier(&format!("a{}", "b".repeat(64))));
    }

    fn person(subject: &str) -> IssuerPrincipal {
        IssuerPrincipal {
            issuer: "https://issuer.example".to_owned(),
            subject: subject.to_owned(),
        }
    }

    fn stage(id: &str, required_approvals: u16) -> ReviewStagePolicy {
        ReviewStagePolicy {
            id: id.to_owned(),
            queue: "review".to_owned(),
            deciding_profiles: vec!["reviewer".to_owned()],
            required_approvals,
            exclude_initiator: true,
            exclude_previous_stage_reviewers: true,
        }
    }

    fn approval_policy(stages: Vec<ReviewStagePolicy>) -> ReviewPolicy {
        ReviewPolicy {
            id: "registry-correction".to_owned(),
            version: "1".to_owned(),
            purpose: ReviewPurpose::Approval,
            context: crate::ReviewContextPolicy::Submitted,
            routing: vec![],
            stages,
            clocks: Vec::new(),
            retention: ReviewRetentionPolicy {
                terminal_retention_days: 90,
                accountability_retention_days: 365,
            },
            display_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["summary"],
                "properties": {"summary": {"type": "string", "maxLength": 160}}
            }),
            result_schema: None,
            outcomes: vec![
                ReviewOutcomePolicy {
                    id: "approved".to_owned(),
                    label: "Approve".to_owned(),
                    settlement: ReviewOutcomeSettlement::Approved,
                    reason_required: false,
                    public_reason: ReviewPublicReasonRule::Optional,
                    result_required: false,
                },
                ReviewOutcomePolicy {
                    id: "rejected".to_owned(),
                    label: "Reject".to_owned(),
                    settlement: ReviewOutcomeSettlement::Rejected,
                    reason_required: true,
                    public_reason: ReviewPublicReasonRule::Optional,
                    result_required: false,
                },
                ReviewOutcomePolicy {
                    id: "changes-requested".to_owned(),
                    label: "Request changes".to_owned(),
                    settlement: ReviewOutcomeSettlement::ChangesRequested,
                    reason_required: true,
                    public_reason: ReviewPublicReasonRule::Optional,
                    result_required: false,
                },
            ],
        }
    }

    fn answer_policy() -> ReviewPolicy {
        ReviewPolicy {
            id: "standalone-question".to_owned(),
            version: "1".to_owned(),
            purpose: ReviewPurpose::Answer,
            context: crate::ReviewContextPolicy::Submitted,
            routing: vec![],
            stages: vec![stage("answer", 1)],
            clocks: Vec::new(),
            retention: ReviewRetentionPolicy {
                terminal_retention_days: 90,
                accountability_retention_days: 365,
            },
            display_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["question"],
                "properties": {"question": {"type": "string", "maxLength": 160}}
            }),
            result_schema: Some(json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["code"],
                "properties": {"code": {"type": "integer", "minimum": 1, "maximum": 9}}
            })),
            outcomes: vec![ReviewOutcomePolicy {
                id: "approved".to_owned(),
                label: "Record answer".to_owned(),
                settlement: ReviewOutcomeSettlement::Answered,
                reason_required: false,
                public_reason: ReviewPublicReasonRule::Optional,
                result_required: true,
            }],
        }
    }

    fn task(
        request_id: Uuid,
        stage_index: u16,
        stage_id: &str,
        nonce: u128,
        holder: &str,
    ) -> ReviewTask {
        ReviewTask {
            subject: SubjectBinding {
                source: "source".into(),
                subject_type: "subject".into(),
                id: "1".into(),
                version: "1".into(),
                digest: ContentDigest::for_bytes(b"subject"),
            },
            requester_reference: "reference".into(),
            deadline_at: None,
            created_at: Utc::now(),
            display_reference: None,
            task_id: Uuid::from_u128(nonce),
            request_id,
            stage_index,
            stage_id: stage_id.to_owned(),
            queue: "review".to_owned(),
            revision: 1,
            eligible_profiles: vec!["reviewer".to_owned()],
            state: ReviewTaskState::Held {
                holder: person(holder),
            },
            staffing_diagnostic: None,
            decided_by_caller: None,
            decision_receipt: None,
        }
    }

    fn approve(task: &ReviewTask, reviewer: IssuerPrincipal) -> Decision {
        Decision {
            task_id: task.task_id,
            request_id: task.request_id,
            stage_id: task.stage_id.clone(),
            reviewer,
            profile_id: "reviewer".to_owned(),
            decision: DecisionKind::Approve {
                outcome: "approved".to_owned(),
                public_reason: None,
            },
        }
    }

    #[test]
    fn stage_thresholds_are_independent_and_ordered() {
        let snapshot = approval_policy(vec![stage("technical", 2), stage("authority", 1)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let first = task(request_id, 0, "technical", 1, "a");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &first,
                approve(&first, person("a"))
            )
            .unwrap(),
            ReviewTransition::Recorded {
                remaining_approvals: 1
            }
        );
        let second = task(request_id, 0, "technical", 2, "b");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &second,
                approve(&second, person("b"))
            )
            .unwrap(),
            ReviewTransition::StageAdvanced {
                completed_stage: "technical".to_owned(),
                next_stage: "authority".to_owned(),
            }
        );
        assert!(progress.settlement.is_none());
        let third = task(request_id, 1, "authority", 3, "c");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &third,
                approve(&third, person("c"))
            )
            .unwrap(),
            ReviewTransition::Settled {
                settlement: ReviewSettlement::Approved {
                    outcome: "approved".to_owned(),
                    public_reason: None,
                }
            }
        );
    }

    #[test]
    fn duplicate_initiator_and_previous_stage_reviewers_are_refused() {
        let snapshot = approval_policy(vec![stage("first", 2), stage("second", 1)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let initiator = person("initiator");
        let mut progress =
            ReviewProgress::new(request_id, Some(initiator.clone()), None, &snapshot).unwrap();
        let initiator_task = task(request_id, 0, "first", 1, "initiator");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &initiator_task,
                approve(&initiator_task, initiator)
            ),
            Err(ReviewDecisionError::InitiatorExcluded)
        );
        let first = task(request_id, 0, "first", 2, "a");
        record_review_decision(
            &snapshot,
            &mut progress,
            &first,
            approve(&first, person("a")),
        )
        .unwrap();
        let duplicate = task(request_id, 0, "first", 3, "a");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &duplicate,
                approve(&duplicate, person("a"))
            ),
            Err(ReviewDecisionError::DuplicateReviewer)
        );
        let completing = task(request_id, 0, "first", 4, "b");
        record_review_decision(
            &snapshot,
            &mut progress,
            &completing,
            approve(&completing, person("b")),
        )
        .unwrap();
        let prior = task(request_id, 1, "second", 5, "a");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &prior,
                approve(&prior, person("a"))
            ),
            Err(ReviewDecisionError::PreviousStageReviewerExcluded)
        );
    }

    #[test]
    fn empty_or_zero_count_stages_are_refused_and_insufficient_staffing_stays_open() {
        assert_eq!(
            approval_policy(vec![]).check(),
            Err(ReviewPolicyError::Stages)
        );
        assert_eq!(
            approval_policy(vec![stage("invalid", 0)]).check(),
            Err(ReviewPolicyError::StageThreshold)
        );

        let snapshot = approval_policy(vec![stage("only", 2)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let only_staffed_task = task(request_id, 0, "only", 1, "sole-reviewer");
        assert!(matches!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &only_staffed_task,
                approve(&only_staffed_task, person("sole-reviewer"))
            ),
            Ok(ReviewTransition::Recorded {
                remaining_approvals: 1
            })
        ));
        assert!(progress.settlement.is_none());
    }

    #[test]
    fn policy_closure_digest_pins_every_stage_rule() {
        let mut snapshot = approval_policy(vec![stage("first", 1)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        assert_eq!(
            serde_json::to_value(&snapshot.identity).unwrap(),
            json!({
                "id": "registry-correction",
                "version": "1",
                "digest": snapshot.identity.digest.clone(),
            })
        );
        snapshot.stages[0].exclude_initiator = false;
        assert_eq!(snapshot.verify(), Err(ReviewPolicyError::DigestMismatch));

        let mut context_snapshot = approval_policy(vec![stage("first", 1)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        context_snapshot.context = crate::ReviewContextPolicy::CurrentSource {
            provider: "provider".into(),
            contract: crate::ReviewContextContract {
                id: "contract".into(),
                revision: ContentDigest::for_bytes(b"contract"),
                schema_digest: ContentDigest::for_bytes(b"schema"),
            },
        };
        assert_eq!(
            context_snapshot.verify(),
            Err(ReviewPolicyError::DigestMismatch)
        );

        let mut clock_snapshot = approval_policy(vec![stage("first", 1)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        clock_snapshot.clocks.push("response-deadline".to_owned());
        assert_eq!(
            clock_snapshot.verify(),
            Err(ReviewPolicyError::DigestMismatch)
        );

        let mut oversized = approval_policy(vec![stage("first", 1)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        oversized.display_schema = Value::String("x".repeat(MAXIMUM_REVIEW_POLICY_CLOSURE_BYTES));
        assert_eq!(oversized.verify(), Err(ReviewPolicyError::ClosureSize));
    }

    #[test]
    fn accepted_policy_fields_fit_the_closure_envelope() {
        fn identifier(prefix: char, index: usize) -> String {
            let suffix = format!("{index:02}");
            format!("{prefix}{}{suffix}", "a".repeat(63 - suffix.len()))
        }

        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        });
        let mut policy = approval_policy(
            (0..MAXIMUM_REVIEW_STAGES)
                .map(|stage_index| ReviewStagePolicy {
                    id: identifier('s', stage_index),
                    queue: identifier('q', stage_index),
                    deciding_profiles: (0..MAXIMUM_REVIEW_PROFILES_PER_STAGE)
                        .map(|profile_index| identifier('p', profile_index))
                        .collect(),
                    required_approvals: MAXIMUM_REVIEW_APPROVALS_PER_STAGE,
                    exclude_initiator: true,
                    exclude_previous_stage_reviewers: true,
                })
                .collect(),
        );
        policy.id = "a".repeat(64);
        policy.version = "v".repeat(64);
        policy.context = crate::ReviewContextPolicy::Submitted;
        policy.clocks = (0..32).map(|index| identifier('c', index)).collect();
        policy.retention = ReviewRetentionPolicy {
            terminal_retention_days: MAXIMUM_REVIEW_RETENTION_DAYS,
            accountability_retention_days: MAXIMUM_REVIEW_RETENTION_DAYS,
        };
        policy.display_schema = schema.clone();
        policy.result_schema = Some(schema.clone());
        // An approval policy declares one approved outcome, which can
        // require neither a reason nor a result; every other outcome carries
        // the largest metadata.
        policy.outcomes = (0..MAXIMUM_REVIEW_OUTCOMES)
            .map(|index| ReviewOutcomePolicy {
                id: identifier('o', index),
                label: "\"".repeat(120),
                settlement: if index == 0 {
                    ReviewOutcomeSettlement::Approved
                } else {
                    ReviewOutcomeSettlement::ChangesRequested
                },
                reason_required: index != 0,
                public_reason: ReviewPublicReasonRule::Optional,
                result_required: index != 0,
            })
            .collect();

        let snapshot = policy
            .closure_with(crate::ReviewPolicyDependencies::default())
            .expect("maximum bounded policy metadata");
        let snapshot_bytes = registry_platform_canonical_json::canonicalize_json(
            &serde_json::to_value(snapshot).expect("snapshot value"),
        )
        .expect("canonical snapshot");
        let schema_bytes = registry_platform_canonical_json::canonicalize_json(&schema)
            .expect("canonical schema")
            .len();
        let maximum_accepted_bytes =
            snapshot_bytes.len() - 2 * schema_bytes + 2 * MAXIMUM_REVIEW_SCHEMA_BYTES;
        assert!(maximum_accepted_bytes <= MAXIMUM_REVIEW_POLICY_CLOSURE_BYTES);
    }

    #[test]
    fn subject_clock_correlation_names_the_subject_of_each_request_and_activity_names_the_task() {
        let clock = ClockPolicy::Subject {
            id: "response-budget".to_owned(),
            anchor: crate::SubjectClockAnchor {
                kind: crate::SubjectClockAnchorType::RequestAccepted,
            },
            after: crate::ElapsedDuration::Hours(1),
        };
        let first = SubjectBinding {
            source: "registry".to_owned(),
            subject_type: "record".to_owned(),
            id: "record-1".to_owned(),
            version: "1".to_owned(),
            digest: ContentDigest::for_bytes(b"one"),
        };
        let mut next = first.clone();
        next.version = "2".to_owned();
        next.digest = ContentDigest::for_bytes(b"two");
        let first_request = Uuid::from_u128(1);
        let next_request = Uuid::from_u128(2);

        assert_eq!(
            ReviewClockCorrelation::for_policy(&clock, &first, first_request, "review"),
            ReviewClockCorrelation::for_policy(&clock, &next, next_request, "review")
        );
        assert_ne!(
            ReviewClockCorrelation::Activity {
                task_id: first_request,
                stage_id: "review".to_owned(),
            },
            ReviewClockCorrelation::Activity {
                task_id: next_request,
                stage_id: "review".to_owned(),
            }
        );
    }

    #[test]
    fn review_clock_correlation_uses_camel_case_wire_fields() {
        assert_eq!(
            serde_json::to_value(ReviewClockCorrelation::Subject {
                source: "registry".to_owned(),
                subject_type: "record".to_owned(),
                id: "record-1".to_owned(),
            })
            .unwrap(),
            json!({
                "scope": "subject",
                "source": "registry",
                "subjectType": "record",
                "id": "record-1",
            })
        );
        assert_eq!(
            serde_json::to_value(ReviewClockCorrelation::Activity {
                task_id: Uuid::from_u128(1),
                stage_id: "review".to_owned(),
            })
            .unwrap(),
            json!({
                "scope": "activity",
                "taskId": "00000000-0000-0000-0000-000000000001",
                "stageId": "review",
            })
        );
    }

    #[test]
    fn review_outcome_omits_result_required_when_false() {
        let mut outcome = approval_policy(vec![stage("review", 1)]).outcomes.remove(0);
        let omitted = serde_json::to_value(&outcome).unwrap();
        assert!(!omitted.as_object().unwrap().contains_key("resultRequired"));

        outcome.result_required = true;
        assert_eq!(
            serde_json::to_value(outcome).unwrap()["resultRequired"],
            true
        );
    }

    #[test]
    fn an_open_task_cannot_be_decided_without_current_ownership() {
        let snapshot = approval_policy(vec![stage("review", 1)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let mut open_task = task(request_id, 0, "review", 1, "reviewer");
        open_task.state = ReviewTaskState::Open;
        let decision = approve(&open_task, person("reviewer"));

        assert_eq!(
            record_review_decision(&snapshot, &mut progress, &open_task, decision),
            Err(ReviewDecisionError::TaskNotHeld)
        );
        assert!(progress.decisions.is_empty());
        assert!(progress.settlement.is_none());
    }

    /// Corrupts a snapshot's stored digest so `ReviewPolicyClosure::verify`
    /// fails, without touching the valid snapshot the caller already used to
    /// build `ReviewProgress`. Used to prove the cheap task-state/holder check
    /// runs before the expensive policy re-verification in
    /// `record_review_decision`.
    fn corrupted(mut snapshot: ReviewPolicyClosure) -> ReviewPolicyClosure {
        snapshot.identity.digest = ContentDigest::for_bytes(b"tampered-policy-snapshot");
        snapshot
    }

    #[test]
    fn holder_mismatch_is_refused_before_policy_verification() {
        let snapshot = approval_policy(vec![stage("review", 1)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let held_task = task(request_id, 0, "review", 1, "holder-a");
        let decision = approve(&held_task, person("holder-b"));

        assert_eq!(
            record_review_decision(&corrupted(snapshot), &mut progress, &held_task, decision),
            Err(ReviewDecisionError::HolderMismatch)
        );
        assert!(progress.decisions.is_empty());
        assert!(progress.settlement.is_none());
    }

    #[test]
    fn open_task_is_refused_before_policy_verification() {
        let snapshot = approval_policy(vec![stage("review", 1)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let mut open_task = task(request_id, 0, "review", 1, "reviewer");
        open_task.state = ReviewTaskState::Open;
        let decision = approve(&open_task, person("reviewer"));

        assert_eq!(
            record_review_decision(&corrupted(snapshot), &mut progress, &open_task, decision),
            Err(ReviewDecisionError::TaskNotHeld)
        );
        assert!(progress.decisions.is_empty());
        assert!(progress.settlement.is_none());
    }

    #[test]
    fn decided_task_is_refused_before_policy_verification() {
        let snapshot = approval_policy(vec![stage("review", 1)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let mut decided_task = task(request_id, 0, "review", 1, "reviewer");
        decided_task.state = ReviewTaskState::Decided;
        let decision = approve(&decided_task, person("reviewer"));

        assert_eq!(
            record_review_decision(&corrupted(snapshot), &mut progress, &decided_task, decision),
            Err(ReviewDecisionError::TaskAlreadyDecided)
        );
        assert!(progress.decisions.is_empty());
        assert!(progress.settlement.is_none());
    }

    #[test]
    fn custom_outcome_named_approved_settles_as_answered() {
        let snapshot = answer_policy()
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let task = task(request_id, 0, "answer", 1, "answerer");
        let decision = Decision {
            task_id: task.task_id,
            request_id,
            stage_id: "answer".to_owned(),
            reviewer: person("answerer"),
            profile_id: "reviewer".to_owned(),
            decision: DecisionKind::Answer {
                outcome: "approved".to_owned(),
                reason: None,
                public_reason: None,
                result: Some(json!({"code": 4})),
            },
        };
        let transition = record_review_decision(&snapshot, &mut progress, &task, decision).unwrap();
        assert_eq!(
            transition,
            ReviewTransition::Settled {
                settlement: ReviewSettlement::Answered {
                    outcome: "approved".to_owned(),
                    public_reason: None,
                    result: Some(json!({"code": 4})),
                }
            }
        );
        assert_eq!(
            progress.settlement.unwrap().result_status(),
            ReviewResultStatus::Answered
        );
    }

    #[test]
    fn structured_answers_reuse_required_result_and_schema_rules() {
        let snapshot = answer_policy()
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let request_id = Uuid::from_u128(100);

        let invalid_result = |result: Option<Value>| Decision {
            task_id: Uuid::from_u128(1),
            request_id,
            stage_id: "answer".to_owned(),
            reviewer: person("answerer"),
            profile_id: "reviewer".to_owned(),
            decision: DecisionKind::Answer {
                outcome: "approved".to_owned(),
                reason: None,
                public_reason: None,
                result,
            },
        };
        let task = task(request_id, 0, "answer", 1, "answerer");

        for result in [None, Some(json!({"code": "four"}))] {
            let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
            assert!(matches!(
                record_review_decision(&snapshot, &mut progress, &task, invalid_result(result)),
                Err(ReviewDecisionError::Validation(
                    ReviewDecisionValidationError::Structured(_)
                ))
            ));
            assert!(progress.decisions.is_empty());
            assert!(progress.settlement.is_none());
        }

        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        assert!(record_review_decision(
            &snapshot,
            &mut progress,
            &task,
            invalid_result(Some(json!({"code": 4})))
        )
        .is_ok());
    }

    #[test]
    fn review_schemas_are_closed_and_display_errors_are_bounded() {
        let mut policy = answer_policy();
        policy.display_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"details": {"properties": {"secret": {"type": "string"}}}}
        });
        assert_eq!(policy.check(), Err(ReviewPolicyError::Schema));

        policy.display_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"details": {"$ref": "https://example.test/details.json"}}
        });
        assert_eq!(policy.check(), Err(ReviewPolicyError::Schema));

        let snapshot = answer_policy()
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let secret = "sensitive-display-value".repeat(20);
        let error = snapshot
            .validate_display(&json!({"question": secret}))
            .expect_err("the display schema bounds question text");
        let ReviewDecisionValidationError::Structured(error) = error else {
            panic!("expected structured display validation failure");
        };
        assert_eq!(error.path, "$.display/question");
        assert_eq!(error.reason, ReviewValidationReason::SchemaMismatch);
        assert!(!error.to_string().contains("sensitive-display-value"));
        assert!(!error.to_string().contains("hosted"));
    }

    #[test]
    fn result_constraints_refuse_widening_and_apply_after_schema_validation() {
        assert_eq!(
            compare_json_numbers(
                &json!(9_007_199_254_740_992_u64),
                &json!(9_007_199_254_740_993_u64)
            ),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_json_numbers(
                &json!(-9_007_199_254_740_993_i64),
                &json!(-9_007_199_254_740_992_i64)
            ),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_json_numbers(&json!(0), &json!(0.5)),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_json_numbers(&json!(0.5), &json!(0)),
            Some(Ordering::Greater)
        );
        let snapshot = answer_policy()
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        assert_eq!(
            snapshot.validate_result_constraints(&json!({
                "code": {"minimum": 4, "maximum": 6}
            })),
            Ok(())
        );
        for (constraints, expected) in [
            (
                json!({"code": {"minimum": 0}}),
                ReviewValidationReason::ConstraintInvalid,
            ),
            (
                json!({"undeclared": {"enum": [4]}}),
                ReviewValidationReason::FieldNotDeclared,
            ),
        ] {
            let error = snapshot
                .validate_result_constraints(&constraints)
                .expect_err("constraints cannot widen the pinned result schema");
            let ReviewDecisionValidationError::Structured(error) = error else {
                panic!("expected structured constraint validation failure");
            };
            assert_eq!(error.reason, expected);
        }

        let request_id = Uuid::from_u128(100);
        let task = task(request_id, 0, "answer", 1, "answerer");
        let decide = |result: Value| Decision {
            task_id: task.task_id,
            request_id,
            stage_id: "answer".to_owned(),
            reviewer: person("answerer"),
            profile_id: "reviewer".to_owned(),
            decision: DecisionKind::Answer {
                outcome: "approved".to_owned(),
                reason: None,
                public_reason: None,
                result: Some(result),
            },
        };
        for (result, expected) in [
            (
                json!({"code": "not-an-integer"}),
                ReviewValidationReason::SchemaMismatch,
            ),
            (
                json!({"code": 7}),
                ReviewValidationReason::ConstraintViolated,
            ),
        ] {
            let mut progress = ReviewProgress::new(
                request_id,
                None,
                Some(json!({"code": {"minimum": 4, "maximum": 6}})),
                &snapshot,
            )
            .unwrap();
            let error = record_review_decision(&snapshot, &mut progress, &task, decide(result))
                .expect_err("the result must satisfy the schema and its narrowing");
            let ReviewDecisionError::Validation(ReviewDecisionValidationError::Structured(error)) =
                error
            else {
                panic!("expected structured decision validation failure");
            };
            assert_eq!(error.reason, expected);
            assert!(progress.decisions.is_empty());
            assert!(progress.settlement.is_none());
        }
    }

    #[test]
    fn numeric_choices_use_json_schema_value_equality() {
        let mut policy = answer_policy();
        policy.result_schema = Some(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["score"],
            "properties": {"score": {"type": "number"}}
        }));
        let snapshot = policy
            .closure_with(crate::ReviewPolicyDependencies::default())
            .expect("numeric-choice policy closures");
        let request_id = Uuid::from_u128(100);
        let task = task(request_id, 0, "answer", 1, "answerer");

        for constraints in [
            json!({"score": {"enum": [1]}}),
            json!({"score": {"oneOf": [{"const": 1, "title": "One"}]}}),
        ] {
            snapshot
                .validate_result_constraints(&constraints)
                .expect("integer notation is a valid numeric narrowing");
            let mut progress =
                ReviewProgress::new(request_id, None, Some(constraints), &snapshot).unwrap();
            let decision = Decision {
                task_id: task.task_id,
                request_id,
                stage_id: "answer".to_owned(),
                reviewer: person("answerer"),
                profile_id: "reviewer".to_owned(),
                decision: DecisionKind::Answer {
                    outcome: "approved".to_owned(),
                    reason: None,
                    public_reason: None,
                    result: Some(json!({"score": 1.0})),
                },
            };
            record_review_decision(&snapshot, &mut progress, &task, decision)
                .expect("1 and 1.0 are equal JSON Schema numbers");
        }
    }

    #[test]
    fn decision_deserialization_preserves_explicit_null_result() {
        let explicit_null: DecisionKind = serde_json::from_value(json!({
            "type": "answer",
            "outcome": "approved",
            "result": null
        }))
        .expect("explicit null remains a semantic validation input");
        assert!(matches!(
            explicit_null,
            DecisionKind::Answer {
                result: Some(Value::Null),
                ..
            }
        ));

        let omitted: DecisionKind = serde_json::from_value(json!({
            "type": "answer",
            "outcome": "approved"
        }))
        .expect("an omitted optional result remains absent");
        assert!(matches!(omitted, DecisionKind::Answer { result: None, .. }));
    }

    #[test]
    fn result_paths_escape_json_pointer_segments() {
        assert_eq!(
            result_field_path(RESULT_PATH, "path/segment"),
            "$.result/path~1segment"
        );
        assert_eq!(
            result_field_path(RESULT_CONSTRAINTS_PATH, "tilde~segment"),
            "$.resultConstraints/tilde~0segment"
        );
    }

    #[test]
    fn review_retention_and_outcome_vocabulary_are_bounded() {
        let mut policy = answer_policy();
        policy.retention.accountability_retention_days =
            policy.retention.terminal_retention_days - 1;
        assert_eq!(policy.check(), Err(ReviewPolicyError::Retention));

        let mut policy = answer_policy();
        policy.outcomes.push(policy.outcomes[0].clone());
        assert_eq!(policy.check(), Err(ReviewPolicyError::Outcomes));
    }

    /// A validation reason is a word a caller reads in the validation
    /// problem, so it is spelled as every other value is: kebab-case.
    #[test]
    fn every_review_validation_reason_is_kebab_case() {
        let expected = [
            (
                ReviewValidationReason::PolicyNotAllowed,
                "policy-not-allowed",
            ),
            (
                ReviewValidationReason::ReferenceInvalid,
                "reference-invalid",
            ),
            (ReviewValidationReason::ObjectRequired, "object-required"),
            (
                ReviewValidationReason::MaximumBytesExceeded,
                "maximum-bytes-exceeded",
            ),
            (
                ReviewValidationReason::MaximumDepthExceeded,
                "maximum-depth-exceeded",
            ),
            (ReviewValidationReason::SchemaMismatch, "schema-mismatch"),
            (
                ReviewValidationReason::OutcomeNotDeclared,
                "outcome-not-declared",
            ),
            (ReviewValidationReason::ReasonRequired, "reason-required"),
            (ReviewValidationReason::TextInvalid, "text-invalid"),
            (
                ReviewValidationReason::ResultNotDeclared,
                "result-not-declared",
            ),
            (ReviewValidationReason::ResultRequired, "result-required"),
            (
                ReviewValidationReason::FieldNotDeclared,
                "field-not-declared",
            ),
            (
                ReviewValidationReason::ConstraintInvalid,
                "constraint-invalid",
            ),
            (
                ReviewValidationReason::ConstraintViolated,
                "constraint-violated",
            ),
        ];
        for (reason, word) in expected {
            assert_eq!(serde_json::to_value(reason).unwrap(), word);
            assert_eq!(
                serde_json::from_value::<ReviewValidationReason>(serde_json::json!(word)).unwrap(),
                reason
            );
            assert!(
                serde_json::from_value::<ReviewValidationReason>(serde_json::json!(
                    word.replace('-', "_")
                ))
                .is_err(),
                "the previous spelling of {word} is refused"
            );
        }
    }

    #[test]
    fn review_task_ownership_and_decision_receipt_words_are_kebab_case() {
        for (value, word) in [
            (
                serde_json::to_value(ReviewTaskOwnership::AssignedToMe).unwrap(),
                "assigned-to-me",
            ),
            (
                serde_json::to_value(ReviewTaskOwnership::Unclaimed).unwrap(),
                "unclaimed",
            ),
            (
                serde_json::to_value(ReviewDecisionType::ChangesRequested).unwrap(),
                "changes-requested",
            ),
            (
                serde_json::to_value(SupervisoryReviewTaskState::Held).unwrap(),
                "held",
            ),
        ] {
            assert_eq!(value, word);
        }
        assert!(
            serde_json::from_value::<ReviewTaskOwnership>(serde_json::json!("assigned_to_me"))
                .is_err(),
            "the ownership selector has one spelling"
        );
        assert!(
            serde_json::from_value::<ReviewDecisionType>(serde_json::json!("changes_requested"))
                .is_err(),
            "the receipt decision has one spelling"
        );
    }

    #[test]
    fn multi_word_review_values_are_kebab_case() {
        let decision: DecisionKind = serde_json::from_value(serde_json::json!({
            "type": "changes-requested",
            "outcome": "needs-change",
        }))
        .expect("the decision type is read in kebab-case");
        assert!(matches!(decision, DecisionKind::ChangesRequested { .. }));
        assert_eq!(
            serde_json::to_value(&decision).unwrap()["type"],
            "changes-requested"
        );
        assert!(
            serde_json::from_value::<DecisionKind>(serde_json::json!({
                "type": "changes_requested",
                "outcome": "needs-change",
            }))
            .is_err(),
            "the previous spelling of the decision type is refused"
        );

        let settlement = ReviewSettlement::ChangesRequested {
            outcome: "needs-change".to_owned(),
            public_reason: None,
            result: None,
        };
        let settled = serde_json::to_value(ReviewTransition::Settled {
            settlement: settlement.clone(),
        })
        .unwrap();
        assert_eq!(settled["settlement"]["status"], "changes-requested");
        assert_eq!(
            serde_json::from_value::<ReviewTransition>(settled.clone()).unwrap(),
            ReviewTransition::Settled { settlement }
        );
        let mut previous = settled;
        previous["settlement"]["status"] = serde_json::json!("changes_requested");
        assert!(serde_json::from_value::<ReviewTransition>(previous).is_err());

        let advanced = serde_json::to_value(ReviewTransition::StageAdvanced {
            completed_stage: "technical".to_owned(),
            next_stage: "authority".to_owned(),
        })
        .unwrap();
        assert_eq!(advanced["type"], "stage-advanced");
        let mut previous = advanced;
        previous["type"] = serde_json::json!("stage_advanced");
        assert!(serde_json::from_value::<ReviewTransition>(previous).is_err());

        assert_eq!(
            serde_json::to_value(ReviewSourceBindingStatus::BindingChanged).unwrap(),
            "binding-changed"
        );
        assert!(
            serde_json::from_value::<ReviewSourceBindingStatus>(serde_json::json!(
                "binding_changed"
            ))
            .is_err()
        );
    }

    #[test]
    fn rejection_and_changes_requested_veto_without_waiting_for_threshold() {
        let snapshot = approval_policy(vec![stage("review", 3)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let request_id = Uuid::from_u128(100);
        for (decision_kind, expected) in [
            (
                DecisionKind::Reject {
                    outcome: "rejected".to_owned(),
                    reason: Some("unsafe".to_owned()),
                    public_reason: None,
                    result: None,
                },
                ReviewSettlement::Rejected {
                    outcome: "rejected".to_owned(),
                    public_reason: None,
                    result: None,
                },
            ),
            (
                DecisionKind::ChangesRequested {
                    outcome: "changes-requested".to_owned(),
                    reason: Some("correct target".to_owned()),
                    public_reason: None,
                    result: None,
                },
                ReviewSettlement::ChangesRequested {
                    outcome: "changes-requested".to_owned(),
                    public_reason: None,
                    result: None,
                },
            ),
        ] {
            let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
            let task = task(request_id, 0, "review", 1, "reviewer");
            let decision = Decision {
                task_id: task.task_id,
                request_id,
                stage_id: "review".to_owned(),
                reviewer: person("reviewer"),
                profile_id: "reviewer".to_owned(),
                decision: decision_kind,
            };
            assert_eq!(
                record_review_decision(&snapshot, &mut progress, &task, decision),
                Ok(ReviewTransition::Settled {
                    settlement: expected
                })
            );
        }
    }

    #[test]
    fn approval_policies_declare_an_approved_outcome() {
        let mut policy = approval_policy(vec![stage("review", 1)]);
        policy
            .outcomes
            .retain(|outcome| outcome.settlement != ReviewOutcomeSettlement::Approved);
        assert_eq!(policy.check(), Err(ReviewPolicyError::ApprovalOutcomes));
        let finding = policy
            .findings()
            .into_iter()
            .find(|finding| {
                finding.code == "casework.review-policy.approval-without-approved-outcome"
            })
            .expect("the missing approved outcome is reported");
        assert_eq!(finding.pointer, "/outcomes");
        assert_eq!(
            finding.suggested_action,
            "Declare an outcome with settlement: approved."
        );
    }

    #[test]
    fn approval_must_name_a_declared_approved_outcome() {
        let snapshot = approval_policy(vec![stage("review", 1)])
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap();
        let request_id = Uuid::from_u128(100);
        // An empty outcome is what a decision without `outcome` reads as.
        for outcome in ["", "rejected", "undeclared"] {
            let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
            let task = task(request_id, 0, "review", 1, "reviewer");
            let mut decision = approve(&task, person("reviewer"));
            decision.decision = DecisionKind::Approve {
                outcome: outcome.to_owned(),
                public_reason: None,
            };
            let error =
                record_review_decision(&snapshot, &mut progress, &task, decision).unwrap_err();
            assert_eq!(
                error,
                ReviewDecisionError::OutcomeNotAllowed {
                    settlement: ReviewOutcomeSettlement::Approved,
                    declared: vec!["approved".to_owned()],
                }
            );
            assert_eq!(
                error.to_string(),
                "outcome must name a declared approved outcome of this review policy; use one of: approved"
            );
            assert!(progress.decisions.is_empty());
        }
    }

    #[test]
    fn public_reasons_follow_the_outcome_rule() {
        let request_id = Uuid::from_u128(100);
        let decide = |rule: ReviewPublicReasonRule, public_reason: Option<&str>| {
            let mut policy = approval_policy(vec![stage("review", 1)]);
            policy.outcomes[1].public_reason = rule;
            let snapshot = policy
                .closure_with(crate::ReviewPolicyDependencies::default())
                .unwrap();
            let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
            let task = task(request_id, 0, "review", 1, "reviewer");
            let mut decision = approve(&task, person("reviewer"));
            decision.decision = DecisionKind::Reject {
                outcome: "rejected".to_owned(),
                reason: Some("private reviewer note".to_owned()),
                public_reason: public_reason.map(str::to_owned),
                result: None,
            };
            record_review_decision(&snapshot, &mut progress, &task, decision)
        };
        let refused = |reason: ReviewValidationReason| {
            Err(ReviewDecisionError::Validation(
                ReviewValidationError::new("$.publicReason", reason).into(),
            ))
        };
        assert_eq!(
            decide(ReviewPublicReasonRule::Required, None),
            refused(ReviewValidationReason::PublicReasonRequired)
        );
        assert_eq!(
            decide(ReviewPublicReasonRule::None, Some("Not eligible.")),
            refused(ReviewValidationReason::PublicReasonNotDeclared)
        );
        assert_eq!(
            decide(
                ReviewPublicReasonRule::Optional,
                Some(&"x".repeat(registry_review_protocol::MAXIMUM_PUBLIC_REASON_BYTES + 1))
            ),
            refused(ReviewValidationReason::MaximumBytesExceeded)
        );
        for (rule, public_reason) in [
            (ReviewPublicReasonRule::Required, Some("Not eligible.")),
            (ReviewPublicReasonRule::Optional, Some("Not eligible.")),
            (ReviewPublicReasonRule::Optional, None),
            (ReviewPublicReasonRule::None, None),
        ] {
            assert_eq!(
                decide(rule, public_reason),
                Ok(ReviewTransition::Settled {
                    settlement: ReviewSettlement::Rejected {
                        outcome: "rejected".to_owned(),
                        public_reason: public_reason.map(str::to_owned),
                        result: None,
                    }
                })
            );
        }
    }

    /// An oversized reason names the byte bound, so the fix is in the
    /// refusal; blank text and control characters stay invalid text.
    #[test]
    fn reasons_over_the_byte_bound_name_the_bound() {
        let request_id = Uuid::from_u128(100);
        let decide = |reason: Option<String>, public_reason: Option<String>| {
            let mut policy = approval_policy(vec![stage("review", 1)]);
            policy.outcomes[1].public_reason = ReviewPublicReasonRule::Optional;
            let snapshot = policy
                .closure_with(crate::ReviewPolicyDependencies::default())
                .unwrap();
            let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
            let task = task(request_id, 0, "review", 1, "reviewer");
            let mut decision = approve(&task, person("reviewer"));
            decision.decision = DecisionKind::Reject {
                outcome: "rejected".to_owned(),
                reason,
                public_reason,
                result: None,
            };
            record_review_decision(&snapshot, &mut progress, &task, decision)
        };
        let refused = |path: &str, reason: ReviewValidationReason| {
            Err(ReviewDecisionError::Validation(
                ReviewValidationError::new(path, reason).into(),
            ))
        };
        let public_maximum = MAXIMUM_PUBLIC_REASON_BYTES;
        for (path, maximum) in [
            ("$.reason", MAXIMUM_REVIEW_REASON_BYTES),
            ("$.publicReason", public_maximum),
        ] {
            let at = |text: String| {
                if path == "$.reason" {
                    decide(Some(text), None)
                } else {
                    decide(Some("private reviewer note".to_owned()), Some(text))
                }
            };
            assert_eq!(
                at("x".repeat(maximum + 1)),
                refused(path, ReviewValidationReason::MaximumBytesExceeded),
                "{path}"
            );
            assert!(at("x".repeat(maximum)).is_ok(), "{path}");
            assert_eq!(
                at("   ".to_owned()),
                refused(path, ReviewValidationReason::TextInvalid),
                "{path}"
            );
            assert_eq!(
                at("not\u{7}eligible".to_owned()),
                refused(path, ReviewValidationReason::TextInvalid),
                "{path}"
            );
        }
    }

    #[test]
    fn input_bounds_name_the_byte_bound_before_the_text_rules() {
        let check = |reason: Option<String>, public_reason: Option<String>| {
            DecisionKind::Reject {
                outcome: "rejected".to_owned(),
                reason,
                public_reason,
                result: None,
            }
            .check_input()
        };
        for (path, maximum) in [
            ("$.reason", MAXIMUM_REVIEW_REASON_BYTES),
            ("$.publicReason", MAXIMUM_PUBLIC_REASON_BYTES),
        ] {
            let at = |text: String| {
                if path == "$.reason" {
                    check(Some(text), None)
                } else {
                    check(None, Some(text))
                }
            };
            assert_eq!(
                at("x".repeat(maximum + 1)),
                Err(ReviewValidationError::new(
                    path,
                    ReviewValidationReason::MaximumBytesExceeded
                )),
                "{path}"
            );
            assert_eq!(at("x".repeat(maximum)), Ok(()), "{path}");
            for text in ["   ", "not\u{7}eligible"] {
                assert_eq!(
                    at(text.to_owned()),
                    Err(ReviewValidationError::new(
                        path,
                        ReviewValidationReason::TextInvalid
                    )),
                    "{path}"
                );
            }
        }
    }

    fn two_approval_policy_with_conditions() -> ReviewPolicyClosure {
        let mut policy = approval_policy(vec![stage("review", 2)]);
        policy.outcomes.push(ReviewOutcomePolicy {
            id: "approved-with-conditions".to_owned(),
            label: "Approve with conditions".to_owned(),
            settlement: ReviewOutcomeSettlement::Approved,
            reason_required: false,
            public_reason: ReviewPublicReasonRule::Required,
            result_required: false,
        });
        policy
            .closure_with(crate::ReviewPolicyDependencies::default())
            .unwrap()
    }

    fn approve_with_conditions(task: &ReviewTask, reviewer: IssuerPrincipal) -> Decision {
        let mut decision = approve(task, reviewer);
        decision.decision = DecisionKind::Approve {
            outcome: "approved-with-conditions".to_owned(),
            public_reason: Some("Approved; renew the permit within a year.".to_owned()),
        };
        decision
    }

    #[test]
    fn approvals_in_one_stage_that_agree_settle_with_their_outcome() {
        let snapshot = two_approval_policy_with_conditions();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let first = task(request_id, 0, "review", 1, "a");
        record_review_decision(
            &snapshot,
            &mut progress,
            &first,
            approve_with_conditions(&first, person("a")),
        )
        .unwrap();
        let second = task(request_id, 0, "review", 2, "b");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &second,
                approve_with_conditions(&second, person("b"))
            ),
            Ok(ReviewTransition::Settled {
                settlement: ReviewSettlement::Approved {
                    outcome: "approved-with-conditions".to_owned(),
                    public_reason: Some("Approved; renew the permit within a year.".to_owned()),
                }
            })
        );
    }

    #[test]
    fn an_approval_naming_another_outcome_than_its_stage_already_chose_is_refused() {
        let snapshot = two_approval_policy_with_conditions();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let first = task(request_id, 0, "review", 1, "a");
        record_review_decision(
            &snapshot,
            &mut progress,
            &first,
            approve_with_conditions(&first, person("a")),
        )
        .unwrap();
        let second = task(request_id, 0, "review", 2, "b");
        let error = record_review_decision(
            &snapshot,
            &mut progress,
            &second,
            approve(&second, person("b")),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ReviewDecisionError::ApprovalOutcomeDiffers {
                chosen: "approved-with-conditions".to_owned(),
            }
        );
        assert_eq!(
            error.to_string(),
            "an earlier approval in this stage chose approved-with-conditions, and every approval in a stage names the same outcome; approve with approved-with-conditions, or request changes or reject"
        );
        assert_eq!(
            progress.decisions.len(),
            1,
            "a refused approval is not recorded"
        );
        assert!(progress.settlement.is_none());
    }

    #[test]
    fn answer_policies_require_a_configured_outcome() {
        let mut policy = answer_policy();
        policy.outcomes.clear();
        assert_eq!(policy.check(), Err(ReviewPolicyError::AnswerOutcomes));
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskDecisionRequest {
    pub decision: DecisionKind,
}
