//! Activation preflight for work pinned under an earlier policy package.
//!
//! A review request pins its kind's policy snapshot when it is admitted, and a
//! work item keeps the queue it was routed to. A review request also keeps the
//! id of the producer that submitted it, and that producer reads it only under
//! that id. A later package can remove the queue or access profile that pinned
//! work still names, remove or rename the producer of an in-flight review,
//! change a kind's content under an unchanged version, or change the fields a
//! source read discloses so that the pinned display schema refuses them. Each
//! of those hides or orphans in-flight work without any error, so the runtime
//! compares the package it is about to activate with the work already
//! retained.

use std::collections::{BTreeMap, BTreeSet};

use registry_casework_core::{
    CaseworkProject, ReviewContextStrategy, ReviewKindPolicySnapshot, SourceAdapter,
};
use serde::Serialize;
use serde_json::Value;

use crate::{PostgresStore, StoreError};

/// Pinned in-flight work a candidate package would hide or orphan, with the
/// number of retained records affected. The counts carry no subject data.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    tag = "reason",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum StrandedWork {
    /// In-flight reviews or open work items name a queue the package no
    /// longer declares, so no team can be configured to serve them.
    QueueRemoved {
        queue: String,
        reviews: u64,
        work_items: u64,
    },
    /// In-flight reviews have a remaining stage decided only through an
    /// access profile the package no longer declares.
    ProfileRemoved { profile: String, reviews: u64 },
    /// In-flight reviews were submitted by a review producer the package no
    /// longer declares, so no caller can read, cancel, or receive the result
    /// of them.
    ProducerRemoved { producer: String, reviews: u64 },
    /// The package declares the pinned review kind version with different
    /// content, so one kind version would name two policies.
    ReviewKindChanged {
        review_kind: String,
        version: String,
        reviews: u64,
    },
    /// In-flight source-context reviews or open work items name a source the
    /// runtime no longer binds, so their context can no longer be read and no
    /// action on them can reach the source.
    SourceRemoved {
        source: String,
        reviews: u64,
        work_items: u64,
    },
    /// A source read now discloses a field the pinned display schema does not
    /// declare, so the pinned schema refuses every reviewer's context.
    ContextFieldNotDisplayed {
        source: String,
        entity: String,
        review_kind: String,
        version: String,
        field: String,
        reviews: u64,
    },
    /// The pinned display schema requires a field the source read no longer
    /// discloses, so the pinned schema refuses every reviewer's context.
    DisplayedFieldNotProjected {
        source: String,
        entity: String,
        review_kind: String,
        version: String,
        field: String,
        reviews: u64,
    },
}

impl StrandedWork {
    /// One value-free sentence naming the conflict and its counts.
    pub fn describe(&self) -> String {
        match self {
            Self::QueueRemoved {
                queue,
                reviews,
                work_items,
            } => format!(
                "{} and {} are in queue {queue}, which the package no longer declares",
                count(*reviews, "in-flight review"),
                count(*work_items, "open work item"),
            ),
            Self::ProfileRemoved { profile, reviews } => format!(
                "{} can be decided only through access profile {profile}, which the package no longer declares",
                count(*reviews, "in-flight review"),
            ),
            Self::ProducerRemoved { producer, reviews } => format!(
                "{} came from review producer {producer}, which the package no longer declares",
                count(*reviews, "in-flight review"),
            ),
            Self::ReviewKindChanged {
                review_kind,
                version,
                reviews,
            } => format!(
                "{} pin review kind {review_kind} version {version}, which the package declares with different content; give the changed kind a new version",
                count(*reviews, "in-flight review"),
            ),
            Self::SourceRemoved {
                source,
                reviews,
                work_items,
            } => format!(
                "{} and {} depend on source {source}, which the package no longer declares",
                count(*reviews, "in-flight review"),
                count(*work_items, "open work item"),
            ),
            Self::ContextFieldNotDisplayed {
                source,
                entity,
                review_kind,
                version,
                field,
                reviews,
            } => format!(
                "{} of review kind {review_kind} version {version} would receive field {field} from source {source} entity {entity}, which their pinned displaySchema does not declare",
                count(*reviews, "in-flight review"),
            ),
            Self::DisplayedFieldNotProjected {
                source,
                entity,
                review_kind,
                version,
                field,
                reviews,
            } => format!(
                "{} of review kind {review_kind} version {version} require field {field}, which source {source} entity {entity} no longer projects",
                count(*reviews, "in-flight review"),
            ),
        }
    }
}

fn count(value: u64, noun: &str) -> String {
    if value == 1 {
        format!("1 {noun}")
    } else {
        format!("{value} {noun}s")
    }
}

/// Join conflicts into one operator sentence.
pub fn describe_stranded_work(conflicts: &[StrandedWork]) -> String {
    conflicts
        .iter()
        .map(StrandedWork::describe)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Whether a runtime may activate a package given the pinned work it strands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinnedWorkVerdict {
    /// The package strands no pinned work.
    Clear,
    /// The package strands pinned work and `package.acknowledgeStrandedWork`
    /// names its exact digest.
    Acknowledged,
    /// The package strands pinned work the operator has not acknowledged.
    Refused,
}

/// Decide activation of the package with `package_digest`.
pub fn pinned_work_verdict(
    conflicts: &[StrandedWork],
    package_digest: &str,
    acknowledged: Option<&str>,
) -> PinnedWorkVerdict {
    if conflicts.is_empty() {
        PinnedWorkVerdict::Clear
    } else if acknowledged == Some(package_digest) {
        PinnedWorkVerdict::Acknowledged
    } else {
        PinnedWorkVerdict::Refused
    }
}

/// The operator sentence for a refused activation: what is stranded, and
/// the two ways forward.
pub fn stranded_work_refusal(conflicts: &[StrandedWork], package_digest: &str) -> String {
    format!(
        "the policy package would strand work pinned under an earlier package: {}. Let that \
         work finish under the earlier package, or set package.acknowledgeStrandedWork to \
         {package_digest} to activate this package anyway",
        describe_stranded_work(conflicts)
    )
}

/// In-flight reviews that share one pinned policy, subject source and type,
/// and active stage.
#[derive(Clone, Debug)]
pub(crate) struct PinnedReviewGroup {
    pub(crate) policy: ReviewKindPolicySnapshot,
    pub(crate) subject_source: String,
    pub(crate) subject_type: String,
    pub(crate) active_stage_index: usize,
    pub(crate) reviews: u64,
}

/// Retained in-flight work, grouped without subject data.
#[derive(Clone, Debug, Default)]
pub(crate) struct PinnedWorkInventory {
    pub(crate) reviews: Vec<PinnedReviewGroup>,
    /// In-flight reviews per producer that submitted them.
    pub(crate) reviews_by_producer: BTreeMap<String, u64>,
    /// Open work items per queue.
    pub(crate) work_items: BTreeMap<String, u64>,
    /// Open work items per source.
    pub(crate) work_items_by_source: BTreeMap<String, u64>,
}

/// Compare `project` and the fields its source adapters disclose with the
/// in-flight work retained in `store`. An empty result means activation
/// strands nothing.
pub async fn stranded_pinned_work(
    store: &PostgresStore,
    project: &CaseworkProject,
    adapters: &[&dyn SourceAdapter],
) -> Result<Vec<StrandedWork>, StoreError> {
    let inventory = store.pinned_work_inventory().await?;
    Ok(compare_pinned_work(project, adapters, &inventory))
}

pub(crate) fn compare_pinned_work(
    project: &CaseworkProject,
    adapters: &[&dyn SourceAdapter],
    inventory: &PinnedWorkInventory,
) -> Vec<StrandedWork> {
    let queues: BTreeSet<&str> = project
        .queues
        .iter()
        .map(|queue| queue.id.as_str())
        .collect();
    let profiles: BTreeSet<&str> = project
        .access_profiles
        .iter()
        .map(|profile| profile.id.as_str())
        .collect();
    let producers: BTreeSet<&str> = project
        .review_producers
        .iter()
        .map(|producer| producer.id.as_str())
        .collect();
    let kinds: BTreeMap<(&str, &str), _> = project
        .review_kinds
        .iter()
        .map(|kind| ((kind.id.as_str(), kind.version.as_str()), kind))
        .collect();

    let mut queue_reviews = BTreeMap::<String, u64>::new();
    let mut profile_reviews = BTreeMap::<String, u64>::new();
    let mut changed_kinds = BTreeMap::<(String, String), u64>::new();
    let mut removed_sources = BTreeMap::<String, u64>::new();
    let mut context_fields = BTreeMap::<ContextKey, u64>::new();

    for group in &inventory.reviews {
        let identity = &group.policy.identity;
        let remaining = group
            .policy
            .stages
            .iter()
            .skip(group.active_stage_index)
            .collect::<Vec<_>>();
        for queue in remaining
            .iter()
            .map(|stage| stage.queue.as_str())
            .collect::<BTreeSet<_>>()
        {
            if !queues.contains(queue) {
                *queue_reviews.entry(queue.to_owned()).or_default() += group.reviews;
            }
        }
        for profile in remaining
            .iter()
            .flat_map(|stage| stage.deciding_profiles.iter().map(String::as_str))
            .collect::<BTreeSet<_>>()
        {
            if !profiles.contains(profile) {
                *profile_reviews.entry(profile.to_owned()).or_default() += group.reviews;
            }
        }
        if let Some(current) = kinds.get(&(identity.id.as_str(), identity.version.as_str())) {
            // A current kind that does not check is refused by project
            // validation before this comparison runs.
            if current
                .policy_digest()
                .is_ok_and(|digest| digest != identity.digest)
            {
                *changed_kinds
                    .entry((identity.id.clone(), identity.version.clone()))
                    .or_default() += group.reviews;
            }
        }
        if group.policy.context_strategy != ReviewContextStrategy::Source {
            continue;
        }
        let Some(adapter) = adapters
            .iter()
            .find(|adapter| adapter.source_id() == group.subject_source)
        else {
            *removed_sources
                .entry(group.subject_source.clone())
                .or_default() += group.reviews;
            continue;
        };
        let Some(disclosed) = adapter.caller_disclosure_fields(&group.subject_type) else {
            continue;
        };
        let (declared, required) = display_fields(&group.policy.display_schema);
        let key = |field: &str, reason: ContextReason| ContextKey {
            source: group.subject_source.clone(),
            entity: group.subject_type.clone(),
            review_kind: identity.id.clone(),
            version: identity.version.clone(),
            field: field.to_owned(),
            reason,
        };
        for field in &disclosed {
            if !declared.contains(field.as_str()) {
                *context_fields
                    .entry(key(field, ContextReason::NotDisplayed))
                    .or_default() += group.reviews;
            }
        }
        for field in required {
            if !disclosed.iter().any(|disclosed| disclosed == field) {
                *context_fields
                    .entry(key(field, ContextReason::NotProjected))
                    .or_default() += group.reviews;
            }
        }
    }

    let mut conflicts = Vec::new();
    let stranded_queues = queue_reviews
        .keys()
        .chain(inventory.work_items.keys())
        .filter(|queue| !queues.contains(queue.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    for queue in stranded_queues {
        conflicts.push(StrandedWork::QueueRemoved {
            reviews: queue_reviews.get(&queue).copied().unwrap_or_default(),
            work_items: inventory
                .work_items
                .get(&queue)
                .copied()
                .unwrap_or_default(),
            queue,
        });
    }
    conflicts.extend(
        profile_reviews
            .into_iter()
            .map(|(profile, reviews)| StrandedWork::ProfileRemoved { profile, reviews }),
    );
    conflicts.extend(
        inventory
            .reviews_by_producer
            .iter()
            .filter(|(producer, _)| !producers.contains(producer.as_str()))
            .map(|(producer, reviews)| StrandedWork::ProducerRemoved {
                producer: producer.clone(),
                reviews: *reviews,
            }),
    );
    conflicts.extend(
        changed_kinds
            .into_iter()
            .map(
                |((review_kind, version), reviews)| StrandedWork::ReviewKindChanged {
                    review_kind,
                    version,
                    reviews,
                },
            ),
    );
    let bound = |source: &str| adapters.iter().any(|adapter| adapter.source_id() == source);
    let stranded_sources = removed_sources
        .keys()
        .chain(inventory.work_items_by_source.keys())
        .filter(|source| !bound(source.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    for source in stranded_sources {
        conflicts.push(StrandedWork::SourceRemoved {
            reviews: removed_sources.get(&source).copied().unwrap_or_default(),
            work_items: inventory
                .work_items_by_source
                .get(&source)
                .copied()
                .unwrap_or_default(),
            source,
        });
    }
    conflicts.extend(context_fields.into_iter().map(|(key, reviews)| {
        let ContextKey {
            source,
            entity,
            review_kind,
            version,
            field,
            reason,
        } = key;
        match reason {
            ContextReason::NotDisplayed => StrandedWork::ContextFieldNotDisplayed {
                source,
                entity,
                review_kind,
                version,
                field,
                reviews,
            },
            ContextReason::NotProjected => StrandedWork::DisplayedFieldNotProjected {
                source,
                entity,
                review_kind,
                version,
                field,
                reviews,
            },
        }
    }));
    conflicts
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ContextReason {
    NotDisplayed,
    NotProjected,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ContextKey {
    source: String,
    entity: String,
    review_kind: String,
    version: String,
    field: String,
    reason: ContextReason,
}

/// The property names a closed display schema declares and the ones it
/// requires. Review kinds admit only closed object schemas.
fn display_fields(schema: &Value) -> (BTreeSet<&str>, Vec<&str>) {
    let declared = schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| properties.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|required| required.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    (declared, required)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use registry_casework_core::{
        AccessProfile, ActiveSubjectsPage, AuthoritativeObservation, CallerSubjectView,
        CaseworkRole, DiscoveryCursor, EphemeralCredential, EventRequest, ExecutePreparedRequest,
        PrepareActionRequest, PreparedSourceAttempt, ProjectIdentity, QueuePolicy,
        ReviewKindPolicy, ReviewKindPurpose, ReviewProducerPolicy, ReviewRetentionPolicy,
        ReviewStagePolicy, SourceAdapterError, SourceReceipt, SubjectRef, TransitionHint,
    };
    use serde_json::json;

    use super::*;

    fn stage(id: &str, queue: &str, profile: &str) -> ReviewStagePolicy {
        ReviewStagePolicy {
            id: id.to_owned(),
            queue: queue.to_owned(),
            deciding_profiles: vec![profile.to_owned()],
            required_approvals: 1,
            exclude_initiator: false,
            exclude_previous_stage_reviewers: false,
        }
    }

    fn kind(strategy: ReviewContextStrategy) -> ReviewKindPolicy {
        ReviewKindPolicy {
            id: "correction".to_owned(),
            version: "1".to_owned(),
            purpose: ReviewKindPurpose::Approval,
            context_strategy: strategy,
            stages: vec![
                stage("first", "intake", "clerk"),
                stage("second", "senior", "senior-officer"),
            ],
            clocks: Vec::new(),
            retention: ReviewRetentionPolicy {
                terminal_days: 30,
                accountability_days: 365,
            },
            display_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["summary"],
                "properties": {"summary": {"type": "string"}}
            }),
            result_schema: None,
            outcomes: Vec::new(),
        }
    }

    fn profile(id: &str) -> AccessProfile {
        AccessProfile {
            id: id.to_owned(),
            principal_claim: "sub".to_owned(),
            required_scopes: Vec::new(),
            role: CaseworkRole::Staff,
        }
    }

    fn project(kind: ReviewKindPolicy) -> CaseworkProject {
        CaseworkProject {
            api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
            kind: registry_casework_core::CASEWORK_KIND.to_owned(),
            project: ProjectIdentity {
                id: "pinned".parse().unwrap(),
                version: "1".to_owned(),
            },
            access_profiles: vec![profile("clerk"), profile("senior-officer")],
            queues: ["intake", "senior"]
                .into_iter()
                .map(|id| QueuePolicy {
                    id: id.to_owned(),
                    label: id.to_owned(),
                })
                .collect(),
            sources: Vec::new(),
            review_kinds: vec![kind],
            review_producers: Vec::new(),
            calendars: Vec::new(),
            clocks: Vec::new(),
            inbox: Default::default(),
            task_templates: Vec::new(),
        }
    }

    fn group(
        kind: &ReviewKindPolicy,
        active_stage_index: usize,
        reviews: u64,
    ) -> PinnedReviewGroup {
        PinnedReviewGroup {
            policy: kind.snapshot().expect("pinned snapshot"),
            subject_source: "registry".to_owned(),
            subject_type: "licence".to_owned(),
            active_stage_index,
            reviews,
        }
    }

    struct Disclosing(Option<Vec<String>>);

    #[async_trait]
    impl SourceAdapter for Disclosing {
        fn source_id(&self) -> &str {
            "registry"
        }

        fn binding_generation(&self) -> &str {
            "generation"
        }

        fn caller_disclosure_fields(&self, entity: &str) -> Option<Vec<String>> {
            assert_eq!(entity, "licence");
            self.0.clone()
        }

        async fn verify_transition(
            &self,
            _request: EventRequest,
        ) -> Result<TransitionHint, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }

        async fn read_authoritative(
            &self,
            _subject: &SubjectRef,
        ) -> Result<AuthoritativeObservation, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }

        async fn discover_active(
            &self,
            _cursor: Option<&DiscoveryCursor>,
            _limit: usize,
        ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }

        async fn read_for_caller(
            &self,
            _subject: &SubjectRef,
            _source_profile_id: &str,
            _credential: EphemeralCredential<'_>,
        ) -> Result<CallerSubjectView, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }

        async fn prepare_action(
            &self,
            _request: PrepareActionRequest<'_>,
        ) -> Result<PreparedSourceAttempt, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }

        async fn execute_prepared(
            &self,
            _request: ExecutePreparedRequest<'_>,
        ) -> Result<SourceReceipt, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }
    }

    #[test]
    fn the_package_that_admitted_the_work_strands_nothing() {
        let pinned = kind(ReviewContextStrategy::Submitted);
        let inventory = PinnedWorkInventory {
            reviews: vec![group(&pinned, 0, 3)],
            work_items: BTreeMap::from([("intake".to_owned(), 2)]),
            ..PinnedWorkInventory::default()
        };
        assert!(compare_pinned_work(&project(pinned), &[], &inventory).is_empty());
    }

    #[test]
    fn a_removed_queue_counts_remaining_stages_and_open_work_items() {
        let pinned = kind(ReviewContextStrategy::Submitted);
        let inventory = PinnedWorkInventory {
            // Two reviews still at the first stage and one already at the
            // second: only the first two still need the intake queue.
            reviews: vec![group(&pinned, 0, 2), group(&pinned, 1, 1)],
            work_items: BTreeMap::from([("intake".to_owned(), 4), ("retired".to_owned(), 1)]),
            ..PinnedWorkInventory::default()
        };
        let mut renamed = pinned.clone();
        renamed.version = "2".to_owned();
        renamed.stages[0].queue = "front-desk".to_owned();
        let mut candidate = project(renamed);
        candidate.queues[0].id = "front-desk".to_owned();

        let conflicts = compare_pinned_work(&candidate, &[], &inventory);
        assert_eq!(
            conflicts,
            vec![
                StrandedWork::QueueRemoved {
                    queue: "intake".to_owned(),
                    reviews: 2,
                    work_items: 4,
                },
                StrandedWork::QueueRemoved {
                    queue: "retired".to_owned(),
                    reviews: 0,
                    work_items: 1,
                },
            ]
        );
        assert_eq!(
            describe_stranded_work(&conflicts),
            "2 in-flight reviews and 4 open work items are in queue intake, which the package \
             no longer declares; 0 in-flight reviews and 1 open work item are in queue retired, \
             which the package no longer declares"
        );
    }

    #[test]
    fn a_removed_profile_and_changed_content_under_one_version_are_named() {
        let pinned = kind(ReviewContextStrategy::Submitted);
        let inventory = PinnedWorkInventory {
            reviews: vec![group(&pinned, 0, 1), group(&pinned, 1, 2)],
            ..PinnedWorkInventory::default()
        };
        let mut renamed = pinned.clone();
        renamed.stages[1].deciding_profiles = vec!["licence-officer".to_owned()];
        let mut candidate = project(renamed);
        candidate.access_profiles[1].id = "licence-officer".to_owned();

        assert_eq!(
            compare_pinned_work(&candidate, &[], &inventory),
            vec![
                StrandedWork::ProfileRemoved {
                    profile: "senior-officer".to_owned(),
                    reviews: 3,
                },
                StrandedWork::ReviewKindChanged {
                    review_kind: "correction".to_owned(),
                    version: "1".to_owned(),
                    reviews: 3,
                },
            ]
        );
    }

    #[test]
    fn a_source_read_the_pinned_display_schema_refuses_is_named_by_field() {
        let pinned = kind(ReviewContextStrategy::Source);
        let inventory = PinnedWorkInventory {
            reviews: vec![group(&pinned, 0, 5)],
            ..PinnedWorkInventory::default()
        };
        let candidate = project(pinned);

        let matching = Disclosing(Some(vec!["summary".to_owned()]));
        assert!(compare_pinned_work(&candidate, &[&matching], &inventory).is_empty());

        let undeclared = Disclosing(None);
        assert!(compare_pinned_work(&candidate, &[&undeclared], &inventory).is_empty());

        let widened = Disclosing(Some(vec!["summary".to_owned(), "reason".to_owned()]));
        assert_eq!(
            compare_pinned_work(&candidate, &[&widened], &inventory),
            vec![StrandedWork::ContextFieldNotDisplayed {
                source: "registry".to_owned(),
                entity: "licence".to_owned(),
                review_kind: "correction".to_owned(),
                version: "1".to_owned(),
                field: "reason".to_owned(),
                reviews: 5,
            }]
        );

        let narrowed = Disclosing(Some(Vec::new()));
        assert_eq!(
            compare_pinned_work(&candidate, &[&narrowed], &inventory),
            vec![StrandedWork::DisplayedFieldNotProjected {
                source: "registry".to_owned(),
                entity: "licence".to_owned(),
                review_kind: "correction".to_owned(),
                version: "1".to_owned(),
                field: "summary".to_owned(),
                reviews: 5,
            }]
        );

        assert_eq!(
            compare_pinned_work(&candidate, &[], &inventory),
            vec![StrandedWork::SourceRemoved {
                source: "registry".to_owned(),
                reviews: 5,
                work_items: 0,
            }]
        );
    }

    #[test]
    fn open_work_items_from_a_source_the_runtime_no_longer_binds_are_named() {
        let pinned = kind(ReviewContextStrategy::Source);
        let inventory = PinnedWorkInventory {
            reviews: vec![group(&pinned, 0, 1)],
            work_items: BTreeMap::from([("intake".to_owned(), 3)]),
            work_items_by_source: BTreeMap::from([
                ("registry".to_owned(), 2),
                ("retired-registry".to_owned(), 1),
            ]),
            ..PinnedWorkInventory::default()
        };
        let candidate = project(pinned);

        let bound = Disclosing(Some(vec!["summary".to_owned()]));
        let conflicts = compare_pinned_work(&candidate, &[&bound], &inventory);
        assert_eq!(
            conflicts,
            vec![StrandedWork::SourceRemoved {
                source: "retired-registry".to_owned(),
                reviews: 0,
                work_items: 1,
            }]
        );
        assert_eq!(
            describe_stranded_work(&conflicts),
            "0 in-flight reviews and 1 open work item depend on source retired-registry, which \
             the package no longer declares"
        );

        assert_eq!(
            compare_pinned_work(&candidate, &[], &inventory),
            vec![
                StrandedWork::SourceRemoved {
                    source: "registry".to_owned(),
                    reviews: 1,
                    work_items: 2,
                },
                StrandedWork::SourceRemoved {
                    source: "retired-registry".to_owned(),
                    reviews: 0,
                    work_items: 1,
                },
            ]
        );
    }

    #[test]
    fn only_an_acknowledgement_of_the_exact_package_digest_admits_stranded_work() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let other = format!("sha256:{}", "b".repeat(64));
        let conflicts = [StrandedWork::ProfileRemoved {
            profile: "clerk".to_owned(),
            reviews: 1,
        }];
        assert_eq!(
            pinned_work_verdict(&[], &digest, None),
            PinnedWorkVerdict::Clear
        );
        assert_eq!(
            pinned_work_verdict(&conflicts, &digest, None),
            PinnedWorkVerdict::Refused
        );
        assert_eq!(
            pinned_work_verdict(&conflicts, &digest, Some(&other)),
            PinnedWorkVerdict::Refused
        );
        assert_eq!(
            pinned_work_verdict(&conflicts, &digest, Some(&digest)),
            PinnedWorkVerdict::Acknowledged
        );
        assert_eq!(
            stranded_work_refusal(&conflicts, &digest),
            format!(
                "the policy package would strand work pinned under an earlier package: 1 \
                 in-flight review can be decided only through access profile clerk, which the \
                 package no longer declares. Let that work finish under the earlier package, or \
                 set package.acknowledgeStrandedWork to {digest} to activate this package anyway"
            )
        );
    }

    fn producer(id: &str) -> ReviewProducerPolicy {
        ReviewProducerPolicy {
            id: id.to_owned(),
            profile: "clerk".to_owned(),
            issuer: "https://issuer.test".to_owned(),
            subject: "registry-service".to_owned(),
            trusted_initiator_issuer: None,
            initiator_profile: None,
            source_namespaces: vec!["registry".to_owned()],
            kinds: vec!["correction".to_owned()],
            recovery_days: 30,
            completion: None,
        }
    }

    #[test]
    fn a_removed_producer_counts_the_in_flight_reviews_it_submitted() {
        let pinned = kind(ReviewContextStrategy::Submitted);
        let inventory = PinnedWorkInventory {
            reviews: vec![group(&pinned, 0, 3)],
            // The id the earlier package declared is compared as it was
            // stored, whatever grammar this release holds a declared id to.
            reviews_by_producer: BTreeMap::from([
                ("Registry_Service".to_owned(), 2),
                ("payments".to_owned(), 1),
            ]),
            ..PinnedWorkInventory::default()
        };
        let mut declared = project(pinned.clone());
        declared.review_producers = vec![producer("Registry_Service"), producer("payments")];
        assert!(compare_pinned_work(&declared, &[], &inventory).is_empty());

        let mut renamed = project(pinned);
        renamed.review_producers = vec![producer("registry-service"), producer("payments")];
        let conflicts = compare_pinned_work(&renamed, &[], &inventory);
        assert_eq!(
            conflicts,
            vec![StrandedWork::ProducerRemoved {
                producer: "Registry_Service".to_owned(),
                reviews: 2,
            }]
        );
        assert_eq!(
            describe_stranded_work(&conflicts),
            "2 in-flight reviews came from review producer Registry_Service, which the package \
             no longer declares"
        );
        assert_eq!(
            serde_json::to_value(&conflicts[0]).unwrap(),
            json!({"reason": "producer-removed", "producer": "Registry_Service", "reviews": 2})
        );
    }

    #[test]
    fn a_package_with_no_producer_strands_every_producer_with_in_flight_reviews() {
        let pinned = kind(ReviewContextStrategy::Submitted);
        let inventory = PinnedWorkInventory {
            reviews: vec![group(&pinned, 0, 1)],
            reviews_by_producer: BTreeMap::from([("registry".to_owned(), 1)]),
            ..PinnedWorkInventory::default()
        };
        let conflicts = compare_pinned_work(&project(pinned), &[], &inventory);
        assert_eq!(
            conflicts,
            vec![StrandedWork::ProducerRemoved {
                producer: "registry".to_owned(),
                reviews: 1,
            }]
        );
        assert_eq!(
            describe_stranded_work(&conflicts),
            "1 in-flight review came from review producer registry, which the package no longer \
             declares"
        );
    }

    #[test]
    fn conflicts_serialize_with_a_closed_reason_and_camel_case_counts() {
        let conflict = StrandedWork::QueueRemoved {
            queue: "intake".to_owned(),
            reviews: 1,
            work_items: 2,
        };
        assert_eq!(
            serde_json::to_value(&conflict).unwrap(),
            json!({"reason": "queue-removed", "queue": "intake", "reviews": 1, "workItems": 2})
        );
    }
}
