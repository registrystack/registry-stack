// SPDX-License-Identifier: Apache-2.0

//! The governed-ingestion job: the `AdapterJob` definition, its bounded
//! profile, the projection and trigger declarations, the item contract,
//! the CSV decoder options, and the job-side authoring checks
//! (`products/adapter/CONCEPT.md` sections 17.1 and 17.2).
//!
//! A job pairs one pack source route with an explicit, bounded profile and
//! runs beside the facade: no listener, no inbound record shape, and no
//! facade ceiling change. Every bound here is a check-time guarantee the
//! engine enforces again at the edge; every refusal carries a value-free
//! `adapter.job.*` code.

use std::collections::HashSet;

use registry_platform_yaml::{Diagnostic, LocalId};
use serde::{Deserialize, Serialize};

use crate::pack::AdapterPack;
use crate::route::Step;

/// apiVersion of the authored ingestion job definition.
pub const ADAPTER_JOB_API_VERSION: &str = "id.registrystack.org/formats/adapter/job/v1alpha1";

/// Kind of the authored ingestion job definition.
pub const ADAPTER_JOB_KIND: &str = "AdapterJob";

/// The job ceiling on one upstream send's response body, in bytes: the
/// platform's own response-body cap
/// (`registry-platform-httputil`'s `MAX_DESTINATION_RESPONSE_BODY_BYTES`).
/// An endpoint only source routes reach may declare up to this bound
/// (D39); a facade-reachable endpoint stays at the facade ceiling of
/// `crate::checks::MAXIMUM_RESPONSE_BYTES`.
pub const MAXIMUM_JOB_RESPONSE_BYTES: u64 = 16_777_216;
const _: () = assert!(
    MAXIMUM_JOB_RESPONSE_BYTES
        == registry_platform_httputil::destination::MAX_DESTINATION_RESPONSE_BODY_BYTES as u64
);

/// The job ceiling on one upstream attempt, in milliseconds. It equals the
/// platform-frozen facade ceiling on purpose:
/// `registry-platform-httputil`'s `FixedDestinationPolicy::send` hard-caps
/// every operation at 10 seconds, so a job profile cannot exceed it and a
/// page must fit inside it (D39).
pub const MAXIMUM_JOB_ATTEMPT_TIMEOUT_MILLISECONDS: u64 = 10_000;
const _: () = assert!(
    MAXIMUM_JOB_ATTEMPT_TIMEOUT_MILLISECONDS
        == registry_platform_httputil::destination::MAX_DESTINATION_OPERATION_TIMEOUT.as_millis()
            as u64
);

/// The longest one source-route run may take, in milliseconds: the page
/// deadline one job profile declares
/// (`products/adapter/CONCEPT.md` section 17.2).
pub const MAXIMUM_JOB_PAGE_DEADLINE_MILLISECONDS: u64 = 600_000;

/// The most items one produced page may carry.
pub const MAXIMUM_JOB_PAGE_ITEMS: u32 = 10_000;

/// The largest serialized item page, in bytes; equal to the platform
/// response-body cap so a page never outgrows a send that carries it.
pub const MAXIMUM_JOB_PAGE_BYTES: u64 = MAXIMUM_JOB_RESPONSE_BYTES;

/// The largest file one read may take in, in bytes (1 GiB). A bigger file
/// is refused, never partially read.
pub const MAXIMUM_JOB_FILE_BYTES: u64 = 1_073_741_824;

/// The largest one decoded row or line may take, in bytes.
pub const MAXIMUM_JOB_ROW_BYTES: u64 = 1_048_576;

/// The largest one decoded field may take, in bytes.
pub const MAXIMUM_JOB_FIELD_BYTES: u64 = 65_536;

/// The most decoded rows one page may carry.
pub const MAXIMUM_JOB_ROWS_PER_PAGE: u32 = 10_000;

/// The most named parameters one `postgres:` send may carry
/// (`products/adapter/CONCEPT.md` section 8.10, the SQL row).
pub const MAXIMUM_POSTGRES_QUERY_PARAMETERS: usize = 16;

/// The longest one item key may be, in bytes.
pub const MAXIMUM_ITEM_KEY_BYTES: usize = 512;

/// The longest one item revision may be, in bytes.
pub const MAXIMUM_ITEM_REVISION_BYTES: usize = 512;

/// The longest serialized `next` cursor, in bytes.
pub const MAXIMUM_NEXT_BYTES: usize = 2048;

/// The closed decoder names a `pollEnrich` step may write. Anything else
/// refuses under `adapter.job.decoder-unknown`.
pub const POLL_DECODER_NAMES: &[&str] = &["csv", "jsonl", "raw"];

/// The job's own upstream-call ceiling: the largest
/// `maximumUpstreamCalls` a job profile may declare. A pass never needs
/// more; a route whose static worst case passes this bound is a route
/// for another job shape.
pub const MAXIMUM_JOB_UPSTREAM_CALLS: u64 = 1_000;

/// The most fields one job projection may declare.
pub const MAXIMUM_PROJECTION_FIELDS: usize = 64;

/// The longest one projected path may be, in characters.
pub const MAXIMUM_PROJECTION_FIELD_CHARACTERS: usize = 128;

/// The most dotted segments one projected path may carry, the deepest
/// lookup a mapping is held to.
pub const MAXIMUM_PROJECTION_SEGMENTS: usize = 8;

/// The largest serialized projection field list, in bytes.
pub const MAXIMUM_PROJECTION_BYTES: usize = 2_048;

/// The closed trigger kinds a job may declare: `interval`, the served
/// kind, and `hook`, the declared seam the checks refuse until it is
/// built (`adapter.job.trigger-hook-unserved`).
pub const TRIGGER_KIND_VALUES: &[&str] = &["interval", "hook"];

/// The most triggers one job may declare. Coordinator holds its
/// workflows to the same bound on `eventTriggers`
/// (crates/registry-coordinator/src/event_trigger.rs), so a deployment
/// reasons about one trigger-count shape across products.
pub const MAXIMUM_JOB_TRIGGERS: usize = 16;

/// The shortest interval between two passes, in milliseconds: one
/// second. Camel's scheduler consumer defaults to a 500-millisecond
/// delay; a governed pass that re-reads a real source never runs that
/// hot.
pub const MINIMUM_TRIGGER_DELAY_MILLISECONDS: u64 = 1_000;

/// The longest interval between two passes, in milliseconds: one day,
/// the same cadence ceiling the rescan delay keeps.
pub const MAXIMUM_TRIGGER_DELAY_MILLISECONDS: u64 = 86_400_000;

/// The longest wait before the first pass, in milliseconds: one day.
pub const MAXIMUM_TRIGGER_INITIAL_DELAY_MILLISECONDS: u64 = 86_400_000;

/// The most consecutive idle or error polls a backoff threshold may
/// demand before it fires.
pub const MAXIMUM_TRIGGER_BACKOFF_THRESHOLD: u32 = 100;

/// The smallest backoff multiplier: 1, no pass skipped, the default.
pub const MINIMUM_TRIGGER_BACKOFF_MULTIPLIER: u32 = 1;

/// The largest backoff multiplier: 10 passes skipped once a threshold
/// fires, so a stalled source never disappears from the schedule for
/// longer than ten intervals.
pub const MAXIMUM_TRIGGER_BACKOFF_MULTIPLIER: u32 = 10;

/// The interval between two passes a job declares when it names no
/// delay: one minute. Camel's scheduler consumer default is 500
/// milliseconds
/// (camel-4.23.0:core/camel-support/src/main/java/org/apache/camel/support/ScheduledPollEndpoint.java,
/// `DEFAULT_DELAY`); a minute is the safer default for a governed pass.
pub const DEFAULT_TRIGGER_DELAY_MILLISECONDS: u64 = 60_000;

/// Every job-side configuration diagnostic code, in code-string order.
/// The vocabulary follows the closed-code pattern of
/// `crate::diagnostics`; these codes point into the pack's source-route
/// surface and the job definition, so they live beside the job model they
/// police.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum JobCode {
    CallBudget,
    ComponentFacadeRefused,
    DecoderUnknown,
    EndpointResponseBound,
    PageBytesBound,
    PageItemsBound,
    PageKey,
    PageNextBound,
    PageShape,
    PollEndpointKind,
    PollEndpointUnknown,
    PollFacadeRefused,
    PollTimeout,
    PostgresParametersUnbounded,
    PostgresQueryUnpinned,
    ProfileBound,
    ProfileEndpointBound,
    ProfileInconsistent,
    ProjectionBound,
    ProjectionShape,
    RouteUnknown,
    SendComponentRefused,
    SourceBoundRefused,
    SourceCalledRefused,
    SourceEditsRequired,
    SourceEditsUnknown,
    SourceIdCollision,
    SourceRecoveryRequired,
    SourceRescanDelay,
    SourceScanRequired,
    TriggerBound,
    TriggerHookUnserved,
    TriggerKind,
    TriggersRequired,
}

impl JobCode {
    /// The complete closed vocabulary, in code-string order.
    pub const ALL: &'static [Self] = &[
        Self::CallBudget,
        Self::ComponentFacadeRefused,
        Self::DecoderUnknown,
        Self::EndpointResponseBound,
        Self::PageBytesBound,
        Self::PageItemsBound,
        Self::PageKey,
        Self::PageNextBound,
        Self::PageShape,
        Self::PollEndpointKind,
        Self::PollEndpointUnknown,
        Self::PollFacadeRefused,
        Self::PollTimeout,
        Self::PostgresParametersUnbounded,
        Self::PostgresQueryUnpinned,
        Self::ProfileBound,
        Self::ProfileEndpointBound,
        Self::ProfileInconsistent,
        Self::ProjectionBound,
        Self::ProjectionShape,
        Self::RouteUnknown,
        Self::SendComponentRefused,
        Self::SourceBoundRefused,
        Self::SourceCalledRefused,
        Self::SourceEditsRequired,
        Self::SourceEditsUnknown,
        Self::SourceIdCollision,
        Self::SourceRecoveryRequired,
        Self::SourceRescanDelay,
        Self::SourceScanRequired,
        Self::TriggerBound,
        Self::TriggerHookUnserved,
        Self::TriggerKind,
        Self::TriggersRequired,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CallBudget => "adapter.job.call-budget",
            Self::ComponentFacadeRefused => "adapter.job.component-facade-refused",
            Self::DecoderUnknown => "adapter.job.decoder-unknown",
            Self::EndpointResponseBound => "adapter.job.endpoint-response-bound",
            Self::PageBytesBound => "adapter.job.page-bytes-bound",
            Self::PageItemsBound => "adapter.job.page-items-bound",
            Self::PageKey => "adapter.job.page-key",
            Self::PageNextBound => "adapter.job.page-next-bound",
            Self::PageShape => "adapter.job.page-shape",
            Self::PollEndpointKind => "adapter.job.poll-endpoint-kind",
            Self::PollEndpointUnknown => "adapter.job.poll-endpoint-unknown",
            Self::PollFacadeRefused => "adapter.job.poll-facade-refused",
            Self::PollTimeout => "adapter.job.poll-timeout",
            Self::PostgresParametersUnbounded => "adapter.job.postgres-parameters-unbounded",
            Self::PostgresQueryUnpinned => "adapter.job.postgres-query-unpinned",
            Self::ProfileBound => "adapter.job.profile-bound",
            Self::ProfileEndpointBound => "adapter.job.profile-endpoint-bound",
            Self::ProfileInconsistent => "adapter.job.profile-inconsistent",
            Self::ProjectionBound => "adapter.job.projection-bound",
            Self::ProjectionShape => "adapter.job.projection-shape",
            Self::RouteUnknown => "adapter.job.route-unknown",
            Self::SendComponentRefused => "adapter.job.send-component-refused",
            Self::SourceBoundRefused => "adapter.job.source-bound-refused",
            Self::SourceCalledRefused => "adapter.job.source-called-refused",
            Self::SourceEditsRequired => "adapter.job.source-edits-required",
            Self::SourceEditsUnknown => "adapter.job.source-edits-unknown",
            Self::SourceIdCollision => "adapter.job.source-id-collision",
            Self::SourceRecoveryRequired => "adapter.job.source-recovery-required",
            Self::SourceRescanDelay => "adapter.job.source-rescan-delay",
            Self::SourceScanRequired => "adapter.job.source-scan-required",
            Self::TriggerBound => "adapter.job.trigger-bound",
            Self::TriggerHookUnserved => "adapter.job.trigger-hook-unserved",
            Self::TriggerKind => "adapter.job.trigger-kind",
            Self::TriggersRequired => "adapter.job.triggers-required",
        }
    }

    /// The artifact kind whose document this finding points into: the
    /// route, endpoint, and source-route findings point into the pack,
    /// the profile and page findings into the job definition.
    #[must_use]
    pub const fn artifact(self) -> &'static str {
        match self {
            Self::ComponentFacadeRefused
            | Self::DecoderUnknown
            | Self::EndpointResponseBound
            | Self::PollEndpointKind
            | Self::PollEndpointUnknown
            | Self::PollFacadeRefused
            | Self::PollTimeout
            | Self::PostgresParametersUnbounded
            | Self::PostgresQueryUnpinned
            | Self::SendComponentRefused
            | Self::SourceBoundRefused
            | Self::SourceCalledRefused
            | Self::SourceEditsRequired
            | Self::SourceEditsUnknown
            | Self::SourceIdCollision
            | Self::SourceRecoveryRequired
            | Self::SourceRescanDelay
            | Self::SourceScanRequired => crate::naming::ADAPTER_PACK_KIND,
            Self::CallBudget
            | Self::PageBytesBound
            | Self::PageItemsBound
            | Self::PageKey
            | Self::PageNextBound
            | Self::PageShape
            | Self::ProfileBound
            | Self::ProfileEndpointBound
            | Self::ProfileInconsistent
            | Self::ProjectionBound
            | Self::ProjectionShape
            | Self::RouteUnknown
            | Self::TriggerBound
            | Self::TriggerHookUnserved
            | Self::TriggerKind
            | Self::TriggersRequired => ADAPTER_JOB_KIND,
        }
    }

    /// Resolve a code string back to its variant, or `None` for any string
    /// outside the closed vocabulary.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code() == code)
    }
}

/// One job-side finding: the same diagnostic shape the authoring checks
/// report, carrying a closed `adapter.job.*` code, its artifact kind, a
/// pointer, and a value-free message with a suggested action.
#[must_use]
pub fn job_finding(code: JobCode, path: &str, message: &str, action: &str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(code.code(), path, message, action);
    diagnostic.artifact = Some(code.artifact().to_string());
    diagnostic
}

/// The job identity block: the job's own name and version, the same
/// identity shape the project carries (CFG-ENV-6).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobIdentity {
    /// The job identifier.
    pub id: LocalId,
    /// The job version.
    pub version: String,
}

/// The pack and source route a job runs: the pack pinned by version and
/// digest exactly as a project pins it (CFG-ID-4), and the
/// `sourceRoutes` id of the route that acquires.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobSource {
    /// The pinned adapter pack.
    pub pack: crate::project::PinnedRef,
    /// The source route the job runs, a `sourceRoutes` id of the pinned
    /// pack.
    pub route: String,
}

/// The explicit, bounded profile of one job (`products/adapter/CONCEPT.md`
/// section 17.2). Every member is mandatory and checked; the engine
/// enforces each bound again at the edge. The facade ceilings of section
/// 8.8 are unchanged: the per-attempt timeout stays at the platform-frozen
/// ceiling, and only a source-route-only endpoint's response bound may
/// rise, to the platform cap (D39).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobProfile {
    /// The longest one source-route run may take, in milliseconds
    /// (1 to 600000).
    pub page_deadline_milliseconds: u64,
    /// The largest response body one send of the job may take in, in
    /// bytes (1 to 16777216). Where an endpoint declares a tighter bound,
    /// the lower of the two applies; the checks refuse a profile tighter
    /// than an endpoint the source route reaches.
    pub maximum_response_bytes: u64,
    /// The most items one produced page may carry (1 to 10000).
    pub maximum_page_items: u32,
    /// The largest serialized item page, in bytes (1 to 16777216).
    pub maximum_page_bytes: u64,
    /// The job's own upstream-call budget: the largest static worst-case
    /// number of upstream calls one pass may make (1 to 1000). The checks
    /// refuse a budget below the source route's worst-case call count
    /// under `adapter.job.call-budget`, reusing the same walk the facade
    /// binding's `maximumUpstreamCalls` stands on, so one budget shape
    /// covers both modes.
    pub maximum_upstream_calls: u64,
    /// The bounds of the reads the decoders produce.
    pub read: ReadBounds,
}

/// The read bounds of one job profile: what one poll may take in and what
/// one decoded row may carry (`products/adapter/CONCEPT.md` section
/// 17.2). Every read has a count, byte, and deadline bound.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBounds {
    /// The largest file one read may take in, in bytes (1 to 1073741824).
    /// A bigger file is refused, never partially read.
    pub maximum_file_bytes: u64,
    /// The largest one decoded row or line may take, in bytes
    /// (1 to 1048576).
    pub maximum_row_bytes: u64,
    /// The largest one decoded field may take, in bytes (1 to 65536).
    pub maximum_field_bytes: u64,
    /// The most decoded rows one page may carry (1 to 10000); never more
    /// than the page's own `maximumPageItems`.
    pub maximum_rows_per_page: u32,
}

/// The ingestion job definition (`AdapterJob`): an identity, the pinned
/// pack and its source route, the item projection and the pass triggers,
/// and the bounded job profile (`products/adapter/CONCEPT.md` sections
/// 17.1 and 17.2). The `apiVersion` and `kind` envelope members are
/// carried and validated like every other Adapter artifact's, through the
/// loader's format constants [`ADAPTER_JOB_API_VERSION`] and
/// [`ADAPTER_JOB_KIND`].
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterJob {
    /// The format envelope version.
    pub api_version: String,
    /// The format kind: `AdapterJob`.
    pub kind: String,
    /// The job's identity.
    pub job: JobIdentity,
    /// The pinned pack and the source route the job runs.
    pub source: JobSource,
    /// The projection of each source item the workflow needs; the checks
    /// refuse a job that declares none, so every job's data minimization
    /// is explicit.
    #[serde(default)]
    pub projection: ProjectionDecl,
    /// The triggers that decide when a pass starts; the checks refuse an
    /// empty list, so every job names at least one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggers: Vec<JobTrigger>,
    /// The bounded job profile.
    pub profile: JobProfile,
}

impl AdapterJob {
    /// The `sha256` hex digest over the canonical serialization of the
    /// job's projection block: the compact JSON object of the block's
    /// members with sorted keys (`digestOf` before `fields`), for example
    /// `{"digestOf":"projection","fields":["household.name"]}`. The pass
    /// stores the digest beside the item rows and reports when it
    /// changes, so a projection edit re-flags every item as changed
    /// instead of reading as no change. `check_job` validates the digest
    /// non-empty before a job runs.
    #[must_use]
    pub fn projection_digest(&self) -> String {
        let mut members = std::collections::BTreeMap::new();
        members.insert(
            "digestOf",
            serde_json::Value::String(self.projection.digest_of.as_str().to_string()),
        );
        members.insert(
            "fields",
            serde_json::Value::Array(
                self.projection
                    .fields
                    .iter()
                    .map(|field| serde_json::Value::String(field.clone()))
                    .collect(),
            ),
        );
        let canonical = serde_json::to_vec(&members)
            .expect("a string-keyed map of JSON strings and arrays serializes");
        registry_platform_config::sha256_uri(&canonical)
            .strip_prefix("sha256:")
            .map(str::to_string)
            .expect("sha256_uri prefixes its hex with sha256:")
    }
}

/// The projection of one source item the workflow needs (the
/// governed-ingestion concept sections 3 and 8): the dotted paths the job
/// reads from each item's captured value, and what the item row's Last
/// digest covers.
///
/// The projection is the job's data-minimization declaration: the field
/// list of the concept's custody control, so a whole source form never
/// reaches the destination or its operators because the workflow needed
/// two fields. The projection names what the workflow needs; the route
/// does the projecting. `check` cannot statically determine what a
/// route's final `setBody` targets, so the declaration is advisory to the
/// route and digest-relevant only: the pass stores
/// [`AdapterJob::projection_digest`] beside the item rows and reports
/// when it changes, and the route is held to the declared fields by
/// review, not by route analysis.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionDecl {
    /// The projected paths, each a dotted identifier path whose segments
    /// carry ASCII letters, digits, underscores, and dashes, at most
    /// [`MAXIMUM_PROJECTION_SEGMENTS`] segments and
    /// [`MAXIMUM_PROJECTION_FIELD_CHARACTERS`] characters; at most
    /// [`MAXIMUM_PROJECTION_FIELDS`] paths and at most
    /// [`MAXIMUM_PROJECTION_BYTES`] bytes serialized. The checks refuse a
    /// job that declares no fields under
    /// `adapter.job.projection-shape` and any other fault of the list
    /// under `adapter.job.projection-shape` or
    /// `adapter.job.projection-bound`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// What the item row's Last digest covers: `projection`, the
    /// serialized projected fields (the default), or `value`, the whole
    /// captured item. A `value` digest means the workflow compares whole
    /// items, and the projection then names only what the mapping reads.
    #[serde(default, skip_serializing_if = "is_default_digest_of")]
    pub digest_of: ProjectionDigestOf,
}

/// What the item row's Last digest covers, the closed set the projection
/// block pins.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub enum ProjectionDigestOf {
    /// The serialized projected fields, the default: an item counts as
    /// changed when what the workflow needs changed.
    #[default]
    #[serde(rename = "projection")]
    Projection,
    /// The whole captured item value.
    #[serde(rename = "value")]
    Value,
}

impl ProjectionDigestOf {
    /// The wire spelling of the kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Projection => "projection",
            Self::Value => "value",
        }
    }
}

fn is_default_digest_of(digest_of: &ProjectionDigestOf) -> bool {
    *digest_of == ProjectionDigestOf::Projection
}

/// One trigger of the job: the declaration of when a pass starts. A
/// trigger carries no data into the pass; a hook only starts a pass,
/// which then re-reads the source from the saved position, and a hook
/// body is never trusted or stored (the governed-ingestion concept
/// sections 3 and 5).
///
/// The interval options port the scheduled polling consumer options of
/// Camel's scheduler component
/// (camel-4.23.0:components/camel-scheduler/src/main/docs/scheduler-component.adoc);
/// the option names and their Camel defaults are read from the shared
/// `ScheduledPollEndpoint` base the scheduler endpoint extends
/// (camel-4.23.0:core/camel-support/src/main/java/org/apache/camel/support/ScheduledPollEndpoint.java),
/// not invented. Recorded divergences: Camel's `delay` default is that
/// file's `DEFAULT_DELAY` of 500 milliseconds and its `initialDelay`
/// default is `DEFAULT_INITIAL_DELAY` of 1000 milliseconds, where the
/// job pins 60000 and 0; and Camel's `backoffMultiplier` field defaults
/// to 0, which turns backoff off, where the job's default of 1 skips no
/// pass and the checks bound the value. The skip semantics (once an idle
/// or error threshold is met, that many polls are skipped before the
/// next attempt) are the consumer's own
/// (camel-4.23.0:core/camel-support/src/main/java/org/apache/camel/support/ScheduledPollConsumer.java#doRun).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobTrigger {
    /// The trigger kind, one of [`TRIGGER_KIND_VALUES`]: `interval`, the
    /// served kind, or `hook`, the declared seam. Mandatory in effect:
    /// the checks refuse a trigger that names no kind, or a kind outside
    /// the closed set, under `adapter.job.trigger-kind`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// The milliseconds between two interval passes, from
    /// [`MINIMUM_TRIGGER_DELAY_MILLISECONDS`] to
    /// [`MAXIMUM_TRIGGER_DELAY_MILLISECONDS`]. Ports `delay`
    /// (camel-4.23.0:core/camel-support/src/main/java/org/apache/camel/support/ScheduledPollEndpoint.java#delay,
    /// "Milliseconds before the next poll"; Camel's default is that
    /// file's 500-millisecond `DEFAULT_DELAY`). The job default is
    /// [`DEFAULT_TRIGGER_DELAY_MILLISECONDS`], one minute.
    #[serde(
        default = "default_trigger_delay_milliseconds",
        skip_serializing_if = "is_default_trigger_delay_milliseconds"
    )]
    pub delay_milliseconds: u64,
    /// The milliseconds before the first interval pass starts, from 0 to
    /// [`MAXIMUM_TRIGGER_INITIAL_DELAY_MILLISECONDS`]. Ports
    /// `initialDelay`
    /// (camel-4.23.0:core/camel-support/src/main/java/org/apache/camel/support/ScheduledPollEndpoint.java#initialDelay,
    /// "Milliseconds before the first poll starts"; Camel's default is
    /// that file's 1000-millisecond `DEFAULT_INITIAL_DELAY`). The job
    /// default of 0 starts the first pass immediately.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub initial_delay_milliseconds: u64,
    /// Whether a pass starts again immediately when the previous one
    /// read at least one item. Ports `greedy`
    /// (camel-4.23.0:core/camel-support/src/main/java/org/apache/camel/support/ScheduledPollEndpoint.java#greedy,
    /// "If greedy is enabled, then the ScheduledPollConsumer will run
    /// immediately again, if the previous run polled 1 or more
    /// messages"; the scheduler component doc
    /// camel-4.23.0:components/camel-scheduler/src/main/docs/scheduler-component.adoc
    /// warns that a greedy scheduler keeps firing). Default false,
    /// Camel's.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub greedy: bool,
    /// The consecutive idle passes that put the trigger into backoff.
    /// Ports `backoffIdleThreshold`
    /// (camel-4.23.0:core/camel-support/src/main/java/org/apache/camel/support/ScheduledPollEndpoint.java#backoffIdleThreshold,
    /// "The number of subsequent idle polls that should happen before
    /// the backoffMultipler should kick-in"). Default 0, off; the checks
    /// bound the value to [`MAXIMUM_TRIGGER_BACKOFF_THRESHOLD`].
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub backoff_idle_threshold: u32,
    /// The consecutive failed passes that put the trigger into backoff.
    /// Ports `backoffErrorThreshold`
    /// (camel-4.23.0:core/camel-support/src/main/java/org/apache/camel/support/ScheduledPollEndpoint.java#backoffErrorThreshold,
    /// "The number of subsequent error polls (failed due some error)
    /// that should happen before the backoffMultipler should kick-in").
    /// Default 0, off; the checks bound the value to
    /// [`MAXIMUM_TRIGGER_BACKOFF_THRESHOLD`].
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub backoff_error_threshold: u32,
    /// The passes backoff skips once an idle or error threshold is met.
    /// Ports `backoffMultiplier`
    /// (camel-4.23.0:core/camel-support/src/main/java/org/apache/camel/support/ScheduledPollEndpoint.java#backoffMultiplier,
    /// "The multiplier is then the number of polls that will be skipped
    /// before the next actual attempt is happening again"); Camel
    /// requires an idle or error threshold beside it, and its field
    /// default of 0 turns backoff off. The job default of 1 skips no
    /// pass, and the checks bound the value from
    /// [`MINIMUM_TRIGGER_BACKOFF_MULTIPLIER`] to
    /// [`MAXIMUM_TRIGGER_BACKOFF_MULTIPLIER`].
    #[serde(
        default = "default_trigger_backoff_multiplier",
        skip_serializing_if = "is_default_trigger_backoff_multiplier"
    )]
    pub backoff_multiplier: u32,
    /// The listener path a `hook` trigger waits on. Contract-only: the
    /// checks refuse every hook trigger under
    /// `adapter.job.trigger-hook-unserved` until the hook seam is built,
    /// so no pack or job can silently rely on one; the hook body is
    /// never trusted or stored, and no listener is built here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

fn default_trigger_delay_milliseconds() -> u64 {
    DEFAULT_TRIGGER_DELAY_MILLISECONDS
}

fn is_default_trigger_delay_milliseconds(value: &u64) -> bool {
    *value == DEFAULT_TRIGGER_DELAY_MILLISECONDS
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

fn default_trigger_backoff_multiplier() -> u32 {
    1
}

fn is_default_trigger_backoff_multiplier(value: &u32) -> bool {
    *value == 1
}

/// One source item of the item contract
/// (`products/adapter/CONCEPT.md` section 17.2): the source-native key
/// inside the job's configured namespace, the observed source revision
/// when reliable, and the captured value.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceItem {
    /// The source item's key; a non-empty string of at most
    /// [`MAXIMUM_ITEM_KEY_BYTES`] bytes.
    pub key: String,
    /// The observed source version, when the source reports one; at most
    /// [`MAXIMUM_ITEM_REVISION_BYTES`] bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// The captured item, any JSON value.
    pub value: serde_json::Value,
}

/// One page of the item contract (`products/adapter/CONCEPT.md` section
/// 17.2): the items one source-route run produced and the resumption
/// cursor, absent at the end of a finite scan. The job entry validates
/// every produced page against the job profile with
/// [`ItemPage::from_value`] before it is returned.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ItemPage {
    /// The items of this page.
    pub items: Vec<SourceItem>,
    /// The resumption cursor; absent at the end of a finite scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<serde_json::Value>,
}

/// Why a produced page was refused. The code is value-free: the message
/// built beside it names the accepted shape and the bounds, never a value
/// read from the page.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ItemPageFault {
    /// The page is not an object carrying an `items` array of objects, or
    /// a member carries the wrong JSON type, or an item carries no
    /// `value`.
    Shape,
    /// An item key is empty or longer than the bound, or a revision is
    /// longer than the bound.
    Key,
    /// The page carries more items than the profile's
    /// `maximumPageItems`.
    ItemsBound,
    /// The serialized page is larger than the profile's
    /// `maximumPageBytes`.
    BytesBound,
    /// The serialized `next` cursor is larger than the cursor bound.
    NextBound,
}

impl ItemPageFault {
    /// The value-free `adapter.job.page-*` code this fault reports.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Shape => "adapter.job.page-shape",
            Self::Key => "adapter.job.page-key",
            Self::ItemsBound => "adapter.job.page-items-bound",
            Self::BytesBound => "adapter.job.page-bytes-bound",
            Self::NextBound => "adapter.job.page-next-bound",
        }
    }
}

impl ItemPage {
    /// Validate one produced page against the job profile and the item
    /// contract. The value must be an object whose `items` is an array of
    /// objects, each carrying a non-empty string `key` of at most
    /// [`MAXIMUM_ITEM_KEY_BYTES`] bytes, an optional string `revision` of
    /// at most [`MAXIMUM_ITEM_REVISION_BYTES`] bytes, and any JSON
    /// `value`; `next` is absent or any JSON value whose serialization
    /// stays within [`MAXIMUM_NEXT_BYTES`] bytes. The page bounds of the
    /// profile apply to the item count and the serialized page. The
    /// caller passes a checked profile: bounds outside their ranges are
    /// refused by `check_job` before a job runs.
    pub fn from_value(
        value: &serde_json::Value,
        profile: &JobProfile,
    ) -> Result<Self, ItemPageFault> {
        let members = value.as_object().ok_or(ItemPageFault::Shape)?;
        let items = members
            .get("items")
            .and_then(serde_json::Value::as_array)
            .ok_or(ItemPageFault::Shape)?;
        let mut parsed = Vec::with_capacity(items.len());
        for item in items {
            let members = item.as_object().ok_or(ItemPageFault::Shape)?;
            let key = members
                .get("key")
                .and_then(serde_json::Value::as_str)
                .ok_or(ItemPageFault::Shape)?;
            if key.is_empty() || key.len() > MAXIMUM_ITEM_KEY_BYTES {
                return Err(ItemPageFault::Key);
            }
            let revision = match members.get("revision") {
                None => None,
                Some(revision) => {
                    let revision = revision.as_str().ok_or(ItemPageFault::Shape)?;
                    if revision.len() > MAXIMUM_ITEM_REVISION_BYTES {
                        return Err(ItemPageFault::Key);
                    }
                    Some(revision.to_string())
                }
            };
            let value = members.get("value").cloned().ok_or(ItemPageFault::Shape)?;
            parsed.push(SourceItem {
                key: key.to_string(),
                revision,
                value,
            });
        }
        if parsed.len() > profile.maximum_page_items as usize {
            return Err(ItemPageFault::ItemsBound);
        }
        if members
            .get("next")
            .is_some_and(|next| serialized_length(next) > MAXIMUM_NEXT_BYTES)
        {
            return Err(ItemPageFault::NextBound);
        }
        let page = Self {
            items: parsed,
            next: members.get("next").cloned(),
        };
        if serialized_length(&page.to_value()) > profile.maximum_page_bytes as usize {
            return Err(ItemPageFault::BytesBound);
        }
        Ok(page)
    }

    /// The wire form of the page: `{"items": [...], "next": ...}`, with
    /// `next` omitted when absent, exactly the shape
    /// [`ItemPage::from_value`] reads.
    #[must_use]
    pub fn to_value(&self) -> serde_json::Value {
        let mut members = serde_json::Map::new();
        members.insert(
            "items".to_string(),
            serde_json::Value::Array(
                self.items
                    .iter()
                    .map(|item| {
                        let mut members = serde_json::Map::new();
                        members.insert("key".to_string(), serde_json::json!(item.key));
                        if let Some(revision) = &item.revision {
                            members.insert("revision".to_string(), serde_json::json!(revision));
                        }
                        members.insert("value".to_string(), item.value.clone());
                        serde_json::Value::Object(members)
                    })
                    .collect(),
            ),
        );
        if let Some(next) = &self.next {
            members.insert("next".to_string(), next.clone());
        }
        serde_json::Value::Object(members)
    }
}

/// The serialized length of a JSON value, in bytes.
fn serialized_length(value: &serde_json::Value) -> usize {
    serde_json::to_vec(value).map_or(0, |bytes| bytes.len())
}

/// The character encoding a decoder reads. UTF-8 only: Camel carries a
/// charset per exchange where its CSV data format has no encoding option
/// of its own; the bounded decoder pins one encoding instead
/// (`products/adapter/CONCEPT.md` section 17.2).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DecoderEncoding {
    /// UTF-8, the only encoding the decoders read.
    #[serde(rename = "utf-8")]
    Utf8,
}

/// The CSV decoder options, the port of Camel's `CsvDataFormat` at
/// camel-4.23.0 restricted to a bounded row decoder
/// (`products/adapter/CONCEPT.md` section 8.10, the CSV row). Every kept
/// option cites the Java field it ports, and every default is that
/// field's effective default: the reference `DEFAULT` format's comma
/// delimiter, double quote, no comment marker, header record on, and no
/// trimming. The dropped options and the reason each is dropped are
/// recorded in `products/adapter/scratch/core/port-record.md`. Our rows
/// are maps keyed by the header record, so `useMaps` has no false form
/// here; type inference is refused, so a field decodes as the text the
/// file carries.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct CsvDecoder {
    /// The field delimiter. Ports `delimiter`
    /// (camel-4.23.0:core/camel-core-model/src/main/java/org/apache/camel/model/dataformat/CsvDataFormat.java#delimiter,
    /// "The default value is , (comma)"; the component-side field the
    /// engine reads is a `Character`), typed as one character so the
    /// reader refuses a multi-character delimiter.
    #[serde(
        default = "default_csv_delimiter",
        skip_serializing_if = "is_default_csv_delimiter"
    )]
    pub delimiter: char,
    /// The quote character. Ports `quote`
    /// (camel-4.23.0:core/camel-core-model/src/main/java/org/apache/camel/model/dataformat/CsvDataFormat.java#quote,
    /// "The quote character to use. The default is double-quote
    /// character.").
    #[serde(
        default = "default_csv_quote",
        skip_serializing_if = "is_default_csv_quote"
    )]
    pub quote: char,
    /// Whether quoting is off. Ports `quoteDisabled`
    /// (camel-4.23.0:core/camel-core-model/src/main/java/org/apache/camel/model/dataformat/CsvDataFormat.java#quoteDisabled);
    /// false keeps Camel's default quoting on.
    #[serde(
        default = "default_csv_quote_disabled",
        skip_serializing_if = "is_default_csv_quote_disabled"
    )]
    pub quote_disabled: bool,
    /// Whether the file's first record is the column header the row maps
    /// are keyed by. Ports `headerDisabled`, complemented: Camel's
    /// default keeps headers enabled, so the default here is true
    /// (camel-4.23.0:core/camel-core-model/src/main/java/org/apache/camel/model/dataformat/CsvDataFormat.java#headerDisabled).
    /// The comma-separated header rename list of Camel's `header` field
    /// is not ported: renaming columns is mapping work, and the row map
    /// keys are the file's own header names.
    #[serde(
        default = "default_csv_header",
        skip_serializing_if = "is_default_csv_header"
    )]
    pub header: bool,
    /// The comment marker; absent, comments are off, the reference
    /// format's default. Ports `commentMarker`
    /// (camel-4.23.0:core/camel-core-model/src/main/java/org/apache/camel/model/dataformat/CsvDataFormat.java#commentMarker);
    /// the separate `commentMarkerDisabled` flag is folded into absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment_marker: Option<char>,
    /// Whether leading and trailing blanks are trimmed. Ports `trim`
    /// (camel-4.23.0:core/camel-core-model/src/main/java/org/apache/camel/model/dataformat/CsvDataFormat.java#trim);
    /// false keeps the reference format's default.
    #[serde(
        default = "default_csv_trim",
        skip_serializing_if = "is_default_csv_trim"
    )]
    pub trim: bool,
    /// The encoding the bytes are decoded with; UTF-8 only.
    #[serde(
        default = "default_csv_encoding",
        skip_serializing_if = "is_default_csv_encoding"
    )]
    pub encoding: DecoderEncoding,
}

impl Default for CsvDecoder {
    fn default() -> Self {
        Self {
            delimiter: ',',
            quote: '"',
            quote_disabled: false,
            header: true,
            comment_marker: None,
            trim: false,
            encoding: DecoderEncoding::Utf8,
        }
    }
}

fn default_csv_encoding() -> DecoderEncoding {
    DecoderEncoding::Utf8
}

fn is_default_csv_encoding(value: &DecoderEncoding) -> bool {
    *value == DecoderEncoding::Utf8
}

fn default_csv_delimiter() -> char {
    ','
}

fn is_default_csv_delimiter(value: &char) -> bool {
    *value == ','
}

fn default_csv_quote() -> char {
    '"'
}

fn is_default_csv_quote(value: &char) -> bool {
    *value == '"'
}

fn default_csv_quote_disabled() -> bool {
    false
}

fn is_default_csv_quote_disabled(value: &bool) -> bool {
    !*value
}

fn default_csv_header() -> bool {
    true
}

fn is_default_csv_header(value: &bool) -> bool {
    *value
}

fn default_csv_trim() -> bool {
    false
}

fn is_default_csv_trim(value: &bool) -> bool {
    !*value
}

/// The job-side checks over one parsed job and its pinned pack
/// (`products/adapter/CONCEPT.md` sections 17.1 and 17.2): the source
/// route resolves, the profile bounds hold and agree, the profile is
/// never tighter than an endpoint the source route reaches, the
/// projection declares a bounded field list, the triggers name a served
/// kind inside every bound, and the profile's upstream-call budget
/// covers the source route's worst case. Pure: no I/O.
#[must_use]
pub fn check_job(job: &AdapterJob, pack: &AdapterPack) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    if pack.source_routes.get(job.source.route.as_str()).is_none() {
        findings.push(job_finding(
            JobCode::RouteUnknown,
            "/source/route",
            "the job names no source route its pinned pack declares",
            "Name a sourceRoutes id of the pinned pack.",
        ));
    }
    findings.extend(profile_bound_checks(&job.profile));
    findings.extend(profile_consistency_checks(&job.profile));
    findings.extend(profile_endpoint_checks(job, pack));
    findings.extend(projection_checks(&job.projection));
    if job.projection_digest().is_empty() {
        findings.push(job_finding(
            JobCode::ProjectionShape,
            "/projection",
            "the job's projection digest computed empty",
            "Declare projection fields so the item rows can carry their digest.",
        ));
    }
    findings.extend(trigger_checks(&job.triggers));
    findings.extend(call_budget_checks(job, pack));
    findings
}

/// The profile bounds: every member inside its declared range, the field
/// named in the message and never the value.
fn profile_bound_checks(profile: &JobProfile) -> Vec<Diagnostic> {
    let ranges: [(&str, u64, u64); 9] = [
        (
            "pageDeadlineMilliseconds",
            profile.page_deadline_milliseconds,
            MAXIMUM_JOB_PAGE_DEADLINE_MILLISECONDS,
        ),
        (
            "maximumResponseBytes",
            profile.maximum_response_bytes,
            MAXIMUM_JOB_RESPONSE_BYTES,
        ),
        (
            "maximumPageItems",
            u64::from(profile.maximum_page_items),
            u64::from(MAXIMUM_JOB_PAGE_ITEMS),
        ),
        (
            "maximumPageBytes",
            profile.maximum_page_bytes,
            MAXIMUM_JOB_PAGE_BYTES,
        ),
        (
            "maximumUpstreamCalls",
            profile.maximum_upstream_calls,
            MAXIMUM_JOB_UPSTREAM_CALLS,
        ),
        (
            "read/maximumFileBytes",
            profile.read.maximum_file_bytes,
            MAXIMUM_JOB_FILE_BYTES,
        ),
        (
            "read/maximumRowBytes",
            profile.read.maximum_row_bytes,
            MAXIMUM_JOB_ROW_BYTES,
        ),
        (
            "read/maximumFieldBytes",
            profile.read.maximum_field_bytes,
            MAXIMUM_JOB_FIELD_BYTES,
        ),
        (
            "read/maximumRowsPerPage",
            u64::from(profile.read.maximum_rows_per_page),
            u64::from(MAXIMUM_JOB_ROWS_PER_PAGE),
        ),
    ];
    let mut findings = Vec::new();
    for &(field, value, maximum) in &ranges {
        if !(1..=maximum).contains(&value) {
            findings.push(job_finding(
                JobCode::ProfileBound,
                &format!("/profile/{field}"),
                "the profile bound lies outside its 1-to-maximum range",
                &format!("Declare the bound inside its 1 to {maximum} range."),
            ));
        }
    }
    findings
}

/// The profile's own consistency: the row and page bounds never exceed
/// the bounds they sit inside.
fn profile_consistency_checks(profile: &JobProfile) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    if profile.read.maximum_rows_per_page > profile.maximum_page_items {
        findings.push(job_finding(
            JobCode::ProfileInconsistent,
            "/profile/read/maximumRowsPerPage",
            "the read's maximumRowsPerPage exceeds the page's maximumPageItems",
            "Keep the rows-per-page bound at or below the page item bound.",
        ));
    }
    if profile.maximum_page_bytes > profile.maximum_response_bytes {
        findings.push(job_finding(
            JobCode::ProfileInconsistent,
            "/profile/maximumPageBytes",
            "the page's maximumPageBytes exceeds the profile's maximumResponseBytes",
            "Keep the page byte bound at or below the response byte bound.",
        ));
    }
    findings
}

/// The profile is never tighter than a bound of an endpoint the source
/// route reaches: at runtime the lower of the two applies, so a profile
/// below an endpoint's declared bound would shorten it unreviewed.
fn profile_endpoint_checks(job: &AdapterJob, pack: &AdapterPack) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    let Some(source) = pack.source_routes.get(job.source.route.as_str()) else {
        return findings;
    };
    let mut reached = HashSet::new();
    collect_reached_endpoints(
        source.steps.as_slice(),
        pack,
        &mut HashSet::new(),
        0,
        &mut reached,
    );
    for endpoint in &reached {
        if let Some(declared) = pack
            .endpoints
            .get(endpoint.as_str())
            .map(|endpoint| endpoint.maximum_response_bytes.get())
        {
            if declared > job.profile.maximum_response_bytes {
                findings.push(job_finding(
                    JobCode::ProfileEndpointBound,
                    "/profile/maximumResponseBytes",
                    "the profile is tighter than a bound of an endpoint the source route reaches",
                    "Raise the profile bound to at least the declared bound of every endpoint the source route reaches.",
                ));
                break;
            }
        }
    }
    findings
}

/// The projection checks: the job declares at least one projected path,
/// every path is a dotted identifier path of at most
/// [`MAXIMUM_PROJECTION_SEGMENTS`] segments, and the declaration stays
/// inside its count, length, and byte bounds. Structural faults refuse
/// under `adapter.job.projection-shape`, size faults under
/// `adapter.job.projection-bound`; the field named in the message, never
/// the value.
fn projection_checks(projection: &ProjectionDecl) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    if projection.fields.is_empty() {
        findings.push(job_finding(
            JobCode::ProjectionShape,
            "/projection/fields",
            "the job declares no projected fields",
            "Declare the dotted paths the workflow reads from each item value.",
        ));
        return findings;
    }
    if projection.fields.len() > MAXIMUM_PROJECTION_FIELDS {
        findings.push(job_finding(
            JobCode::ProjectionBound,
            "/projection/fields",
            "the projection declares more than the 64-field bound",
            "Declare at most 64 projected fields.",
        ));
    }
    for (index, field) in projection.fields.iter().enumerate() {
        if field.chars().count() > MAXIMUM_PROJECTION_FIELD_CHARACTERS {
            findings.push(job_finding(
                JobCode::ProjectionBound,
                &format!("/projection/fields/{index}"),
                "the projected path is longer than its 128-character bound",
                "Declare each projected path inside 128 characters.",
            ));
        } else if !is_dotted_identifier_path(field) {
            findings.push(job_finding(
                JobCode::ProjectionShape,
                &format!("/projection/fields/{index}"),
                "the projected path is not a dotted identifier path of at most 8 segments",
                "Write each projected path as dot-separated segments of ASCII letters, digits, underscores, and dashes, at most 8 segments.",
            ));
        }
    }
    if serialized_length(&serde_json::Value::Array(
        projection
            .fields
            .iter()
            .map(|field| serde_json::Value::String(field.clone()))
            .collect(),
    )) > MAXIMUM_PROJECTION_BYTES
    {
        findings.push(job_finding(
            JobCode::ProjectionBound,
            "/projection/fields",
            "the serialized projection passes its 2048-byte bound",
            "Declare fewer or shorter projected fields.",
        ));
    }
    findings
}

/// Whether a path is a non-empty dotted identifier path: at most
/// [`MAXIMUM_PROJECTION_SEGMENTS`] segments, each a non-empty run of
/// ASCII letters, digits, underscores, and dashes.
fn is_dotted_identifier_path(path: &str) -> bool {
    let segments = path.split('.').collect::<Vec<_>>();
    segments.len() <= MAXIMUM_PROJECTION_SEGMENTS
        && segments
            .iter()
            .all(|segment| !segment.is_empty() && segment.bytes().all(is_identifier_byte))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// The trigger checks: the job names at least one trigger and at most
/// [`MAXIMUM_JOB_TRIGGERS`], every trigger names a kind in
/// [`TRIGGER_KIND_VALUES`], every interval trigger sits inside its
/// option bounds, and a hook trigger is refused outright as the
/// contract-only seam it is. The hook refusal fires at check time so no
/// pack or job can silently rely on the seam before it is built.
fn trigger_checks(triggers: &[JobTrigger]) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    if triggers.is_empty() {
        findings.push(job_finding(
            JobCode::TriggersRequired,
            "/triggers",
            "the job declares no trigger, so no pass would ever start",
            "Declare at least one interval trigger.",
        ));
    }
    if triggers.len() > MAXIMUM_JOB_TRIGGERS {
        findings.push(job_finding(
            JobCode::TriggerBound,
            "/triggers",
            "the job declares more than the 16-trigger bound",
            "Declare at most 16 triggers, the bound Coordinator holds its workflows to.",
        ));
    }
    for (index, trigger) in triggers.iter().enumerate() {
        let prefix = format!("/triggers/{index}");
        match trigger.kind.as_str() {
            "interval" => {
                if trigger.path.is_some() {
                    findings.push(job_finding(
                        JobCode::TriggerKind,
                        &format!("{prefix}/path"),
                        "the interval trigger carries the hook-only path member",
                        "Drop path; only a hook trigger names a path.",
                    ));
                }
                let bounds: [(&str, u64, u64, u64); 5] = [
                    (
                        "delayMilliseconds",
                        trigger.delay_milliseconds,
                        MINIMUM_TRIGGER_DELAY_MILLISECONDS,
                        MAXIMUM_TRIGGER_DELAY_MILLISECONDS,
                    ),
                    (
                        "initialDelayMilliseconds",
                        trigger.initial_delay_milliseconds,
                        0,
                        MAXIMUM_TRIGGER_INITIAL_DELAY_MILLISECONDS,
                    ),
                    (
                        "backoffIdleThreshold",
                        u64::from(trigger.backoff_idle_threshold),
                        0,
                        u64::from(MAXIMUM_TRIGGER_BACKOFF_THRESHOLD),
                    ),
                    (
                        "backoffErrorThreshold",
                        u64::from(trigger.backoff_error_threshold),
                        0,
                        u64::from(MAXIMUM_TRIGGER_BACKOFF_THRESHOLD),
                    ),
                    (
                        "backoffMultiplier",
                        u64::from(trigger.backoff_multiplier),
                        u64::from(MINIMUM_TRIGGER_BACKOFF_MULTIPLIER),
                        u64::from(MAXIMUM_TRIGGER_BACKOFF_MULTIPLIER),
                    ),
                ];
                for &(field, value, minimum, maximum) in &bounds {
                    if !(minimum..=maximum).contains(&value) {
                        findings.push(job_finding(
                            JobCode::TriggerBound,
                            &format!("{prefix}/{field}"),
                            "the trigger option lies outside its range",
                            &format!("Declare the option inside its {minimum} to {maximum} range."),
                        ));
                    }
                }
            }
            "hook" => match &trigger.path {
                None => findings.push(job_finding(
                    JobCode::TriggerKind,
                    &format!("{prefix}/path"),
                    "the hook trigger names no path",
                    "Name the listener path the hook waits on.",
                )),
                Some(_) => findings.push(job_finding(
                    JobCode::TriggerHookUnserved,
                    &prefix,
                    "a hook trigger is a contract-only seam no engine serves yet",
                    "Replace the hook trigger with an interval trigger until the hook seam is built; a hook only starts a pass, which re-reads the source.",
                )),
            },
            _ => findings.push(job_finding(
                JobCode::TriggerKind,
                &format!("{prefix}/kind"),
                "the trigger names no kind in the closed interval-and-hook set",
                "Declare kind as interval, or hook once the seam is served.",
            )),
        }
    }
    findings
}

/// The profile's own upstream-call budget against the source route's
/// static worst case: the same walk the facade binding budget stands on,
/// over the pack's route graph alone, because a job runs beside no
/// project. A budget below the worst case refuses, and so does an
/// uncountable route, one nested past the reader's depth bound: a budget
/// that cannot be proven sufficient is refused, never silently passed.
fn call_budget_checks(job: &AdapterJob, pack: &AdapterPack) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    let Some(source) = pack.source_routes.get(job.source.route.as_str()) else {
        return findings;
    };
    let (worst, depth_exceeded) =
        crate::checks::source_route_worst_case(pack, source.steps.as_slice());
    if depth_exceeded {
        findings.push(job_finding(
            JobCode::CallBudget,
            "/profile/maximumUpstreamCalls",
            "the source route nests past the reader's depth bound, so its worst-case call count cannot be counted",
            "Flatten the nesting; the reader refuses documents deeper than the bound.",
        ));
    } else if worst > job.profile.maximum_upstream_calls {
        findings.push(job_finding(
            JobCode::CallBudget,
            "/profile/maximumUpstreamCalls",
            "the profile's upstream-call budget is below the source route's static worst-case call count",
            "Raise maximumUpstreamCalls to at least the route's worst case, or bound the sends the route can make.",
        ));
    }
    findings
}

/// The endpoint ids the sends of one source route reach, through
/// `direct:` expansion into the pack's internal routes and templates. A
/// `direct:` target that names another source route does not resolve
/// (source routes are entry points, not subroutines), and the expansion
/// cannot cycle because the direct graph is acyclic; the visited set
/// guards a defective pack regardless.
fn collect_reached_endpoints<'a>(
    steps: &'a [Step],
    pack: &'a AdapterPack,
    visiting: &mut HashSet<&'a str>,
    depth: usize,
    reached: &mut HashSet<String>,
) {
    if depth > crate::checks::MAX_DIRECT_DEPTH {
        return;
    }
    for step in steps {
        match step {
            Step::To(to) => match to.uri.component {
                crate::model::SendComponent::Http
                | crate::model::SendComponent::GraphQl
                | crate::model::SendComponent::Postgres => {
                    reached.insert(to.uri.id.clone());
                }
                crate::model::SendComponent::Direct => {
                    expand_reached(to.uri.id.as_str(), pack, visiting, depth, reached);
                }
                crate::model::SendComponent::File | crate::model::SendComponent::Sftp => {}
            },
            Step::Enrich(enrich) => match enrich.uri.component {
                crate::model::SendComponent::Http
                | crate::model::SendComponent::GraphQl
                | crate::model::SendComponent::Postgres => {
                    reached.insert(enrich.uri.id.clone());
                }
                crate::model::SendComponent::Direct => {
                    expand_reached(enrich.uri.id.as_str(), pack, visiting, depth, reached);
                }
                crate::model::SendComponent::File | crate::model::SendComponent::Sftp => {}
            },
            // A poll names its endpoint through the step's static URI, not
            // a send; the poll page is bounded by the read bounds, so no
            // send bound of the profile rides on it.
            Step::PollEnrich(_) => {}
            other => {
                for nested in nested_steps(other) {
                    collect_reached_endpoints(nested, pack, visiting, depth, reached);
                }
            }
        }
    }
}

fn expand_reached<'a>(
    name: &'a str,
    pack: &'a AdapterPack,
    visiting: &mut HashSet<&'a str>,
    depth: usize,
    reached: &mut HashSet<String>,
) {
    if !visiting.insert(name) {
        return;
    }
    let body = pack
        .routes
        .iter()
        .find(|route| route.from.uri.id.as_str() == name)
        .map(|route| route.steps.as_slice())
        .or_else(|| {
            pack.route_templates
                .iter()
                .find(|template| template.id.as_str() == name)
                .map(|template| template.steps.as_slice())
        });
    if let Some(body) = body {
        collect_reached_endpoints(body, pack, visiting, depth + 1, reached);
    }
    visiting.remove(name);
}

/// The nested step lists of a composite step, for the walks that expand
/// `direct:` sends themselves and so cannot use
/// `crate::checks::walk_steps`.
fn nested_steps(step: &Step) -> Vec<&[Step]> {
    match step {
        Step::Choice(choice) => choice
            .when
            .iter()
            .map(|when| when.steps.as_slice())
            .chain(
                choice
                    .otherwise
                    .iter()
                    .map(|otherwise| otherwise.steps.as_slice()),
            )
            .collect(),
        Step::Filter(filter) => vec![filter.steps.as_slice()],
        Step::Split(split) => vec![split.steps.as_slice()],
        Step::Loop(loop_step) => vec![loop_step.steps.as_slice()],
        Step::CircuitBreaker(breaker) => std::iter::once(breaker.steps.as_slice())
            .chain(
                breaker
                    .on_fallback
                    .iter()
                    .map(|fallback| fallback.steps.as_slice()),
            )
            .collect(),
        Step::Throttle(throttle) => vec![throttle.steps.as_slice()],
        Step::IdempotentConsumer(idempotent) => vec![idempotent.steps.as_slice()],
        Step::OnException(clause) => vec![clause.steps.as_slice()],
        Step::DoTry(do_try) => std::iter::once(do_try.steps.as_slice())
            .chain(do_try.do_catch.iter().map(|catch| catch.steps.as_slice()))
            .chain(
                do_try
                    .do_finally
                    .iter()
                    .map(|do_finally| do_finally.steps.as_slice()),
            )
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_yaml::Digest;

    const DIGEST: &str = "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9";

    fn profile() -> JobProfile {
        JobProfile {
            page_deadline_milliseconds: 60_000,
            maximum_response_bytes: 16_777_216,
            maximum_page_items: 1_000,
            maximum_page_bytes: 1_048_576,
            maximum_upstream_calls: 16,
            read: ReadBounds {
                maximum_file_bytes: 1_073_741_824,
                maximum_row_bytes: 1_048_576,
                maximum_field_bytes: 65_536,
                maximum_rows_per_page: 1_000,
            },
        }
    }

    /// The canonical interval trigger, the form every job names at least
    /// once.
    fn interval_trigger() -> JobTrigger {
        JobTrigger {
            kind: "interval".to_string(),
            delay_milliseconds: DEFAULT_TRIGGER_DELAY_MILLISECONDS,
            initial_delay_milliseconds: 0,
            greedy: false,
            backoff_idle_threshold: 0,
            backoff_error_threshold: 0,
            backoff_multiplier: 1,
            path: None,
        }
    }

    /// The canonical projection: the two dotted paths of the governed-
    /// ingestion concept's example, digesting the projected fields.
    fn projection() -> ProjectionDecl {
        ProjectionDecl {
            fields: vec!["household.name".to_string(), "household.size".to_string()],
            digest_of: ProjectionDigestOf::Projection,
        }
    }

    fn job(source_route: &str) -> AdapterJob {
        AdapterJob {
            api_version: ADAPTER_JOB_API_VERSION.to_string(),
            kind: ADAPTER_JOB_KIND.to_string(),
            job: JobIdentity {
                id: LocalId::new("kobo-daily").expect("id"),
                version: "1".to_string(),
            },
            source: JobSource {
                pack: crate::project::PinnedRef {
                    id: LocalId::new("kobo-pack").expect("id"),
                    version: "1".to_string(),
                    digest: Digest::new(DIGEST).expect("digest"),
                },
                route: source_route.to_string(),
            },
            projection: projection(),
            triggers: vec![interval_trigger()],
            profile: profile(),
        }
    }

    fn pack() -> AdapterPack {
        serde_json::from_str(
            r#"{
                "id": "kobo-pack",
                "version": "1",
                "testedVersions": [],
                "endpoints": [
                    { "id": "submissions", "component": "file", "authentication": { "type": "none" },
                      "attemptTimeoutMilliseconds": 10000, "maximumResponseBytes": 16777216 },
                    { "id": "ledger", "component": "postgres", "authentication": { "type": "none" },
                      "attemptTimeoutMilliseconds": 10000, "maximumResponseBytes": 1048576,
                      "queryFile": "queries/ledger.sql" }
                ],
                "sourceRoutes": [
                    { "id": "kobo-submissions", "scan": "ongoing", "nextRecovery": "key-deduplicated",
                      "edits": "ordered",
                      "steps": [ { "to": { "uri": "postgres:ledger" } } ] }
                ]
            }"#,
        )
        .expect("pack")
    }

    /// The artifact round-trips: identity block, pinned pack and source
    /// route, projection, triggers, bounded profile. Unknown members
    /// refuse, and a member at its default stays off the wire.
    #[test]
    fn job_round_trips_and_refuses_unknown_members() {
        let base = job("kobo-submissions");
        let json = serde_json::to_value(&base).expect("serialize");
        assert_eq!(json["kind"], "AdapterJob");
        assert_eq!(json["source"]["route"], "kobo-submissions");
        assert_eq!(json["profile"]["read"]["maximumFileBytes"], 1_073_741_824);
        assert_eq!(json["profile"]["maximumUpstreamCalls"], 16);
        assert_eq!(json["projection"]["fields"][0], "household.name");
        assert_eq!(json["triggers"][0]["kind"], "interval");
        // Defaults stay off the wire: the digest-of default, the minute
        // delay, and the backoff defaults.
        assert_eq!(
            json["projection"],
            serde_json::json!({"fields": ["household.name", "household.size"]})
        );
        assert_eq!(json["triggers"][0], serde_json::json!({"kind": "interval"}));
        assert_eq!(
            serde_json::from_value::<AdapterJob>(json).ok(),
            Some(base.clone())
        );
        let mut extra = serde_json::to_value(&base).expect("serialize");
        extra["bogus"] = serde_json::json!(1);
        assert!(
            serde_json::from_value::<AdapterJob>(extra).is_err(),
            "an unknown member is refused"
        );
        // An unknown digestOf refuses at the reader: the closed set.
        let mut unknown_digest = serde_json::to_value(&base).expect("serialize");
        unknown_digest["projection"]["digestOf"] = serde_json::json!("row");
        assert!(
            serde_json::from_value::<AdapterJob>(unknown_digest).is_err(),
            "an unknown digestOf is refused"
        );
        // A digest over the whole item value round-trips and spells
        // lowercase.
        let value_digest = AdapterJob {
            projection: ProjectionDecl {
                fields: vec!["household.name".to_string()],
                digest_of: ProjectionDigestOf::Value,
            },
            ..job("kobo-submissions")
        };
        let wire = serde_json::to_value(&value_digest).expect("serialize");
        assert_eq!(wire["projection"]["digestOf"], "value");
        assert_eq!(
            serde_json::from_value::<AdapterJob>(wire).ok(),
            Some(value_digest)
        );
    }

    /// The job checks accept a sound job over a sound pack: the source
    /// route resolves and every profile bound is inside its range.
    #[test]
    fn check_job_accepts_a_sound_job() {
        let findings = check_job(&job("kobo-submissions"), &pack());
        assert!(
            findings.is_empty(),
            "a sound job produces no findings: {findings:?}"
        );
    }

    /// A job naming a source route the pack does not declare refuses under
    /// `adapter.job.route-unknown`.
    #[test]
    fn check_job_refuses_an_unknown_source_route() {
        let findings = check_job(&job("nope"), &pack());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].code, JobCode::RouteUnknown.code());
        assert_eq!(findings[0].artifact.as_deref(), Some(ADAPTER_JOB_KIND));
    }

    /// Each profile bound refuses outside its range under
    /// `adapter.job.profile-bound`, with the field named and no value
    /// repeated. `maximumUpstreamCalls` at its default of 0 refuses too:
    /// the member is mandatory at check time.
    #[test]
    fn check_job_refuses_out_of_range_profile_bounds() {
        let cases: [(&str, JobProfile); 10] = [
            (
                "/profile/pageDeadlineMilliseconds",
                JobProfile {
                    page_deadline_milliseconds: 600_001,
                    ..profile()
                },
            ),
            (
                "/profile/maximumResponseBytes",
                JobProfile {
                    maximum_response_bytes: 16_777_217,
                    ..profile()
                },
            ),
            (
                "/profile/maximumPageItems",
                JobProfile {
                    maximum_page_items: 10_001,
                    ..profile()
                },
            ),
            (
                "/profile/maximumPageBytes",
                JobProfile {
                    maximum_page_bytes: 0,
                    ..profile()
                },
            ),
            (
                "/profile/maximumUpstreamCalls",
                JobProfile {
                    maximum_upstream_calls: 0,
                    ..profile()
                },
            ),
            (
                "/profile/maximumUpstreamCalls",
                JobProfile {
                    maximum_upstream_calls: 1_001,
                    ..profile()
                },
            ),
            (
                "/profile/read/maximumFileBytes",
                JobProfile {
                    read: ReadBounds {
                        maximum_file_bytes: 1_073_741_825,
                        ..profile().read
                    },
                    ..profile()
                },
            ),
            (
                "/profile/read/maximumRowBytes",
                JobProfile {
                    read: ReadBounds {
                        maximum_row_bytes: 1_048_577,
                        ..profile().read
                    },
                    ..profile()
                },
            ),
            (
                "/profile/read/maximumFieldBytes",
                JobProfile {
                    read: ReadBounds {
                        maximum_field_bytes: 65_537,
                        ..profile().read
                    },
                    ..profile()
                },
            ),
            (
                "/profile/read/maximumRowsPerPage",
                JobProfile {
                    read: ReadBounds {
                        maximum_rows_per_page: 0,
                        ..profile().read
                    },
                    ..profile()
                },
            ),
        ];
        for (pointer, bad) in cases {
            let findings = check_job(
                &AdapterJob {
                    profile: bad,
                    ..job("kobo-submissions")
                },
                &pack(),
            );
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.code == JobCode::ProfileBound.code()
                        && finding.path == pointer),
                "{pointer} refuses with its own finding: {findings:?}"
            );
        }
    }

    /// An inconsistent profile refuses: rows per page over the page item
    /// bound, and page bytes over the response bytes.
    #[test]
    fn check_job_refuses_an_inconsistent_profile() {
        let rows = JobProfile {
            read: ReadBounds {
                maximum_rows_per_page: 1_001,
                ..profile().read
            },
            ..profile()
        };
        let findings = check_job(
            &AdapterJob {
                profile: rows,
                ..job("kobo-submissions")
            },
            &pack(),
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == JobCode::ProfileInconsistent.code()),
            "rows per page over the item bound refuses: {findings:?}"
        );
        let bytes = JobProfile {
            maximum_page_bytes: 2_097_152,
            maximum_response_bytes: 1_048_576,
            ..profile()
        };
        let findings = check_job(
            &AdapterJob {
                profile: bytes,
                ..job("kobo-submissions")
            },
            &pack(),
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == JobCode::ProfileInconsistent.code()),
            "page bytes over response bytes refuse: {findings:?}"
        );
    }

    /// A profile tighter than an endpoint the source route reaches
    /// refuses under `adapter.job.profile-endpoint-bound`; an endpoint
    /// bound at or below the profile accepts.
    #[test]
    fn check_job_refuses_a_profile_tighter_than_a_reached_endpoint() {
        let pinned = pack();
        let mut tight = job("kobo-submissions");
        tight.profile.maximum_response_bytes = 1_048_575;
        let findings = check_job(&tight, &pinned);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == JobCode::ProfileEndpointBound.code())
                .count(),
            1,
            "the ledger endpoint declares 1 MiB, the profile 1 MiB less one: {findings:?}"
        );
        // An unreachable endpoint's bound never constrains the profile.
        let mut isolated = job("kobo-submissions");
        isolated.profile.maximum_response_bytes = 2;
        isolated.profile.maximum_page_bytes = 2;
        let mut endpoints = pack().endpoints.into_vec();
        let ledger = endpoints
            .iter_mut()
            .find(|endpoint| endpoint.id.as_str() == "ledger")
            .expect("endpoint");
        ledger.maximum_response_bytes =
            registry_platform_yaml::BoundedU64::new(2).expect("in range");
        let relaxed = AdapterPack {
            endpoints: registry_platform_yaml::UniqueIdList::new(endpoints).expect("unique"),
            ..pack()
        };
        let findings = check_job(&isolated, &relaxed);
        assert!(
            findings.is_empty(),
            "the only reached endpoint matches the profile: {findings:?}"
        );
    }

    /// A job that declares no projected fields refuses under
    /// `adapter.job.projection-shape`: the projection is the job's
    /// data-minimization declaration, so a job never runs without one.
    #[test]
    fn check_job_refuses_an_undeclared_projection() {
        let bare = AdapterJob {
            projection: ProjectionDecl::default(),
            ..job("kobo-submissions")
        };
        let findings = check_job(&bare, &pack());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].code, JobCode::ProjectionShape.code());
        assert_eq!(findings[0].path, "/projection/fields");
    }

    /// A projected path that is not a dotted identifier path refuses
    /// under `adapter.job.projection-shape`: an empty segment, a
    /// forbidden character, and a path past the 8-segment bound each
    /// refuse at their own position.
    #[test]
    fn check_job_refuses_malformed_projection_paths() {
        let cases = [
            "",
            "household..name",
            ".household",
            "household.",
            "household name",
            "household.\u{00e9}lderly",
            "a.b.c.d.e.f.g.h.i",
        ];
        for field in cases {
            let bad = AdapterJob {
                projection: ProjectionDecl {
                    fields: vec!["household.name".to_string(), field.to_string()],
                    digest_of: ProjectionDigestOf::Projection,
                },
                ..job("kobo-submissions")
            };
            let findings = check_job(&bad, &pack());
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.code == JobCode::ProjectionShape.code()
                        && finding.path == "/projection/fields/1"),
                "{field:?} refuses with its own shape finding: {findings:?}"
            );
        }
        // The accepted spellings stay clean: letters, digits, underscore,
        // dash, and eight segments.
        let good = AdapterJob {
            projection: ProjectionDecl {
                fields: vec![
                    "household.head.name".to_string(),
                    "household_size-2".to_string(),
                    "a.b.c.d.e.f.g.h".to_string(),
                ],
                digest_of: ProjectionDigestOf::Projection,
            },
            ..job("kobo-submissions")
        };
        let findings = check_job(&good, &pack());
        assert!(
            findings.is_empty(),
            "accepted path spellings stay clean: {findings:?}"
        );
    }

    /// A projection past its size bounds refuses under
    /// `adapter.job.projection-bound`: more than 64 fields, a path past
    /// 128 characters, and a serialized list past 2048 bytes.
    #[test]
    fn check_job_refuses_out_of_bounds_projections() {
        let many: Vec<String> = (0..65).map(|index| format!("field{index}")).collect();
        let bad = AdapterJob {
            projection: ProjectionDecl {
                fields: many,
                digest_of: ProjectionDigestOf::Projection,
            },
            ..job("kobo-submissions")
        };
        let findings = check_job(&bad, &pack());
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == JobCode::ProjectionBound.code()
                    && finding.path == "/projection/fields"),
            "65 fields refuse: {findings:?}"
        );

        let long = format!(
            "household.{}",
            "n".repeat(MAXIMUM_PROJECTION_FIELD_CHARACTERS)
        );
        let bad = AdapterJob {
            projection: ProjectionDecl {
                fields: vec![long],
                digest_of: ProjectionDigestOf::Projection,
            },
            ..job("kobo-submissions")
        };
        let findings = check_job(&bad, &pack());
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == JobCode::ProjectionBound.code()
                    && finding.path == "/projection/fields/0"),
            "a path over 128 characters refuses: {findings:?}"
        );

        // A serialized list past 2048 bytes: 64 paths of 40 characters
        // each, every other bound met.
        let wide: Vec<String> = (0..64)
            .map(|index| format!("field.{index:03}.{}", "m".repeat(30)))
            .collect();
        let bad = AdapterJob {
            projection: ProjectionDecl {
                fields: wide,
                digest_of: ProjectionDigestOf::Projection,
            },
            ..job("kobo-submissions")
        };
        let findings = check_job(&bad, &pack());
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == JobCode::ProjectionBound.code()
                    && finding.path == "/projection/fields"),
            "a list past 2048 serialized bytes refuses: {findings:?}"
        );
    }

    /// The projection digest is the sha256 hex over the canonical
    /// serialization of the block with sorted keys, stable across
    /// construction order, and distinct for a different block.
    #[test]
    fn projection_digest_pins_the_canonical_block() {
        let base = job("kobo-submissions");
        assert_eq!(
            base.projection_digest(),
            "2a3b1d33acaa434c224c83c220774bfdbaefd1f7e3175f1c23a36d562a0ac9ed",
            "the digest covers the canonical sorted-key serialization"
        );
        let value_digest = AdapterJob {
            projection: ProjectionDecl {
                fields: vec!["household.name".to_string()],
                digest_of: ProjectionDigestOf::Value,
            },
            ..job("kobo-submissions")
        };
        assert_eq!(
            value_digest.projection_digest(),
            "78f4b2ade56abf5a8905a6063a2f1082fdea1941a2105e20b3540556cdde4ce2",
            "a digestOf: value block digests differently"
        );
        // The same fields in another order are a different projection
        // block, so a reordering reports as a change.
        let reordered = AdapterJob {
            projection: ProjectionDecl {
                fields: vec!["household.size".to_string(), "household.name".to_string()],
                digest_of: ProjectionDigestOf::Projection,
            },
            ..job("kobo-submissions")
        };
        assert_ne!(base.projection_digest(), reordered.projection_digest());
    }

    /// A job with no trigger refuses under `adapter.job.triggers-required`:
    /// no trigger means no pass ever starts, and the refusal names that.
    #[test]
    fn check_job_refuses_an_empty_trigger_list() {
        let bare = AdapterJob {
            triggers: Vec::new(),
            ..job("kobo-submissions")
        };
        let findings = check_job(&bare, &pack());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].code, JobCode::TriggersRequired.code());
        assert_eq!(findings[0].path, "/triggers");
    }

    /// A trigger outside the closed kind set refuses under
    /// `adapter.job.trigger-kind`, at its own position.
    #[test]
    fn check_job_refuses_an_unknown_trigger_kind() {
        for kind in ["", "timer", "cron"] {
            let bad = AdapterJob {
                triggers: vec![JobTrigger {
                    kind: kind.to_string(),
                    ..interval_trigger()
                }],
                ..job("kobo-submissions")
            };
            let findings = check_job(&bad, &pack());
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.code == JobCode::TriggerKind.code()
                        && finding.path == "/triggers/0/kind"),
                "kind {kind:?} refuses with its own finding: {findings:?}"
            );
        }
    }

    /// Every interval option bound refuses under
    /// `adapter.job.trigger-bound` at its own position: a delay below one
    /// second (Camel's own 500-millisecond default among them) or above a
    /// day, an initial delay above a day, a backoff threshold past 100,
    /// and a multiplier outside 1 to 10.
    #[test]
    fn check_job_refuses_out_of_range_trigger_options() {
        let cases: [(&str, JobTrigger); 7] = [
            (
                "/triggers/0/delayMilliseconds",
                JobTrigger {
                    delay_milliseconds: 500,
                    ..interval_trigger()
                },
            ),
            (
                "/triggers/0/delayMilliseconds",
                JobTrigger {
                    delay_milliseconds: 86_400_001,
                    ..interval_trigger()
                },
            ),
            (
                "/triggers/0/initialDelayMilliseconds",
                JobTrigger {
                    initial_delay_milliseconds: 86_400_001,
                    ..interval_trigger()
                },
            ),
            (
                "/triggers/0/backoffIdleThreshold",
                JobTrigger {
                    backoff_idle_threshold: 101,
                    ..interval_trigger()
                },
            ),
            (
                "/triggers/0/backoffErrorThreshold",
                JobTrigger {
                    backoff_error_threshold: 101,
                    ..interval_trigger()
                },
            ),
            (
                "/triggers/0/backoffMultiplier",
                JobTrigger {
                    backoff_multiplier: 0,
                    ..interval_trigger()
                },
            ),
            (
                "/triggers/0/backoffMultiplier",
                JobTrigger {
                    backoff_multiplier: 11,
                    ..interval_trigger()
                },
            ),
        ];
        for (pointer, trigger) in cases {
            let bad = AdapterJob {
                triggers: vec![trigger],
                ..job("kobo-submissions")
            };
            let findings = check_job(&bad, &pack());
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.code == JobCode::TriggerBound.code()
                        && finding.path == pointer),
                "{pointer} refuses with its own finding: {findings:?}"
            );
        }
        // The accepted edges stay clean: a one-second delay, a day, a
        // day's initial delay, thresholds at 100, a multiplier of 1 and
        // 10.
        let edges = AdapterJob {
            triggers: vec![JobTrigger {
                kind: "interval".to_string(),
                delay_milliseconds: 1_000,
                initial_delay_milliseconds: 86_400_000,
                greedy: true,
                backoff_idle_threshold: 100,
                backoff_error_threshold: 100,
                backoff_multiplier: 10,
                path: None,
            }],
            ..job("kobo-submissions")
        };
        let findings = check_job(&edges, &pack());
        assert!(
            findings.is_empty(),
            "the trigger bounds accept their edges: {findings:?}"
        );
    }

    /// A hook trigger is the contract-only seam: refused at check time
    /// under `adapter.job.trigger-hook-unserved`, so no pack or job can
    /// silently rely on it, and a hook trigger without its path refuses
    /// under `adapter.job.trigger-kind`.
    #[test]
    fn check_job_refuses_a_hook_trigger() {
        let hook = AdapterJob {
            triggers: vec![JobTrigger {
                kind: "hook".to_string(),
                path: Some("submissions".to_string()),
                ..interval_trigger()
            }],
            ..job("kobo-submissions")
        };
        let findings = check_job(&hook, &pack());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].code, JobCode::TriggerHookUnserved.code());
        assert_eq!(findings[0].path, "/triggers/0");

        let pathless = AdapterJob {
            triggers: vec![JobTrigger {
                kind: "hook".to_string(),
                ..interval_trigger()
            }],
            ..job("kobo-submissions")
        };
        let findings = check_job(&pathless, &pack());
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == JobCode::TriggerKind.code()
                    && finding.path == "/triggers/0/path"),
            "a hook trigger without its path refuses: {findings:?}"
        );
    }

    /// A job past the 16-trigger bound refuses under
    /// `adapter.job.trigger-bound`, the bound Coordinator holds its
    /// workflows to.
    #[test]
    fn check_job_refuses_more_than_sixteen_triggers() {
        let bad = AdapterJob {
            triggers: std::iter::repeat_n(interval_trigger(), MAXIMUM_JOB_TRIGGERS + 1).collect(),
            ..job("kobo-submissions")
        };
        let findings = check_job(&bad, &pack());
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == JobCode::TriggerBound.code()
                    && finding.path == "/triggers"),
            "17 triggers refuse: {findings:?}"
        );
        let full = AdapterJob {
            triggers: std::iter::repeat_n(interval_trigger(), MAXIMUM_JOB_TRIGGERS).collect(),
            ..job("kobo-submissions")
        };
        let findings = check_job(&full, &pack());
        assert!(findings.is_empty(), "16 triggers stay clean: {findings:?}");
    }

    /// The profile's upstream-call budget covers the source route's
    /// static worst case, computed by the same walk the facade binding
    /// budget stands on: a loop of two sends against a budget of one
    /// refuses, and the same route at the budget passes.
    #[test]
    fn check_job_refuses_a_budget_below_the_route_worst_case() {
        let looping_pack: AdapterPack = serde_json::from_str(
            r#"{
                "id": "kobo-pack",
                "version": "1",
                "testedVersions": [],
                "endpoints": [
                    { "id": "submissions", "component": "http", "authentication": { "type": "none" },
                      "attemptTimeoutMilliseconds": 10000, "maximumResponseBytes": 1048576 }
                ],
                "sourceRoutes": [
                    { "id": "kobo-submissions", "scan": "ongoing", "nextRecovery": "key-deduplicated",
                      "edits": "ordered",
                      "steps": [
                        { "loop": { "constant": 2, "maximumIterations": 2,
                            "steps": [ { "to": { "uri": "http:submissions" } } ] } }
                      ] }
                ]
            }"#,
        )
        .expect("pack");
        let mut below = job("kobo-submissions");
        below.profile.maximum_upstream_calls = 1;
        let findings = check_job(&below, &looping_pack);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].code, JobCode::CallBudget.code());
        assert_eq!(findings[0].path, "/profile/maximumUpstreamCalls");

        let mut at_budget = job("kobo-submissions");
        at_budget.profile.maximum_upstream_calls = 2;
        let findings = check_job(&at_budget, &looping_pack);
        assert!(
            findings.is_empty(),
            "a route at the budget passes: {findings:?}"
        );
    }

    /// The item contract: a sound page validates, round-trips through
    /// `to_value`, and every fault carries its own value-free code.
    #[test]
    fn item_pages_validate_and_round_trip() {
        let page = ItemPage {
            items: vec![
                SourceItem {
                    key: "region/form/1".to_string(),
                    revision: Some("42".to_string()),
                    value: serde_json::json!({"answers": {"age": "045"}}),
                },
                SourceItem {
                    key: "region/form/2".to_string(),
                    revision: None,
                    value: serde_json::json!("captured"),
                },
            ],
            next: Some(serde_json::json!({"digest": "sha256:ab", "position": 512})),
        };
        let wire = page.to_value();
        let back = ItemPage::from_value(&wire, &profile()).expect("valid page");
        assert_eq!(back, page);
        let text = serde_json::to_string(&wire).expect("text");
        assert_eq!(
            serde_json::from_str::<ItemPage>(&text).expect("serde"),
            page,
            "the serde form round-trips"
        );

        let faults: [(ItemPageFault, serde_json::Value); 6] = [
            (ItemPageFault::Shape, serde_json::json!([])),
            (ItemPageFault::Shape, serde_json::json!({"items": {}})),
            (
                ItemPageFault::Shape,
                serde_json::json!({"items": [{"key": 1, "value": null}]}),
            ),
            (
                ItemPageFault::Shape,
                serde_json::json!({"items": [{"key": "k"}]}),
            ),
            (
                ItemPageFault::Key,
                serde_json::json!({"items": [{"key": "", "value": null}]}),
            ),
            (
                ItemPageFault::Shape,
                serde_json::json!({"items": [{"key": "k", "revision": {}}]}),
            ),
        ];
        for (fault, value) in faults {
            assert_eq!(
                ItemPage::from_value(&value, &profile())
                    .expect_err("fault")
                    .code(),
                fault.code(),
                "{}",
                value
            );
        }
        let long_key = "k".repeat(MAXIMUM_ITEM_KEY_BYTES + 1);
        assert_eq!(
            ItemPage::from_value(
                &serde_json::json!({ "items": [ {"key": long_key, "value": null} ] }),
                &profile(),
            )
            .expect_err("fault")
            .code(),
            ItemPageFault::Key.code()
        );
        let long_revision = "r".repeat(MAXIMUM_ITEM_REVISION_BYTES + 1);
        assert_eq!(
            ItemPage::from_value(
                &serde_json::json!({ "items": [ {"key": "k", "revision": long_revision, "value": null} ] }),
                &profile(),
            )
            .expect_err("fault")
            .code(),
            ItemPageFault::Key.code()
        );

        // The page bounds.
        let mut tight = profile();
        tight.maximum_page_items = 1;
        let two = serde_json::json!({"items": [{"key": "a", "value": null}, {"key": "b", "value": null}]});
        assert_eq!(
            ItemPage::from_value(&two, &tight)
                .expect_err("fault")
                .code(),
            ItemPageFault::ItemsBound.code()
        );
        let mut tight = profile();
        tight.maximum_page_bytes = 8;
        assert_eq!(
            ItemPage::from_value(
                &serde_json::json!({"items": [{"key": "a", "value": null}]}),
                &tight,
            )
            .expect_err("fault")
            .code(),
            ItemPageFault::BytesBound.code()
        );
        let long_next = "n".repeat(MAXIMUM_NEXT_BYTES + 1);
        assert_eq!(
            ItemPage::from_value(
                &serde_json::json!({ "items": [], "next": long_next }),
                &profile(),
            )
            .expect_err("fault")
            .code(),
            ItemPageFault::NextBound.code()
        );
        // A cursor within the bound accepts, and an absent next stays
        // absent.
        let page = ItemPage::from_value(
            &serde_json::json!({ "items": [], "next": {"position": 1} }),
            &profile(),
        )
        .expect("valid");
        assert_eq!(page.next, Some(serde_json::json!({"position": 1})));
        let page =
            ItemPage::from_value(&serde_json::json!({"items": []}), &profile()).expect("valid");
        assert_eq!(page.next, None);
    }

    /// The job code vocabulary is closed, sorted, value-free, and
    /// three-segment.
    #[test]
    fn job_codes_round_trip() {
        for code in JobCode::ALL {
            assert_eq!(JobCode::from_code(code.code()), Some(*code));
            let mut segments = code.code().split('.');
            assert_eq!(segments.next(), Some("adapter"));
            assert_eq!(segments.next(), Some("job"));
            assert!(
                segments.next().is_some(),
                "{} needs a condition",
                code.code()
            );
            assert_eq!(segments.next(), None);
        }
        assert_eq!(JobCode::from_code("adapter.job.invented"), None);
        let mut codes: Vec<&str> = JobCode::ALL.iter().map(|code| code.code()).collect();
        let expected = codes.clone();
        codes.sort_unstable();
        assert_eq!(codes, expected, "ALL must stay in code-string order");
    }

    /// The decoder options carry Camel's defaults exactly: comma
    /// delimiter, double quote, quoting on, header record on, no comment
    /// marker, no trimming, UTF-8. Defaults stay off the wire.
    #[test]
    fn csv_decoder_defaults_match_camel() {
        let defaults: CsvDecoder = serde_json::from_str("{}").expect("parse");
        assert_eq!(defaults, CsvDecoder::default());
        assert_eq!(defaults.delimiter, ',');
        assert_eq!(defaults.quote, '"');
        assert!(!defaults.quote_disabled);
        assert!(defaults.header);
        assert_eq!(defaults.comment_marker, None);
        assert!(!defaults.trim);
        assert_eq!(defaults.encoding, DecoderEncoding::Utf8);
        let wire = serde_json::to_value(&defaults).expect("serialize");
        assert_eq!(wire, serde_json::json!({}), "defaults stay off the wire");

        let explicit: CsvDecoder = serde_json::from_str(
            r##"{"delimiter": "\t", "quote": "'", "quoteDisabled": true, "header": false, "commentMarker": "#", "trim": true}"##,
        )
        .expect("parse");
        assert_eq!(explicit.delimiter, '\t');
        assert_eq!(explicit.quote, '\'');
        assert!(explicit.quote_disabled);
        assert!(!explicit.header);
        assert_eq!(explicit.comment_marker, Some('#'));
        assert!(explicit.trim);
        let back = serde_json::to_value(&explicit).expect("serialize");
        assert_eq!(
            serde_json::from_value::<CsvDecoder>(back).ok(),
            Some(explicit)
        );
        assert!(
            serde_json::from_str::<CsvDecoder>(r#"{"delimiter": ";;"}"#).is_err(),
            "a multi-character delimiter is refused at the reader"
        );
        assert!(
            serde_json::from_str::<CsvDecoder>(r#"{"bogus": 1}"#).is_err(),
            "an unknown option is refused"
        );
    }

    /// The platform constants this module pins stay pinned.
    #[test]
    fn job_bounds_keep_the_platform_caps() {
        assert_eq!(MAXIMUM_JOB_RESPONSE_BYTES, 16_777_216);
        assert_eq!(MAXIMUM_JOB_ATTEMPT_TIMEOUT_MILLISECONDS, 10_000);
        assert_eq!(MAXIMUM_JOB_PAGE_DEADLINE_MILLISECONDS, 600_000);
        assert_eq!(MAXIMUM_JOB_FILE_BYTES, 1_073_741_824);
        assert_eq!(MAXIMUM_JOB_ROW_BYTES, 1_048_576);
        assert_eq!(MAXIMUM_JOB_FIELD_BYTES, 65_536);
        assert_eq!(MAXIMUM_JOB_PAGE_ITEMS, 10_000);
        assert_eq!(MAXIMUM_JOB_ROWS_PER_PAGE, 10_000);
        assert_eq!(MAXIMUM_POSTGRES_QUERY_PARAMETERS, 16);
        assert_eq!(MAXIMUM_ITEM_KEY_BYTES, 512);
        assert_eq!(MAXIMUM_ITEM_REVISION_BYTES, 512);
        assert_eq!(MAXIMUM_NEXT_BYTES, 2048);
        assert_eq!(MAXIMUM_JOB_UPSTREAM_CALLS, 1_000);
        assert_eq!(MAXIMUM_PROJECTION_FIELDS, 64);
        assert_eq!(MAXIMUM_PROJECTION_FIELD_CHARACTERS, 128);
        assert_eq!(MAXIMUM_PROJECTION_SEGMENTS, 8);
        assert_eq!(MAXIMUM_PROJECTION_BYTES, 2_048);
        assert_eq!(MAXIMUM_JOB_TRIGGERS, 16);
        assert_eq!(MINIMUM_TRIGGER_DELAY_MILLISECONDS, 1_000);
        assert_eq!(MAXIMUM_TRIGGER_DELAY_MILLISECONDS, 86_400_000);
        assert_eq!(MAXIMUM_TRIGGER_INITIAL_DELAY_MILLISECONDS, 86_400_000);
        assert_eq!(MAXIMUM_TRIGGER_BACKOFF_THRESHOLD, 100);
        assert_eq!(MINIMUM_TRIGGER_BACKOFF_MULTIPLIER, 1);
        assert_eq!(MAXIMUM_TRIGGER_BACKOFF_MULTIPLIER, 10);
        assert_eq!(DEFAULT_TRIGGER_DELAY_MILLISECONDS, 60_000);
    }
}
