// SPDX-License-Identifier: Apache-2.0

//! The pass, the only unit of work of the governed-ingestion job
//! (`products/adapter/CONCEPT.md` section 17.3): one bounded page read from the saved position,
//! the per-item comparison against the item table, the hand-offs
//! through the destination seam, and the saved position. The seven
//! steps, in order:
//!
//! 1. Take the job's lease; a held lease refuses the pass with the
//!    position untouched.
//! 2. Read one page at the saved position (at the first page when this
//!    pass starts a rescan); a page fault stops with the position unchanged.
//! 3. For each item, project and digest it, stage its row, and hand it
//!    off: a new item or a changed digest delivers, a still-pending item
//!    re-delivers identical bytes, and a settled or refused item skips
//!    unless this pass is a rescan retrying it.
//! 4. An acknowledged hand-off settles the row with the destination's
//!    reference.
//! 5. An item-scoped refusal is recorded with its code and the pass
//!    continues, until too many consecutive refusals with one code stop
//!    the pass with the position unchanged.
//! 6. A deployment-level answer stops the pass with the position
//!    unchanged.
//! 7. A fully settled page saves the page's next cursor, or clears the
//!    position at a finite end. A queue receipt is source-owned and settles
//!    only after its matching durable item outcome.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use deadpool_postgres::Pool;
use registry_adapter_core::{RecordLocator, SourceScan};
use registry_adapter_engine::job::{run_job_page, JobPageFailure, JobProgram};
#[cfg(feature = "job-rabbitmq")]
use registry_platform_config::sha256_uri;
use serde_json::Value;

use crate::destination::{
    DeliverableItem, DeliveryFamily, HandOffOutcome, JobDestination, DESTINATION_ANSWER_INVALID,
    MAXIMUM_ANSWER_BYTES,
};
use crate::projection;
use crate::store::{self, StagedClassification};
use crate::trigger::JobState;

/// How many consecutive item-scoped refusals with one code stop the
/// pass, when the operator names no limit (the stop rule of
/// `products/adapter/CONCEPT.md` section 17.3): a schema or policy change can refuse every item
/// alike, which would otherwise run the position to the end of the
/// source.
pub const DEFAULT_REFUSAL_LIMIT: u32 = 20;

/// The longest stop text the job state row holds, in bytes: the
/// `last_pass_stop` column's own bound.
pub const MAXIMUM_STOP_TEXT_BYTES: usize = 256;

/// AMQP 0-9-1 has no side-effect-free peek, and even requeueing can consume a
/// delivery attempt, so a queue preview refuses before broker acquisition.
pub const RABBITMQ_DRY_RUN_REFUSED: &str = "adapter.job.rabbitmq-dry-run-refused";

/// The broker could not confirm the source-owned acknowledgement or rejection.
pub const RABBITMQ_SETTLEMENT_UNCERTAIN: &str = "adapter.job.rabbitmq-settlement-uncertain";

/// A durable held row deliberately leaves its broker delivery unsettled.
pub const RABBITMQ_HELD: &str = "adapter.job.rabbitmq-held";

/// A publisher reused one immutable message identity for a different raw body
/// or reviewed normalized projection. The new digest is retained as held, but
/// it is never delivered or acknowledged automatically.
pub const RABBITMQ_EVENT_CHANGED: &str = "adapter.job.rabbitmq-event-changed";

/// A pending signed delivery selected a receiver other than the public
/// authority/configuration frozen for the sequence, or predates that fence.
/// The pass stops before any recipient call and leaves the position unchanged.
pub const COORDINATOR_RECEIVER_CHANGED: &str = "adapter.job.coordinator-receiver-changed";

/// A pending signed delivery was staged before the store recorded receiver
/// and body identity (store schema 103), so the host cannot prove a retry
/// reaches the same authority with the same body. The pass stops before any
/// recipient call; the recovery is to settle the item with the binary that
/// staged it.
pub const COORDINATOR_IDENTITY_UNRECORDED: &str = "adapter.job.coordinator-identity-unrecorded";

/// A pending signed delivery would now be built with a different event body
/// (the job version or the projection changed since it was first attempted).
/// The pass stops before any recipient call, because a new body could start a
/// second Run for the same item; restoring the previous definition lets the
/// pending item settle.
pub const COORDINATOR_BODY_CHANGED: &str = "adapter.job.coordinator-body-changed";

/// A pending direct BReg delivery selected a BReg deployment, caller, Action
/// or mode other than the public configuration frozen for the sequence. The
/// pass stops before any BReg call and leaves the position unchanged;
/// restoring the original configuration recovers it.
pub const BREG_RECEIVER_CHANGED: &str = "adapter.job.breg-receiver-changed";

/// A pending direct BReg delivery was staged before the store recorded
/// receiver and body identity (store schema 103), so the host cannot prove a
/// retry reaches the same BReg with the same operation. The pass stops before
/// any BReg call; the recovery is to settle the item with the binary that
/// staged it.
pub const BREG_IDENTITY_UNRECORDED: &str = "adapter.job.breg-identity-unrecorded";

/// A pending direct BReg delivery would now map to a different operation (the
/// mapping, the projection or the job definition changed since it was first
/// attempted). The pass stops before any BReg call, because a new operation
/// could write a second time for the same item; restoring the previous
/// definition lets the pending item settle.
pub const BREG_BODY_CHANGED: &str = "adapter.job.breg-body-changed";

/// The positive durable delivery-attempt counter cannot advance without
/// leaving PostgreSQL's signed bigint domain. The pass stops with its source
/// position unchanged rather than panicking or wrapping the counter.
pub const DELIVERY_ATTEMPT_EXHAUSTED: &str = "adapter.job.delivery-attempt-exhausted";

/// The governed file/SFTP item identity cannot be adopted over non-empty
/// legacy state or changed in place. The operator accepts a change with
/// `adapter-job rebind-identity`.
pub const ITEM_IDENTITY_MIGRATION_REQUIRED: &str = "adapter.job.identity-migration-required";

/// The options one pass runs under.
#[derive(Clone, Debug)]
pub struct PassOptions {
    /// The consecutive item-scoped refusals with one code that stop the
    /// pass with the position unchanged.
    pub refusal_limit: u32,
    /// Start a rescan from the first page when no rescan is active, or
    /// continue the active rescan from its saved position. A rescan
    /// finds edits an ordered position cannot see and is the only pass
    /// that retries refused items. A completed rescan stamps its own
    /// time, which gates the next one through the source's declared
    /// delay. A dry-run rescan always previews the first page because
    /// it cannot replace or advance an active traversal.
    pub rescan: bool,
    /// Read and deliver but write nothing: the operator preview. No
    /// lease is taken, no row is staged, no position is saved, and the
    /// report says what a real pass would have done.
    pub dry_run: bool,
}

impl Default for PassOptions {
    fn default() -> Self {
        Self {
            refusal_limit: DEFAULT_REFUSAL_LIMIT,
            rescan: false,
            dry_run: false,
        }
    }
}

/// Why a pass stopped before its page settled. Every reason is
/// value-free: a closed code or a structural fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// Another pass holds the job's lease; nothing ran.
    LeaseHeld,
    /// The page read failed under its closed code: the page fault's
    /// `adapter.job.page-*` code, the route failure's class, or the
    /// store's own refusal.
    PageFault {
        /// The closed code of the failure.
        code: String,
        /// The source record ordinal when a decoder identified one.
        record: Option<RecordLocator>,
    },
    /// The destination answered for the deployment, not the item.
    DestinationStop {
        /// The destination's own code.
        code: String,
    },
    /// The destination refused this many items in a row with one code.
    RefusalLimit {
        /// The code the consecutive refusals shared.
        code: String,
    },
}

impl StopReason {
    /// The value-free stop text the job state row records. A
    /// destination's code is recorded as itself, so status names what
    /// the destination said and nothing more.
    #[must_use]
    pub fn stop_text(&self) -> String {
        let mut text = match self {
            StopReason::LeaseHeld => "lease-held".to_string(),
            StopReason::PageFault { code, record } => match record {
                Some(RecordLocator {
                    ordinal,
                    column: Some(column),
                }) => format!("page-fault:{code}:record:{ordinal}:column:{column}"),
                Some(record) => format!("page-fault:{code}:record:{}", record.ordinal),
                None => format!("page-fault:{code}"),
            },
            StopReason::DestinationStop { code } => format!("destination-stop:{code}"),
            StopReason::RefusalLimit { code } => format!("refusal-limit:{code}"),
        };
        // A destination's code or a page fault's class has a length the
        // host does not choose: cut it to the state row's bound on a
        // character boundary rather than let the stop go unrecorded.
        if text.len() > MAXIMUM_STOP_TEXT_BYTES {
            let mut end = MAXIMUM_STOP_TEXT_BYTES;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        text
    }
}

/// What one pass did, value-free: counts, refusal codes, and why it
/// stopped, never an item value.
#[derive(Clone, Debug, Default)]
pub struct PassReport {
    /// The items the page carried.
    pub items_read: u32,
    /// Items staged as new: no row existed.
    pub items_new: u32,
    /// Items staged as changed: the digest moved.
    pub items_changed: u32,
    /// Items re-delivered under the same digest: a still-pending row, or
    /// a refused row this rescan retried.
    pub items_redelivered: u32,
    /// Items skipped: settled, or refused outside a rescan.
    pub items_skipped: u32,
    /// Hand-offs the destination acknowledged.
    pub items_acknowledged: u32,
    /// Hand-offs the destination refused, item-scoped.
    pub items_refused: u32,
    /// Hand-offs the destination held for an operator.
    pub items_held: u32,
    /// The item-scoped refusals by the destination's own code.
    pub refusals_by_code: BTreeMap<String, u32>,
    /// Held items by the destination's value-free reason code.
    pub holds_by_code: BTreeMap<String, u32>,
    /// Malformed input lines the page's decoders skipped, value-free.
    pub malformed_lines: u32,
    /// Why the pass stopped before the page settled, when it did.
    pub stopped: Option<StopReason>,
    /// Why the stop could not be recorded in the job state row, when it
    /// could not: the row then still shows the previous pass, and the
    /// lease frees only at its expiry.
    pub stop_record_failure: Option<String>,
    /// Whether the job's interval schedule had already slipped when the
    /// pass ended: true means the due time had passed, most tellingly on
    /// a lease the pass could not take.
    pub overdue: bool,
}

/// The state the pass reads once, under the lease or the dry-run's
/// read-only glance. The token fences every write a leased pass makes.
struct PassState {
    position: Option<Value>,
    rescan_active: bool,
    token: Option<i64>,
}

/// Run one bounded pass of the job against the item store and the
/// destination. See the module documentation for the seven steps.
///
/// The lease's time to live covers the page deadline the compiled
/// profile enforces, plus the margin an operator needs to see a stalled
/// pass in status before the lease frees; a pass that crashes leaves
/// the lease to expire, and the next pass starts no earlier.
pub async fn run_pass(
    db: &Pool,
    program: &JobProgram,
    destination: &dyn JobDestination,
    options: PassOptions,
) -> PassReport {
    let job = &program.job;
    let job_id = job.job.id.as_str();
    let mut report = PassReport::default();
    if options.dry_run && program.has_rabbitmq_source() {
        report.stopped = Some(StopReason::PageFault {
            code: RABBITMQ_DRY_RUN_REFUSED.to_owned(),
            record: None,
        });
        return report;
    }
    let mut client = match db.get().await {
        Ok(client) => client,
        Err(error) => {
            report.stopped = Some(store_refused_cause(&store::pool_cause(&error)));
            return report;
        }
    };
    // The dry run writes nothing: it reads the state to report what a
    // real pass would do from it, and skips the lease.
    let state = if options.dry_run {
        read_pass_state(&mut client, job_id, program, &mut report).await
    } else {
        take_pass_state(&mut client, job_id, program, &mut report).await
    };
    let Some(state) = state else {
        return report;
    };
    // The dry run writes nothing, so it carries no token; every fenced
    // write below runs only in a leased pass.
    let lease_token = state.token.unwrap_or(0);
    if options.dry_run {
        // The preview applies the fence read-only, so it never looks clean
        // over a state the next real pass refuses.
        let identity = program.item_identity_digest();
        if let Err(error) = store::check_item_identity(&client, job_id, identity.as_ref()).await {
            let reason = identity_stop_reason(&error);
            return finish_stopped(db, job_id, &options, lease_token, report, reason).await;
        }
    } else {
        let identity = program.item_identity_digest();
        if let Err(error) = store::bind_item_identity(
            &mut client,
            job_id,
            identity.as_ref(),
            lease_token,
            lease_ttl(program),
        )
        .await
        {
            let reason = identity_stop_reason(&error);
            return finish_stopped(db, job_id, &options, lease_token, report, reason).await;
        }
    }
    // A traversal the last pass left between pages keeps its rescan
    // mode and saved cursor. Only a newly requested rescan starts from
    // the first page; every real pass that continues it still retries
    // refused rows. An explicit dry-run rescan previews the first page
    // without replacing the active traversal.
    let starts_rescan = options.rescan && (!state.rescan_active || options.dry_run);
    let options = PassOptions {
        rescan: options.rescan || state.rescan_active,
        ..options
    };
    // Step 2: read one page, at the saved position, or at the first page
    // when this pass starts a rescan.
    let cursor = if starts_rescan {
        None
    } else {
        state.position.clone()
    };
    let page_result = match run_job_page(program, cursor).await {
        Ok(result) => {
            report.malformed_lines = result.malformed_lines;
            result
        }
        Err(failure) => {
            return finish_stopped(
                db,
                job_id,
                &options,
                lease_token,
                report,
                page_failure_reason(&failure),
            )
            .await;
        }
    };
    #[cfg(feature = "job-rabbitmq")]
    let source_receipt = page_result.source_receipt;
    let page = page_result.page;
    report.items_read = page.items.len() as u32;
    // Steps 3 to 6: per item, compare, stage, deliver, record.
    let mut consecutive = ConsecutiveRefusals::new(options.refusal_limit);
    for item in &page.items {
        #[cfg(feature = "job-rabbitmq")]
        let digest = {
            let projected_digest = projection::item_digest(&job.projection, &item.value);
            source_receipt
                .as_ref()
                .map_or(projected_digest.clone(), |receipt| {
                    rabbitmq_item_digest(receipt.expected_revision(), &projected_digest)
                })
        };
        #[cfg(not(feature = "job-rabbitmq"))]
        let digest = projection::item_digest(&job.projection, &item.value);
        let staged_at = SystemTime::now();
        let staged = if options.dry_run {
            store::peek_item(
                &client,
                job_id,
                &item.key,
                &digest,
                options.rescan,
                staged_at,
            )
            .await
        } else {
            store::stage_item(
                &mut client,
                job_id,
                &item.key,
                &digest,
                options.rescan,
                staged_at,
                lease_token,
                lease_ttl(program),
            )
            .await
        };
        let staged = match staged {
            Ok(staged) => staged,
            Err(store::StoreError::DeliveryAttemptExhausted) => {
                return finish_stopped(
                    db,
                    job_id,
                    &options,
                    lease_token,
                    report,
                    StopReason::DestinationStop {
                        code: DELIVERY_ATTEMPT_EXHAUSTED.to_owned(),
                    },
                )
                .await;
            }
            Err(error) => {
                return finish_stopped(
                    db,
                    job_id,
                    &options,
                    lease_token,
                    report,
                    store_refused_reason(&error),
                )
                .await;
            }
        };
        let Some(staged) = staged else {
            report.items_skipped += 1;
            #[cfg(feature = "job-rabbitmq")]
            if let Some(receipt) = source_receipt.as_ref() {
                let stored = match store::inspect_item(&client, job_id, &item.key).await {
                    Ok(Some(stored)) if stored.last_digest == digest => stored,
                    Ok(_) => {
                        return finish_stopped(
                            db,
                            job_id,
                            &options,
                            lease_token,
                            report,
                            rabbitmq_settlement_reason(),
                        )
                        .await;
                    }
                    Err(error) => {
                        return finish_stopped(
                            db,
                            job_id,
                            &options,
                            lease_token,
                            report,
                            store_refused_reason(&error),
                        )
                        .await;
                    }
                };
                let settled = match stored.status {
                    store::ItemStatus::Acknowledged => receipt.accept().await,
                    store::ItemStatus::Refused => receipt.refuse().await,
                    store::ItemStatus::Held => {
                        return finish_stopped(
                            db,
                            job_id,
                            &options,
                            lease_token,
                            report,
                            StopReason::PageFault {
                                code: RABBITMQ_HELD.to_owned(),
                                record: None,
                            },
                        )
                        .await;
                    }
                    store::ItemStatus::Pending => {
                        return finish_stopped(
                            db,
                            job_id,
                            &options,
                            lease_token,
                            report,
                            rabbitmq_settlement_reason(),
                        )
                        .await;
                    }
                };
                if settled.is_err() {
                    return finish_stopped(
                        db,
                        job_id,
                        &options,
                        lease_token,
                        report,
                        rabbitmq_settlement_reason(),
                    )
                    .await;
                }
            }
            continue;
        };
        match staged.classification {
            StagedClassification::New => report.items_new += 1,
            StagedClassification::Changed => report.items_changed += 1,
            StagedClassification::Redelivered => report.items_redelivered += 1,
        }
        #[cfg(feature = "job-rabbitmq")]
        if source_receipt.is_some() && staged.classification == StagedClassification::Changed {
            if let Err(error) = store::record_held(
                &mut client,
                job_id,
                &staged.key,
                RABBITMQ_EVENT_CHANGED,
                None,
                SystemTime::now(),
                lease_token,
                lease_ttl(program),
            )
            .await
            {
                return finish_stopped(
                    db,
                    job_id,
                    &options,
                    lease_token,
                    report,
                    store_refused_reason(&error),
                )
                .await;
            }
            report.items_held += 1;
            *report
                .holds_by_code
                .entry(RABBITMQ_EVENT_CHANGED.to_owned())
                .or_insert(0) += 1;
            return finish_stopped(
                db,
                job_id,
                &options,
                lease_token,
                report,
                StopReason::PageFault {
                    code: RABBITMQ_HELD.to_owned(),
                    record: None,
                },
            )
            .await;
        }
        let deliverable = DeliverableItem {
            key: staged.key.clone(),
            sequence: staged.sequence,
            digest: staged.digest.clone(),
            prior_run_id: staged.prior_run_id.clone(),
            admitted_before: staged.admitted_before,
            first_seen: staged.first_seen,
            event_time: staged.event_time,
            delivery_attempt: staged.delivery_attempt,
            projected: projection::project(&job.projection, &item.value),
        };
        if !options.dry_run {
            if let Some(identity) = destination.delivery_identity(&job.job, &deliverable) {
                let body_identity = match identity.canonical_body {
                    Ok(body_identity) => Some(body_identity),
                    Err(()) if staged.receipt_uncertain => {
                        let code = match identity.family {
                            DeliveryFamily::Coordinator => COORDINATOR_RECEIVER_CHANGED,
                            DeliveryFamily::Breg => BREG_BODY_CHANGED,
                        };
                        return finish_stopped(
                            db,
                            job_id,
                            &options,
                            lease_token,
                            report,
                            StopReason::DestinationStop {
                                code: code.to_owned(),
                            },
                        )
                        .await;
                    }
                    Err(()) => None,
                };
                if let Some(body_identity) = body_identity {
                    let allow_rebind = staged.classification == StagedClassification::Redelivered
                        && !staged.receipt_uncertain;
                    if let Err(error) = store::bind_delivery_identity(
                        &mut client,
                        job_id,
                        &staged.key,
                        &identity.receiver,
                        &body_identity,
                        staged.delivery_attempt,
                        allow_rebind,
                        lease_token,
                        lease_ttl(program),
                    )
                    .await
                    {
                        let reason = delivery_identity_stop_reason(identity.family, &error);
                        return finish_stopped(db, job_id, &options, lease_token, report, reason)
                            .await;
                    }
                }
            }
        }
        let outcome = if direct_receipt_expired(&job.destination, &staged, staged_at) {
            HandOffOutcome::Held {
                code: "adapter.job.breg-receipt-horizon".to_string(),
                run_id: None,
            }
        } else {
            destination.deliver(&job.job, &deliverable).await
        };
        if !answer_fits(&outcome) {
            // An answer the item table cannot hold is the destination's
            // fault, not the item's: the row stays pending and the pass
            // stops with the position unchanged.
            return finish_stopped(
                db,
                job_id,
                &options,
                lease_token,
                report,
                StopReason::DestinationStop {
                    code: DESTINATION_ANSWER_INVALID.to_string(),
                },
            )
            .await;
        }
        match outcome {
            HandOffOutcome::Acknowledged { run_id } => {
                report.items_acknowledged += 1;
                consecutive.reset();
                if !options.dry_run {
                    if let Err(error) = store::record_acknowledged(
                        &mut client,
                        job_id,
                        &staged.key,
                        run_id.as_deref(),
                        SystemTime::now(),
                        lease_token,
                        lease_ttl(program),
                    )
                    .await
                    {
                        return finish_stopped(
                            db,
                            job_id,
                            &options,
                            lease_token,
                            report,
                            store_refused_reason(&error),
                        )
                        .await;
                    }
                }
                #[cfg(feature = "job-rabbitmq")]
                if let Some(receipt) = source_receipt.as_ref() {
                    if receipt.accept().await.is_err() {
                        return finish_stopped(
                            db,
                            job_id,
                            &options,
                            lease_token,
                            report,
                            rabbitmq_settlement_reason(),
                        )
                        .await;
                    }
                }
            }
            HandOffOutcome::Refused { code } => {
                report.items_refused += 1;
                *report.refusals_by_code.entry(code.clone()).or_insert(0) += 1;
                // The row records its refusal before the limit is
                // evaluated: a pass that stops at the limit still leaves
                // the refused row its code, and only a rescan retries it.
                if !options.dry_run {
                    if let Err(error) = store::record_refused(
                        &mut client,
                        job_id,
                        &staged.key,
                        &code,
                        SystemTime::now(),
                        lease_token,
                        lease_ttl(program),
                    )
                    .await
                    {
                        return finish_stopped(
                            db,
                            job_id,
                            &options,
                            lease_token,
                            report,
                            store_refused_reason(&error),
                        )
                        .await;
                    }
                }
                #[cfg(feature = "job-rabbitmq")]
                if let Some(receipt) = source_receipt.as_ref() {
                    if receipt.refuse().await.is_err() {
                        return finish_stopped(
                            db,
                            job_id,
                            &options,
                            lease_token,
                            report,
                            rabbitmq_settlement_reason(),
                        )
                        .await;
                    }
                }
                if let Some(limit_code) = consecutive.refused(code.clone()) {
                    return finish_stopped(
                        db,
                        job_id,
                        &options,
                        lease_token,
                        report,
                        StopReason::RefusalLimit { code: limit_code },
                    )
                    .await;
                }
            }
            HandOffOutcome::Held { code, run_id } => {
                report.items_held += 1;
                *report.holds_by_code.entry(code.clone()).or_insert(0) += 1;
                consecutive.reset();
                if !options.dry_run {
                    if let Err(error) = store::record_held(
                        &mut client,
                        job_id,
                        &staged.key,
                        &code,
                        run_id.as_deref(),
                        SystemTime::now(),
                        lease_token,
                        lease_ttl(program),
                    )
                    .await
                    {
                        return finish_stopped(
                            db,
                            job_id,
                            &options,
                            lease_token,
                            report,
                            store_refused_reason(&error),
                        )
                        .await;
                    }
                }
                #[cfg(feature = "job-rabbitmq")]
                if source_receipt.is_some() {
                    return finish_stopped(
                        db,
                        job_id,
                        &options,
                        lease_token,
                        report,
                        StopReason::PageFault {
                            code: RABBITMQ_HELD.to_owned(),
                            record: None,
                        },
                    )
                    .await;
                }
            }
            HandOffOutcome::StopPass { code } => {
                return finish_stopped(
                    db,
                    job_id,
                    &options,
                    lease_token,
                    report,
                    StopReason::DestinationStop { code },
                )
                .await;
            }
        }
    }
    // Step 7: the page settled. Save the position, stamp the schedule,
    // release the lease. A page without a cursor is the finite end: the
    // position clears (the page reader reads a JSON null cursor as
    // absent). An ongoing scan holds its place at the tail with a cursor
    // even on an empty page, so its rescan ends at the first empty page,
    // where it has caught up.
    let next = page.next.as_ref();
    let ongoing = program.source_route.scan == Some(SourceScan::Ongoing);
    let traversal_ended = next.is_none() || (ongoing && report.items_read == 0);
    let rescan = match (options.rescan, traversal_ended) {
        (false, _) => store::RescanProgress::None,
        (true, false) => store::RescanProgress::Continues,
        (true, true) => store::RescanProgress::Ended,
    };
    if !options.dry_run {
        if let Err(error) = store::complete_pass(
            &client,
            job_id,
            lease_token,
            next,
            report.items_read == 0,
            rescan,
            SystemTime::now(),
        )
        .await
        {
            return finish_stopped(
                db,
                job_id,
                &options,
                lease_token,
                report,
                store_refused_reason(&error),
            )
            .await;
        }
    }
    report
}

#[cfg(feature = "job-rabbitmq")]
fn rabbitmq_settlement_reason() -> StopReason {
    StopReason::PageFault {
        code: RABBITMQ_SETTLEMENT_UNCERTAIN.to_owned(),
        record: None,
    }
}

/// The queue item's stored digest covers both immutable broker bytes and the
/// declared projection after reviewed route normalization. Domain separation
/// prevents this combination from colliding with ordinary projection digests;
/// no payload or projection bytes enter the store.
#[cfg(feature = "job-rabbitmq")]
fn rabbitmq_item_digest(source_revision: &str, projected_digest: &str) -> String {
    let material =
        format!("registry-adapter:rabbitmq-item-digest:v1\0{source_revision}\0{projected_digest}");
    sha256_uri(material.as_bytes())
}

fn direct_receipt_expired(
    destination: &registry_adapter_core::JobDestination,
    staged: &store::StagedItem,
    now: SystemTime,
) -> bool {
    let registry_adapter_core::JobDestination::DirectBreg {
        receipt_retention_days,
        ..
    } = destination
    else {
        return false;
    };
    staged.receipt_uncertain
        && now.duration_since(staged.event_time).is_ok_and(|age| {
            age >= Duration::from_secs(u64::from(*receipt_retention_days) * 86_400)
        })
}

/// The stopped-pass ending: record the stop with the position untouched
/// and return the report. The dry run records nothing, because it
/// writes nothing.
async fn finish_stopped(
    db: &Pool,
    job_id: &str,
    options: &PassOptions,
    token: i64,
    mut report: PassReport,
    reason: StopReason,
) -> PassReport {
    if !options.dry_run {
        let recorded = match db.get().await {
            Ok(client) => store::stop_pass(
                &client,
                job_id,
                token,
                &reason.stop_text(),
                SystemTime::now(),
            )
            .await
            .map_err(|error| error.to_string()),
            Err(error) => Err(format!("the job store refused a connection: {error}")),
        };
        report.stop_record_failure = recorded.err();
    }
    report.stopped = Some(reason);
    report
}

/// Whether the destination's answer fits the item table: every code and
/// reference is non-empty and within [`MAXIMUM_ANSWER_BYTES`].
fn answer_fits(outcome: &HandOffOutcome) -> bool {
    let fits = |text: &str| !text.is_empty() && text.len() <= MAXIMUM_ANSWER_BYTES;
    match outcome {
        HandOffOutcome::Acknowledged { run_id } => run_id.as_deref().is_none_or(fits),
        HandOffOutcome::Held { code, run_id } => fits(code) && run_id.as_deref().is_none_or(fits),
        HandOffOutcome::Refused { code } | HandOffOutcome::StopPass { code } => fits(code),
    }
}

/// The stop reason for a failed item-identity fence.
/// The closed code of a pass the job store refused. The stop text adds one
/// value-free `cause:<token>` qualifier: the store condition, or the
/// PostgreSQL SQLSTATE of a refused query (`sqlstate-42501`).
pub const STORE_REFUSED: &str = "adapter.job.store-refused";

/// The stop for a refused delivery identity fence: a changed receiver, a
/// changed body, or a legacy row whose identity was never recorded each stop
/// under their own closed code, named for the destination the operator
/// configured; anything else is a store refusal.
fn delivery_identity_stop_reason(family: DeliveryFamily, error: &store::StoreError) -> StopReason {
    let (receiver_changed, unrecorded, body_changed) = match family {
        DeliveryFamily::Coordinator => (
            COORDINATOR_RECEIVER_CHANGED,
            COORDINATOR_IDENTITY_UNRECORDED,
            COORDINATOR_BODY_CHANGED,
        ),
        DeliveryFamily::Breg => (
            BREG_RECEIVER_CHANGED,
            BREG_IDENTITY_UNRECORDED,
            BREG_BODY_CHANGED,
        ),
    };
    let code = match error {
        store::StoreError::ReceiverIdentityChanged => receiver_changed,
        store::StoreError::ReceiverIdentityUnknown
        | store::StoreError::CanonicalBodyIdentityUnknown => unrecorded,
        store::StoreError::CanonicalBodyIdentityChanged => body_changed,
        error => return store_refused_reason(error),
    };
    StopReason::DestinationStop {
        code: code.to_owned(),
    }
}

fn identity_stop_reason(error: &store::StoreError) -> StopReason {
    match error {
        store::StoreError::ItemIdentityMigrationRequired => StopReason::PageFault {
            code: ITEM_IDENTITY_MIGRATION_REQUIRED.to_owned(),
            record: None,
        },
        error => store_refused_reason(error),
    }
}

/// The stop reason for a store refusal: [`STORE_REFUSED`] with the
/// store's closed cause token, value-free.
fn store_refused_reason(error: &store::StoreError) -> StopReason {
    store_refused_cause(&error.cause())
}

fn store_refused_cause(cause: &str) -> StopReason {
    StopReason::PageFault {
        code: format!("{STORE_REFUSED}:cause:{cause}"),
        record: None,
    }
}

/// A pass that could not reach its own state row: the report carries
/// the failure and nothing ran.
fn store_refused(mut report: PassReport, error: &store::StoreError) -> PassReport {
    report.stopped = Some(store_refused_reason(error));
    report
}

/// Read the state the pass runs from, without taking the lease, and
/// stamp the report's overdue flag from it. `None` means the report
/// already carries its ending.
async fn read_pass_state(
    client: &mut deadpool_postgres::Object,
    job_id: &str,
    program: &JobProgram,
    report: &mut PassReport,
) -> Option<PassState> {
    let row = match store::read_state(client, job_id).await {
        Ok(row) => row,
        Err(error) => {
            *report = store_refused(std::mem::take(report), &error);
            return None;
        }
    };
    let row = row.unwrap_or_default();
    report.overdue = overdue(&row, program);
    Some(PassState {
        position: row.position,
        rescan_active: row.rescan_active,
        token: None,
    })
}

/// Take the lease and read the state under it: the pass's step 1. The
/// grant itself returns the position and rescan marker, read in the
/// statement that wrote the lease, so a competing pass that finishes
/// first can never leave this pass a stale cursor. `None` means the
/// report already carries its ending, a held lease or a refused store.
async fn take_pass_state(
    client: &mut deadpool_postgres::Object,
    job_id: &str,
    program: &JobProgram,
    report: &mut PassReport,
) -> Option<PassState> {
    if let Err(error) = store::ensure_state(client, job_id).await {
        *report = store_refused(std::mem::take(report), &error);
        return None;
    }
    // The overdue flag reads the state as this pass found it: on a held
    // lease, where no pass ran at all, it is the number that matters.
    let before = match store::read_state(client, job_id).await {
        Ok(row) => row.unwrap_or_default(),
        Err(error) => {
            *report = store_refused(std::mem::take(report), &error);
            return None;
        }
    };
    report.overdue = overdue(&before, program);
    let leased = match store::take_lease(client, job_id, lease_ttl(program)).await {
        Ok(leased) => leased,
        Err(error) => {
            *report = store_refused(std::mem::take(report), &error);
            return None;
        }
    };
    let Some(leased) = leased else {
        report.stopped = Some(StopReason::LeaseHeld);
        return None;
    };
    // The state row's projection digest follows the job's current one, so
    // status can show a projection edit; the items re-flag through their
    // own digests, which a new projection changes.
    if before.projection_digest.as_deref() != Some(program.job.projection_digest().as_str()) {
        if let Err(error) =
            store::sync_projection_digest(client, job_id, &program.job.projection_digest()).await
        {
            *report = store_refused(std::mem::take(report), &error);
            return None;
        }
    }
    Some(PassState {
        position: leased.position,
        rescan_active: leased.rescan_active,
        token: Some(leased.token),
    })
}

/// The lease's time to live: the profile's page deadline plus the
/// margin an operator needs to see a stalled pass before the lease
/// frees.
fn lease_ttl(program: &JobProgram) -> Duration {
    Duration::from_millis(program.profile().page_deadline_milliseconds.get())
        + Duration::from_secs(store::LEASE_MARGIN_SECONDS)
}

/// The closed reason of a failed page read: the page fault's own code,
/// or the route failure's class.
fn page_failure_reason(failure: &JobPageFailure) -> StopReason {
    if let Some(code) = failure.code {
        return StopReason::PageFault {
            code: code.to_string(),
            record: failure.record,
        };
    }
    StopReason::PageFault {
        code: failure
            .class
            .map(|class| class.class().to_owned())
            .unwrap_or_else(|| "adapter.job.page-failure".to_string()),
        record: failure.record,
    }
}

/// The consecutive-same-code refusal counter of one pass. Refusals with
/// the same code stack toward the limit; a different code restarts the
/// count at one, because the stop rule targets one refusal cause running
/// through every item alike; and any acknowledgement clears it.
struct ConsecutiveRefusals {
    limit: u32,
    code: Option<String>,
    count: u32,
}

impl ConsecutiveRefusals {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            code: None,
            count: 0,
        }
    }

    fn reset(&mut self) {
        self.code = None;
        self.count = 0;
    }

    /// Count one refusal with its code; `Some` when the count reached
    /// the limit, carrying the code the pass stops on.
    fn refused(&mut self, code: String) -> Option<String> {
        if self.code.as_deref() == Some(code.as_str()) {
            self.count += 1;
        } else {
            self.code = Some(code.clone());
            self.count = 1;
        }
        if self.count >= self.limit {
            self.code.clone()
        } else {
            None
        }
    }
}

/// Whether the job's interval schedule had already slipped when the pass
/// started: the trigger's due time, read against the state as found, has
/// passed. A settled or stopped pass stamps the clock it ended on, so
/// this answers true mostly where the pass could not run at all, the
/// held lease above.
fn overdue(row: &store::JobStateRow, program: &JobProgram) -> bool {
    let view = JobState {
        position: None,
        projection_digest: None,
        lease_expires: None,
        last_pass_at: row.last_pass_at,
        last_pass_stop: None,
        last_rescan_at: row.last_rescan_at,
        rescan_active: false,
        idle_streak: u32::try_from(row.idle_streak.max(0)).unwrap_or(u32::MAX),
        error_streak: u32::try_from(row.error_streak.max(0)).unwrap_or(u32::MAX),
    };
    // A never-run job anchors its initial delay to this pass's own
    // start, so the schedule reads as not yet due rather than overdue.
    let now = SystemTime::now();
    crate::trigger::next_due(&program.job, &view, now, now).is_some_and(|due| due == Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stop_texts_name_the_reason_and_nothing_from_the_items() {
        assert_eq!(StopReason::LeaseHeld.stop_text(), "lease-held");
        assert_eq!(
            StopReason::PageFault {
                code: "adapter.job.page-key".to_string(),
                record: None,
            }
            .stop_text(),
            "page-fault:adapter.job.page-key"
        );
        assert_eq!(
            StopReason::PageFault {
                code: "adapter.job.file-row".to_string(),
                record: Some(RecordLocator {
                    ordinal: 7,
                    column: None,
                }),
            }
            .stop_text(),
            "page-fault:adapter.job.file-row:record:7"
        );
        assert_eq!(
            StopReason::PageFault {
                code: "adapter.job.postgres-column-type".to_string(),
                record: Some(RecordLocator {
                    ordinal: 0,
                    column: Some(3),
                }),
            }
            .stop_text(),
            "page-fault:adapter.job.postgres-column-type:record:0:column:3"
        );
        assert_eq!(
            StopReason::DestinationStop {
                code: "auth.rejected".to_string()
            }
            .stop_text(),
            "destination-stop:auth.rejected"
        );
        assert_eq!(
            StopReason::RefusalLimit {
                code: "schema.required".to_string()
            }
            .stop_text(),
            "refusal-limit:schema.required"
        );
    }

    #[test]
    fn page_failure_preserves_the_typed_record_locator() {
        let reason = page_failure_reason(&JobPageFailure {
            class: None,
            code: Some("adapter.job.file-key-invalid"),
            record: Some(RecordLocator {
                ordinal: 12,
                column: None,
            }),
        });
        assert_eq!(
            reason,
            StopReason::PageFault {
                code: "adapter.job.file-key-invalid".to_string(),
                record: Some(RecordLocator {
                    ordinal: 12,
                    column: None,
                }),
            }
        );
    }

    #[test]
    fn an_unrecorded_delivery_identity_stops_under_its_own_code() {
        let stop = |code: &str| StopReason::DestinationStop {
            code: code.to_owned(),
        };
        let family = DeliveryFamily::Coordinator;
        for unrecorded in [
            store::StoreError::ReceiverIdentityUnknown,
            store::StoreError::CanonicalBodyIdentityUnknown,
        ] {
            assert_eq!(
                delivery_identity_stop_reason(family, &unrecorded),
                stop(COORDINATOR_IDENTITY_UNRECORDED),
                "a legacy row is not a changed receiver: {unrecorded}"
            );
        }
        assert_eq!(
            delivery_identity_stop_reason(family, &store::StoreError::ReceiverIdentityChanged),
            stop(COORDINATOR_RECEIVER_CHANGED)
        );
        assert_eq!(
            delivery_identity_stop_reason(family, &store::StoreError::CanonicalBodyIdentityChanged),
            stop(COORDINATOR_BODY_CHANGED)
        );
    }

    #[test]
    fn a_refused_breg_fence_stops_under_breg_codes() {
        let stop = |code: &str| StopReason::DestinationStop {
            code: code.to_owned(),
        };
        let family = DeliveryFamily::Breg;
        for unrecorded in [
            store::StoreError::ReceiverIdentityUnknown,
            store::StoreError::CanonicalBodyIdentityUnknown,
        ] {
            assert_eq!(
                delivery_identity_stop_reason(family, &unrecorded),
                stop(BREG_IDENTITY_UNRECORDED),
                "{unrecorded}"
            );
        }
        assert_eq!(
            delivery_identity_stop_reason(family, &store::StoreError::ReceiverIdentityChanged),
            stop(BREG_RECEIVER_CHANGED)
        );
        assert_eq!(
            delivery_identity_stop_reason(family, &store::StoreError::CanonicalBodyIdentityChanged),
            stop(BREG_BODY_CHANGED)
        );
        assert_eq!(BREG_RECEIVER_CHANGED, "adapter.job.breg-receiver-changed");
        assert_eq!(
            BREG_IDENTITY_UNRECORDED,
            "adapter.job.breg-identity-unrecorded"
        );
        assert_eq!(BREG_BODY_CHANGED, "adapter.job.breg-body-changed");
    }

    #[test]
    fn a_store_refusal_carries_the_closed_code_and_a_value_free_cause() {
        for (error, cause) in [
            (store::StoreError::LeaseLost, "lease-lost"),
            (store::StoreError::MigrationLock, "migration-lock"),
            (
                store::StoreError::Pool("connection refused at db.internal:5432".to_string()),
                "pool",
            ),
            (
                store::StoreError::PositionBound {
                    bytes: 9000,
                    maximum: 4096,
                },
                "position-bound",
            ),
        ] {
            assert_eq!(
                store_refused_reason(&error).stop_text(),
                format!("page-fault:{STORE_REFUSED}:cause:{cause}"),
                "{error}"
            );
        }
        assert_eq!(STORE_REFUSED, "adapter.job.store-refused");
    }

    #[test]
    fn a_stop_text_stays_within_the_state_row_bound_on_a_char_boundary() {
        let long = StopReason::PageFault {
            code: format!("adapter.job.page-fault:{}", "\u{e9}".repeat(300)),
            record: None,
        };
        let text = long.stop_text();
        assert!(text.len() <= MAXIMUM_STOP_TEXT_BYTES, "{}", text.len());
        assert!(text.starts_with("page-fault:adapter.job.page-fault:"));
        assert!(
            text.len() > MAXIMUM_STOP_TEXT_BYTES - 2,
            "only a split char is dropped"
        );
    }

    #[test]
    fn the_refusal_limit_stops_on_one_code_run_and_a_new_code_restarts_it() {
        let mut consecutive = ConsecutiveRefusals::new(3);
        assert_eq!(consecutive.refused("a".to_string()), None);
        assert_eq!(consecutive.refused("a".to_string()), None);
        // A different code restarts the count: the stop rule is one code
        // running through the items.
        assert_eq!(consecutive.refused("b".to_string()), None);
        assert_eq!(consecutive.refused("b".to_string()), None);
        assert_eq!(consecutive.refused("b".to_string()), Some("b".to_string()));
    }

    #[test]
    fn an_acknowledgement_clears_the_refusal_run() {
        let mut consecutive = ConsecutiveRefusals::new(2);
        assert_eq!(consecutive.refused("a".to_string()), None);
        consecutive.reset();
        assert_eq!(consecutive.refused("a".to_string()), None);
        assert_eq!(consecutive.refused("a".to_string()), Some("a".to_string()));
    }

    #[test]
    fn a_limit_of_one_stops_at_the_first_refusal() {
        let mut consecutive = ConsecutiveRefusals::new(1);
        assert_eq!(consecutive.refused("a".to_string()), Some("a".to_string()));
    }

    #[test]
    fn only_an_uncertain_pending_retry_past_the_direct_receipt_horizon_expires() {
        let destination = serde_json::from_value(serde_json::json!({
            "type": "direct-breg",
            "binding": "breg-main",
            "accessProfile": "writer",
            "action": "register-household",
            "mode": "proposal",
            "mapping": {"file": "map.rhai", "entrypoint": "map_item", "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
            "receiptRetentionDays": 7
        }))
        .expect("a direct destination");
        let first_seen = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut staged = store::StagedItem {
            key: "submission/a".to_string(),
            sequence: 1,
            digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            prior_run_id: None,
            admitted_before: false,
            first_seen,
            event_time: first_seen,
            delivery_attempt: 2,
            receipt_uncertain: true,
            classification: StagedClassification::Redelivered,
        };
        assert!(!direct_receipt_expired(
            &destination,
            &staged,
            first_seen + Duration::from_secs(7 * 86_400 - 1)
        ));
        assert!(direct_receipt_expired(
            &destination,
            &staged,
            first_seen + Duration::from_secs(7 * 86_400)
        ));
        // BReg's receipt belongs to the sequence's command key, so a
        // revision staged long after the first sighting counts from its own
        // event time.
        let revised = first_seen + Duration::from_secs(9 * 86_400);
        staged.sequence = 2;
        staged.event_time = revised;
        assert!(!direct_receipt_expired(
            &destination,
            &staged,
            revised + Duration::from_secs(7 * 86_400 - 1)
        ));
        assert!(direct_receipt_expired(
            &destination,
            &staged,
            revised + Duration::from_secs(7 * 86_400)
        ));
        staged.receipt_uncertain = false;
        assert!(!direct_receipt_expired(
            &destination,
            &staged,
            revised + Duration::from_secs(8 * 86_400)
        ));
    }
}
