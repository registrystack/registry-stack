// SPDX-License-Identifier: Apache-2.0

//! The pass, the only unit of work of the governed-ingestion job
//! (`products/adapter/CONCEPT.md` section 17.3 and the governed-ingestion
//! concept section 3): one bounded page read from the saved position,
//! the per-item comparison against the item table, the hand-offs
//! through the destination seam, and the saved position. The seven
//! steps, in order:
//!
//! 1. Take the job's lease; a held lease refuses the pass with the
//!    position untouched.
//! 2. Read one page at the saved position (at the first page when this
//!    pass is a rescan); a page fault stops with the position unchanged.
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
//!    position at a finite end, and calls the destination's settle
//!    contract.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use deadpool_postgres::Pool;
use registry_adapter::engine::job::{run_job_page, JobPageFailure, JobProgram};
use serde_json::Value;

use crate::destination::{DeliverableItem, HandOffOutcome, JobDestination, SettledPage};
use crate::projection;
use crate::store::{self, StagedClassification};
use crate::trigger::JobState;

/// How many consecutive item-scoped refusals with one code stop the
/// pass, when the operator names no limit. The governed-ingestion
/// concept's stop rule: a schema or policy change can refuse every item
/// alike, which would otherwise run the position to the end of the
/// source.
pub const DEFAULT_REFUSAL_LIMIT: u32 = 20;

/// The options one pass runs under.
#[derive(Clone, Debug)]
pub struct PassOptions {
    /// The consecutive item-scoped refusals with one code that stop the
    /// pass with the position unchanged.
    pub refusal_limit: u32,
    /// Run this pass from the first page regardless of the saved
    /// position: the rescan that finds edits an ordered position cannot
    /// see, and the only pass that retries refused items. A completed
    /// rescan stamps its own time, which gates the next one through the
    /// source's declared delay.
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
        match self {
            StopReason::LeaseHeld => "lease-held".to_string(),
            StopReason::PageFault { code } => format!("page-fault:{code}"),
            StopReason::DestinationStop { code } => format!("destination-stop:{code}"),
            StopReason::RefusalLimit { code } => format!("refusal-limit:{code}"),
        }
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
    /// The item-scoped refusals by the destination's own code.
    pub refusals_by_code: BTreeMap<String, u32>,
    /// Malformed input lines the page's decoders skipped, value-free.
    pub malformed_lines: u32,
    /// Why the pass stopped before the page settled, when it did.
    pub stopped: Option<StopReason>,
    /// Whether the job's interval schedule had already slipped when the
    /// pass ended: true means the due time had passed, most tellingly on
    /// a lease the pass could not take.
    pub overdue: bool,
}

/// The state the pass reads once, under the lease or the dry-run's
/// read-only glance. The token fences every write a leased pass makes.
struct PassState {
    position: Option<Value>,
    #[allow(dead_code)]
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
    let mut client = match db.get().await {
        Ok(client) => client,
        Err(error) => return store_refused(report, &error.to_string()),
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
    // A traversal the last pass left between pages keeps its rescan
    // mode: the pass the operator named a rescan and the passes that
    // finish it retry refused rows alike.
    let options = PassOptions {
        rescan: options.rescan || state.rescan_active,
        ..options
    };
    // Step 2: read one page, at the saved position, or at the first page
    // when this pass is a rescan.
    let cursor = if options.rescan {
        None
    } else {
        state.position.clone()
    };
    let page = match run_job_page(program, cursor).await {
        Ok(result) => {
            report.malformed_lines = result.malformed_lines;
            result.page
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
    report.items_read = page.items.len() as u32;
    // Steps 3 to 6: per item, compare, stage, deliver, record.
    let mut consecutive = ConsecutiveRefusals::new(options.refusal_limit);
    for item in &page.items {
        let digest = projection::item_digest(&job.projection, &item.value);
        let staged = if options.dry_run {
            store::peek_item(&client, job_id, &item.key, &digest, options.rescan).await
        } else {
            store::stage_item(
                &mut client,
                job_id,
                &item.key,
                &digest,
                options.rescan,
                SystemTime::now(),
                lease_token,
                lease_ttl(program),
            )
            .await
        };
        let staged = match staged {
            Ok(staged) => staged,
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
            continue;
        };
        match staged.classification {
            StagedClassification::New => report.items_new += 1,
            StagedClassification::Changed => report.items_changed += 1,
            StagedClassification::Redelivered => report.items_redelivered += 1,
        }
        let deliverable = DeliverableItem {
            key: staged.key.clone(),
            sequence: staged.sequence,
            digest: staged.digest.clone(),
            prior_run_id: staged.prior_run_id,
            admitted_before: staged.admitted_before,
            projected: projection::project(&job.projection, &item.value),
        };
        match destination.deliver(&job.job, &deliverable).await {
            HandOffOutcome::Acknowledged { run_id } => {
                report.items_acknowledged += 1;
                consecutive.reset();
                if !options.dry_run {
                    if let Err(error) = store::record_acknowledged(
                        &client,
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
            }
            HandOffOutcome::Refused { code } => {
                report.items_refused += 1;
                *report.refusals_by_code.entry(code.clone()).or_insert(0) += 1;
                // The row records its refusal before the limit is
                // evaluated: a pass that stops at the limit still leaves
                // the refused row its code, and only a rescan retries it.
                if !options.dry_run {
                    if let Err(error) = store::record_refused(
                        &client,
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
    // release the lease, and call the destination's settle contract. A
    // cursor the route carried out as JSON null is no cursor: the
    // position clears, the finite end.
    let next = page.next.as_ref().filter(|value| !value.is_null());
    if !options.dry_run {
        if let Err(error) = store::complete_pass(
            &client,
            job_id,
            lease_token,
            next,
            report.items_read == 0,
            options.rescan,
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
    destination
        .settle(
            &job.job,
            &SettledPage {
                next: next.cloned(),
                items_read: report.items_read,
            },
        )
        .await;
    report
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
        if let Ok(client) = db.get().await {
            let _ = store::stop_pass(
                &client,
                job_id,
                token,
                &reason.stop_text(),
                SystemTime::now(),
            )
            .await;
        }
    }
    report.stopped = Some(reason);
    report
}

/// The stop reason for a store refusal: the store's own account of the
/// failure, carried under one closed code, value-free.
fn store_refused_reason(error: &store::StoreError) -> StopReason {
    StopReason::PageFault {
        code: format!("adapter.job.store-refused:{error}"),
    }
}

/// A pass that could not reach its own state row: the report carries
/// the failure and nothing ran.
fn store_refused(mut report: PassReport, reason: &str) -> PassReport {
    report.stopped = Some(StopReason::PageFault {
        code: format!("adapter.job.store-refused:{reason}"),
    });
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
            *report = store_refused(std::mem::take(report), &error.to_string());
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
        *report = store_refused(std::mem::take(report), &error.to_string());
        return None;
    }
    // The overdue flag reads the state as this pass found it: on a held
    // lease, where no pass ran at all, it is the number that matters.
    let before = match store::read_state(client, job_id).await {
        Ok(row) => row.unwrap_or_default(),
        Err(error) => {
            *report = store_refused(std::mem::take(report), &error.to_string());
            return None;
        }
    };
    report.overdue = overdue(&before, program);
    let leased = match store::take_lease(client, job_id, lease_ttl(program)).await {
        Ok(leased) => leased,
        Err(error) => {
            *report = store_refused(std::mem::take(report), &error.to_string());
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
            *report = store_refused(std::mem::take(report), &error.to_string());
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
    Duration::from_millis(program.profile().page_deadline_milliseconds)
        + Duration::from_secs(store::LEASE_MARGIN_SECONDS)
}

/// The closed reason of a failed page read: the page fault's own code,
/// or the route failure's class.
fn page_failure_reason(failure: &JobPageFailure) -> StopReason {
    if let Some(code) = failure.code {
        return StopReason::PageFault {
            code: code.to_string(),
        };
    }
    StopReason::PageFault {
        code: failure
            .class
            .map(|class| class.class().to_owned())
            .unwrap_or_else(|| "adapter.job.page-failure".to_string()),
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
                code: "adapter.job.page-key".to_string()
            }
            .stop_text(),
            "page-fault:adapter.job.page-key"
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
}
