// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL lease machine over a product-owned job table.
//!
//! The product creates its job table from [`JobTable::create_statements`],
//! enqueues work with [`enqueue`] inside its own transaction, and implements
//! [`DispatchStore`] for decoding, audit, and extra columns and
//! [`DispatchTransport`] for the send. [`Dispatcher`] runs every transition;
//! [`DispatchWorker`] drains due jobs under bounded concurrency.
//!
//! Every write on behalf of a lease carries its [`Fence`]: key, generation,
//! attempt, and lease token. A lease lasts the captured attempt timeout plus
//! [`LEASE_FINALIZATION_ALLOWANCE`], so the worker that sent can record the
//! outcome before recovery may take the job over.

mod dispatcher;
mod sql;
mod store;
mod table;
mod worker;

pub use dispatcher::{
    CancelOutcome, Claim, DispatchConfig, DispatchOutcome, Dispatcher, LeasedReadError,
    LEASE_FINALIZATION_ALLOWANCE,
};
pub use sql::{Columns, DispatchSql, ExpirySql, SelectSql};
pub use store::{
    AttemptAudit, ClaimRefusal, Decoded, DispatchConnection, DispatchEvent, DispatchStore,
    DispatchTransport, Disposition, Fence, LapsedJob, LeasedJob, Quarantine, QuarantineDisposition,
    QuarantineReason, TargetAction, Transition, TransitionAudit, TransitionCode,
};
pub use table::{enqueue, JobKey, JobState, JobTable, MAX_JOB_PART_BYTES, MAX_TABLE_NAME_BYTES};
pub use worker::{DispatchWorker, WorkerConfig};
