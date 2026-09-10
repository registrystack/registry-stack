// SPDX-License-Identifier: Apache-2.0
//! Canonical, bounded client for Registry Casework.

#![deny(unsafe_code)]

mod client;
mod config;
mod error;
mod model;

pub use client::CaseworkClient;
pub use config::CaseworkClientConfig;
pub use error::{CaseworkClientError, CaseworkProblemCode, CaseworkProtocolFailure};
pub use model::*;
pub use registry_casework_core::{
    AttemptState, AttemptStatus, BootstrapDirectoryRequest, CallerSubjectView, CaseworkAction,
    ClaimRequest, CorrectionRoutingCopy, DecideRequest, Description, DirectoryResponse, Draft,
    DraftResponse, HistoryEntry, HistoryKind, HistoryPage, HoldingSummary, HoldingsPage,
    HoldingsQuery, InboxView, IssuerPrincipal, ListWorkItemsQuery, MutationResponse,
    NextWorkItemQuery, OccurrenceKind, OccurrenceState, OperationName, Page, PageStatus,
    QueueRecord, RecoverAttemptRequest, ReleaseRequest, SaveDraftRequest, SourceBinding,
    SourceReceipt, SubjectRef, TeamRecord, WorkItem, WorkItemPage,
};
pub use registry_platform_httputil::client::BearerToken;
