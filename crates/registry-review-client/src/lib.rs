// SPDX-License-Identifier: Apache-2.0
//! Product-neutral, bounded client for the review handoff protocol.

#![deny(unsafe_code)]

mod client;
mod config;
mod error;
mod model;

pub use client::ReviewClient;
pub use config::ReviewClientConfig;
pub use error::{ReviewClientError, ReviewProtocolFailure};
pub use model::{ReviewComplete, ReviewResultResponse, ReviewResultsQuery};
pub use registry_platform_httputil::client::BearerToken;
pub use registry_review_protocol::{
    submission_digest, ContentDigest, HumanIdentity, PolicyBinding, ProtocolError,
    ReviewCancelRequest, ReviewCancelResponse, ReviewCompletion, ReviewCompletionType,
    ReviewContext, ReviewCreateRequest, ReviewRequestAccepted, ReviewRequestLifecycle,
    ReviewRequestView, ReviewResult, ReviewResultFeedEntry, ReviewResultFeedPage,
    ReviewResultLookup, ReviewResultStatus, SourceContextBinding, SubjectBinding, SubmissionDigest,
};
pub use uuid::Uuid;
