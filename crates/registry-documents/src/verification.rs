// SPDX-License-Identifier: Apache-2.0

//! Content verification: one dispatch job per finalized version and
//! verifier binding.

/// The verification job table, in the shape `registry-platform-dispatch`
/// declares.
pub const JOB_TABLE: &str = "documents_verification_jobs";
