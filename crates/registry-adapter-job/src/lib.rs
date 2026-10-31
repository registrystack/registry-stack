// SPDX-License-Identifier: Apache-2.0

//! The governed-ingestion job host: the item table, the pass, the
//! interval trigger, and the destination seam
//! (`products/adapter/CONCEPT.md` section 17 and the governed-ingestion
//! concept sections 3 to 5).
//!
//! The host owns identity and progress, never payloads. One row per item
//! carries the item's key, a plain `sha256:` digest of its projection, a
//! change sequence, and the destination's answer; the job state row
//! carries the opaque source position and the pass schedule. The pass is
//! the only unit of work: one bounded page read, the per-item comparison,
//! the hand-offs through the [`destination::JobDestination`] seam, and
//! the saved position. A trigger decides only when a pass starts.
//!
//! The seam is the hand-off point later destinations plug into: a direct
//! destination that maps the projection to one product operation, or an
//! event destination that signs the projection for a coordinator. Both
//! derive their retry identity from `(job id, item key, sequence,
//! digest)`, and neither ever sees the raw source item, only the
//! declared projection.

pub mod destination;
pub mod pass;
pub mod projection;
pub mod store;
pub mod trigger;

pub mod cli;
