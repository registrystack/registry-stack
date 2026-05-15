// SPDX-License-Identifier: Apache-2.0
//! data_gate: a config-driven controlled data gateway.
//!
//! This file is a Wave 0 Track 1 stub. Module declarations below are wired
//! by their respective tracks (see decisions/wave-0.md Section 6).

// Module slots reserved for Wave 0 tracks. Each track adds its
// module file under the corresponding path; this `mod` line is added
// here serially as tracks land, per the wave's blocker order.

pub mod api; // Wave 0 Track 6
pub mod audit; // Wave 0 Track 5
pub mod auth; // Wave 0 Track 4
pub mod config; // Wave 0 Track 2
pub mod entity; // Wave 2 entity layer
pub mod error; // Wave 0 Track 3
pub mod format; // Wave 1 Tracks 2-4 (CSV / XLSX / Parquet decoders)
pub mod ingest; // Wave 1 Tracks 5-6 (validation, cache, refresh, registry)
pub mod metadata; // Wave 3 entity-grain catalog / SHACL
pub mod query; // Wave 2 query layer
pub mod server; // Wave 0 Track 6
pub mod source; // Wave 1 Track 1 (byte producers)
