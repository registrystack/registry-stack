// SPDX-License-Identifier: Apache-2.0
//! `data_gate`: a config-driven controlled data gateway.
//!
//! The crate turns local CSV, XLSX, and Parquet sources into protected,
//! read-only, entity-shaped HTTP APIs. The public surface is deliberately
//! domain-oriented: storage tables are private ingest details, while configured
//! entities define routes, fields, relationships, scopes, filters, aggregates,
//! metadata, and optional provenance claims.
//!
//! The main runtime path is:
//!
//! 1. [`config`] loads and validates the operator YAML.
//! 2. [`source`] and [`format`] read local files into Arrow/DataFusion tables.
//! 3. [`ingest`] registers versioned table snapshots and readiness state.
//! 4. [`entity`] and [`query`] expose configured domain resources.
//! 5. [`server`] wires HTTP routes, auth, audit, limits, and observability.

pub mod api;
pub mod audit;
pub mod auth;
pub mod config;
pub mod entity;
pub mod error;
pub mod format;
pub mod ingest;
pub mod metadata;
pub mod observability;
pub mod provenance;
pub mod query;
pub mod server;
pub mod source;
