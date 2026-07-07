// SPDX-License-Identifier: Apache-2.0
//! `registry-relay`: a config-driven registry relay.
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
//! 2. [`connector`] turns configured private tables into Arrow/DataFusion data.
//! 3. [`ingest`] registers versioned table materializations and readiness state.
//! 4. [`entity`] and [`query`] expose configured domain resources.
//! 5. [`server`] wires HTTP routes, auth, audit, limits, and observability.

pub mod api;
pub mod attribute_release;
pub mod audit;
pub mod auth;
pub mod config;
pub mod connector;
pub mod deployment;
pub mod entity;
pub mod error;
pub mod format;
pub mod ingest;
pub mod metadata;
mod net;
pub mod observability;
pub mod provenance;
pub mod query;
pub mod runtime_config;
pub mod serve;
pub mod server;
pub mod source;
#[cfg(feature = "spdci-api-standards")]
pub mod spdci;
pub mod table_provider;
