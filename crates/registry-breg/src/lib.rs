// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

pub mod access;
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub mod access_preview;
pub mod authority;

#[cfg(feature = "runtime")]
pub mod api;
pub mod artifacts;
#[cfg(feature = "runtime")]
pub mod audit;
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub mod audit_tooling;
#[cfg(feature = "runtime")]
pub mod auth;
pub mod change_request;
#[cfg(feature = "runtime")]
pub mod cli;
pub mod compiler;
pub mod contract;
#[cfg(feature = "runtime")]
pub mod correlation;
#[cfg(feature = "runtime")]
pub mod cursor;
pub mod data;
pub mod derived_sql;
pub mod diagnostics;
#[cfg(feature = "runtime")]
pub mod event_destination;
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub mod fixtures;
pub mod generated_ddl;
#[cfg(feature = "runtime")]
pub(crate) mod history_commit;
#[cfg(feature = "runtime")]
pub mod history_context;
#[cfg(feature = "runtime")]
pub mod history_erasure;
#[cfg(feature = "runtime")]
pub mod history_maintenance;
#[cfg(feature = "runtime")]
pub(crate) mod history_migration;
#[cfg(feature = "runtime")]
pub mod history_rebaseline;
pub(crate) mod history_reference;
pub mod history_schema;
#[cfg(feature = "runtime")]
pub(crate) mod history_store;
#[cfg(feature = "runtime")]
pub mod idempotency;
pub mod immediate_actions;
pub mod logical_names;
pub mod manifest_adapter;
#[cfg(feature = "runtime")]
pub mod metrics;
#[cfg(feature = "runtime")]
pub mod migration;
#[cfg(feature = "runtime")]
pub mod migration_plan;
#[cfg(feature = "runtime")]
pub mod migration_reconcile;
pub mod model;
#[cfg(feature = "runtime")]
pub mod mutation;
#[cfg(feature = "runtime")]
pub mod outbox;
#[cfg(feature = "runtime")]
pub mod package;
pub mod physical_names;
#[cfg(feature = "runtime")]
pub mod postgres;
pub mod problem;
pub mod query;
#[cfg(feature = "runtime")]
pub(crate) mod query_binding;
pub mod record_profile;
#[cfg(feature = "runtime")]
pub mod request_events;
#[cfg(feature = "runtime")]
mod request_prepare;
#[cfg(feature = "runtime")]
pub mod request_retention;
#[cfg(feature = "runtime")]
mod request_store;
pub mod request_workflow;
#[cfg(feature = "runtime")]
pub mod revision;
pub mod rhai_planner;
#[cfg(feature = "runtime")]
pub mod runtime_config;
#[cfg(feature = "schema")]
pub mod schema;
#[cfg(feature = "runtime")]
pub mod startup;
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub mod tooling;
#[cfg(feature = "runtime")]
pub mod webhook;

pub use artifacts::{GeneratedArtifact, GeneratedArtifacts};
#[cfg(feature = "runtime")]
pub use cli::command;
pub use compiler::{compile_project, compile_project_with_assets, CompileProfile};
pub use contract::{
    parse_module_json, parse_module_yaml, parse_project_json, parse_project_yaml, RegistryModule,
    RegistryProject,
};
pub use diagnostics::{CompileFailure, Diagnostic, DiagnosticSeverity};
pub use model::CompiledRegistry;
