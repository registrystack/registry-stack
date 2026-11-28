// SPDX-License-Identifier: Apache-2.0
//! Product-free PostgreSQL provisioning for Registry Stack runtimes.
//!
//! A product describes what it needs from an empty server as data
//! ([`ProductDatabase`]) and names its roles and database ([`ProvisionTarget`]).
//! [`plan`] turns those into an ordered list of statements. [`render_script`]
//! prints that list for an administrator to review and run with `psql`. The
//! printed script never holds a password or a password verifier.
//!
//! [`execute`] runs the same plan against a server as an administrator over
//! verified TLS ([`admin_config`]). It checks the server version first, creates
//! only what is absent, refuses what exists in another shape, and names the one
//! statement an administrator role lacks the privilege for. Role passwords
//! reach the server as SCRAM-SHA-256 verifiers and never reach an error or a
//! report. [`verify_logins`] then opens a session as each product role.

mod admin;
#[cfg(feature = "cli")]
pub mod cli;
mod execute;
mod plan;
pub mod sql;

pub use admin::{admin_config, AdminConfig, AdminConfigError};
pub use execute::{execute, verify_logins, Mode, Outcome, ProvisionError, StatementOutcome};

pub use plan::{
    plan, render_script, verify_server_version, Needs, Plan, PlanError, Probe, ProductDatabase,
    ProvisionTarget, RoleCredential, SchemaLayout, Scope, Spatial, Statement, UnsupportedPostgres,
};

#[cfg(feature = "cli")]
pub use cli::{run_provision, ProvisionArgs, ProvisionInput};
