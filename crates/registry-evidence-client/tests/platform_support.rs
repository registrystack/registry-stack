//! Which platforms the deployment-backed suite covers.
//!
//! `against_a_real_deployment.rs` writes a deployment project to disk and sets
//! Unix permission modes on it, because the runtime it starts refuses key
//! material and configuration that are group or world writable. The whole file is
//! therefore compiled only on Unix. Nothing else in this crate is
//! platform-specific: the unit suite drives the client against local stubs and
//! runs everywhere.

/// Stated as a test so the gap appears in the test output on a platform the
/// deployment-backed suite cannot run on, instead of that suite silently
/// contributing nothing.
#[cfg(not(unix))]
#[test]
fn the_deployment_backed_suite_runs_only_on_unix() {}
