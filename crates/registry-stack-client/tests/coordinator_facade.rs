// SPDX-License-Identifier: Apache-2.0

//! The Coordinator client, reached only through the facade.
//!
//! A caller who depends on this crate alone must be able to name every type a
//! Coordinator method takes and returns. The signatures below are compiled,
//! never run: a type the facade does not re-export cannot be named here, so
//! the build fails rather than the caller's. The catalogue test then holds
//! the re-export list level with the client's own public surface in both
//! directions, so a name added to the client reaches the facade too.

use std::collections::BTreeSet;

use registry_stack_client::coordinator::{
    BearerToken, CoordinatorClient, CoordinatorClientConfig, CoordinatorClientError,
    CoordinatorComplete, RetryScheduled, RunInspection, RunList, RunListQuery, RunListState,
    RunStatus, StartRunRequest, Uuid,
};

/// The client's public surface, read from the crate that publishes it.
const CLIENT_SOURCE: &str = include_str!("../../registry-coordinator-client/src/lib.rs");

/// The facade's own source, read to compare the two lists as written.
const FACADE_SOURCE: &str = include_str!("../src/lib.rs");

/// Every Coordinator method, with its parameter and return types named
/// through the facade alone.
async fn every_coordinator_method_names_its_types(
    config: CoordinatorClientConfig,
    token: &BearerToken,
    idempotency_key: &str,
    run: Uuid,
    request: &StartRunRequest,
    query: &RunListQuery,
    state: RunListState,
) -> Result<(), CoordinatorClientError> {
    let client: CoordinatorClient = CoordinatorClient::new(config)?;
    let _: CoordinatorComplete<RunStatus> = client.start(token, idempotency_key, request).await?;
    let _: CoordinatorComplete<RunStatus> = client.status(token, run).await?;
    let _: CoordinatorComplete<RunInspection> = client.inspect(token, run).await?;
    let _: CoordinatorComplete<RunInspection> = client
        .reconcile(token, run, "operator reviewed the original receipt")
        .await?;
    let _: CoordinatorComplete<RunList> = client.list(token, 20).await?;
    let mut filtered_query = query.clone();
    filtered_query.state = Some(state);
    let _: CoordinatorComplete<RunList> = client.list_page(token, &filtered_query).await?;
    let _: CoordinatorComplete<RetryScheduled> = client
        .retry_same(token, run, "operator reviewed the inspection")
        .await?;
    let _: CoordinatorComplete<RunStatus> = client
        .cancel(token, run, "caller withdrew the request")
        .await?;
    Ok(())
}

/// Every name one `pub use` statement publishes, whether braced or single.
fn published_names(statement: &str) -> Vec<String> {
    if let Some(open) = statement.find('{') {
        let close = statement
            .rfind('}')
            .unwrap_or_else(|| panic!("a re-export opens a brace it never closes: {statement}"));
        return statement[open + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }
    let name = statement
        .rsplit("::")
        .next()
        .unwrap_or_else(|| panic!("a re-export names nothing: {statement}"))
        .trim();
    vec![name.to_owned()]
}

/// Every name a source re-exports with `pub use`, refusing a glob because a
/// glob hides the names this test compares.
fn re_exported_names(source: &str, publisher: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (index, _) in source.match_indices("pub use ") {
        let rest = &source[index + "pub use ".len()..];
        let end = rest
            .find(';')
            .unwrap_or_else(|| panic!("{publisher} opens a re-export it never ends"));
        let statement = &rest[..end];
        for name in published_names(statement) {
            assert_ne!(
                name, "*",
                "{publisher} re-exports {statement} as a glob, so this test cannot read its names"
            );
            assert!(
                names.insert(name.clone()),
                "{publisher} re-exports {name} twice"
            );
        }
    }
    names
}

/// The body of the facade's Coordinator module, so re-exports of other
/// products are not read as Coordinator names.
fn facade_coordinator_module() -> &'static str {
    let start = FACADE_SOURCE
        .find("pub mod coordinator {")
        .expect("the facade carries a coordinator module");
    let body = &FACADE_SOURCE[start..];
    let end = body
        .find("\n}\n")
        .expect("the facade's coordinator module is never closed");
    &body[..end]
}

#[test]
fn the_facade_names_every_coordinator_method_signature() {
    // Naming the function is what keeps the signatures above compiled; calling
    // one would need a Coordinator service.
    let _ = every_coordinator_method_names_its_types;
}

#[test]
fn the_facade_re_exports_every_public_client_name() {
    let client = re_exported_names(CLIENT_SOURCE, "crates/registry-coordinator-client");
    let facade = re_exported_names(
        facade_coordinator_module(),
        "the facade's coordinator module",
    );
    for name in &client {
        assert!(
            facade.contains(name),
            "the facade is behind the client: coordinator::{name} cannot be named through it"
        );
    }
    for name in &facade {
        assert!(
            client.contains(name),
            "the facade is ahead of the client: coordinator::{name} is not a public client name"
        );
    }
}
