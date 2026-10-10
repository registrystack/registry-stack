// SPDX-License-Identifier: Apache-2.0

//! The Scheduling client, reached only through the facade.
//!
//! A caller who depends on this crate alone must be able to name every type a
//! Scheduling method takes and returns. The signatures below are compiled,
//! never run: a type the facade does not re-export cannot be named here, so
//! the build fails rather than the caller's. The catalogue test then holds
//! the re-export list level with the client's own public surface in both
//! directions, so a name added to the client reaches the facade too.
//!
//! The Scheduling client takes `chrono` instants without re-exporting
//! `chrono`, so the instants below are the one type named through `chrono`
//! itself.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use registry_stack_client::scheduling::{
    AdmissionRequest, AppointmentDocument, AppointmentHistoryEntryDocument, AvailabilityEntry,
    BearerToken, CancelAppointmentRequest, CreateAppointmentRequest, ExplainDocument,
    ExternalReference, HoldDocument, LocationDocument, OfferingDocument, PageDocument,
    RescheduleAppointmentRequest, ResourceDocument, SchedulingAuth, SchedulingClient,
    SchedulingClientConfig, SchedulingClientError, SchedulingComplete, SchedulingServiceDocument,
    ServiceDocument,
};

/// The client's public surface, read from the crate that publishes it.
const CLIENT_SOURCE: &str = include_str!("../../registry-scheduling-client/src/lib.rs");

/// The facade's own source, read to compare the two lists as written.
const FACADE_SOURCE: &str = include_str!("../src/lib.rs");

/// The requests every mutating Scheduling method sends.
struct Requests<'a> {
    admission: &'a AdmissionRequest,
    create: &'a CreateAppointmentRequest,
    reschedule: &'a RescheduleAppointmentRequest,
    cancel: &'a CancelAppointmentRequest,
    reference: &'a ExternalReference,
}

/// Every Scheduling method, with its parameter and return types named
/// through the facade alone.
async fn every_scheduling_method_names_its_types(
    config: SchedulingClientConfig,
    token: &BearerToken,
    idempotency_key: &str,
    identifier: &str,
    start: DateTime<Utc>,
    requests: Requests<'_>,
) -> Result<(), SchedulingClientError> {
    let client: SchedulingClient = SchedulingClient::new(config)?;
    let auth = || SchedulingAuth::new(token);
    let _: SchedulingComplete<SchedulingServiceDocument> = client.get_scheduling(auth()).await?;
    let _: SchedulingComplete<PageDocument<ServiceDocument>> =
        client.list_services(auth(), None).await?;
    let _: SchedulingComplete<PageDocument<OfferingDocument>> =
        client.list_offerings(auth(), None).await?;
    let _: SchedulingComplete<PageDocument<AvailabilityEntry>> = client
        .availability(auth(), identifier, Some(start), None, None, Some(25))
        .await?;
    let _: SchedulingComplete<ExplainDocument> = client.explain(auth(), identifier, start).await?;
    let _: SchedulingComplete<HoldDocument> = client
        .create_hold(auth(), idempotency_key, requests.admission)
        .await?;
    let _: SchedulingComplete<()> = client.release_hold(auth(), identifier).await?;
    let _: SchedulingComplete<AppointmentDocument> = client
        .create_appointment(auth(), idempotency_key, requests.create)
        .await?;
    let _: SchedulingComplete<AppointmentDocument> = client
        .appointment_receipt(auth(), idempotency_key, requests.create)
        .await?;
    let _: SchedulingComplete<AppointmentDocument> =
        client.get_appointment(auth(), identifier).await?;
    let _: SchedulingComplete<PageDocument<AppointmentDocument>> = client
        .list_appointments(auth(), requests.reference, None, None)
        .await?;
    let _: SchedulingComplete<AppointmentDocument> = client
        .reschedule_appointment(auth(), identifier, idempotency_key, requests.reschedule)
        .await?;
    let _: SchedulingComplete<AppointmentDocument> = client
        .cancel_appointment(auth(), identifier, idempotency_key, requests.cancel)
        .await?;
    let _: SchedulingComplete<PageDocument<AppointmentHistoryEntryDocument>> =
        client.appointment_history(auth(), identifier, None).await?;
    let _: SchedulingComplete<PageDocument<ResourceDocument>> =
        client.list_resources(auth(), None).await?;
    let _: SchedulingComplete<PageDocument<LocationDocument>> =
        client.list_locations(auth(), None).await?;
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

/// The body of the facade's Scheduling module, so re-exports of other
/// products are not read as Scheduling names.
fn facade_scheduling_module() -> &'static str {
    let start = FACADE_SOURCE
        .find("pub mod scheduling {")
        .expect("the facade carries a scheduling module");
    let body = &FACADE_SOURCE[start..];
    let end = body
        .find("\n}\n")
        .expect("the facade's scheduling module is never closed");
    &body[..end]
}

#[test]
fn the_facade_names_every_scheduling_method_signature() {
    // Naming the function is what keeps the signatures above compiled; calling
    // one would need a Scheduling service.
    let _ = every_scheduling_method_names_its_types;
}

#[test]
fn the_facade_re_exports_every_public_client_name() {
    let client = re_exported_names(CLIENT_SOURCE, "crates/registry-scheduling-client");
    let facade = re_exported_names(facade_scheduling_module(), "the facade's scheduling module");
    for name in &client {
        assert!(
            facade.contains(name),
            "the facade is behind the client: scheduling::{name} cannot be named through it"
        );
    }
    for name in &facade {
        assert!(
            client.contains(name),
            "the facade is ahead of the client: scheduling::{name} is not a public client name"
        );
    }
}
