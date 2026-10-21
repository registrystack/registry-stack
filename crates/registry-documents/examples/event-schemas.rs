// SPDX-License-Identifier: Apache-2.0

//! Write a generated Document Store document; see `registry_documents::schema`.

#[cfg(feature = "schema")]
fn main() -> std::process::ExitCode {
    registry_documents::schema::write_documents(
        "event-schemas",
        registry_documents::schema::event_documents,
    )
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("event-schemas requires the schema feature");
    std::process::ExitCode::from(2)
}
