// SPDX-License-Identifier: Apache-2.0

//! Write the JSON Schemas of the Messaging project, template, and provider
//! files.

#[cfg(feature = "schema")]
fn main() -> std::process::ExitCode {
    registry_messaging::schema::write_documents(
        "authoring-schema",
        registry_messaging::schema::authoring_documents,
    )
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("authoring-schema requires the schema feature");
    std::process::ExitCode::from(2)
}
