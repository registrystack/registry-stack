// SPDX-License-Identifier: Apache-2.0

//! Write the Messaging OpenAPI document.

#[cfg(feature = "schema")]
fn main() -> std::process::ExitCode {
    registry_messaging::schema::write_documents(
        "openapi",
        registry_messaging::schema::openapi_documents,
    )
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("openapi requires the schema feature");
    std::process::ExitCode::from(2)
}
