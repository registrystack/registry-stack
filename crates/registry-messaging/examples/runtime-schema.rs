// SPDX-License-Identifier: Apache-2.0

//! Write the Messaging runtime configuration JSON Schema.

#[cfg(feature = "schema")]
fn main() -> std::process::ExitCode {
    registry_messaging::schema::write_documents(
        "runtime-schema",
        registry_messaging::schema::runtime_documents,
    )
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("runtime-schema requires the schema feature");
    std::process::ExitCode::from(2)
}
