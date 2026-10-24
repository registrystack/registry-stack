// SPDX-License-Identifier: Apache-2.0

//! Write a generated Document Store document; see `registry_documents::schema`.

#[cfg(feature = "schema")]
fn main() -> std::process::ExitCode {
    registry_documents::schema::write_documents(
        "runtime-schema",
        registry_documents::schema::runtime_documents,
    )
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("runtime-schema requires the schema feature");
    std::process::ExitCode::from(2)
}
