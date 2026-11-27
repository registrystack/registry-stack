// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "schema")]
fn main() -> std::process::ExitCode {
    let usage = "usage: provision-report-schema --output <file>";
    let mut arguments = std::env::args_os().skip(1);
    let (Some(flag), Some(output), None) = (arguments.next(), arguments.next(), arguments.next())
    else {
        eprintln!("{usage}");
        return std::process::ExitCode::from(2);
    };
    if flag != "--output" {
        eprintln!("{usage}");
        return std::process::ExitCode::from(2);
    }
    let output = std::path::PathBuf::from(output);
    let document = match registry_platform_provision::cli::report_schema_document() {
        Ok(document) => document,
        Err(error) => {
            eprintln!("provision report schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let written = match output.parent() {
        Some(parent) => std::fs::create_dir_all(parent),
        None => Ok(()),
    }
    .and_then(|()| std::fs::write(&output, document));
    if let Err(error) = written {
        eprintln!("provision report schema generation failed: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("provision-report-schema requires the schema feature");
    std::process::ExitCode::from(2)
}
