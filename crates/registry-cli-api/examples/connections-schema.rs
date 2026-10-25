// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "schema")]
fn main() -> std::process::ExitCode {
    let usage = "usage: connections-schema --output <file> --report-output <file>";
    let mut output = None;
    let mut report_output = None;
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        let destination = match argument.to_str() {
            Some("--output") => &mut output,
            Some("--report-output") => &mut report_output,
            _ => {
                eprintln!("{usage}");
                return std::process::ExitCode::from(2);
            }
        };
        if destination.is_some() {
            eprintln!("{usage}");
            return std::process::ExitCode::from(2);
        }
        let Some(path) = arguments.next().map(std::path::PathBuf::from) else {
            eprintln!("{usage}");
            return std::process::ExitCode::from(2);
        };
        *destination = Some(path);
    }
    let (Some(output), Some(report_output)) = (output, report_output) else {
        eprintln!("{usage}");
        return std::process::ExitCode::from(2);
    };

    let documents = [
        (output, registry_cli_api::schema::document()),
        (
            report_output,
            registry_cli_api::schema::connection_check_report_document(),
        ),
    ];
    for (output, document) in documents {
        let document = match document {
            Ok(document) => document,
            Err(error) => {
                eprintln!("connections schema generation failed: {error}");
                return std::process::ExitCode::FAILURE;
            }
        };
        if let Err(error) = write_document(&output, &document) {
            eprintln!("connections schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(feature = "schema")]
fn write_document(output: &std::path::Path, document: &str) -> std::io::Result<()> {
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, document)
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("connections-schema requires the schema feature");
    std::process::ExitCode::from(2)
}
