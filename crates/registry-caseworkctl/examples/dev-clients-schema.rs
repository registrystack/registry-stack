// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "schema")]
fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        eprintln!("usage: dev-clients-schema --output <directory>");
        return std::process::ExitCode::from(2);
    }
    let Some(output) = arguments.next().map(std::path::PathBuf::from) else {
        eprintln!("usage: dev-clients-schema --output <directory>");
        return std::process::ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("usage: dev-clients-schema --output <directory>");
        return std::process::ExitCode::from(2);
    }
    let documents = match registry_caseworkctl::schema::documents() {
        Ok(documents) => documents,
        Err(error) => {
            eprintln!("dev-clients schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if let Err(error) = std::fs::create_dir_all(&output) {
        eprintln!("dev-clients schema generation failed: {error}");
        return std::process::ExitCode::FAILURE;
    }
    for (name, contents) in documents {
        let path = output.join(name);
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                eprintln!("dev-clients schema generation failed: {error}");
                return std::process::ExitCode::FAILURE;
            }
        }
        if let Err(error) = std::fs::write(path, contents) {
            eprintln!("dev-clients schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("dev-clients-schema requires the schema feature");
    std::process::ExitCode::from(2)
}
