//! Write the Evidence client profile and reviewed contracts JSON Schemas.

#[cfg(feature = "schema")]
fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        eprintln!("usage: client-schema --output <directory>");
        return std::process::ExitCode::from(2);
    }
    let Some(output) = arguments.next().map(std::path::PathBuf::from) else {
        eprintln!("usage: client-schema --output <directory>");
        return std::process::ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("usage: client-schema --output <directory>");
        return std::process::ExitCode::from(2);
    }
    let documents = match registry_evidence_client::schema::client_documents() {
        Ok(documents) => documents,
        Err(error) => {
            eprintln!("client schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    for (name, contents) in documents {
        let path = output.join(name);
        let written = path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::write(&path, contents));
        if let Err(error) = written {
            eprintln!("client schema generation failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(feature = "schema"))]
fn main() -> std::process::ExitCode {
    eprintln!("client-schema requires the schema feature");
    std::process::ExitCode::from(2)
}
