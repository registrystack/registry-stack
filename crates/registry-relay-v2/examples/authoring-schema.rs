// SPDX-License-Identifier: Apache-2.0

use std::{env, fs, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(flag) = arguments.next() else {
        eprintln!("usage: authoring-schema --output <directory>");
        return ExitCode::from(2);
    };
    let Some(output) = arguments.next() else {
        eprintln!("usage: authoring-schema --output <directory>");
        return ExitCode::from(2);
    };
    if flag != "--output" || arguments.next().is_some() {
        eprintln!("usage: authoring-schema --output <directory>");
        return ExitCode::from(2);
    }
    let output = PathBuf::from(output);
    if fs::create_dir_all(&output).is_err() {
        eprintln!("authoring schema output directory could not be created");
        return ExitCode::FAILURE;
    }
    let documents = match registry_relay_v2::schema::documents() {
        Ok(documents) => documents,
        Err(_) => {
            eprintln!("authoring schemas could not be generated");
            return ExitCode::FAILURE;
        }
    };
    for (name, document) in documents {
        if fs::write(output.join(name), document).is_err() {
            eprintln!("authoring schema could not be written");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
