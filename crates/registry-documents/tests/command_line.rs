// SPDX-License-Identifier: Apache-2.0

//! The `documents` binary answers `--version` and `--help` whatever
//! `DOCUMENTS_LOG` holds, and refuses an invalid level only for a command
//! that would log.

use std::process::{Command, Output};

fn documents(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_documents"))
        .args(args)
        .env("DOCUMENTS_LOG", "debug")
        .output()
        .expect("the documents binary executes")
}

#[test]
fn version_and_help_answer_under_an_invalid_log_level() {
    for flag in ["--version", "--help"] {
        let output = documents(&[flag]);
        assert!(
            output.status.success(),
            "{flag}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty(), "{flag} prints to stdout");
    }
}

#[test]
fn serve_refuses_an_invalid_log_level_before_reading_its_configuration() {
    let output = documents(&["--runtime-config", "/nonexistent/runtime.yaml", "serve"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "documents: DOCUMENTS_LOG must be one of error, warn, or info\n"
    );
}
