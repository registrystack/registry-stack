// SPDX-License-Identifier: Apache-2.0

use super::*;
use registry_platform_config::{declared_from, Posture, PostureError, PostureSource};
use std::ffi::OsStr;

#[test]
fn public_commands_resolve_posture_at_dispatch() {
    let commands: &[&[&str]] = &[
        &["init", "/unused/project"],
        &["check", "/unused/project"],
        &[
            "check",
            "/unused/project",
            "--runtime-config",
            "/unused/runtime.yaml",
        ],
        &["explain", "/unused/project"],
        &["test", "/unused/project"],
        &["types", "/unused/project", "--output", "/unused/types"],
        &["package", "/unused/project", "--dry-run"],
        &[
            "generate",
            "identity-facts",
            "/unused/project",
            "--runtime-config",
            "/unused/runtime.yaml",
            "--output",
            "/unused/facts",
        ],
        &[
            "provider",
            "add",
            "/unused/project",
            "--breg-project",
            "/unused/breg",
            "--action",
            "example",
            "--pattern",
            "single-reviewer-approval",
        ],
        &[
            "provider",
            "pair",
            "/unused/project",
            "--provider-id",
            "example",
            "--breg-package",
            "/unused/package",
            "--action-id",
            "example",
        ],
        &["serve", "--runtime-config", "/unused/runtime.yaml"],
        &["doctor", "--runtime-config", "/unused/runtime.yaml"],
        &["plan", "--runtime-config", "/unused/runtime.yaml"],
        &["status", "--runtime-config", "/unused/runtime.yaml"],
        &["apply", "--runtime-config", "/unused/runtime.yaml"],
        &[
            "provision",
            "--runtime-config",
            "/unused/runtime.yaml",
            "--print-sql",
        ],
        &["lifecycle"],
        &["api", "/health", "--project", "/unused/project"],
        &["connection", "check", "--file", "/unused/connections.yaml"],
    ];
    let cases = [
        (
            Some("development"),
            None,
            Ok(DeclaredPosture {
                posture: Posture::Development,
                source: PostureSource::Flag,
            }),
        ),
        (
            None,
            Some("development"),
            Ok(DeclaredPosture {
                posture: Posture::Development,
                source: PostureSource::Environment,
            }),
        ),
        (
            None,
            None,
            Ok(DeclaredPosture {
                posture: Posture::Production,
                source: PostureSource::Default,
            }),
        ),
        (
            Some("production"),
            Some("development"),
            Err(PostureError::Conflict),
        ),
    ];

    let mut unresolved = Vec::new();
    for &command in commands {
        for (flag, environment, expected) in cases {
            let mut args = vec!["caseworkctl", "--format", "json"];
            args.extend(command);
            if let Some(flag) = flag {
                args.extend(["--posture", flag]);
            }
            let mut called = false;
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            let exit = main_entry_with_posture_resolver(
                args.into_iter().map(OsString::from),
                &mut stdout,
                &mut stderr,
                |parsed_flag| {
                    called = true;
                    assert_eq!(parsed_flag, flag, "{command:?}");
                    let resolved = declared_from(parsed_flag, environment.map(OsStr::new));
                    assert_eq!(resolved, expected, "{command:?}");
                    // Stop before the command performs I/O, including for accepted declarations.
                    Err(resolved.err().unwrap_or(PostureError::InvalidFlag))
                },
            );
            if !called {
                unresolved.push((command, flag, environment));
                continue;
            }
            assert_eq!(exit, ExitCode::from(2), "{command:?}");
            let report: Value = serde_json::from_slice(&stdout).unwrap();
            assert_eq!(
                report["diagnostics"][0]["code"],
                expected.err().unwrap_or(PostureError::InvalidFlag).code(),
                "{command:?}",
            );
        }
    }
    assert!(
        unresolved.is_empty(),
        "commands bypassed posture: {unresolved:?}"
    );
}

#[test]
fn lifecycle_keeps_its_report_shape_after_resolving_posture() {
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let exit = main_entry_with_posture_resolver(
        [
            "caseworkctl",
            "--format",
            "json",
            "lifecycle",
            "--posture",
            "development",
        ]
        .map(OsString::from),
        &mut stdout,
        &mut stderr,
        |flag| declared_from(flag, None),
    );
    assert_eq!(exit, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let report: Value = serde_json::from_slice(&stdout).unwrap();
    assert!(report["lifecycles"].is_array(), "{report}");
    assert!(report.get("posture").is_none(), "{report}");
}
