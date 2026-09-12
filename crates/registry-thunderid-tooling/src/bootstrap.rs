//! The explicit bootstrap and schema-configuration step.
//!
//! Stateful configuration provisioning, documented as such: the upstream
//! one-shot `bootstrap --defaults` command runs against owned, retained state
//! with the serving process stopped, exactly as the pinned release defines
//! it. It needs no standing admin token, no temporary system client, and no
//! HTTP admin surface, and this crate adds none of those.

use std::path::{Path, PathBuf};

use crate::ToolingError;

/// How a command is executed. Real use runs the container engine; tests run
/// fakes that assert on the exact argv and environment without starting
/// anything.
pub trait CommandRunner {
    /// Run one command. `secret_environment` names environment variables
    /// whose values live in owner-only files: the runner reads each file and
    /// injects the value, so no secret ever sits in an argv element.
    fn run(
        &mut self,
        program: &str,
        args: &[String],
        secret_environment: &[(String, PathBuf)],
    ) -> Result<CommandOutcome, ToolingError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutcome {
    pub success: bool,
    /// Docker `ps` container IDs only. All other stdout, including setup's
    /// administrator credential, is discarded by every real runner.
    pub container_ids: String,
}

/// Where the schema directory is mounted inside the one-shot container.
pub const SCHEMA_MOUNT_POINT: &str = "/mounted/registry-schema";

/// The bootstrap one-shot over a rendered agent-schema directory.
pub struct Bootstrap<'a> {
    pub runner: &'a mut dyn CommandRunner,
    pub image: &'a str,
}

impl Bootstrap<'_> {
    /// Run the upstream schema one-shot.
    ///
    /// `--defaults` is the whole point: without it the command re-applies the
    /// entire bootstrap bundle, which would overwrite shared state. The
    /// `ADMIN_PASSWORD` the upstream command demands is satisfied from a
    /// fresh throwaway value in an owner-only file — never the real
    /// administrator credential, never an argv element — and the command's
    /// stdout is discarded without inspection because the pinned release
    /// echoes the value it was given on success.
    pub fn apply_agent_schema(
        &mut self,
        provisioning_dir: &Path,
        throwaway_admin_password_file: &Path,
        state_mounts: &[(PathBuf, PathBuf)],
    ) -> Result<(), ToolingError> {
        if !provisioning_dir.join("agent-type.yaml").is_file() {
            return Err(ToolingError::InvalidState {
                reason:
                    "the bootstrap provisioning directory does not carry the agent-schema update",
            });
        }
        let mut args: Vec<String> = vec![
            "run".into(),
            "--rm".into(),
            "--entrypoint".into(),
            "./thunderid".into(),
        ];
        for (host, container) in state_mounts {
            args.push("--mount".into());
            args.push(format!(
                "type=bind,src={},dst={}",
                host.display(),
                container.display()
            ));
        }
        args.push(self.image.to_owned());
        args.push("bootstrap".into());
        args.push("--defaults".into());
        args.push(SCHEMA_MOUNT_POINT.to_owned());

        let outcome = self.runner.run(
            "docker",
            &args,
            &[(
                "ADMIN_PASSWORD".to_owned(),
                throwaway_admin_password_file.to_path_buf(),
            )],
        )?;
        if !outcome.success {
            return Err(ToolingError::CommandFailed {
                step: "the agent-schema bootstrap one-shot did not succeed; staged state is preserved for diagnosis and nothing was reset",
            });
        }
        Ok(())
    }
}

/// The real command runner: executes the container engine, reads secret
/// environment values from owner-only files, and discards captured output
/// unread — upstream tooling echoes credential material on stdout, so no
/// byte of it ever reaches a log.
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[String],
        secret_environment: &[(String, PathBuf)],
    ) -> Result<CommandOutcome, ToolingError> {
        let mut command = std::process::Command::new(program);
        // `docker run` does not inherit the client's environment; `-e NAME`
        // with no value forwards the client process's variable into the
        // container, so each secret is injected from its owner-only file
        // without ever appearing in an argv element.
        let mut forwarded: Vec<&str> = Vec::new();
        let mut secrets: Vec<(String, String)> = Vec::new();
        for (name, file) in secret_environment {
            let value = std::fs::read_to_string(file).map_err(|_| ToolingError::Filesystem {
                reason: "a secret environment file could not be read",
            })?;
            forwarded.push("-e");
            forwarded.push(name);
            secrets.push((name.clone(), value.trim_end_matches('\n').to_owned()));
        }
        let mut arguments: Vec<&str> = args.iter().map(String::as_str).collect();
        if program == "docker" {
            let insertion = arguments
                .iter()
                .position(|argument| *argument == "run")
                .map(|position| position + 2)
                .unwrap_or(arguments.len());
            for (offset, flag) in forwarded.iter().enumerate() {
                arguments.insert(insertion + offset, flag);
            }
        }
        command.args(&arguments);
        for (name, value) in &secrets {
            command.env(name, value);
        }
        let output = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|_| ToolingError::CommandFailed {
                step: "the container engine could not be executed",
            })?;
        // Command output is not relayed: upstream tooling echoes credential
        // material, and nothing here may relay it. The one exception is an
        // explicitly requested diagnostic run without a supplied credential,
        // which prints a bounded tail of stderr. Upstream commands can echo
        // credentials, so neither stream is printed for a secret-bearing run.
        if !output.status.success()
            && secret_environment.is_empty()
            && std::env::var_os("REGISTRY_THUNDERID_TOOLING_DIAGNOSTICS").is_some()
        {
            let bounded: String = String::from_utf8_lossy(&output.stderr)
                .chars()
                .rev()
                .take(600)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            eprintln!("diagnostics: {bounded}");
        }
        Ok(CommandOutcome {
            success: output.status.success(),
            container_ids: if args.first().is_some_and(|arg| arg == "ps") {
                String::from_utf8(output.stdout).unwrap_or_default()
            } else {
                String::new()
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records every command it is asked to run and answers from a script.
    struct FakeRunner {
        recorded: Vec<(String, Vec<String>, Vec<String>)>,
        success: bool,
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &mut self,
            program: &str,
            args: &[String],
            secret_environment: &[(String, PathBuf)],
        ) -> Result<CommandOutcome, ToolingError> {
            self.recorded.push((
                program.to_owned(),
                args.to_vec(),
                secret_environment
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect(),
            ));
            Ok(CommandOutcome {
                success: self.success,
                container_ids: String::new(),
            })
        }
    }

    #[test]
    fn the_schema_one_shot_uses_defaults_and_a_file_injected_throwaway_password() {
        let mut runner = FakeRunner {
            recorded: Vec::new(),
            success: true,
        };
        let schema = std::env::temp_dir().join("tooling-test-schema");
        std::fs::create_dir_all(&schema).expect("the schema directory exists");
        std::fs::write(
            schema.join("agent-type.yaml"),
            "resource_type: agent_type\n",
        )
        .expect("the schema document exists");
        let password_file = std::env::temp_dir().join("tooling-test-throwaway-password");
        std::fs::write(&password_file, "throwaway-not-the-real-admin-password")
            .expect("the throwaway password file exists");

        let image = "ghcr.io/thunder-id/thunderid:1.0.1@sha256:d3c0613ff447a551fd440768a15bdfb6668948e80809cbb50f82d6752f22ab3e";
        let mut bootstrap = Bootstrap {
            runner: &mut runner,
            image,
        };
        bootstrap
            .apply_agent_schema(
                &schema,
                &password_file,
                &[(schema.clone(), PathBuf::from(SCHEMA_MOUNT_POINT))],
            )
            .expect("the one-shot succeeds");

        let (program, args, secrets) = &runner.recorded[0];
        assert_eq!(program, "docker");
        // `--defaults` with the mounted directory, never a bare re-bootstrap.
        let position = args
            .iter()
            .position(|argument| argument == "bootstrap")
            .expect("the bootstrap subcommand is present");
        assert_eq!(args[position + 1], "--defaults");
        assert_eq!(args[position + 2], SCHEMA_MOUNT_POINT);
        // The demanded password arrives as a file-injected environment
        // variable, never as an argv element.
        assert_eq!(secrets, &["ADMIN_PASSWORD".to_owned()]);
        assert!(!args.iter().any(|argument| argument.contains("throwaway")));
        // The entrypoint is the upstream binary, so the container runs no
        // shell and no server.
        assert!(args.contains(&"./thunderid".to_owned()));
        assert!(!args.iter().any(|argument| argument == "serve"));

        runner.success = false;
        let mut bootstrap = Bootstrap {
            runner: &mut runner,
            image,
        };
        assert!(matches!(
            bootstrap.apply_agent_schema(&schema, &password_file, &[]),
            Err(ToolingError::CommandFailed { .. })
        ));
    }
}
