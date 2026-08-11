// SPDX-License-Identifier: Apache-2.0

use zed_extension_api as zed;

struct RegistryStackExtension;

// The subcommand an adopter CLI answers to when it hosts the language server.
const HOSTED_SERVER_ARGS: [&str; 2] = ["tooling", "language-server"];

// The adopter CLIs that may host the server, in product order. A matching
// relayctl must remain reachable when an older evidencectl is also on PATH.
const HOSTING_CLI_NAMES: [&str; 2] = ["evidencectl", "relayctl"];

impl zed::Extension for RegistryStackExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> zed::Result<zed::Command> {
        // A standalone registry-language-server on PATH is trusted by name: it
        // has no subcommands, so there is nothing to probe with
        // "tooling language-server --help".
        if let Some(command) = worktree.which("registry-language-server") {
            return Ok(zed::Command {
                command,
                args: Vec::new(),
                env: worktree.shell_env(),
            });
        }

        let mut hosting_errors = Vec::new();
        for name in HOSTING_CLI_NAMES {
            let Some(command) = worktree.which(name) else {
                continue;
            };
            match hosts_language_server(&command) {
                Ok(true) => {
                    return Ok(zed::Command {
                        command,
                        args: HOSTED_SERVER_ARGS.into_iter().map(str::to_owned).collect(),
                        env: worktree.shell_env(),
                    });
                }
                Ok(false) => {
                    hosting_errors.push(format!("{name} does not provide tooling language-server"));
                }
                Err(error) => {
                    hosting_errors.push(format!("{name} could not be probed: {error}"));
                }
            }
        }

        if hosting_errors.is_empty() {
            Err(
                "neither registry-language-server nor a supported Registry Stack adopter CLI was found on PATH; install evidencectl or relayctl before enabling this extension"
                    .to_owned(),
            )
        } else {
            Err(format!(
                "registry-language-server was not found on PATH, and no supported CLI on PATH can host it: {}; install a matching evidencectl or relayctl",
                hosting_errors.join("; ")
            ))
        }
    }
}

// Whether this command hosts the language server, asked of the command rather
// than inferred from its name. The probe is the CLI's own help for the
// subcommand, so it starts no server and reads no project.
fn hosts_language_server(command: &str) -> Result<bool, String> {
    let mut probe = hosting_probe_command(command);
    let output = probe.output()?;
    Ok(probe_succeeded(&output))
}

// The probe command itself, split out so its shape (the exact program and
// arguments run against a PATH candidate) can be checked without starting a
// process.
fn hosting_probe_command(command: &str) -> zed::process::Command {
    zed::process::Command::new(command)
        .args(HOSTED_SERVER_ARGS)
        .arg("--help")
}

// Whether a finished probe counts as hosting the language server. A clean
// exit is success; a nonzero exit or termination by signal is not.
fn probe_succeeded(output: &zed::process::Output) -> bool {
    output.status == Some(0)
}

zed::register_extension!(RegistryStackExtension);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosting_probe_command_asks_for_tooling_language_server_help() {
        let probe = hosting_probe_command("relayctl");
        assert_eq!(probe.command, "relayctl");
        assert_eq!(probe.args, ["tooling", "language-server", "--help"]);
    }

    #[test]
    fn probe_succeeded_requires_a_clean_exit() {
        let clean_exit = zed::process::Output {
            status: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert!(probe_succeeded(&clean_exit));

        let nonzero_exit = zed::process::Output {
            status: Some(1),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert!(!probe_succeeded(&nonzero_exit));

        let killed_by_signal = zed::process::Output {
            status: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert!(!probe_succeeded(&killed_by_signal));
    }
}
