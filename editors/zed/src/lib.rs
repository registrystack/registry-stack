// SPDX-License-Identifier: Apache-2.0

use zed_extension_api as zed;

struct RegistryStackExtension;

// The subcommand an adopter CLI answers to when it hosts the language server.
const HOSTED_SERVER_ARGS: [&str; 2] = ["tooling", "language-server"];

// Evidence tooling hosts the shared server for every supported product.
const HOSTING_CLI_NAMES: [&str; 1] = ["evidencectl"];

impl zed::Extension for RegistryStackExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> zed::Result<zed::Command> {
        let shell_env = worktree.shell_env();
        if let Some(binary) =
            zed::settings::LspSettings::for_worktree("registry-stack", worktree)?.binary
        {
            return configured_command(binary, shell_env);
        }

        let candidates = HOSTING_CLI_NAMES
            .into_iter()
            .filter_map(|name| worktree.which(name).map(|command| (name, command)));
        let hosting_errors =
            match select_hosting_cli(candidates, matching_cli_version, hosts_language_server) {
                Ok(command) => {
                    return Ok(zed::Command {
                        command,
                        args: HOSTED_SERVER_ARGS.into_iter().map(str::to_owned).collect(),
                        env: shell_env,
                    });
                }
                Err(errors) => errors,
            };

        if hosting_errors.is_empty() {
            Err(format!(
                "no supported Registry Stack adopter CLI was found on PATH; install evidencectl {} or configure lsp.registry-stack.binary.path",
                env!("CARGO_PKG_VERSION")
            ))
        } else {
            Err(format!(
                "no matching Registry Stack adopter CLI on PATH can host the language server: {}; install evidencectl {} or configure lsp.registry-stack.binary.path",
                hosting_errors.join("; "),
                env!("CARGO_PKG_VERSION")
            ))
        }
    }
}

fn configured_command(
    binary: zed::settings::CommandSettings,
    shell_env: Vec<(String, String)>,
) -> zed::Result<zed::Command> {
    let path = binary.path.filter(|path| !path.trim().is_empty()).ok_or(
        "lsp.registry-stack.binary.path must name an executable; remove the binary setting to search PATH".to_owned(),
    )?;
    Ok(zed::Command {
        command: path,
        args: binary.arguments.unwrap_or_default(),
        env: merge_env(shell_env, binary.env.unwrap_or_default()),
    })
}

fn select_hosting_cli(
    candidates: impl IntoIterator<Item = (&'static str, String)>,
    mut version_probe: impl FnMut(&str, &str) -> Result<bool, String>,
    mut host_probe: impl FnMut(&str) -> Result<bool, String>,
) -> Result<String, Vec<String>> {
    let mut errors = Vec::new();
    for (name, command) in candidates {
        match version_probe(&command, name) {
            Ok(true) => {}
            Ok(false) => {
                errors.push(format!(
                    "{name} does not match Registry Stack {}",
                    env!("CARGO_PKG_VERSION")
                ));
                continue;
            }
            Err(error) => {
                errors.push(format!("{name} version could not be probed: {error}"));
                continue;
            }
        }
        match host_probe(&command) {
            Ok(true) => return Ok(command),
            Ok(false) => errors.push(format!("{name} does not provide tooling language-server")),
            Err(error) => errors.push(format!("{name} could not be probed: {error}")),
        }
    }
    Err(errors)
}

fn merge_env(
    mut shell_env: Vec<(String, String)>,
    overrides: std::collections::HashMap<String, String>,
) -> Vec<(String, String)> {
    for (key, value) in overrides {
        if let Some((_, existing)) = shell_env.iter_mut().find(|(name, _)| name == &key) {
            *existing = value;
        } else {
            shell_env.push((key, value));
        }
    }
    shell_env
}

// Ask a candidate's version before launching it. A CLI from an older product
// release may still answer the hosted-language-server help command.
fn matching_cli_version(command: &str, name: &str) -> Result<bool, String> {
    let mut probe = zed::process::Command::new(command).arg("--version");
    let output = probe.output()?;
    Ok(output.status == Some(0)
        && parse_cli_version(&output.stdout, name)
            .is_some_and(|version| version_matches(version, env!("CARGO_PKG_VERSION"))))
}

fn parse_cli_version<'a>(stdout: &'a [u8], name: &str) -> Option<&'a str> {
    let output = std::str::from_utf8(stdout).ok()?;
    let version = output.trim_end().strip_prefix(name)?.strip_prefix(' ')?;
    version.split_whitespace().next()
}

fn version_matches(installed: &str, expected: &str) -> bool {
    installed == expected || installed == format!("{expected}-dev")
}

// Whether this command hosts the language server, asked of the command rather
// than inferred from its name. The probe is the CLI's own help for the
// subcommand, so it starts no server and reads no project.
fn hosts_language_server(command: &str) -> Result<bool, String> {
    let mut probe = hosting_probe_command(command);
    let output = probe.output()?;
    Ok(probe_succeeded(&output))
}

fn hosting_probe_command(command: &str) -> zed::process::Command {
    zed::process::Command::new(command)
        .args(HOSTED_SERVER_ARGS)
        .arg("--help")
}

fn probe_succeeded(output: &zed::process::Output) -> bool {
    output.status == Some(0)
}

zed::register_extension!(RegistryStackExtension);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosting_probe_command_asks_for_tooling_language_server_help() {
        let probe = hosting_probe_command("evidencectl");
        assert_eq!(probe.command, "evidencectl");
        assert_eq!(probe.args, ["tooling", "language-server", "--help"]);
    }

    #[test]
    fn cli_version_must_match_this_extension() {
        let version = env!("CARGO_PKG_VERSION");
        let dev_version = format!("{version}-dev");
        assert_eq!(
            parse_cli_version(format!("evidencectl {version}\n").as_bytes(), "evidencectl"),
            Some(version)
        );
        assert_eq!(
            parse_cli_version(
                format!("evidencectl {dev_version} (abc)\n").as_bytes(),
                "evidencectl"
            ),
            Some(dev_version.as_str())
        );
        assert_eq!(
            parse_cli_version(format!("registryctl {version}\n").as_bytes(), "evidencectl"),
            None
        );
        assert_eq!(parse_cli_version(b"evidencectl\n", "evidencectl"), None);
        assert!(version_matches(version, version));
        assert!(version_matches(&dev_version, version));
        assert!(!version_matches("0.36.0", version));
        assert!(!version_matches(&format!("{version}-pre"), version));
    }

    #[test]
    fn configured_binary_uses_path_arguments_and_environment() {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("PATH".to_owned(), "/chosen/bin".to_owned());
        overrides.insert("REGISTRY_TEST".to_owned(), "enabled".to_owned());
        let command = configured_command(
            zed::settings::CommandSettings {
                path: Some("/chosen/bin/evidencectl".to_owned()),
                arguments: Some(vec!["tooling".to_owned(), "language-server".to_owned()]),
                env: Some(overrides),
            },
            vec![("PATH".to_owned(), "/shell/bin".to_owned())],
        )
        .unwrap();
        assert_eq!(command.command, "/chosen/bin/evidencectl");
        assert_eq!(command.args, ["tooling", "language-server"]);
        assert!(command
            .env
            .contains(&("PATH".to_owned(), "/chosen/bin".to_owned())));
        assert!(command
            .env
            .contains(&("REGISTRY_TEST".to_owned(), "enabled".to_owned())));
        assert_eq!(command.env.len(), 2);
        assert!(configured_command(
            zed::settings::CommandSettings {
                path: None,
                arguments: None,
                env: None,
            },
            Vec::new(),
        )
        .is_err());
    }

    #[test]
    fn matching_evidence_cli_follows_mismatched_copy() {
        let selected = select_hosting_cli(
            [
                ("evidencectl", "/old/evidencectl".to_owned()),
                ("evidencectl", "/current/evidencectl".to_owned()),
            ],
            |command, _| Ok(command == "/current/evidencectl"),
            |_| Ok(true),
        );
        assert_eq!(selected.unwrap(), "/current/evidencectl");
    }

    #[test]
    fn matching_cli_without_server_does_not_hide_next_candidate() {
        let selected = select_hosting_cli(
            [
                ("evidencectl", "/current/evidencectl".to_owned()),
                ("evidencectl", "/current/evidencectl".to_owned()),
            ],
            |_, _| Ok(true),
            |command| Ok(command == "/current/evidencectl"),
        );
        assert_eq!(selected.unwrap(), "/current/evidencectl");
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
