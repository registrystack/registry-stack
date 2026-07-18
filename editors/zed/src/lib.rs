// SPDX-License-Identifier: Apache-2.0

use zed_extension_api as zed;

struct RegistryStackExtension;

impl zed::Extension for RegistryStackExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> zed::Result<zed::Command> {
        let (command, args) = if let Some(command) = worktree.which("registry-language-server") {
            (command, Vec::new())
        } else if let Some(command) = worktree.which("registryctl") {
            (
                command,
                vec!["authoring".to_owned(), "language-server".to_owned()],
            )
        } else {
            return Err(
                "neither registry-language-server nor registryctl was found on PATH; install Registry Stack before enabling this extension"
                    .to_owned(),
            );
        };
        Ok(zed::Command {
            command,
            args,
            env: worktree.shell_env(),
        })
    }
}

zed::register_extension!(RegistryStackExtension);
