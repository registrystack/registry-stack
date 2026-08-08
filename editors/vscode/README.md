# Registry Stack for VS Code

This beta integration is installed from a Registry Stack source release.
It is not yet published to the VS Code Marketplace and no release VSIX is provided.
For the stable beta path, run `registryctl init <directory> --template http` or
`registryctl -C <project> tooling editor` for a Relay project, or
`evidencectl tooling editor --project <directory>` for an Evidence authoring project, and use the
generated YAML schema settings. Install this integration for optional semantic navigation.

This extension starts `registry-language-server` for a workspace whose root declares a project. A
Relay project root contains `registry-stack.yaml`. An Evidence authoring project root contains
`evidence-project.yaml`, or the pre-marker pair of a `source.openapi.yaml` and a `questions`
directory. It adds cross-file definitions, references, workspace/document symbols, and Registry
Stack reference diagnostics. Red Hat YAML remains responsible for YAML syntax, schema validation,
completion, formatting, and ordinary hover information.

Multi-root workspaces are supported. The extension starts one isolated language-server process for
each folder whose root declares a project, and it responds when workspace folders are added or
removed. One process serves both families, so a workspace holding a Relay project and an Evidence
project needs no separate configuration. Because the server executes a local binary and reads local
files, the extension is disabled in untrusted and virtual workspaces.

## Install and launch

Prerequisites are Node.js 22 or newer, the `code` command-line tool, and either the `registryctl` or
the `evidencectl` version that matches this source checkout. Both embed the same language server, so
either satisfies the installer.

1. From the repository root, install the integration into the active VS Code profile:

   ```console
   ./editors/install.sh vscode
   ```

   The installer checks the version and embedded language server of `registryctl`, or of
   `evidencectl` when `registryctl` is absent, packages the extension, and installs it without
   reading or changing a project. The locally built VSIX records the verified absolute path of the
   CLI it selected, so it also works when an existing VS Code process did not inherit the shell
   `PATH`. Use `--profile <name>` to select an existing profile.

2. Complete the [shared smoke-project setup](../README.md#local-end-to-end-smoke-test), then open
   it in the same profile:

   ```console
   code --new-window "$REGISTRY_STACK_SMOKE_PROJECT"
   ```

   Alternatively, `./editors/install.sh vscode --open "$REGISTRY_STACK_SMOKE_PROJECT"` installs
   and opens the directory without configuring it.
3. Trust the opened workspace if you have reviewed it. The integration runs a local executable
   and is disabled in Restricted Mode and virtual workspaces.
4. Run **Registry Stack: Restart Language Server**. Open **View: Toggle Output**, select the
   **Registry Stack Language Server (project)** channel, and confirm it reports the smoke project
   as indexed.
5. Complete the [shared expected-behavior checklist](../README.md#expected-behavior). VS Code uses
   `F12` for definitions, `Shift+F12` for references, `Cmd+Shift+O`/`Ctrl+Shift+O` for document
   symbols, and `Cmd+T`/`Ctrl+T` for workspace symbols.

The source VSIX contains the extension runtime and the verified path to the CLI the installer
selected, not a platform server binary. Its server discovery order is: the explicit
`registryStack.languageServer.path` setting, the installer-selected CLI,
`registry-language-server` on `PATH`, a matching `registryctl` on `PATH`, then a matching
`evidencectl` on `PATH`. Every tier but the standalone server runs `<cli> tooling language-server`.
A manually packaged VSIX omits the local path metadata and retains the PATH-based discovery
behavior.

## Manual packaging

The installer performs these commands when a maintainer needs to inspect or repeat the individual
packaging steps:

```console
cd editors/vscode
npm ci
npm run package:dev
code --install-extension ./registry-stack-dev.vsix --force
```

`package:dev` type-checks the source, bundles its runtime dependencies into `dist/extension.js`,
and verifies that the VSIX contains no external `node_modules` runtime.

## Iterate

- After changing the Rust server, rebuild it from the repository root with
  `cargo build --locked -p registry-language-server`. Add
  `"registryStack.languageServer.path": "/absolute/path/to/target/debug/registry-language-server"`
  to the generated workspace settings, then run **Registry Stack: Restart Language Server**.
- After changing the extension, rerun `npm run package:dev`, reinstall the VSIX with `--force`,
  and run **Developer: Reload Window**.
- Run `npm test` after building `registry-language-server` to launch the Extension Host test for
  multi-root behavior and declared workspace capabilities. On headless Linux, use
  `xvfb-run -a npm test`.

## Troubleshooting

- If activation does not occur, confirm each intended workspace folder root itself contains
  `registry-stack.yaml`, `evidence-project.yaml`, or a `source.openapi.yaml` beside a `questions`
  directory, and that VS Code trusts the workspace. Opening only a YAML file or a parent directory
  does not activate it. Select **Workspaces: Manage Workspace Trust**, trust the reviewed project,
  and run **Registry Stack: Restart Language Server**.
- If startup reports that no server was found, set `registryStack.languageServer.path` to the
  standalone executable built for source iteration. Otherwise, add `registry-language-server` to
  `PATH`, or ensure a matching `registryctl` or `evidencectl` is on the environment inherited by VS
  Code and restart the language server. The output message names the project folder that failed.
- If navigation is absent, confirm the file's VS Code language mode is YAML and inspect the output
  channel named for that workspace folder.
- Red Hat YAML still owns schema validation, completion, hover, formatting, and syntax errors. Its
  diagnostics do not indicate a Registry Stack language-server failure.

## Remove the extension

```console
code --uninstall-extension registrystack.registry-stack
```

VS Code also supports installing the VSIX through **Extensions: Install from VSIX**. See the
[official VSIX instructions](https://code.visualstudio.com/docs/configure/extensions/extension-marketplace#_install-from-a-vsix)
for profile and command-line alternatives.
