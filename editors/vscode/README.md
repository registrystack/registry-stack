# Registry Stack for VS Code

This extension starts `registry-language-server` for a workspace whose root contains
`registry-stack.yaml`. It adds cross-file definitions, references, workspace/document symbols,
and Registry Stack reference diagnostics. Red Hat YAML remains responsible for YAML syntax,
schema validation, completion, formatting, and ordinary hover information.

## Package, install, and launch

Prerequisites are Node.js 22, the `code` command-line tool, and the Rust toolchain used by the
repository. First complete the [shared smoke-project setup](../README.md#local-end-to-end-smoke-test).

1. Package and install the extension from this directory:

   ```console
   cd "$REGISTRY_STACK_REPO/editors/vscode"
   npm ci
   npm run package:dev
   code --install-extension ./registry-stack-dev.vsix --force
   ```

   `package:dev` type-checks the source, bundles its runtime dependencies, and creates an
   installable VSIX. The explicit install affects the active VS Code profile.

2. Open the smoke project as the workspace root:

   ```console
   code --new-window "$REGISTRY_STACK_SMOKE_PROJECT"
   ```

3. Run **Preferences: Open Workspace Settings (JSON)** and add this property to the existing
   generated settings object, replacing the example with the absolute value of
   `$REGISTRY_STACK_REPO`:

   ```json
   "registryStack.languageServer.path": "/absolute/path/to/registry-stack/target/debug/registry-language-server"
   ```

4. Run **Registry Stack: Restart Language Server**. Open **View: Toggle Output**, select
   **Registry Stack Language Server**, and confirm it reports the smoke project as indexed.
5. Complete the [shared expected-behavior checklist](../README.md#expected-behavior). VS Code uses
   `F12` for definitions, `Shift+F12` for references, `Cmd+Shift+O`/`Ctrl+Shift+O` for document
   symbols, and `Cmd+T`/`Ctrl+T` for workspace symbols.

The source VSIX does not contain a platform server binary. Instead of the explicit setting, the
extension can find `registry-language-server` on `PATH`, then fall back to
`registryctl authoring language-server` when `registryctl` is on `PATH`.

## Iterate

- After changing the Rust server, rebuild it from the repository root with
  `cargo build --locked -p registry-language-server`, then run
  **Registry Stack: Restart Language Server**.
- After changing the extension, rerun `npm run package:dev`, reinstall the VSIX with `--force`,
  and run **Developer: Reload Window**.

## Troubleshooting

- If activation does not occur, confirm the opened workspace root itself contains
  `registry-stack.yaml`. Opening only a YAML file or a parent directory does not activate it.
- If startup reports that no executable was found, verify the workspace setting is an absolute
  path to an executable regular file.
- If navigation is absent, confirm the file's VS Code language mode is YAML and inspect the
  **Registry Stack Language Server** output channel.
- Red Hat YAML still owns schema validation, completion, hover, formatting, and syntax errors. Its
  diagnostics do not indicate a Registry Stack language-server failure.

## Remove the development extension

```console
code --uninstall-extension registrystack.registry-stack
```

VS Code also supports installing the VSIX through **Extensions: Install from VSIX**. See the
[official VSIX instructions](https://code.visualstudio.com/docs/configure/extensions/extension-marketplace#_install-from-a-vsix)
for profile and command-line alternatives.
