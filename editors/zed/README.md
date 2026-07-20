# Registry Stack for Zed

This beta integration is installed from a Registry Stack source release.
It is not yet listed in Zed Extensions and no release artifact is provided.
For the stable beta path, run `registryctl init --from <starter>` or
`registryctl authoring editor --project-dir <project>` and use the generated YAML schema settings.
Install this integration for optional semantic navigation.

This extension attaches `registry-language-server` to Zed's built-in YAML language. It adds
cross-file definitions, references, workspace/document symbols, and Registry Stack reference
diagnostics. Zed's YAML language server remains responsible for YAML syntax, schema validation,
completion, formatting, and ordinary hover information.

## Install and launch

Zed requires Rust installed through `rustup`, the `zed` command-line tool, and the `registryctl`
version that matches this source checkout. Run the installer once from the repository root:

```console
./editors/install.sh zed
```

The installer checks the matching `registryctl` and embedded language server, installs the required
`wasm32-wasip2` target when missing, compile-checks the Zed extension, and prints its absolute path.
It does not read or change a project.

1. Complete the [shared smoke-project setup](../README.md#local-end-to-end-smoke-test), then open it
   from the same shell so Zed inherits the matching `registryctl`:

   ```console
   zed "$REGISTRY_STACK_SMOKE_PROJECT"
   ```

   Alternatively, `./editors/install.sh zed --open "$REGISTRY_STACK_SMOKE_PROJECT"` prepares the
   extension and opens the directory without configuring it.
2. Run **Zed: Install Dev Extension** from the command palette and select the extension path printed
   by the installer. Zed requires this explicit approval because its CLI cannot install a local
   development extension.
3. Run `editor: restart language server`, then `dev: open language server logs`. Select
   `registry-stack` for the smoke project and confirm the server log reports that the project was
   indexed. Use `zed: open log` instead for extension compilation or launcher failures.
4. Complete the [shared expected-behavior checklist](../README.md#expected-behavior). Zed uses
   `F12` for definitions, `Alt+Shift+F12` for references, `Cmd+Shift+O`/`Ctrl+Shift+O` for document
   symbols, and `Cmd+T`/`Ctrl+T` for workspace symbols.

The installer cannot approve the development extension on the user's behalf. This is a deliberate
Zed trust boundary, not missing automation.

## Iterate

- After changing the Rust server, run `cargo build --locked -p registry-language-server`, then
  put `target/debug` before `registryctl` on the environment inherited by Zed, then run
  `editor: restart language server`.
- After changing the Zed launcher, install the development extension again from the same directory
  and restart the language server.

## Troubleshooting

- If the development extension does not compile, confirm `rustup` owns the active Rust installation
  and that `cargo check` for `wasm32-wasip2` passes.
- If Zed cannot find the server, close it, export the updated `PATH`, and relaunch it from that
  terminal. The launcher first looks for `registry-language-server`, then runs
  `registryctl authoring language-server` when `registryctl` is on `PATH`. The two executables must
  come from the same checkout or beta build that you are testing.
- Use `dev: open language server logs` to inspect how the server was launched. Use
  `zed: open log` for extension errors. For verbose extension output, close Zed and relaunch it with
  `zed --foreground "$REGISTRY_STACK_SMOKE_PROJECT"`.
- Confirm the project root contains `registry-stack.yaml` and the active file language is YAML.

The Extensions page identifies a successful local install as a development extension. Remove it
from that page after the smoke test if you do not want the override to remain active.

Zed does not permit shipping an external language server inside the extension.
The current Zed extension API registers a language server against a language name, but has no
worktree-root predicate for `registry-stack.yaml`.
The integration therefore attaches to YAML while the development extension remains installed.
It has no Registry Stack behavior without a server binary, but Zed can log a missing-server error
when you open unrelated YAML in another worktree.
Keep the development extension installed only while using a Registry Stack project, and remove
it afterwards to avoid that noise.
See Zed's official
[development-extension instructions](https://zed.dev/docs/extensions/developing-extensions#developing-an-extension-locally)
for the current installation and logging workflow.
