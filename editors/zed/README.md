# Registry Stack for Zed

This extension attaches `registry-language-server` to Zed's built-in YAML language. It adds
cross-file definitions, references, workspace/document symbols, and Registry Stack reference
diagnostics. Zed's YAML language server remains responsible for YAML syntax, schema validation,
completion, formatting, and ordinary hover information.

## Install and launch

Zed requires Rust installed through `rustup` to compile development extensions. First complete the
[shared smoke-project setup](../README.md#local-end-to-end-smoke-test), then verify the required Zed
WebAssembly target from the repository root:

```console
rustup target add wasm32-wasip2
cargo check --locked --target wasm32-wasip2 --manifest-path editors/zed/Cargo.toml
```

1. Put the freshly built language server on the environment inherited by Zed, then open the smoke
   project from the same terminal:

   ```console
   export PATH="$REGISTRY_STACK_REPO/target/debug:$PATH"
   zed "$REGISTRY_STACK_SMOKE_PROJECT"
   ```

2. Run `zed: install dev extension` from the command palette and select
   `$REGISTRY_STACK_REPO/editors/zed`. Zed compiles and installs the WebAssembly extension.
3. Run `editor: restart language server`, then `dev: open language server logs`. Select
   `registry-stack` for the smoke project and confirm the server log reports that the project was
   indexed. Use `zed: open log` instead for extension compilation or launcher failures.
4. Complete the [shared expected-behavior checklist](../README.md#expected-behavior). Zed uses
   `F12` for definitions, `Alt+Shift+F12` for references, `Cmd+Shift+O`/`Ctrl+Shift+O` for document
   symbols, and `Cmd+T`/`Ctrl+T` for workspace symbols.

## Iterate

- After changing the Rust server, run `cargo build --locked -p registry-language-server`, then
  `editor: restart language server` in Zed.
- After changing the Zed launcher, install the development extension again from the same directory
  and restart the language server.

## Troubleshooting

- If the development extension does not compile, confirm `rustup` owns the active Rust installation
  and that `cargo check` for `wasm32-wasip2` passes.
- If Zed cannot find the server, close it, export the updated `PATH`, and relaunch it from that
  terminal. The launcher looks for `registry-language-server`, then `registryctl`.
- Use `dev: open language server logs` to inspect how the server was launched. Use
  `zed: open log` for extension errors. For verbose extension output, close Zed and relaunch it with
  `zed --foreground "$REGISTRY_STACK_SMOKE_PROJECT"`.
- Confirm the project root contains `registry-stack.yaml` and the active file language is YAML.

The Extensions page identifies a successful local install as a development extension. Remove it
from that page after the smoke test if you do not want the override to remain active.

Zed does not permit shipping an external language server inside the extension. This launcher first
looks on `PATH` for `registry-language-server`, then falls back to
`registryctl authoring language-server`. See Zed's official
[development-extension instructions](https://zed.dev/docs/extensions/developing-extensions#developing-an-extension-locally)
for the current installation and logging workflow.
