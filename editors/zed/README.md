# Registry Stack for Zed

This beta integration is installed from a Registry Stack source release.
It is not yet listed in Zed Extensions and no release artifact is provided.
Set up a project with `python3 editors/configure.py <product> <project>` before
opening it. The helper uses the current product's maintained schemas and check
commands where they exist. For Evidence, it runs the existing
`evidencectl tooling editor` command. Install this integration for semantic navigation.

This extension attaches the shared Registry Stack language server to Zed's built-in YAML and JSON languages.
It provides cross-file definitions, references, workspace/document symbols, and Registry Stack
reference diagnostics for the current product authoring projects. Zed's YAML language server
remains responsible for YAML syntax, schema validation, formatting, and ordinary hover information.

## Install and launch

Zed requires Rust installed through `rustup`, the `zed` command-line tool, and a matching
`evidencectl`. Run the installer once from the repository root:

```console
./editors/install.sh zed
```

The installer checks a matching adopter CLI and embedded language server, installs the required
`wasm32-wasip2` target when missing, compile-checks the Zed extension, and prints its absolute path.
It does not read or change a project.

1. Complete the [shared smoke-project setup](../README.md#local-end-to-end-smoke-test), then open it
   from the same shell so Zed inherits the matching adopter CLI:

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

## Supported projects

The shared server covers Base Registry Engine, Casework, Scheduling, Messaging, Discovery,
Manifest, Render, Evidence OID4VCI, and Evidence authoring projects. Run
`python3 editors/configure.py <product> <project>` from this source checkout to set up
editor settings and check tasks. Manifest and Evidence OID4VCI projects with an arbitrary
authored YAML filename need `--document <project-relative.yaml>`; the helper writes a
project marker so the language server can identify that file.

The Zed extension launches the same language server for every product. A matching
`evidencectl` supplies it for all project families; the launcher does not
need a separate server binary for each product.

Rhai request-preparation and derivation scripts (`*.rhai`) get no support from this extension: no
`tree-sitter-rhai` grammar is bundled or referenced here, so an open `.rhai` file gets neither
syntax highlighting nor a language server from Registry Stack. This is a known gap in the current
integration, not a defect to work around.

Zed's extension API has no worktree-root predicate, so this extension cannot identify a
Registry Stack worktree before attaching; see the note at the end of this file for what that
means in practice.

## Iterate

- After changing the Rust server, run `cargo build --locked -p registry-language-server`, then
  set the worktree's `.zed/settings.json` to the absolute path of that build and run
  `editor: restart language server`:

  ```json
  {
    "lsp": {
      "registry-stack": {
        "binary": {
          "path": "/absolute/path/to/registry-stack/target/debug/registry-language-server"
        }
      }
    }
  }
  ```

  If the server runs through an adopter CLI instead, set `path` to that CLI and
  `arguments` to `["tooling", "language-server"]`. Zed also accepts `binary.env` for
  per-worktree environment overrides. Clear the `binary` setting to return to PATH selection.
- After changing the Zed launcher, install the development extension again from the same directory
  and restart the language server.

## Troubleshooting

- If the development extension does not compile, confirm `rustup` owns the active Rust installation
  and that `cargo check` for `wasm32-wasip2` passes.
- If Zed cannot find the server, close it, export the updated `PATH`, and relaunch it from that
  terminal. The launcher uses the first `evidencectl` on `PATH`, accepts only a CLI
  reporting this extension's version (or that version with `-dev`), and checks that it answers
  `tooling language-server --help`. It does not look past that first copy: if it is old or lacks
  the server, remove it from `PATH` or put the matching copy ahead of it, then relaunch Zed.
  A standalone `registry-language-server` has no version command; select
  it through `lsp.registry-stack.binary.path` when iterating on source.
- Use `dev: open language server logs` to inspect how the server was launched. Use
  `zed: open log` for extension errors. For verbose extension output, close Zed and relaunch it with
  `zed --foreground "$REGISTRY_STACK_SMOKE_PROJECT"`.
- Confirm the project has its product's authored root file or the helper's
  `.registry-stack-editor/project.json` marker, and the active file language is YAML or JSON.

The Extensions page identifies a successful local install as a development extension. Remove it
from that page after the smoke test if you do not want the override to remain active.

Zed does not permit shipping an external language server inside the extension.
The current Zed extension API registers a language server against a language name, but has no
worktree-root predicate for Registry Stack authoring markers.
The integration therefore attaches to YAML and JSON while the development extension remains installed.
It has no Registry Stack behavior without a server binary, but Zed can log a missing-server error
when you open unrelated YAML or JSON in another worktree.
Keep the development extension installed only while using a Registry Stack project, and remove
it afterwards to avoid that noise.
See Zed's official
[development-extension instructions](https://zed.dev/docs/extensions/developing-extensions#developing-an-extension-locally)
for the current installation and logging workflow.
