# Registry Stack for VS Code

This beta integration follows the Registry Stack release version and is installed from its source
release. It is not yet published to the VS Code Marketplace and no release VSIX is provided.
The shared language server provides semantic navigation for all current Registry Stack products.

Project roots use each product's own authoring marker:

| Product | Marker |
|---|---|
| Base Registry Engine | `registry.yaml` declaring `BRegProject` |
| Evidence | `evidence-project.yaml`, or `source.openapi.yaml` beside `questions/` |
| Registry Casework | `casework.yaml` declaring `CaseworkProject` |
| Registry Scheduling | `scheduling.yaml` declaring `SchedulingProject` |
| Registry Messaging | `messaging.yaml` declaring `MessagingProject` |
| Registry Discovery | `origins.yaml` declaring the Discovery origins schema |
| Registry Render | `manifest.yaml` declaring `RenderBundle` |
| Registry Manifest | `metadata.yaml` declaring `registry-manifest/v1`, or an explicit editor marker |
| Evidence OID4VCI | An explicit editor marker naming its configuration document |

An explicit marker is `.registry-stack-editor/project.json` with a `product` of `manifest` or
`evidence-oid4vci` and a `document` naming an existing YAML file relative to the project.
The shared editor configurator writes it for adopter-chosen filenames. A generic `runtime.yaml`
alone cannot distinguish products. Markers and declared document paths must be regular local files
and directories.

A workspace folder that is itself a project starts its language server immediately. For a project
nested below a workspace folder, opening its first YAML or JSON document starts one language server
for the containing workspace folder; the server discovers the project by walking upward from that
document. This avoids recursively scanning the workspace from the extension. The server adds
cross-file definitions, references, workspace/document symbols, and product reference diagnostics.
Red Hat YAML remains responsible for YAML syntax, schema validation, completion, formatting, and
ordinary hover information. Product CLI checks remain responsible for complete package validation.

Multi-root workspaces are supported. The extension starts at most one isolated language-server
process for each eligible local workspace folder and responds when workspace folders are added or
removed. One process serves every product project discovered inside that folder. Because
the server executes a local binary and reads local files, the extension is disabled in untrusted
and virtual workspaces.

## Install and launch

Prerequisites are Node.js 22 or newer, the `code` command-line tool, and a matching
`evidencectl`, which embeds the language server.

Configure the project's maintained schemas and native validation task from the repository root:

```console
python3 editors/configure.py breg /path/to/project
```

Use the product name from the [shared setup guide](../README.md). For a project nested below the
opened workspace folder, add `--workspace /path/to/workspace`. Manifest files with a custom name use
`--document custom.yaml`; Evidence OID4VCI requires `--document wallet-config.yaml`. The configurator
writes the explicit marker for those two families, adds available schema mappings, and preserves
existing editor settings and tasks. Evidence schema setup runs through the matching
`evidencectl`. See the shared guide for products whose validation remains a native CLI check.

1. From the repository root, install the integration into the active VS Code profile:

   ```console
   ./editors/install.sh vscode
   ```

   The installer checks the version and embedded language server of the first `evidencectl` on
   `PATH`, packages the extension, and installs it without
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
`evidencectl` on `PATH` matching the extension release version.
A source build reporting the same version with `-dev` is also accepted.
The explicit setting runs the executable directly. Installer-selected and PATH adopter CLIs run
`<cli> tooling language-server`; the standalone server runs directly.
Installer metadata and PATH candidates are checked for a matching version and the hosted-server
subcommand before use. Replacing the installer-selected executable with a different release therefore
falls through to PATH discovery. A standalone development build has no version probe; select it
explicitly with `registryStack.languageServer.path`. A manually packaged VSIX omits the local path metadata and retains the PATH-based
discovery behavior.

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
- For a macOS source build linked to a dynamic AWS-LC FIPS library, set
  `REGISTRY_STACK_TEST_LIBRARY_PATH` to its Cargo build artifact directory when running `npm test`.
  Test-only launcher wrappers restore that loader path after Electron strips `DYLD_*` variables.
  Installed release CLIs use their packaged libraries.

## Troubleshooting

- If activation does not occur, confirm the workspace contains a product marker from the table
  above and that VS Code trusts the workspace. For a project below the workspace-folder root, open one of that
  project's YAML or JSON documents to start its folder's language server. Select **Workspaces: Manage
  Workspace Trust**, trust the reviewed project, and run **Registry Stack: Restart Language
  Server** if needed.
- If startup reports that no server was found, set `registryStack.languageServer.path` to the
  standalone executable built for source iteration. Otherwise, ensure a matching `evidencectl` is on the environment inherited by VS
  Code and restart the language server. The output message names the project folder that failed.
- If navigation is absent, confirm the file's VS Code language mode is YAML or JSON and inspect the output
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
