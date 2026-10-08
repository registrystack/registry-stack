# Registry Stack editor integrations

Semantic navigation for VS Code and Zed is installable from a Registry Stack source checkout.
The integrations are beta features and are not yet marketplace extensions or release assets.
The integrations follow the workspace version in `Cargo.toml`. Build the
adopter CLI from the same source as the extension when using unreleased main.
Install an integration for definitions, references, symbols, reference-value
completion, and hover across the current products' authored YAML and JSON. Schema
validation, mapping-key completion, and formatting remain with the editor's
YAML language server.

The Registry Stack editor support is split into one reusable language server and thin editor
launchers:

- `../crates/registry-language-server` owns project indexing, navigation, symbols,
  and Registry Stack reference diagnostics for every product family below.
- `vscode` launches the server through VS Code's language-client API.
- `zed` launches the same server through Zed's extension API.

These integrations intentionally run alongside each editor's YAML language server.
Project setup writes `.vscode/settings.json` and `.zed/settings.json` with
version-matched schemas where the product publishes them. Product validators
remain authoritative for rules that require compilation or runtime configuration.

The language server watches Registry Stack authored files for changes made by generators, Git, or
other tools. An open editor buffer remains authoritative until it is closed, so a filesystem event
cannot replace unsaved content.

## Product coverage

| Product | Project entry | Semantic navigation |
|---|---|---|
| Base Registry Engine | `registry.yaml` declaring `RegistryProject` | Entities, fields, access profiles, actions, and authored modules |
| Registry Casework | `casework.yaml` | Sources, queues, routing, review policies, and directory references |
| Registry Scheduling | `scheduling.yaml` | Services, locations, offerings, opening patterns, holiday sets, and fixture references |
| Registry Messaging | `messaging.yaml` | Templates and versions, access profiles, providers, and template files |
| Registry Discovery | `origins.yaml` | Origin and mapping declarations across the project |
| Registry Manifest | `metadata.yaml`, or an explicitly selected document | Datasets, entities, fields, codelists, services, forms, and their references |
| Registry Render | `manifest.yaml` declaring `RenderBundle` | Documents and their template, schema, and locale files |
| Evidence wallet delivery | Explicitly selected configuration | Configuration sections and contained, configuration-relative key-file navigation |
| Evidence | `evidence-project.yaml`, or the legacy OpenAPI/questions pair | Questions, sources, selectors, policies, facts, and authored file references |

Each family uses its own names and scopes. A BReg `registry.yaml` never receives
diagnostics from another product. Discovery's remote vocabulary identifiers are not unresolved
local references. The server does not fetch remote descriptions, execute scripts,
query databases, or read private key bytes. Navigation to a contained key file
opens it only when the author requests that editor action.

See the [language-server reference](../crates/registry-language-server/README.md)
for the indexed relationships and their boundaries. These integrations navigate
YAML references to scripts and templates; they do not implement the scripting
languages' own language servers.

## Configure a project

From the source checkout, use Python 3.10 or newer to prepare both editors:

```console
python3 editors/configure.py breg /path/to/registry-project
python3 editors/configure.py scheduling /path/to/scheduling-project
python3 editors/configure.py manifest /path/to/metadata-project --document publication.yaml
python3 editors/configure.py evidence-oid4vci /path/to/issuer --document config/wallet.yaml
```

The product argument also accepts `casework`, `messaging`, `discovery`,
`render`, `evidence`, and `platform` (a directory holding a task connection
file, `task-connection.yaml`). Manifest and wallet-delivery setup records the
selected document in `.registry-stack-editor/project.json`, so an arbitrary
configuration filename can be recognized without claiming unrelated YAML.

Setup copies maintained schemas from this checkout and adds a **Registry Stack:
check** task where the product supplies a validation command. Use **Tasks: Run
Task** in VS Code or **task: spawn** in Zed. No validator is run automatically
when a file opens. Casework, Scheduling, and Messaging currently publish runtime
schemas; their policy/package validation comes from their check task. Render
maps its bundle `manifest.yaml`, its `labels/*.yaml` tables, and a `runtime.yaml`
beside them. Manifest maps the selected document to the metadata manifest
schema and every `profile.yaml` below the project to the profile descriptor
schema. Platform maps `task-connection.yaml` and checks it with `evidencectl
dev check`. Wallet delivery has no maintained authoring JSON schema.

For multiple product directories in one workspace, pass `--workspace` with the
ancestor directory. Schema mappings name the specific project's paths so one
product's `runtime.yaml` does not inherit another's grammar. Setup preserves
unrelated JSON settings and tasks and refreshes its own unchanged entries. It
refuses edited managed files or JSONC it cannot merge without losing comments;
the error identifies the file to resolve before retrying. Rerun setup from the
matching checkout after upgrading. The generated setup contains local paths;
regenerate it when moving a workspace.

Evidence retains its canonical `tooling editor` schema generator.
The shared helper invokes the matching Evidence CLI. Schema setup and
CLI tasks can be used without installing the semantic extension.

## Install

Project setup and editor installation are separate operations. Refresh a
project's version-matched schema settings with its adopter CLI:

```console
evidencectl tooling editor /path/to/evidence-project
```

Install the `evidencectl` version that matches this source checkout, then install
an integration once from the repository root:

```console
./editors/install.sh vscode
./editors/install.sh zed
```

The installer verifies a CLI's version and embedded language server without reading or changing a
project. It checks the first `evidencectl` on `PATH` and stops with an error when that copy
does not match this checkout or carries no language server. VS Code is packaged and installed into the active profile. Pass
`--profile <existing-name>` to select another VS Code profile. The local VSIX records the verified
CLI path, so an already-running VS Code process does not need to inherit the installer's `PATH`.
Zed is compiled, then requires the command-palette selection that its CLI cannot perform.
At startup both launchers check that a CLI still matches the extension version,
including the matching `-dev` version. VS Code skips a copy that does not match and tries the
next `evidencectl` on `PATH`. Zed checks the first `evidencectl` on `PATH` and reports an error
when it does not match.

The installer does not trust a project or approve a development extension. Those decisions stay
with the user. Pass `--open <existing-directory>` only as a convenience to open a directory after
installation. It does not configure that directory. Use `--help` for the complete interface.

## Evidence projects

The same language server and editor launchers also serve an Evidence authoring project. There is
no separate Evidence editor integration: one client per workspace folder covers
the product families it contains.

A folder is an Evidence project root when it contains the `evidence-project.yaml` marker, or, for
a project created before the marker existed, the legacy pair of a `source.openapi.yaml` file and a
`questions` directory. Either form gets the same cross-file definitions, references,
workspace/document symbols, and reference diagnostics over its authoring documents (selectors,
questions, sources, access policies, and the schemas they cite) that a `registry.yaml` root
gets for supported products.

Project setup and schema refresh use `evidencectl`:

```console
evidencectl new /path/to/evidence-project
evidencectl tooling editor /path/to/evidence-project
```

`evidencectl tooling editor` writes project-local, version-matched YAML schema
mappings. Run it again after changing the authoring project's shape.

## Local end-to-end smoke test

Run the commands in this section from the repository root. They create a disposable Evidence
starter outside the checkout, so the diagnostic checks below cannot modify a tracked project.

```console
export REGISTRY_STACK_SMOKE_ROOT="$(mktemp -d)"
export REGISTRY_STACK_SMOKE_PROJECT="$REGISTRY_STACK_SMOKE_ROOT/project"
evidencectl --version
evidencectl init "$REGISTRY_STACK_SMOKE_PROJECT" --transport sqlite-extract --profile local
evidencectl tooling editor "$REGISTRY_STACK_SMOKE_PROJECT"
```

Keep that terminal open so the two variables remain available. Then follow the editor-specific
installation and launch instructions:

- [VS Code](vscode/README.md#install-and-launch)
- [Zed](zed/README.md#install-and-launch)

### Expected behavior

Use the following checks in either editor:

1. Confirm the Registry Stack language-server output or log says that the project was indexed.
2. In `questions/record-status.yaml`, invoke **Go to Definition** on `record-status` in the
   question's `source: {ref: record-status}` binding. It must open `sources/record-status.yaml`.
3. Invoke **Find References** on that same name. Results must include the question's binding.
4. Invoke **Go to Definition** on `record-reference-v1` in `profile: record-reference-v1`. It
   must open `selectors/record-reference-v1.yaml`.
5. Search workspace symbols for `record`. Results must include the `record-status` question, the
   `record-status` source, and the `record-reference-v1` selector profile. The document outline
   for `questions/record-status.yaml` must list the question and its `condition_satisfied`
   answer.
6. Temporarily change the question's source reference to `ref: missing-source`. The editor must
   report `Unknown source reference 'missing-source'`. Restore `record-status` and confirm that
   the diagnostic clears.

The YAML language server may report additional schema or syntax diagnostics. Semantic
diagnostics identify their product in the source, such as `evidence` or `breg`. The editor
indexes authored documents only and performs no source request.

### Automated checks

The same core behavior has non-GUI coverage:

```console
bash editors/tests/install_test.sh
python3 -m unittest discover -s editors/tests -p 'test_*.py'
cargo test --locked -p registry-language-server
cargo build --locked -p registry-language-server
cd editors/vscode && npm ci && npm test
```

Check the Zed launcher from the repository root:

```console
cargo test --locked --manifest-path editors/zed/Cargo.toml
cargo check --locked --target wasm32-wasip2 --manifest-path editors/zed/Cargo.toml
```

The VS Code test launches the minimum supported VS Code release line in an Extension Host. It
checks activation, the trust and virtual-workspace declarations, external file reloads, and the
addition and removal of Registry Stack folders in a multi-root workspace. On headless Linux, run
it as `xvfb-run -a npm test`, matching CI.

When finished, close the smoke project and remove the temporary directory shown by
`$REGISTRY_STACK_SMOKE_ROOT` after checking that it is the directory created by `mktemp` above.

## Develop the language server from source

The installer deliberately uses a matching `evidencectl` from `PATH`, which exercises the
language server embedded in the installed release. To iterate on language-server source changes,
build the standalone server and configure the editor to use it explicitly:

```console
cargo build --locked -p registry-language-server
```

Follow the editor-specific iteration instructions to point the editor at
`target/debug/registry-language-server` and restart it.
The standalone development server has no version probe and is selected through
an explicit editor setting. It is not selected automatically from `PATH`.

When opening a new workspace release version, update the VS Code package and
lockfile plus the Zed extension, crate, and lockfile versions together. VSIX
packaging checks the extension version against the source workspace version.
