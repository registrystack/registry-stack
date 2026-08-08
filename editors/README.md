# Registry Stack editor integrations

Semantic navigation for VS Code and Zed is installable from a Registry Stack source release.
The integrations are beta features and are not yet marketplace extensions or release assets.
Use `registryctl init <directory> --template http` and its generated editor schema setup as the
stable beta path for YAML validation, completion, hover, and formatting.
Install the editor integration when you also want optional cross-file semantic navigation.

The Registry Stack editor support is split into one reusable language server and thin editor
launchers:

- `../crates/registry-language-server` owns project indexing, navigation, symbols, and Registry
  Stack reference diagnostics.
- `vscode` launches the server through VS Code's language-client API.
- `zed` launches the same server through Zed's extension API.

These integrations intentionally run alongside each editor's YAML language server.
The generated `.vscode/settings.json` and `.zed/settings.json` files continue to provide
version-matched schema validation and YAML completion without duplicating that behavior here.

The language server watches Registry Stack YAML paths for changes made by generators, Git, or
other tools. An open editor buffer remains authoritative until it is closed, so a filesystem event
cannot replace unsaved content.

## Install

Project setup and editor installation are separate operations. `registryctl init` configures new
projects automatically. For an existing project, refresh its version-matched schema settings with:

```console
registryctl -C /path/to/registry-stack-project tooling editor
```

Install the `registryctl` or `evidencectl` version that matches this source checkout, then install
an integration once from the repository root:

```console
./editors/install.sh vscode
./editors/install.sh zed
```

The installer verifies a CLI's version and embedded language server without reading or changing a
project. It tries `registryctl` first and `evidencectl` next, and a candidate that fails either
check does not stop the one behind it, so an Evidence adopter holding an older `registryctl` still
installs. VS Code is packaged and installed into the active profile. Pass
`--profile <existing-name>` to select another VS Code profile. The local VSIX records the verified
CLI path, so an already-running VS Code process does not need to inherit the installer's `PATH`.
Zed is compiled, then requires the command-palette selection that its CLI cannot perform.

The installer does not trust a project or approve a development extension. Those decisions stay
with the user. Pass `--open <existing-directory>` only as a convenience to open a directory after
installation. It does not configure that directory. Use `--help` for the complete interface.

## Evidence projects

The same language server and editor launchers also serve an Evidence authoring project. There is
no separate Evidence editor integration: one client per workspace folder covers both project
families, and neither `vscode` nor `zed` branches on which one a folder is.

A folder is an Evidence project root when it contains the `evidence-project.yaml` marker, or, for
a project created before the marker existed, the legacy pair of a `source.openapi.yaml` file and a
`questions` directory. Either form gets the same cross-file definitions, references,
workspace/document symbols, and reference diagnostics over its authoring documents (selectors,
questions, sources, access policies, and the schemas they cite) that a `registry-stack.yaml` root
gets for Relay.

Project setup and schema refresh mirror the Relay commands, spelled with `evidencectl` instead of
`registryctl`:

```console
evidencectl new /path/to/evidence-project
evidencectl tooling editor --project /path/to/evidence-project
```

`evidencectl tooling editor` writes the same kind of project-local, version-matched YAML schema
mappings that `registryctl tooling editor` writes for a Relay project. Run it again after changing
the authoring project's shape.

Two gaps to know about before relying on this for Evidence work:

- The language server completes Evidence YAML values it can name a candidate for: cross-file
  references (source, selector profile, operation, and question names, and similar) and the fact
  paths a source's operation makes selectable. Manually invoking completion (Ctrl+Space) always
  returns that list, because the server answers an invoked request and one opened by a trigger
  character (`:`, `.`, `/`) identically. An automatic popup while typing inside a string, without
  invoking it, still needs `editor.quickSuggestions.strings: true`, since VS Code decides whether
  to ask at all before the request reaches the server. Two things get no candidates from this
  server at all: a mapping key, whose completion comes from the generated schema through the
  `redhat.vscode-yaml` extension rather than from here, and a source's `request.prepareScript` and
  `extractScript` pointers, which the project index does not walk into references yet.
- Rhai request-preparation and derivation scripts (`*.rhai`) get no editor behavior from this
  integration in either editor. Neither the VS Code client's document selector nor the Zed
  extension associates `.rhai` files with the language server yet; the watcher that reindexes a
  project on an external change to one is not the same as offering completion, diagnostics, or
  navigation inside it.

## Local end-to-end smoke test

Run the commands in this section from the repository root. They create a disposable HTTP starter
outside the checkout, so the diagnostic checks below cannot modify a tracked golden project.

```console
export REGISTRY_STACK_SMOKE_ROOT="$(mktemp -d)"
export REGISTRY_STACK_SMOKE_PROJECT="$REGISTRY_STACK_SMOKE_ROOT/project"
registryctl --version
registryctl init "$REGISTRY_STACK_SMOKE_PROJECT" --template http
```

Keep that terminal open so the two variables remain available. Then follow the editor-specific
installation and launch instructions:

- [VS Code](vscode/README.md#install-and-launch)
- [Zed](zed/README.md#install-and-launch)

### Expected behavior

Use the following checks in either editor:

1. Confirm the Registry Stack language-server output or log says that the project was indexed.
2. In `registry-stack.yaml`, invoke **Go to Definition** on `person-record` in the consultation's
   `integration: person-record` field. It must open the `id` in
   `integrations/person-record/integration.yaml`.
3. Invoke **Go to Definition** on `person-record` under the manifest's top-level `integrations:`
   mapping. It must open the same integration definition.
4. Open `environments/local.yaml` and invoke **Go to Definition** on the `person-record` key under
   `integrations:`. It must open the same integration definition.
5. Open `integrations/person-record/integration.yaml` and invoke **Find References** on
   `person-record` in the `id` field. Results must include the manifest alias, the consultation's
   integration reference, and the environment binding.
6. Search workspace symbols for `person`. Results must include the integration, service,
   consultation, and fixture symbols. The document outline for `registry-stack.yaml` must list its
   registry, service, and consultation symbols.
7. Temporarily change `integration: person-record` to `integration: missing-source`. The editor
   must report `Unknown integration reference 'missing-source'`. Restore `person-record` and
   confirm that the diagnostic clears.

The YAML language server may report additional schema or syntax diagnostics. Those are expected
and are separate from diagnostics whose source is `registry-stack`.

### Automated checks

The same core behavior has non-GUI coverage:

```console
bash editors/tests/install_test.sh
cargo test --locked -p registry-language-server
cargo test --locked -p registryctl --test language_server
cargo build --locked -p registry-language-server
cd editors/vscode && npm ci && npm test
```

The VS Code test launches the minimum supported VS Code release line in an Extension Host. It
checks activation, the trust and virtual-workspace declarations, external file reloads, and the
addition and removal of Registry Stack folders in a multi-root workspace. On headless Linux, run
it as `xvfb-run -a npm test`, matching CI.

When finished, close the smoke project and remove the temporary directory shown by
`$REGISTRY_STACK_SMOKE_ROOT` after checking that it is the directory created by `mktemp` above.

## Develop the language server from source

The installer deliberately uses the matching `registryctl` from `PATH`, which exercises the
language server embedded in the installed release. To iterate on language-server source changes,
build the standalone server and configure the editor to use it explicitly:

```console
cargo build --locked -p registry-language-server
```

Follow the editor-specific iteration instructions to point the editor at
`target/debug/registry-language-server` and restart it.
