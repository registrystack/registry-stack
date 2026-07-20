# Registry Stack editor integrations

Semantic navigation for VS Code and Zed is installable from a Registry Stack source release.
The integrations are beta features and are not yet marketplace extensions or release assets.
Use `registryctl init --from <starter>` and its generated editor schema setup as the stable beta
path for YAML validation, completion, hover, and formatting.
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
registryctl authoring editor --project-dir /path/to/registry-stack-project
```

Install the `registryctl` version that matches this source checkout, then install an integration
once from the repository root:

```console
./editors/install.sh vscode
./editors/install.sh zed
```

The installer verifies the `registryctl` version and embedded language server without reading or
changing a project. VS Code is packaged and installed into the active profile. Pass
`--profile <existing-name>` to select another VS Code profile. The local VSIX records the verified
`registryctl` path, so an already-running VS Code process does not need to inherit the installer's
`PATH`. Zed is compiled, then requires the command-palette selection that its CLI cannot perform.

The installer does not trust a project or approve a development extension. Those decisions stay
with the user. Pass `--open <existing-directory>` only as a convenience to open a directory after
installation. It does not configure that directory. Use `--help` for the complete interface.

## Local end-to-end smoke test

Run the commands in this section from the repository root. They create a disposable HTTP starter
outside the checkout, so the diagnostic checks below cannot modify a tracked golden project.

```console
export REGISTRY_STACK_SMOKE_ROOT="$(mktemp -d)"
export REGISTRY_STACK_SMOKE_PROJECT="$REGISTRY_STACK_SMOKE_ROOT/project"
registryctl --version
registryctl init --from http --project-dir "$REGISTRY_STACK_SMOKE_PROJECT"
```

Keep that terminal open so the two variables remain available. Then follow the editor-specific
installation and launch instructions:

- [VS Code](vscode/README.md#install-and-launch)
- [Zed](zed/README.md#install-and-launch)

### Expected behavior

Use the following checks in either editor:

1. Confirm the Registry Stack language-server output or log says that the project was indexed.
2. In `registry-stack.yaml`, invoke **Go to Definition** on the value in
   `integration: person-record`. It must open the `id` in
   `integrations/person-record/integration.yaml`.
3. Invoke **Go to Definition** on `person_record` in `output: person_record.active`. It must jump
   to the `consultations.person_record` key in the same manifest.
4. Invoke **Go to Definition** on `person-active` in the `person-status` profile's `claims` list.
   It must jump to the `claims.person-active` definition.
5. Open `integrations/person-record/fixtures/active.yaml` and invoke **Go to Definition** on
   `person-active` under `expect.claims`. It must jump back to the manifest claim.
6. Open `environments/local.yaml` and invoke **Go to Definition** on the `person-record`
   integration key. It must open the integration definition.
7. Invoke **Find References** on the integration definition. Results must include the manifest
   alias, consultation reference, and environment binding.
8. Search workspace symbols for `person`. Results must include the registry, integration, service,
   consultation, claims, credential profile, and fixture symbols. The document outline for
   `registry-stack.yaml` must list its Registry Stack symbols.
9. Temporarily change `integration: person-record` to `integration: missing-source`. The editor
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
