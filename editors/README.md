# Registry Stack editor integrations

The Registry Stack editor support is split into one reusable language server and thin editor
launchers:

- `../crates/registry-language-server` owns project indexing, navigation, symbols, and Registry
  Stack reference diagnostics.
- `vscode` launches the server through VS Code's language-client API.
- `zed` launches the same server through Zed's extension API.

These integrations intentionally run alongside each editor's YAML language server. The generated
`.vscode/settings.json` and `.zed/settings.json` files continue to provide version-matched schema
validation and YAML completion without duplicating that behavior here.

## Local end-to-end smoke test

Run the commands in this section from the repository root. They build both server entry points and
create a disposable HTTP starter outside the checkout, so the diagnostic checks below cannot
modify a tracked golden project.

```console
export REGISTRY_STACK_REPO="$(pwd)"
export REGISTRY_STACK_SMOKE_ROOT="$(mktemp -d)"
export REGISTRY_STACK_SMOKE_PROJECT="$REGISTRY_STACK_SMOKE_ROOT/project"
cargo build --locked -p registry-language-server -p registryctl
cargo run --locked -p registryctl -- init --from http --project-dir "$REGISTRY_STACK_SMOKE_PROJECT"
```

Keep that terminal open so the three variables remain available. Then follow the editor-specific
installation and launch instructions:

- [VS Code](vscode/README.md#package-install-and-launch)
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
cargo test --locked -p registry-language-server
cargo test --locked -p registryctl --test language_server
```

When finished, close the smoke project and remove the temporary directory shown by
`$REGISTRY_STACK_SMOKE_ROOT` after checking that it is the directory created by `mktemp` above.
