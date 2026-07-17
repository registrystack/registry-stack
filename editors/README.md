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
