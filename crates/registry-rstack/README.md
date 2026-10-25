# Registry Stack command and local installer

`rstack` is the public command for a managed local Registry Stack installation.
It selects one release generation and dispatches product commands from that
generation. The managed installation adds only `rstack` to the public executable
directory; service binaries and their images remain independently runnable for
deployment.

The release-pinned installer is published as `rstack-vX.Y.Z-install.sh`. Download
it and the release verification material from the same release, then follow
[`release/VERIFY.md`](../../release/VERIFY.md) to authenticate the checksum
bundle. For an exact release, run:

```sh
bash rstack-vX.Y.Z-install.sh
rstack components list
rstack install breg evidence
rstack breg --help
rstack evidence check --help
```

The first command installs the launcher alone. Pass component names to the
installer, or use `--all`, to install them during bootstrap. The installable
product names are `breg`, `casework`, `discovery`, `evidence`, `manifest`,
`messaging`, `render`, `scheduling`, and `coordinator`, subject to availability
in the exact release and platform. A selection that mixes available and
unavailable products fails as a whole. A component's release payload includes
its required runtime and companion files, with a capability inventory in the
release manifest.

The defaults are `~/.local/bin` for the public `rstack` link and
`~/.local/lib/registrystack` for generations. Use `--bin-dir` and
`--install-root` on the installer and on later `rstack` calls if you override
them. To use assets already obtained and verified, pass `--asset-dir DIR` to the
installer or component manager. The installer checks every staged asset against
the release manifest and `SHA256SUMS`; that checksum comparison alone does not
authenticate the publisher.

```sh
rstack --format json components list
rstack --format json doctor
rstack install casework
rstack update --release vX.Y.Z --preview
rstack update --release vX.Y.Z
rstack uninstall casework
rstack cleanup
rstack uninstall --all
```

`--format` is `human` or `json`, and defaults to `human` even when output is
piped. An explicit report format reaches finite product report actions.
Artifact and foreground-service commands reject an inapplicable report format
and keep their output streams unchanged. `--preview`
checks an exact update and reports its component and download changes without
activation. An exact downgrade is refused. Updating or changing components
activates a complete new generation; an invocation already using the previous
one holds a lease until it exits. `cleanup` removes only inactive owned
generations whose leases have ended. `uninstall --all` removes the managed
installation and refuses changed or unrelated paths rather than deleting
them. These operations do not roll back a database or service deployment.

For scripts, use `--format json` and the report's `schema_version`, `status`
where present, and process exit status. A refusal has one JSON object on stdout
and exits `1` for a domain refusal, `2` for invalid usage, or `3` for an
operational failure. Help is available without an installation:
`rstack help breg`, `rstack breg --help`, and their `--format json` forms use
the offline command catalogue. `rstack doctor` checks the selected generation
and executable path, including whether a different `rstack` shadows it on
`PATH`.

## Call a running service

Product API commands use the same connection and HTTP conventions:

```sh
rstack breg api /v1/records/contacts --client editor
rstack breg connection add pilot
rstack breg api /v1/records/contacts --connection pilot
```

Local client selection reuses the ready project's endpoint and acquires a
fresh credential. The guided connection setup saves a remote endpoint and
credential references once. `connection use NAME` selects a default for the
current product project, including calls from its subdirectories; explicit
connection names also work outside a project.

`api` defaults to GET, or POST with `--input FILE` (`-` reads stdin). It
writes the HTTP response bytes directly; `--output`, `--include`, `--accept`,
and repeated `--header` options handle files and content negotiation. A
refused HTTP response retains its body and exits 1. Usage exits 2 and
operational failures exit 3. Requests are sent once. Product authorization,
mutation revisions, idempotency keys, and Evidence verification retain their
own API meanings. See [API connections](../../docs/site/src/content/docs/configure/api-connections.mdx)
for local and remote setup.

## Command migration

| Previous local command | Managed command |
| --- | --- |
| `bregctl` | `rstack breg` |
| `caseworkctl` | `rstack casework` |
| `discoveryctl` | `rstack discovery` |
| `evidencectl` | `rstack evidence` |
| `registry-manifest` | `rstack manifest` |
| `messagingctl` | `rstack messaging` |
| `registry-render` | `rstack render` |
| `schedulingctl` | `rstack scheduling` |
| `coordinatorctl` | `rstack coordinator` |
| `breg-mcp` | `rstack breg mcp` |
| `breg-review` | `rstack breg review` |
| `evidence-oid4vci` | `rstack evidence oid4vci` |

Scripts that invoke the old executable names must update their commands or
continue using a separately managed binary installation. Product artifact
format and destination flags retain their own meanings; in particular,
Manifest's `--format human|json` selects report encoding on report actions;
`render` uses `--artifact-format` for artifact bytes, and `--output` names
the artifact destination where applicable. The local manager does not rewrite
deployment configuration or install shell completion files. `rstack completions zsh`
prints completion source for an operator to install explicitly.
