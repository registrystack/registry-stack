# registryctl

`registryctl` is the adopter CLI for authoring, testing, reviewing, developing,
and packaging Registry Stack projects.

Download the latest released installer without cloning the repository:

```sh
curl -fsSLo registryctl-install.sh https://docs.registrystack.org/install.sh
```

The stable URL serves the installer from the latest promoted Registry Stack
documentation release. The quick installer trusts Registry Docs hosting,
GitHub, and TLS, then verifies downloaded artifacts against the release
checksums. The separate download and execution steps preserve download
failures and let you inspect the installer's tag-frozen `verify_url` before
running it. Use [`release/VERIFY.md`](../../release/VERIFY.md) when you need to
authenticate release signatures and provenance before installation.

Run the installer after applying the verification policy you need:

```sh
bash registryctl-install.sh
```

## Newcomer workflow

Create a project from a tested embedded template, exercise its offline
fixtures, and start the disposable local runtime:

```sh
registryctl init my-registry --template spreadsheet
cd my-registry
registryctl test
registryctl dev
```

The ordinary workflow is:

```text
init -> test -> dev -> check -> build
```

`registryctl dev` prints loopback endpoints, source mode, the ready-to-run
request, and the exact `smoke`, `logs`, and `down` follow-up commands. Add
`--detach` to return after startup. Runtime state, credentials, and trust are
disposable development inputs and are not production inputs.

Use `--template http` instead when connecting an existing registry API.
Both public starters use the same lifecycle commands.

Use the project-independent lifecycle commands when needed:

```sh
registryctl dev status
registryctl dev logs
registryctl dev smoke
registryctl dev down
```

## Governed handoff

Review and build unsigned product-lane inputs before independent trust owners
sign them and assemble an approved set:

```sh
registryctl review compare
registryctl build
registryctl trust --help
registryctl deploy --help
```

`deploy generate` creates a governed package but does not activate it.
`deploy verify` checks package ownership, freshness, and hard invariants.

## Project selection and reports

Commands discover `registry-stack.yaml` from the current directory upward.
Use `-C <directory>` to select a project explicitly. Environment selection is,
in order, `--environment`, `REGISTRYCTL_ENVIRONMENT`, the authored project
default, or the sole declared environment.

Human output is the default. Commands that support machine output accept only:

```sh
--format human
--format json
```

JSON output is one strict versioned document. Registryctl does not perform
automatic update checks or background network activity.

## Authoring tools

Static schemas, references, editor mappings, diagnostics, and the language
server are grouped under `tooling`:

```sh
registryctl tooling schema --kind project
registryctl tooling reference configuration
registryctl tooling editor
registryctl tooling diagnostics --catalog authoring --format json
registryctl tooling language-server
```

`test` executes deterministic offline fixtures through production semantics.
`check` validates and explains authored intent without writing build state.
`build` emits deterministic unsigned signing inputs.

## Host and release readiness

```sh
registryctl doctor --profile local
```

Doctor is read-only. It validates the authored environment, the signed
`registry-release-lock.v1.json` installed beside the running executable,
Docker installation and daemon availability, Docker Compose 2.35.0 or later,
and local availability of every exact digest-locked image. It never pulls
images or writes project state. `--profile` selects diagnostics only and does
not change an operating contract.

## Development

Use the repository-provided checks from the workspace root. For focused work:

```sh
cargo fmt --check
cargo clippy -p registryctl --all-targets -- -D warnings
cargo test -p registryctl
```
