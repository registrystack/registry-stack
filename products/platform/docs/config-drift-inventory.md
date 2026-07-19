# Registry configuration inventory

The Registry Stack monorepo keeps a lightweight inventory of Relay operator,
demo, performance, profile, and parser-test configuration. It helps reviewers
find configuration surfaces that may need coordinated changes when a shared
platform type or security invariant changes.

Run the inventory from the monorepo root:

```sh
products/platform/scripts/audit-configs.sh --check --format markdown
```

The `--check` gate fails when an expected configuration root moves or
disappears without the inventory being updated. The generated output is the
authoritative current file list, so this document does not carry a dated copy
that can silently become stale.

The inventory annotates files that mention static authentication, fingerprints,
OIDC, audit configuration, or SD-JWT credentials. Those annotations are review
prompts, not proof that the configuration is secure or migration-complete.

The current roots are:

| Surface | Monorepo path |
| --- | --- |
| Relay operator examples | `crates/registry-relay/config/` |
| Relay demos | `crates/registry-relay/demo/config/` |
| Relay performance fixtures | `crates/registry-relay/perf/config/` |
| Relay integration profiles | `crates/registry-relay/profiles/` |
| Relay parser fixtures | `crates/registry-relay/tests/fixtures/config/` |

Notary currently has no equivalent checked-in operator configuration tree.
Its product policy, API contracts, test vectors, and deployment configuration
are verified by their owning root CI gates rather than being mislabeled as a
platform config inventory.
