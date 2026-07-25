# Registry Notary

> **Experimental:** This product is pre-1.0. Its configuration and API may change before the first stable release.

Registry Notary evaluates purpose-bound claims, applies disclosure policy, and
issues credentials. Registry-backed evidence enters Notary only through an
authenticated, compiler-pinned Registry Relay consultation. Notary does not
hold registry destinations or source credentials and does not execute source
adapters.

A Registry Stack project may deploy:

- Relay only, for governed source access, materialization, or records APIs;
- Notary only, for source-free self-attested evaluation and rendering; or
- Relay and Notary, for claims derived from Relay consultation outcomes and outputs.

Credential issuance is available only in a combined Relay and Notary project.
Every credential claim must come from a freshly executed, compiler-pinned Relay
consultation. Source-free claims remain evaluation-only and cannot belong to a
credential profile or OID4VCI configuration.

Notary keeps independent authority over caller authentication, purpose,
service policy, claim evaluation, disclosure, credential issuance, and its own
audit chain. Relay keeps independent authority over source acquisition,
normalization, protocol verification, typed outputs, and its audit chain.

See [`docs/README.md`](docs/README.md) for product documentation. Use
Registry Stack project authoring and `registryctl` to generate deployable
Relay and Notary inputs. Do not hand-author source access inside Notary.

## Layout

- `crates/registry-notary-core`: domain, configuration, claim, disclosure,
  audit, and credential contracts.
- `crates/registry-notary-server`: HTTP routes, strict Relay client, claim
  evaluation, credential issuance, federation, and operational surfaces.
- `crates/registry-notary-client`: typed Rust client and local credential verification.
- `crates/registry-notary`: process startup, diagnostics, config verification,
  and OpenAPI generation.
- `bindings/python` and `bindings/node`: application client bindings.
- `docs`: integrator and operator references.
- `specs`: implementation records and design history.

## Local run

Generate or build a Registry Stack project first, then pass the resulting
Notary configuration explicitly:

```bash
just run config=/absolute/path/to/generated/notary.yaml
```

The binary fails closed when caller authentication is not configured. A
Registry-backed configuration also fails startup and readiness when its Relay
semantic contract or hash does not match the compiled expectation.

## Verification

From the Registry Stack monorepo root, use the product preflight and workspace
gates documented in `AGENTS.md`. Product-local focused checks include:

```bash
just ci-preflight
just openapi-check
just exposure-check
python3 -m unittest discover -s tests -p '*_test.py'
```

## Distribution and security

The product crates are not published to crates.io. Consume the Registry Notary
container using a release tag or immutable digest. Report vulnerabilities
through GitHub Security Advisories as described in the repository security
policy.

Apache-2.0. See [`LICENSE`](LICENSE).
