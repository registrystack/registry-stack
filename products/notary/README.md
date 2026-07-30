# Registry Notary

> **Experimental:** This product is pre-1.0. Its configuration and API may change before the first stable release.

Registry Notary evaluates purpose-bound claims, applies disclosure policy, and
issues credentials. Registry-backed evidence enters Notary only through an
authenticated, compiler-pinned Registry Relay consultation. Notary does not
hold registry destinations or source credentials and does not execute source
adapters.

A Registry Stack project may deploy:

- Relay only, for governed source access, materialization, or records APIs;
- Notary without configured claims, for an empty control-plane deployment; or
- Relay and Notary, for claims derived from Relay consultation outcomes and outputs.

Every evaluable claim must derive from exactly one compiler-pinned Relay
consultation. Credential issuance is available only from a freshly executed
Relay-backed evaluation with the exact required provenance.

Notary keeps independent authority over caller authentication, purpose,
service policy, claim evaluation, disclosure, credential issuance, and its own
audit chain. Relay keeps independent authority over source acquisition,
normalization, protocol verification, typed outputs, and its audit chain.

The evidence consumer determines how returned evidence is used. The decision
owner remains accountable for requirements, eligibility, qualification,
prioritization, approval, referral, payment, workflow, and action policy.
Notary may attest a decision that an authoritative source already made when
the claim is named and documented as source-owned, but Notary does not
recompute consumer policy.

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
