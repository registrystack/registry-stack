# Registry Discovery

Registry Discovery is a curated, read-only index of public Evidence service
descriptions. It helps an application find advertisements. It does not
establish provider trust, authorize a caller, proxy a native request, issue a
credential, or carry credentials.

The first provider representation is the closed
`registry-discovery-v1alpha1` JSON-LD profile. The public profile resources
are in `profile/`; product decisions, security traceability, and Definition of
Done are in `contracts/`.

The profile uses a deliberately selected DCAT 3 / DCAT-AP 3.0.1 / BRegDCAT-AP
alignment subset. It claims neither full DCAT-AP nor BRegDCAT-AP conformance.
The pinned versions and terms are in `contracts/standards-profile.yaml`.

The relying-party SDK is available in Rust as `registry-discovery-client`, and
in Node.js and Python as the `discovery` namespace of the maintained Registry
Stack client packages. All three perform the same bounded, product-specific
search and ambiguity-safe selection. Evidence selections retain the complete
resolved AND-list and mapping provenance. Persisted selections can be revalidated
before local trust accepts them and their advertised base URL is handed to the
native Evidence client. A selection remains inert public metadata, not a trust
decision or native request.

The published `registry-discovery-v1alpha1` profile resources remain unchanged
and still validate historical Relay descriptions. Current Rust publication,
index, query, and client contracts support Evidence only. Operators must remove
Relay origins and rebuild a mixed pre-retirement index before starting a current
runtime.
Starting with Registry Stack v0.26.1, install the Node.js package as
`@registrystack/client@<version>` or the Python package as
`registry-stack-client==<version>`, using the SDK version selected by the recommended Stack distribution.
Discovery and discoveryctl can also ship together under an independent
`discovery/vX.Y.Z` release. A newer compatible Discovery patch does not require
republishing the SDK; use a combination named in the distribution or release notes. The Python distribution imports as `registry_client`.

Run `scripts/check-contracts.sh` to validate the resources and their
traceability. The normal operator flow, owned by `discoveryctl`, is offline
`check`, one explicit `package`, deployment of the immutable package directory,
then restart. The runtime verifies `SHA256SUMS` and an optional
`package.expectedDigest` pin before consuming the exact packaged index bytes.

`discoveryctl api` has no local `--client` credential adapter. Discovery's
endpoint is public, so the product resolver directs operators to an anonymous
saved connection. The shared CLI also permits an operator to deliberately
select an explicit or saved authenticated connection, but that credential is
operator-supplied transport state: it is never derived from catalog metadata,
creates no Discovery authority, and does not make Discovery a native-provider
proxy. Endpoint and request handling follow the shared
[`registry-cli-api` security boundary](../../crates/registry-cli-api/README.md#security-boundary).
`api_and_saved_connections_are_available_without_a_runtime_config` in
`crates/registry-discoveryctl/tests/api_cli.rs` pins the product surface; the
shared README names the transport and credential tests. These are maintained
references, not claims of execution here.

## Independent release installation

For a published Discovery unit release, download its `discovery-vX.Y.Z-install.sh`
from the `discovery/vX.Y.Z` GitHub Release, authenticate its checksum chain as
explained in [release verification](../../release/VERIFY.md), then run it. The
installer installs both `discovery` and `discoveryctl` on Linux amd64. Set
`DISCOVERY_INSTALL_DIR` to choose the destination and `DISCOVERY_ASSET_DIR` to
use already verified offline assets. It requires an explicit version or the
version embedded in a release installer, because GitHub's latest release names
the recommended Stack distribution.

The client accepts additive HTTP response members while rejecting duplicate
members, invalid known values, and unsupported service kinds. Persisted
selections, provider descriptions, and server configuration remain strict.

## HTTP problems

Discovery uses the [shared problem contract](../platform/HTTP-PROBLEMS.md),
including fixed safe `detail`, `family.reason` `code`, and a `traceId` matching
`traceparent`. Existing problem type URIs remain stable. An indeterminate
503 has no synthetic Retry-After interval.
