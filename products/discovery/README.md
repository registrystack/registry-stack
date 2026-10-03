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
`registry-stack-client==<version>`, using the exact version that matches the
deployment. The Python distribution imports as `registry_client`.

Run `scripts/check-contracts.sh` to validate the resources and their
traceability. The normal operator flow, owned by `discoveryctl`, is offline
`check`, one explicit `package`, deployment of the immutable package directory,
then restart. The runtime verifies `SHA256SUMS` and an optional
`package.expectedDigest` pin before consuming the exact packaged index bytes.
