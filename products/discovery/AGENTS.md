# Discovery guidance

This guide covers `registry-discovery`, `registry-discoveryctl`,
`registry-discovery-profile`, and Discovery product material. Client work also
follows [client guidance](../../crates/CLIENTS.md).

Discovery is a curated index of public provider advertisements. Origin
provenance, a valid profile, and a resolved selection establish no provider
trust or caller authority. The relying application accepts the endpoint under
its own trust configuration and invokes the native Evidence or Relay client.
Discovery carries no credentials and proxies no native operation.

`registry-discovery-profile` owns only the closed provider publication model
shared with Evidence and Relay. Origins, mappings, index records, revisions,
queries, and client handoff belong outside that crate. The profile's pinned
JSON-LD context is a local contract resource; parsing does not fetch contexts,
expand RDF, resolve remote references, or merge graphs.

`discoveryctl` builds indexes outside the serving runtime, fetching only exact
operator-approved origins within fixed bounds. A failure leaves the previous
output intact.
The runtime serves one immutable index until restart. Keep records scoped to
their origin, preserve exact capability pairs and mapping provenance, and
reject ambiguous selection. Evidence matching retains the complete AND-list;
Relay matching retains the correlated semantic-class/operation-family pair.
Persisted selections remain inert and require current local acceptance;
provenance renewal must not silently accept changed service semantics.

Use [DECISIONS.md](DECISIONS.md) for these ownership and identity rules,
[profile/README.md](profile/README.md) for the publication profile,
`contracts/standards-profile.yaml` for precise alignment claims, and relevant
rows of `contracts/security-invariant-matrix.yaml` and
`contracts/security-test-traceability.yaml` for refusal tests. Standards
alignment is a selected subset, not a full DCAT-AP conformance claim.
`catalogRevision` binds the normalized semantic projection, not timestamps or
every byte of a rebuilt index.

Select focused tests in the changed crate, then the applicable product gate
from the monorepo root:

```sh
products/discovery/scripts/check-contracts.sh
products/discovery/scripts/test-http.sh
products/discovery/scripts/test-adopter-tutorial.sh
```

The contract gate checks publication artifacts and traceability. HTTP tests
exercise runtime queries; the adopter journey proves selection, explicit local
acceptance, and native-client handoff. Keep that composition straightforward:
one metadata selection, an explicit application trust decision, then the
existing native client, without a new proxy or trust service.
Profile changes also affect Evidence and Relay publication, so verify those
producers' projections. Keep query values, full descriptions, origin documents,
credentials, and subject data out of problems, logs, and traces.
