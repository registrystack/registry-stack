# Registry Discovery

Registry Discovery is a curated, read-only index of public Evidence and Relay
service descriptions. It helps an application find advertisements. It does not
establish provider trust, authorize a caller, proxy a native request, issue a
credential, or carry credentials.

The first provider representation is the closed
`registry-discovery-v1alpha1` JSON-LD profile. The public profile resources
are in `profile/`; product decisions, security traceability, and Definition of
Done are in `contracts/`.

The profile uses a deliberately selected DCAT 3 / DCAT-AP 3.0.1 / BRegDCAT-AP
alignment subset. It claims neither full DCAT-AP nor BRegDCAT-AP conformance.
The pinned versions and terms are in `contracts/standards-profile.yaml`.

Run `scripts/check-contracts.sh` to validate the resources and their
traceability. The normal operator flow, owned by `discoveryctl`, is offline
`check`, one explicit `build`, deployment of an immutable index, then restart.
