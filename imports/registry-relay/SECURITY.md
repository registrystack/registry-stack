# Security

## Supported Versions

Registry Relay is pre-1.0. Security fixes are targeted at the current `main`
branch until release branches are introduced.

## Reporting a Vulnerability

Please do not open a public issue for suspected vulnerabilities.

Use GitHub private vulnerability reporting for this repository:

https://github.com/jeremi/registry-relay/security/advisories/new

If GitHub advisories are unavailable, contact Jeremi through an existing private
project channel before opening a public issue or pull request. Do not open
public issues for suspected API-key disclosure, authentication bypass, scoped
data exposure, audit redaction failure, source connector data leakage, or
configuration reload authorization bugs.

Include the affected version or commit, relevant config shape, reproduction
steps, impact, and any known workaround. Do not include live credentials, bearer
tokens, API keys, database URLs, private source paths, or raw registry records
in the report.

We aim to acknowledge private reports within 5 business days.

In scope for this policy: authentication bypass, scope enforcement failure,
API-key or bearer-token disclosure, audit redaction failure, audit integrity
failure, protected metadata or row exposure beyond configured scopes, source
connector data leakage, unsafe admin reload behavior, and privacy regressions
that expose raw subject identifiers.

Known pilot limitations such as read-only operation, no built-in provisioning
or write API, no hosted key-management service, no end-user consent workflow,
and evidence offerings that only advertise Registry Notary endpoints should be
reported as product gaps unless they create an exploitable security or privacy
issue beyond the documented limitation. Optional standards adapters and
provenance credential responses are deployment-configured surfaces; report
security issues there when the adapter exposes data, credentials, or metadata
outside the configured scopes or documented public routes.
