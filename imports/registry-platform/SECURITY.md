# Security Policy

## Supported Versions

`registry-platform` is pre-1.0 and consumed by Registry Relay and Registry Notary through pinned git tags. Security fixes are released on the newest tag line only unless Jeremi explicitly opens a backport lane for a consumer migration.

| Version | Supported |
| --- | --- |
| `0.3.x` | Yes, newest supported tag is `v0.3.2` |
| Untagged branches | No |

## Reporting a Vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories for `github.com/jeremi/registry-platform`. If GitHub advisories are unavailable, contact Jeremi through an existing private project channel before opening a public issue or pull request.

Please include:

- The affected crate, function, middleware, script, or workflow.
- Reproduction steps, test case, or exploit sketch.
- Impacted consumers, if known: Registry Relay, Registry Notary, or both.
- Whether secrets, key material, audit integrity, outbound fetching, auth, OIDC, SD-JWT issuance, or config migration are involved.

Do not include live credentials, bearer tokens, private keys, customer data, or full environment dumps.

## Handling Expectations

Security fixes should land first in this platform repo, then propagate to consumers through a coordinated tag bump. When a vulnerability affects duplicated consumer code that has not yet migrated, the fix must identify both the platform change and the temporary consumer-side mitigation.

## Disclosure

Public disclosure waits until the fix is tagged, affected consumers are updated or have an approved mitigation, and release notes describe the operator action required.
