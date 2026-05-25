# Security

Report vulnerabilities privately through GitHub Security Advisories:

`https://github.com/jeremi/registry-witness/security/advisories/new`

If GitHub advisories are unavailable, contact Jeremi through an existing private
project channel before opening a public issue or pull request. Do not open
public issues for suspected credential disclosure, auth bypass, audit redaction
failure, source connector data leakage, or signing key handling bugs.

Include the affected commit, config shape, reproduction steps, and impact. Do
not include live credentials, bearer tokens, API keys, private keys, or raw
registry records in the report.

We aim to acknowledge private reports within 5 business days.

In scope for this policy: authentication bypass, credential disclosure, audit
redaction failure, audit integrity failure, signing-key handling bugs, source
connector data leakage, and privacy regressions that expose raw subject
identifiers.

Known pilot limitations such as no revocation service, no
`/.well-known/jwt-vc-issuer` endpoint, and no built-in data-subject erasure
workflow should be reported as product gaps unless they create an exploitable
security or privacy issue beyond the documented limitation.
