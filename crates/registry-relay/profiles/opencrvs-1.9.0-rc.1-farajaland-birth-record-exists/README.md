# OpenCRVS birth-record existence consultation profile

This directory contains a Registry Stack-maintained, unofficial reference
profile for one complete journey: determine whether one exact Farajaland UIN
has one registered OpenCRVS birth record, then return only a boolean through
Registry Notary.

The profile pins the OpenCRVS DCI adapter at `v1.9.0-rc.1`, the compatible
OpenCRVS Event API shape, and Farajaland country configuration `v1.9.5`. It is
country-specific on purpose. Another country can reuse the closed executor but
must review and hash its own UIN grammar and birth-record schema rather than
loosening this pack.

## Closed product journey

Every consultation performs exactly three same-origin exchanges under one
20-second durable deadline and without retries. Each individual exchange is
also capped at 10 seconds:

1. POST client credentials to `/oauth2/client/token` and accept the exact
   two-member, no-expiry bearer response. The token is never cached.
2. GET a fresh `/.well-known/jwks.json` containing exactly one RS256 signing
   key and one RSA-OAEP-256 encryption key.
3. POST an unsigned, Relay-generated DCI exact search to
   `/registry/sync/search`, requesting at most two birth records for the
   canonical UIN.

Relay verifies the compact RS256 signature before using the response. It also
checks the exact unsigned sibling, request correlation, sender identity,
pagination, closed envelope and record schemas, and that every returned
record's first UIN identifier equals the requested UIN. Zero records is
`no_match`, one is `match`, and two or a larger declared total is `ambiguous`.

The pinned adapter necessarily returns a complete birth-person record. Relay
therefore validates that complete acquisition honestly, but the profile uses
`presence_only` output. The Relay response contains `{}` for a match and never
contains the UIN, name, sex, date of birth, parent identifiers, source URL,
token, JWKS, signature, or native response. Notary derives only `true` or
`false` from the signed cardinality outcome. Ambiguity and every contract
violation fail closed.

## Operator journey

1. Review `integration-pack.json`, `public-contract.json`, and the three
   evidence files. A different country form, identifier grammar, adapter
   release, purpose, or source shape requires a new pack version.
2. Copy `private-binding.example.json`. Replace the deployment identities and
   the single HTTPS origin. Keep both destination application base paths at
   root, keep the data and credential origins equal, and retain distinct
   destination ids.
3. Update the private-binding raw digest in the Relay configuration after any
   authorized binding change. Do not change the public pack or contract hashes
   for deployment-only values.
4. Put the OAuth client id and secret, Relay audit secret, PostgreSQL URL, and
   audit-pseudonym material in the secret store under the environment names in
   `relay-config.example.yaml`. No credential value belongs in YAML or Git.
5. Run `registry-relay doctor`, bootstrap the dedicated PostgreSQL consultation
   state as documented in the operations runbook, and start Relay with only
   its runtime database identity.
6. For a combined Relay and Notary deployment, initialize the maintained
   OpenCRVS Registry Stack project with `registryctl init --from opencrvs` and
   build its compiler-pinned product inputs. Do not hand-author a second Notary
   copy of this Relay profile. Notary receives no OpenCRVS URL or OAuth
   credential.
7. Run the project-owned offline fixtures and `registryctl check --explain`
   before applying deployment-only source and workload bindings.

The example configurations use local deployment posture and placeholder
identities. Production deployments must use the signed configuration-bundle
path, durable replay protection, managed secret delivery, PostgreSQL backups,
and the deployment's reviewed network allowlist.

Readiness verifies only the authenticated, hash-pinned Relay profile metadata.
It does not acquire a token, fetch JWKS, send a UIN, or call OpenCRVS. This
keeps operator health checks safe and predictable while every actual
consultation still uses fresh source authorization and verification material.

Repository conformance fixtures and source review do not claim OpenCRVS
maintainer endorsement, a country deployment, or a successful positive-record
interoperability result. Positive proof requires an explicitly authorized UIN;
it must never be discovered by broad source enumeration or copied into test
evidence.
