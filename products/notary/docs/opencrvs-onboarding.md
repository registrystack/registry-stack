# OpenCRVS onboarding model

> **Page type:** Explanation · **Product:** Registry Notary · **Layer:**
> evaluation, signing posture · **Audience:** integrator

The OpenCRVS recipe in `registryctl` is a local onboarding path for
integrators who already have OpenCRVS credentials. It generates a Registry
Notary project that can validate configuration and evaluate a starter
birth-record claim without asking the user to hand-write Notary YAML before the
first success.

For commands, use the Registry Docs tutorial, "Verify OpenCRVS claims with
registryctl."

## Project boundary

The generated project has three trust zones:

- OpenCRVS credentials in `.env`.
- Registry Notary local demo credentials in `secrets/notary.local.env`.
- Inspectable generated configuration in `notary/config.yaml` and
  `registryctl.yaml`.

OpenCRVS remains the source registry. Registry Notary asks OpenCRVS an evidence
question, applies the configured claim rule, and returns a claim result. The
generated project does not issue OpenCRVS credentials and does not make Registry
Notary a copy of the OpenCRVS registry.

## Evidence question

The starter question is:

```text
Does this UIN have a birth registration record in the configured OpenCRVS source?
```

The generated claim id is:

```text
opencrvs-birth-record-exists
```

The generated Notary config uses the `dci` source connector, the
`/registry/sync/search` source path, a birth registry event type, and a configured lookup on
`target.identifiers.UIN`. The default disclosure is `value`, which means
callers receive the truth of the claim rather than a copied source record.

## Signing literacy

Registry Notary signs credentials when a configured credential flow is used. The
OpenCRVS recipe generates a local demo issuer key and one demo credential
profile named `opencrvs_birth_record_sd_jwt`.

That local key is not a production trust root. It is generated for one local
project, stored in `secrets/notary.local.env`, and referenced from
`notary/config.yaml` by environment variable name. Do not reuse it across
deployments. For production signing posture, use the signing key provider
reference and a deployment-specific hardening process.

The demo profile can issue only the `opencrvs-birth-record-exists` claim from a
stored evaluation result. OpenCRVS supplies evidence; Registry Notary signs the
demo SD-JWT VC. That credential is not an OpenCRVS-issued credential and should
not be treated as production trust material.

## PDP literacy

A policy decision point (PDP) is the component that decides whether a request is
permitted under a policy. A policy enforcement point (PEP) is the component that
enforces that decision at runtime. In a Registry Notary deployment, Notary is
the enforcement point for its evaluation routes.

Authentication and scopes happen before a governed PDP decision. If a caller
lacks the required Notary scope for a claim, that is an authentication or
authorization failure at the Notary boundary, not proof that a governed PDP
denied the request.

The OpenCRVS starter project introduces this model but does not configure a
governed PDP. The shipped local path checks API credentials, claim scopes,
source lookup configuration, and the claim rule. Do not describe the smoke test
as a governed policy decision unless the runtime config includes a governed PDP
integration and the audit output records that provenance.

## What to inspect first

After generation, inspect these files:

- `.env`: OpenCRVS base URL, client ID, and client secret names.
- `secrets/notary.local.env`: local Notary API key, audit secret, replay URL,
  and demo issuer key.
- `registryctl.yaml`: manifest, recipe, env files, and output directory.
- `notary/config.yaml`: source connector, claim id, lookup field, disclosure
  policy, signing key reference, and demo credential profile.
- `output/notary-smoke-results.json`: redacted smoke evidence.

The generated config may contain the OpenCRVS base URL because Notary needs a
literal source route. It must not contain raw OpenCRVS client secrets, bearer
tokens, test UINs, API keys, or private issuer key values.

## Next

- [OpenCRVS tutorial](opencrvs-dci-standalone-tutorial.md) for the lower-level Notary-only
  OpenCRVS tutorial.
- [Source claim modeling guide](source-claim-modeling-guide.md) for source bindings, disclosure, and
  claim rules.
- [Signing key provider](signing-key-provider.md) and [Deployment hardening runbook](deployment-hardening-runbook.md) for
  production signing and deployment hardening.
