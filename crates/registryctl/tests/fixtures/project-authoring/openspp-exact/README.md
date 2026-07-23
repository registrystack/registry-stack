# OpenSPP exact-lookup owner holdout

This workspace is offline-fixture-only pending the OpenSPP product-owner proof
in [GH#357](https://github.com/registrystack/registry-stack/issues/357).
It is not a supported public starter, evidence of live OpenSPP compatibility,
or an E2 interoperability claim.

The committed HTTP path, query, fields, version label, identifiers, and
responses describe a synthetic wire shape.
They do not assert that an OpenSPP release exposes this API.

## Run the offline workspace

Run these commands from the repository root:

```sh
cd crates/registryctl/tests/fixtures/project-authoring/openspp-exact
registryctl test --project-dir . --integration individual --fixture social-registry-match --trace
registryctl test --project-dir . --integration individual --fixture social-registry-match --watch
registryctl test --project-dir .
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
```

The watch command runs the selected fixture once, waits for an authored file to
change, and reruns it.
Press `Ctrl+C` after observing the rerun.
The other commands exit after reporting their result.

`test` uses synthetic fixtures and an implementation-owned offline binding.
It does not contact the origin in `environments/local.yaml`.
`check` and `build` validate that environment, but the `.invalid` origins and
placeholder secret references are deliberately non-deployable.

## Prepare the owner-run workspace

Use a private copy of this workspace from one tagged Registry Stack release
that contains both
[PR #355](https://github.com/registrystack/registry-stack/pull/355) and
[PR #364](https://github.com/registrystack/registry-stack/pull/364).
Record the tag and use the matching `registryctl`, Relay image, Notary image,
and published image digests.
Atomically pin the candidate adopter deployment to those artifacts.
Do not use a source build, a branch image, the retired monorepo `lab/`, shared
Relay or Notary state, or a hand-edited generated YAML file.
Each Relay authority needs its own dedicated Notary and Notary-owned PostgreSQL
state.

Select and record one exact OpenSPP version and one read-only operation before
editing the workspace.
Replace every fictional assumption in the private copy:

| File | Fields to replace and review |
| --- | --- |
| `integrations/individual/integration.yaml` | Replace `id` and the `source.versions.unverified` fixture label with the reviewed integration identity and exact selected OpenSPP version. Classify that version under `source.versions.tested` only after the owner evidence is accepted. |
| `integrations/individual/integration.yaml` | Replace the input name, type, length, pattern, HTTP method, relative path, query, no-match statuses, authentication type, response format, and response-size bound with the selected read-only operation's contract. |
| `integrations/individual/integration.yaml` | Replace output names, types, lengths, and `x-registry-source` pointers. Reassess the `ambiguity` and `subject_mismatch` not-applicable rationales. Add fixtures when either outcome is applicable. |
| `integrations/individual/fixtures/*.yaml` | Replace the synthetic selector, request expectation, source response, normalized outputs, outcome, and claims. Keep all retained fixture data synthetic. |
| `registry-stack.yaml` | Replace `registry.id`, the service id, `purpose`, `legal_basis`, `consent`, `access.scopes`, the consultation input mapping, claim ids and declarations, disclosure modes, and credential profile with reviewed owner decisions. |
| `environments/<owner-environment>.yaml` | Replace `integrations.individual.source.origin`, `integrations.individual.source.credential.token.secret`, and `integrations.individual.source.credential.generation` with the private OpenSPP source binding. |
| `environments/<owner-environment>.yaml` | Replace every `issuance` field and the `callers.programme-service` map key, API-key fingerprint secret reference, and scopes with candidate-owned values. |
| `environments/<owner-environment>.yaml` | Replace every `relay`, `notary_relay`, and `deployment` field. Add the candidate-required state bindings. Keep all deployment values outside public evidence. |

Use bounded one-request HTTP authoring when it expresses the selected operation.
Use reviewed Rhai only when the operation requires project-owned traversal or
normalization.
Do not add OpenSPP-specific Rust dispatch, restore a Notary source connector,
add an integration sidecar, or edit generated runtime configuration.

Rerun the focused trace, complete offline fixture suite, check, and build after
every contract change.
For the private owner environment, replace `local` in the check and build
commands with the exact environment filename without `.yaml`.
Activate the generated Relay and Notary Config Bundle inputs through the
documented path for the selected tagged candidate, without modifying generated
files.

## Prepare the governed live evaluation

Create the request and expected-result files under `.registry-stack/` in the
private workspace.
That directory is ignored by this workspace.
Use only an owner-approved non-production record.
The following request shape matches the committed synthetic project, so replace
the identifier scheme, value, purpose, and claim ids when the authored project
changes:

```json
{
  "target": {
    "type": "Person",
    "identifiers": [
      {
        "scheme": "openspp_individual_id",
        "value": "IND-AB12CD34"
      }
    ]
  },
  "claims": [
    "social-registry-record-exists",
    "social-registry-active",
    "programme-code",
    "household-reference"
  ],
  "format": "application/vnd.registry-notary.claim-result+json",
  "purpose": "social-programme-verification"
}
```

The expected-result file must contain only a `claims` object.
Its keys must exactly match the request's claim ids.
Each claim value must be a non-empty object containing only the exact `value`,
`satisfied`, or `disclosure` fields that the owner intends to verify.
This example reflects only the committed synthetic fixture and must be replaced
with reviewed expectations for the owner-approved record:

```json
{
  "claims": {
    "social-registry-record-exists": {
      "satisfied": true,
      "disclosure": "predicate"
    },
    "social-registry-active": {
      "satisfied": true,
      "disclosure": "predicate"
    },
    "programme-code": {
      "value": "SUPPORT",
      "disclosure": "value"
    },
    "household-reference": {
      "disclosure": "redacted"
    }
  }
}
```

The governed live test reads exactly four process variables:

| Variable | Owner-supplied value |
| --- | --- |
| `REGISTRY_STACK_LIVE_NOTARY_ORIGIN` | The non-production candidate Notary origin. Use HTTPS with no path, query, user information, or fragment. HTTP is accepted only for a loopback origin. |
| `REGISTRY_STACK_LIVE_NOTARY_API_KEY` | The deployed Notary caller API key. This is not the OpenSPP source credential. Load it from the owner's secret mechanism, never from a command argument or tracked file. |
| `REGISTRY_STACK_LIVE_REQUEST_FILE` | The absolute path to the strict JSON evaluation request. Use a bounded regular file, not a symbolic link. |
| `REGISTRY_STACK_LIVE_EXPECTED_FILE` | The absolute path to the strict JSON expected-result file. Use a bounded regular file, not a symbolic link. |

Load the API key into the process environment without echoing it, export the
other three variables, and run:

```sh
registryctl test --project-dir . --environment <owner-environment> --live
```

The command refuses a production environment.
It first reruns the offline fixtures, checks the candidate Notary's Relay
readiness, and then sends one request to the governed Notary evaluation path.
It requires the returned claim fields to match the expected file and requires
source-backed Relay provenance.
It never sends the request directly to OpenSPP.
Unset all four variables after the run.

Repeat the live command with separate private request and expected-result files
for each owner-approved match or no-match case.
Use the candidate's governed denial and failure checks for authorization denial
before source access and bounded source failures.
Prove ambiguity and subject mismatch with live cases when the selected operation
makes them applicable, or retain an owner-reviewed not-applicable rationale
that matches the real response contract.

## Evidence and redaction checklist

Before asking to close GH#357, record:

- [ ] Exact OpenSPP version and read-only operation, including which
      country-specific mapping files changed.
- [ ] Exact Registry Stack tag, `registryctl` version, adopter commit, Relay and
      Notary image digests, and per-authority Notary and PostgreSQL topology.
- [ ] The commands and pass or fail outcomes for focused trace, watch, complete
      offline fixtures, check, build, activation, and governed live evaluation.
- [ ] Match and no-match outcomes, plus applicable ambiguity or subject-mismatch
      behavior or reviewed reasons that they are not applicable.
- [ ] Authorization denial before source access, bounded failure, disclosure,
      redaction, and source-backed provenance outcomes.
- [ ] Confirmation that generated Relay and Notary files were activated
      unchanged.
- [ ] Confirmation that no OpenSPP-specific Registry Stack Rust, Notary source
      connector, integration sidecar, or direct registry test path was needed.
- [ ] Confirmation that changing the country mapping required only reviewed
      project-authored files and fixtures.
- [ ] Any gap fixed in the generic authoring or runtime model, or recorded as an
      explicit limitation before the 1.0 decision.

Before retaining or publishing evidence:

- [ ] Remove Notary and OpenSPP credentials, secret values, private origins,
      private network details, raw selectors, subject identifiers, source rows,
      source response bodies, and deployment-specific file paths.
- [ ] Do not retain shell history, environment dumps, packet captures, verbose
      HTTP transcripts, or logs that can contain those values.
- [ ] Keep public evidence to tested versions, the operation description,
      commands, outcomes, limitations, redaction checks, and non-sensitive
      artifact digests.
- [ ] Have the OpenSPP owner review the redacted evidence before publication.

A successful owner run can support only the wording
`live-authoring-validated OpenSPP starter` for the exact tested version and
operation.
It does not establish E2 interoperability unless the complete common
integration matrix also passes.
Until that evidence exists, this workspace remains an offline fixture and no
public OpenSPP support claim follows from it.
