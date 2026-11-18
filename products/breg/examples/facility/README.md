# Facility registry

This project combines ordinary record routes, an immediate Action that creates
a facility and assignment atomically, and durable Proposals for later changes.
Every permission and domain rule is authored in `registry.yaml`.

With matching `breg`, `bregctl` and `rstack` binaries on `PATH` and Docker running:

```sh
bregctl check .
bregctl explain actions .
bregctl explain proposals .
rstack dev start . --ttl 4h
```

`rstack dev start` runs the authored journeys, starts the registry and sends the scenarios in the
scenario file that `dev.yaml` names. Write a header file for a caller with `rstack dev token RUN --as
PERSON` and send further requests with `rstack breg api PATH --url BREG_URL --header @HEADER_FILE`.
[Run a project with rstack dev](https://docs.registrystack.org/dev/configure/run-a-project-with-rstack-dev/)
describes the report and token expiry.

The registration scenario retains both Action results in one atomic step as
`facility` and `assignment`, then reads both records. `captureResults` maps each
caller-visible Action result alias to the local capture alias later steps use.
The older `recordType`, `result`, and `capture` form remains available when a
scenario needs one Action result.

The deactivation scenario starts and inspects a draft, edits it, submits the frozen effects,
and manually applies them as the separately authorized `applier`. No independent
review service is required. The cancellation scenario cancels a draft without applying it.

`bregctl check` reports an intentional related-disclosure advisory. The
`operators` related read uses the selected facility root profile, so review that
grant alongside direct operator access. This project gives both reads the same
jurisdiction claim and readable field set. Sharing a claim name does not prove
that linked operator rows meet the direct grant's boundary. The related read
applies the facility boundary; the direct operator grant does not restrict it.

`tests/journeys.yaml` exercises registration, reads both resulting records,
checks jurisdiction concealment, edits a no-review Proposal, refuses stale
submission conditions, and recovers the exact Submit and Apply commands. It
reads the submitted Proposal as the applier before applying, since lifecycle
ETags bind the caller and profile. It also checks cancellation. `dev start` runs
these authored schema tests against its disposable PostgreSQL before serving
requests.

The `author`, `applier`, and `reviewer` callers are explicit synthetic human
fixtures. A development run is disposable: `rstack dev stop RUN` stops the services and removes
the run's records.

## Optional independent review

With matching `casework` and `caseworkctl` binaries also on `PATH`, a facility run can submit
changes to a Casework authority for independent review. The `correct-address` scenario freezes a
Rhai plan, sends it to the configured `casework` review authority, and applies it automatically
only after fresh approval. The registry independently checks current source authority and target
revisions. Startup, registration, reads, and no-review changes work without Casework.

The optional `supporting-document` PDF slot is projected as `supportingDocument`
under the reviewer's `get-review-context` grant. An empty frozen slot is `null`.
A populated field contains bounded metadata and a source download link; the
download reruns the complete context's current Record/Changes disclosure.
The reviewer needs no Proposal `get` or attachment read grant. The canonical
PostgreSQL journey uploads a synthetic document and downloads its exact bytes
with the maintained review-context client. For consent-sensitive deployments,
keep an authoritative Record/Changes projection that identifies the subject
whose current consent governs the review; document contents do not establish
that binding themselves.

Configure that independent authority in the runtime configuration. The authority must serve
the shared Review protocol and a compatible `facility-address-review` policy, with its own
authenticated reviewer access. The binding has this shape:

```yaml
reviewAuthorities:
  casework:
    endpoint: http://127.0.0.1:8100/
    profile: requester
    producerId: facility-registry
    recoveryDays: 30
    client: requester
```

`casework` matches the authority ID in `registry.yaml`. `profile` selects the
authority's producer profile, `producerId` names its trusted producer binding,
and `client` names the registered client used to authenticate.
`recoveryDays` bounds uncertain-submission recovery. Keep it no larger than
the Casework producer's `retention.receiptRetentionDays`: BReg retries
against a receipt that Casework keeps only that long. A submitted Proposal is
not evidence that application completed. An unavailable authority cannot
approve or apply the correction.

The editable scenario inputs are in `examples/inputs/`. The generated client
contract and promoted Proposal links determine available operations. This
starter contains no application console and needs no Registry Stack source tree.

Set the institution's registry identity and immutable source revision before
preparing a production package. Replace local callers with the institution's
OAuth claims and independently configured grants.
