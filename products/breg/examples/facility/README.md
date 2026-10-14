# Facility registry

This project combines ordinary record routes, an immediate Action that creates
a facility and assignment atomically, and durable Proposals for later changes.
Every permission and domain rule is authored in `registry.yaml`.

With matching `breg` and `bregctl` binaries on `PATH` and Docker running:

```sh
bregctl check .
bregctl explain actions .
bregctl explain proposals .
bregctl dev start .
bregctl examples run register-facility .
```

Keep the returned `attempt` UUID. The next scenario uses its typed captures:

```sh
bregctl examples run deactivate-facility . --from-attempt REGISTRATION_ATTEMPT
```

That scenario starts and inspects a draft, edits it, submits the frozen effects,
and manually applies them as the separately authorized `applier`. No independent
review service is required. Use `cancel-deactivation` with a registration attempt
to cancel a draft without applying it. Each invocation prints a `nextCommand`
with its attempt UUID. Running that command resumes the original saved commands,
including their conditions and idempotency keys. Changed input requires an explicit
`--new-attempt`; it cannot silently replace uncertain work.

`bregctl check` reports an intentional related-disclosure advisory. The
`operators` related read uses the selected facility root profile, so review that
grant alongside direct operator access. This project gives both reads the same
jurisdiction boundary and readable field set.

`tests/journeys.yaml` exercises registration, reads both resulting records,
checks jurisdiction concealment, edits a no-review Proposal, refuses stale
submission conditions, and recovers the exact Submit and Apply commands. It
reads the submitted Proposal as the applier before applying, since lifecycle
ETags bind the caller and profile. It also checks cancellation. `dev start` runs
these authored schema tests against its disposable PostgreSQL before serving
requests.

The `author`, `applier`, and `reviewer` clients are explicit synthetic human
fixtures. Restarting the local session retains its data and example attempts.
`bregctl dev stop .` stops services; `bregctl dev stop --remove .` removes the
session and its records.

## Optional independent review

With matching `casework` and `caseworkctl` binaries also on `PATH`, one opt-in
command creates fresh facility and canonical Casework projects, pairs the
source context schema, and starts both services with the same issuer:

```sh
bregctl examples review ./reviewed-session --approve
```

`--approve` explicitly records an approval as the local synthetic staff fixture
through Casework's ordinary context, claim and decision APIs. It then observes
the captured source submission until it applies. Omit that flag to leave the
review pending for independent interaction. The command prints both project
paths, the observation command and commands to stop their services. Existing
directories are never overwritten. The project policies come from the installed
templates; no source checkout or copied application console is required.

`correct-address` freezes a Rhai plan, sends it to the configured `casework`
review authority, and applies it automatically only after fresh approval. The
registry independently checks current source authority and target revisions.
Startup, registration, reads, and no-review changes work without Casework.

Configure that independent authority in `dev-clients.yaml` before starting the
session. The authority must serve the shared Review protocol and a compatible
`facility-address-review` policy, with its own authenticated reviewer access.
Use a separate registration attempt whose facility has not been deactivated:

```sh
bregctl examples run submit-address-correction . --from-attempt REGISTRATION_ATTEMPT
```

Keep the returned submission attempt UUID, complete the review at the authority,
then observe that exact Proposal and its source record:

```sh
bregctl examples run observe-address-correction . --from-attempt SUBMISSION_ATTEMPT
```

If independent review or application is still pending, the observation fails
with a resumable command. Run that command again after progress. A submitted
Proposal is not evidence that application completed. An unavailable authority
cannot approve or apply the correction.

The editable scenario inputs are in `examples/inputs/`. The generated client
contract and promoted Proposal links determine available operations. This
starter contains no application console and needs no Registry Stack source tree.

Set the institution's registry identity and immutable source revision before
preparing a production package. Replace local callers with the institution's
OAuth claims and independently configured grants.
