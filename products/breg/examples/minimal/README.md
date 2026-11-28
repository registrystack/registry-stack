# Local directory

One Record type with generated CRUD, two Actions, and an access profile bounded
to the caller's jurisdiction. The project includes a development plan with two synthetic callers,
an allowed and refused journey, and a scenario that adds a contact.

It declares two Actions. `update-contact-email` is immediate: invoking it
patches the contact's email at once and returns an ActionReceipt.
`register-contact` creates a contact through a Proposal with no review: starting
it saves a draft, and submitting it applies the Plan automatically.

With matching `breg`, `bregctl` and `rstack` binaries on `PATH` and Docker running:

```sh
bregctl check .
bregctl explain model .
rstack dev check .
rstack dev start . --ttl 4h
```

`rstack dev start` checks and packages the project, starts a managed PostgreSQL and a local
issuer, runs the authored journeys, starts the registry, and sends the scenario in
`dev/scenarios.yaml`: it creates a contact as `editor` and reads it back. The scenario file sits in
`dev/` because `bregctl check` reads every YAML file under `tests/` as one of its own checks.
`dev.yaml` names the products, the two callers and that file. Stopping the run with
`rstack dev stop RUN` keeps its managed data. Use `rstack dev stop RUN --clean` to remove it or
`rstack dev start . --clean` to start fresh. A run that is not stopped ends after its time to live.
[Run a project with rstack dev](https://docs.registrystack.org/configure/run-a-project-with-rstack-dev/)
describes tokens and the rest of the report.

To call the registry, write a token header file for a caller and send a request with it:

```sh
rstack dev token RUN --as editor
rstack breg api /v1/records/contacts --url BREG_URL --header @HEADER_FILE
```

The [Change a registry with an Action](https://docs.registrystack.org/tutorials/change-a-registry-with-an-action/)
tutorial adds scenarios for both Actions to `dev/scenarios.yaml`. Automatic application of a
submitted Proposal runs after the response, so that scenario reads the Proposal until it is applied.

The `editor` caller operates in `zone-a`, and `foreign-editor` operates in `zone-b`.
The refusal journey proves that knowing a contact ID does not grant access to
another jurisdiction. Neither caller configuration contains credentials.

The reserved registry identity and local source revision are examples. Set the
institution's identity and an immutable source revision before preparing a
production package. Production deployment also supplies its own PostgreSQL,
OAuth issuer, TLS, signing, and secret configuration.
