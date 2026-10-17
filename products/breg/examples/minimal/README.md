# Local directory

One Record type with generated CRUD, two Actions, and an access profile bounded
to the caller's jurisdiction. The project includes synthetic clients, an allowed and refused
journey, and resumable examples.

It declares two Actions. `update-contact-email` is immediate: invoking it
patches the contact's email at once and returns an ActionReceipt.
`register-contact` creates a contact through a Proposal with no review: starting
it saves a draft, and submitting it applies the Plan automatically.

With matching `breg` and `bregctl` binaries on `PATH` and Docker running:

```sh
bregctl check .
bregctl explain model .
bregctl dev start .
bregctl examples list .
bregctl examples run contact .
bregctl examples run update-contact-email . --from-attempt <contact attempt>
bregctl examples run register-contact .
bregctl dev stop .
```

`dev start` checks and packages the project, starts a local issuer and disposable
PostgreSQL, and verifies the journeys before serving requests. Restarting it
retains the records. `bregctl dev stop --remove .` removes this project's local
session and its data. `update-contact-email` acts on the contact the `contact`
example created, so pass the attempt ID that run printed. Automatic application
of a submitted Proposal runs after the response, so `register-contact` waits up
to 10 seconds for it; if it still reports a differing Proposal state, rerun the
`next command` it prints.

The `editor` client operates in `zone-a`; `foreign-editor` operates in `zone-b`.
The refusal journey proves that knowing a contact ID does not grant access to
another jurisdiction. Neither client configuration contains credentials.

The reserved registry identity and local source revision are examples. Set the
institution's identity and an immutable source revision before preparing a
production package. Production deployment also supplies its own PostgreSQL,
OAuth issuer, TLS, signing, and secret configuration.
