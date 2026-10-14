# Local directory

One Record type, generated CRUD, and an access profile bounded to the caller's
jurisdiction. The project includes synthetic clients, an allowed and refused
journey, and a resumable create/read example.

With matching `breg` and `bregctl` binaries on `PATH` and Docker running:

```sh
bregctl check .
bregctl explain model .
bregctl dev start .
bregctl examples list .
bregctl examples run contact .
bregctl dev stop .
```

`dev start` checks and packages the project, starts a local issuer and disposable
PostgreSQL, and verifies the journeys before serving requests. Restarting it
retains the records. `bregctl dev stop --remove .` removes this project's local
session and its data.

The `editor` client operates in `zone-a`; `foreign-editor` operates in `zone-b`.
The refusal journey proves that knowing a contact ID does not grant access to
another jurisdiction. Neither client configuration contains credentials.

The reserved registry identity and local source revision are examples. Set the
institution's identity and an immutable source revision before preparing a
production package. Production deployment also supplies its own PostgreSQL,
OAuth issuer, TLS, signing, and secret configuration.
