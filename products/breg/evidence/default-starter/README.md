# Record status from a retained BReg project

This one-question starter matches the unmodified `bregctl init` teaching model:
`record-active` uses the `by-code` selector and derives a boolean from status.
Its 11 synthetic cases cover positive and negative answers, absent facts,
identity checks, source failure, output refusal, and disclosure constraints.

Start and use your BReg project before creating Evidence. When you are ready,
stop the registry normally and connect it with `evidencectl source add`. That
command runs the matching `bregctl` for the registry side, so a `bregctl` binary
of the same version must be on `PATH`, or named by `--bregctl-bin` or
`BREGCTL_BIN`. It previews the proposed source authority without writing
anything:

```sh
bregctl dev stop ./registry
evidencectl source add ./registry --project ./evidence \
  --source-id registry-status --selector-profile by-code
```

Select entity `record`, unique field `code`, and readable fact `status`. For
these synthetic records choose every record in the entity explicitly; a supplied
code is not a row authorization rule, so institutional data needs the required
row boundary instead. Repeat the command with `--apply` to perform the
connection:

```sh
evidencectl source add ./registry --project ./evidence \
  --source-id registry-status --selector-profile by-code --apply
```

That one operation prepares a lookup-only source client on the registry,
exports its contract, imports it into the Evidence project, copies the
dedicated credentials into the project's `secrets/` directory, and writes the
`registry` connection into `evidence/targets/local`. Retained records,
revisions, and client identities remain; the registry's package revision
advances to carry the chosen source authority, so restart the registry to
activate it.

Copy this starter's `questions/`, `derivations/`, and `fixtures/` into the
project. From the Evidence project directory, rehearse the connection with
generated local caller authority:

```sh
evidencectl fixtures run --project . --target ./targets/local --local
```

Fixtures use recorded synthetic responses, so they need neither a running
registry nor source credentials.

The copied `targets/local/settings.yaml` is the explicit loopback teaching
target for a candidate. Review its fixed authority and connection, then use
`pwd -P` to replace its absolute runtime paths: set the bundle directory to your
chosen candidate's `bundle/`, the file secret root to this project's `secrets/`,
and audit storage to `audit/evidence.jsonl`. Its source endpoints use BReg's
default ports `8090` and `8091`; match any ports you selected on the registry's
first start. Then build the candidate and serve the local rehearsal:

```sh
evidencectl target new ./targets/configured --settings ./targets/local/settings.yaml \
  --signing-public-key ./secrets/signing-p256-public.jwk.json
evidencectl build --project . --target ./targets/configured --output ../candidate
bregctl dev start ../registry
evidencectl dev --target ./targets/local --detach
```

`dev --target` rehearses the source connection using a separate generated local
caller authority. It does not serve the target's complete caller governance.
Use the maintained “Answer questions from Base Registry Engine” tutorial for
record creation, requests, verification, and shutdown.

When the registry and the Evidence project are not on the same machine,
`source add` has no registry to drive, and the two sides connect by hand
instead: the registry operator runs `bregctl generate evidence-source` for the
reviewed lookup and `bregctl dev export-client` for the dedicated source
credentials, and you run `evidencectl source import` on the exported directory.

The neighboring `starter/` input remains the broader two-selector example,
requiring its matching registry.
