# Acceptance journeys

This folder holds the tables behind three acceptance journeys and a static check
of those tables. A journey walks one product from nothing to a first
authenticated call, or from a development run to a production start, using only
what a reader of the documentation has. The tables say where each journey stops
for each product today and which milestone removes the stop.

## The three journeys

| Journey | What it does | Steps |
|---|---|---|
| `own-provider` | Starts a product against an identity provider and a PostgreSQL server the reader already runs. | prepare, issuer, database.provision, database.connect, start, ready, token, call, hook, stop |
| `rstack-dev` | Starts the product with `rstack dev` and uses its own issuer, with no identity provider to set up. | init, plan, start, issuer, token, call, hook, keep, attach, stop |
| `promote` | Takes the files a development journey ended with and starts them as production. | input, start-as-production, refusals, fix, start, call, same-contract |

The own-provider journey uses Keycloak. The image is the one
`products/breg/scripts/test-issuer-portability.py` pins, and `products.yaml`
repeats it so the test can compare the two. The `rstack dev` journey uses the
issuer the run starts and does not start an identity provider.

## Files

| File | Holds |
|---|---|
| `products.yaml` | The product column: the sixteen runtimes that load a runtime file, with their crate, binary, tool, and whether they use PostgreSQL or verify tokens. Ten are primary and six are supporting. A supporting runtime starts beside its parent, so a journey records it as unreached. |
| `first-hour-pass-rule.yaml` | What counts as a pass for a first hour: six hard conditions, ten counters with a threshold for each path, and the model that turns effort into reader time. |
| `concepts.yaml` | The closed list of concepts that counter 6 counts. |
| `expected-failures.yaml` | The ratchet table. Every cell (a journey and a product) is listed once, as an expected failure, as unreached, or as a pass. |
| `test_journey_tables.py` | The static check. |
| `lib.sh` | The shared library every journey script sources: options, binaries, generated secrets and redaction, containers and their cleanup, steps, outcomes and the ratchet comparison. |
| `test_lib.sh` | The library's self-test. It runs against fake `docker`, `curl` and `cargo` commands, so it starts no container and builds nothing: `bash products/platform/journeys/test_lib.sh`. |
| `rstack-dev.sh` | The `rstack dev` journey, with a recipe per product for the steps from `start` on. |
| `own-provider.sh` | The own-provider journey: a stock Keycloak and a stock PostgreSQL started on loopback, then each product from its starter to a first authenticated call. |
| `keycloak/realm.json` | The realm the own-provider journey imports: per product, one caller client with a service account and one API client for the product's audience. It holds no protocol mappers. |
| `projects/` | The runtime files the own-provider journey gives the products whose starter has none (Render, Coordinator). |

## Reading the ratchet table

A cell fails at its first failing step with one code. The code has one of these
forms.

- `journey.needs.<thing>`: the only way past the step is something the journeys
  forbid. The things are a certificate, a claim mapper, hand-written SQL, an
  image build, a signature verifier and a hand-written plan.
- `journey.promote.<thing>`, `journey.keep.<thing>`, `journey.attach.<thing>`: the
  step named in the form found nothing to work with, lost the written record or
  refused the reader's own setup.
- `http.<status>.<stage>`: a refused call. The stage is one of the
  authentication stages the shared OIDC crate reports.
- `product.<dotted code>`: the diagnostic code a product prints.

Each row has a `basis`. A `predicted` row was inferred from reading the code. A
journey run replaces it with the code the run saw and sets `observed`. A
harness failure, such as a container that did not start, is never a row.

A journey run in ratchet mode succeeds when every cell matches the table. A
milestone that fixes a cell deletes the row in the same commit and adds the
cell to `passes`. A fix that is not recorded fails the run, and so does a new
failure that the table does not list.

## Running the static check

The check reads these files and a few source files. It starts no container and
builds nothing. It needs PyYAML.

```
uv run --no-project --with PyYAML==6.0.2 python3 -m unittest products/platform/journeys/test_journey_tables.py
```

It checks that:

- the product list has sixteen unique rows, each with a crate, binary and tool
  that exist in `crates/`
- the `rstackDevPlan` flag matches the products `rstack dev` can plan
- the Keycloak image equals the pin in the portability journey
- the pass rule has the six hard conditions, ten numbered counters with both
  thresholds, and the full reader-time model
- the concept list has unique, well-formed entries
- every journey and product cell appears exactly once, every step belongs to its
  journey, every code is valid, every failure row names a listed milestone,
  and every row records its basis and a reason
- journey scripts, when they exist, call none of `openssl`, `mkcert`, `keytool`,
  `psql`, `docker build` or `docker exec`, outside `lib-assists.sh`, and the
  Keycloak realm import has no `protocolMappers`

## Why the journeys are shell and not Python

Journey scripts start product binaries directly. On macOS a process started
through a protected system launcher, such as `/usr/bin/env` under `uv` or the
system Python, loses the `DYLD_*` variables, and the binary then aborts on a
missing FIPS library. Keeping the journeys in `bash` with direct launches avoids
that. A Python helper that starts a binary would bring the problem back.
