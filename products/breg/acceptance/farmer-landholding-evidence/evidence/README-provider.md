# Synthetic farmer Evidence deployment

This bundle supplies the two requirements imported by the BREG trial. The
registered BREG procedure may resolve exact identifiers in this synthetic
namespace. Its service token carries the reviewed requester tag; caller input
cannot create that tag. The source adapter refuses a nonunique result or a
returned identifier different from the requested identifier.

The status requirement discloses only `active`; the category requirement
separately discloses only `category`. Each has its own fixed field projection and
fact schema, so status does not request or require category. Each invocation is
a separate observation.
The fixture source contains only canonical identifier, active status and category.
It resolves `TH-00042` to an active record and `TH-00043` to an inactive record.
No real institutional records or credentials belong here.

`./run-provider.py --evidence /absolute/path/to/evidence --output /private/tmp/fresh-trial`
starts a real Evidence binary and local source and token-issuer endpoints. It
requires Python with PyYAML and OpenSSL. Keep its standard input open; a newline,
EOF or SIGTERM stops its child service. The output directory contains synthetic
keys, tokens, exact source requests and audit material with owner-only access.
The token expires after five minutes, so build all binaries before starting it.

Wait for `ready.json`, then use its absolute paths. `contractsFile` contains the
actual requester-filtered contract revisions for this exact deployment. Copy it
into the trial project's imported contract before compiling and signing the
BREG package. This preparation is an explicit test acceptance step. The running
BREG adapter does not discover or replace contracts or trust.

`tokenFile` authenticates the registered procedure. `unauthorizedTokenFile` is
signed by the same issuer but lacks the permitted requester tag, so denial must
precede source access. `jwksFile` contains the locally generated pinned Evidence
verification key. `requestsFile` records only synthetic source request bodies.
Change `controlFile` while the service runs to set `active`, `category`, and
`mode` (`match`, `missing`, `ambiguous`, or `mismatch`). The latter three exercise
safe dependency refusal; none is a business value.
