# Record status offline, from a synthetic source

This starter is complete on its own. The synthetic source, selector, question,
derivation, and fixtures it ships are everything `evidencectl check` and
`evidencectl test` need, so a freshly initialized project passes both
immediately offline: no running registry, no source export, no credentials,
and no network. Create one and prove it:

```sh
evidencectl init <dir> --starter <repo>/products/breg/evidence/offline-starter --profile local
evidencectl check <dir>
evidencectl test <dir>
```

`record-active` asks whether a registered record is active. The caller sends
one code and nothing else. The source runs one fixed statement over a
synthetic SQLite extract built from the fixture text, extraction hands the
derivation the single `status` fact, and the derivation answers one boolean;
the disclosure list lets the assertion carry that boolean alone. Every value
is invented: `synthetic_only` keeps the run from reaching any real source, and
the private-label canary must stay out of assertions and diagnostics. The
thirteen cases cover true and false answers, no match, ambiguity, the row
bound, extract age, source failure, parameter binding, statement refusal,
hostile selector text, the output gate, and anti-reconstruction.

The copied `targets/local/settings.yaml` is an explicit loopback teaching
target for the day this project goes live. Review its fixed authority and the
`registry` source connection it names, then set its absolute runtime paths.

Going live is the one step this starter deliberately does not take for you:
replace the synthetic source by importing the reviewed
`bregctl generate evidence-source` export, re-author the question onto that
source, and reconnect its fixtures. The neighboring `starter/README.md` walks
that import end to end for the two-selector registry example; the
`default-starter/` and `named-starter/` inputs take the guided
`evidencectl source add` path instead.
