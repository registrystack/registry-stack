# Multi-reference Action authority

This synthetic fixture proves that one `in` row boundary applies independently
to two Action inputs that reference the same Record type. The transfer succeeds
when the caller's `allowed_jurisdictions` array covers both referenced public
authorities. The maintained journey proves that one-value arrays excluding
either referenced authority, and a missing claim, refuse without creating
another transfer. The fixture's PostgreSQL test
also sends a signed token with a scalar claim through the production
authenticator and proves that the malformed credential fails closed before the
Action runs.

Check the fixture, then run it with `rstack dev`:

```bash
bregctl check .
rstack dev start . --ttl 1h
```

`rstack dev start` runs `tests/journeys.yaml` before serving the package, then sends the one
read in `dev/scenarios.yaml`. Stop the run with
`rstack dev stop RUN`, which keeps its managed data. Add `--clean` to remove the data. The claim variants bind to their exact refusal steps
through the people the fixture's `dev.yaml` names for each journey step.
