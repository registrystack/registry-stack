# Multi-reference Action authority

This synthetic fixture proves that one `in` row boundary applies independently
to two Action inputs that reference the same Record type. The transfer succeeds
when the caller's `allowed_jurisdictions` array covers both referenced public
authorities. The maintained journey proves that a one-value array and a missing
claim refuse without creating another transfer. The fixture's PostgreSQL test
also sends a signed token with a scalar claim through the production
authenticator and proves that the malformed credential fails closed before the
Action runs.

Run the fixture through the local development lifecycle:

```bash
bregctl check .
bregctl dev start .
```

`bregctl dev start` runs `tests/journeys.yaml` before serving the package. Stop
the session with `bregctl dev stop . --remove`.
The claim variants bind to their exact refusal steps through
[`testBindings`](../../DEV.md#explicit-teaching-clients).
