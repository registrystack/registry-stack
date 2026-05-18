# Contributing

Registry Relay is a Rust service for protected, read-only registry consultation
APIs. Contributions should preserve the read-only data-plane boundary and avoid
exposing storage table details through public routes.

## Local Setup

```sh
just setup
```

## Development Checks

Run focused checks while iterating, then the full local gate when practical:

```sh
just fmt-check
just lint
just test
just deny
```

The closest local CI equivalent is:

```sh
just ci
```

Coverage metrics are documented in
[docs/development.md#coverage-metrics](docs/development.md#coverage-metrics).

PostgreSQL integration tests require `DATA_GATE_POSTGRES_TEST_URL`; without it,
the relevant tests are ignored locally.

## Pull Requests

Keep pull requests focused. Include tests or explain why the change is docs,
configuration, or tooling only. Do not commit secrets, production data, private
operator notes, or internal planning documents.
