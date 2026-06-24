# Contributing

Registry Relay is a Rust service for protected, read-only registry consultation
APIs. Contributions should preserve the read-only data-plane boundary and avoid
exposing storage table details through public routes.

Local setup, development checks, coverage, project layout, pull request
expectations, and documentation style are documented in
[docs/development.md](docs/development.md).

Do not commit secrets, production data, private operator notes, or internal
planning documents.
