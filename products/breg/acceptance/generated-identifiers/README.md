# Generated identifiers acceptance project

This project declares two server-generated string fields on `application`:
`number` is a sequence scoped by `jurisdiction`, and `code` is a random code.
Callers supply only `jurisdiction` and `applicant`. BReg assigns both values
when a direct create commits or when a Proposal is submitted. The record's
internal UUID remains its identity and is still used in references and routes.

Check the configuration and journeys with the repository's `bregctl`:

```sh
cargo run --locked -p registry-bregctl -- check products/breg/acceptance/generated-identifiers
cargo run --locked -p registry-bregctl -- check products/breg/acceptance/generated-identifiers --file products/breg/acceptance/generated-identifiers/tests/journeys.yaml
```

See [generated-identifiers.md](../../generated-identifiers.md) for migration,
uniqueness, and Proposal retry behavior.
