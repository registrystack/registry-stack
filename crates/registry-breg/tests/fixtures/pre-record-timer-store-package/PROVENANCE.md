# Pre-record-timer-store package fixture

This fixture was produced from the clean Registry Stack source revision
`9623438128e700ebd14f346bd01a231c2be990df`, the immediately preceding
main-branch baseline for the record-timer-store change. The compiler and
`registry-breg` package builder came from that unreleased source revision, not
from a published release binary.

The timer-free authoring source is the existing native-minimal project with
only `package.sourceRevision` set to that exact compiler revision. Its input
hashes are:

- `registry.yaml`: `sha256:f15e307da2f101d908edd63c52e1e40d4dccdfb43645ac54e7040b8bee92fca2`
- `tests/journeys.yaml`: `sha256:3b51413089485ac6916fe0ddb7be01bbab0723005ea26f519df65117d37e62d3`

The baseline `bregctl test --fingerprint-only` command measured managed schema
fingerprint
`sha256:c58e601533dafc4c0fa7a940b79d4367e0403a4da84c081c7928a2e6bad673cb`
against a disposable PostgreSQL 17 database. The fixture package was then
published directly with that revision's `registry-breg` package builder and
checked with the same revision's `bregctl check --package` command. The exact
historical builder invocation, database state, packaging receipt, and command
transcript are not included with this fixture.

For a future regeneration, the pinned revision's supported public CLI accepts
the following command sequence. This is a proposed procedure, not the
historical construction path, and it was not executed for this documentation
repair. `PROJECT` contains the two hashed inputs above, `RUNTIME` points to a
disposable PostgreSQL 17 schema-test database, and `CREDENTIALS` contains only
synthetic journey credentials:

```sh
bregctl test PROJECT --fingerprint-only --runtime-config RUNTIME
bregctl test PROJECT --runtime-config RUNTIME --credentials CREDENTIALS \
  --output RECEIPT
bregctl package PROJECT --test-receipt RECEIPT --output BUILD
bregctl check --package BUILD/package
```

Fresh receipt and database inputs do not by themselves prove byte-identical
reproduction of the historical package. A regeneration must confirm the source
hashes and schema fingerprint, inspect every byte-level package difference,
and update the recorded package digest only through review.

The fixture's `SHA256SUMS` digest, which is also its package digest, is
`sha256:670898e30e7f380dc9ec1f989e8f507bf64ce8457ddba8b9798a866420cef28d`.
No compiler binary or database state is retained in this repository.
