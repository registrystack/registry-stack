# Token fixtures

This folder holds the tokens that real identity providers issue, reduced to their shape. Every product that verifies a caller's token is tested against them. The aim is to know, for each product and each kind of token, whether the token is admitted or refused, and at which check.

A fixture is data. It has no signature and no key. The test loader signs it when a test runs.

## What is here

| Path | Content |
| --- | --- |
| `fixtures/<id>.json` | One decoded token shape per file. |
| `expected.yaml` | The expected result for each fixture, product and configuration. |
| `token-fixture.schema.json` | The JSON Schema every fixture must satisfy. |

The loader, the signer and the test driver live in `crates/registry-platform-testing`, behind the `token-fixtures` feature. Each product's test passes its own authenticator to that driver.

## Two kinds of fixture

A **positive** fixture is a token that a correctly configured product can admit for a plain read. It is here to show what a product must accept from a provider's stock output, or what it refuses today and why.

A **negative** fixture is a token that every product must refuse, in every configuration. Examples are an ID token, a refresh token, an API key, and a token from an issuer that no product trusts. A negative fixture admitted by any product is a security defect. Report it through `SECURITY.md`. Do not open a public issue or pull request.

## Providers covered

Keycloak, ThunderID, Microsoft Entra ID, Supabase Auth and eSignet. One fixture, `rstack-dev-run-user`, holds the shape the development runner signs. One fixture, `identity-only`, is a token built to carry identity and nothing else.

## What a fixture file holds

```json
{
  "schema": "registry.token-fixture/v1",
  "id": "keycloak-client-credentials",
  "class": "positive",
  "provider": "keycloak",
  "kind": "client-access",
  "tokenUse": "access",
  "subjectKind": "service",
  "source": { "basis": "observed", "...": "..." },
  "header": { "alg": "RS256", "typ": "JWT", "kid": { "generated": true } },
  "claims": {
    "iss": { "bind": "issuer" },
    "aud": { "bind": "audience" },
    "azp": "journey-service",
    "iat": { "offsetSeconds": 0 },
    "exp": { "offsetSeconds": 300 }
  },
  "omits": ["registry_actor_kind"]
}
```

- `class` is `positive` or `negative`.
- `kind` and `tokenUse` say what the token is: an access token, an ID token, a refresh token or an API key.
- `subjectKind` says who the token stands for: a `user`, a `service` or `unspecified`.
- `header` and `claims` keep the header members and claim names that the provider issues. Values keep their JSON type.
- `omits` lists claims whose absence is the point. The loader checks they are absent.
- `opaque` replaces `header` and `claims` for a credential that is not a JWT. Its value is a synthetic string.
- `notes` explains a choice a reader would otherwise have to guess.

### Values

A claim value is plain JSON, or one of three directives.

| Directive | Meaning |
| --- | --- |
| `{ "bind": "issuer" }` or `{ "bind": "audience" }` | Take the issuer or the audience of the product under test. The fixture then tests the token's shape, and not a mismatch the test set up. |
| `{ "offsetSeconds": 300 }` | Seconds after the moment of signing. A lifetime is part of the shape. |
| `{ "generated": true }` | A value the loader makes at signing time, such as a key identifier. |

A literal `iss` or `aud` models a value the provider fixes. Keycloak's stock audience `account`, Supabase's `authenticated`, the client identifier in an ID token and the eSignet issuer are literals.

All identifiers, addresses and names in a fixture are synthetic. Hosts use `example.test` or the documentation address block.

## How a fixture is signed

The loader makes one key for each algorithm once per test process. It serves the public half as a static key set and signs each fixture with the private half. The private half is never written to disk. This folder holds no private key and no live token.

A corpus test fails on any string shaped like a compact JWT, and on any private JWK member name (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`).

## Where a fixture comes from

Every fixture states its source in `source.basis`.

- `observed` with `observedFrom: capture`. The token was issued by a running provider. The fixture names the provider version, the container image digest, and the capture file. Only claim names, header members and value types were kept.
- `observed` with `observedFrom: code`. The shape was read from the code that signs it.
- `documentation`. The shape comes from the provider's public documentation. The fixture names the page. Replace a documentation fixture with an observed one as soon as you can capture a token.
- `constructed`. The token was built on purpose and the fixture says why.

## expected.yaml

`expected.yaml` has one row for each fixture, `against` value and configuration. Each row has one cell for every product that verifies a token.

A cell holds:

- `main`: the result today.
- `target`: the result the caller contract work aims for.
- `changedBy`: the milestone that changes the result, such as `M7`, or `none`.
- `landed`: present when `changedBy` is a milestone. It is `false` until that milestone makes `target` true.
- `basis`: `inferred` while `main` is a reading of the code, `observed` once a test has run the fixture through the product.
- `reason` and `targetReason`: why a `main` or a `target` is `unknown`, `n-a` or `none`, or why a product cannot follow one of the driver's choices listed at the head of `expected.yaml`.

A result is `admitted`, `admitted/<actor kind>`, `admitted/unspecified`, `refused/<stage>`, `none`, `n-a` or `unknown`. A stage is one of the verifier's labels (`header`, `algorithm`, `token-type`, `key`, `signature`, `issuer`, `audience`, `time`, `client`, `scope`, `profile`, `unavailable`) or `claims`, which a product uses for its own claim checks.

The test asserts `target` where `landed` is `true` and `main` everywhere else. Work on a milestone goes row by row. Set `landed: true`, watch the test fail, make the change, watch it pass.

The head of `expected.yaml` lists the choices the driver makes for every row, such as which client list and which read scope a product is given.

## Add a fixture

1. Capture the token from a running provider. Decode it. Keep claim names, header members and value types. Never save the token itself.
2. Write `fixtures/<id>.json`. The file name equals `id`. Replace every value that identifies a person, tenant, host or client with a synthetic one. Use `bind` for the issuer and the audience unless the provider fixes them.
3. Fill in `source`. Add `omits` for any claim whose absence matters.
4. Check the file against `token-fixture.schema.json`.
5. Add a row to `expected.yaml` for each configuration you want to cover, with a cell for every product. If you could not read a product's code to the end, write `unknown` and give the reason. Do not guess.
6. Run the corpus test. It checks that every fixture has a row, that every row has every product, and that no negative fixture has a `target` of `admitted`.
