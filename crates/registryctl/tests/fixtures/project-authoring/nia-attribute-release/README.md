# NIA attribute-release authoring fixture

This Relay-only project demonstrates the bounded project authoring surface for
the `solmara-nia-userinfo` eSignet profile. Run the same check and build journey
used by a country project:

```console
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local
```

The profile is declared under its entity's `records_api` service. Claims are a
map keyed by released claim name, so names cannot be duplicated and project
review shows the complete release policy in one place. Direct claims name an
explicitly projected entity field; computed claims and the required release
condition may reference only the projected `source` object.

The compiler fixes subject cardinality to exactly one and always generates
`include_source_metadata: false`. Authors may set only a private cache lifetime
from 1 to 3,600 seconds. The authored profile and generated Relay configuration
are both covered by the signed project semantic and closure digests.
