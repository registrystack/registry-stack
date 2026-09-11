# Registry Casework Node binding

This internal napi-rs binding supplies the `casework` module assembled into
`@registrystack/client`. Applications should use that unified package.

Every operation accepts a bearer token and an explicit Casework profile for
that call. Source-reading operations also require an explicit source profile.
The binding does not retain credentials and exposes no browser credential API.
