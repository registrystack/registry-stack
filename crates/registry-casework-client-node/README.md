# Registry Casework Node binding

This internal napi-rs binding supplies the `casework` module assembled into
`@registrystack/client`. Applications should use that unified package.

Every operation accepts a bearer token and an explicit Casework profile for
that call. Source-reading operations also require an explicit source profile.
The binding does not retain credentials and exposes no browser credential API.

Task delegation uses the current human profile for template previews, grant
approval, listing, and revocation. Approval accepts only the template ID and
version, with the item revision and a caller-owned idempotency key. The preview
contains the exact destination, purpose, authority bounds, derived subjects,
and lifetime; the grant list omits stored subjects. Agent assertion and grant
status calls take only a bearer token and grant ID, without human or source
profile headers. Neither binding retains credentials or retries a mutation.
