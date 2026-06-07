# Release Notes

## 0.1.0

- Added the V1 protected consultation gateway over CSV, XLSX, Parquet, and bounded PostgreSQL sources.
- Added API-key and OIDC resource-server authentication, independent dataset scopes, purpose-header enforcement, redacted audit records, and admin-listener reload operations.
- Added the V1 protected consultation API, unauthenticated health/readiness/docs routes, and optional provenance verifier-support resources.
- Added portable metadata publication through `registry-manifest-core`, including `/metadata/*`, DCAT/BRegDCAT-AP, SHACL, ODRL policy metadata, evidence-offering discovery, and `/.well-known/api-catalog`.
- Added optional standards adapters for OGC API Features, OGC API Records, OGC API EDR, SP DCI sync, PublicSchema VC mapping, and VC-JWT provenance responses.
- Added performance fixtures, k6 scenarios, Criterion benchmarks, Docker image support, and local verification recipes.

Known limits:

- Registry Relay does not execute claim or evidence verification. Evidence offerings are discovery records for Registry Notary.
- Admin reload reloads runtime resources, not `config.yaml`; config and keyring changes require a restart or rolling deploy.
- Row-level authorization is not available. Use dataset/entity scopes, required filters, purpose headers, explicit field projections, and audit redaction.
- `sensitive: true` controls audit redaction only; it does not hide fields from authorized API responses.
- Remote provenance signing backends are reserved for future work; V1 supports local software Ed25519 signing.
- The static OpenAPI artifact is an abstract contract. Deployments fetch `/openapi.json` for their concrete dataset/entity shape. The route is auth-gated by default unless `server.openapi_requires_auth` is disabled for demos or controlled tooling.
