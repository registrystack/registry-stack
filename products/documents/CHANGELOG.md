# Registry Document Store changelog

## Unreleased

- Serve Prometheus metrics on an optional operator-private listener. Set
  `metricsListener.bind` in `runtime.yaml` to a loopback or private address,
  distinct from the serving listener. It is off by default, and the serving
  listener never answers `/metrics`. The series report content verification,
  erasure and hook delivery jobs by state, the age of the oldest overdue item
  of each, the last success of the cleanup pass, and requests by route and
  status class. A failed sample is logged and counted in
  `documents_metrics_sample_failures_total` and its gauges are left out, never
  reported as zero.
- The metrics listener accepts `metricsListener.networkExposure`. Set
  `metricsListener.networkExposure: container-private` to also allow the
  unspecified address (for example `0.0.0.0`), for a container whose network
  is private to the deployment. The default, `private-address`, keeps the
  loopback-or-private rule.

- Each access profile may carry an optional `label` and `description`, accepted for authoring and tooling; the Document Store does not serve them until a view exists. Neither is matched against a caller, and a profile that writes neither reads as before.

- BREAKING: Document Store access profiles rename `role` to `actsAs`; the values are unchanged; the schema definition `AccessRole` is now `ActsAs`. Migration: in each `accessProfiles` entry, write `actsAs: VALUE` where the file wrote `role: VALUE`. A file that still writes `role` is refused with `config.removed-key` naming `actsAs`.

- BREAKING: A runtime configuration file is refused with
  `platform.runtime-config.unsafe-file` when it or an ancestor directory is not
  owned by root or the runtime user, or is writable by group or others. A
  root-owned sticky ancestor stays allowed.
- Adopt the shared platform implementations for the access-token algorithm
  roster (still exactly RS256 and ES256), framework-rejection normalization
  (400, 413, 415 and 422 answer the same `request.*` problem codes) and the
  stop signal. `serve` refuses startup with the signal error when a stop-signal
  handler cannot be installed; SIGINT is now installed at startup alongside
  SIGTERM.

Initial scope of the Document Store: custody of document bytes for an owning
system, exact-version document grants, content verification before release,
scheduled erasure, and after-commit document events, served over `/v1/` with
`documentsctl` for operators. The product is held out of releases until it is
published. Under citizen delivery the reserving system sees a document's
metadata and status only: it cannot grant, read the bytes, or list the grants
(`GET /v1/documents/{documentId}/grants` is the custodian's alone and answers
the reserving system `profile.not-authorized`), so the issuer never learns
whom the citizen shared with.

`documentsctl check --project` reads an optional `check-acceptances.yaml`,
keeps exactly matched warnings visible with their reasons, and excludes only
those accepted warnings from `--deny-warnings`.
