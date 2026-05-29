# Service-First Discovery Story

Registry Lab publishes a standards-facing metadata bootstrap at
`/.well-known/api-catalog`. The live story follows the CPSV-AP service
catalogue URL advertised by that RFC 9727 Linkset document for the
health-linked child support eligibility review, then uses the metadata index
for supporting artifacts such as the form JSON Schema.

The story flow is:

1. Publish static metadata from `config/static-metadata/metadata.yaml`.
2. Fetch `/.well-known/api-catalog`, then fetch the advertised CPSV-AP
   catalogue URL from the static metadata publisher.
3. Invoke the Registry Atlas `semantic-asset-discovery` CLI to produce a
   discovery report.
4. Invoke the Atlas `service-view` command over that report to extract the
   public service, channels, requirements, grouped CCCEV evidence options,
   accepted evidence types, evidence providers, routes, gaps, and source
   evidence.
5. Validate one sample service-form payload against the JSON Schema published
   from the form's `validates_with.json_schema` reference.
6. Call Registry Notary through the access-service endpoints discovered from
   the evidence offerings. The runner only maps Compose-internal hostnames to
   host ports for local execution.

The interactive page presents the core chain as:

`api-catalog -> CPSV-AP PublicService -> CCCEV requirement/evidence option -> BRegDCAT/DCAT access service -> Notary claim discovery -> evaluation`

When the runner captures response header artifacts for discovery calls, the
page shows the important headers alongside the payload values, including
content type, Link, ETag, cache-control, and Vary.

Notary dispatch is intentionally service-first. The story does not choose a
Notary URL from a static evidence-type table. Atlas discovers the evidence
offering access services, the runner records each discovered `endpoint_url`,
selects a satisfiable evidence option group for each requirement, and the HTTP
call is made to the corresponding Notary service. The only local demo
adaptation is translating Compose URLs such as
`http://shared-eligibility-notary:8080` to their published host ports such as
`http://127.0.0.1:4323`.

Generated artifacts are written under `output/live-stories/`:

- `service-api-catalog.json`
- `service-api-catalog-headers.json`
- `service-catalogue.json`
- `service-catalogue-headers.json`
- `service-metadata-index.json`
- `service-metadata-index-headers.json`
- `service-discovery-report.json`
- `service-graph-excerpt.json`
- `service-requirement-evidence-map.json`
- `service-form-validation.json`
- `service-evidence-provider-map.json`
- `service-route-status.json`
- `service-notary-evaluations.json`
- `service-route-provenance-validation.json`

The Python story runner deliberately does not traverse JSON-LD relations by
hand, does not compile a Lab-local Atlas helper, and does not select Notary
endpoints from a static evidence-type table. JSON-LD parsing, graph navigation,
and provider/access-service route selection stay in Atlas.

`service-route-provenance-validation.json` fails the live story if an evaluated
Notary route was not present in Atlas-discovered access-service metadata, or
if the host URL cannot be derived from that endpoint by the local Compose
hostname-to-host-port translation.

The lab does not implement OOTS Evidence Broker or Data Service Directory
calls. OOTS-style fulfillment is represented only as portable metadata until a
cross-border once-only flow is added.

## Definition Of Done

A service-first live story is done when:

- The manifest publisher emits `/.well-known/api-catalog`,
  `/.well-known/registry-manifest.json` for compatibility,
  `/metadata/index.json`, and an indexed CPSV-AP JSON-LD catalogue.
- The runner starts from the RFC 9727 api-catalog document, follows its CPSV-AP
  service catalogue URL for Atlas discovery, and follows its metadata index URL
  for form validation metadata.
- Atlas `service-view` returns the public service, channels, requirements,
  evidence option groups, accepted evidence types, provider map, access
  services, routes, source evidence, gaps, and report summary.
- The HTML walkthrough displays the returned API result for each discovery
  step, relevant HTTP response headers when captured, and the value used by the
  next call.
- Notary evaluations are made only through endpoints derived from Atlas
  access-service metadata, except for local Compose hostname-to-host-port
  translation.
- Form JSON Schema validation passes for the service sample payload.
- Demo artifacts avoid secrets and unnecessary source records.
