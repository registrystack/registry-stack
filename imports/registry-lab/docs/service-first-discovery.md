# Service-First Discovery Story

Registry Lab publishes a CPSV-AP service catalogue at `/metadata/cpsv-ap`.
The live story uses that catalogue as the starting point for the health-linked
child support eligibility review.

The story flow is:

1. Publish static metadata from `config/static-metadata/metadata.yaml`.
2. Fetch `/metadata/index.json` and `/metadata/cpsv-ap` from the static
   metadata publisher.
3. Invoke the Registry Atlas `semantic-asset-discovery` CLI to produce a
   discovery report.
4. Invoke the Atlas `ServiceGraph` Rust API over that report to extract the
   public service, channels, requirements, grouped CCCEV evidence options,
   accepted evidence types, evidence providers, routes, gaps, and source
   evidence.
5. Validate one sample service-form payload against the JSON Schema published
   from the form's `validates_with.json_schema` reference.
6. Call Registry Witness through the access-service endpoints discovered from
   the evidence offerings. The runner only maps Compose-internal hostnames to
   host ports for local execution.

Witness dispatch is intentionally service-first. The story does not choose a
Witness URL from a static evidence-type table. Atlas discovers the evidence
offering access services, the runner records each discovered `endpoint_url`,
selects a satisfiable evidence option group for each requirement, and the HTTP
call is made to the corresponding Witness service. The only local demo
adaptation is translating Compose URLs such as
`http://shared-eligibility-witness:8080` to their published host ports such as
`http://127.0.0.1:4323`.

Generated artifacts are written under `output/live-stories/`:

- `service-catalogue.json`
- `service-discovery-report.json`
- `service-graph-excerpt.json`
- `service-requirement-evidence-map.json`
- `service-form-validation.json`
- `service-evidence-provider-map.json`
- `service-route-status.json`
- `service-witness-evaluations.json`
- `service-route-provenance-validation.json`

The Python story runner deliberately does not traverse JSON-LD relations by
hand and does not select Witness endpoints from a static evidence-type table.
JSON-LD parsing, graph navigation, and provider/access-service route selection
stay in Atlas.

`service-route-provenance-validation.json` fails the live story if an evaluated
Witness route was not present in Atlas-discovered access-service metadata, or
if the host URL cannot be derived from that endpoint by the local Compose
hostname-to-host-port translation.

The lab does not implement OOTS Evidence Broker or Data Service Directory
calls. OOTS-style fulfillment is represented only as portable metadata until a
cross-border once-only flow is added.
