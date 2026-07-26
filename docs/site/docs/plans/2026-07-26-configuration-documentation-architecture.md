# Configuration documentation review: six comparable projects

**Status:** current
**Date:** 2026-07-26
**Applies to:** planning input for `docs/site/src/content/docs/`, not published site content.

## Purpose and method

Six projects that ship user-authored configuration were reviewed to answer one question: how should
Registry Stack document a configuration model that an adopter authors as YAML and a CLI compiles into
per-product runtime configuration.

The review is documentation-only. No accounts were created, no service was deployed, and no hosted
onboarding was exercised. Every observation comes from a public documentation page that was fetched
and is linked inline. Where a claim could not be confirmed from a fetched page, the text says so
rather than filling the gap.

The projects were chosen because each solves one part of Registry Stack's problem:

| Project | Why it is comparable |
| --- | --- |
| Kong Gateway | Declarative gateway entities compiled onto running nodes, schema endpoint as the authority for defaults |
| Tyk | Two authored dialects over one runtime, an OpenAPI document plus a vendor extension |
| Airbyte Connector Builder | Author-time YAML manifest with a declared end-user configuration contract and an offline test loop |
| SpiceDB | Authored policy schema with an assertion-fixture format run by both a playground and a CLI |
| Terraform | The strongest published separation between authored configuration, generated artifacts, and state |
| OpenTelemetry Collector | Composable pipeline configuration with per-component reference living outside the docs site |

Each project is reviewed on the same axes: configuration-domain map, onboarding ladder, documentation
tree, how defaults and secrets and validation are explained, how examples stay consistent with
schemas and runtime behavior, friction, and the line between authored intent and generated or runtime
configuration. Each closes with three practices to adopt and two to avoid. Part B proposes the
resulting Registry Stack documentation architecture.

## What the six projects agree on

Five findings recur, and they are the load-bearing ones.

1. **The smallest first configuration is two or three fields.** Kong teaches a service with a name and
   a URL. Tyk teaches a listen path and an upstream URL. Airbyte teaches an endpoint URL and a method.
   SpiceDB teaches six lines with two relations and two permissions. Terraform teaches a provider and
   two resources with no variables, no outputs, and no backend. None of them opens with a complete
   object.
2. **The projects that survive contact with real users publish the schema as the authority and generate
   the reference from it.** Kong points readers at `/schemas` rather than copying defaults into prose.
   Terraform generates provider documentation with `tfplugindocs`. Airbyte names one
   `declarative_component_schema.yaml` as the validator. Where the reference is hand-maintained beside a
   real schema, it drifts, and Terraform's own variable pages prove it.
3. **The best validation documentation states what each tier cannot catch.** Kong distinguishes offline
   `deck file validate` from `deck gateway validate` against a live Admin API. Terraform says
   `terraform validate` "does not validate remote services". That sentence saves more support time than
   any feature description.
4. **Redaction is not containment, and the mature projects have learned it in public.** Terraform moved
   from `sensitive` to ephemeral and write-only values because sensitive values still landed in state
   and plan files. Kong moved secrets out of entities into vault references. Airbyte keeps credentials
   out of the connector entirely.
5. **Terminology collisions are the most expensive documentation debt in the set.** Kong's "service"
   carries four meanings and its "control plane" two. Terraform's "workspace" carries two and needed a
   permanent explanatory paragraph. SpiceDB's own FAQ concedes it uses `relation`, `permission`, and
   `relationship` "somewhat interchangeably". Every one of these was cheaper to prevent than to fix.

# Part A: Six project reviews

## A.1 Kong Gateway

### Configuration-domain map

Kong's proxy model is a small directed graph, and almost every page assumes it:
`Route -> Service -> (Upstream -> Target)`, with `Consumer`, `Plugin`, and the security entities
attaching at defined points, all enclosed by `Workspace` in the enterprise build and by a Konnect
control plane in the managed product
([gateway/entities](https://developer.konghq.com/gateway/entities/)).

| Object | Definition as documented | Cardinality |
| --- | --- | --- |
| Gateway Service | "Gateway Services represent the upstream services in your system" ([entities/service](https://developer.konghq.com/gateway/entities/service/)) | One service, many routes; optionally points at one upstream |
| Route | "A Route uses specific URL patterns and HTTP verbs to match incoming requests and pass them to a Gateway Service", and "A Route must be attached to a Gateway Service" ([entities/route](https://developer.konghq.com/gateway/entities/route/)) | Many routes to one service |
| Upstream and Target | "An Upstream enables load balancing by providing a virtual hostname and collection of Targets (upstream service instances)" ([entities/upstream](https://developer.konghq.com/gateway/entities/upstream/)) | One upstream, many targets |
| Consumer | "identifies an external client that consumes or uses the APIs" ([entities/consumer](https://developer.konghq.com/gateway/entities/consumer/)) | Grouped by consumer group |
| Plugin | Attaches globally or at service, route, consumer, or consumer-group scope, with a documented twelve-level precedence order and the rule that "A single plugin instance always runs once per request" ([entities/plugin](https://developer.konghq.com/gateway/entities/plugin/)) | Many per scope |
| Partial | "extract shared configurations into reusable entities that can be linked to multiple plugins" ([entities/partial](https://developer.konghq.com/gateway/entities/partial/)) | Referenced by many plugins |
| Vault | "securely store and then reference secrets from within other entities" so "secrets aren't visible in plaintext throughout the platform" ([secrets-management](https://developer.konghq.com/gateway/secrets-management/)) | Referenced by config fields |
| Workspace | "namespacing Kong Gateway entities so they can be managed independently" ([entities/workspace](https://developer.konghq.com/gateway/entities/workspace/)) | Contains the rest |

Ownership is stated unusually plainly in one place. On consumers: "the Kong team creates Consumers,
generates credentials, and shares them with the developers", contrasted with self-service
applications ([entities/consumer](https://developer.konghq.com/gateway/entities/consumer/)). Workspace
administration is split between super admins who create workspaces and workspace admins who own
contents. Process configuration in `kong.conf` is operator-owned and sits outside the entity graph
entirely ([gateway/configuration](https://developer.konghq.com/gateway/configuration/)).

Two deployment axes cut across all of it. Storage: `database=postgres` for a shared cluster against
`database=off` for declarative-only nodes loading a file "via the `declarative_config` property, or
via the Admin API using the `/config` endpoint"
([db-less-mode](https://developer.konghq.com/gateway/db-less-mode/)). Topology: hybrid mode "splits
all Kong Gateway nodes in a cluster into one of two roles", control plane nodes owning the database
and the Admin API, data plane nodes serving proxy traffic from a local cache so a control-plane
outage does not stop proxying ([hybrid-mode](https://developer.konghq.com/gateway/hybrid-mode/)).

### Documented onboarding ladder

The smallest configuration, verbatim from
[gateway/get-started](https://developer.konghq.com/gateway/get-started/):

```sh
echo '
_format_version: "3.0"
services:
  - name: example_service
    url: https://httpbin.konghq.com
' | deck gateway apply -
```

Two fields, a name and a URL, and the page notes the URL is "an attribute that populates the `host`,
`port`, and `path` of the Service". The rungs are one page, cumulative, and every one of them is
another `deck gateway apply -` of a slightly larger document: ping, service, route, proxy a request
to prove it, key authentication with a consumer and a credential, load balancing with an upstream and
two weighted targets, caching, rate limiting, cleanup. Then it hands off to the filtered how-to index,
the entities index, the configuration reference, and the plugin catalog.

The ladder's defining choice is that Kong teaches declarative-first and never shows the Admin API in
the getting-started path. The reader's first mental model is a file, not a POST.

### Simplified documentation tree

```text
(top level is by product, not by document type)
For agents & the CLI     tool docs         deck, kongctl, inso, MCP server
Platform > Gateway
  entities/*             concept           service, route, upstream, target, consumer,
                                           consumer-group, plugin, partial, workspace,
                                           vault, certificate, sni, key, key-set
  hybrid-mode,
  db-less-mode           concept
  get-started            tutorial
  configuration,
  manage-kong-conf       reference
  security/*             security          admin API hardening, authn/z, encryption,
                                           monitoring, vulnerability management
  self-managed-migration,
  upgrade/lts-upgrade-*  migration
  (troubleshooting)      absent as a hub   content lives in logs/, debugger/,
                                           data-plane-version-compatibility/
how-to/                  how-to            one filterable index across all products
api/                     reference         OpenAPI specs, pinned per release
```

The notable structural gap: there is no troubleshooting hub. Diagnostic material is distributed into
feature pages, which means a reader with a symptom rather than a feature has no entry point.

### How configuration facts are explained

**Defaults.** decK states the policy explicitly: "decK recognizes value defaults and doesn't interpret
them as changes to configuration", and rather than duplicating default tables it points at the live
schema endpoint, `curl -i http://localhost:8001/schemas/routes`, with a documented precedence of
instance value, then `_info: defaults`, then the Admin API schema
([deck/gateway/defaults](https://developer.konghq.com/deck/gateway/defaults/)). Plugin schemas come
from `/schemas/plugins/<name>`. This is the most important idea in Kong's documentation of
configuration: the schema endpoint is the authority, and the documentation refuses to become a stale
copy of it.

**Environment binding.** "declare an environment variable with the name of the setting, prefixed with
`KONG_`", and precedence is stated: "Kong Gateway checks existing environment variables first"
([manage-kong-conf](https://developer.konghq.com/gateway/manage-kong-conf/)).

**Secrets.** `{vault://<vault-name>/<path>/<key>}`, with a worked AWS versioned form
`{vault://aws/secret-name/foo#1}`, and an explicit warning that "secret names with forward slashes
require URL encoding to avoid unexpected fetching". Referenceable surface is "any field in the
kong.conf" plus plugin fields explicitly marked referenceable. Backends are tier-gated: environment
variables for open source, external vaults for enterprise. Rotation is honest about its limits: TTL
scheduled checks, plus an experimental `kong.vault.try` that is "currently limited to PostgreSQL
credentials" ([secrets-management](https://developer.konghq.com/gateway/secrets-management/)).

**Validation.** Two tiers. `deck file validate` is offline, parsing and foreign-key checking without
contacting Kong, and is documented as faster but able to catch fewer errors. `deck gateway validate`
adds a round trip through the live Admin API. A JSON Schema is published for editors at
`json.schemastore.org/kong_json_schema.json` ([deck](https://developer.konghq.com/deck/)).

**Generated values.** Authored files omit `id` and `created_at`; decK assigns and manages them, and
tags scope what a `dump` pulls back, so "decK tags each entity with a value, and ignores any resources
that don't have that tag", with `default_lookup_tags` resolving cross-file foreign keys without
absorbing those entities into the managed state
([deck/gateway/tags](https://developer.konghq.com/deck/gateway/tags/)).

### Example and schema consistency

Kong's answer is delegation rather than generation. Prose points at `/schemas` and at per-release
OpenAPI specifications, and the API index pins specs to a specific gateway release rather than to
"latest" ([api](https://developer.konghq.com/api/)). decK's diff semantics resolve defaults from the
live schema instead of from documentation. The documentation site itself is a static site with Vale
prose linting; no public evidence was found that prose examples are executed in CI, so example
correctness rests on the schema endpoint being the thing readers are sent to.

### Friction

- **"Service" carries at least four meanings.** The Gateway Service entity; the `kong.service` PDK
  module, "a set of functions to manipulate the connection aspect of the request to the Service"
  ([pdk/reference/kong.service](https://developer.konghq.com/gateway/pdk/reference/kong.service/));
  a Konnect API product that bundles multiple gateway services; and plain prose "service". No live
  glossary page reconciling them was found.
- **"Control plane" carries two.** A hybrid-mode node role and a Konnect SaaS object, and the Konnect
  page does not cross-reference the node-role meaning
  ([konnect](https://developer.konghq.com/konnect/)).
- **Duplicated path fields with two incompatible modes.** Route `paths` against Service `path`,
  reconciled by `path_handling`, where "v0... treats service.path, route.path and request path as
  segments" and "v1... treats service.path as a prefix". The docs recommend v0 and warn v1 "is not
  supported in the expressions router and may be removed"
  ([entities/route](https://developer.konghq.com/gateway/entities/route/)).
- **Tier gating found late.** Workspaces are revealed as enterprise-only on the workspace page rather
  than on the entities index, and the getting-started tutorial's prerequisites require either a Konnect
  personal access token or an enterprise licence, which is not visible from the gateway landing page.
- **Legacy host fragmentation.** Some `docs.konghq.com` paths redirect cleanly to
  `developer.konghq.com`, while old version-pinned paths land on a frozen archive host, so search
  results split across two corpora of differing freshness.

### Authored intent against generated and runtime configuration

Kong draws the line through tooling behavior rather than file syntax. Authored YAML omits generated
identifiers, defaults are resolved from the live schema rather than written into the file, and tags
keep a `dump` from pulling other teams' or UI-created entities into the authored state. In hybrid and
Konnect deployments the control plane compiles authored intent into what data planes run, and the
data-plane local cache is purely derived.

### Three practices Registry Stack should adopt

1. **Make the schema the authority and refuse to copy it into prose.** decK's "recognizes value
   defaults and doesn't interpret them as changes", plus pointing readers at `/schemas`, is the pattern
   Registry Stack should apply to `schemas/registry-relay.config.schema.json` and
   `schemas/registry-notary.config.schema.json`: generate the reference, never hand-write it, and state
   the precedence rule for a default in one place.
2. **Ship a two-tier validate and name the difference.** Registry Stack already has the tiers,
   `registryctl test` offline and `check --environment` against generated product configuration, plus a
   `--live` mode restricted to explicitly non-production environments. Kong's contribution is telling
   the reader what each tier can and cannot catch, in one sentence each.
3. **Teach declarative-first, with one cumulative example.** Kong's whole ladder is one growing YAML
   document applied repeatedly. Registry Stack's starter journeys already work this way; the ladder
   should say so, so a reader knows the file they end with is the file they started with.

### Two practices Registry Stack should avoid

1. **Terminology drift across product surfaces.** Four meanings of "service" and two of "control
   plane" cost Kong a public renaming exercise. Registry Stack should pin authoring vocabulary in
   `spec/rs-terms` and the glossary before it multiplies, particularly around "service", which already
   means an evidence service in the project file and a deployment service in the environment file.
2. **No troubleshooting entry point.** Distributing diagnostics into feature pages leaves a reader who
   has a symptom, not a feature, with nowhere to start. Registry Stack has the same shape today, across
   two separate code families and with no index for either. The roughly fifteen
   `registryctl.authoring.*` diagnostics in
   `crates/registryctl/src/project_authoring/diagnostics.rs` reach no published page, and only
   `registryctl.authoring.diagnostics.truncated` is named in prose on `reference/registryctl`. The
   offline fixture errors are a different family, defined in
   `crates/registryctl/src/project_authoring/fixtures.rs`, and exactly one of them,
   `input.pattern_mismatch`, appears in a tutorial troubleshooting table.

## A.2 Tyk

### Configuration-domain map

Tyk carries two authored dialects over one runtime. A **Tyk OAS API definition** is a standard
OpenAPI document plus one vendor extension: "The OpenAPI description of the upstream API is not
enough on its own to configure the Gateway. This is where the Tyk Vendor Extension comes in."
The extension `x-tyk-api-gateway` holds four sections, `info` (proxy metadata), `server`
(client-to-gateway integration, listen path, authentication), `upstream` (gateway-to-upstream
targets, load balancing, rate limits), and `middleware`, and Tyk treats "the OpenAPI description as
the source of truth for the data stored within it"
([gateway-config-tyk-oas](https://tyk.io/docs/api-management/gateway-config-tyk-oas)). The **Tyk
Classic API definition** is the legacy flat JSON dialect, still required for GraphQL, XML/SOAP, and
TCP, with the guidance that "From Tyk 5.8 we recommend that any REST APIs are migrated to the newer
Tyk OAS API style"
([gateway-config-tyk-classic](https://tyk.io/docs/api-management/gateway-config-tyk-classic)).

Around those sit **Security Policies**, "a reusable template or blueprint that defines a set of
access rights, rate limits, and quotas", many sessions to one policy, with more than one policy
attachable to a session, and, importantly, "the Gateway does not permanently copy the Policy's rules
into the Session data in Redis... Policies are applied dynamically during request processing"
([policies](https://tyk.io/docs/api-management/policies)). **Keys and sessions** are Redis-resident
runtime state, not authored configuration
([what-is-a-session-object](https://tyk.io/docs/getting-started/key-concepts/what-is-a-session-object/)).
Process configuration lives in `tyk.conf` for the Gateway and a parallel file for the Dashboard
([tyk-oss-gateway/configuration](https://tyk.io/docs/tyk-oss-gateway/configuration)).

The ownership root is the **Organisation**: "The organization object is the most fundamental object
in a Tyk setup, all other ownership properties hang off the relationship between an organization and
its APIs, Policies and API Tokens"
([dashboard-configuration](https://tyk.io/docs/api-management/dashboard-configuration)). The
**Portal catalogue** is deliberately decoupled from APIs: catalogue entries "are not actual directly
tied to APIs in any way, they are connected to policies", which lets an operator "separate
'management' from 'consumption'"
([api-catalogue](https://tyk.io/docs/getting-started/key-concepts/api-catalogue/)). In Kubernetes,
**Tyk Operator** CRDs (`ApiDefinition`, `TykOasApiDefinition`, `SecurityPolicy`) become the authored
plane, the Operator "functions as a system user, bound by Organization and RBAC rules", and the docs
tell teams to "set up RBAC such that human users cannot have the 'write' permission on the API
definition endpoints"
([automations/operator](https://tyk.io/docs/api-management/automations/operator)).

### Documented onboarding ladder

The floor is keyless. "Open or keyless authentication allows access to APIs without any
authentication", and "Tyk OAS APIs are already open by default unless you explicitly configure
authentication"
([open-keyless](https://tyk.io/docs/basic-config-and-security/security/authentication-authorization/open-keyless/)).
The smallest thing taught is a reverse proxy with two required fields, a listen path and an upstream
URL, and the same result is shown three ways, Dashboard form, `POST /tyk/apis` on the Gateway API,
and a JSON file in the Gateway's app folder followed by a reload
([getting-started/create-api](https://tyk.io/docs/getting-started/create-api/),
[configure-first-api](https://tyk.io/docs/getting-started/configure-first-api)).

The rungs after that, in the order the pages cross-link: auth token, "the default mode of any API
Definition created for Tyk"
([bearer-token](https://tyk.io/docs/api-management/authentication/bearer-token)); security policies;
rate limits and quotas; traffic transformation
([request-body](https://tyk.io/docs/api-management/traffic-transformation/request-body));
versioning, where OAS and Classic diverge structurally; event-driven APIs and streams
([event-driven-apis](https://tyk.io/docs/api-management/event-driven-apis)); and multi-data-centre
operation. Tyk does not publish this as one canonical numbered path. The quickstart's own next steps
name only rate limiting and the Dashboard guide, so the ladder is reconstructed from cross-links
rather than declared.

### Simplified documentation tree

```text
Getting Started            tutorial + concept   create-api, configure-first-api, key-concepts/*
API Management             concept + how-to     gateway-config-tyk-oas, gateway-config-tyk-classic,
                                               policies, sync, automations/operator,
                                               authentication/*, traffic-transformation/*
Tyk APIs                   reference            tyk-gateway-api/api-definition-objects/*
Tyk Configuration Ref.     reference            kv-store, securing-system-payloads,
                                               tyk-oss-gateway/configuration
Tyk Governance             how-to               api-labeling
Developer Support          troubleshooting +    upgrading, release notes, release summary
                           migration
Product Stack              troubleshooting      tyk-operator/troubleshooting/*
```

Two structural facts dominate. The tree is versioned per release, with URLs pinned as `/docs/4.1/`,
`/docs/5.7/`, `/docs/nightly/`. And the OAS and Classic dialects each get their own subtree, their
own object reference, and their own versioning model, so a reader who lands from search must first
work out which dialect the page describes.

### How configuration facts are explained

`tyk.conf` "by default is called `tyk.conf`, though it can be renamed and specified using the
`--conf` flag". Environment variables are mechanical: `TYK_GW_`-prefixed names "created from the dot
notation versions of the JSON objects contained with the config files", so
`security.private_certificate_encoding_secret` becomes
`TYK_GW_SECURITY_PRIVATECERTIFICATEENCODINGSECRET`, and they "take precedence over the values in the
configuration file" ([tyk-oss-gateway/configuration](https://tyk.io/docs/tyk-oss-gateway/configuration)).

The best page in the whole set is the KV store reference, because it documents secret resolution
*timing* per location rather than only syntax. `consul://`, `vault://`, `secrets://`, `env://`, and
`file://` are accepted, but `tyk.conf` references are "retrieved at gateway startup only. A full
gateway restart is required", API-definition references are retrieved "when the API is loaded or
reloaded... on the next gateway hot-reload", and `$secret_*` references inside transformation
middleware are "retrieved for each call to the API"
([kv-store](https://tyk.io/docs/tyk-configuration-reference/kv-store/)). Hot reload itself is
`/tyk/reload`.

Generated values are thin. `api_id` is author-set with a recommendation to use a UUID, and `org_id`
is prepended to keys Tyk generates.

### Example and schema consistency

Tyk publishes a real machine-checkable artifact for its extension, a JSON Schema at
`raw.githubusercontent.com/TykTechnologies/tyk-schemas/main/JSON/draft-04/schema_TykOasApiDef_3.0.x.json`,
plus "a Tyk VS Code extension that provides Tyk API schema validation and auto-completion", and it
tells authors to "iterate on that document within your source control system until you are totally
happy" before deploying
([gateway-config-managing-oas](https://tyk.io/docs/api-management/gateway-config-managing-oas)).
Declarative round-tripping is Tyk Sync, which exists "to manage and synchronise a Tyk installation
with your version control system (VCS)"
([sync/quick-start](https://tyk.io/docs/api-management/sync/quick-start)).

What is missing is any published statement that prose examples are generated from that schema or
drift-checked against it. The schema exists for authors' editors, not for the documentation build.

### Friction

- **Two dialects, no forced cutover.** Auth, rate limiting, and versioning are each documented twice
  under different field names in different subtrees, and migration is worded as a recommendation.
- **Policy and key overlap.** "Policy templates are similar to key definitions in that they allow
  you to set quotas, access rights and rate limits for keys". The same control exists at two layers
  with dynamic-overlay semantics a reader has to learn rather than infer
  ([policies](https://tyk.io/docs/api-management/policies)).
- **Path terminology.** Listen path, target URL, and strip listen path are defined together, with a
  documented trap: `strip_listen_path` "has no effect" when a request arrives via `/{APIID}/`
  ([url-matching](https://tyk.io/docs/getting-started/key-concepts/url-matching)). Tyk does flag one
  collision itself: "It's important not to confuse the *API proxy* with the API for the upstream
  service"
  ([what-is-an-api-definition](https://tyk.io/docs/getting-started/key-concepts/what-is-an-api-definition/)).
- **Late prerequisites.** The Redis dependency appears in the OSS overview, "no 3rd party
  dependencies aside from Redis for distributed rate-limiting and token storage"
  ([tyk-oss-gateway](https://tyk.io/docs/tyk-oss-gateway/)), while database sizing sits on a separate
  production-planning page.
- **Tier gating found late.** The Gateway is described as "'Batteries-included', with no feature
  lockout", but self-managed node counts are gated by licence tier on a licensing page rather than
  inline in the configuration reference.

### Authored intent against generated and runtime configuration

Tyk's separation is clean in practice and never stated as a doctrine. API definitions and policies
are author-time and git-bound, with Tyk Sync as the round-trip. Sessions and keys are runtime, read
from Redis per request, with policy rules "applied dynamically" rather than baked in. Under the
Operator, CRDs are desired state and `latestTransaction.Status`/`Time`/`Error` report convergence.
A reader assembles this model themselves.

### Three practices Registry Stack should adopt

1. **Document secret-reference resolution timing per location, beyond syntax.** The KV store page's
   split between startup-only, reload-time, and per-request resolution is the single most operationally
   useful configuration page in this review. Registry Stack's `${VAR}`, `${VAR:-fallback}`, and
   `${VAR:?message}` expansion happens before YAML parsing, at product config-load time, and it happens
   the same way for a local configuration file and for the configuration document inside a signed Config
   Bundle. Both paths run through the same loader, `parse_expanded_config` alongside
   `validate_signed_bundle_config_document` in `crates/registry-notary/src/config_loader.rs`. The docs
   should say that as plainly as Tyk says its three cases, because an operator who believes expansion is
   tied to bundle activation will draw the wrong conclusion about when an environment change takes
   effect.
2. **Publish the authoring schemas as fetchable URLs with editor wiring, and say so on a page.**
   `registryctl authoring schema --kind` and the `init`-time VS Code and Zed configuration already do
   the mechanism. Tyk's contribution is treating the schema as a documented, addressable artifact.
3. **Keep one artifact the source of truth and add capability in a namespaced block.** The
   "OpenAPI description is the source of truth" rule maps directly onto Registry Stack's split between
   an integration's fixed request contract and the environment's binding of that contract, and it is
   worth stating in the same words.

### Two practices Registry Stack should avoid

1. **Letting a second authored dialect live indefinitely.** Classic and OAS have coexisted for years
   with soft migration guidance, doubling the reference surface. Registry Stack has one authoring
   contract today and five schemas; adding a second dialect for any source shape should require a
   dated removal plan for the first.
2. **Reconstructing the ladder from cross-links.** Tyk's rungs exist but are never published as one
   ordered path with exit tests, so the reader's route depends on which page search delivered.

## A.3 Airbyte Connector Builder

### Configuration-domain map

One YAML tree rooted at a `DeclarativeSource`. Top-level keys are `version`, "The version of the
Airbyte CDK used to build and test the source", `check`, which "Defines the streams to try reading
when running a check operation", `definitions`, `streams` and `dynamic_streams`, `spec`, plus
`concurrency_level` and `api_budget`
([understanding-the-yaml-file/reference](https://docs.airbyte.com/platform/connector-development/config-based/understanding-the-yaml-file/reference)).

Each stream is a `DeclarativeStream`, "A stream whose behavior is described by a set of declarative
low code components", and its `retriever` composes four responsibilities the documentation names
individually: "Requester: Describes how to submit requests to the API source", "Paginator: Describes
how to navigate through the API's pages", "Record selector: Describes how to extract records from a
HTTP response", and "Partition router: Describes how to retrieve data across multiple resource
locations"
([yaml-overview](https://docs.airbyte.com/platform/connector-development/config-based/understanding-the-yaml-file/yaml-overview)).
The `HttpRequester` holds `url_base`, `path`, `http_method`, a request options provider, an
authenticator, and an error handler
([requester](https://docs.airbyte.com/platform/connector-development/config-based/understanding-the-yaml-file/requester)).

The ownership boundary is the sharpest of any project in this review, because it is enforced by the
interpolation syntax rather than by convention.

| Plane | Owner | Where it lives |
| --- | --- | --- |
| Manifest: streams, retriever, requester, paginator, error handler | Connector author | The YAML, fixed at build time |
| `spec.connectionSpecification` | Connector author declares it, end user fills it | A JSON Schema rendered as a form; `airbyte_secret` makes Airbyte "obfuscate fields in the UI and API" ([connector-specification-reference](https://docs.airbyte.com/platform/connector-development/connector-specification-reference)) |
| Cursor state | Runtime | "the cursor value of the last record will be saved as part of the connection as the new cutoff date" ([incremental-sync](https://docs.airbyte.com/platform/connector-development/connector-builder-ui/incremental-sync)) |
| Discovered schema | Runtime, written back into the manifest | "By default, new streams are configured to automatically import the detected schema into the declared schema on every test read" ([record-processing](https://docs.airbyte.com/platform/connector-development/connector-builder-ui/record-processing)) |
| Testing values | Ephemeral | "will be used but not saved" ([overview](https://docs.airbyte.com/platform/connector-development/connector-builder-ui/overview)) |

`{{ config['start_time'] }}` is the seam. "The engine will evaluate the content passed within
`{{...}}`", with `config` always in scope and some components injecting extra context
([string-interpolation](https://docs.airbyte.com/platform/connector-development/config-based/advanced-topics/string-interpolation)).
Anything inside the braces is end-user territory; anything outside is author territory.

Defaults are documented where they matter. Unconfigured error handling retries "requests that
received a 429 and 5XX status code ... 5 times using a 5-second exponential backoff"
([error-handling](https://docs.airbyte.com/platform/connector-development/connector-builder-ui/error-handling)).

### Documented onboarding ladder

"In this tutorial, you'll create an Airbyte connector using the Connector Builder UI to read and
extract data from an API called the Exchange Rates API"
([tutorial](https://docs.airbyte.com/platform/connector-development/connector-builder-ui/tutorial)).
The smallest configuration is one unauthenticated GET: set the API endpoint URL, set HTTP method to
`GET`, press Test. Authentication arrives immediately after, as a single declared input with a name,
a field ID, and a type.

The rungs, in the order the tutorial's own "What's next?" lists them: AI Assistant, authentication,
record processing, pagination, incremental sync, partitioning, error handling, stream templates,
asynchronous job streams. Custom Python components sit deliberately outside the ladder as an escape
hatch, marked unsafe and experimental, unavailable on the hosted product, and gated behind
`AIRBYTE_ENABLE_UNSAFE_CODE=true`
([custom-components](https://docs.airbyte.com/platform/connector-development/connector-builder-ui/custom-components)).
Publishing closes it: to a workspace, or to the public catalog through a pull request, where
"Reviews typically take under a week"
([submit-new-connector](https://docs.airbyte.com/platform/connector-development/submit-new-connector)).

### Simplified documentation tree

```text
Connector Builder (UI docs)
  Overview                       concept
  Tutorial                       tutorial
  Global configuration,
  Authentication, Record
  processing, Pagination,
  Incremental sync,
  Partitioning, Error handling    concept
  Stream templates               concept + how-to
  Custom components              how-to
Low-Code CDK (YAML docs)
  Overview                       concept
  Understanding the YAML file    concept + reference
    yaml-overview, requester, record-selector, request-options, reference
  Advanced topics                concept + reference
    parameters, string-interpolation, custom-components, component-schema-reference
Python CDK                       tutorial + reference
Testing connectors               how-to
Contribute a new connector       how-to
Managing breaking changes        migration
Connector specification ref.     reference + security
Debugging Docker containers      troubleshooting
Best practices, UX handbook      concept
```

The defining structural fact is duplication by audience. "The Connector Builder provides an intuitive
user interface on top of the low-code YAML format" and authors can "seamlessly switch between the
visual UI and direct YAML editing"
([overview](https://docs.airbyte.com/platform/connector-development/connector-builder-ui/overview)),
which means every concept is documented twice, once in UI terms under `connector-builder-ui/*` and
once in schema terms under `config-based/*`. There is no Builder-scoped security or troubleshooting
section; secrets live inside the specification reference, and the zero-record schema pitfall lives
inside the record-processing concept page.

### How configuration facts are explained

Secrets are declarative and scoped to the user plane. `airbyte_secret: true` obfuscates a field in UI
and API, the Builder exposes it as a per-input toggle, and the docs state plainly that "Credentials,
like a username and password, aren't specified as part of the connector"
([authentication](https://docs.airbyte.com/platform/connector-development/connector-builder-ui/authentication)).
Build-time testing values are never persisted.

Reuse is layered and the precedence is written down. `$ref` handles static structure; `$parameters`
are "passed down from a parent component to its subcomponents ... to avoid repetitions", and the rule
is "Explicit values win... Child parameters supersede parent ones"
([parameters](https://docs.airbyte.com/platform/connector-development/config-based/advanced-topics/parameters)).

Validation is execution. The testing panel shows records, request, and response, with "a dropdown
above the records view that lets you step through" each slice and request pair. That per-slice
request and response inspector is the single most transferable idea in Airbyte's documentation: the
author sees the exact wire interaction their configuration produced, not a description of it.

### Example and schema consistency

Both the reference page and the component schema reference delegate to one file: "For the technical
JSON schema definition that low code manifests are validated against, see
`declarative_component_schema.yaml`"
([component-schema-reference](https://docs.airbyte.com/platform/connector-development/config-based/advanced-topics/component-schema-reference)).
That schema is the validator, and the prose reference is a hand-authored companion to it rather than a
render of it, so drift between the two is structurally possible. The real consistency mechanism is the
live-test loop, which catches drift by execution. Documented pytest-based unit, integration, and
acceptance testing exists separately and does not appear to assert declarative-schema conformance
([testing-connectors](https://docs.airbyte.com/platform/connector-development/testing-connectors)).

### Friction

- **Three words near one idea.** "Stream", "partition" (a subset of data), and "slice" (an execution
  context exposed as `{{ stream_slice }}`) are distinguished only inside the partitioning page, with no
  central glossary
  ([partitioning](https://docs.airbyte.com/platform/connector-development/connector-builder-ui/partitioning)).
- **`spec`, `config`, and `$parameters`** are introduced on three pages that do not link to each other.
- **One containment fact stated once.** That `retriever` contains `requester` appears on the YAML
  overview and nowhere prominent, and it is the fact a reader most needs to navigate the reference.
- **The same knob in three places, with no precedence.** Request options can be set on the requester's
  options provider, on `DefaultPaginator` as `page_size_option` and `page_token_option`, and on
  `DatetimeBasedCursor` as `start_time_option` and `end_time_option`. Three injection points into one
  HTTP request, and no documented rule for a collision
  ([request-options](https://docs.airbyte.com/platform/connector-development/config-based/understanding-the-yaml-file/request-options)).
- **A cliff between tutorial and reference.** The tutorial's first stream has five fields; the
  reference enumerates dozens of component types with full property specifications, and there is no
  cookbook tier in between.
- **The UI cannot express everything the YAML can.** Custom components require dropping to the YAML
  editor, which means the visual tool is not a complete view of the model.

### Authored intent against generated and runtime configuration

Airbyte's separation is explicit and enforced by mechanism rather than by prose: the manifest is
author intent; connection configuration is user-supplied through a declared JSON Schema; cursor state
overwrites the authored start value on every run; discovered schemas are written back from live reads;
testing values are ephemeral. The one soft spot is schema write-back, where a runtime-discovered
artifact lands inside the authored file, and the docs warn that overriding it manually can produce
silent zero-record syncs.

### Three practices Registry Stack should adopt

1. **Show the wire interaction per case, stepping through cases.** The testing panel's per-slice
   request and response view is what `registryctl test --trace` already produces for one fixture. The
   adoptable part is presenting it as the primary authoring loop in documentation, one screen per
   fixture, so the reader learns to read the trace rather than to trust the config.
2. **Make the author and end-user planes visible in the syntax, and document the precedence of every
   layered value.** Airbyte's `{{ config[...] }}` boundary plus the explicit "Child parameters supersede
   parent ones" rule is the pattern. Registry Stack's equivalent boundary is the closed set of
   consultation input mappings, `request.target.id`,
   `request.target.identifiers.<stable-id>`, and `request.target.attributes.<stable-name>`, together
   with the rule that consultation inputs "cannot select an origin, method, credential, capability,
   projection, or response mapper". That rule is currently stated inside a tutorial and deserves a
   reference page.
3. **State the unconfigured default behavior for anything with retries or limits.** "429 and 5XX ...
   5 times using a 5-second exponential backoff" is one sentence that saves a reader a debugging
   session. Registry Stack's byte ceilings, timeouts, and cardinality bounds deserve the same
   treatment in the generated reference.

### Two practices Registry Stack should avoid

1. **Letting one value be settable from several components without a documented precedence.** For
   authorization, disclosure, and limits, a field reachable from two authored surfaces needs an
   explicit, tested precedence rule, or it needs to be reachable from one surface only. Registry Stack
   is currently in the good position of having environment binding and integration contract disjoint;
   the documentation should say that is deliberate.
2. **Documenting the same concept twice for two audiences.** The UI and YAML trees double the surface
   area and let the two drift. Registry Stack's analogue is the split between authored surfaces and
   generated product configuration; one concept page covering both planes beats two parallel trees.

## A.4 SpiceDB

### Configuration-domain map

Three planes, cleanly separated by page placement and never drawn together on one page.

**Schema.** Author-time policy: `definition`, `relation`, `permission`, the arrow operator `->`, and
the `+`, `-`, `&` set operators, plus caveats, wildcards, and subject relations. The distinction that
carries the whole model: "A `relation` defines how two objects (or an object and subject) can relate
to one another" against "A permission defines a *computed* set of subjects that have a permission of
some kind on the object" ([concepts/schema](https://authzed.com/docs/spicedb/concepts/schema)). The
modeling guide states the consequence: "A `permission`, unlike a `relation`, cannot be explicitly
written in the database: it is *computed* at query time"
([modeling/developing-a-schema](https://authzed.com/docs/spicedb/modeling/developing-a-schema)).
Owned by the schema author, shipped through `WriteSchema`.

**Server and operations.** `spicedb serve` flags, datastore engine, dispatch and cluster, caches,
TLS, `--grpc-preshared-key`
([concepts/commands](https://authzed.com/docs/spicedb/concepts/commands),
[getting-started/configuration](https://authzed.com/docs/spicedb/getting-started/configuration)).
Owned by the operator.

**Relationships.** Runtime instances of relations, written by the application, along with ZedTokens
and per-request consistency modes. Explicitly not configuration:
"ZedToken is the SpiceDB equivalent of Google Zanzibar's Zookie concept which protects users from
the New Enemy Problem"
([reference/zedtokens-and-zookies](https://authzed.com/docs/reference/zedtokens-and-zookies)), and
consistency is "the ability to specify the desired consistency level on a per-request basis by using
ZedTokens" ([concepts/consistency](https://authzed.com/docs/spicedb/concepts/consistency)). Owned by
the application developer.

### Documented onboarding ladder

The first configuration is a six-line schema, from "Protecting a Blog Application"
([getting-started/protecting-a-blog](https://authzed.com/docs/spicedb/getting-started/protecting-a-blog)):

```text
definition user {}
definition post {
  relation reader: user
  relation writer: user
  permission read = reader + writer
  permission write = writer
}
```

The rungs: write relationships, where "Writing relationships returns a ZedToken which is critical to
ensuring performance and consistency"; check a permission, where "Checks not only test for the
existence of direct relationships, but also compute and traverse transitive relationships"; then
develop the schema with assertions and expected relations
([modeling/validation-testing-debugging](https://authzed.com/docs/spicedb/modeling/validation-testing-debugging));
then advanced modeling, custom roles
([modeling/access-control-management](https://authzed.com/docs/spicedb/modeling/access-control-management)),
attributes through caveats written in CEL
([concepts/caveats](https://authzed.com/docs/spicedb/concepts/caveats)), multi-tenancy through arrow
traversal, and subject relations for tokens
([modeling/representing-users](https://authzed.com/docs/spicedb/modeling/representing-users)); then
operations, datastore choice
([concepts/datastores](https://authzed.com/docs/spicedb/concepts/datastores)) and datastore
migrations ([concepts/datastore-migrations](https://authzed.com/docs/spicedb/concepts/datastore-migrations)).

The ladder's distinguishing feature is that rung four is a *testing* rung. The reader is taught to
assert the schema before deploying anything.

### Simplified documentation tree

```text
Getting Started        tutorial      protecting-a-blog, first-steps, installing-zed,
                                     configuration, faq, "Coming from" OPA/Rails
Concepts               concept       zanzibar, schema, writing-relationships, querying-data,
                                     consistency, datastores, caveats, watch, commands (reference)
Modeling               how-to        developing-a-schema, migrating-schema, composable-schemas,
                                     access-control-management, incorporating-attributes,
                                     protecting-a-list-endpoint, validation-testing-debugging
Best Practices         concept       schema testing strategies, schema-as-migrations
API Reference          reference     off-site: buf.build/authzed/api protobuf docs
Managed SpiceDB        product       AuthZed Cloud only: audit logging, private networking, ...
Managed Materialize    product       unrelated data product, sibling nav section
```

Troubleshooting is folded into the validation page rather than standing alone. There is no
OSS-scoped security page in the tree. Migration is split in two, schema migration under Modeling and
datastore migration under Concepts, and the reader has to learn those are different things.

### How configuration facts are explained

Environment binding is mechanical and stated once: kebab-case flag to `SPICEDB_`-prefixed screaming
snake case, so `--datastore-conn-pool-read-max-open 50` is
`SPICEDB_DATASTORE_CONN_POOL_READ_MAX_OPEN=50`, with an optional `spicedb.env` file in the working
directory ([getting-started/configuration](https://authzed.com/docs/spicedb/getting-started/configuration)).

Insecure defaults are documented, though not loudly. `serve-testing` is "An in-memory SpiceDB server
which serves completely isolated datastores per client-supplied auth token used", which quietly turns
the auth token into a datastore selector rather than a credential
([concepts/commands](https://authzed.com/docs/spicedb/concepts/commands)). The memory datastore is
"Recommended for local development and integration testing", "Fully ephemeral; all data is lost when
the process is terminated", and cannot run in HA because "multiple instances will not share the same
in-memory data" ([concepts/datastores](https://authzed.com/docs/spicedb/concepts/datastores)).

Advanced options exist and are kept out of the ladder: dispatch cluster and concurrency limits,
namespace and dispatch caches, relationship expiration, and the Watch API
([concepts/watch](https://authzed.com/docs/spicedb/concepts/watch)).

### Example and schema consistency

This is the strongest mechanism in the whole review. A validation file combines `schema` or
`schemaFile`, `relationships`, `assertions` (`assertTrue`, `assertFalse`, `assertCaveated`), and
`validation` for expected relations, and *the same file* is consumed by the interactive Playground
and by `zed validate validations/*` on the command line
([modeling/validation-testing-debugging](https://authzed.com/docs/spicedb/modeling/validation-testing-debugging)).
One fixture format, two consumers, one of them a CI-runnable binary. Best Practices raises it to
policy, naming "Schema testing strategies" and treating schema updates like database migrations
([best-practices](https://authzed.com/docs/best-practices)).

Whether the schema snippets embedded in prose pages are themselves executed by a documentation build
is not stated anywhere found, so that remains unverified.

### Friction

- **Three words for one idea.** `relation` is declared and written, `permission` is declared and
  computed, `relationship` is the runtime instance, and the FAQ concedes it "uses these terms somewhat
  interchangeably" ([getting-started/faq](https://authzed.com/docs/spicedb/getting-started/faq)).
  `subject`, `resource`, and `object` overlap without a formal disambiguation.
- **A synonym inherited from a paper.** ZedToken and zookie are bridged explicitly, which is good, and
  still adds a term to carry.
- **The arrow is a cliff.** Union, intersection, and exclusion are flat and learnable; the first arrow
  traversal is a jump from role lists to graph traversal, and it arrives without ceremony.
- **Two patterns, no default.** Role relations and custom roles sit on one page with no stated
  recommendation ([modeling/access-control-management](https://authzed.com/docs/spicedb/modeling/access-control-management)).
- **Landing page with no command.** "First Steps" defers every runnable command to child pages
  ([getting-started/first-steps](https://authzed.com/docs/spicedb/getting-started/first-steps)).
- **The API reference is on another site.** The authoritative gRPC and HTTP reference lives on
  buf.build, outside the documentation's own styling and navigation.
- **Open source and commercial in one nav.** SpiceDB, Managed SpiceDB, and an unrelated Managed
  Materialize product are sibling top-level sections ([authzed.com/docs](https://authzed.com/docs)),
  so browsing surfaces cloud-only features beside open-source ones.

### Authored intent against generated and runtime configuration

Schema is authored, versioned like code, and type-checked at write time: "it is not possible to break
the type safety of a schema"
([modeling/migrating-schema](https://authzed.com/docs/spicedb/modeling/migrating-schema)).
Relationships are runtime application data. Permission results are neither, computed at query time
over an operator-tunable cache with per-request consistency. The separation is learned from section
placement rather than stated as a model.

### Three practices Registry Stack should adopt

1. **One assertion-fixture format, run by both the interactive tool and the CLI.** Registry Stack
   already has the harder half: `integrations/*/fixtures/*.yaml` run offline through the real Relay
   decoder and claim evaluator, and the CLI derives malformed-decoding, byte-ceiling, timeout,
   authorization-before-source, and output-minimization cases from them. What SpiceDB adds is the
   discipline of making the fixture format itself a documented, first-class authoring artifact with
   its own page, rather than an implementation detail of a tutorial.
2. **Treat authored-policy change as a migration with an explicit safe and unsafe operation matrix.**
   "A `relation` can only be removed if all of the relationships referencing it have been deleted and
   it is not referenced by any other relation or permission" is the shape to copy for Notary claim
   identifiers, Relay scopes, and disclosure modes. Registry Stack already computes semantic change
   against a signed baseline across five review classes; the missing piece is the reader-facing matrix
   of which changes are additive and which require re-approval.
3. **Say the computed-versus-stored distinction in the first sentence of the concept page.** SpiceDB's
   `relation` against `permission` line is the clearest sentence in this review. Registry Stack has the
   same distinction between a declared output and a claim derived by a CEL rule, and it deserves the
   same one-line treatment.

### Two practices Registry Stack should avoid

1. **Letting near-synonyms accumulate without a single canonical terms page.** Registry Stack already
   carries consultation, integration, capability, output, claim, evidence, disclosure mode, and
   credential. The glossary and `spec/rs-terms` exist; the risk is new authoring vocabulary landing in
   tutorials without reaching them.
2. **Hosting the authoritative reference somewhere else.** Pushing readers to a different site
   mid-task breaks the reading context. Registry Stack's own convention already resolves this by
   generating OpenAPI into the site, and the same rule should bind the configuration schemas rather
   than pointing readers at a pinned source file in the repository.

## A.5 Terraform

### Configuration-domain map

The authored language is a closed set of block types, each with its own reference page under
`/terraform/language/block/*`.

- **`terraform`**, the settings root: `required_version`, "Specifies which version of the Terraform
  CLI is allowed to run the configuration", `required_providers`, `backend`, `cloud`, `provider_meta`,
  `experiments` ([language/block/terraform](https://developer.hashicorp.com/terraform/language/block/terraform)).
- **`provider`**: "Use the `provider` block to declare and configure Terraform plugins, called
  providers", with `alias` for multiple configurations
  ([language/providers/configuration](https://developer.hashicorp.com/terraform/language/providers/configuration)).
- **`resource`** against **`data`**, separated in the glossary: a resource "describes one or more
  infrastructure objects", a data source is "A resource-like object... Unlike resources, data sources do
  not create or manage infrastructure" ([docs/glossary](https://developer.hashicorp.com/terraform/docs/glossary)).
- **`variable`**, `output`, `locals`, `module`.
- **State-address blocks**: `moved`, "Use this block to programmatically change the address of a
  resource" ([language/block/moved](https://developer.hashicorp.com/terraform/language/block/moved)),
  `removed`, and `import`, which can scaffold configuration through `terraform plan` with
  `generate-config-out` ([language/import](https://developer.hashicorp.com/terraform/language/import)).
- **`check`**, the only non-blocking validation surface: "Use the `check` block to validate your
  infrastructure outside of the typical resource lifecycle", running "as the last step of plan or apply
  operation", and "Unlike other ways of validating your configuration, `check` blocks do not block
  operations" ([language/checks](https://developer.hashicorp.com/terraform/language/checks)).
- **Provisioners**, framed as a warning: "Terraform is primarily designed for immutable infrastructure
  operations, so we strongly recommend using purpose-built solutions to perform post-apply operations",
  and "Terraform cannot predictably model provisioner behaviors represented in the configuration"
  ([resources/provisioners/syntax](https://developer.hashicorp.com/terraform/language/resources/provisioners/syntax)).
- **Meta-arguments**, a closed set with a page each: `count`, `for_each`, `depends_on`, `lifecycle`,
  `provider`, `providers`, with a stated preference for implicit edges: "Instead of `depends_on`, we
  recommend using expression references to imply dependencies when possible"
  ([meta-arguments/depends_on](https://developer.hashicorp.com/terraform/language/meta-arguments/depends_on)).

Ownership is documented as a rule with teeth, not a suggestion. Provider configuration belongs to the
root module: "Define provider configurations in the root module of your Terraform configuration. Child
modules receive their provider configurations from their parent modules, so we strongly recommend
against defining `provider` blocks in child modules", and the module-authoring page hardens it to "A
module intended to be called by one or more other modules must not contain any `provider` blocks",
with the consequence spelled out, "A module with its own provider configurations is not compatible with
`for_each`, `count`, or `depends_on`"
([modules/develop/providers](https://developer.hashicorp.com/terraform/language/modules/develop/providers)).

Credentials are deliberately outside configuration. Providers "support shell environment variables or
other alternate sources for their configuration values, which helps keep credentials out of your
version-controlled Terraform configuration", and the backend page warns: "We recommend using
environment variables to supply credentials and other sensitive data. If you use `-backend-config` or
hardcode these values directly in your configuration, Terraform will include these values in both the
`.terraform` subdirectory and in plan files. This can leak sensitive credentials"
([language/backend](https://developer.hashicorp.com/terraform/language/backend)).

The non-configuration planes are named and bounded: **state**, "Terraform's cached information about
your managed infrastructure and configuration", with "the state format is subject to change in new
Terraform versions" ([language/state](https://developer.hashicorp.com/terraform/language/state));
**plan files**, where "The generated file is not in any standard format intended for consumption by
other software" ([cli/commands/plan](https://developer.hashicorp.com/terraform/cli/commands/plan));
and the **registry's generated provider reference**.

### Documented onboarding ladder

The smallest configuration, verbatim from
[tutorials/docker-get-started/docker-build](https://developer.hashicorp.com/terraform/tutorials/docker-get-started/docker-build):

```terraform
terraform {
  required_providers {
    docker = {
      source = "kreuzwerker/docker"
      version = "~> 4.2.0"
    }
  }
}

provider "docker" {}

resource "docker_image" "nginx" {
  name         = "nginx:latest"
  keep_locally = false
}

resource "docker_container" "nginx" {
  image = docker_image.nginx.image_id
  name  = "tutorial"
  ports {
    internal = 80
    external = 8000
  }
}
```

What is absent is the lesson. No variable, no output, no backend, no meta-argument, and an empty
`provider "docker" {}`. Configuration surface is introduced strictly on demand.

Tutorials are organized as timed collections. The Docker collection is 35 minutes across seven
tutorials in a fixed order: what infrastructure as code is (3 minutes), install (7), build (10),
change (4), destroy (2), define input variables (4), query data with outputs (5)
([tutorials/docker-get-started](https://developer.hashicorp.com/terraform/tutorials/docker-get-started)).
Each rung is tightly scoped: the variables rung teaches exactly one variable and one `-var` flag; the
outputs rung teaches two outputs, `terraform output`, and destroy. State inspection arrives inside the
build rung through `terraform show` and `terraform state list`.

Beyond that, the collections continue: variables in depth with `terraform.tfvars` auto-loading and
`validation` blocks, then a ten-step modules track, then remote state migration, then
`terraform test`, then refactoring with `moved` blocks, where the tutorial frames the value as being
able to "plan, preview, and validate resource moves, enabling you to safely refactor your
configuration" and notes that "retained `moved` blocks in your configuration serve as a record of your
changes"
([tutorials/configuration-language/move-config](https://developer.hashicorp.com/terraform/tutorials/configuration-language/move-config)).

### Simplified documentation tree

```text
/terraform/tutorials      tutorial     timed collections with per-tutorial estimates and
                                       companion repos in the hashicorp-education org
/terraform/language
  concept tier            concept      get started, configure providers, resources, data sources,
                                       variables, locals, outputs, modules, meta-arguments,
                                       sensitive data (security), backends,
                                       search and import (migration), state, stacks,
                                       test and validate
  reference tier          reference     style guide, syntax, files and configuration structure,
                                       configuration blocks, meta-arguments, built-in resources,
                                       expressions, functions, internals
  upgrade-guides          migration     14 versioned variants, v1.1.x through v1.14.x
/terraform/cli            how-to        initializing, provisioning, authenticating, writing and
                                       modifying code, inspecting, import (migration),
                                       manually update state, workspaces, plugins,
                                       CLI configuration, testing, automating,
                                       alphabetical command list (reference)
/terraform/registry       how-to        publishing-side only
registry.terraform.io     reference     the generated provider reference, on a different host
/terraform/docs/glossary  reference
```

Two structural notes. The concept-tier and reference-tier split inside `/language` is the cleanest
information architecture in this review: one page to understand variables, another to look up every
argument. And explicit troubleshooting is thin, with `terraform validate`, `terraform console`, and
`TF_LOG` standing in for it.

### How configuration facts are explained

**Variable surface and validation.** `default` makes a variable optional; a `validation` block ensures
"the value a consumer specifies as the input value meets module requirements"; `sensitive` "prevent[s]
Terraform from displaying the value in CLI output"; `ephemeral` "omit[s] the variable from state and
plan files"; `nullable` "lets module consumers assign the value `null` to the variable"
([values/variables](https://developer.hashicorp.com/terraform/language/values/variables),
[block/variable](https://developer.hashicorp.com/terraform/language/block/variable)).

**Precedence is published as an ordered list**, lowest to highest: the `default`, environment
variables, `terraform.tfvars`, `terraform.tfvars.json`, "Any `*.auto.tfvars` or `*.auto.tfvars.json`
files in lexical order", then command-line `-var` and `-var-file` in the order provided. The
environment-variable page then says `TF_VAR_name` "will be checked last for a value"
([cli/config/environment-variables](https://developer.hashicorp.com/terraform/cli/config/environment-variables)),
where "last" means lowest priority. Two correct statements that read as contradictory, which is a
useful warning about wording precedence rules in two places.

**Environment bindings** are enumerated, fourteen `TF_*` variables, including one built for pipelines:
`TF_IN_AUTOMATION` makes Terraform "adjust... its output to avoid suggesting specific commands to run
next", and `TF_WORKSPACE` carries its own caution, "recommended only for non-interactive usage, since
in a local shell environment it can be easy to forget the variable is set".

**Secrets.** The central warning is repeated across pages: "Terraform stores values with the
`sensitive` argument in both state and plan files, and anyone who can access those files can access
your sensitive values", and "If your plan includes any sort of sensitive data, even if obscured in
Terraform's terminal output, it will be saved in cleartext in the plan file. You should therefore treat
any saved plan files as potentially-sensitive artifacts"
([manage-sensitive-data](https://developer.hashicorp.com/terraform/language/manage-sensitive-data),
[cli/commands/plan](https://developer.hashicorp.com/terraform/cli/commands/plan)). The documented
remedy is structural rather than cosmetic: ephemeral values and write-only arguments, which are "only
available during the current Terraform operation, and Terraform does not store them in state or plan
files" ([resources/ephemeral](https://developer.hashicorp.com/terraform/language/resources/ephemeral)).
Redaction is not containment, and the docs now say so.

**Validation ladder, with each tier's limits stated.** `terraform validate` "runs checks that verify
whether a configuration is syntactically valid and internally consistent, regardless of any provided
variables or existing state", and "It does not validate remote services, such as remote state or
provider APIs" ([cli/commands/validate](https://developer.hashicorp.com/terraform/cli/commands/validate)).
`terraform plan` adds provider round-trips. `terraform test` adds behavior: "Terraform tests let
authors validate that module configuration updates do not introduce breaking changes. Tests run against
test-specific, short-lived resources", with `.tftest.hcl` files whose `run` blocks choose `plan` or
`apply` ([language/tests](https://developer.hashicorp.com/terraform/language/tests)). `terraform fmt`
"automatically rewrites Terraform configuration files to a canonical format and style".

### Example and schema consistency

Three mechanisms, and Terraform is the only project in this review that has all three.

1. **Generated provider reference.** "The tfplugindocs command can be used to automatically generate
   documentation for your provider in the format necessary for the Terraform Registry", wired through a
   `go:generate` directive, reading schemas and descriptions into markdown
   ([registry/providers/docs](https://developer.hashicorp.com/terraform/registry/providers/docs)).
   Publishing is pinned to git tags, so a documentation fix requires a release.
2. **A versioned JSON projection of every machine-readable artifact**, with the compatibility contract
   written down: "We will increment the minor version... for backward-compatible changes or additions.
   Ignore any object properties with unrecognized names to remain forward-compatible with future minor
   versions", and "We will increment the major version... for changes that are not backward-compatible.
   Reject any input which reports an unsupported major version"
   ([internals/json-format](https://developer.hashicorp.com/terraform/internals/json-format)).
   `terraform providers schema -json` emits `format_version` `"1.0"`.
3. **Companion repositories for tutorial code**, in the `hashicorp-education` organization, separately
   versioned from the prose. That is honest about the drift risk it creates: the Docker tutorial pins
   `version = "~> 4.2.0"` inline, exactly the kind of value that skews from its repository.

### Friction

- **"Workspace" means two things, and the disambiguation is prose.** "Workspaces in the Terraform CLI
  refer to separate instances of state data inside the same Terraform working directory", and these are
  "distinctly different from workspaces in HCP Terraform, which each have their own Terraform
  configuration and function as separate working directories"
  ([cli/workspaces](https://developer.hashicorp.com/terraform/cli/workspaces)). There is no admonition
  marking the collision, the glossary defines only the CLI sense, and `TF_WORKSPACE` binds the other.
- **Root against child module is defined in a tutorial.** "When you run Terraform commands directly
  from such a directory, it is considered the **root module**"
  ([tutorials/modules/module](https://developer.hashicorp.com/terraform/tutorials/modules/module)),
  while the glossary gives one flat definition. The distinction is load-bearing for provider ownership.
- **State, backend, and remote state.** The glossary defines state and backend but not remote state,
  and `terraform_remote_state` is a data source, adding a fourth sense with a sharp caveat: "any user or
  server which has enough access to read the root module output values will also always have access to
  the full state snapshot data by direct network requests"
  ([state/remote-state-data](https://developer.hashicorp.com/terraform/language/state/remote-state-data)).
- **The same object documented twice, diverging.** `/language/values/variables` omits `nullable`,
  `const`, and `deprecated` that `/language/block/variable` documents. The concept and reference tiers
  are the right structure and they have already drifted.
- **Two modal strengths for one rule.** Provider blocks in child modules are "strongly recommend
  against" on one page and "must not contain" on another.
- **Prerequisites that cost money.** The AWS getting-started build requires "An AWS account and
  associated credentials that allow you to create resources in the `us-west-2` region, including an EC2
  instance, VPC, and security groups"
  ([tutorials/aws-get-started/aws-build](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/aws-build)).
  The Docker track avoids this and is the better first rung.
- **Generated pages vary with their author's hygiene.** Provider reference quality is a function of
  whoever wrote the schema descriptions, frozen per release tag, and the registry pages are
  client-rendered, so the canonical provider reference is not reliably readable by crawlers.
- **Gated features woven into general paths.** The modules track routes through a private-registry step
  at step five of ten, and the style guide recommends speculative plans through the hosted product
  ([cloud-docs/overview](https://developer.hashicorp.com/terraform/cloud-docs/overview)).
- **URL churn.** `/language/files/json`, `/language/provisioners/syntax`, `/language/block`, and
  `/language/plan` return 404 while remaining widely linked.

### Authored intent against generated and runtime configuration

This is Terraform's strongest contribution, five separated layers.

| Layer | Status | Documented rule |
| --- | --- | --- |
| `.tf` | Authored | Prescriptive file split: `main.tf`, `variables.tf`, `outputs.tf`, `providers.tf`, `backend.tf`, `locals.tf` ([language/style](https://developer.hashicorp.com/terraform/language/style)) |
| `.tf.json` | Generated, same grammar | "The JSON syntax is defined in terms of the native syntax, and everything that can be expressed in native syntax can also be expressed in JSON syntax" ([syntax/json](https://developer.hashicorp.com/terraform/language/syntax/json)) |
| `.terraform.lock.hcl` | Machine-written, human-reviewed, committed | "You should include this file in your version control repository so that you can discuss potential changes to your external dependencies via code review", and it is "primarily maintained automatically by Terraform itself, rather than being updated manually by you or your team" ([files/dependency-lock](https://developer.hashicorp.com/terraform/language/files/dependency-lock)) |
| State | Never hand-edited | "Do not directly edit this file. Terraform provides the `terraform state` command to perform basic modifications of the state using the CLI" ([language/state](https://developer.hashicorp.com/terraform/language/state)) |
| Plan | Opaque, sensitive | Not a standard format, cleartext secrets, treat as sensitive artifacts |

The doctrine underneath: every non-authored artifact gets either a stable JSON projection with
`format_version` semantics or an explicit prohibition on touching it. Nothing generated is left
ambiguous.

### Three practices Registry Stack should adopt

1. **Publish a versioned projection of every generated artifact and write down the increment rule.**
   Registry Stack already versions its CLI reports (`registryctl.init.v1`, `registryctl.smoke.v1`, and
   the rest). Extend that to the `build` output envelope, so a tool reading
   `.registry-stack/build/<env>/reviewable/review.json` can tell which contract it is reading, and
   document the increment rule for that envelope.

   Adopt the versioning idea and not Terraform's forward-compatibility rule. Terraform tells consumers
   to "Ignore any object properties with unrecognized names", which is right for a plan projection and
   wrong for runtime configuration: both product config graphs use `serde(deny_unknown_fields)`, the
   generated schemas are closed, and the published contract already says "strict parsers and the
   deprecated-field guard reject unknown or retired fields"
   (`reference/api-stability`). Keep that rejection. If newer `registryctl` output reached an older
   Relay or Notary, silently ignoring an unrecognized field could drop an authorization or disclosure
   setting. Loosening it would be a security-sensitive product-contract decision, not something a
   documentation plan should prescribe.
2. **Split concept pages from generated block references, and lint for prose coverage.** The
   `/language/{concept}` against `/language/block/{name}` shape maps directly onto the five authored
   surfaces. Generate the field tables from the schemas the `check` command already validates against,
   and add a linter that fails when a schema field has no prose anywhere, which is precisely the failure
   Terraform's own concept and reference variable pages demonstrate.
3. **Make secrets structurally unpersistable, then repeat the reason in three places.** Terraform's arc
   from `sensitive` to ephemeral and write-only arguments is the lesson: redaction is not containment.
   Registry Stack's compiled `build` output is the analogue of state, and it already carries secret
   references rather than values. The docs should state that boundary on the configuration reference, on
   the `build` page, and in a security how-to, matching the repository rule that changes to credential
   handling need explicit review notes.

### Two practices Registry Stack should avoid

1. **Overloading one noun across two planes with only prose to separate them.** "Workspace" cost
   Terraform a permanent explanatory paragraph on every relevant page. Registry Stack's live hazards are
   "registry" (the product family, a data source, and an artifact registry a reader may import from) and
   "manifest" (Registry Manifest the portable source description against `release/manifests/*.yaml`).
   Define both senses in the glossary and mark the first collision with an admonition rather than a
   sentence.
2. **Letting URLs churn without redirects.** Four widely linked Terraform language paths are dead.
   Registry Stack already has both halves of the defense: the build fails on a dangling internal link,
   and `docs/site/astro.config.mjs` carries an inbound `redirects` map for retired and renamed routes,
   with `astro-config.test.mjs` asserting docset-specific behavior. The practice to avoid is letting
   that map fall behind a slug change, so treat adding a redirect as part of any rename rather than as
   follow-up work.

## A.6 OpenTelemetry Collector

### Configuration-domain map

Six top-level keys, each defined in one sentence on the configuration page: "Receivers collect
telemetry from one or more sources.", "Exporters send data to one or more backends or destinations.",
"Connectors join two pipelines, acting as both exporter and receiver.", "Extensions are optional
components that expand the capabilities of the Collector", plus `processors` and `service`, which
holds `pipelines`, `extensions`, and `telemetry`
([collector/configuration](https://opentelemetry.io/docs/collector/configuration/)).

The load-bearing distinction is definition against instantiation, and it is stated well:
"Receivers, processors, exporters and pipelines are defined through component identifiers following
the `type[/name]` format, for example `otlp` or `otlp/2`. You can define components of a given type
more than once as long as the identifiers are unique." Defining a component does nothing; only listing
it in a pipeline activates it. The troubleshooting page treats forgetting this as a top failure mode,
"the receiver is defined in the `receivers` section but not enabled in any `pipelines`"
([collector/troubleshooting](https://opentelemetry.io/docs/collector/troubleshooting/)).

Connectors are the one genuinely unusual object: "A connector is both an exporter and receiver... it
emits data as an exporter at the end of one pipeline and consumes data as a receiver at the start of
another pipeline", constrained so that "A connector can only be used in a pair of pipelines when it
supports the combination of [Exporter Pipeline Type] and [Receiver Pipeline Type]"
([connector/README](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/connector/README.md)).

Cross-cutting configuration lives in shared packages, `configtls`, `confighttp`, `configgrpc`, and
`configauth`, with `configtls` explaining its own reach: "Crypto TLS exposes a variety of settings.
Several of these settings are available for configuration within individual receivers or exporters"
([configtls/README](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/config/configtls/README.md)).
Retry is the exception that proves the cost of this pattern: `config/configretry` has no README at
all, so its defaults, `initial_interval: 5s`, `max_interval: 30s`, `max_elapsed_time: 300s`, are
documented in the exporter helper's README and in a generated schema file rather than in the shared
package a reader would look in
([exporterhelper/README](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/exporter/exporterhelper/README.md)).

The non-configuration planes: internal telemetry under `service::telemetry`, where "The Collector uses
the OpenTelemetry SDK declarative configuration schema", metrics on `127.0.0.1:8888` and self-tracing
off by default as "an experimental feature"
([internal-telemetry](https://opentelemetry.io/docs/collector/internal-telemetry/)); zPages, which is
configured in the config plane but observed out of band on port `55679`; and the build plane,
`builder-config.yaml` with a `dist:` section and a `gomod` pin per component
([extend/ocb](https://opentelemetry.io/docs/collector/extend/ocb/)).

Ownership is real and never named as a concept. The distribution owner decides what exists at all:
"The components included in the distributions can be found by in the manifest.yaml of each
distribution" ([distributions](https://opentelemetry.io/docs/collector/distributions/), typo in the
original). The configuration author selects from what exists. Credentials are pushed to a topology
tier, with the gateway pattern's stated advantage being "Separation of concerns such as centrally
managed credentials" ([deploy/gateway](https://opentelemetry.io/docs/collector/deploy/gateway/)).

One documented fact is already out of date, which is itself the finding. The site says pipelines
"can operate on three telemetry data types: traces, metrics, and logs"
([architecture](https://opentelemetry.io/docs/collector/architecture/)), while the collector's own
service metadata declares a fourth signal behind an alpha gate, `service.profilesSupport` from
`v0.112.0`
([service/metadata.yaml](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/service/metadata.yaml)),
and the stability document already says "A component can support multiple telemetry signals (traces,
metrics, logs and profiles)"
([component-stability](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/docs/component-stability.md)).

### Documented onboarding ladder

The smallest configuration taught first is no configuration at all. Quick start ships zero YAML and
runs the image's built-in config ([quick-start](https://opentelemetry.io/docs/collector/quick-start/)):

```sh
docker run \
  -p 127.0.0.1:4317:4317 \
  -p 127.0.0.1:4318:4318 \
  -p 127.0.0.1:55679:55679 \
  otel/opentelemetry-collector:0.157.0 \
  2>&1 | tee collector-output.txt
```

That is a defensible choice, and it has a cost: the first hand-written pipeline a reader meets is on
the troubleshooting page, a `zipkin` receiver into a `debug` exporter, introduced with "For live
troubleshooting, consider using the `debug` exporter, which can confirm that the Collector is
receiving, processing, and exporting data". Meanwhile the configuration page's first example is
already maximal, three pipelines and three extensions.

The rungs exist but are not authored as a path: quick start, configuration, processors, deployment
patterns, scaling, resiliency, custom distributions, internal telemetry. Rung two jumps from zero
configuration to a complete one, and the ordering advice a reader most needs is not on the site at
all. Processor ordering lives in the core repository README, "memory_limiter -- must be first so it
can shed load before downstream processors accumulate data" and "batch -- batching after filtering
and transformation... prefer using the exporter's batching capabilities when available"
([processor/README](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/processor/README.md)).

### Simplified documentation tree

```text
/docs/collector/
  quick-start                     tutorial       the only one
  install, deploy/{agent,
    gateway,other}                how-to
  configuration                   reference +    the single densest page
                                  how-to
  components/{receiver,processor,
    exporter,connector,extension} generated      an index, not a reference
  architecture, distributions,
    management, registry          concept        registry is a redirect to the ecosystem explorer
  transforming-telemetry, scaling,
    resiliency, extend/{ocb,
    build-from-source,
    custom-component}             how-to
  troubleshooting, benchmarks     troubleshooting + generated data
  (security)                      absent         lives at /docs/security/config-best-practices/
  (migration)                     absent
```

Note that `/docs/collector/deployment/` and `/docs/collector/building/` now return 404; the paths are
`/deploy/` and `/extend/`.

The defining structural fact: per-component configuration reference is not on the documentation site.
It lives in repository READMEs, reached through generated tables whose component names link into a
version-pinned GitHub tree. There is no single policy sentence stating this, only per-type delegation
on the configuration page. The closest the site comes to admitting the cost is telling readers to
combine two lists: "You can find the full list of processors by combining the list from
[opentelemetry-collector-contrib] and the list from [opentelemetry-collector]".

### How configuration facts are explained

**Defaults** live in component READMEs, generated from each component's `metadata.yaml` by `mdatagen`,
so `otlpreceiver` documents "`endpoint` (default = localhost:4317 for grpc protocol, localhost:4318
http protocol)". The site itself publishes almost no defaults.

**Environment binding** has a migration the site does not mention. Two syntaxes are supported, the
braces syntax `${ENV}` and the provider syntax `${env:ENV}`, and "The naked syntax supported in Bash is
not supported in the Collector"
([rfcs/env-vars](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/docs/rfcs/env-vars.md)).
What changed is that bare `$VAR` was removed and `${VAR}` was redefined to mean `${env:VAR}`, through
the `confmap.unifyEnvVarExpansion` gate promoted to stable in v0.107.0: "Expansion of `$FOO` env vars
is no longer supported. Use `${FOO}` or `${env:FOO}` instead."
([release v0.107.0](https://github.com/open-telemetry/opentelemetry-collector/releases/tag/v0.107.0)).
The site documents the destination and not the journey.

**Configuration sources** are confmap providers, and the core set is exactly five, `env`, `file`,
`http`, `https`, and `yaml`
([confmap/README](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/confmap/README.md)).
`s3` and the secret-store providers are contrib, which makes provider availability a build-time
decision, and `providers:` is a `builder-config.yaml` section. The site lists the five and does not
say that. Merging is by repeated `--config` plus `--set outer::inner=value`.

**Validation** is `otelcol validate --config=...`. Effective configuration is `otelcol print-config`,
which is where the design is right and the delivery is not: it is marked "[!CAUTION] This command is
an experimental functionality", defaults to `--mode=redacted`, and is gated behind
`--feature-gates=otelcol.printInitialConfig`. Gate syntax is documented crisply: "Gate identifiers
prefixed with `-` will disable the gate and prefixing with `+` or with no prefix will enable the gate"
([featuregate/README](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/featuregate/README.md)).

**Stability** is a first-class published property. Six levels, with the rule that "each component
should list its current stability level for each telemetry signal in its README file", and a
consequence for abandonment: an unmaintained component "does not have an active code owner", and
"After 3 months... removed from official distribution".

**Security** is documented as a history, which is unusually honest: "From Collector v0.110.0 onwards,
the default host for all servers in Collector components is `localhost`", reached through the
`component.UseLocalHostAsDefaultHost` gate, accelerated by an external audit and by CVE-2024-36129, a
decompression denial of service in the shared HTTP and gRPC packages
([hardening-the-collector-one](https://opentelemetry.io/blog/2024/hardening-the-collector-one/),
[cve-2024-36129](https://opentelemetry.io/blog/2024/cve-2024-36129/)). Secret guidance is thin:
"store sensitive information securely such as on an encrypted filesystem or secret store"
([config-best-practices](https://opentelemetry.io/docs/security/config-best-practices/)).

### Example and schema consistency

There is no published whole-configuration JSON Schema. The tracking issue, "Improve otel collector
configuration w/ JSON schema", is open from March 2024
([issue 9769](https://github.com/open-telemetry/opentelemetry-collector/issues/9769)). The situation
has moved partway: `mdatagen` now emits per-component schemas, "This generates JSON Schema files that
enable IDE autocompletion, validation, and documentation for component configuration", with
`metadata.yaml`'s `config` section following draft 2020-12, and a real artifact exists at
`config/configretry/config.schema.yaml`. What is missing is aggregation and publication. There is no
assembled, versioned, per-distribution schema at a URL.

The honesty mechanisms in its place are colocated generated READMEs, `otelcol validate`,
unmarshalling errors, `gomod` pins in the build manifest, and the contrib testbed, "a controlled
environment and tools for conducting end-to-end tests for the Otel Collector, including reproducible
short-term benchmarks, correctness tests, long-running stability tests and maximum load stress tests"
([testbed/README](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/main/testbed/README.md)).

Two concrete drift facts are worth carrying away. The contrib `examples/` directory has no target that
validates its configurations. And the site deliberately hardcodes an insecure value: an accepted issue
asked to "update all examples in opentelemetry.io to explicitly set the endpoint to `0.0.0.0`"
([opentelemetry.io issue 3839](https://github.com/open-telemetry/opentelemetry.io/issues/3839)), so
every site example now permanently contradicts the security page's `localhost` recommendation, by
design, to shield readers from a default change.

### Friction

- **Category boundaries are functional, not explained.** Nothing says why routing is a connector while
  authentication is an extension.
- **"Collector" collapses four things.** Agent and gateway are topologies, a distribution is a build,
  and all three are called the Collector.
- **`service.telemetry` against telemetry data.** The Collector's own telemetry and the payload it
  carries share a word, unaddressed.
- **Component naming is acknowledged broken.** "The OTLP gRPC exporter is currently configured via
  `otlp`, which is different than the `otlphttp` exporter. This has led to end user confusion"
  ([issue 14099](https://github.com/open-telemetry/opentelemetry-collector/issues/14099)). The
  configuration page's first example now uses the new `otlp_grpc` alias, which no README teaches.
- **Shared blocks restated and then diverged.** `prometheusremotewriteexporter` delegates to the shared
  packages, restates TLS fields locally, and then diverges: the exporter "doesn't support
  'sending_queue' but provides 'remote_write_queue'". Batching now has three documented homes with an
  open resolution issue.
- **Unexplained prerequisites.** Quick start assumes Go and Docker silently.
- **Sprawl.** Core ships one receiver; contrib holds roughly 260 components across the five kinds.
  Version skew is managed rather than removed, "We release both core and contrib collectors with the
  same versions where the contrib release uses the core release as a dependency", on "very short 2 week
  release cycles"
  ([docs/release](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/docs/release.md)).
- **Three ways to discover what is in a distribution, none canonical.** Read `manifest.yaml`, run
  `otelcol components`, which is documented under troubleshooting, or read a distributions column in a
  table. The distributions page links to only the first.

### Authored intent against generated and runtime configuration

Four artifacts, of which the documentation names two explicitly.

| Artifact | Status | Documented |
| --- | --- | --- |
| `config.yaml` | Authored | Yes |
| `builder-config.yaml` | Authored, different lifecycle | Yes, but never contrasted with `config.yaml` |
| OCB output: `go.mod`, `go.sum`, `main.go`, binary | Generated | Only as a footgun, warning that changing `dist.name` or `output_path` requires editing matching Dockerfile lines |
| Runtime-effective configuration | Resolved | Only through an experimental, gated `print-config` |
| Internal telemetry | Runtime | Yes |

Gating the only answer to "what is actually running" behind a feature flag is the sharpest structural
gap in this project's documentation.

The documentation site itself adds a fifth layer worth copying: component tables are generated from
data files synced from the ecosystem registry and pinned by a version file. Reference is therefore
generated twice, once from each component's `metadata.yaml` into a README and once from the registry
into the site, from two sources that can disagree.

### Three practices Registry Stack should adopt

1. **One machine-readable source per configuration surface, fanning out to both schema and prose.**
   `mdatagen` is the right shape and Registry Stack is already further along: both products reproduce
   their committed JSON Schema from the typed config graph and fail CI on drift. The step to take is
   rendering the published reference pages from those same schemas, gated beside the existing OpenAPI
   drift check, so the strength does not decay into prose.
2. **Publish per-field stability and per-product availability inside the reference itself.** The
   collector's `Stability` and `Distributions` columns tell a reader about this field, for this signal,
   in this build. Pre-1.0 with two products, Registry Stack should carry `stability` and the owning
   product per configuration block in the schema and render it as a column, which also gives the
   version-skew story one home.
3. **Ship `validate` and a redacted effective-configuration dump as ordinary commands.** Registry
   Stack's compile step makes the gap between authored and effective configuration wider than the
   collector's, so a redacted dump matters more, not less. Redaction should be the default and
   unredacted an explicit act, with tests asserting the redaction, which the repository's own rules
   already classify as security-sensitive.

### Two practices Registry Stack should avoid

1. **Moving the reference off the documentation site.** A reader on the collector's configuration page
   looking for one receiver's options is sent to a repository README that documents a different
   receiver, and the real page is reachable only through a generated table into a version-pinned tree.
   Registry Stack's configuration reference must be generated into the site, not linked out to
   `crates/*/README.md` or to a pinned source file.
2. **Restating shared blocks in prose, and pinning examples to values that are meant to change.** The
   collector documents TLS, retry, and queue settings centrally, restates them per component, restates
   them again on a resiliency page, and then lets one exporter silently rename a field. Separately,
   hardcoding `0.0.0.0` across every site example to smooth a future default change left the whole
   corpus contradicting the security page permanently. Render shared blocks once from a schema
   reference, show the secure value, and let a generated "default changed in vX" note carry the
   migration.

# Part B: Proposed Registry Stack documentation architecture

## B.0 How the five journeys are read

The review scope names five journeys: spreadsheet, OpenAPI, `http`, `script`, and `snapshot`. Four
of them are source shapes, so this proposal reads all five on the source-shape axis.

| Journey | What the adopter starts from | Current surface |
| --- | --- | --- |
| Spreadsheet | A workbook or table the institution already holds | `registryctl init relay --sample benefits` (`InitProjectKind::RelaySpreadsheetApi`); tutorial `tutorials/publish-spreadsheet-secured-registry-api` |
| OpenAPI | A source that publishes an OpenAPI description, so the bounded request is lifted from a contract | None. No starter names this shape, and a repository search finds no OpenAPI ingestion or request-lifting code. The three standards starters are not instances of it: `fhir-r4`, `dhis2-tracker`, and `opencrvs-dci` each ship an `adapter.rhai` and declare `capability.script` |
| `http` | One bounded request declared by hand | `init --from http`, `capability.http` with the request nested under it; tutorial `tutorials/author-registry-project` |
| `script` | A source recipe needing more than one bounded call | `capability.script`, `adapter.rhai`, `xw.v1`; tutorial `tutorials/configure-project-script-adapter`, plus the `fhir-r4`, `dhis2-tracker`, and `opencrvs-dci` starters |
| `snapshot` | An immutable local snapshot | `init --from snapshot`, `capability.snapshot`; tutorial `tutorials/configure-project-snapshot-materialization` |

A second reading of "OpenAPI" is the generated `openapi.json` contract a configured Relay or Notary
serves to consumers. That is a publishing concern, not an authoring journey, so this proposal keeps
it under generated artifacts (B.6). If the second reading was intended, only the OpenAPI row of B.3
moves; the rest of the architecture is unchanged.

## B.1 Configuration-domain map to document

Three planes, and the documentation should never let a reader confuse them.

**Plane 1, authored intent.** Five YAML surfaces, each with a strict schema printable from
`registryctl authoring schema --kind` and wired into VS Code and Zed by `init`, plus a script adapter
when the capability requires one:

| Surface | Schema | Owner |
| --- | --- | --- |
| `registry-stack.yaml` | `project.schema.json` | Registry authority: registry id, services, purpose, caller scopes, consultations, claims, disclosure modes, credential claim allow-list |
| `integrations/<id>/integration.yaml` | `integration.schema.json` | Integration reviewer: input schemas, one fixed capability (`http`, `script`, `snapshot`), output pointers, cardinality, limits |
| `integrations/<id>/fixtures/*.yaml` | `fixture.schema.json` | Integration reviewer: synthetic interactions, expected outputs, expected claims, denial cases |
| `environments/<name>.yaml` | `environment.schema.json` | Deployment operator: source origin, secret references, caller fingerprints, Relay trust, deployment services |
| `entities/*.yaml` | `entity.schema.json` | Registry authority: entity shapes |
| `adapter.rhai` plus reviewed local modules | `xw.v1` function surface | Integration reviewer, only when `capability.script` |

**Plane 2, generated product input.** `registryctl build --environment <name>` writes
`.registry-stack/build/<env>/` with a `reviewable/` half (`integration-packs/`,
`consultation-contracts/`, `review.json`) and a `private/` half (`relay/config/relay.yaml`,
`notary/config/notary.yaml`, each with `approval/review.json`). These validate against
`schemas/registry-relay.config.schema.json` and `schemas/registry-notary.config.schema.json`, which
the products' `config-schema-check` commands reproduce from their typed config graphs.

A signed Config Bundle belongs to this plane, not to plane 3. `registryctl bundle sign` packages the
generated product input directory, the bundle carries that product's `config/` document, and Relay or
Notary verifies the bundle before parsing the configuration inside it. It is governed generated
configuration under a signature, so build, sign, verify, and activate document one artifact through one
lifecycle. The trust anchor is the exception and belongs to the operator: it is trust configuration the
deployment owns, not an output of `build`.

**Plane 3, runtime and evidence state.** Served `openapi.json`, audit records, credential status,
issued credentials, and posture reads. Not configuration, and never hand-edited.

The ownership boundary the docs must state once and enforce everywhere: integration plus environment
define Relay source access and adaptation policy; the evidence service defines Notary authorization
and disclosure policy; the evidence consumer's use, decision, workflow, and action policy stays
outside the project entirely.

## B.2 The onboarding ladder

Four rungs, each with an explicit exit test. The ladder is the sidebar's first group.

1. **See one protected read.** Spreadsheet journey, local, no source credentials. Exit test: a
   denied request and an allowed request against the same route.
2. **See one claim answered.** Registry-backed claim over the same project. Exit test: `true`,
   `false`, and `no_match` all reachable, and the reader can say why `no_match` is not `false`.
3. **Author your own source contract.** The `http` starter, then whichever of OpenAPI-described,
   `script`, or `snapshot` matches the reader's source. Exit test: `registryctl test` green with the
   reader's own fixtures, including denial cases.
4. **Bind an environment and generate product input.** Exit test: `check --explain` reviewed,
   `build` reproduced twice with identical output, then Config Bundle sign and verify.

Rungs 1 and 2 exist. Rung 3 exists but is entered through a tutorial whose title does not say
"choose by source shape". Rung 4 is split across `reference/registryctl` and the operate pages with
no single page that walks it.

## B.3 Proposed documentation tree

Additions marked `[new]`, moves marked `[move]`. Everything else already exists and keeps its slug.

```text
Get started
  Overview
  Choose your source shape                      [new]  how-to, the journey chooser
  Your first registry API (spreadsheet)
  Your first claim check
  When to use
  Run Solmara Lab

Configure a project                             [move] renamed from "Integrations"
  Author a project (http)
  Choose by source shape:
    Spreadsheet source
    OpenAPI-described source                    [new, blocked: no current surface]
    Bounded HTTP source            (existing author-registry-project)
    Script source adapter
    Snapshot materialization
  Write and run fixtures                        [new]  how-to, extracted from the tutorials
  Define a service policy                       [new]  how-to: scopes, purpose, attribute release
  Declare a Relay consultation                  [new]  how-to: bind integration inputs to
                                                       typed request paths
  Define a Notary claim                         [new]  how-to: atomic claims, CEL rules,
                                                       disclosure mode per claim
  Bind an environment                           [new]  how-to: origins, secret refs, fingerprints
  API-key source authentication
  FHIR R4 integration
  OpenCRVS claims

Concepts
  Architecture
  Records stay home
  Configuration planes and ownership            [new]  explanation, the B.1 map
  Relay protected read flow
  Evidence issuance
  Disclosure modes
  Data minimization
  Trusted context
  Integration patterns
  DPI safeguards

Reference
  Authored configuration                        [new]  generated from the five authoring schemas
    Project
    Environment
    Integration
    Fixture
    Entity
  Runtime configuration                         [new]  generated from the two config schemas
    Relay
    Notary
  API reference (Relay, Notary)
  registryctl CLI
  Errors and status codes
  Authoring diagnostics                         [new]  generated index of the ~15 codes
  Environment variables
  Contracts
  API stability and versioning
  Deprecation policy
  Standards
  Glossary

Operate
  Validate before you deploy                    [new]  how-to: test, check, build, sign, verify
  Single-node Compose
  Backup and restore
  Retention and state
  Upgrade and roll back

Security
  (unchanged)

Specifications
  (unchanged)
```

Per Diátaxis guidance on incremental adoption, this tree is a target for content that exists or is
being written, not a scaffold of empty sections to create first.

## B.4 What each new page must contain

- **Choose your source shape.** A five-row table keyed by what the reader has, not by what Registry
  Stack calls it. Each row: the question that identifies the shape, the starter command, the
  capability kind, and the one thing that shape cannot do.
- **Configuration planes and ownership.** The B.1 three-plane map, the five authored surfaces with
  their owners, and one worked example of a field that looks like it belongs on two surfaces
  (a source origin, which is environment-owned, not integration-owned).
- **Write and run fixtures.** The offline loop: one fixture, `--trace`, `--watch`, then the derived
  security cases Registry Stack generates for free (malformed decoding, byte ceiling, timeout,
  authorization before source, output minimization). States what a fixture may not supply: a
  destination, a credential, a worker command, an authentication bypass, or a decoder mode.
- **Define a service policy.** Caller scopes, purpose, attribute release profiles, credential claim
  allow-list, and the claim design test already written in `tutorials/author-registry-project`,
  promoted out of that tutorial so it is citable.
- **Declare a Relay consultation.** The closed input-mapping set, `request.target.id`,
  `request.target.identifiers.<stable-id>`, and `request.target.attributes.<stable-name>`, the
  `[a-z][a-z0-9_]{0,63}` attribute-name rule, and the constraint that consultation inputs "cannot
  select an origin, method, credential, capability, projection, or response mapper". States plainly
  that an attribute is caller-supplied context, and that mapping one neither authenticates the value
  nor turns it into an identifier. This is the page that keeps a consultation from becoming a general
  query interface, and today it exists only as prose inside one tutorial.
- **Define a Notary claim.** One atomic evidence fact per claim, the meanings of `true`, `false`,
  `null`, `no_match`, `ambiguous`, and source failure, the rule that missing evidence is not a negative
  fact, the reuse test, and the narrow exception where a claim attests a decision an authoritative
  source already made. Names the boundary against CEL: a rule "may derive a precise evidence predicate
  from typed outputs, but it is not a general-purpose eligibility engine."
- **Bind an environment.** Secret references by name only, `${VAR}`, `${VAR:-fallback}`, and
  `${VAR:?message}` expansion before YAML parsing, and the rule that diagnostics never print values.
- **Validate before you deploy.** The single page that walks `test` to `check --explain` to `build`
  to `bundle sign` and `bundle verify` with `anchor`, plus `check --against` and `--anchor` for a
  signed baseline and the five review classes (`claim`, `integration`, `service_policy`,
  `operator_security`, `disclosure`).
- **Authored configuration reference** and **Runtime configuration reference.** Generated, never
  hand-written, each field carrying type, default, required, and the owning plane.
- **Authoring diagnostics.** Generated from `diagnostics.rs`: code, cause, remediation. Today one
  code appears in a tutorial troubleshooting table and the rest are reachable only by reading a
  pinned source file.

## B.5 Consistency machinery

Already in place and worth naming in the docs as the reason examples can be trusted:

- `ProjectStarterSequence` and `ProjectWorkspaceJourneys` are generated from
  `crates/registryctl/tests/fixtures/project-authoring-journeys.yaml` and the committed golden
  workspaces, so every published command sequence is a tested sequence.
- `check:tutorial:registryctl` executes the two deployable adopter tutorials against checked-out
  source, `tutorials/publish-spreadsheet-secured-registry-api` and
  `tutorials/verify-claim-registry-api`.
- `check:tutorial:dry-run`, which is the variant `npm run check` calls, does not execute anything: it
  runs extraction and drift checks and then exits, printing `dry-run: extraction and drift checks
  passed`. The project-authoring tutorials therefore get drift checking here and their execution
  coverage from the Rust tests in `crates/registryctl/tests/project_authoring.rs`.
- `check:openapi` lints both products' committed OpenAPI documents; Redoc output is generated.
- `check:config-vocabulary` is a grep guard that fails the build when retired configuration
  vocabulary reappears in prose.
- `check:evidence-links`, `check:content` (frontmatter), Vale, markdownlint, and
  `check:links:built`.

Three additions this proposal depends on:

1. **Generate the two reference sections from schema.** A `generate-config-reference.mjs` step that
   reads the five authoring schemas from `registryctl authoring schema --kind <kind>` and the two
   runtime schemas from the committed `schemas/*.config.schema.json`, then writes
   `src/data/generated/`. The runtime half is nearly free: `just config-schema-generate` and
   `just config-schema-check` in `crates/registry-relay/justfile` and `products/notary/justfile`
   already reproduce those two files from each product's typed config graph and fail CI on drift, so
   the docs step consumes an artifact that is already gated rather than adding a second source of
   truth. Reference drift then fails `npm run check` the same way OpenAPI drift already fails CI.
2. **Generate the diagnostics index** from the same source the CLI uses, so a new code cannot ship
   undocumented.
3. **Assert the ownership matrix.** One data file mapping every top-level authored field to its
   owning plane, checked against the schemas, so a new field cannot land without an owner.

## B.6 Generated artifacts to keep visibly generated

Every generated page carries the author-facing note the style guide already requires, naming the
source file and the regeneration command. The artifacts: the two products' OpenAPI documents and
their Redoc renders, `src/data/generated/**`, the starter sequence tables, the proposed configuration
and diagnostics references, and, on the adopter side, `.registry-stack/build/<env>/`. The docs should
say plainly that the build output is institutionally sensitive, contains secret references rather
than values, is reproducible from the same inputs, and belongs outside source control.

## B.7 Advanced operations

Advanced material stays out of the ladder and is entered by an operational question, not by
curiosity: Config Bundle packaging, signing, verification, trust anchors and rotation, monotonic
sequence and stream binding, semantic-change review against a signed baseline, upgrade and rollback,
backup and restore, retention and persistent state, and the hardening checklist. Each page states
its prerequisite rung, so a reader who has not completed rung 4 is told so rather than discovering
it through a failed command.

## B.8 Sequencing

1. `Choose your source shape`, `Configuration planes and ownership`, `Validate before you deploy`.
   Three pages, no new tooling, and they close the three navigational holes.
2. `Write and run fixtures`, `Define a service policy`, `Bind an environment`, extracted from
   existing tutorial prose so the tutorials get shorter.
3. The generated references and their CI drift gates.
4. `OpenAPI-described source`, once a starter or a documented lift-from-contract procedure exists.

## B.9 Where each element comes from

| Proposal element | Borrowed from | Adapted how |
| --- | --- | --- |
| Journey chooser keyed by what the reader has | Kong's cumulative single-example ladder; Airbyte's tutorial-first ordering | Keyed by source shape rather than by feature, because Registry Stack's first decision is about the source, not the gateway |
| Three-plane ownership page | SpiceDB's implicit three planes, made explicit; Terraform's five named layers | Registry Stack has five authored surfaces rather than one, so the page is a table, not a diagram |
| Generated configuration references | Terraform's `tfplugindocs`; Kong's `/schemas` as authority; Airbyte's single validating schema | Generated from the schemas the CLI already validates against, gated in `npm run check` like the OpenAPI drift check |
| Prose-coverage linter for schema fields | Terraform's drifted concept and reference variable pages, as a negative example | New. Fails when a schema field has no prose anywhere |
| Fixtures as a first-class documented artifact | SpiceDB's one assertion format for playground and CLI | Registry Stack's fixtures already run through the real decoder and evaluator, so the gap is documentation, not mechanism |
| Validate page that states each tier's limits | Terraform's "does not validate remote services"; Kong's two-tier decK validate | Extended to Registry Stack's four tiers, offline fixtures, generated-config check, live non-production evaluation, and signed-baseline comparison |
| Secret-reference resolution timing | Tyk's per-location KV resolution table | Registry Stack has one resolution point, before YAML parsing, which is simpler and should be said once, plainly |
| `format_version` on generated build output | Terraform's JSON-format compatibility contract | Applied to the compiled Relay and Notary configuration, alongside the existing versioned CLI reports |
| Precedence rules for anything layered | Airbyte's "Child parameters supersede parent ones"; Terraform's ordered variable precedence list, and its two conflicting statements of it | Stated in exactly one place per rule |
| Authoring diagnostics index | Kong's missing troubleshooting hub, as a negative example | Generated from the same source the CLI uses |
| Advanced operations behind a stated prerequisite rung | Terraform's gated features woven into a general path, as a negative example | Every advanced page names the rung it assumes |
| Glossary discipline and admonition at first collision | Kong's four meanings of "service"; Terraform's two "workspace"; SpiceDB's own FAQ concession | Applied to "registry", "manifest", and "service" |

# Appendix: sources and method limits

Every claim in Part A links the page it came from. The documentation roots fetched for this review:

| Project | Roots fetched |
| --- | --- |
| Kong Gateway | `developer.konghq.com/gateway/*` (entities, configuration, get-started, hybrid-mode, db-less-mode, security, secrets-management, manage-kong-conf, pdk), `developer.konghq.com/deck/*`, `developer.konghq.com/how-to/`, `developer.konghq.com/api/`, `developer.konghq.com/konnect/` |
| Tyk | `tyk.io/docs/api-management/*`, `tyk.io/docs/getting-started/*`, `tyk.io/docs/tyk-oss-gateway/*`, `tyk.io/docs/tyk-configuration-reference/kv-store/`, `tyk.io/docs/basic-config-and-security/*`, `tyk.io/docs/tyk-governance/*` |
| Airbyte Connector Builder | `docs.airbyte.com/platform/connector-development/connector-builder-ui/*`, `docs.airbyte.com/platform/connector-development/config-based/*`, `docs.airbyte.com/platform/connector-development/connector-specification-reference` |
| SpiceDB | `authzed.com/docs/spicedb/{getting-started,concepts,modeling}/*`, `authzed.com/docs/best-practices`, `authzed.com/docs/reference/zedtokens-and-zookies` |
| Terraform | `developer.hashicorp.com/terraform/{language,cli,tutorials,registry,docs,internals,cloud-docs}/*` |
| OpenTelemetry Collector | `opentelemetry.io/docs/collector/*` plus the component READMEs in `open-telemetry/opentelemetry-collector` and `opentelemetry-collector-contrib` that the site delegates to |

Method limits worth stating, because they bound how far the conclusions carry:

- No accounts, deployments, or hosted onboarding. Anything only observable by running a hosted
  onboarding flow is outside this review, including Konnect, Tyk Cloud, Airbyte Cloud, the SpiceDB
  Playground's saved state, HCP Terraform, and any vendor collector distribution.
- Several projects render documentation client-side. The Terraform registry's provider pages returned a
  bare shell rather than content, so the provider-reference observations rest on the publishing
  documentation and on a provider's source markdown rather than on a rendered registry page.
- Where a project's own tooling is the authority for defaults, such as Kong's `/schemas` endpoint, the
  authority was not queried, because that requires a running instance. Those claims describe what the
  documentation says the authority is.
- Documentation moves. Four Terraform language paths that are widely linked returned 404 during this
  review, and Kong's legacy host splits between clean redirects and a frozen archive. Any URL in this
  review is a claim about 2026-07-26.
- The OpenTelemetry Collector section cites roughly ten `raw.githubusercontent.com/.../main/...` URLs
  for READMEs, RFCs, component metadata, and release documents, because that project keeps its
  per-component reference in repository files rather than on its documentation site. Those are mutable
  branch URLs and their content will drift. They are cited unpinned deliberately: `main` is what was
  fetched, and rewriting them to a release tag would assert evidence that was not read. Where a claim
  depends on a specific version, the version appears in the prose instead, as with the `${VAR}`
  expansion change in v0.107.0, the `localhost` default in v0.110.0, the profiles gate from v0.112.0,
  and the v0.157.0 component tables. A reader re-verifying this section after the fact should read those
  paths at the matching tag. The repository's own rule about pinning links to a tag or commit binds
  citations of Registry Stack source, and every such citation in this review names a repository path
  rather than a branch URL.

## Next

- Decide whether the OpenAPI journey means an OpenAPI-described source or the served instance contract,
  which is the one open question in Part B.
- Take Part B step one as a separate change: three pages, no new tooling.
- Raise the generated configuration reference as its own change, because it touches
  `docs/site/scripts/` and the `npm run check` gate.
