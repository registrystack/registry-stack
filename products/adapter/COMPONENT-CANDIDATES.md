# Camel component candidates

Reviewed 2026-10-30 against the Camel 4.22.x component index
(`https://camel.apache.org/components/4.22.x/index.html`, about 380
components). This is a ranked candidate list, not a commitment: the port
table in `CONCEPT.md` 8.10 stays the plan of record, and a candidate enters
it only through the escalation ladder of `CONCEPT.md` 8.9 and the two-system
rule.

The filter is the adapter's job: a synchronous, request-reply facade over a
system of record that a government or humanitarian programme already runs.
Most of the catalog fails that filter for a structural reason (it consumes
events, moves files on a schedule, or belongs to another Registry Stack
product), which the last section records so nobody re-litigates it.

## How Camel's system components map onto ours

Camel's DHIS2 and FHIR components are Java SDK wrappers. That is the opposite
of our design: in Camel, system knowledge lives in a compiled component; here
it lives in a pack, and Rust only carries protocol envelopes.

- **DHIS2** (`camel-dhis2`) wraps the DHIS2 Java SDK with five operations:
  `get/collection` (with `paging`, `fields`, `filter`, `rootJunction`),
  `get/resource`, `post/resource`, `put/resource`, `delete/resource`, plus
  `resourceTables/analytics`. Authentication is username and password or a
  personal access token. All of it is `http` plus a pack. Use it as a
  coverage check for the `dhis2-tracker` pack (its `fields`, `filter`, and
  `rootJunction` parameters are the ones our route templates must expose),
  never as a Rust component.
- **FHIR** (`camel-fhir`) wraps HAPI FHIR: `read`, `search`, `create`,
  `update`, `patch`, `delete`, `transaction`, `history`, `operation`,
  `load-page` (Bundle `next` and `previous` links), `meta`, `validate`,
  `capabilities`, for DSTU2 to R5, JSON or XML. FHIR's REST API is ordinary
  JSON over HTTP, so a FHIR source is a pack over `http`: Bundle paging is
  `loop` plus `enrich` over `link[relation=next]`, and conditional create
  (`If-None-Exist`) is the source-side idempotency that `idempotentUpstream`
  declares. FHIR is also a natural target profile (D17): a registry exposed
  as FHIR R4 Bundles with `OperationOutcome` problems. A `fhir` Rust
  component is justified only if XML encoding or `transaction` Bundles prove
  inexpressible in a pack.

## Ranked candidates

Relevance: **A**, demand we can name today; **B**, recurring in government
and humanitarian registries; **C**, plausible later. Rung refers to the
escalation ladder.

| # | Camel component | What it is for us | Rung | Relevance | Status |
|---|---|---|---|---|---|
| 1 | HTTP | Every REST source | 4 (shipped) | A | Increment 1 |
| 2 | REST, REST API | The facade consumer and its OpenAPI | 4 (shipped) | A | Increment 1 |
| 3 | Direct, Kamelet | Internal routes; packs as template catalogs | core | A | Increments 0 and 1 |
| 4 | Mock, Stub | Fixture replay and the upstream double | test | A | Increment 0 |
| 5 | GraphQL | OpenCRVS (if confirmed), openIMIS | 4 | A | Increment 3 |
| 6 | DHIS2 | DHIS2 Tracker and aggregate | 1 (pack) | A | `dhis2-tracker` pack |
| 7 | FHIR | Health registries (OpenMRS, openIMIS, HAPI servers) as sources; FHIR as a target profile | 1 (pack), 4 only if forced | A | Proposed: experiment after Increment 1 |
| 8 | JSON Schema Validator | Validate upstream responses and facade bodies against a declared JSON Schema | 4 (small) | A | Candidate: the `validate` EIP's schema form |
| 9 | REST OpenApi (producer side) | Validate outbound calls and responses against the source's own OpenAPI document | 4 | B | Candidate: strengthens response validation |
| 10 | CXF, Spring WebService (SOAP) | Civil registries, tax and social security systems, X-Road services exposed as SOAP | 4, with XML, XPath, XSLT | B | Candidate: largest real gap; needs an XML message body |
| 11 | SQL, JDBC | A legacy MIS with a database and no API, read-only | 4 | B | Candidate: fixed named parameterized read-only queries only, on the Evidence SQLite boundary precedent |
| 12 | Olingo4 (OData), SAP NetWeaver | ODK Central's OData feed, SAP and Dynamics ERPs | 1 (pack over `http`) | B | Pack only; Camel deprecated Olingo |
| 13 | Google Sheets | Programmes run from spreadsheets | 1 (pack over `http`) | B | Pack only; needs the JWT bearer grant (see the auth note) |
| 14 | MLLP (HL7 v2) | Hospital and lab systems | 4, TCP | C | Later; not HTTP request-reply |
| 15 | LDAP | Staff and organisation directories | 4 | C | Later |
| 16 | Salesforce, ServiceNow | Case management built on SaaS CRMs | 1 (pack over `http`) | C | Pack only |
| 17 | gRPC | Newer national platforms | 4 | C | Later |
| 18 | Wasm | Camel's own analogue of our rung 3 | 3 | C | Port-table row when the WASM rung arrives |

Language and transformation components considered: JSONata, JSLT, and JOLT
are popular JSON transformation languages. They overlap `jsonpath` plus
`rhai`, and each embedded language is one more sandbox and budget surface to
secure, so none is recommended until an experiment shows a transformation
that Rhai expresses badly. XSLT, XPath, and XQuery arrive only with a SOAP
component (row 10).

Secret stores (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, Google
Secret Manager, CyberArk) are not adapter components: they are backends for
the platform's `secret:` references, decided at the platform level for every
product.

## Systems outside the Camel catalog worth a pack

From our domain, all reachable with `http` or `graphql` plus a pack (APIs
named from public documentation; each pack's pre-check confirms the current
release):

- OpenCRVS: Increment 3.
- openIMIS: GraphQL API and a FHIR R4 module.
- OpenMRS: REST and FHIR R4.
- ODK Central and KoboToolbox: REST, and OData for submissions.
- CommCare: REST.
- MOSIP: REST (identity verification belongs to Evidence, not the adapter).
- Odoo-based systems such as OpenSPP: JSON-RPC over HTTP; expressible over
  `http` as POST with a JSON body, so it needs no component.
- Mojaloop: the FSPIOP REST API (payment flows are asynchronous callbacks,
  so only its lookups fit the facade).
- X-Road: a member's services are REST or SOAP through its security server;
  REST works today, SOAP needs row 10.

## Authentication note

Two candidates need an authentication kind beyond `CONCEPT.md` 10.2: Google
service accounts use the RFC 7523 section 2.1 JWT bearer grant (the JWT is
the grant, not client authentication), and some SOAP services sign with
WS-Security. Neither enters D18 until a pack needs it.

## Out of the adapter's model

Recorded so the list is complete, not to reopen it:

- Event and messaging transports (Kafka, AMQP, JMS, ActiveMQ, NATS, MQTT,
  Pulsar, SQS, Pub/Sub, Event Hubs, Debezium, PostgreSQL LISTEN/NOTIFY and
  replication): the facade is request-reply; event intake is a separate
  product question.
- File and batch transfer (File, FTP, FTPS, SFTP, SCP, SMB, AS2, Flatpack,
  DFDL): scheduled bulk exchange with banks and telecoms fits Registry
  Coordinator and a payments integration, not a live facade.
- Schedulers and triggers (Timer, Scheduler, Cron, Quartz, Webhook): the
  adapter has no consumer besides `rest`.
- Owned by other Registry Stack products: SMS, email, and chat (SMPP, CM SMS,
  Twilio, WhatsApp, Telegram, Mail, Slack) are Registry Messaging; object
  storage (S3, MinIO, Azure Blob, Google Storage) is Document Store; PDF and
  FOP are Registry Render; BPM engines (Camunda, Flowable, Bonita, Zeebe)
  overlap Registry Coordinator; signing and crypto (Crypto, PQC, XML
  Security) are Evidence's.
- Infrastructure, cloud management, caches, data grids, analytics stores,
  vector stores, AI and LLM components, IoT and industrial protocols, social
  media, and finance trading: no registry facade use.
