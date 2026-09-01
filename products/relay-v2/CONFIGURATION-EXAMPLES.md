# Relay V2 Configuration Examples

Status: Illustrative design probes
Date: 2026-08-10
Product direction: [Relay V2 Product Concept](CONCEPT.md)
Acceptance boundary: [Relay V2 Definition of Done](DEFINITION-OF-DONE.md)

## How to read these examples

These examples test whether one small authoring model can describe materially
different registries. Their named keys and boundaries are the intended Version
1 authoring shape; the generated schema will make their constraints precise.
Relay owns the strict contract. A Registry Manifest projection is later
portability tooling, not a Version one runtime input.

The intended boundaries are firmer than the syntax:

- `RegistryContract` is governed, versioned, compiled and sealed by `relayctl package`, verified at startup, and cannot be overridden by runtime configuration;
- `RelayRuntime` binds deployment-local paths, listeners, token issuers, and audit storage without changing resources, operations, disclosure, or semantics;
- SQLite views and columns are source bindings, while resources and properties are the public model;
- one contract describes one Registry; each resource is a Record type within it;
- every resource declares required `datasetIdentifier` and `entityTypeIdentifier` values beside `id`; Relay never infers either value from the resource id, route, view, or semantic class;
- every Record has mandatory Registry Core bindings in addition to selectable domain properties, while homogeneous Registry, dataset, and entity-type context appears once in JSON or JSON-LD response `meta`;
- `sourceRequired` governs complete source-Record validation, while the public access-profile schema permits any compiled selectable `domainData` subset;
- external semantic alignment is optional and file-based, pinned, and reviewed;
- every operation declares one default and a finite ordered set of access profiles; an operation with any public access profile uses a public default; access and disclosure belong to the access profile, while the requester may only select fewer properties within the chosen access profile;
- token issuers assign authority, but they cannot enable an operation Relay did not compile;
- family capabilities are derived from compiled operations, never duplicated in configuration;
- `statisticalDatasets` is a separate, format-neutral publication contract with exactly one fixed `access`, snapshot-only sources, bounded observation queries, and an explicit `bindings.sdmx` selection;
- SDMX REST and serialization profile versions are compiler-owned binding metadata and are never authored as Registry `alignmentTargets`;
- none of these examples enables response signing.

Each short classification entry inherits scheme versions and review provenance
from its contract-level `classifications` block. Each external mapping file is
digest-pinned and must name an explicit exact, close, broad, narrow, or related
relation for every mapped term.

The examples pin written standards as alignment targets. They do not consume
the legacy Digital Registries OpenAPI or claim GovStack conformance. The API
binding uses `pageSize`, `cursor`, direct camelCase equality filters, the
`items`/`pageInfo.nextCursor` list envelope, and Registry Stack problems.

## Publish a Registry for discovery

Add only the jurisdiction identifiers that Relay cannot derive from the
Registry contract:

```yaml
publication:
  jurisdictions: [urn:example:jurisdiction:national]
```

`relayctl package` derives the service identity, title, description, native
client base URL, publisher, operator, Registry authority, Relay profile, and
public capability identifiers from the reviewed contract. It publishes each
exact public semantic-class and operation-family pair under a distinct derived
binding identity, so catalog filters cannot combine capabilities from different
resources. The generated sealed artifact is served, without a new route or
credential, at `/v2/artifacts/discovery-description`.

Run the production compilation flow after changing the contract:

```sh
relayctl check <project> --production
relayctl generate <project> --output <generated>
relayctl package <project> --output <package>
```

Relay startup validates the sealed package and exact-regenerates every artifact
before activation. The description is a closed
public-facts projection for search. It is not a trust anchor, and protected
operations and internal source, access, policy, and audit fields are excluded
by the provider-public-projection invariant tests.

Every successful JSON or JSON-LD response carries one homogeneous Registry
Record context in response-level `meta`. Items do not repeat that context. For
example, an identifier read has this shape:

```json
{
  "data": {
    "recordIdentifier": "B-00142",
    "revisionIdentifier": "17",
    "lifecycleState": "ACTIVE",
    "schemaReference": "https://business.example.invalid/v2/artifacts/registered-business.schema.json",
    "semanticModelReference": "https://business.example.invalid/v2/artifacts/registered-business.vocabulary.jsonld",
    "authorityIdentifier": "urn:example:institution:company-registrar",
    "recordedAt": "2026-08-01T10:30:00Z",
    "domainData": {
      "legalName": "Example Cooperative",
      "registrationStatus": "ACTIVE"
    }
  },
  "meta": {
    "registryIdentifier": "urn:example:registry:registered-businesses",
    "datasetIdentifier": "legal-entities",
    "entityTypeIdentifier": "company"
  }
}
```

`fields=legalName,registrationStatus` narrowed only `domainData`. List responses
place such items in `items`; single reads and resolved lookups place one in
`data`. The semantic-model reference resolves to the generated local vocabulary;
the response `meta` retains Relay operation, access, disclosure, source, field,
and link extensions. JSON-LD adds the shared Registry Record context before the
generated operation context. GeoJSON remains a separate media profile.

Each example shows the governed and runtime documents together for readability. A real project would keep them as separately validated files and package them with synthetic fixtures and generated artifacts.

The fourth coequal acceptance project, [labour statistics](acceptance/labour-statistics/),
exercises a different governed shape without changing the three Record examples.
It declares two pre-aggregated datasets under `statisticalDatasets`, each over a
snapshot SQLite view. Each dataset has dimensions, one time dimension with an
explicit annual, quarterly, monthly, or daily granularity, one measure,
attributes, publication metadata, bounded query limits, exactly one access
rule, and a required `bindings.sdmx`. The binding compiles only keyed data, the
omitted-key data alias, and exact dataflow and datastructure structure routes.
It emits SDMX-JSON 2.1.0, SDMX-CSV 2.1.0, and Structure JSON 2.1.0 within the
aligned SDMX REST 2.2.2 read subset. It does not add access profiles, dynamic
aggregation, schema or availability placeholders, history, or structure
maintenance.

## Example 1: social assistance enrolment

This is a sensitive, exact-lookup-only registry. It deliberately has no list or identifier-read operation. An authorized service officer supplies two exact selectors in a bounded request body. Relay also binds the verified officer's service area to a hidden source column. The response discloses a reviewed status summary, not names, addresses, dates of birth, selectors, or household membership.

The Version one live source is intentionally unversioned. Record revisions
still come from each row, while response and audit source revision are
explicitly unavailable and every response is `no-store`.

```yaml
apiVersion: relay.registrystack.org/v2alpha1
kind: RegistryContract
metadata:
  id: social-assistance-enrolments
  version: 2026-08-01
  title: Social assistance enrolment consultations

registry:
  registryIdentifier: urn:example:registry:social-assistance-enrolments
  name: Social assistance enrolment registry
  authority:
    identifier: urn:example:institution:social-protection-authority
    name: Social Protection Authority
  operator:
    identifier: urn:example:institution:digital-service-operator
    name: Government Digital Service Operator
  authoritativeScope: Social assistance enrolment decisions in the declared jurisdiction
  baseUri: https://social-registry.example.invalid/registry/
  identifierLifecyclePolicyRef: governance/record-identifiers.yaml
  alignmentTargets:
    - {name: govstack-digital-registries, version: 3.0.0-alpha.2, cfrTarget: govstack-cfr-2.1.0, status: directional}
    - {name: govstack-api-design-guide, version: 0.1.0-draft, status: directional}

governance:
  controller: urn:example:institution:social-protection-authority
  publisher: urn:example:institution:social-registry-office
  auditOwner: urn:example:institution:internal-audit

semantics:
  localVocabulary: https://social-registry.example.invalid/vocabulary/

classifications:
  privacy: {scheme: "https://w3id.org/dpv", version: "2.3"}
  institutional: {scheme: "urn:example:classification:social-protection", version: "2026-08-01"}
  handling: {scheme: "https://id.registrystack.org/vocab/handling", version: "1"}
  provenanceRef: governance/classification-review.yaml

sources:
  assistance:
    kind: sqlite
    profile: live-read-only
    expectedSchemaFingerprint: sha256:1111111111111111111111111111111111111111111111111111111111111111

resources:
  - id: assistance-enrolment
    datasetIdentifier: assistance-enrolments
    entityTypeIdentifier: assistance-enrolment
    title: Assistance enrolment
    description: Reviewed consultation view of one assistance enrolment Record
    semanticClass: local:AssistanceEnrolment
    source:
      source: assistance
      view: relay_assistance_enrolments
    classificationDefaults: {institutional: restricted, handling: restricted, status: reviewed}
    recordContext:
      recordIdentifier: {sourceColumn: enrolment_reference}
      revisionIdentifier: {sourceColumn: record_revision}
      lifecycleState: {sourceColumn: lifecycle_state, codelist: codelists/record-lifecycle.yaml}
      recordedAt: {sourceColumn: recorded_at}
    sourceColumnClassifications:
      enrolment_reference: {privacy: identifying, institutional: restricted, handling: restricted, status: reviewed}
      record_revision: {privacy: derived}
      lifecycle_state: {privacy: personal-context}
      recorded_at: {privacy: personal-context}
      case_reference: {privacy: identifying}
      person_reference: {privacy: identifying}
      service_area_code: {privacy: personal-context}

    properties:
      enrolmentReference:
        label: Enrolment reference
        description: Stable reference assigned to the enrolment Record
        sourceColumn: enrolment_reference
        type: string
        sourceRequired: true
        semanticTerm: local:enrolmentReference
        classification: {privacy: identifying}
      maskedEnrolmentReference:
        label: Masked enrolment reference
        description: Relay-owned partial-string view that exposes only the final four Unicode scalars
        sourceColumn: enrolment_reference
        transform: {kind: partial-string, reveal: suffix, characters: 4}
        type: string
        sourceRequired: true
        semanticTerm: local:maskedEnrolmentReference
        classification: {privacy: partially-revealed-identifying, institutional: confidential, handling: confidential, status: reviewed}
      programmeCode:
        label: Programme code
        description: Reviewed code for the assistance programme
        sourceColumn: programme_code
        type: controlled-code
        codelist: codelists/programmes.yaml
        sourceRequired: true
        semanticTerm: local:programme
        classification: {privacy: sensitive-personal}
      enrolmentStatus:
        label: Enrolment status
        description: Current reviewed status of the enrolment
        sourceColumn: enrolment_status
        type: controlled-code
        codelist: codelists/enrolment-status.yaml
        sourceRequired: true
        semanticTerm: local:enrolmentStatus
        classification: {privacy: sensitive-personal}
      entitlementCategory:
        label: Entitlement category
        description: Optional reviewed category of entitlement
        sourceColumn: entitlement_category
        type: controlled-code
        codelist: codelists/entitlement-categories.yaml
        sourceRequired: false
        semanticTerm: local:entitlementCategory
        classification: {privacy: sensitive-personal}
      validThrough:
        label: Valid through
        description: Optional final date of the current enrolment validity
        sourceColumn: valid_through
        type: date
        sourceRequired: false
        semanticTerm: local:validThrough
        classification: {privacy: personal}
      serviceOfficeCode:
        label: Service office code
        description: Reviewed service office responsible for the enrolment
        sourceColumn: service_office_code
        type: controlled-code
        codelist: codelists/service-offices.yaml
        sourceRequired: true
        semanticTerm: local:serviceOffice
        classification: {privacy: personal-context, institutional: internal}

    disclosureProfiles:
      limited:
        properties: [maskedEnrolmentReference, enrolmentStatus, validThrough]
      caseworker:
        properties: [enrolmentReference, programmeCode, enrolmentStatus, entitlementCategory, validThrough, serviceOfficeCode]

    operations:
      lookups:
        - id: by-case-and-person
          requestBody:
            maximumBytes: 512
            selectors:
              caseReference: {sourceColumn: case_reference, type: string, minimumBytes: 8, maximumBytes: 96}
              personReference: {sourceColumn: person_reference, type: string, minimumBytes: 8, maximumBytes: 96}
          defaultAccessProfile: limited
          accessProfiles:
            limited:
              access:
                scope: registry:social-assistance:limited
                purpose: {claim: purpose, allowed: [benefit-delivery]}
                authorityRowBinding: {claim: service_area, sourceColumn: service_area_code}
              disclosureProfile: limited
            caseworker:
              access:
                scope: registry:social-assistance:caseworker
                purpose: {claim: purpose, allowed: [benefit-delivery]}
                authorityRowBinding: {claim: service_area, sourceColumn: service_area_code}
              disclosureProfile: caseworker

    processingDescriptions:
      - id: benefit-delivery-consultation
        operationRefs: ["lookup:by-case-and-person"]
        purpose: benefit-delivery
        recipientClass: authorized-service-officer
        legalBasisRef: governance/social-assistance-legal-basis.yaml
        dpvProfileRef: governance/social-assistance-processing.dpv.yaml
        safeguards: [exact-lookup, principal-row-binding, property-minimization, value-free-audit]

metadataVisibility:
  service: public
  resources: operation-bound
  semantics: operation-bound
  classifications: operator-only
  processing: operation-bound

---
apiVersion: relay.registrystack.org/v2alpha1
kind: RelayRuntime
server: {bind: "127.0.0.1:8080"}
packagePath: /srv/relay/social-assistance-package
sources:
  assistance: {path: /srv/registries/social-assistance.sqlite}
authentication:
  issuer:
    id: institutional-authorization-server
    trustedIssuer: https://identity.example.invalid
    discoveryUrl: https://identity-transport.example.invalid/.well-known/openid-configuration
    audience: relay-social-assistance
    tokenTypes: [at+jwt]
    algorithms: [ES256]
audit:
  sink: /var/lib/relay/audit/social-assistance.jsonl
  integrityKeyRef: secret:file/audit-integrity-key
limits: {requestTimeoutMilliseconds: 1500, concurrentQueries: 16}
quotas: {requestsPerMinute: 120, burst: 20}
```

`trustedIssuer` is the exact JWT `iss` value Relay accepts. `discoveryUrl` is
the operator-selected metadata transport and may use a different hostname;
the returned discovery document must still declare the exact trusted issuer.
Existing runtimes may omit `trustedIssuer` only when `discoveryUrl` is the
canonical issuer plus `/.well-known/openid-configuration`. As a controlled
alternative, set `trustedIssuer` with `jwksUrl` and omit `discoveryUrl`; Relay
then binds that exact key endpoint directly while preserving exact token issuer
validation. Defining both transports or neither fails startup. Run `relay
check --runtime <runtime.yaml>` before routing traffic to prove the sealed
package, source, audit, secret, and issuer key transport without binding the
listener.

What this example must prove:

- even a broadly scoped token cannot create list or identifier-read routes;
- lookup scope, trusted purpose, and service-area binding are all required;
- selectors and the hidden `service_area_code` never become public properties;
- selecting `enrolmentStatus,validThrough` returns less than the authorized default without changing authorization;
- a useful local vocabulary, JSON-LD context, JSON Schema, and SHACL starter are generated without any external vocabulary mapping;
- no match, ambiguity, and a hidden row return the same `404` problem except for trace
  correlation, while an invalid selected source Record fails closed as `503 source.unavailable`;
- mandatory Registry Record context remains present and capability discovery derives only constrained `consultation.search`.

## Example 2: public business registry

This is a genuinely public snapshot. It supports deterministic collection listing and identifier read without a token. Filters are predefined exact matches. The source view deliberately omits directors, beneficial owners, full addresses, filing history, and internal source keys.

```yaml
apiVersion: relay.registrystack.org/v2alpha1
kind: RegistryContract
metadata:
  id: registered-businesses
  version: 2026-08-01
  title: Registered businesses

registry:
  registryIdentifier: urn:example:registry:registered-businesses
  name: Registered business registry
  authority:
    identifier: urn:example:institution:company-registrar
    name: Company Registrar
  operator:
    identifier: urn:example:institution:digital-service-operator
    name: Government Digital Service Operator
  authoritativeScope: Legal business registrations in the declared jurisdiction
  baseUri: https://business.example.invalid/registry/
  identifierLifecyclePolicyRef: governance/record-identifiers.yaml
  alignmentTargets:
    - {name: govstack-digital-registries, version: 3.0.0-alpha.2, cfrTarget: govstack-cfr-2.1.0, status: directional}
    - {name: govstack-api-design-guide, version: 0.1.0-draft, status: directional}

governance:
  controller: urn:example:institution:company-registrar
  publisher: urn:example:institution:company-registrar
  auditOwner: urn:example:institution:company-registrar-audit

semantics:
  localVocabulary: https://business.example.invalid/vocabulary/
  alignments:
    - id: semic-core-business
      version: 2.0.0
      profileRef: semantics/semic-core-business.yaml
      digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      relationRequired: true

classifications:
  privacy: {scheme: "https://w3id.org/dpv", version: "2.3"}
  institutional: {scheme: "urn:example:classification:company-registrar", version: "2026-08-01"}
  handling: {scheme: "https://id.registrystack.org/vocab/handling", version: "1"}
  provenanceRef: governance/classification-review.yaml

sources:
  companies:
    kind: sqlite
    profile: snapshot
    expectedSchemaFingerprint: sha256:2222222222222222222222222222222222222222222222222222222222222222

resources:
  - id: registered-business
    datasetIdentifier: legal-entities
    entityTypeIdentifier: company
    title: Registered business
    description: Public registration facts for one legal business Record
    semanticClass: local:RegisteredBusiness
    source:
      source: companies
      view: relay_registered_businesses
    classificationDefaults: {privacy: non-personal, institutional: public, handling: public, status: reviewed}
    recordContext:
      recordIdentifier: {sourceColumn: registration_number}
      revisionIdentifier: {sourceColumn: record_revision}
      lifecycleState: {sourceColumn: lifecycle_state, codelist: codelists/record-lifecycle.yaml}
      recordedAt: {sourceColumn: recorded_at}
    sourceColumnClassifications:
      record_revision: {}
      lifecycle_state: {}
      recorded_at: {}

    properties:
      registrationNumber:
        label: Registration number
        description: Stable public identifier assigned by the Company Registrar
        sourceColumn: registration_number
        type: string
        sourceRequired: true
        semanticTerm: local:registrationNumber
      legalName:
        label: Legal name
        description: Current registered legal name of the business
        sourceColumn: registrar_legal_name
        type: string
        sourceRequired: true
        semanticTerm: local:legalName
        classification: {privacy: potentially-personal, institutional: public-by-law}
      registrarLegalName:
        label: Registrar legal name
        description: Protected authoritative legal name for registrar work
        sourceColumn: legal_name
        type: string
        sourceRequired: true
        semanticTerm: local:registrarLegalName
        classification: {privacy: potentially-personal, institutional: public-by-law, handling: confidential, status: reviewed}
      registrationStatus:
        label: Registration status
        description: Current lifecycle status of the business registration
        sourceColumn: registration_status
        type: controlled-code
        codelist: codelists/business-status.yaml
        sourceRequired: true
        semanticTerm: local:registrationStatus
      legalForm:
        label: Legal form
        description: Registered legal form of the business
        sourceColumn: legal_form
        type: controlled-code
        codelist: codelists/legal-forms.yaml
        sourceRequired: true
        semanticTerm: local:legalForm
      registeredJurisdiction:
        label: Registered jurisdiction
        description: Jurisdiction in which the business is registered
        sourceColumn: jurisdiction_code
        type: controlled-code
        codelist: codelists/jurisdictions.yaml
        sourceRequired: true
        semanticTerm: local:registeredJurisdiction
      registeredOfficeArea:
        label: Registered office area
        description: Public administrative area of the registered office
        sourceColumn: registered_office_area
        type: controlled-code
        codelist: codelists/office-areas.yaml
        sourceRequired: false
        semanticTerm: local:registeredOfficeArea
        classification: {privacy: potentially-personal, institutional: public-by-law}

    disclosureProfiles:
      public-register:
        properties: [registrationNumber, legalName, registrationStatus, legalForm, registeredJurisdiction, registeredOfficeArea]
      registrar-register:
        properties: [registrationNumber, registrarLegalName, registrationStatus, legalForm, registeredJurisdiction]

    operations:
      list:
        defaultAccessProfile: public-register
        accessProfiles:
          public-register: {access: public, disclosureProfile: public-register}
          registrar: {access: {scope: registry:business:list-registrar}, disclosureProfile: registrar-register}
        filters:
          - {name: status, property: registrationStatus, type: controlled-code}
          - {name: jurisdiction, property: registeredJurisdiction, type: controlled-code}
        allowUnfiltered: true
        orderBy: [registrationNumber]
        pagination: {defaultPageSize: 50, maximumPageSize: 200}
      read:
        defaultAccessProfile: public-register
        accessProfiles:
          public-register: {access: public, disclosureProfile: public-register}
          registrar: {access: {scope: registry:business:read-registrar}, disclosureProfile: registrar-register}

    processingDescriptions:
      - id: statutory-publication
        operationRefs: [list, read]
        purpose: statutory-publication
        recipientClass: public
        legalBasisRef: governance/business-register-publication.yaml
        dpvProfileRef: governance/business-register-processing.dpv.yaml
        safeguards: [reviewed-public-view, property-minimization, deterministic-pagination, change-impact-review]

metadataVisibility:
  service: public
  resources: public
  semantics: public
  classifications: public
  processing: public

---
apiVersion: relay.registrystack.org/v2alpha1
kind: RelayRuntime
server: {bind: "127.0.0.1:8080"}
packagePath: /srv/relay/business-register-package
sources:
  companies: {path: /srv/registries/business-register.sqlite}
authentication: {issuer: null}
audit:
  sink: /var/lib/relay/audit/business-register.jsonl
  integrityKeyRef: secret:file/audit-integrity-key
limits: {requestTimeoutMilliseconds: 1500, concurrentQueries: 32}
```

What this example must prove:

- public means explicitly compiled public access, not absence of a global authentication setting;
- filters appear as direct camelCase parameters such as `status=ACTIVE`, and accept only the named property, datatype, codelist, and exact-equality operator;
- pagination uses `pageSize`, a client-opaque authenticated-encrypted `cursor`, and `items` with nullable `pageInfo.nextCursor`, while publisher-declared stable ordering prevents arbitrary sorting; encryption prevents filter and keyset-order values from bypassing field minimization;
- a requested subset such as `registrationNumber,legalName,registrationStatus` has its own correct ETag and JSON-LD representation;
- the captured snapshot digest and schema fingerprint make responses reproducible and strongly cacheable by revision;
- capability discovery derives `consultation.list` and `consultation.retrieve` and no other family pattern.

### Point location variant: governed premises search

The business Registry may add this second resource. Scalar properties keep the
same mapping shape used elsewhere. `location` is the one additive Point form:
it names exact CRS84 and a closed two-column `source`, then
`primaryGeometry` references that property by name. The named search owns
`bbox`; it is not a list option and its protected scope is distinct from list.

```yaml
- id: registered-premises
  datasetIdentifier: business-premises
  entityTypeIdentifier: premises
  title: Registered premises
  description: Current synthetic public premises locations associated with registered businesses.
  semanticClass: local:RegisteredPremises
  source: {source: companies, view: relay_registered_premises}
  classificationDefaults: {privacy: non-personal, institutional: public, handling: public, status: reviewed}
  sourceColumnClassifications:
    longitude: {privacy: non-personal, institutional: public, handling: public, status: reviewed}
    latitude: {privacy: non-personal, institutional: public, handling: public, status: reviewed}
  recordContext:
    recordIdentifier: {sourceColumn: premises_identifier}
    revisionIdentifier: {sourceColumn: record_revision}
    lifecycleState: {sourceColumn: lifecycle_state, codelist: codelists/record-lifecycle.yaml}
    recordedAt: {sourceColumn: recorded_at}
  properties:
    premisesIdentifier:
      type: string
      sourceColumn: premises_identifier
      sourceRequired: true
      semanticTerm: local:premisesIdentifier
      label: Premises identifier
      description: Stable identifier of the registered premises.
    businessRegistrationNumber:
      type: string
      sourceColumn: registration_number
      sourceRequired: true
      semanticTerm: local:businessRegistrationNumber
      label: Business registration number
      description: Registration number linking the premises to its registered business.
    premisesName:
      type: string
      sourceColumn: premises_name
      sourceRequired: true
      semanticTerm: local:premisesName
      label: Premises name
      description: Published name of the synthetic registered premises.
    location:
      type: point
      crs: http://www.opengis.net/def/crs/OGC/0/CRS84
      source: {longitudeColumn: longitude, latitudeColumn: latitude}
      sourceRequired: true
      semanticTerm: local:location
      label: Premises location
      description: Reviewed Point location of the registered premises in CRS84 longitude-latitude order.
      classification: {privacy: non-personal, institutional: public, handling: public, status: reviewed}
  primaryGeometry: location
  disclosureProfiles:
    public-premises: {properties: [premisesIdentifier, premisesName, location]}
    registrar-premises: {properties: [premisesIdentifier, businessRegistrationNumber, premisesName, location]}
  operations:
    list:
      defaultAccessProfile: registrar-premises
      accessProfiles:
        registrar-premises:
          access: {scope: registry:business:premises-list}
          disclosureProfile: registrar-premises
      allowUnfiltered: true
      orderBy: [premisesIdentifier]
      pagination: {defaultPageSize: 2, maximumPageSize: 4}
    read:
      defaultAccessProfile: public-premises
      accessProfiles:
        public-premises: {access: public, disclosureProfile: public-premises}
        registrar-premises:
          access: {scope: registry:business:premises-read-registrar}
          disclosureProfile: registrar-premises
    searches:
      - id: within-bbox
        query:
          kind: point-bbox
          maximumLongitudeSpanDegrees: 2
          maximumLatitudeSpanDegrees: 2
        defaultAccessProfile: public-premises
        accessProfiles:
          public-premises: {access: public, disclosureProfile: public-premises}
          registrar-premises:
            access: {scope: registry:business:premises-search-registrar}
            disclosureProfile: registrar-premises
        orderBy: [premisesIdentifier]
        pagination: {defaultPageSize: 2, maximumPageSize: 4}
```

`GET /v2/resources/registered-premises/searches/within-bbox?bbox=100,13,101,14`
performs inclusive containment. JSON and JSON-LD remain available. When the
selected access profile discloses `location`, `Accept: application/geo+json`
returns RFC 7946 by default; `formatProfile=jsonfg` adds the bounded JSON-FG
metadata. These formats do not change authorization or disclosure, and this
profile does not claim OGC API Features conformance.

## Example 3: civil-event registry

This registry is CRVS-shaped but the runtime remains event-domain neutral. It has no collection-list operation. Authorized registrars may read a known opaque event identifier under one scope and disclosure profile. A verification client may perform only a named exact lookup under a different scope and smaller disclosure profile. It uses an ordinary external issuer for the core journey. Registry Mint may replace that issuer by registering the same audience, scope, and optional authority claims.

This live source is intentionally unversioned. Its Record revision remains
source-bound, while source revision is explicitly unavailable and responses are
`no-store`.

```yaml
apiVersion: relay.registrystack.org/v2alpha1
kind: RegistryContract
metadata:
  id: civil-events
  version: 2026-08-01
  title: Civil event registrations

registry:
  registryIdentifier: urn:example:registry:civil-events
  name: Civil event registry
  authority:
    identifier: urn:example:institution:civil-registration-authority
    name: Civil Registration Authority
  operator:
    identifier: urn:example:institution:digital-service-operator
    name: Government Digital Service Operator
  authoritativeScope: Civil event registrations in the declared jurisdiction
  baseUri: https://civil-registry.example.invalid/registry/
  identifierLifecyclePolicyRef: governance/record-identifiers.yaml
  alignmentTargets:
    - {name: govstack-digital-registries, version: 3.0.0-alpha.2, cfrTarget: govstack-cfr-2.1.0, status: directional}
    - {name: govstack-api-design-guide, version: 0.1.0-draft, status: directional}

governance:
  controller: urn:example:institution:civil-registration-authority
  publisher: urn:example:institution:civil-registration-authority
  auditOwner: urn:example:institution:civil-registration-inspectorate

semantics:
  localVocabulary: https://civil-registry.example.invalid/vocabulary/
  alignments:
    - id: publicschema-events
      version: pinned-2026-08-01
      profileRef: semantics/publicschema-events.yaml
      digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
      relationRequired: true

classifications:
  privacy: {scheme: "https://w3id.org/dpv", version: "2.3"}
  institutional: {scheme: "urn:example:classification:civil-registration", version: "2026-08-01"}
  handling: {scheme: "https://id.registrystack.org/vocab/handling", version: "1"}
  provenanceRef: governance/classification-review.yaml

sources:
  events:
    kind: sqlite
    profile: live-read-only
    expectedSchemaFingerprint: sha256:3333333333333333333333333333333333333333333333333333333333333333

resources:
  - id: civil-event
    datasetIdentifier: civil-events
    entityTypeIdentifier: civil-event
    title: Civil event registration
    description: Protected registration facts for one civil-event Record
    semanticClass: local:CivilEventRegistration
    source:
      source: events
      view: relay_civil_events
    classificationDefaults: {institutional: restricted, handling: restricted, status: reviewed}
    recordContext:
      recordIdentifier: {sourceColumn: event_reference}
      revisionIdentifier: {sourceColumn: record_revision}
      lifecycleState: {sourceColumn: lifecycle_state, codelist: codelists/record-lifecycle.yaml}
      recordedAt: {sourceColumn: recorded_at}
    sourceColumnClassifications:
      record_revision: {privacy: derived}
      lifecycle_state: {privacy: personal-context}
      recorded_at: {privacy: personal-context}
      registration_number: {privacy: identifying}
      jurisdiction_code: {privacy: personal-context}

    properties:
      eventReference:
        label: Event reference
        description: Stable opaque identifier assigned to the civil-event Record
        sourceColumn: event_reference
        type: string
        sourceRequired: true
        semanticTerm: local:eventReference
        classification: {privacy: identifying}
      eventType:
        label: Event type
        description: Reviewed type of civil event
        sourceColumn: event_type
        type: controlled-code
        codelist: codelists/civil-event-types.yaml
        sourceRequired: true
        semanticTerm: local:eventType
        classification: {privacy: sensitive-personal}
      registrationStatus:
        label: Registration status
        description: Current lifecycle status of the civil-event registration
        sourceColumn: registration_status
        type: controlled-code
        codelist: codelists/civil-registration-status.yaml
        sourceRequired: true
        semanticTerm: local:registrationStatus
        classification: {privacy: personal}
      registrationDate:
        label: Registration date
        description: Date on which the civil event was registered
        sourceColumn: registration_date
        type: date
        sourceRequired: true
        semanticTerm: local:registrationDate
        classification: {privacy: personal}
      registrationYear:
        label: Registration year
        description: Reviewed year-precision form of the registration date
        sourceColumn: registration_date
        transform: {kind: date-precision, sourceType: date, precision: year}
        type: year
        sourceRequired: true
        semanticTerm: local:registrationYear
        classification: {privacy: derived, institutional: confidential, handling: confidential, status: reviewed}
      registrationArea:
        label: Registration area
        description: Administrative area responsible for the registration
        sourceColumn: registration_area_code
        type: controlled-code
        codelist: codelists/registration-areas.yaml
        sourceRequired: true
        semanticTerm: local:registrationArea
        classification: {privacy: personal-context}
      certificateAvailable:
        label: Certificate available
        description: Whether a certificate can currently be issued
        sourceColumn: certificate_available
        type: boolean
        sourceRequired: true
        semanticTerm: local:certificateAvailable
        classification: {privacy: personal}

    disclosureProfiles:
      registrar-record:
        properties: [eventReference, eventType, registrationStatus, registrationDate, registrationArea, certificateAvailable]
      verification-result:
        properties: [eventReference, eventType, registrationStatus, registrationDate, certificateAvailable]
      supervisory-verification:
        properties: [eventReference, eventType, registrationStatus, registrationYear, certificateAvailable]

    operations:
      read:
        defaultAccessProfile: registrar
        accessProfiles:
          registrar:
            access:
              scope: registry:civil-events:read
              purpose: {claim: purpose, allowed: [civil-registration-administration]}
              authorityRowBinding: {claim: jurisdiction, sourceColumn: jurisdiction_code}
            disclosureProfile: registrar-record
      lookups:
        - id: verify-registration
          requestBody:
            maximumBytes: 384
            selectors:
              registrationNumber: {sourceColumn: registration_number, type: string, minimumBytes: 12, maximumBytes: 96}
              eventType: {sourceColumn: event_type, type: controlled-code, codelist: codelists/civil-event-types.yaml}
          defaultAccessProfile: registrar-verification
          accessProfiles:
            registrar-verification:
              access:
                scope: registry:civil-events:lookup
                purpose: {claim: purpose, allowed: [registration-verification]}
                authorityRowBinding: {claim: jurisdiction, sourceColumn: jurisdiction_code}
              disclosureProfile: verification-result
            supervisory:
              access:
                scope: registry:civil-events:supervisory
                purpose: {claim: purpose, allowed: [registration-supervision]}
                authorityRowBinding: {claim: jurisdiction, sourceColumn: jurisdiction_code}
              disclosureProfile: supervisory-verification

    processingDescriptions:
      - id: registrar-administration
        operationRefs: [read]
        purpose: civil-registration-administration
        recipientClass: authorized-registrar
        legalBasisRef: governance/civil-registration-legal-basis.yaml
        dpvProfileRef: governance/civil-event-administration.dpv.yaml
        safeguards: [no-collection-list, operation-scopes, principal-row-binding, property-minimization, value-free-audit]
      - id: registration-verification
        operationRefs: ["lookup:verify-registration"]
        purpose: registration-verification
        recipientClass: authorized-verifier
        legalBasisRef: governance/civil-registration-legal-basis.yaml
        dpvProfileRef: governance/civil-event-verification.dpv.yaml
        safeguards: [no-collection-list, operation-scopes, principal-row-binding, minimum-disclosure-profile, value-free-audit]

metadataVisibility:
  service: public
  resources: operation-bound
  semantics: operation-bound
  classifications: operator-only
  processing: operation-bound

---
apiVersion: relay.registrystack.org/v2alpha1
kind: RelayRuntime
server: {bind: "127.0.0.1:8080"}
packagePath: /srv/relay/civil-events-package
sources:
  events: {path: /srv/registries/civil-events.sqlite}
authentication:
  issuer:
    id: civil-registry-authorization-server
    discoveryUrl: https://identity.example.invalid/.well-known/openid-configuration
    audience: relay-civil-events
    tokenTypes: [at+jwt]
    algorithms: [ES256]
audit:
  sink: /var/lib/relay/audit/civil-events.jsonl
  integrityKeyRef: secret:file/audit-integrity-key
limits: {requestTimeoutMilliseconds: 1500, concurrentQueries: 16}
quotas: {requestsPerMinute: 120, burst: 20}
```

## Complete accepted key-path inventory

The following blocks come from successful typed `relayctl check --production`
reports for all four coequal acceptance projects. They describe the complete
strict configuration surface exercised by those projects. Run
`products/relay-v2/scripts/check-configs.sh --write` after an intentional model
change, then review and explain every new path in the examples above.

<!-- relay-v2-registry-key-paths:start -->
```text
apiVersion
classifications
classifications.handling
classifications.handling.scheme
classifications.handling.version
classifications.institutional
classifications.institutional.scheme
classifications.institutional.version
classifications.privacy
classifications.privacy.scheme
classifications.privacy.version
classifications.provenanceRef
governance
governance.auditOwner
governance.controller
governance.publisher
kind
metadata
metadata.id
metadata.title
metadata.version
metadataVisibility
metadataVisibility.classifications
metadataVisibility.processing
metadataVisibility.resources
metadataVisibility.semantics
metadataVisibility.service
metadataVisibility.statisticalDatasets
publication
publication.jurisdictions
publication.jurisdictions[]
registry
registry.alignmentTargets
registry.alignmentTargets[]
registry.alignmentTargets[].cfrTarget
registry.alignmentTargets[].name
registry.alignmentTargets[].status
registry.alignmentTargets[].version
registry.authoritativeScope
registry.authority
registry.authority.identifier
registry.authority.name
registry.baseUri
registry.identifierLifecyclePolicyRef
registry.name
registry.operator
registry.operator.identifier
registry.operator.name
registry.registryIdentifier
resources
resources[]
resources[].classificationDefaults
resources[].classificationDefaults.handling
resources[].classificationDefaults.institutional
resources[].classificationDefaults.privacy
resources[].classificationDefaults.status
resources[].datasetIdentifier
resources[].description
resources[].disclosureProfiles
resources[].disclosureProfiles.*
resources[].disclosureProfiles.*.properties
resources[].disclosureProfiles.*.properties[]
resources[].entityTypeIdentifier
resources[].id
resources[].operations
resources[].operations.list
resources[].operations.list.accessProfiles
resources[].operations.list.accessProfiles.*
resources[].operations.list.accessProfiles.*.access
resources[].operations.list.accessProfiles.*.access.authorityRowBinding
resources[].operations.list.accessProfiles.*.access.purpose
resources[].operations.list.accessProfiles.*.access.scope
resources[].operations.list.accessProfiles.*.disclosureProfile
resources[].operations.list.allowUnfiltered
resources[].operations.list.defaultAccessProfile
resources[].operations.list.filters
resources[].operations.list.filters[]
resources[].operations.list.filters[].name
resources[].operations.list.filters[].property
resources[].operations.list.filters[].type
resources[].operations.list.orderBy
resources[].operations.list.orderBy[]
resources[].operations.list.pagination
resources[].operations.list.pagination.defaultPageSize
resources[].operations.list.pagination.maximumPageSize
resources[].operations.lookups
resources[].operations.lookups[]
resources[].operations.lookups[].accessProfiles
resources[].operations.lookups[].accessProfiles.*
resources[].operations.lookups[].accessProfiles.*.access
resources[].operations.lookups[].accessProfiles.*.access.authorityRowBinding
resources[].operations.lookups[].accessProfiles.*.access.authorityRowBinding.claim
resources[].operations.lookups[].accessProfiles.*.access.authorityRowBinding.sourceColumn
resources[].operations.lookups[].accessProfiles.*.access.purpose
resources[].operations.lookups[].accessProfiles.*.access.purpose.allowed
resources[].operations.lookups[].accessProfiles.*.access.purpose.allowed[]
resources[].operations.lookups[].accessProfiles.*.access.purpose.claim
resources[].operations.lookups[].accessProfiles.*.access.scope
resources[].operations.lookups[].accessProfiles.*.disclosureProfile
resources[].operations.lookups[].defaultAccessProfile
resources[].operations.lookups[].id
resources[].operations.lookups[].requestBody
resources[].operations.lookups[].requestBody.maximumBytes
resources[].operations.lookups[].requestBody.selectors
resources[].operations.lookups[].requestBody.selectors.*
resources[].operations.lookups[].requestBody.selectors.*.codelist
resources[].operations.lookups[].requestBody.selectors.*.maximumBytes
resources[].operations.lookups[].requestBody.selectors.*.minimumBytes
resources[].operations.lookups[].requestBody.selectors.*.sourceColumn
resources[].operations.lookups[].requestBody.selectors.*.type
resources[].operations.read
resources[].operations.read.accessProfiles
resources[].operations.read.accessProfiles.*
resources[].operations.read.accessProfiles.*.access
resources[].operations.read.accessProfiles.*.access.authorityRowBinding
resources[].operations.read.accessProfiles.*.access.authorityRowBinding.claim
resources[].operations.read.accessProfiles.*.access.authorityRowBinding.sourceColumn
resources[].operations.read.accessProfiles.*.access.purpose
resources[].operations.read.accessProfiles.*.access.purpose.allowed
resources[].operations.read.accessProfiles.*.access.purpose.allowed[]
resources[].operations.read.accessProfiles.*.access.purpose.claim
resources[].operations.read.accessProfiles.*.access.scope
resources[].operations.read.accessProfiles.*.disclosureProfile
resources[].operations.read.defaultAccessProfile
resources[].operations.searches
resources[].operations.searches[]
resources[].operations.searches[].accessProfiles
resources[].operations.searches[].accessProfiles.*
resources[].operations.searches[].accessProfiles.*.access
resources[].operations.searches[].accessProfiles.*.access.authorityRowBinding
resources[].operations.searches[].accessProfiles.*.access.purpose
resources[].operations.searches[].accessProfiles.*.access.scope
resources[].operations.searches[].accessProfiles.*.disclosureProfile
resources[].operations.searches[].defaultAccessProfile
resources[].operations.searches[].id
resources[].operations.searches[].orderBy
resources[].operations.searches[].orderBy[]
resources[].operations.searches[].pagination
resources[].operations.searches[].pagination.defaultPageSize
resources[].operations.searches[].pagination.maximumPageSize
resources[].operations.searches[].query
resources[].operations.searches[].query.kind
resources[].operations.searches[].query.maximumLatitudeSpanDegrees
resources[].operations.searches[].query.maximumLongitudeSpanDegrees
resources[].primaryGeometry
resources[].processingDescriptions
resources[].processingDescriptions[]
resources[].processingDescriptions[].dpvProfileRef
resources[].processingDescriptions[].id
resources[].processingDescriptions[].legalBasisRef
resources[].processingDescriptions[].operationRefs
resources[].processingDescriptions[].operationRefs[]
resources[].processingDescriptions[].purpose
resources[].processingDescriptions[].recipientClass
resources[].processingDescriptions[].safeguards
resources[].processingDescriptions[].safeguards[]
resources[].properties
resources[].properties.*
resources[].properties.*.classification
resources[].properties.*.classification.handling
resources[].properties.*.classification.institutional
resources[].properties.*.classification.privacy
resources[].properties.*.classification.status
resources[].properties.*.codelist
resources[].properties.*.crs
resources[].properties.*.description
resources[].properties.*.label
resources[].properties.*.semanticTerm
resources[].properties.*.source
resources[].properties.*.source.latitudeColumn
resources[].properties.*.source.longitudeColumn
resources[].properties.*.sourceColumn
resources[].properties.*.sourceRequired
resources[].properties.*.transform
resources[].properties.*.transform.characters
resources[].properties.*.transform.kind
resources[].properties.*.transform.precision
resources[].properties.*.transform.reveal
resources[].properties.*.transform.sourceType
resources[].properties.*.type
resources[].recordContext
resources[].recordContext.lifecycleState
resources[].recordContext.lifecycleState.codelist
resources[].recordContext.lifecycleState.sourceColumn
resources[].recordContext.recordIdentifier
resources[].recordContext.recordIdentifier.sourceColumn
resources[].recordContext.recordedAt
resources[].recordContext.recordedAt.sourceColumn
resources[].recordContext.revisionIdentifier
resources[].recordContext.revisionIdentifier.sourceColumn
resources[].semanticClass
resources[].source
resources[].source.source
resources[].source.view
resources[].sourceColumnClassifications
resources[].sourceColumnClassifications.*
resources[].sourceColumnClassifications.*.handling
resources[].sourceColumnClassifications.*.institutional
resources[].sourceColumnClassifications.*.privacy
resources[].sourceColumnClassifications.*.status
resources[].title
semantics
semantics.alignments
semantics.alignments[]
semantics.alignments[].digest
semantics.alignments[].id
semantics.alignments[].profileRef
semantics.alignments[].relationRequired
semantics.alignments[].version
semantics.localVocabulary
sources
sources.*
sources.*.expectedSchemaFingerprint
sources.*.kind
sources.*.profile
statisticalDatasets
statisticalDatasets[]
statisticalDatasets[].access
statisticalDatasets[].access.authorityRowBinding
statisticalDatasets[].access.authorityRowBinding.claim
statisticalDatasets[].access.authorityRowBinding.sourceColumn
statisticalDatasets[].access.purpose
statisticalDatasets[].access.purpose.allowed
statisticalDatasets[].access.purpose.allowed[]
statisticalDatasets[].access.purpose.claim
statisticalDatasets[].access.scope
statisticalDatasets[].attributes
statisticalDatasets[].attributes.unitMeasure
statisticalDatasets[].attributes.unitMeasure.classification
statisticalDatasets[].attributes.unitMeasure.classification.handling
statisticalDatasets[].attributes.unitMeasure.classification.institutional
statisticalDatasets[].attributes.unitMeasure.classification.privacy
statisticalDatasets[].attributes.unitMeasure.classification.status
statisticalDatasets[].attributes.unitMeasure.column
statisticalDatasets[].attributes.unitMeasure.concept
statisticalDatasets[].attributes.unitMeasure.description
statisticalDatasets[].attributes.unitMeasure.label
statisticalDatasets[].attributes.unitMeasure.required
statisticalDatasets[].attributes.unitMeasure.type
statisticalDatasets[].attributes.unitMeasure.vocabulary
statisticalDatasets[].bindings
statisticalDatasets[].bindings.sdmx
statisticalDatasets[].bindings.sdmx.agencyId
statisticalDatasets[].bindings.sdmx.conceptSchemeId
statisticalDatasets[].bindings.sdmx.dataStructureId
statisticalDatasets[].bindings.sdmx.dataflowId
statisticalDatasets[].bindings.sdmx.version
statisticalDatasets[].classificationDefaults
statisticalDatasets[].classificationDefaults.handling
statisticalDatasets[].classificationDefaults.institutional
statisticalDatasets[].classificationDefaults.privacy
statisticalDatasets[].classificationDefaults.status
statisticalDatasets[].description
statisticalDatasets[].dimensions
statisticalDatasets[].dimensions.refArea
statisticalDatasets[].dimensions.refArea.classification
statisticalDatasets[].dimensions.refArea.classification.handling
statisticalDatasets[].dimensions.refArea.classification.institutional
statisticalDatasets[].dimensions.refArea.classification.privacy
statisticalDatasets[].dimensions.refArea.classification.status
statisticalDatasets[].dimensions.refArea.column
statisticalDatasets[].dimensions.refArea.concept
statisticalDatasets[].dimensions.refArea.description
statisticalDatasets[].dimensions.refArea.label
statisticalDatasets[].dimensions.refArea.type
statisticalDatasets[].dimensions.refArea.vocabulary
statisticalDatasets[].dimensions.sex
statisticalDatasets[].dimensions.sex.classification
statisticalDatasets[].dimensions.sex.classification.handling
statisticalDatasets[].dimensions.sex.classification.institutional
statisticalDatasets[].dimensions.sex.classification.privacy
statisticalDatasets[].dimensions.sex.classification.status
statisticalDatasets[].dimensions.sex.column
statisticalDatasets[].dimensions.sex.concept
statisticalDatasets[].dimensions.sex.description
statisticalDatasets[].dimensions.sex.label
statisticalDatasets[].dimensions.sex.type
statisticalDatasets[].dimensions.sex.vocabulary
statisticalDatasets[].id
statisticalDatasets[].measure
statisticalDatasets[].measure.classification
statisticalDatasets[].measure.classification.handling
statisticalDatasets[].measure.classification.institutional
statisticalDatasets[].measure.classification.privacy
statisticalDatasets[].measure.classification.status
statisticalDatasets[].measure.column
statisticalDatasets[].measure.concept
statisticalDatasets[].measure.description
statisticalDatasets[].measure.id
statisticalDatasets[].measure.label
statisticalDatasets[].measure.type
statisticalDatasets[].processingDescriptions
statisticalDatasets[].processingDescriptions[]
statisticalDatasets[].processingDescriptions[].dpvProfileRef
statisticalDatasets[].processingDescriptions[].id
statisticalDatasets[].processingDescriptions[].legalBasisRef
statisticalDatasets[].processingDescriptions[].operationRefs
statisticalDatasets[].processingDescriptions[].operationRefs[]
statisticalDatasets[].processingDescriptions[].purpose
statisticalDatasets[].processingDescriptions[].recipientClass
statisticalDatasets[].processingDescriptions[].safeguards
statisticalDatasets[].processingDescriptions[].safeguards[]
statisticalDatasets[].publication
statisticalDatasets[].publication.releaseAt
statisticalDatasets[].query
statisticalDatasets[].query.allowUnfiltered
statisticalDatasets[].query.maximumObservations
statisticalDatasets[].query.maximumOffset
statisticalDatasets[].source
statisticalDatasets[].source.source
statisticalDatasets[].source.view
statisticalDatasets[].sourceColumnClassifications
statisticalDatasets[].sourceColumnClassifications.authority_scope
statisticalDatasets[].sourceColumnClassifications.authority_scope.handling
statisticalDatasets[].sourceColumnClassifications.authority_scope.institutional
statisticalDatasets[].sourceColumnClassifications.authority_scope.privacy
statisticalDatasets[].sourceColumnClassifications.authority_scope.status
statisticalDatasets[].time
statisticalDatasets[].time.classification
statisticalDatasets[].time.classification.handling
statisticalDatasets[].time.classification.institutional
statisticalDatasets[].time.classification.privacy
statisticalDatasets[].time.classification.status
statisticalDatasets[].time.column
statisticalDatasets[].time.concept
statisticalDatasets[].time.description
statisticalDatasets[].time.granularity
statisticalDatasets[].time.label
statisticalDatasets[].title
```
<!-- relay-v2-registry-key-paths:end -->

<!-- relay-v2-runtime-key-paths:start -->
```text
apiVersion
audit
audit.integrityKeyRef
audit.sink
authentication
authentication.issuer
authentication.issuer.algorithms
authentication.issuer.algorithms[]
authentication.issuer.audience
authentication.issuer.discoveryUrl
authentication.issuer.id
authentication.issuer.jwksUrl
authentication.issuer.tokenTypes
authentication.issuer.tokenTypes[]
authentication.issuer.trustedIssuer
cursor
cursor.integrityKeyRef
cursor.maximumAgeSeconds
kind
limits
limits.concurrentQueries
limits.requestTimeoutMilliseconds
packagePath
quotas
quotas.burst
quotas.requestsPerMinute
server
server.bind
shutdown
shutdown.gracePeriodMilliseconds
sources
sources.*
sources.*.path
```
<!-- relay-v2-runtime-key-paths:end -->

What this example must prove:

- the absence of `list` prevents collection enumeration for every client;
- read and lookup scopes are independent and cannot be substituted for one another;
- the lookup disclosure is smaller than the registrar disclosure, and both can be narrowed further by the requester;
- issuer-assigned audience, scope, purpose, and jurisdiction authority all use the one standard verifier path; a conforming Mint token may use that path without a Mint-specific branch;
- Relay returns an unsigned registry response, while Evidence may use the fixed verification lookup as a source when a signed assertion is needed;
- capability discovery derives `consultation.retrieve` and constrained `consultation.search`, not Record Match or Evidence-family support.

## Design observations from the examples

The four acceptance examples suggest a compact core model:

```text
registry contract
  -> source reference and reviewed view
  -> resource and published properties
  -> compiled operation query shape
  -> finite defaulted access profiles with access and disclosure
  -> optional requester property subset
  -> access constraints
  -> semantics, classification, and processing description
  -> deterministic query, response, revision, and audit evidence
```

The examples also freeze these boundaries:

- Registry Manifest projection is later portability tooling, not a runtime input;
- Registry Record context and core fields are native and cannot be removed;
- `fields` is one comma-separated property syntax across list, read, and lookup;
- a live source remains useful for read and lookup but is unversioned, `no-store`, and has no paginated list;
- handling uses `public`, `internal`, `confidential`, and `restricted`, while purpose and row binding remain explicit constraints;
- one explicit default and a finite ordered access profile set is compiled per operation; requester `fields` only narrows the selected profile and caller-derived variants are deferred;
- identification is schema-only and value-free; generated, imported, and manual classification review all bind the complete classification inventory before production compilation;
- only `partial-string` with Relay's fixed `***` marker and `date-precision` to `year` or `year-month` are transform forms; every transform produces a distinct reviewed property;
- Mint and external issuers use one strict Relay JWT access-token profile;
- generated capabilities and a maintained alignment note describe the written draft standards without consuming their legacy OpenAPI or claiming conformance.
