# Relay V2 Configuration Examples

Status: Illustrative design probes
Date: 2026-08-09
Product direction: [Relay V2 Product Concept](CONCEPT.md)
Acceptance boundary: [Relay V2 Definition of Done](DEFINITION-OF-DONE.md)

## How to read these examples

These examples test whether one small authoring model can describe materially
different registries. Their named keys and boundaries are the intended Version
1 authoring shape; the generated schema will make their constraints precise.
Relay owns the strict contract. A Registry Manifest projection is later
portability tooling, not a Version one runtime input.

The intended boundaries are firmer than the syntax:

- `RegistryContract` is governed, versioned, compiled at startup, and cannot be overridden by runtime configuration;
- `RelayRuntime` binds deployment-local paths, listeners, token issuers, and audit storage without changing resources, operations, disclosure, or semantics;
- SQLite views and columns are source bindings, while resources and properties are the public model;
- one contract describes one Registry; each resource is a Record type within it;
- every Record has mandatory Registry Core bindings in addition to selectable domain properties;
- `sourceRequired` governs complete source-Record validation, while the public representation schema permits any compiled selectable `domainData` subset;
- external semantic alignment is optional and file-based, pinned, and reviewed;
- every operation chooses a maximum disclosure profile, and the requester may only select fewer properties;
- token issuers assign authority, but they cannot enable an operation Relay did not compile;
- family capabilities are derived from compiled operations, never duplicated in configuration;
- none of these examples enables response signing.

Each short classification entry inherits scheme versions and review provenance
from its contract-level `classifications` block. Each external mapping file is
digest-pinned and must name an explicit exact, close, broad, narrow, or related
relation for every mapped term.

The examples pin written standards as alignment targets. They do not consume
the legacy Digital Registries OpenAPI or claim GovStack conformance. The API
binding uses `pageSize`, `cursor`, direct camelCase equality filters, the
`items`/`pageInfo.nextCursor` list envelope, and Registry Stack problems.

Every successful item has the same non-selectable core shape. For example:

```json
{
  "registryIdentifier": "urn:example:registry:registered-businesses",
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
}
```

`fields=legalName,registrationStatus` narrowed only `domainData`. List responses
place such items in `items`; single reads and resolved lookups place one in
`data`. The semantic-model reference resolves to the generated local vocabulary;
the representation `meta` links the JSON-LD context separately.

Each example shows the governed and runtime documents together for readability. A real project would keep them as separately validated files and package them with synthetic fixtures and generated artifacts.

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
      consultation:
        properties: [enrolmentReference, programmeCode, enrolmentStatus, entitlementCategory, validThrough, serviceOfficeCode]

    operations:
      lookups:
        - id: by-case-and-person
          access:
            scope: registry:social-assistance:lookup
            purpose:
              claim: purpose
              allowed: [benefit-delivery]
            authorityRowBinding:
              claim: service_area
              sourceColumn: service_area_code
          requestBody:
            maximumBytes: 512
            selectors:
              caseReference: {sourceColumn: case_reference, type: string, minimumBytes: 8, maximumBytes: 96}
              personReference: {sourceColumn: person_reference, type: string, minimumBytes: 8, maximumBytes: 96}
          disclosureProfile: consultation

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
    discoveryUrl: https://identity.example.invalid/.well-known/openid-configuration
    audience: relay-social-assistance
    tokenTypes: [at+jwt]
    algorithms: [ES256]
audit:
  sink: /var/lib/relay/audit/social-assistance.jsonl
  integrityKeyRef: secret:file/audit-integrity-key
limits: {requestTimeoutMilliseconds: 1500, concurrentQueries: 16}
quotas: {requestsPerMinute: 120, burst: 20}
```

What this example must prove:

- even a broadly scoped token cannot create list or identifier-read routes;
- lookup scope, trusted purpose, and service-area binding are all required;
- selectors and the hidden `service_area_code` never become public properties;
- selecting `enrolmentStatus,validThrough` returns less than the authorized default without changing authorization;
- a useful local vocabulary, JSON-LD context, JSON Schema, and SHACL starter are generated without any external vocabulary mapping;
- no match, ambiguity, a hidden row, and an invalid source record return the same `404` problem except for trace correlation;
- mandatory Registry Core context remains present and capability discovery derives only constrained `consultation.search`.

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
        sourceColumn: legal_name
        type: string
        sourceRequired: true
        semanticTerm: local:legalName
        classification: {privacy: potentially-personal, institutional: public-by-law}
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

    operations:
      list:
        access: public
        disclosureProfile: public-register
        filters:
          - {name: status, property: registrationStatus, type: controlled-code}
          - {name: jurisdiction, property: registeredJurisdiction, type: controlled-code}
        allowUnfiltered: true
        orderBy: [registrationNumber]
        pagination: {defaultPageSize: 50, maximumPageSize: 200}
      read:
        access: public
        disclosureProfile: public-register

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
- pagination uses `pageSize`, an opaque `cursor`, and `items` with nullable `pageInfo.nextCursor`, while publisher-declared stable ordering prevents arbitrary sorting;
- a requested subset such as `registrationNumber,legalName,registrationStatus` has its own correct ETag and JSON-LD representation;
- the captured snapshot digest and schema fingerprint make responses reproducible and strongly cacheable by revision;
- capability discovery derives `consultation.list` and `consultation.retrieve` and no other family pattern.

## Example 3: civil-event registry

This registry is CRVS-shaped but the runtime remains event-domain neutral. It has no collection-list operation. Authorized registrars may read a known opaque event identifier under one scope and disclosure profile. A verification client may perform only a named exact lookup under a different scope and smaller disclosure profile. It uses an ordinary external issuer for the core journey. Registry Mint may replace that issuer later when it emits the same standard token profile.

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
        properties: [eventReference, eventType, registrationStatus, certificateAvailable]

    operations:
      read:
        access:
          scope: registry:civil-events:read
          purpose:
            claim: purpose
            allowed: [civil-registration-administration]
          authorityRowBinding:
            claim: jurisdiction
            sourceColumn: jurisdiction_code
        disclosureProfile: registrar-record
      lookups:
        - id: verify-registration
          access:
            scope: registry:civil-events:lookup
            purpose:
              claim: purpose
              allowed: [registration-verification]
            authorityRowBinding:
              claim: jurisdiction
              sourceColumn: jurisdiction_code
          requestBody:
            maximumBytes: 384
            selectors:
              registrationNumber: {sourceColumn: registration_number, type: string, minimumBytes: 12, maximumBytes: 96}
              eventType: {sourceColumn: event_type, type: controlled-code, codelist: codelists/civil-event-types.yaml}
          disclosureProfile: verification-result

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
reports for all three coequal acceptance projects. They describe the complete
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
resources[].description
resources[].disclosureProfiles
resources[].disclosureProfiles.*
resources[].disclosureProfiles.*.properties
resources[].disclosureProfiles.*.properties[]
resources[].id
resources[].operations
resources[].operations.list
resources[].operations.list.access
resources[].operations.list.allowUnfiltered
resources[].operations.list.disclosureProfile
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
resources[].operations.lookups[].access
resources[].operations.lookups[].access.authorityRowBinding
resources[].operations.lookups[].access.authorityRowBinding.claim
resources[].operations.lookups[].access.authorityRowBinding.sourceColumn
resources[].operations.lookups[].access.purpose
resources[].operations.lookups[].access.purpose.allowed
resources[].operations.lookups[].access.purpose.allowed[]
resources[].operations.lookups[].access.purpose.claim
resources[].operations.lookups[].access.scope
resources[].operations.lookups[].disclosureProfile
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
resources[].operations.read.access
resources[].operations.read.access.authorityRowBinding
resources[].operations.read.access.authorityRowBinding.claim
resources[].operations.read.access.authorityRowBinding.sourceColumn
resources[].operations.read.access.purpose
resources[].operations.read.access.purpose.allowed
resources[].operations.read.access.purpose.allowed[]
resources[].operations.read.access.purpose.claim
resources[].operations.read.access.scope
resources[].operations.read.disclosureProfile
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
resources[].properties.*.description
resources[].properties.*.label
resources[].properties.*.semanticTerm
resources[].properties.*.sourceColumn
resources[].properties.*.sourceRequired
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
authentication.issuer.tokenTypes
authentication.issuer.tokenTypes[]
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

The three examples suggest a compact core model:

```text
registry contract
  -> source reference and reviewed view
  -> resource and published properties
  -> compiled operations
  -> maximum disclosure profile
  -> optional requester property subset
  -> access constraints
  -> semantics, classification, and processing description
  -> deterministic query, response, revision, and audit evidence
```

The examples also freeze these boundaries:

- Registry Manifest projection is later portability tooling, not a runtime input;
- Registry Core fields are native and cannot be removed;
- `fields` is one comma-separated property syntax across list, read, and lookup;
- a live source remains useful for read and lookup but is unversioned, `no-store`, and has no paginated list;
- handling uses `public`, `internal`, `confidential`, and `restricted`, while purpose and row binding remain explicit constraints;
- one maximum disclosure profile is compiled per operation, so different operations may differ but caller-dependent variants within one operation are deferred;
- Mint and external issuers use one strict Relay JWT access-token profile;
- generated capabilities and a maintained alignment note describe the written draft standards without consuming their legacy OpenAPI or claiming conformance.
