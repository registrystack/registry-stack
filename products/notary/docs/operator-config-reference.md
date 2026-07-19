# Operator configuration reference

Registry Notary configuration describes caller authentication, service policy,
claims, disclosure, issuance, state, and operations. Registry-backed source
access is represented only by one Relay connection plus compiler-produced
consultation expectations. Direct registry connections and adapter runtimes
are not valid Notary configuration.

The complete deserialization-oriented Draft 2020-12 schema is committed at
[`schemas/registry-notary.config.schema.json`](../../../schemas/registry-notary.config.schema.json).
Reproduce it with `just config-schema-generate`, verify drift with `just
config-schema-check`, or print the exact same bytes with `registry-notary
schema`. The schema checks document structure, closed objects, tagged
variants, scalar types, and key paths. JSON Schema deliberately leaves custom
duration, socket-address, CIDR, and consultation-input grammars to the same
runtime parsers that deserialize them, avoiding a narrower duplicate grammar.
`registry-notary doctor` remains authoritative for environment and secret
availability, filesystem and Relay access, deployment gates, and cross-field
runtime validation.

## Bounded batch settings

The batch platform ceiling is 100 items and cannot be raised. Set
`evidence.inline_batch_limit` to lower the service-wide limit, then use
`evidence.claims[].operations.batch_evaluate.max_subjects` to lower it for an
individual claim. Both fields accept only integers from 1 through 100. Notary
rejects zero or values above 100 at configuration load.

For a request, the effective limit is the lowest of 100, the global value, and
the value of every selected claim. A request above that limit is rejected
before quota, idempotency, Relay, source, or retained-state side effects.

`evidence.concurrency.subjects` controls parallel member work and defaults to
16. Relay concurrency is independently bounded by the Relay client and
defaults to 8. Keep the outer `server.request_timeout` at least five seconds
above the 25 second Relay operation deadline for registry-backed evaluation;
the default is 30 seconds. These controls compose with the 1 MiB inbound body,
64 KiB per-Relay-result, and 256 consultation-group limits. They do not replace
the 100-member ceiling.

## OID4VCI 1.0 profile

Enabled OID4VCI configuration requires
`oid4vci.pre_authorized_code.enabled: true`. The only wallet-facing grant is
issuer-initiated pre-authorized code. `oid4vci.nonce.enabled` controls the
transaction-bound proof nonce returned by the token response; it does not mount
a public nonce route. `oid4vci.nonce_endpoint` must be omitted, and
`oid4vci.offer_endpoint` has no route effect in the 1.0 profile.

`oid4vci.pre_authorized_code.tx_code.required` defaults to `true`. An explicit
`false` setting, including the Walt compatibility profile, requires
`pre_authorized_code_ttl_seconds` of no more than 300. The no-PIN offer is
single-use bearer credential material until redemption and must remain covered
by rate limits and disclosure controls.

{/* registry-notary-config-key-paths:start */}
```text
audit
audit.hash_secret_env
audit.max_files
audit.max_size_mb
audit.path
audit.sink
audit.syslog_socket_path
auth
auth.access_token_signing
auth.access_token_signing.access_token_ttl_seconds
auth.access_token_signing.allowed_algorithms
auth.access_token_signing.allowed_algorithms[]
auth.access_token_signing.audiences
auth.access_token_signing.audiences[]
auth.access_token_signing.enabled
auth.access_token_signing.issuer
auth.access_token_signing.signing_key_id
auth.access_token_signing.token_typ
auth.access_token_signing.verification_key_ids
auth.access_token_signing.verification_key_ids[]
auth.api_keys
auth.api_keys[]
auth.api_keys[].authorization_details
auth.api_keys[].authorization_details.access_mode
auth.api_keys[].authorization_details.actions
auth.api_keys[].authorization_details.actions[]
auth.api_keys[].authorization_details.assisted_access_context
auth.api_keys[].authorization_details.assisted_access_context.channel
auth.api_keys[].authorization_details.assurance_level
auth.api_keys[].authorization_details.claims
auth.api_keys[].authorization_details.claims[]
auth.api_keys[].authorization_details.claims[].id
auth.api_keys[].authorization_details.claims[].version
auth.api_keys[].authorization_details.consent_ref
auth.api_keys[].authorization_details.disclosure
auth.api_keys[].authorization_details.format
auth.api_keys[].authorization_details.jurisdiction
auth.api_keys[].authorization_details.legal_basis_ref
auth.api_keys[].authorization_details.locations
auth.api_keys[].authorization_details.locations[]
auth.api_keys[].authorization_details.purpose
auth.api_keys[].authorization_details.relationship
auth.api_keys[].authorization_details.relationship.proof_claim
auth.api_keys[].authorization_details.relationship.relationship_type
auth.api_keys[].authorization_details.schema_version
auth.api_keys[].authorization_details.subject
auth.api_keys[].authorization_details.subject.binding_claim
auth.api_keys[].authorization_details.subject.id_type
auth.api_keys[].authorization_details.target
auth.api_keys[].authorization_details.target.id
auth.api_keys[].authorization_details.target.id_type
auth.api_keys[].authorization_details.type
auth.api_keys[].fingerprint
auth.api_keys[].fingerprint.name
auth.api_keys[].fingerprint.path
auth.api_keys[].fingerprint.provider
auth.api_keys[].id
auth.api_keys[].scopes
auth.api_keys[].scopes[]
auth.bearer_tokens
auth.bearer_tokens[]
auth.bearer_tokens[].authorization_details
auth.bearer_tokens[].authorization_details.access_mode
auth.bearer_tokens[].authorization_details.actions
auth.bearer_tokens[].authorization_details.actions[]
auth.bearer_tokens[].authorization_details.assisted_access_context
auth.bearer_tokens[].authorization_details.assisted_access_context.channel
auth.bearer_tokens[].authorization_details.assurance_level
auth.bearer_tokens[].authorization_details.claims
auth.bearer_tokens[].authorization_details.claims[]
auth.bearer_tokens[].authorization_details.claims[].id
auth.bearer_tokens[].authorization_details.claims[].version
auth.bearer_tokens[].authorization_details.consent_ref
auth.bearer_tokens[].authorization_details.disclosure
auth.bearer_tokens[].authorization_details.format
auth.bearer_tokens[].authorization_details.jurisdiction
auth.bearer_tokens[].authorization_details.legal_basis_ref
auth.bearer_tokens[].authorization_details.locations
auth.bearer_tokens[].authorization_details.locations[]
auth.bearer_tokens[].authorization_details.purpose
auth.bearer_tokens[].authorization_details.relationship
auth.bearer_tokens[].authorization_details.relationship.proof_claim
auth.bearer_tokens[].authorization_details.relationship.relationship_type
auth.bearer_tokens[].authorization_details.schema_version
auth.bearer_tokens[].authorization_details.subject
auth.bearer_tokens[].authorization_details.subject.binding_claim
auth.bearer_tokens[].authorization_details.subject.id_type
auth.bearer_tokens[].authorization_details.target
auth.bearer_tokens[].authorization_details.target.id
auth.bearer_tokens[].authorization_details.target.id_type
auth.bearer_tokens[].authorization_details.type
auth.bearer_tokens[].fingerprint
auth.bearer_tokens[].fingerprint.name
auth.bearer_tokens[].fingerprint.path
auth.bearer_tokens[].fingerprint.provider
auth.bearer_tokens[].id
auth.bearer_tokens[].scopes
auth.bearer_tokens[].scopes[]
auth.oidc
auth.oidc.allow_insecure_localhost
auth.oidc.allowed_algorithms
auth.oidc.allowed_algorithms[]
auth.oidc.allowed_clients
auth.oidc.allowed_clients[]
auth.oidc.allowed_token_types
auth.oidc.allowed_token_types[]
auth.oidc.audiences
auth.oidc.audiences[]
auth.oidc.issuer
auth.oidc.jwks_url
auth.oidc.leeway
auth.oidc.principal_claim
auth.oidc.scope_claim
auth.oidc.scope_map
auth.oidc.scope_map.*
auth.oidc.scope_map.*[]
auth.oidc.scope_separator
auth.oidc.userinfo_endpoint
auth.oidc.userinfo_issuers
auth.oidc.userinfo_issuers[]
cel
cel.allow_regex
cel.eval_timeout_ms
cel.max_binding_json_bytes
cel.max_expression_bytes
cel.max_list_items
cel.max_object_depth
cel.max_object_keys
cel.max_result_json_bytes
cel.max_string_bytes
cel.mode
cel.worker_count
cel.worker_memory_bytes
cel.worker_stderr_bytes
config_trust
config_trust.antirollback_state_path
config_trust.break_glass_override_path
config_trust.bundle_path
config_trust.trust_anchor_path
credential_status
credential_status.base_url
credential_status.enabled
credential_status.retention_seconds
deployment
deployment.evidence
deployment.evidence.audit_ack_cursor_path
deployment.evidence.audit_ack_max_age_secs
deployment.evidence.audit_offhost_shipping
deployment.evidence.signer_custody_approved
deployment.multi_instance
deployment.profile
deployment.waivers
deployment.waivers[]
deployment.waivers[].expires
deployment.waivers[].finding
deployment.waivers[].reason
evidence
evidence.allowed_purposes
evidence.allowed_purposes[]
evidence.api_base_url
evidence.api_version
evidence.claims
evidence.claims[]
evidence.claims[].cccev
evidence.claims[].cccev.evidence_type
evidence.claims[].cccev.evidence_type_iri
evidence.claims[].cccev.requirement_type
evidence.claims[].credential_profiles
evidence.claims[].credential_profiles[]
evidence.claims[].depends_on
evidence.claims[].depends_on[]
evidence.claims[].disclosure
evidence.claims[].disclosure.allowed
evidence.claims[].disclosure.allowed[]
evidence.claims[].disclosure.default
evidence.claims[].disclosure.downgrade
evidence.claims[].evidence_mode
evidence.claims[].evidence_mode.consultations
evidence.claims[].evidence_mode.consultations.*
evidence.claims[].evidence_mode.consultations.*.inputs
evidence.claims[].evidence_mode.consultations.*.inputs.*
evidence.claims[].evidence_mode.consultations.*.outputs
evidence.claims[].evidence_mode.consultations.*.outputs.*
evidence.claims[].evidence_mode.consultations.*.outputs.*.max_bytes
evidence.claims[].evidence_mode.consultations.*.outputs.*.maximum
evidence.claims[].evidence_mode.consultations.*.outputs.*.minimum
evidence.claims[].evidence_mode.consultations.*.outputs.*.nullable
evidence.claims[].evidence_mode.consultations.*.outputs.*.type
evidence.claims[].evidence_mode.consultations.*.profile
evidence.claims[].evidence_mode.consultations.*.profile.contract_hash
evidence.claims[].evidence_mode.consultations.*.profile.id
evidence.claims[].evidence_mode.type
evidence.claims[].formats
evidence.claims[].formats[]
evidence.claims[].id
evidence.claims[].inputs
evidence.claims[].inputs[]
evidence.claims[].inputs[].name
evidence.claims[].inputs[].type
evidence.claims[].oots
evidence.claims[].oots.authentication_level_of_assurance
evidence.claims[].oots.enabled
evidence.claims[].oots.evidence_type_classification
evidence.claims[].oots.evidence_type_list
evidence.claims[].oots.languages
evidence.claims[].oots.languages[]
evidence.claims[].oots.reference_framework
evidence.claims[].oots.requirement
evidence.claims[].operations
evidence.claims[].operations.batch_evaluate
evidence.claims[].operations.batch_evaluate.enabled
evidence.claims[].operations.batch_evaluate.max_subjects
evidence.claims[].operations.evaluate
evidence.claims[].operations.evaluate.enabled
evidence.claims[].purpose
evidence.claims[].required_scopes
evidence.claims[].required_scopes[]
evidence.claims[].rule
evidence.claims[].rule.bindings
evidence.claims[].rule.bindings.claims
evidence.claims[].rule.bindings.claims.*
evidence.claims[].rule.bindings.claims.*.binding_type
evidence.claims[].rule.bindings.claims.*.claim
evidence.claims[].rule.bindings.vars
evidence.claims[].rule.consultation
evidence.claims[].rule.expression
evidence.claims[].rule.output
evidence.claims[].rule.type
evidence.claims[].semantics
evidence.claims[].semantics.concept
evidence.claims[].semantics.derived_from
evidence.claims[].semantics.derived_from[]
evidence.claims[].semantics.predicate
evidence.claims[].semantics.property
evidence.claims[].semantics.value_mapping
evidence.claims[].semantics.vocabulary
evidence.claims[].subject_type
evidence.claims[].title
evidence.claims[].value
evidence.claims[].value.nullable
evidence.claims[].value.type
evidence.claims[].value.unit
evidence.claims[].version
evidence.claims_url
evidence.concurrency
evidence.concurrency.subjects
evidence.credential_profiles
evidence.credential_profiles.*
evidence.credential_profiles.*.allowed_claims
evidence.credential_profiles.*.allowed_claims[]
evidence.credential_profiles.*.disclosure
evidence.credential_profiles.*.disclosure.allowed
evidence.credential_profiles.*.disclosure.allowed[]
evidence.credential_profiles.*.format
evidence.credential_profiles.*.holder_binding
evidence.credential_profiles.*.holder_binding.allowed_did_methods
evidence.credential_profiles.*.holder_binding.allowed_did_methods[]
evidence.credential_profiles.*.holder_binding.mode
evidence.credential_profiles.*.holder_binding.proof_of_possession
evidence.credential_profiles.*.issuer
evidence.credential_profiles.*.signing_key
evidence.credential_profiles.*.validity_seconds
evidence.credential_profiles.*.vct
evidence.enabled
evidence.formats_url
evidence.inline_batch_limit
evidence.machine_quota
evidence.machine_quota.enabled
evidence.machine_quota.subjects_per_minute
evidence.max_credential_validity_seconds
evidence.relay
evidence.relay.allow_insecure_localhost
evidence.relay.allowed_private_cidrs
evidence.relay.allowed_private_cidrs[]
evidence.relay.base_url
evidence.relay.max_in_flight
evidence.relay.token_file
evidence.relay.workload_client_id
evidence.service_id
evidence.signing_keys
evidence.signing_keys.*
evidence.signing_keys.*.alg
evidence.signing_keys.*.key_id_hex
evidence.signing_keys.*.key_label
evidence.signing_keys.*.kid
evidence.signing_keys.*.module_path
evidence.signing_keys.*.password_env
evidence.signing_keys.*.path
evidence.signing_keys.*.pin_env
evidence.signing_keys.*.private_jwk_env
evidence.signing_keys.*.provider
evidence.signing_keys.*.public_jwk_env
evidence.signing_keys.*.publish_until_unix_seconds
evidence.signing_keys.*.status
evidence.signing_keys.*.token_label
evidence.variables
evidence.variables.*
evidence.variables.*.from
evidence.variables.*.type
federation
federation.clock_leeway_seconds
federation.emergency_denylist
federation.emergency_denylist.kids
federation.emergency_denylist.kids[]
federation.emergency_denylist.node_ids
federation.emergency_denylist.node_ids[]
federation.enabled
federation.evaluation_profiles
federation.evaluation_profiles[]
federation.evaluation_profiles[].assurance_level
federation.evaluation_profiles[].claim_id
federation.evaluation_profiles[].consent_ref
federation.evaluation_profiles[].disclosure
federation.evaluation_profiles[].id
federation.evaluation_profiles[].jurisdiction
federation.evaluation_profiles[].legal_basis_ref
federation.evaluation_profiles[].max_claim_result_age_seconds
federation.evaluation_profiles[].ruleset
federation.evaluation_profiles[].subject_id_type
federation.federation_api
federation.inbound_body_limit_bytes
federation.issuer
federation.jwks_uri
federation.max_request_lifetime_seconds
federation.node_id
federation.pairwise_subject_hash
federation.pairwise_subject_hash.secret_env
federation.peers
federation.peers[]
federation.peers[].allow_insecure_localhost
federation.peers[].allow_insecure_private_network
federation.peers[].allowed_profiles
federation.peers[].allowed_profiles[]
federation.peers[].allowed_protocol_versions
federation.peers[].allowed_protocol_versions[]
federation.peers[].allowed_purposes
federation.peers[].allowed_purposes[]
federation.peers[].evaluation_scopes
federation.peers[].evaluation_scopes[]
federation.peers[].issuer
federation.peers[].jwks_uri
federation.peers[].node_id
federation.response_shaping
federation.response_shaping.minimum_denial_latency_ms
federation.signing
federation.signing.signing_key
federation.supported_protocol_versions
federation.supported_protocol_versions[]
instance
instance.environment
instance.id
instance.jurisdiction
instance.owner
instance.public_base_url
oid4vci
oid4vci.accepted_token_audiences
oid4vci.accepted_token_audiences[]
oid4vci.authorization
oid4vci.authorization.require_pkce_method
oid4vci.authorization_servers
oid4vci.authorization_servers[]
oid4vci.credential_configurations
oid4vci.credential_configurations.*
oid4vci.credential_configurations.*.claim_id
oid4vci.credential_configurations.*.claims
oid4vci.credential_configurations.*.claims[]
oid4vci.credential_configurations.*.claims[].display_name
oid4vci.credential_configurations.*.claims[].id
oid4vci.credential_configurations.*.claims[].output_path
oid4vci.credential_configurations.*.claims[].output_path[]
oid4vci.credential_configurations.*.claims[].sd
oid4vci.credential_configurations.*.credential_profile
oid4vci.credential_configurations.*.cryptographic_binding_methods_supported
oid4vci.credential_configurations.*.cryptographic_binding_methods_supported[]
oid4vci.credential_configurations.*.display
oid4vci.credential_configurations.*.display.background_color
oid4vci.credential_configurations.*.display.background_image
oid4vci.credential_configurations.*.display.background_image.alt_text
oid4vci.credential_configurations.*.display.background_image.uri
oid4vci.credential_configurations.*.display.background_image.url
oid4vci.credential_configurations.*.display.description
oid4vci.credential_configurations.*.display.locale
oid4vci.credential_configurations.*.display.logo
oid4vci.credential_configurations.*.display.logo.alt_text
oid4vci.credential_configurations.*.display.logo.uri
oid4vci.credential_configurations.*.display.logo.url
oid4vci.credential_configurations.*.display.secondary_image
oid4vci.credential_configurations.*.display.secondary_image.alt_text
oid4vci.credential_configurations.*.display.secondary_image.uri
oid4vci.credential_configurations.*.display.secondary_image.url
oid4vci.credential_configurations.*.display.text_color
oid4vci.credential_configurations.*.display_name
oid4vci.credential_configurations.*.format
oid4vci.credential_configurations.*.proof_signing_alg_values_supported
oid4vci.credential_configurations.*.proof_signing_alg_values_supported[]
oid4vci.credential_configurations.*.scope
oid4vci.credential_configurations.*.vct
oid4vci.credential_endpoint
oid4vci.credential_issuer
oid4vci.display
oid4vci.display[]
oid4vci.display[].locale
oid4vci.display[].logo
oid4vci.display[].logo.alt_text
oid4vci.display[].logo.uri
oid4vci.display[].logo.url
oid4vci.display[].name
oid4vci.enabled
oid4vci.nonce
oid4vci.nonce.enabled
oid4vci.nonce.ttl_seconds
oid4vci.nonce_endpoint
oid4vci.offer_endpoint
oid4vci.pre_authorized_code
oid4vci.pre_authorized_code.enabled
oid4vci.pre_authorized_code.esignet
oid4vci.pre_authorized_code.esignet.allow_insecure_localhost
oid4vci.pre_authorized_code.esignet.authorize_url
oid4vci.pre_authorized_code.esignet.client_id
oid4vci.pre_authorized_code.esignet.client_signing_key_id
oid4vci.pre_authorized_code.esignet.issuer
oid4vci.pre_authorized_code.esignet.jwks_uri
oid4vci.pre_authorized_code.esignet.login_state_ttl_seconds
oid4vci.pre_authorized_code.esignet.redirect_uri
oid4vci.pre_authorized_code.esignet.scopes
oid4vci.pre_authorized_code.esignet.scopes[]
oid4vci.pre_authorized_code.esignet.token_url
oid4vci.pre_authorized_code.esignet.userinfo_url
oid4vci.pre_authorized_code.pre_authorized_code_ttl_seconds
oid4vci.pre_authorized_code.tx_code
oid4vci.pre_authorized_code.tx_code.input_mode
oid4vci.pre_authorized_code.tx_code.length
oid4vci.pre_authorized_code.tx_code.required
oid4vci.proof
oid4vci.proof.max_age_seconds
oid4vci.proof.max_clock_skew_seconds
server
server.admin_listener
server.admin_listener.bind
server.admin_listener.mode
server.bind
server.cors
server.cors.allowed_origins
server.cors.allowed_origins[]
server.http1_header_read_timeout
server.max_connections
server.openapi_requires_auth
server.request_body_timeout
server.request_timeout
server.trusted_proxy_ips
server.trusted_proxy_ips[]
state
state.postgresql
state.postgresql.connect_timeout_ms
state.postgresql.max_connections
state.postgresql.operation_timeout_ms
state.postgresql.root_certificate_path
state.postgresql.sensitive_state_key_env
state.postgresql.url_env
state.storage
subject_access
subject_access.allowed_claims
subject_access.allowed_claims[]
subject_access.allowed_disclosures
subject_access.allowed_disclosures[]
subject_access.allowed_formats
subject_access.allowed_formats[]
subject_access.allowed_operations
subject_access.allowed_operations.batch_evaluate
subject_access.allowed_operations.evaluate
subject_access.allowed_operations.issue_credential
subject_access.allowed_operations.render
subject_access.allowed_purposes
subject_access.allowed_purposes[]
subject_access.allowed_wallet_origins
subject_access.allowed_wallet_origins[]
subject_access.citizen_clients
subject_access.citizen_clients.allowed_audiences
subject_access.citizen_clients.allowed_audiences[]
subject_access.citizen_clients.allowed_client_ids
subject_access.citizen_clients.allowed_client_ids[]
subject_access.credential_profiles
subject_access.credential_profiles[]
subject_access.delegation
subject_access.delegation.allowed_relationships
subject_access.delegation.allowed_relationships[]
subject_access.delegation.allowed_relationships[].allowed_claims
subject_access.delegation.allowed_relationships[].allowed_claims[]
subject_access.delegation.allowed_relationships[].allowed_disclosures
subject_access.delegation.allowed_relationships[].allowed_disclosures[]
subject_access.delegation.allowed_relationships[].allowed_formats
subject_access.delegation.allowed_relationships[].allowed_formats[]
subject_access.delegation.allowed_relationships[].allowed_purposes
subject_access.delegation.allowed_relationships[].allowed_purposes[]
subject_access.delegation.allowed_relationships[].credential_profiles
subject_access.delegation.allowed_relationships[].credential_profiles[]
subject_access.delegation.allowed_relationships[].proof_claim
subject_access.delegation.allowed_relationships[].relationship_type
subject_access.delegation.allowed_relationships[].target_id_type
subject_access.delegation.enabled
subject_access.enabled
subject_access.rate_limits
subject_access.rate_limits.credential_issuance_per_principal_per_hour
subject_access.rate_limits.invalid_token_per_client_address_per_minute
subject_access.rate_limits.per_holder_per_hour
subject_access.rate_limits.per_principal_per_minute
subject_access.rate_limits.subject_mismatch_per_principal_per_hour
subject_access.rate_limits.tx_code_attempts_per_code_per_minute
subject_access.required_scopes
subject_access.required_scopes[]
subject_access.scope_policy
subject_access.subject_binding
subject_access.subject_binding.allow_sub_as_civil_id
subject_access.subject_binding.claim_source
subject_access.subject_binding.id_type
subject_access.subject_binding.normalize
subject_access.subject_binding.request_field
subject_access.subject_binding.token_claim
subject_access.token_policy
subject_access.token_policy.assurance_claim_source
subject_access.token_policy.max_access_token_lifetime_seconds
subject_access.token_policy.max_auth_age_seconds
subject_access.token_policy.max_clock_leeway_seconds
subject_access.token_policy.max_credential_validity_seconds
subject_access.token_policy.max_evaluation_age_seconds
subject_access.token_policy.required_acr_values
subject_access.token_policy.required_acr_values[]
```
{/* registry-notary-config-key-paths:end */}

## Top-level areas

| Area | Responsibility |
| --- | --- |
| `server` | Public and optional dedicated admin listeners and HTTP bounds |
| `auth` | Configured API-key, static bearer, and OIDC authentication and scope mapping |
| `deployment` | Deployment profile and assurance evidence |
| `audit` | Notary-owned redacted audit sink and keyed chain |
| `config_trust` | Product bundle verification and anti-rollback state |
| `evidence` | Service identity, Relay connection, claims, signing keys, and credential profiles |
| `cel` | Isolated claim-policy worker limits |
| `state` | PostgreSQL or explicit local in-memory correctness state |
| `credential_status` | Optional credential lifecycle state |
| `subject_access` | OIDC-bound direct and delegated subject-access policy |
| `oid4vci` | Wallet-facing issuance facade |
| `federation` | Static-peer delegated evaluation |

Unknown configuration fields are rejected except forward-compatible metadata
inside `authorization_details`, as described under Authentication and
delegation. Use the generated configuration from Registry Stack project
authoring as the source of truth rather than maintaining a second handwritten
example.

## Environment expansion

Notary expands `${VAR}` expressions before YAML parsing. `${VAR}` requires
`VAR` to be set to a non-empty value. `${VAR:-fallback}` uses `fallback` when
`VAR` is unset or empty, including `${VAR:-}` for an explicit empty result.
`${VAR:?message}` fails with `message` when `VAR` is unset or empty.
Whitespace-only values are non-empty. Diagnostics name the variable or use the
supplied message; they never include the variable value.

## Evidence modes

Every claim uses one sealed evidence mode:

- `registry_backed` names a compiler-produced consultation expectation. It
  requires the project's Relay connection.
- `self_attested` performs no Relay or source I/O and may depend only on other
  source-free claims.

A configuration may contain claims for the topology generated by the project.
A Notary-only project must not configure Relay. A combined project has exactly
one logical Relay connection. Source-free claims are evaluation-only. Every
credential-capable claim in `subject_access.allowed_claims`, every claim in a
credential profile, and every OID4VCI projection must resolve through mutually
consistent credential-profile bindings to `registry_backed` claims.
Configuration load rejects mixed or source-free credential surfaces.

## Relay connection

The Relay connection contains the Relay origin and an owner-readable workload
token file. Exact private CIDRs may be admitted when required. Notary does not
configure source origins, OAuth token endpoints, source credentials, protocol
keys, source request limits, or adapter scripts.

Notary validates each expected consultation's identity, purpose, input roles
and schemas, outcome union, output schemas, provenance, runtime requirements,
and `contract_hash` before serving. Startup and readiness fail closed on a
semantic or hash mismatch. Every execute request carries the exact hash.

Rotate the workload credential by atomically replacing its regular,
owner-readable file. Do not rewrite it in place. Diagnostics must report only
bounded status and never the token, its path, selectors, Relay response body,
or source details.

## Claims and disclosure

Claims may directly reference a consultation output or use CEL over allowed
consultation outcome, outputs, and bounded request variables. Direct output
claims become null on `no_match` in the evaluation view and are not issuable
as null credential claims. Ambiguity or failure evaluates no claims from that
consultation.

Disclosure remains a Notary decision. Credential profiles own ordered claim
membership, issuance format, holder binding, validity, and allowed disclosure.
Relay outputs are never credentials or public claims by themselves.

`formats` is optional for each claim. When omitted, Notary uses
`application/vnd.registry-notary.claim-result+json`, the canonical evaluation
response format. An explicit list must include that format and may otherwise
contain only `application/ld+json; profile="cccev"`. Do not set `formats: []`,
an unknown format, or `application/dc+sd-jwt`: all are invalid configuration.
SD-JWT VC belongs in a credential profile's issuance `format`, not a claim's
evaluation response-format list. The same separation applies to
`subject_access.allowed_formats`: list evaluation renderers there and select
the credential output through `credential_profiles`.

## Authentication and delegation

Authentication has no mode selector. The configured methods define the
accepted callers. API keys may be configured alongside OIDC so service callers
and citizen or wallet flows can use one Notary instance. Each request must
present exactly one credential type; presenting an API key and a bearer token
together fails before either credential is authenticated. Static bearer tokens
cannot be configured alongside OIDC because both use the `Authorization:
Bearer` transport.

`authorization_details` is a versioned interoperability object shared by
static configuration and token or OIDC JSON. Known authorization fields,
including subject, target, relationship, assisted access, and exact claim
references, are enforced by the authorization checks. Future metadata fields
at those object levels are accepted and ignored so an additive producer does
not break an older Notary. Unrecognized metadata never grants authority.
`ClaimRef` objects remain closed because an extra field there could conceal a
misspelled claim or version selector.

Citizen and wallet flows use the self-attestation subject-binding policy.
Delegated access must bind requester, target, relationship, purpose, and
authorization details before evaluation. A delegated Relay proof consultation
proves only its exact compiled edge and does not grant scopes.

Credential issuance additionally requires the stored evaluation to contain one
exact compiler pin for every registry-backed claim in each selected root's
dependency closure, plus one normalized execution record for every unique Relay
consultation ULID. Claim/version, Relay profile and contract hash, canonical
purpose, ULID, acquisition time, and each root's public unique-consultation
count must match the active configuration and evaluation. A deterministic
SHA-256 execution binding cross-binds each claim pin, execution, and exact claim
provenance. Missing, duplicated,
extra, legacy, or modified provenance is denied before signer, credential-id,
or status side effects. Direct issuance checks before holder-proof replay
mutation. OID4VCI rejects a source-free credential configuration, creates and
evaluates the registry transaction before rendering an offer, consumes the
transaction-bound proof nonce at the credential endpoint, and checks stored
provenance before signer access. Delegated self-attestation is
evaluation-only; delegated relationship and claim credential-profile bindings
are rejected at configuration load.

Notary persists these private Relay identifiers only when every selected root
shares a mutually validated credential profile. Registry-backed
evaluation-only claims store no private issuance provenance. The execution
binding detects partial mutation, not a store operator who can rewrite all
fields and recompute an unkeyed digest; database and audit controls remain the
authenticity boundary.

## State and operations

Use the typed Notary-owned PostgreSQL state schema for multi-instance or
production deployments. The schema holds replay, nonce, evaluation,
idempotency, credential-status, quota, and preauthorization state. Explicit
in-memory state is limited to local, single-instance development. Keep Notary
and Relay state, audit keys, and chains separate. Protect admin routes with
their dedicated listener and required operator scopes.

## Validation workflow

Run checks in increasing order of network effect:

```sh
registry-notary explain-config --config generated-notary.yaml
registry-notary doctor --config generated-notary.yaml
registry-notary --config generated-notary.yaml state doctor
registry-notary doctor --config generated-notary.yaml --live
```

The live check contacts only the approved Relay dependency. Run a controlled
project journey separately to exercise source acquisition, claim evaluation,
disclosure, and issuance. Keep all credentials in process environments or
mounted secret files and out of command lines and retained logs.

## Rollout

Activate Relay and Notary as one compatible project generation. For blue-green
rollout, stage a complete generation without traffic, verify readiness, then
switch. For a smaller deployment, drain traffic, restart both products,
verify readiness, and resume. Never serve a mixed semantic contract.

The complete generated schema, runtime diagnostics, and OpenAPI are
authoritative for exact field syntax.
