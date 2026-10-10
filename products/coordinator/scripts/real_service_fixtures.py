# SPDX-License-Identifier: Apache-2.0
"""Synthetic authored inputs for the native CLI composition test.

The public product CLIs compile these projects and generate all runtime state,
credentials, source descriptions, and dev sessions. JSON documents are written
as YAML, which the maintained authoring loaders accept, using only the stdlib.
"""

import json
from pathlib import Path
from urllib.parse import urlsplit

SOURCE = "coordinator-source"
AUTHORITY = "https://casework.local.example"
MESSAGING_RESOURCE = "urn:example:messaging"
SCHEDULING_RESOURCE = "urn:example:scheduling"
COORDINATOR_RESOURCE = "urn:example:coordinator"
TENANT_CLAIMS = {"tenant_claim": "tenant-a", "registry_purpose": "review"}
CASEWORK_PRINCIPALS = {
    "staff": "synthetic-casework-staff",
    "supervisor": "synthetic-casework-supervisor",
    "administrator": "synthetic-casework-administrator",
    "producer": "synthetic-casework-producer",
}
REQUEST_FIELDS = ["tenant", "record", "proposed-email", "reason"]
APPLICATION_FIELDS = ["tenant", "email", "notice-allowed", "appointment-allowed"]
BOUNDARY = [{"field": "tenant", "claim": "tenant_claim", "operator": "equals"}]


def _write(path, document):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(document, indent=2) + "\n")


def _permission(entity, operations, fields, *, writable=False, request=False):
    result = {
        "entity": entity,
        "operations": operations,
        "readableFields": fields,
        "rowBoundaries": BOUNDARY,
    }
    if writable:
        result["writableFields"] = fields
    if request:
        result["readableRequestFields"] = ["reason", "review-state"]
    return result


def _profile(name, kind, client, permissions, *, purpose=True):
    profile = {
        "id": name,
        "principalClaim": "sub",
        "actorKind": kind,
        "requesterClients": [client],
        "requiredScopes": ["records:get"],
        "permissions": {"entities": permissions},
    }
    if purpose:
        profile["requiredPurposes"] = ["review"]
    return profile


def _owner_client(name, scopes, profiles=(), claims=None, *, human=False):
    result = {
        "id": name,
        "accessProfiles": list(profiles),
        "scopes": scopes,
        "claims": {} if claims is None else claims,
    }
    if human:
        result["allowHumanFixture"] = True
    return result


def _jwks_port(urls):
    port = urlsplit(urls["jwks"]).port
    if port is None or port == 0:
        raise ValueError("jwks must name the reserved public JWKS listener port")
    return port


def write_breg(root, urls):
    """Write registry.yaml and issuer-owner dev-clients.yaml; return root."""
    root = Path(root)
    applications = {
        "id": "application",
        "primaryDataset": "synthetic-applications",
        "route": "applications",
        "mutationMode": "mutable",
        "classification": "internal",
        "changeControl": {"requiredFor": ["patch"]},
        "fields": [
            {"id": "tenant", "type": "string", "minimumLength": 1, "maximumLength": 64,
             "required": True, "classification": "internal"},
            {"id": "email", "type": "string", "minimumLength": 1, "maximumLength": 254,
             "required": True, "classification": "internal"},
            {"id": "notice-allowed", "type": "boolean", "required": True,
             "classification": "internal"},
            {"id": "appointment-allowed", "type": "boolean", "required": True,
             "classification": "internal"},
        ],
    }
    request = {
        "id": "application-change",
        "primaryDataset": "synthetic-applications",
        "route": "application-changes",
        "mutationMode": "mutable",
        "classification": "internal",
        "fields": [
            {"id": "tenant", "type": "string", "minimumLength": 1, "maximumLength": 64,
             "required": True, "classification": "internal"},
            {"id": "record", "type": "reference", "target": "application",
             "required": True, "classification": "internal"},
            {"id": "proposed-email", "type": "string", "minimumLength": 1,
             "maximumLength": 254, "required": True, "classification": "internal"},
            {"id": "reason", "type": "text", "maximumLength": 1000,
             "required": True, "classification": "internal"},
        ],
        "changeRequest": {
            "effects": [{"target": {"fromField": "record"}, "operation": "patch",
                         "set": {"email": {"fromField": "proposed-email"}}}],
            "review": {"type": "none"},
        },
    }
    profiles = [
        _profile("seeder", "service", "seed-client", [
            _permission("application", ["create", "get", "list"], APPLICATION_FIELDS,
                        writable=True),
            _permission("application-change", ["create", "get", "list", "submit-request"],
                        REQUEST_FIELDS, writable=True, request=True),
        ]),
        _profile("follow-up-reader", "service", "application-reader", [
            _permission("application", ["get"], APPLICATION_FIELDS),
        ]),
        _profile("reviewer", "human", "staff", [
            _permission("application-change", ["get"], REQUEST_FIELDS, request=True),
        ]),
        _profile("reader", "service", "source-reader", [
            _permission("application-change", ["get", "list"], REQUEST_FIELDS, request=True),
        ]),
        _profile("approved-reader", "agent", "task-agent", [
            _permission("application", ["get"], APPLICATION_FIELDS),
        ]),
    ]
    profiles[0]["default"] = True
    profiles[-1]["taskGrant"] = {"sourceIssuer": AUTHORITY}
    # The request compiler requires an explicit complete application ceiling.
    # This seed-service profile is not used by the external-review journey.
    apply = _permission("application-change", ["get", "apply-request"], REQUEST_FIELDS,
                        request=True)
    apply["applyTargets"] = [{"entity": "application", "rowBoundaries": BOUNDARY}]
    profiles.append(_profile("applier", "service", "seed-client", [apply]))
    _write(root / "registry.yaml", {
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {"id": SOURCE, "version": "1", "defaultLanguage": "en",
                     "canonicalBaseIri": "https://synthetic.example.invalid/coordinator"},
        "package": {"sourceRevision": "coordinator-synthetic-1"},
        "entities": [applications, request],
        "accessProfiles": profiles,
    })
    clients = [
        _owner_client("seed-client", ["records:get"], ["seeder", "applier"], TENANT_CLAIMS),
        _owner_client("application-reader", ["records:get"], ["follow-up-reader"], TENANT_CLAIMS),
        _owner_client("source-reader", ["records:get"], ["reader"],
                      {"registry_actor_kind": "service", **TENANT_CLAIMS}),
        _owner_client("task-agent", ["casework:grants:assert"], ["approved-reader"],
                      {"registry_actor_kind": "agent"}),
        _owner_client("status-client", ["casework:grants:status"],
                      claims={"registry_actor_kind": "service"}),
        _owner_client("scheduling-status", ["casework:grants:status"],
                      claims={"registry_actor_kind": "service"}),
        _owner_client("producer", ["casework:reviews:request"],
                      claims={"casework_principal": CASEWORK_PRINCIPALS["producer"]}),
        _owner_client("staff", ["casework:staff", "records:get"], ["reviewer"],
                      {"registry_actor_kind": "human", **TENANT_CLAIMS,
                       "casework_principal": CASEWORK_PRINCIPALS["staff"]}, human=True),
        _owner_client("supervisor", ["casework:supervisor"],
                      claims={"registry_actor_kind": "human",
                              "casework_principal": CASEWORK_PRINCIPALS["supervisor"]}, human=True),
        _owner_client("administrator", ["casework:admin"],
                      claims={"registry_actor_kind": "human",
                              "casework_principal": CASEWORK_PRINCIPALS["administrator"]}, human=True),
        _owner_client("case-system", ["messaging:send"]),
        _owner_client("scheduling-reader", ["scheduling:read"]),
        _owner_client("coordinator-producer", ["coordinator:start", "coordinator:operate"]),
    ]
    # Ordinary observation remains owned by the booking agent, independently
    # of its single Casework bootstrap scope and deferred commitment grant.
    next(client for client in clients if client["id"] == "task-agent")["grants"] = [
        {"audience": SCHEDULING_RESOURCE, "scopes": ["scheduling:read"]}
    ]
    _write(root / "dev-clients.yaml", {
        "apiVersion": "id.registrystack.org/formats/breg/dev-clients/v1alpha1",
        "kind": "BRegDevClients",
        "clients": clients,
        "issuer": {
            "resources": [
                {"audience": MESSAGING_RESOURCE, "scopes": ["messaging:send"]},
                {"audience": SCHEDULING_RESOURCE, "scopes": ["scheduling:read", "scheduling:commit"]},
                {"audience": COORDINATOR_RESOURCE, "scopes": ["coordinator:start", "coordinator:operate"]},
            ],
            "clientResources": {"case-system": MESSAGING_RESOURCE,
                                "scheduling-reader": SCHEDULING_RESOURCE,
                                "coordinator-producer": COORDINATOR_RESOURCE},
            "exchangeClients": ["task-agent"],
            "exchangeIssuers": [{
                "id": "casework", "issuer": AUTHORITY,
                "jwksEndpoint": f"http://host.docker.internal:{_jwks_port(urls)}/oauth2/jwks",
                "mapping": "institutional-grant", "clients": ["task-agent"],
            }],
        },
        "taskGrantStatus": {"casework": {
            "sourceIssuer": AUTHORITY, "baseUrl": urls["casework"], "client": "status-client",
        }},
    })
    # Native dev startup runs the maintained adopter journey gate before it
    # serves the package. Claims match the explicitly registered seed client.
    # bregctl resolves this explicit native marker from its captured session
    # owner and selected client before building the candidate fixture package.
    claims = {"principal": "$localClientSubject", "scopes": ["records:get"],
              "purpose": "review", "actorKind": "service", "requesterClient": "seed-client",
              "directClaims": {"tenant_claim": "tenant-a"}}
    data = {"tenant": "tenant-a", "email": "journey@example.invalid", "notice-allowed": True,
            "appointment-allowed": True}
    _write(root / "tests/journeys.yaml", {
        "apiVersion": "id.registrystack.org/formats/breg/journeys/v1",
        "kind": "BRegJourneys",
        "journeys": [{"id": "synthetic-application", "steps": [
            {"id": "create", "entity": "application", "accessProfile": "seeder", "claims": claims,
             "request": {"type": "create", "data": data},
             "expect": {"outcome": "success", "status": 201}, "capture": "application"},
            {"id": "read", "entity": "application", "accessProfile": "seeder", "claims": claims,
             "request": {"type": "get", "recordCapture": "application"},
             "expect": {"outcome": "success", "status": 200, "fields": data}},
        ]}],
    })
    return root


def write_casework(root, urls, resource, agent_subject):
    """Write policy and explicit borrowed-issuer inputs; parent supplies source.json."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "sources").mkdir(exist_ok=True)
    template = {
        "version": "1", "label": "Read approved synthetic application",
        "eligibleTeams": ["team"], "eligibleProfiles": ["staff"],
        "source": SOURCE, "reviewKinds": ["external-review"],
        "agent": {"issuer": urls["issuer"], "subject": agent_subject},
        "client": "task-agent", "resource": resource, "scopes": ["records:get"],
        "purpose": "review", "bounds": {"type": "breg", "permissions": [{
            "collection": "applications", "operations": ["get"],
        }]},
        "subjects": {"tenant_claim": "tenant"},
    }
    booking_template = {
        **template, "id": "book-appointment", "label": "Deferred synthetic appointment",
        "authorizationMode": "deferred", "lifetimeSeconds": 3600, "resource": SCHEDULING_RESOURCE,
        "scopes": ["scheduling:read", "scheduling:commit"],
        "bounds": {"type": "scheduling", "permissions": [{
            "service": "application-review", "location": "pilot-desk",
            "actions": ["appointment.create"],
        }]},
    }
    _write(root / "casework.yaml", {
        "apiVersion": "id.registrystack.org/formats/casework/project/v1alpha1",
        "kind": "CaseworkProject", "project": {"id": "coordinator-casework", "version": "1"},
        "accessProfiles": [
            {"id": "staff", "principalClaim": "casework_principal", "requiredScopes": ["casework:staff"], "role": "staff"},
            {"id": "supervisor", "principalClaim": "casework_principal", "requiredScopes": ["casework:supervisor"], "role": "supervisor"},
            {"id": "administrator", "principalClaim": "casework_principal", "requiredScopes": ["casework:admin"], "role": "administrator"},
            {"id": "producer", "principalClaim": "casework_principal", "requiredScopes": ["casework:reviews:request"], "role": "requester"},
        ],
        "queues": [{"id": "review", "label": "Synthetic application review"}],
        "sources": [{"id": SOURCE, "adapter": "breg", "description": "sources/source.json",
                     "requests": [{"entity": "application-change", "queue": "review", "projection": ["tenant"]}]}],
        "reviewKinds": [{
            "id": "external-review", "version": "1", "purpose": "approval",
            "contextStrategy": "source", "stages": [{
                "id": "review", "queue": "review", "decidingProfiles": ["staff"], "requiredApprovals": 1,
            }],
            "retention": {"terminalDays": 30, "accountabilityDays": 90},
            "displaySchema": {"type": "object", "additionalProperties": False, "properties": {}},
        }],
        "reviewProducers": [{
            "id": "breg", "profile": "producer", "issuer": urls["issuer"],
            "subject": CASEWORK_PRINCIPALS["producer"], "sourceNamespaces": [SOURCE],
            "kinds": ["external-review"], "recoveryDays": 7,
        }],
        "taskTemplates": [
            {**template, "id": "read-record", "lifetimeSeconds": 60},
            {**template, "id": "read-record-short", "lifetimeSeconds": 5},
            booking_template,
            {**booking_template, "id": "book-appointment-expiry-control",
             "label": "Synthetic expired approval control", "lifetimeSeconds": 5},
        ],
    })
    webhook = root.resolve() / "source-webhook"
    with webhook.open("xb") as output:
        output.write(b"synthetic-coordinator-source-webhook-32-bytes")
    webhook.chmod(0o600)
    _write(root / "dev-clients.yaml", {
        "apiVersion": "id.registrystack.org/formats/casework/dev-clients/v1alpha1",
        "kind": "CaseworkDevClients",
        "clients": [
            {"id": "staff", "accessProfile": "staff", "scopes": ["casework:staff", "records:get"],
             "claims": {"registry_actor_kind": "human", **TENANT_CLAIMS,
                        "casework_principal": CASEWORK_PRINCIPALS["staff"]}},
            {"id": "supervisor", "accessProfile": "supervisor", "scopes": ["casework:supervisor"],
             "claims": {"registry_actor_kind": "human",
                        "casework_principal": CASEWORK_PRINCIPALS["supervisor"]}},
            {"id": "administrator", "accessProfile": "administrator", "scopes": ["casework:admin"],
             "claims": {"registry_actor_kind": "human",
                        "casework_principal": CASEWORK_PRINCIPALS["administrator"]}},
            {"id": "producer", "accessProfile": "producer", "scopes": ["casework:reviews:request"],
             "claims": {"casework_principal": CASEWORK_PRINCIPALS["producer"]}},
        ],
        "directory": [{"team": "team", "queue": "review", "staff": ["staff"], "supervisors": ["supervisor"]}],
        "integrations": {
            "resource": resource,
            "sources": {SOURCE: {
                "baseUrl": urls["breg"], "readerProfile": "reader",
                "tokenEndpoint": urls["issuer"].rstrip("/") + "/oauth2/token",
                "clientAssertionAudience": urls["issuer"], "resource": resource, "scopes": ["records:get"],
                "clientIdRef": "secret:file/service-source-reader-id",
                "clientAssertionKeyRef": "secret:file/service-source-reader-key",
                "webhookSecretRef": "secret:file/source-webhook",
                "eventSource": f"urn:registrystack:registry:{SOURCE}:instance:coordinator-source",
            }},
            "secretFiles": {"source-webhook": str(webhook)},
            "serviceClients": [
                {"id": "source-reader", "scopes": ["records:get"], "claims": TENANT_CLAIMS},
                {"id": "task-agent", "scopes": ["casework:grants:assert"], "taskExchange": True},
                {"id": "status-client", "scopes": ["casework:grants:status"]},
                {"id": "scheduling-status", "scopes": ["casework:grants:status"]},
            ],
            "taskAuthority": {"issuer": AUTHORITY, "jwksPort": _jwks_port(urls),
                              "statusClients": {"status-client": resource, "scheduling-status": SCHEDULING_RESOURCE}},
        },
    })
    return root


def write_messaging(root):
    """Write the synthetic email package used by the real Messaging fixture."""
    root = Path(root)
    _write(root / "messaging.yaml", {
        "apiVersion": "id.registrystack.org/formats/messaging/project/v1alpha1",
        "kind": "MessagingProject", "project": {"id": "coordinator-messaging", "version": "1"},
        "providers": [{"id": "mail-relay", "type": "smtp"}],
        "senderProfiles": [{"id": "transactional", "channel": "email", "provider": "mail-relay",
                            "sender": "notices@example.invalid"}],
        "templates": [{"id": "application-follow-up", "version": "1"},
                      {"id": "appointment-confirmed", "version": "1"}],
        "accessProfiles": [{
            "id": "case-notices", "principalClaim": "sub", "requiredScopes": ["messaging:send"],
            "requesterClients": ["case-system"], "actorKind": "service", "role": "sender",
            "senderProfiles": ["transactional"], "templates": ["application-follow-up", "appointment-confirmed"],
            "requestsPerMinute": 600, "burst": 100,
        }],
    })
    template = root / "templates/application-follow-up/1"
    _write(template / "template.yaml", {"apiVersion": "id.registrystack.org/formats/messaging/template/v1alpha1", "kind": "MessagingTemplate",
        "channel": "email", "locales": ["en"], "parts": ["subject", "text"]})
    _write(template / "schema.json", {
        "type": "object", "additionalProperties": False, "required": ["applicationReference"],
        "properties": {"applicationReference": {"type": "string"}},
    })
    _write(template / "sample.json", {"applicationReference": "00000000-0000-4000-8000-000000000001"})
    (template / "en").mkdir()
    for part, content in {
        "subject": "Application follow-up",
        "text": "Application {{ applicationReference }}",
    }.items():
        with (template / "en" / f"{part}.j2").open("x", encoding="utf-8") as output:
            output.write(content + "\n")
    confirmation = root / "templates/appointment-confirmed/1"
    _write(confirmation / "template.yaml", {"apiVersion": "id.registrystack.org/formats/messaging/template/v1alpha1", "kind": "MessagingTemplate",
        "channel": "email", "locales": ["en"], "parts": ["subject", "text"]})
    fields = ["applicationReference", "appointmentReference", "appointmentStart"]
    _write(confirmation / "schema.json", {"type": "object", "additionalProperties": False,
        "required": fields, "properties": {field: {"type": "string"} for field in fields}})
    _write(confirmation / "sample.json", {"applicationReference": "application-one",
        "appointmentReference": "appointment-one", "appointmentStart": "2026-10-10T10:00:00Z"})
    (confirmation / "en").mkdir()
    (confirmation / "en/subject.j2").write_text("Appointment confirmed\n")
    (confirmation / "en/text.j2").write_text("Appointment {{ appointmentReference }} at {{ appointmentStart }}\n")
    return root


def write_scheduling(root, day):
    """Synthetic exact-time supply, compiled by Scheduling's own authoring CLI."""
    root = Path(root)
    _write(root / "scheduling.yaml", {
        "apiVersion": "id.registrystack.org/formats/scheduling/project/v1alpha1",
        "kind": "SchedulingProject", "project": {"id": "coordinator-scheduling", "version": "1"},
        "services": [{"id": "application-review", "label": "Synthetic application review"}],
        "offerings": [{"id": "application-review", "service": "application-review",
            "label": "Synthetic appointment", "mode": "exact-time", "location": "pilot-desk",
            "because": "Synthetic controlled pilot capacity.",
            "exactTime": {"durationMinutes": 30, "bufferBeforeMinutes": 0, "bufferAfterMinutes": 0,
                "leadTimeMinutes": 1, "horizonDays": 7, "pool": "pilot-resources",
                "startIncrementMinutes": 30, "maximumRecipients": 1},
            "cancellationCutoffMinutes": 1, "duplicateActiveKey": "subject"}],
        "holidaySets": [{"id": "pilot-holidays", "revision": 1, "because": "Synthetic fixture with no holidays."}],
        "openings": [{"id": "pilot-opening", "location": "pilot-desk", "holidaySet": "pilot-holidays", "weekdays": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
            "startTime": "09:00", "endTime": "17:00", "effectiveFrom": day, "effectiveUntil": day,
            "because": "One finite synthetic supply day."}],
        "channels": ["public", "assisted"],
        "holdPolicy": {"ttlMinutes": 5, "maximumPerCaller": 1, "because": "Synthetic fixture bound."},
    })
    _write(root / "records.yaml", {
        "apiVersion": "id.registrystack.org/formats/scheduling/records/v1alpha1",
        "kind": "SchedulingRecords",
        "locations": [{"id": "pilot-desk", "timezone": "UTC"}],
        "pools": [{"id": "pilot-resources", "members": [{"resourceId": "pilot-one", "available": True}]}],
    })
    return root
