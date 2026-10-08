#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Generate the caseworkctl JSON report schemas.

A report that carries part of the authored project, such as `explain` and
`check`, refers to the project schema's definitions of it rather than
copying them.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


API_VERSION = "registry.registrystack.org/caseworkctl/v1alpha3"
OUTPUT = Path(__file__).resolve().parents[1] / "contracts" / "cli"
SCHEMA_ID_BASE = "https://id.registrystack.org/schemas/"
# The project schema, relative to a report schema's identifier.
PROJECT_SCHEMA = "../project/project.v1alpha1.schema.json"
# The largest integer JSON carries exactly: the stated maximum of a count,
# version, or order whose Rust type is wider.
JSON_INTEGER_MAXIMUM = 2**53 - 1

STRING = {"type": "string"}
BOOLEAN = {"type": "boolean"}
OBJECT = {"type": "object"}
ARRAY = {"type": "array"}
STRING_ARRAY = {"type": "array", "items": {"type": "string"}}
OBJECT_ARRAY = {"type": "array", "items": {"type": "object"}}
DIAGNOSTICS = {"$ref": "#/$defs/diagnostics"}
WARNINGS = {"$ref": "#/$defs/warnings"}
COUNT = {"type": "integer", "minimum": 0, "maximum": JSON_INTEGER_MAXIMUM}
TIMESTAMP = {"type": "string", "format": "date-time"}
NULLABLE_TIMESTAMP = {"type": ["string", "null"], "format": "date-time"}
UUID = {"type": "string", "format": "uuid"}
# A check reads the project file, the runtime configuration it is given, the
# project's dev-clients.yaml, its retained development session state, at most
# MAXIMUM_SOURCES (64) source descriptions, and at most
# MAXIMUM_DIRECTORY_FILES (1024) YAML files from each of the three offline
# directories.
FILES_CHECKED = {"type": "integer", "minimum": 1, "maximum": 1 + 1 + 1 + 1 + 64 + 3 * 1024}


def passthrough(reason: str) -> dict:
    """An object carried in another product's grammar, which this report does not describe."""
    return {"type": "object", "x-registry-passthrough": reason}


DIGEST = {"$ref": "#/$defs/Digest"}
LOCAL_ID = {"$ref": "#/$defs/LocalId"}
URL = {"$ref": "#/$defs/Url"}
NULLABLE_STRING = {"type": ["string", "null"]}
ROLE_MODE = {"enum": ["single", "split"]}
PLAN_KIND = {"enum": ["initial", "successor"]}
SCHEMA_VERSION = {"type": "integer", "minimum": 1, "maximum": JSON_INTEGER_MAXIMUM}
NULLABLE_SCHEMA_VERSION = {"type": ["integer", "null"], "minimum": 1, "maximum": JSON_INTEGER_MAXIMUM}
SINGLE_ROLE_STATEMENT = {"type": ["string", "null"]}
ACTIVATION = {"$ref": "#/$defs/activation"}
NULLABLE_ACTIVATION = {"oneOf": [ACTIVATION, {"type": "null"}]}
ACTIVATION_DEFS = {
    "activation": {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "activationId",
            "applyOrder",
            "packageDigest",
            "predecessorPackageDigest",
            "databaseId",
            "planKind",
            "appliedAt",
            "operatorReferenceHash",
            "backupReferences",
            "roleMode",
        ],
        "properties": {
            "activationId": STRING,
            "applyOrder": {"type": "integer", "minimum": 1, "maximum": JSON_INTEGER_MAXIMUM},
            "packageDigest": DIGEST,
            "predecessorPackageDigest": {"oneOf": [DIGEST, {"type": "null"}]},
            "databaseId": STRING,
            "planKind": PLAN_KIND,
            "appliedAt": STRING,
            "operatorReferenceHash": NULLABLE_STRING,
            "backupReferences": {"type": "array", "maxItems": 16, "items": STRING},
            "roleMode": ROLE_MODE,
        },
    },
    "refusal": {
        "type": "object",
        "additionalProperties": False,
        "required": ["code", "path", "message"],
        "properties": {"code": STRING, "path": STRING, "message": STRING},
    },
}
# Pinned work a candidate package would hide or orphan. `reason` says which
# of the other members are present; the counts carry no subject data.
STRANDED_WORK = {
    "type": "object",
    "additionalProperties": False,
    "required": ["reason", "reviews"],
    "properties": {
        "reason": {
            "enum": [
                "queue-removed",
                "profile-removed",
                "review-kind-changed",
                "source-removed",
                "context-field-not-displayed",
                "displayed-field-not-projected",
            ]
        },
        "queue": STRING,
        "profile": STRING,
        "reviewKind": STRING,
        "version": STRING,
        "source": STRING,
        "entity": STRING,
        "field": STRING,
        "reviews": COUNT,
        "workItems": COUNT,
    },
}
EFFECTS_DEFS = {
    "effects": {
        "type": "object",
        "additionalProperties": False,
        "required": ["pinnedWork", "sourceGenerations", "taskTemplates"],
        "properties": {
            "pinnedWork": {
                "type": "object",
                "additionalProperties": False,
                "required": ["verdict", "stranded"],
                "properties": {
                    "verdict": {"enum": ["clear", "acknowledged", "refused"]},
                    "stranded": {"type": "array", "items": {"$ref": "#/$defs/strandedWork"}},
                },
            },
            "sourceGenerations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["sourceId", "change"],
                    "properties": {
                        "sourceId": STRING,
                        "change": {"enum": ["registered", "unchanged", "changed"]},
                    },
                },
            },
            "taskTemplates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["templateId", "templateVersion", "change"],
                    "properties": {
                        "templateId": STRING,
                        "templateVersion": STRING,
                        "change": {"enum": ["added", "activated", "retained", "deactivated"]},
                    },
                },
            },
        },
    },
    "strandedWork": STRANDED_WORK,
}
ACTIVATION_FIELDS = [
    "activationId",
    "applyOrder",
    "packageDigest",
    "predecessorPackageDigest",
    "databaseId",
    "planKind",
    "appliedAt",
    "operatorReferenceHash",
    "backupReferences",
    "roleMode",
]
PLAN_REQUIRED = [
    "runtimeConfig",
    "active",
    "candidatePackageDigest",
    "databaseIdCheck",
    "planKind",
    "schemaVersion",
    "supportedSchemaVersion",
    "pendingSchemaVersions",
    "effects",
    "refusals",
    "runtimeRoleMode",
    "changesPending",
]
PLAN_PROPERTIES = {
    "runtimeConfig": STRING,
    "active": NULLABLE_ACTIVATION,
    "candidatePackageDigest": DIGEST,
    "databaseIdCheck": {"enum": ["notRecorded", "matches", "differs"]},
    "planKind": PLAN_KIND,
    "schemaVersion": NULLABLE_SCHEMA_VERSION,
    "supportedSchemaVersion": SCHEMA_VERSION,
    "pendingSchemaVersions": {"type": "array", "items": SCHEMA_VERSION},
    "effects": {"oneOf": [{"$ref": "#/$defs/effects"}, {"type": "null"}]},
    "refusals": {"type": "array", "items": {"$ref": "#/$defs/refusal"}},
    "runtimeRoleMode": {"oneOf": [ROLE_MODE, {"type": "null"}]},
    "changesPending": BOOLEAN,
}


# What an operator settled or marked about one source attempt. `outcome` is
# `applied` or `not_applied`; `itemState` is the occurrence state the item
# holds once the decision is applied.
ATTEMPT_REPORT_PROPERTIES = {
    "attemptId": UUID,
    "itemId": UUID,
    "operation": STRING,
    "bindingReference": STRING,
    "reason": STRING,
    "decidedBy": STRING,
    "attemptState": {"enum": ["pending", "uncertain", "completed", "refused"]},
    "itemState": STRING,
    "applied": BOOLEAN,
}
ATTEMPT_REPORT_REQUIRED = [
    "attemptId",
    "itemId",
    "operation",
    "bindingReference",
    "reason",
    "decidedBy",
    "attemptState",
    "itemState",
    "applied",
]
SETTLEMENT = {
    "type": "object",
    "additionalProperties": False,
    "required": [*ATTEMPT_REPORT_REQUIRED, "outcome"],
    "properties": {**ATTEMPT_REPORT_PROPERTIES, "outcome": STRING},
}
UNCERTAIN_MARKING = {
    "type": "object",
    "additionalProperties": False,
    "required": [*ATTEMPT_REPORT_REQUIRED, "originalActor", "originalProfileId"],
    "properties": {
        **ATTEMPT_REPORT_PROPERTIES,
        "originalActor": {
            "type": "object",
            "additionalProperties": False,
            "required": ["issuer", "subject"],
            "properties": {"issuer": URL, "subject": STRING},
        },
        "originalProfileId": STRING,
    },
}
def project_definition(name: str) -> dict:
    return {"$ref": f"{PROJECT_SCHEMA}#/$defs/{name}"}


PROJECT_QUEUE = project_definition("QueuePolicy")
PROJECT_REVIEW_KIND = project_definition("ReviewKindPolicy")
PROJECT_REVIEW_PRODUCER = project_definition("ReviewProducerPolicy")
PROJECT_INBOX = project_definition("InboxPolicy")
# A project declares at most MAXIMUM_SOURCES sources and each request at most
# MAXIMUM_ROUTING_RULES routing rules; check refuses more.
MAXIMUM_SOURCES = 64
MAXIMUM_ROUTING_RULES = 64

# The connection `source add` reports for one request entity. `application`
# names an executor and an access profile when its mode is `automatic`;
# `completion` is null when the producer declares none.
CONNECTION_PROPERTIES = {
    "policy": {
        "type": "object",
        "additionalProperties": False,
        "required": ["authority", "kind"],
        "properties": {"authority": STRING, "kind": STRING},
    },
    "producerAdmission": {
        "type": "object",
        "additionalProperties": False,
        "required": ["producerId", "profile", "recoveryDays", "completion"],
        "properties": {
            "producerId": STRING,
            "profile": STRING,
            "recoveryDays": COUNT,
            "completion": {
                "oneOf": [
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["destinationId", "recipientBinding"],
                        "properties": {"destinationId": STRING, "recipientBinding": STRING},
                    },
                    {"type": "null"},
                ]
            },
        },
    },
    "application": {
        "type": "object",
        "additionalProperties": False,
        "required": ["mode"],
        "properties": {
            "mode": {"enum": ["manual", "automatic"]},
            "executor": STRING,
            "accessProfile": STRING,
        },
    },
}
RETENTION_COUNTS = [
    "blockedLiveAttempts",
    "items",
    "drafts",
    "correctionContexts",
    "attemptPayloads",
    "receiptPayloads",
    "historyDetails",
    "eventDetails",
    "idempotencyResponses",
    "clockOccurrences",
    "clockPreviews",
]
# A count-only erasure preview or report: no erased content and no local item
# identifiers.
RETENTION = {
    "type": "object",
    "additionalProperties": False,
    "required": ["selector", "applied", *RETENTION_COUNTS],
    "properties": {
        "selector": {
            "type": "object",
            "additionalProperties": False,
            "required": ["sourceId", "requestKind", "requestId"],
            "properties": {"sourceId": STRING, "requestKind": STRING, "requestId": STRING},
        },
        "applied": BOOLEAN,
        **{name: COUNT for name in RETENTION_COUNTS},
    },
}


REPORTS = {
    "AttemptSettlementReport": {
        "command": "attempt settle",
        "required": ["project", "runtimeConfig", "report"],
        "properties": {"project": STRING, "runtimeConfig": STRING, "report": {"$ref": "#/$defs/settlement"}},
        "defs": {"settlement": SETTLEMENT},
    },
    "AttemptUncertainMarkingReport": {
        "command": "attempt mark-uncertain",
        "required": ["project", "runtimeConfig", "report"],
        "properties": {"project": STRING, "runtimeConfig": STRING, "report": {"$ref": "#/$defs/uncertainMarking"}},
        "defs": {"uncertainMarking": UNCERTAIN_MARKING},
    },
    "CheckReport": {
        "command": "check",
        "required": [
            "status",
            "project",
            "effective",
            "profile",
            "filesChecked",
            "diagnostics",
            "networkAccess",
            "databaseAccess",
        ],
        "properties": {
            "status": {"enum": ["complete", "incomplete"]},
            "project": STRING,
            "effective": {"$ref": "#/$defs/effective"},
            "profile": {"enum": ["authoring", "production"]},
            "filesChecked": FILES_CHECKED,
            "diagnostics": WARNINGS,
            "networkAccess": {"const": False},
            "databaseAccess": {"const": False},
            "runtimeConfig": STRING,
            "bregPackage": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "package",
                    "packageDigest",
                    "registryRevision",
                    "sourceId",
                    "sourceRevision",
                    "pin",
                ],
                "properties": {
                    "package": STRING,
                    "packageDigest": DIGEST,
                    "registryRevision": STRING,
                    "sourceId": STRING,
                    "sourceRevision": STRING,
                    "pin": {"const": "current"},
                },
            },
        },
        "defs": {
            # A standalone project reports `mode`, `queues`, and
            # `sourceConnections`; a project with sources reports `sources`,
            # `sourceDescription` (`checked` or `pending_source_add`), and
            # `limits`.
            "effective": {
                "type": "object",
                "additionalProperties": False,
                "required": ["projectId", "inbox", "reviewKinds", "reviewProducers"],
                "properties": {
                    "projectId": STRING,
                    "mode": {"const": "standalone"},
                    "queues": {"type": "array", "items": PROJECT_QUEUE},
                    "reviewKinds": {"type": "array", "items": PROJECT_REVIEW_KIND},
                    "reviewProducers": {"type": "array", "items": PROJECT_REVIEW_PRODUCER},
                    "inbox": PROJECT_INBOX,
                    "sourceConnections": {"const": 0},
                    "sources": {"type": "array", "items": {"$ref": "#/$defs/checkedSource"}},
                    "sourceDescription": STRING,
                    "limits": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["sources", "queues"],
                        "properties": {
                            "sources": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_SOURCES},
                            "queues": COUNT,
                        },
                    },
                },
            },
            "checkedSource": {
                "type": "object",
                "additionalProperties": False,
                "required": ["sourceId", "sourceAdapter", "requests"],
                "properties": {
                    "sourceId": STRING,
                    "sourceAdapter": STRING,
                    "requests": {"type": "array", "items": {"$ref": "#/$defs/checkedRequest"}},
                },
            },
            # `queueMode` is `default` or `first_match`. `target` is the
            # authored passive target, or null when the request declares none;
            # its `id` is the one `casework.yaml` declares and its `elapsed`
            # the duration it is due after.
            "checkedRequest": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "entity",
                    "queue",
                    "queueMode",
                    "routingRules",
                    "applicationMode",
                    "clock",
                    "target",
                ],
                "properties": {
                    "entity": STRING,
                    "queue": STRING,
                    "queueMode": STRING,
                    "routingRules": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_ROUTING_RULES},
                    "applicationMode": NULLABLE_STRING,
                    "clock": NULLABLE_STRING,
                    "target": {
                        "oneOf": [
                            {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["id", "elapsed"],
                                "properties": {"id": LOCAL_ID, "elapsed": STRING},
                            },
                            {"type": "null"},
                        ]
                    },
                },
            },
        },
    },
    "PlanReport": {
        "command": "plan",
        "required": PLAN_REQUIRED,
        "properties": PLAN_PROPERTIES,
        "refusal_carries_report": True,
        "defs": {**ACTIVATION_DEFS, **EFFECTS_DEFS},
    },
    "ApplyReport": {
        "command": "apply",
        "required": [
            "runtimeConfig",
            *ACTIVATION_FIELDS,
            "schemaVersionsApplied",
            "effects",
            "singleRoleStatement",
        ],
        "properties": {
            "runtimeConfig": STRING,
            **ACTIVATION_DEFS["activation"]["properties"],
            "schemaVersionsApplied": {"type": "array", "items": SCHEMA_VERSION},
            "effects": {"$ref": "#/$defs/effects"},
            "singleRoleStatement": SINGLE_ROLE_STATEMENT,
        },
        "defs": {**ACTIVATION_DEFS, **EFFECTS_DEFS},
    },
    "StatusReport": {
        "command": "status",
        "required": [
            "runtimeConfig",
            "active",
            "history",
            "schemaVersion",
            "supportedSchemaVersion",
            "roleMode",
            "singleRoleStatement",
        ],
        "properties": {
            "runtimeConfig": STRING,
            "active": NULLABLE_ACTIVATION,
            "history": {"type": "array", "items": ACTIVATION},
            "schemaVersion": NULLABLE_SCHEMA_VERSION,
            "supportedSchemaVersion": SCHEMA_VERSION,
            "roleMode": {"oneOf": [ROLE_MODE, {"type": "null"}]},
            "singleRoleStatement": SINGLE_ROLE_STATEMENT,
        },
        "defs": ACTIVATION_DEFS,
    },
    "DoctorReport": {
        "command": "doctor",
        "required": [
            "runtimeConfig",
            "packageRoot",
            "checks",
            "packageDigest",
            "secretFileChecks",
            "sourceChecks",
            "pinnedWork",
            "eventWiringGuidance",
            "roleMode",
            "singleRoleStatement",
        ],
        "properties": {
            "runtimeConfig": STRING,
            "packageRoot": STRING,
            "packageDigest": DIGEST,
            "checks": {"$ref": "#/$defs/doctorChecks"},
            "secretFileChecks": {"type": "array", "items": {"$ref": "#/$defs/secretFileCheck"}},
            "sourceChecks": {"type": "array", "items": {"$ref": "#/$defs/sourceCheck"}},
            "pinnedWork": {
                "type": "object",
                "additionalProperties": False,
                "required": ["verdict", "conflicts"],
                "properties": {
                    "verdict": {"enum": ["clear", "acknowledged"]},
                    "conflicts": {"type": "array", "items": {"$ref": "#/$defs/strandedWork"}},
                },
            },
            "eventWiringGuidance": STRING,
            "roleMode": ROLE_MODE,
            "singleRoleStatement": SINGLE_ROLE_STATEMENT,
        },
        "defs": {
            "doctorChecks": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "configuration",
                    "secretFiles",
                    "sourceDescriptions",
                    "sourceConnections",
                    "audit",
                    "database",
                    "activation",
                    "pinnedWork",
                    "oidcIssuer",
                    "directory",
                    "reconciliation",
                ],
                "properties": {
                    key: {"const": "ready"}
                    for key in [
                        "configuration",
                        "secretFiles",
                        "sourceDescriptions",
                        "sourceConnections",
                        "audit",
                        "database",
                        "activation",
                        "pinnedWork",
                        "oidcIssuer",
                        "directory",
                        "reconciliation",
                    ]
                },
            },
            # `refusal` says why an environment secret was not checked.
            "secretFileCheck": {
                "type": "object",
                "additionalProperties": False,
                "required": ["setting", "provider", "status"],
                "properties": {
                    "setting": STRING,
                    "provider": {"enum": ["file", "environment"]},
                    "status": {"enum": ["ready", "not-checked"]},
                    "refusal": STRING,
                },
            },
            "sourceCheck": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "sourceId",
                    "runtime",
                    "readerProfile",
                    "requiredGrants",
                    "eventWiring",
                    "reconciliation",
                ],
                "properties": {
                    "sourceId": STRING,
                    "runtime": {"const": "ready"},
                    "readerProfile": {"const": "ready"},
                    "requiredGrants": {"const": "ready"},
                    "eventWiring": {"const": "unknown"},
                    "reconciliation": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "consecutiveFailures",
                            "lastSucceededAt",
                            "lastFailedAt",
                            "lastFailure",
                        ],
                        "properties": {
                            # The store holds the count as a PostgreSQL integer.
                            "consecutiveFailures": {"type": "integer", "minimum": 0, "maximum": 2**31 - 1},
                            "lastSucceededAt": NULLABLE_TIMESTAMP,
                            "lastFailedAt": NULLABLE_TIMESTAMP,
                            "lastFailure": {
                                "oneOf": [
                                    {"enum": ["source-unavailable", "source-refused", "store", "configuration"]},
                                    {"type": "null"},
                                ]
                            },
                        },
                    },
                },
            },
            "strandedWork": STRANDED_WORK,
        },
    },
    "ExplainReport": {
        "command": "explain",
        "required": [
            "projectId",
            "policyVersion",
            "requests",
            "accessProfiles",
            "queues",
            "reviewKinds",
            "calendars",
            "clocks",
            "networkAccess",
            "databaseAccess",
        ],
        "properties": {
            "projectId": STRING,
            "policyVersion": STRING,
            "requests": {"type": "array", "items": {"$ref": "#/$defs/explainedRequest"}},
            "accessProfiles": {"type": "array", "items": project_definition("AccessProfile")},
            "queues": {"type": "array", "items": PROJECT_QUEUE},
            "reviewKinds": {"type": "array", "items": PROJECT_REVIEW_KIND},
            "calendars": {"type": "array", "items": project_definition("CalendarPolicy")},
            "clocks": {"type": "array", "items": project_definition("ClockPolicy")},
            "networkAccess": {"const": False},
            "databaseAccess": {"const": False},
        },
        "defs": {
            "explainedRequest": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "source",
                    "entity",
                    "defaultQueue",
                    "projection",
                    "routing",
                    "clock",
                    "sourceStages",
                    "sourceFields",
                ],
                "properties": {
                    "source": STRING,
                    "entity": STRING,
                    "defaultQueue": STRING,
                    "projection": STRING_ARRAY,
                    "routing": {"type": "array", "items": project_definition("RoutingRule")},
                    "clock": NULLABLE_STRING,
                    "sourceStages": STRING_ARRAY,
                    "sourceFields": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["field", "apiName"],
                            "properties": {"field": STRING, "apiName": STRING},
                        },
                    },
                },
            }
        },
    },
    "InitReport": {
        "command": "init",
        "required": ["template", "project", "created", "next"],
        "properties": {
            "template": {"enum": ["professional-review", "standalone-decision"]},
            "project": STRING,
            "created": STRING_ARRAY,
            "next": STRING_ARRAY,
        },
    },
    "LifecycleReport": {
        "command": "lifecycle",
        "required": ["lifecycles"],
        "properties": {
            "lifecycles": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": {"$ref": "#/$defs/lifecycle"},
            }
        },
        "defs": {
            "lifecycle": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "label", "states", "transitions", "enforcement"],
                "properties": {
                    "id": {"enum": ["occurrence", "review_request"]},
                    "label": STRING,
                    "states": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"$ref": "#/$defs/lifecycleState"},
                    },
                    "transitions": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"$ref": "#/$defs/lifecycleTransition"},
                    },
                    "enforcement": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"$ref": "#/$defs/enforcementLayer"},
                    },
                },
            },
            "lifecycleState": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "id",
                    "initial",
                    "terminal",
                    "unreachable",
                    "incomingTransitions",
                    "outgoingTransitions",
                ],
                "properties": {
                    "id": STRING,
                    "initial": BOOLEAN,
                    "terminal": BOOLEAN,
                    "unreachable": BOOLEAN,
                    "incomingTransitions": COUNT,
                    "outgoingTransitions": COUNT,
                },
            },
            "lifecycleTransition": {
                "type": "object",
                "additionalProperties": False,
                "required": ["from", "event", "to", "guard"],
                "properties": {
                    "from": STRING,
                    "event": STRING,
                    "to": STRING,
                    "guard": {"type": "string", "minLength": 1},
                },
            },
            "enforcementLayer": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "description", "events"],
                "properties": {
                    "id": STRING,
                    "description": {"type": "string", "minLength": 1},
                    "events": {
                        "type": "array",
                        "minItems": 1,
                        "items": STRING,
                    },
                },
            },
        },
    },
    "PackageReport": {
        "command": "package",
        "required": [
            "project",
            "dryRun",
            "packageDigest",
            "revision",
            "files",
            "runtimeConfigurationIncluded",
            "secretsIncluded",
            "networkAccess",
            "databaseAccess",
        ],
        "properties": {
            "project": STRING,
            "output": STRING,
            "dryRun": BOOLEAN,
            "packageDigest": DIGEST,
            "revision": {"type": ["string", "null"]},
            "files": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["path", "sha256", "bytes"],
                    "properties": {
                        "path": STRING,
                        "sha256": DIGEST,
                        # A package input is at most one MiB.
                        "bytes": {"type": "integer", "minimum": 0, "maximum": 1024 * 1024},
                    },
                },
            },
            "runtimeConfigurationIncluded": {"const": False},
            "secretsIncluded": {"const": False},
            "networkAccess": {"const": False},
            "databaseAccess": {"const": False},
        },
    },
    "RetentionEraseReport": {
        "command": "retention erase",
        "required": ["project", "runtimeConfig", "report"],
        "properties": {"project": STRING, "runtimeConfig": STRING, "report": {"$ref": "#/$defs/retention"}},
        "defs": {"retention": RETENTION},
    },
    "SimulationReport": {
        "command": "simulate",
        "required": [
            "fixture",
            "projectId",
            "policyVersion",
            "source",
            "subject",
            "routing",
            "clock",
            "networkAccess",
            "databaseAccess",
        ],
        "properties": {
            "fixture": STRING,
            "projectId": STRING,
            "policyVersion": STRING,
            "source": STRING,
            "subject": {
                "type": "object",
                "additionalProperties": False,
                "required": ["entity", "id", "version"],
                "properties": {"entity": STRING, "id": STRING, "version": STRING},
            },
            "routing": {
                "type": "object",
                "additionalProperties": False,
                "required": ["queue"],
                "properties": {"queue": STRING, "ruleId": STRING, "because": STRING},
            },
            "clock": {},
            "networkAccess": {"const": False},
            "databaseAccess": {"const": False},
        },
    },
    "SourceAddReport": {
        "command": "source add",
        "required": [
            "status",
            "sourceId",
            "registry",
            "project",
            "sourceDescription",
            "bregRuntimeBinding",
            "connection",
            "bregAuthoringChanges",
            "bregAuthoringPatch",
            "diagnostics",
            "activation",
            "next",
        ],
        "properties": {
            "status": {"enum": ["preview", "applied"]},
            "sourceId": STRING,
            "registry": STRING,
            "project": STRING,
            "sourceDescription": STRING,
            "bregRuntimeBinding": STRING,
            # One request entity reports its connection here; several report
            # one connection per entity under `requests`.
            "connection": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    **CONNECTION_PROPERTIES,
                    "requests": {"type": "array", "minItems": 2, "items": {"$ref": "#/$defs/requestConnection"}},
                },
            },
            "bregAuthoringChanges": ARRAY,
            "bregAuthoringPatch": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "event": passthrough("the hook fragment is part of the Base Registry Engine authoring project, in its grammar"),
                    "events": {
                        "type": "array",
                        "x-registry-passthrough": "the hook fragments are part of the Base Registry Engine authoring project, in its grammar",
                    },
                    "accessProfile": passthrough("the access profile fragment is part of the Base Registry Engine authoring project, in its grammar"),
                    "devClients": passthrough("the dev clients fragment is part of the Base Registry Engine authoring project, in its grammar"),
                },
            },
            "candidateRuntimeBinding": passthrough("the candidate binding is a Base Registry Engine runtime binding, in its grammar"),
            "diagnostics": WARNINGS,
            "activation": {"const": "not_performed"},
            "next": STRING_ARRAY,
        },
        "defs": {
            "requestConnection": {
                "type": "object",
                "additionalProperties": False,
                "required": ["entity", *CONNECTION_PROPERTIES],
                "properties": {"entity": STRING, **CONNECTION_PROPERTIES},
            }
        },
    },
    "TestReport": {
        "command": "test",
        "status": "passed",
        "required": [
            "project",
            "authoringStatus",
            "filesChecked",
            "diagnostics",
            "fixtures",
            "proofBoundary",
            "productionClosure",
            "networkAccess",
            "databaseAccess",
        ],
        "properties": {
            "project": STRING,
            "authoringStatus": {"enum": ["complete", "incomplete"]},
            "filesChecked": FILES_CHECKED,
            "diagnostics": WARNINGS,
            "fixtures": {
                "type": "array",
                "minItems": 1,
                "items": {"$ref": "#/$defs/fixture"},
            },
            "proofBoundary": {"const": "offline_synthetic"},
            "productionClosure": {"const": False},
            "networkAccess": {"const": False},
            "databaseAccess": {"const": False},
        },
        "defs": {
            "fixture": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "status", "file"],
                "properties": {
                    "name": STRING,
                    "status": {"const": "passed"},
                    "file": STRING,
                },
            }
        },
    },
    "DevReport": {
        "command": "dev",
        "required": [
            "status",
            "project",
            "stateFile",
            "operatorConfig",
            "caseworkUrl",
            "tokenEndpoint",
            "issuer",
            "clientAssertionAudience",
            "resource",
            "audience",
            "journal",
            "sources",
            "clients",
            "directory",
        ],
        "properties": {
            "status": {"enum": ["starting", "ready", "stopping", "stopped", "failed"]},
            "project": STRING,
            "stateFile": STRING,
            "operatorConfig": STRING,
            "caseworkUrl": URL,
            "tokenEndpoint": STRING,
            "issuer": URL,
            "clientAssertionAudience": STRING,
            "resource": STRING,
            "audience": STRING,
            "journal": STRING,
            "sources": {
                "type": "object",
                "propertyNames": LOCAL_ID,
                "additionalProperties": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["project", "bregUrl"],
                    "properties": {"project": STRING, "bregUrl": {"oneOf": [URL, {"type": "null"}]}},
                },
            },
            "clients": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["id", "profile", "role", "clientIdFile", "assertionKeyFile"],
                    "properties": {
                        "id": LOCAL_ID,
                        "profile": STRING,
                        "role": {"enum": ["staff", "supervisor", "administrator", "requester"]},
                        "clientIdFile": STRING,
                        "assertionKeyFile": STRING,
                    },
                },
            },
            "directory": {
                "type": "object",
                "additionalProperties": False,
                "required": ["revision", "teams"],
                "properties": {
                    "revision": COUNT,
                    "teams": COUNT,
                },
            },
        },
    },
    "DevEventsReport": {
        "command": "dev events",
        "required": ["project", "journal", "events", "truncated"],
        "properties": {
            "project": STRING,
            "journal": STRING,
            "events": STRING_ARRAY,
            "truncated": BOOLEAN,
        },
    },
    "DevGrantReport": {
        "command": "dev grant",
        "required": ["headerFile", "grantExpiresAt", "diagnostics"],
        "properties": {"headerFile": STRING, "grantExpiresAt": STRING, "diagnostics": WARNINGS},
    },
    "DevIdentityReport": {
        "command": "dev identity",
        "required": ["clientId", "subject"],
        "properties": {"clientId": STRING, "subject": STRING},
    },
    "DevTokenReport": {
        "command": "dev token",
        "required": ["headerFile"],
        "properties": {"headerFile": STRING},
    },
    "UsageReport": {"command": "usage", "failure_only": True},
}


# A position lies inside a document the shared reader accepted, which is at
# most MAXIMUM_DOCUMENT_BYTES (1 MiB) long, so neither its line nor its
# column passes one more than that.
POSITION = {"type": "integer", "minimum": 1, "maximum": 1024 * 1024 + 1}
DIAGNOSTIC_DEFS = {
    "diagnostics": {
        "type": "array",
        "minItems": 1,
        "items": {"$ref": "#/$defs/diagnostic"},
    },
    # The one diagnostic shape every checking command reports (CFG-DIAG-1),
    # carried unchanged from the shared configuration reader.
    "diagnostic": {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "severity",
            "code",
            "path",
            "message",
            "suggestedAction",
        ],
        "properties": {
            "severity": STRING,
            "code": STRING,
            "artifact": STRING,
            "path": STRING,
            "message": STRING,
            "suggestedAction": STRING,
            "source": {
                "type": "object",
                "additionalProperties": False,
                "required": ["file"],
                "properties": {
                    "file": STRING,
                    "line": POSITION,
                    "column": POSITION,
                },
            },
            "related": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["file", "path", "message"],
                    "properties": {
                        "file": STRING,
                        "line": POSITION,
                        "column": POSITION,
                        "path": STRING,
                        "message": STRING,
                    },
                },
            },
        },
    },
    # A check that passed reports every warning it found, possibly none; an
    # error would have refused it.
    "warnings": {
        "type": "array",
        "items": {
            "allOf": [
                {"$ref": "#/$defs/diagnostic"},
                {"properties": {"severity": {"const": "warning"}}},
            ],
            "unevaluatedProperties": False,
        },
    },
}


def status_schema(kind: str, report: dict, ok: bool, carries_report: bool) -> dict:
    # Every report names what happened. A report that states its own status
    # keeps it; a refused plan is `refused`; a failure without a report of its
    # own is named by its exit class.
    if ok:
        return report.get("properties", {}).get("status", {"const": report.get("status", "complete")})
    if carries_report:
        return {"const": "refused"}
    if kind == "UsageReport":
        return {"const": "usage-error"}
    return {"enum": ["domain-refusal", "operational-failure"]}


def object_schema(kind: str, report: dict, ok: bool, carries_report: bool = False) -> dict:
    properties = {
        "ok": {"const": ok},
        "command": {"const": report["command"]},
        "status": status_schema(kind, report, ok, carries_report),
        "apiVersion": {"const": API_VERSION},
        "kind": {"const": kind},
    }
    required = ["ok", "command", "status", "apiVersion", "kind"]
    if ok or carries_report:
        properties.update(
            {name: value for name, value in report.get("properties", {}).items() if name != "status"}
        )
        required.extend(name for name in report.get("required", []) if name != "status")
    if not ok:
        properties["diagnostics"] = DIAGNOSTICS
        required.append("diagnostics")
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


VALUE_DEFS = {
    "Digest": {
        "description": "A SHA-256 digest: `sha256:` followed by 64 lowercase hex digits.",
        "pattern": "^sha256:[0-9a-f]{64}$",
        "type": "string",
    },
    "LocalId": {
        "description": "A local identifier: a lowercase letter, then up to 63 lowercase letters, digits, `_`, or `-`.",
        "pattern": "^[a-z][a-z0-9_-]{0,63}$",
        "type": "string",
    },
    "Url": {
        "description": "An absolute http or https URL with a host and no user information.",
        "format": "uri",
        "maxLength": 2048,
        "pattern": "^[Hh][Tt][Tt][Pp][Ss]?://[^/?#@]+([/?#].*)?$",
        "type": "string",
    },
}


def format_name(kind: str) -> str:
    """`CheckReport` is the format `check-report`."""
    return re.sub(r"(?<!^)(?=[A-Z])", "-", kind).lower()


def schema(kind: str, report: dict) -> dict:
    variants = [object_schema(kind, report, False)]
    if report.get("refusal_carries_report"):
        # A refusal found while planning carries the plan it refused beside
        # its diagnostics; a refusal before the plan exists carries only them.
        variants.insert(0, object_schema(kind, report, False, carries_report=True))
    if not report.get("failure_only"):
        variants.insert(0, object_schema(kind, report, True))
    defs = dict(DIAGNOSTIC_DEFS)
    defs.update(report.get("defs", {}))
    used = json.dumps([variants, defs])
    defs.update({name: value for name, value in VALUE_DEFS.items() if f'"#/$defs/{name}"' in used})
    name = format_name(kind)
    # The envelope members are declared beside the variants, each of which
    # repeats them, so the envelope is visible without choosing a variant.
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_ID_BASE + f"casework/{name}/{name}.v1alpha3.schema.json",
        "title": kind,
        "description": f"Versioned JSON report emitted by caseworkctl for {report['command']}.",
        "type": "object",
        "required": ["apiVersion", "kind"],
        "properties": {"apiVersion": {"const": API_VERSION}, "kind": {"const": kind}},
        "unevaluatedProperties": False,
        "oneOf": variants,
        "$defs": defs,
    }


def rendered_files() -> dict[Path, bytes]:
    return {
        OUTPUT / f"{kind}.schema.json": (
            json.dumps(schema(kind, report), indent=2, sort_keys=False) + "\n"
        ).encode()
        for kind, report in REPORTS.items()
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered_files()
    if args.check:
        stale = [path for path, content in expected.items() if not path.is_file() or path.read_bytes() != content]
        unexpected = sorted(set(OUTPUT.glob("*.schema.json")) - set(expected)) if OUTPUT.exists() else []
        for path in [*stale, *unexpected]:
            print(f"stale caseworkctl schema: {path.relative_to(OUTPUT.parent.parent)}")
        return 1 if stale or unexpected else 0
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for path, content in expected.items():
        path.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
