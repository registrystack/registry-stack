#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Generate the self-contained caseworkctl JSON report schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


API_VERSION = "registry.registrystack.org/caseworkctl/v1alpha3"
OUTPUT = Path(__file__).resolve().parents[1] / "contracts" / "cli"

STRING = {"type": "string"}
BOOLEAN = {"type": "boolean"}
OBJECT = {"type": "object"}
ARRAY = {"type": "array"}
STRING_ARRAY = {"type": "array", "items": {"type": "string"}}
OBJECT_ARRAY = {"type": "array", "items": {"type": "object"}}
DIAGNOSTICS = {"$ref": "#/$defs/diagnostics"}
FINDINGS = {"$ref": "#/$defs/findings"}


DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
NULLABLE_STRING = {"type": ["string", "null"]}
ROLE_MODE = {"enum": ["single", "split"]}
PLAN_KIND = {"enum": ["initial", "successor"]}
SCHEMA_VERSION = {"type": "integer", "minimum": 1}
NULLABLE_SCHEMA_VERSION = {"type": ["integer", "null"], "minimum": 1}
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
            "applyOrder": {"type": "integer", "minimum": 1},
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
    "effects": {"type": ["object", "null"]},
    "refusals": {"type": "array", "items": {"$ref": "#/$defs/refusal"}},
    "runtimeRoleMode": {"oneOf": [ROLE_MODE, {"type": "null"}]},
    "changesPending": BOOLEAN,
}


REPORTS = {
    "AttemptSettlementReport": {
        "command": "attempt settle",
        "required": ["project", "runtimeConfig", "report"],
        "properties": {"project": STRING, "runtimeConfig": STRING, "report": OBJECT},
    },
    "AttemptUncertainMarkingReport": {
        "command": "attempt mark-uncertain",
        "required": ["project", "runtimeConfig", "report"],
        "properties": {"project": STRING, "runtimeConfig": STRING, "report": OBJECT},
    },
    "CheckReport": {
        "command": "check",
        "required": [
            "status",
            "project",
            "effective",
            "profile",
            "findings",
            "networkAccess",
            "databaseAccess",
        ],
        "properties": {
            "status": {"enum": ["complete", "incomplete"]},
            "project": STRING,
            "effective": OBJECT,
            "profile": {"enum": ["authoring", "production"]},
            "findings": FINDINGS,
            "networkAccess": {"const": False},
            "databaseAccess": {"const": False},
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
    },
    "PlanReport": {
        "command": "plan",
        "required": PLAN_REQUIRED,
        "properties": PLAN_PROPERTIES,
        "refusal_carries_report": True,
        "defs": ACTIVATION_DEFS,
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
            "effects": OBJECT,
            "singleRoleStatement": SINGLE_ROLE_STATEMENT,
        },
        "defs": ACTIVATION_DEFS,
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
            "packageDigest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "checks": {"$ref": "#/$defs/doctorChecks"},
            "secretFileChecks": OBJECT_ARRAY,
            "sourceChecks": OBJECT_ARRAY,
            "pinnedWork": {
                "type": "object",
                "additionalProperties": False,
                "required": ["verdict", "conflicts"],
                "properties": {
                    "verdict": {"enum": ["clear", "acknowledged"]},
                    "conflicts": OBJECT_ARRAY,
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
            }
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
            "requests": OBJECT_ARRAY,
            "accessProfiles": OBJECT_ARRAY,
            "queues": OBJECT_ARRAY,
            "reviewKinds": OBJECT_ARRAY,
            "calendars": OBJECT_ARRAY,
            "clocks": OBJECT_ARRAY,
            "networkAccess": {"const": False},
            "databaseAccess": {"const": False},
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
                    "incomingTransitions": {"type": "integer", "minimum": 0},
                    "outgoingTransitions": {"type": "integer", "minimum": 0},
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
            "packageDigest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "revision": {"type": ["string", "null"]},
            "files": OBJECT_ARRAY,
            "runtimeConfigurationIncluded": {"const": False},
            "secretsIncluded": {"const": False},
            "networkAccess": {"const": False},
            "databaseAccess": {"const": False},
        },
    },
    "RetentionEraseReport": {
        "command": "retention erase",
        "required": ["project", "runtimeConfig", "report"],
        "properties": {"project": STRING, "runtimeConfig": STRING, "report": OBJECT},
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
            "routing": OBJECT,
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
            "findings",
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
            "connection": OBJECT,
            "bregAuthoringChanges": ARRAY,
            "bregAuthoringPatch": OBJECT,
            "candidateRuntimeBinding": OBJECT,
            "findings": FINDINGS,
            "activation": {"const": "not_performed"},
            "next": STRING_ARRAY,
        },
    },
    "TestReport": {
        "command": "test",
        "status": "passed",
        "required": [
            "project",
            "authoringStatus",
            "findings",
            "fixtures",
            "proofBoundary",
            "productionClosure",
            "networkAccess",
            "databaseAccess",
        ],
        "properties": {
            "project": STRING,
            "authoringStatus": {"enum": ["complete", "incomplete"]},
            "findings": FINDINGS,
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
            "caseworkUrl": STRING,
            "tokenEndpoint": STRING,
            "issuer": STRING,
            "clientAssertionAudience": STRING,
            "resource": STRING,
            "audience": STRING,
            "journal": STRING,
            "sources": OBJECT,
            "clients": OBJECT_ARRAY,
            "directory": {
                "type": "object",
                "additionalProperties": False,
                "required": ["revision", "teams"],
                "properties": {
                    "revision": {"type": "integer"},
                    "teams": {"type": "integer", "minimum": 0},
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
        "required": ["headerFile", "grantExpiresAt"],
        "properties": {"headerFile": STRING, "grantExpiresAt": STRING},
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
    "findings": {
        "type": "array",
        "items": {"$ref": "#/$defs/diagnostic"},
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
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://registrystack.org/caseworkctl/v1alpha3/{kind}.schema.json",
        "title": kind,
        "description": f"Versioned JSON report emitted by caseworkctl for {report['command']}.",
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
