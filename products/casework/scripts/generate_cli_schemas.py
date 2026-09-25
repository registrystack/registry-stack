#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Generate the self-contained caseworkctl JSON report schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


API_VERSION = "registry.registrystack.org/caseworkctl/v1alpha1"
OUTPUT = Path(__file__).resolve().parents[1] / "contracts" / "cli"

STRING = {"type": "string"}
BOOLEAN = {"type": "boolean"}
OBJECT = {"type": "object"}
ARRAY = {"type": "array"}
STRING_ARRAY = {"type": "array", "items": {"type": "string"}}
OBJECT_ARRAY = {"type": "array", "items": {"type": "object"}}
DIAGNOSTICS = {"$ref": "#/$defs/diagnostics"}
FINDINGS = {"$ref": "#/$defs/findings"}


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
        },
    },
    "DatabaseMigrationReport": {
        "command": "db migrate",
        "required": ["project", "runtimeConfig", "status"],
        "properties": {
            "project": STRING,
            "runtimeConfig": STRING,
            "status": {"const": "migrated"},
        },
    },
    "DoctorReport": {
        "command": "doctor",
        "required": [
            "runtimeConfig",
            "packageRoot",
            "checks",
            "secretFileChecks",
            "sourceChecks",
            "eventWiringGuidance",
        ],
        "properties": {
            "runtimeConfig": STRING,
            "packageRoot": STRING,
            "checks": {"$ref": "#/$defs/doctorChecks"},
            "secretFileChecks": OBJECT_ARRAY,
            "sourceChecks": OBJECT_ARRAY,
            "eventWiringGuidance": STRING,
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
                    "oidcIssuer",
                    "directory",
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
                        "oidcIssuer",
                        "directory",
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
            "policyDigest",
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
            "policyDigest": {"type": "string", "pattern": "^sha256:"},
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


DIAGNOSTIC_DEFS = {
    "diagnostics": {
        "type": "array",
        "minItems": 1,
        "items": {"$ref": "#/$defs/diagnostic"},
    },
    "diagnostic": {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "severity",
            "code",
            "artifact",
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
        },
    },
    "findings": {
        "type": "array",
        "items": {"$ref": "#/$defs/diagnostic"},
    },
}


def object_schema(kind: str, report: dict, ok: bool) -> dict:
    properties = {
        "apiVersion": {"const": API_VERSION},
        "kind": {"const": kind},
        "ok": {"const": ok},
        "command": {"const": report["command"]},
    }
    required = ["apiVersion", "kind", "ok"]
    if ok:
        properties.update(report.get("properties", {}))
        required.extend(["command", *report.get("required", [])])
    else:
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
    if not report.get("failure_only"):
        variants.insert(0, object_schema(kind, report, True))
    defs = dict(DIAGNOSTIC_DEFS)
    defs.update(report.get("defs", {}))
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://registrystack.org/caseworkctl/v1alpha1/{kind}.schema.json",
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
