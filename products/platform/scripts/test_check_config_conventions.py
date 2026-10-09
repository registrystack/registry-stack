"""Tests for check-config-conventions.py.

Every test builds a small repository in a temporary directory: a convention
page, a format registry, an exceptions register, schemas, an example, Rust
sources, and an editor mapping. The baseline repository conforms, so each test
plants one deviation and asserts the exact finding the lint reports. Test names
cite the rule they prove.

Run with PyYAML available:

    uv run --no-project --with PyYAML==6.0.2 python -m unittest \
        products/platform/scripts/test_check_config_conventions.py
"""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import yaml

SCRIPT = Path(__file__).with_name("check-config-conventions.py")
SPEC = importlib.util.spec_from_file_location("check_config_conventions", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
lint = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lint
SPEC.loader.exec_module(lint)

REGISTRY = "products/platform/config-formats.yaml"
REGISTER = "products/platform/config-conventions-exceptions.yaml"
CONVENTION = "products/platform/CONFIG-CONVENTIONS.md"
CANONICAL = "products/platform/generated/runtime-config-blocks.schema.json"
PROJECT_SCHEMA = "products/casework/generated/project/project.schema.json"
REPORT_SCHEMA = "products/casework/contracts/cli/CheckReport.schema.json"
EXAMPLE = "products/casework/examples/demo/casework.yaml"
REPORT_EXAMPLE = "products/casework/examples/demo/check-report.json"
CONFIG_RS = "crates/registry-casework-core/src/config.rs"
PLATFORM_RS = "crates/registry-platform-config/src/lib.rs"
P = "casework/project"
R = "casework/check-report"

CONVENTION_TEXT = """\
# Conventions

**CFG-ENV-1 (MUST). Every document carries `apiVersion` and `kind`.**

**CFG-NAME-3 (MUST). Limits are spelled `maximum<Thing>`.**

**CFG-NAME-5 (MUST). A concept shared by several products has one name.**

| Concept | Key | Refused spellings (lint) |
|---|---|---|
| Inbound request | `requestTimeoutMilliseconds` under `listener` | `requestTimeoutSeconds` |
| Outbound attempt | `attemptTimeoutMilliseconds` | `timeoutMilliseconds`, `attemptTimeoutSeconds`, `requestTimeoutMilliseconds` outside `listener` |
| Attempts | `maximumAttempts` | `maxAttempts` |
| Retention | `retentionDays`, or `<thing>RetentionDays` where one block keeps several kinds | `retainDays`, `retention.<thing>Days` |
| Cache | `cacheTtlSeconds` | |
| Size | `maximum<Thing>Bytes` | `max<Thing>Bytes`, `maxSize` |

**CFG-SCHEMA-8 (MUST). Readers refuse unknown keys.**

**CFG-ENV-5 (SHOULD). Files are named after the format.**

## Exceptions

| Class | Meaning | Resolution |
|---|---|---|
| `protocol-constant` | A value another specification defines. | Permanent. |

## Enforcement summary

| Rules | Gate |
|---|---|
| CFG-ENV-1 | reader unit tests named with the rule ID; the conformance corpus; for CFG-ENV-1 also the convention lint (`const` envelope) |
| CFG-NAME-3, 5 | `check-config-conventions.py` over the registry and every schema |
| CFG-SCHEMA-8 | source lint over the reader-type closure |
| CFG-ENV-5 (SHOULD) | review |
"""

LOCAL_ID = {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$"}
CANONICAL_DEFS = {
    "LocalId": LOCAL_ID,
    "ExternalId": {"type": "string", "minLength": 1},
    "Digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "Url": {"type": "string", "format": "uri"},
    "SecretReference": {
        "type": "string",
        "pattern": "^secret:(env/[A-Z][A-Z0-9_]{0,127}|file/[a-z][a-z0-9._-]{0,127})$",
    },
    "ProjectIdentity": {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "version"],
        "properties": {
            "id": {"$ref": "#/$defs/LocalId"},
            "version": {"type": "string", "minLength": 1, "maxLength": 64},
        },
    },
    "ListenerConfig": {
        "type": "object",
        "additionalProperties": False,
        "required": ["bind"],
        "properties": {
            "bind": {"type": "string"},
            "requestTimeoutMilliseconds": {
                "type": "integer",
                "minimum": 1,
                "maximum": 600000,
                "default": 30000,
            },
        },
    },
}


def project_schema() -> dict:
    defs = copy.deepcopy(CANONICAL_DEFS)
    defs["Queue"] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id"],
        "properties": {
            "id": {"$ref": "#/$defs/LocalId"},
            "attemptTimeoutMilliseconds": {
                "type": "integer",
                "minimum": 1,
                "maximum": 60000,
                "default": 1000,
            },
            "mode": {
                "type": "string",
                "enum": ["first-come", "round-robin"],
                "default": "first-come",
            },
            "enabled": {"type": "boolean", "default": True},
        },
    }
    defs["AccessProfile"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "requiredScopes": {
                "anyOf": [
                    {"const": "unrestricted"},
                    {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": True,
                        "items": {"$ref": "#/$defs/ExternalId"},
                    },
                ]
            }
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://id.registrystack.org/schemas/casework/project/project.v1alpha1.schema.json",
        "title": "CaseworkProject",
        "type": "object",
        "additionalProperties": False,
        "required": ["apiVersion", "kind", "project", "queues"],
        "properties": {
            "apiVersion": {"const": "id.registrystack.org/formats/casework/project/v1alpha1"},
            "kind": {"const": "CaseworkProject"},
            "project": {"$ref": "#/$defs/ProjectIdentity"},
            "description": {"type": "string"},
            "queues": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/Queue"}},
            "clientSecretRef": {"$ref": "#/$defs/SecretReference"},
            "sourceDigest": {"$ref": "#/$defs/Digest"},
            "homepageUrl": {"$ref": "#/$defs/Url"},
            "accessProfiles": {
                "type": "object",
                "propertyNames": {"$ref": "#/$defs/LocalId"},
                "additionalProperties": {"$ref": "#/$defs/AccessProfile"},
            },
        },
        "$defs": defs,
    }


def report_schema() -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://id.registrystack.org/schemas/casework/check-report/check-report.v1alpha1.schema.json",
        "type": "object",
        "additionalProperties": False,
        "required": ["apiVersion", "kind", "ok"],
        "properties": {
            "apiVersion": {"const": "id.registrystack.org/formats/casework/check-report/v1alpha1"},
            "kind": {"const": "CaseworkCheckReport"},
            "ok": {"type": "boolean"},
        },
    }


def project_format() -> dict:
    return {
        "id": P,
        "product": "casework",
        "title": "Casework project",
        "files": ["casework.yaml"],
        "syntax": "yaml",
        "audience": "authored",
        "stability": "promised",
        "topLevel": "project",
        "current": {
            "apiVersion": "id.registrystack.org/formats/casework/project/v1alpha1",
            "kind": "CaseworkProject",
            "checkedBy": {"file": CONFIG_RS, "symbol": "CASEWORK_API_VERSION"},
        },
        "target": {
            "apiVersion": "id.registrystack.org/formats/casework/project/v1alpha1",
            "kind": "CaseworkProject",
        },
        "schema": {
            "path": PROJECT_SCHEMA,
            "id": "https://id.registrystack.org/schemas/casework/project/project.v1alpha1.schema.json",
            "origin": "generated",
            "generator": "cargo run -p registry-casework-core --example project-schema",
            "driftCheck": "products/casework/scripts/check-generated.sh",
        },
        "reader": {
            "crate": "registry-casework-core",
            "file": CONFIG_RS,
            "function": "load",
            "type": "CaseworkProject",
        },
        "check": "caseworkctl check {project}",
        "example": EXAMPLE,
        "conformance": {
            "requiredText": "/project/id",
            "optionalText": "/description",
            "integer": "/queues/0/attemptTimeoutMilliseconds",
            "boolean": "/queues/0/enabled",
        },
        "securityMembers": [{"pointer": "/accessProfiles/*/requiredScopes", "whenOmitted": "closed"}],
        "restrictingMembers": ["/accessProfiles/*/requiredScopes"],
    }


def report_format() -> dict:
    return {
        "id": R,
        "product": "casework",
        "title": "caseworkctl check report",
        "files": [],
        "syntax": "json",
        "audience": "generated",
        "stability": "promised",
        "current": {
            "apiVersion": "id.registrystack.org/formats/casework/check-report/v1alpha1",
            "kind": "CaseworkCheckReport",
            "checkedBy": "none",
        },
        "target": {
            "apiVersion": "id.registrystack.org/formats/casework/check-report/v1alpha1",
            "kind": "CaseworkCheckReport",
        },
        "schema": {
            "path": REPORT_SCHEMA,
            "id": "https://id.registrystack.org/schemas/casework/check-report/check-report.v1alpha1.schema.json",
            "origin": "hand-written",
            "differentialTest": "crates/registry-caseworkctl/tests/cli_contract.rs",
        },
        "reader": "none",
        "emittedBy": {"file": "crates/registry-caseworkctl/src/lib.rs", "symbol": "CLI_API_VERSION"},
        "check": "none",
        "example": REPORT_EXAMPLE,
        "conformance": "none",
        "securityMembers": [],
        "restrictingMembers": [],
    }


CONFIG_RS_TEXT = """\
use registry_platform_config::ProjectIdentity;
use registry_platform_yaml::from_str;
use serde::Deserialize;

pub const CASEWORK_API_VERSION: &str = "id.registrystack.org/formats/casework/project/v1alpha1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CaseworkProject {
    api_version: String,
    kind: String,
    project: ProjectIdentity,
    queues: Vec<Queue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Queue {
    id: String,
    attempt_timeout_milliseconds: Option<u32>,
    mode: QueueMode,
}

/// Queue order.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QueueMode {
    FirstCome,
    RoundRobin,
}

pub fn load(text: &str) -> Result<CaseworkProject, Error> {
    from_str(text)
}

#[cfg(test)]
mod tests {
    #[derive(serde::Deserialize)]
    struct Probe {
        #[serde(flatten)]
        rest: std::collections::BTreeSet<String>,
    }
}
"""

PLATFORM_RS_TEXT = """\
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectIdentity {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListenerConfig {
    pub bind: String,
    pub request_timeout_milliseconds: Option<u64>,
}
"""

EXAMPLE_DOC = {
    "apiVersion": "id.registrystack.org/formats/casework/project/v1alpha1",
    "kind": "CaseworkProject",
    "project": {"id": "demo", "version": "1"},
    "description": "Demo project",
    "queues": [{"id": "intake", "attemptTimeoutMilliseconds": 500, "enabled": True}],
    "accessProfiles": {"reviewer": {"requiredScopes": ["casework.review"]}},
}

CONFIGURE_TEXT = """\
SCHEMAS = {
    "casework": (
        ("products/casework/generated/project/project.schema.json", "casework.yaml"),
    ),
}
"""


class Fixture:
    """A conforming repository the tests mutate one deviation at a time."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = project_schema()
        self.report = report_schema()
        self.canonical = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "Shared runtime configuration blocks",
            "$defs": copy.deepcopy(CANONICAL_DEFS),
        }
        self.formats = [project_format(), report_format()]
        self.exceptions: list[dict] = []
        self.example = copy.deepcopy(EXAMPLE_DOC)
        self.write(CONVENTION, CONVENTION_TEXT)
        self.write("Cargo.toml", WORKSPACE_TOML)
        self.write("crates/registry-casework-core/Cargo.toml", CORE_TOML)
        self.write("crates/registry-platform-config/Cargo.toml", PLATFORM_TOML)
        self.write("crates/registry-casework-core/src/lib.rs", "pub mod config;\n")
        self.write(CONFIG_RS, CONFIG_RS_TEXT)
        self.write(PLATFORM_RS, PLATFORM_RS_TEXT)
        self.write(
            "crates/registry-caseworkctl/src/lib.rs",
            'const CLI_API_VERSION: &str = "id.registrystack.org/formats/casework/check-report/v1alpha1";\n',
        )
        self.write(
            "crates/registry-caseworkctl/tests/cli_contract.rs",
            '// reads products/casework/contracts/cli/CheckReport.schema.json\n',
        )
        self.write(
            "products/casework/scripts/check-generated.sh",
            "#!/usr/bin/env bash\ndiff -r products/casework/generated/project \"$tmp\"\n",
        )
        self.write(
            "products/platform/scripts/check-config-conformance.py",
            f'CANONICAL_SCHEMA = "{CANONICAL}"\n',
        )
        self.write("editors/configure.py", CONFIGURE_TEXT)
        self.write(
            REPORT_EXAMPLE,
            json.dumps(
                {
                    "apiVersion": "id.registrystack.org/formats/casework/check-report/v1alpha1",
                    "kind": "CaseworkCheckReport",
                    "ok": True,
                }
            ),
        )
        self.save()

    def write(self, relative: str, text: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def save(self) -> None:
        self.write(PROJECT_SCHEMA, json.dumps(self.project, indent=2))
        self.write(REPORT_SCHEMA, json.dumps(self.report, indent=2))
        self.write(CANONICAL, json.dumps(self.canonical, indent=2))
        self.write(EXAMPLE, yaml.safe_dump(self.example, sort_keys=False))
        registry = {
            "apiVersion": "id.registrystack.org/formats/platform/config-format-registry/v1alpha1",
            "kind": "PlatformConfigFormatRegistry",
            "sharedSchemas": [
                {
                    "id": "platform/runtime-config-blocks",
                    "path": CANONICAL,
                    "origin": "generated",
                    "driftCheck": "products/platform/scripts/check-config-conformance.py",
                }
            ],
            "formats": self.formats,
            "outOfScope": [
                {"files": "products/casework/contracts/*.yaml", "reason": "Repository contract records."}
            ],
        }
        self.write(REGISTRY, yaml.safe_dump(registry, sort_keys=False))
        register = {
            "apiVersion": "id.registrystack.org/formats/platform/config-conventions-exceptions/v1alpha1",
            "kind": "PlatformConfigConventionsExceptions",
            "exceptions": self.exceptions,
        }
        self.write(REGISTER, yaml.safe_dump(register, sort_keys=False))

    def fmt(self, format_id: str = P) -> dict:
        return next(entry for entry in self.formats if entry["id"] == format_id)

    def run(self, **options):
        self.save()
        return lint.run(self.root, **options)

    def main(self, *arguments: str) -> tuple[int, str, str]:
        self.save()
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = lint.main(["--root", str(self.root), *arguments])
        return code, stdout.getvalue(), stderr.getvalue()


WORKSPACE_TOML = """\
[workspace]
members = ["crates/*"]

[workspace.dependencies]
registry-platform-config = { path = "crates/registry-platform-config" }
"""
CORE_TOML = """\
[package]
name = "registry-casework-core"

[dependencies]
registry-platform-config.workspace = true
serde.workspace = true

[dev-dependencies]
registry-casework-dev-only.workspace = true
"""
PLATFORM_TOML = """\
[package]
name = "registry-platform-config"

[dependencies]
serde.workspace = true
"""


def keys(findings) -> set[tuple[str, str, str]]:
    return {(finding.rule, finding.format, finding.location) for finding in findings}


def at(path: str, pointer: str) -> str:
    return f"{path}#{pointer}"


class ConventionsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Fixture(Path(self.directory.name))

    def assertFinding(self, report, rule: str, format_id: str, location: str) -> None:
        found = keys(report.findings)
        self.assertIn((rule, format_id, location), found, "\n".join(sorted(map(str, found))))

    def assertNoFinding(self, report, rule: str) -> None:
        found = sorted(key for key in keys(report.findings) if key[0] == rule)
        self.assertEqual(found, [])

    def assertError(self, report, fragment: str) -> None:
        self.assertTrue(
            any(fragment in error for error in report.errors),
            f"{fragment!r} not in {report.errors}",
        )


class BaselineTests(ConventionsTestCase):
    def test_conforming_repository_has_no_finding_and_no_error(self) -> None:
        report = self.repo.run()
        self.assertEqual(report.errors, [])
        self.assertEqual(sorted(keys(report.findings)), [])
        code, stdout, stderr = self.repo.main()
        self.assertEqual(code, 0, stdout + stderr)
        self.assertIn("0 findings", stdout)


class RegistryAccuracyTests(ConventionsTestCase):
    """CFG-SCHEMA-1: the registry is accurate; inaccuracy is never exceptable."""

    def test_cfg_schema_1_refuses_unknown_enum_value(self) -> None:
        self.repo.fmt()["stability"] = "stable"
        self.assertError(self.repo.run(), "casework/project: stability 'stable'")

    def test_cfg_schema_1_refuses_missing_field(self) -> None:
        del self.repo.fmt()["securityMembers"]
        self.assertError(self.repo.run(), "casework/project: missing field securityMembers")

    def test_cfg_schema_1_refuses_checked_by_symbol_the_file_does_not_define(self) -> None:
        self.repo.fmt()["current"]["checkedBy"]["symbol"] = "MISSING_VERSION"
        self.assertError(self.repo.run(), "does not define MISSING_VERSION")

    def test_cfg_schema_1_refuses_checked_by_file_without_the_header_value(self) -> None:
        self.repo.fmt()["current"]["apiVersion"] = "registry.registrystack.org/casework/v1alpha1"
        self.assertError(self.repo.run(), "does not contain the current header")

    def test_cfg_schema_1_refuses_reader_function_the_file_does_not_define(self) -> None:
        self.repo.fmt()["reader"]["function"] = "parse"
        self.assertError(self.repo.run(), "does not define fn parse")

    def test_cfg_schema_1_refuses_a_build_artifact_that_is_not_generated(self) -> None:
        self.repo.fmt()["buildArtifact"] = True
        self.assertError(self.repo.run(), "casework/project: buildArtifact is only for a generated format")

    def test_cfg_schema_1_refuses_a_build_artifact_value_other_than_true(self) -> None:
        self.repo.fmt(R)["buildArtifact"] = False
        self.assertError(self.repo.run(), "casework/check-report: buildArtifact is true or absent")

    def test_cfg_schema_1_refuses_reader_type_outside_the_crate_closure(self) -> None:
        self.repo.fmt()["reader"]["type"] = "Missing"
        self.assertError(self.repo.run(), "type Missing is not defined")

    def test_cfg_schema_1_follows_type_aliases_across_crates(self) -> None:
        self.repo.write(
            CONFIG_RS, CONFIG_RS_TEXT + "\npub type Identity = registry_platform_config::ProjectIdentity;\n"
        )
        self.repo.fmt()["reader"]["type"] = "Identity"
        self.assertEqual(self.repo.run().errors, [])

    def test_cfg_schema_1_ignores_dev_dependencies_for_the_closure(self) -> None:
        self.repo.write("crates/registry-casework-dev-only/Cargo.toml", '[package]\nname = "x"\n')
        self.repo.write("crates/registry-casework-dev-only/src/lib.rs", "pub struct DevOnly {}\n")
        self.repo.write(
            "Cargo.toml",
            WORKSPACE_TOML
            + 'registry-casework-dev-only = { path = "crates/registry-casework-dev-only" }\n',
        )
        self.repo.fmt()["reader"]["type"] = "DevOnly"
        self.assertError(self.repo.run(), "type DevOnly is not defined")

    def test_cfg_schema_1_refuses_schema_id_the_file_does_not_carry(self) -> None:
        self.repo.fmt()["schema"]["id"] = "https://example.org/other.json"
        self.assertError(self.repo.run(), "$id is https://id.registrystack.org/schemas/casework/project")

    def test_cfg_schema_1_refuses_target_kind_that_does_not_derive_the_format(self) -> None:
        self.repo.fmt()["target"]["kind"] = "CaseworkProjectConfigFile"
        self.assertError(self.repo.run(), "derives format project-config-file")

    def test_cfg_schema_1_refuses_target_kind_outside_the_kind_pattern(self) -> None:
        self.repo.fmt()["target"]["kind"] = "Project"
        self.assertError(self.repo.run(), "does not match the kind pattern")

    def test_cfg_schema_1_refuses_target_version_outside_the_version_pattern(self) -> None:
        target = self.repo.fmt()["target"]
        target["apiVersion"] = "id.registrystack.org/formats/casework/project/v1.0"
        self.assertError(self.repo.run(), "version v1.0 does not match")

    def test_cfg_schema_1_refuses_a_kind_two_formats_share(self) -> None:
        self.repo.fmt(R)["target"]["kind"] = "CaseworkProject"
        self.assertError(self.repo.run(), "kind CaseworkProject is not unique")

    def test_cfg_schema_1_refuses_missing_example(self) -> None:
        self.repo.fmt()["example"] = "products/casework/examples/missing.yaml"
        self.assertError(self.repo.run(), "example products/casework/examples/missing.yaml does not exist")

    def test_cfg_check_3_refuses_conformance_member_the_example_lacks(self) -> None:
        self.repo.fmt()["conformance"]["optionalText"] = "/summary"
        self.assertError(self.repo.run(), "optionalText /summary does not resolve in the example")

    def test_cfg_check_3_refuses_conformance_member_of_the_wrong_type(self) -> None:
        self.repo.fmt()["conformance"]["integer"] = "/queues/0/enabled"
        self.assertError(self.repo.run(), "integer /queues/0/enabled is a bool in the example")

    def test_cfg_check_3_refuses_required_text_the_schema_does_not_require(self) -> None:
        self.repo.fmt()["conformance"]["requiredText"] = "/description"
        self.assertError(self.repo.run(), "requiredText /description is not required by the schema")

    def test_cfg_check_3_accepts_the_optional_shape_roles(self) -> None:
        self.repo.example["description"] = "notes.md"
        self.repo.write("products/casework/examples/demo/notes.md", "Notes.\n")
        self.repo.fmt()["conformance"].update(
            {
                "idList": "/queues",
                "set": "/accessProfiles/reviewer/requiredScopes",
                "reference": "/project/id",
                "relativePath": "/description",
                "operand": "/queues/0/attemptTimeoutMilliseconds",
            }
        )
        self.assertEqual(self.repo.run().errors, [])

    def test_cfg_check_3_refuses_an_unknown_or_missing_conformance_role(self) -> None:
        self.repo.fmt()["conformance"]["mystery"] = "/project/id"
        self.assertError(self.repo.run(), "conformance needs requiredText, optionalText, integer, boolean")
        del self.repo.fmt()["conformance"]["mystery"]
        del self.repo.fmt()["conformance"]["boolean"]
        self.assertError(self.repo.run(), "conformance needs requiredText, optionalText, integer, boolean")

    def test_cfg_id_5_refuses_an_id_list_role_that_is_not_a_list_of_named_items(self) -> None:
        self.repo.fmt()["conformance"]["idList"] = "/accessProfiles/reviewer/requiredScopes"
        self.assertError(
            self.repo.run(),
            "idList /accessProfiles/reviewer/requiredScopes is not a list of mappings with an `id` in the example",
        )

    def test_cfg_id_6_refuses_a_set_role_that_is_not_a_list_of_scalars(self) -> None:
        self.repo.fmt()["conformance"]["set"] = "/queues"
        self.assertError(self.repo.run(), "set /queues is not a list of scalars in the example")

    def test_cfg_id_4_refuses_a_reference_role_that_is_not_an_identifier(self) -> None:
        self.repo.fmt()["conformance"]["reference"] = "/description"
        self.assertError(self.repo.run(), "reference /description is not an identifier in the example")

    def test_cfg_val_8_refuses_a_relative_path_role_that_names_no_file_beside_the_example(self) -> None:
        self.repo.example["description"] = "notes.md"
        self.repo.fmt()["conformance"]["relativePath"] = "/description"
        self.assertError(self.repo.run(), "relativePath /description does not name a file in the example's directory")
        self.repo.example["description"] = "../notes.md"
        self.repo.write("products/casework/examples/notes.md", "Notes.\n")
        self.assertError(self.repo.run(), "relativePath /description does not name a file in the example's directory")

    def test_cfg_val_9_refuses_an_operand_role_that_is_text(self) -> None:
        self.repo.fmt()["conformance"]["operand"] = "/project/id"
        self.assertError(self.repo.run(), "operand /project/id is not a number or boolean in the example")

    def test_cfg_check_3_refuses_a_shape_role_the_schema_does_not_declare(self) -> None:
        self.repo.example["extraItems"] = [{"id": "first"}]
        self.repo.fmt()["conformance"]["idList"] = "/extraItems"
        self.assertError(self.repo.run(), "idList /extraItems does not resolve in the schema")

    def test_cfg_check_3_refuses_a_shape_role_the_example_lacks(self) -> None:
        self.repo.fmt()["conformance"]["set"] = "/missing"
        self.assertError(self.repo.run(), "set /missing does not resolve in the example")

    def test_cfg_empty_3_refuses_security_member_the_schema_does_not_declare(self) -> None:
        self.repo.fmt()["securityMembers"].append({"pointer": "/listener/bind", "whenOmitted": "refused"})
        self.assertError(self.repo.run(), "securityMembers /listener/bind does not resolve in the schema")

    def test_cfg_schema_1_refuses_a_schema_no_entry_registers(self) -> None:
        self.repo.write("products/casework/generated/runtime/runtime.schema.json", "{}")
        self.assertError(self.repo.run(), "products/casework/generated/runtime/runtime.schema.json is not registered")

    def test_cfg_schema_1_accepts_a_schema_out_of_scope(self) -> None:
        self.repo.write("products/casework/contracts/records.schema.yaml", "{}")
        self.assertEqual(self.repo.run().errors, [])

    def test_cfg_schema_1_refuses_an_out_of_scope_glob_over_a_registered_schema(self) -> None:
        self.repo.write("products/casework/contracts/records.schema.yaml", "{}")
        self.repo.fmt(R)["schema"]["path"] = "products/casework/contracts/records.schema.yaml"
        self.assertError(self.repo.run(), "outOfScope products/casework/contracts/*.yaml matches")

    def test_cfg_schema_1_refuses_drift_check_that_does_not_name_the_schema(self) -> None:
        self.repo.write("products/casework/scripts/check-generated.sh", "#!/usr/bin/env bash\ntrue\n")
        self.assertError(self.repo.run(), "driftCheck products/casework/scripts/check-generated.sh does not name")


class EnvelopeTests(ConventionsTestCase):
    def test_cfg_env_1_reports_a_missing_header_once(self) -> None:
        current = self.repo.fmt()["current"]
        current.update(apiVersion="none", kind="none", checkedBy="none")
        report = self.repo.run()
        self.assertFinding(report, "CFG-ENV-1", P, at(REGISTRY, "/current/apiVersion"))
        self.assertFinding(report, "CFG-ENV-1", P, at(REGISTRY, "/current/kind"))
        self.assertNoFinding(report, "CFG-ENV-2")
        self.assertNoFinding(report, "CFG-ENV-3")

    def test_cfg_env_1_reports_a_schema_without_const_envelope(self) -> None:
        self.repo.project["properties"]["kind"] = {"type": "string"}
        self.assertFinding(self.repo.run(), "CFG-ENV-1", P, at(PROJECT_SCHEMA, "/properties/kind"))

    def test_cfg_env_1_reports_a_schema_that_does_not_require_the_envelope(self) -> None:
        for member in ("apiVersion", "kind"):
            with self.subTest(member=member):
                self.setUp()
                self.repo.project["required"].remove(member)
                report = self.repo.run()
                self.assertFinding(report, "CFG-ENV-1", P, at(PROJECT_SCHEMA, "/required"))
                self.assertEqual(
                    [finding.message for finding in report.findings if finding.rule == "CFG-ENV-1"],
                    [f"the schema does not require {member}"],
                )

    def test_cfg_env_1_resolves_a_composed_root_schema(self) -> None:
        root = self.repo.project
        defs = root.pop("$defs")
        body = {key: root.pop(key) for key in ("type", "additionalProperties", "required", "properties")}
        defs["Document"] = body
        root["$ref"] = "#/$defs/Document"
        root["$defs"] = defs
        report = self.repo.run()
        self.assertNoFinding(report, "CFG-ENV-1")
        self.assertNoFinding(report, "CFG-ENV-6")

    def test_cfg_env_2_reports_a_legacy_api_version(self) -> None:
        current = self.repo.fmt()["current"]
        current["apiVersion"] = "registry.registrystack.org/casework/v1alpha1"
        self.repo.write(CONFIG_RS, CONFIG_RS_TEXT.replace(
            "id.registrystack.org/formats/casework/project/v1alpha1",
            "registry.registrystack.org/casework/v1alpha1"))
        self.repo.project["properties"]["apiVersion"]["const"] = current["apiVersion"]
        self.repo.example["apiVersion"] = current["apiVersion"]
        self.assertFinding(self.repo.run(), "CFG-ENV-2", P, at(REGISTRY, "/current/apiVersion"))

    def test_cfg_env_3_reports_a_kind_other_than_the_target(self) -> None:
        self.repo.fmt(R)["current"]["kind"] = "CheckReport"
        self.repo.report["properties"]["kind"]["const"] = "CheckReport"
        self.assertFinding(self.repo.run(), "CFG-ENV-3", R, at(REGISTRY, "/current/kind"))

    def test_cfg_env_6_reports_a_project_block_without_identity(self) -> None:
        self.repo.project["properties"]["casework"] = self.repo.project["properties"].pop("project")
        self.repo.example["casework"] = self.repo.example.pop("project")
        self.repo.fmt()["conformance"]["requiredText"] = "/casework/id"
        self.assertFinding(self.repo.run(), "CFG-ENV-6", P, at(REGISTRY, "/topLevel"))

    def test_cfg_env_6_reports_a_project_kind_not_ending_in_project(self) -> None:
        self.repo.fmt()["current"]["kind"] = "CaseworkPolicyPackage"
        self.repo.project["properties"]["kind"]["const"] = "CaseworkPolicyPackage"
        report = self.repo.run()
        self.assertFinding(report, "CFG-ENV-6", P, at(REGISTRY, "/current/kind"))
        self.assertFinding(report, "CFG-ENV-3", P, at(REGISTRY, "/current/kind"))


class NameTests(ConventionsTestCase):
    def queue(self) -> dict:
        return self.repo.project["$defs"]["Queue"]["properties"]

    def test_cfg_name_1_reports_a_key_outside_camel_case(self) -> None:
        self.queue()["display_name"] = {"type": "string"}
        self.assertFinding(
            self.repo.run(), "CFG-NAME-1", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/display_name")
        )

    def test_cfg_name_1_reports_an_acronym_written_in_capitals(self) -> None:
        self.queue()["sourceURL"] = {"$ref": "#/$defs/Url"}
        self.assertFinding(
            self.repo.run(), "CFG-NAME-1", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/sourceURL")
        )

    def test_cfg_name_1_skips_the_keys_of_a_property_names_map(self) -> None:
        self.repo.project["$defs"]["Labels"] = {
            "type": "object",
            "propertyNames": {"$ref": "#/$defs/ExternalId"},
            "properties": {"x-Custom_Label": {"type": "string"}},
            "additionalProperties": {"type": "string"},
        }
        self.assertNoFinding(self.repo.run(), "CFG-NAME-1")

    def test_cfg_name_2_reports_an_enum_value_outside_kebab_case(self) -> None:
        self.queue()["mode"]["enum"] = ["FirstCome", "round-robin"]
        self.queue()["mode"]["default"] = "round-robin"
        self.assertFinding(
            self.repo.run(), "CFG-NAME-2", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/mode/enum/FirstCome")
        )

    def test_cfg_name_2_accepts_dotted_kebab_codes(self) -> None:
        self.queue()["code"] = {"const": "casework.check.unknown-key"}
        self.assertNoFinding(self.repo.run(), "CFG-NAME-2")

    def test_cfg_name_2_skips_prose_constants_and_reads_paths_by_segment(self) -> None:
        self.queue()["effect"] = {"const": "refuse the package at load"}
        self.queue()["jwksPath"] = {"const": "/.well-known/evidence/jwks.json"}
        self.assertNoFinding(self.repo.run(), "CFG-NAME-2")

    def test_cfg_name_2_accepts_a_command_written_as_typed(self) -> None:
        self.queue()["command"] = {"const": "attempt mark-uncertain"}
        self.assertNoFinding(self.repo.run(), "CFG-NAME-2")

    def test_cfg_name_2_reads_a_command_word_by_word_and_only_under_command(self) -> None:
        self.queue()["command"] = {"enum": ["source add", "source_add now"]}
        self.queue()["action"] = {"const": "source add"}
        report = self.repo.run()
        self.assertFinding(
            report, "CFG-NAME-2", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/command/enum/source_add now")
        )
        self.assertFinding(report, "CFG-NAME-2", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/action/const/source add"))
        names = {key[2] for key in keys(report.findings) if key[0] == "CFG-NAME-2"}
        self.assertEqual(len(names), 2, names)

    def test_cfg_name_2_skips_member_name_enums_and_envelope_constants(self) -> None:
        self.queue()["select"] = {
            "type": "string",
            "enum": ["givenName", "familyName"],
            "x-registry-member-names": True,
        }
        report = self.repo.run()
        self.assertNoFinding(report, "CFG-NAME-2")

    def test_cfg_name_3_reports_max_and_limit_spellings(self) -> None:
        self.queue()["maxItems"] = {"type": "integer", "minimum": 1, "maximum": 10}
        self.queue()["itemLimit"] = {"type": "integer", "minimum": 1, "maximum": 10}
        self.queue()["minLength"] = {"type": "integer", "minimum": 1, "maximum": 10}
        report = self.repo.run()
        for key in ("maxItems", "itemLimit", "minLength"):
            self.assertFinding(report, "CFG-NAME-3", P, at(PROJECT_SCHEMA, f"/$defs/Queue/properties/{key}"))

    def test_cfg_name_4_reports_a_duration_without_its_unit(self) -> None:
        self.queue()["cacheTtl"] = {"type": "integer", "minimum": 1, "maximum": 10}
        self.queue()["pollIntervalMs"] = {"type": "integer", "minimum": 1, "maximum": 10}
        report = self.repo.run()
        self.assertFinding(report, "CFG-NAME-4", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/cacheTtl"))
        self.assertFinding(report, "CFG-NAME-4", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/pollIntervalMs"))

    def test_cfg_name_4_accepts_a_count_without_a_unit(self) -> None:
        self.queue()["maximumAttempts"] = {"type": "integer", "minimum": 1, "maximum": 10}
        self.assertNoFinding(self.repo.run(), "CFG-NAME-4")

    def test_cfg_name_5_reports_a_refused_spelling_once(self) -> None:
        self.queue()["maxAttempts"] = {"type": "integer", "minimum": 1, "maximum": 10}
        report = self.repo.run()
        self.assertFinding(report, "CFG-NAME-5", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/maxAttempts"))
        self.assertNoFinding(report, "CFG-NAME-3")

    def test_cfg_name_5_reads_the_contextual_refusals(self) -> None:
        self.queue()["requestTimeoutMilliseconds"] = {"type": "integer", "minimum": 1, "maximum": 10}
        self.queue()["retention"] = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "terminalDays": {"type": "integer", "minimum": 1, "maximum": 10},
                "retentionDays": {"type": "integer", "minimum": 1, "maximum": 10},
            },
        }
        report = self.repo.run()
        self.assertFinding(
            report, "CFG-NAME-5", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/requestTimeoutMilliseconds")
        )
        self.assertFinding(
            report,
            "CFG-NAME-5",
            P,
            at(PROJECT_SCHEMA, "/$defs/Queue/properties/retention/properties/terminalDays"),
        )
        names = {key[2] for key in keys(report.findings) if key[0] == "CFG-NAME-5"}
        self.assertEqual(len(names), 2, names)

    def test_cfg_name_5_leaves_a_pool_size_to_the_bound_rule(self) -> None:
        self.queue()["maxSize"] = {"type": "integer", "minimum": 1, "maximum": 10}
        self.queue()["pool"] = {
            "type": "object",
            "additionalProperties": False,
            "properties": {"maxSize": {"type": "integer", "minimum": 1, "maximum": 10}},
        }
        report = self.repo.run()
        plain = at(PROJECT_SCHEMA, "/$defs/Queue/properties/maxSize")
        pooled = at(PROJECT_SCHEMA, "/$defs/Queue/properties/pool/properties/maxSize")
        self.assertFinding(report, "CFG-NAME-5", P, plain)
        self.assertFinding(report, "CFG-NAME-3", P, pooled)
        names = {key[2] for key in keys(report.findings) if key[0] == "CFG-NAME-5"}
        self.assertEqual(names, {plain}, names)

    def test_cfg_name_5_follows_the_convention_table(self) -> None:
        self.queue()["deliveryWindowHours"] = {"type": "integer", "minimum": 1, "maximum": 10}
        self.assertNoFinding(self.repo.run(), "CFG-NAME-5")
        self.repo.write(
            CONVENTION,
            CONVENTION_TEXT.replace(
                "| Cache | `cacheTtlSeconds` | |",
                "| Cache | `cacheTtlSeconds` | |\n| Window | `deliveryWindowMinutes` | `deliveryWindowHours` |",
            ),
        )
        self.assertFinding(
            self.repo.run(), "CFG-NAME-5", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/deliveryWindowHours")
        )

    def test_cfg_name_5_refuses_to_run_without_the_table(self) -> None:
        self.repo.write(CONVENTION, CONVENTION_TEXT.replace("Refused spellings (lint)", "Refused"))
        self.assertError(self.repo.run(), "CFG-NAME-5 table")


class IdentifierTests(ConventionsTestCase):
    def test_cfg_id_1_reports_an_id_without_the_local_id_type(self) -> None:
        self.repo.project["$defs"]["Queue"]["properties"]["id"] = {"type": "string"}
        self.assertFinding(self.repo.run(), "CFG-ID-1", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/id"))

    def test_cfg_id_1_reports_a_map_without_typed_keys(self) -> None:
        del self.repo.project["properties"]["accessProfiles"]["propertyNames"]
        self.assertFinding(self.repo.run(), "CFG-ID-1", P, at(PROJECT_SCHEMA, "/properties/accessProfiles"))

    def test_cfg_id_1_accepts_a_foreign_map(self) -> None:
        self.repo.project["properties"]["headers"] = {
            "type": "object",
            "x-registry-foreign": "openapi-3.1",
            "additionalProperties": {"type": "string"},
        }
        self.assertNoFinding(self.repo.run(), "CFG-ID-1")

    def test_cfg_id_6_reports_a_set_of_values_without_unique_items(self) -> None:
        self.repo.project["$defs"]["Queue"]["properties"]["modes"] = {
            "type": "array",
            "items": {"type": "string", "enum": ["first-come", "round-robin"]},
        }
        self.assertFinding(self.repo.run(), "CFG-ID-6", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/modes"))

    def union(self, branches: list, keyword: str = "oneOf") -> None:
        self.repo.project["$defs"]["Queue"]["properties"]["source"] = {keyword: branches}

    def variant(self, tag: str, value: str, extra: str) -> dict:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": [tag, extra],
            "properties": {tag: {"const": value}, extra: {"type": "string"}},
        }

    def test_cfg_id_7_accepts_a_union_tagged_by_type(self) -> None:
        self.union([self.variant("type", "file", "path"), self.variant("type", "inline", "text")])
        self.assertNoFinding(self.repo.run(), "CFG-ID-7")

    def test_cfg_id_7_reports_a_union_tagged_by_another_member(self) -> None:
        self.union([self.variant("kind", "file", "path"), self.variant("kind", "inline", "text")])
        self.assertFinding(self.repo.run(), "CFG-ID-7", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/source"))

    def test_cfg_id_7_accepts_the_command_report_envelope_tagged_by_ok(self) -> None:
        self.union([self.variant("ok", True, "result"), self.variant("ok", False, "error")])
        self.assertNoFinding(self.repo.run(), "CFG-ID-7")

    def test_cfg_id_7_reports_an_ok_member_that_is_not_the_boolean_envelope(self) -> None:
        self.union([self.variant("ok", "yes", "result"), self.variant("ok", "no", "error")])
        self.assertFinding(self.repo.run(), "CFG-ID-7", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/source"))

    def test_cfg_id_7_reports_a_boolean_tag_with_another_name(self) -> None:
        self.union([self.variant("done", True, "result"), self.variant("done", False, "error")])
        self.assertFinding(self.repo.run(), "CFG-ID-7", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/source"))

    def test_cfg_id_7_accepts_single_key_mappings(self) -> None:
        single = lambda name: {  # noqa: E731
            "type": "object",
            "additionalProperties": False,
            "required": [name],
            "properties": {name: {"type": "string"}},
        }
        self.union([single("file"), single("inline")])
        self.assertNoFinding(self.repo.run(), "CFG-ID-7")

    def test_cfg_id_7_accepts_exactly_one_of_two_members_written_as_required_branches(self) -> None:
        queue = self.repo.project["$defs"]["Queue"]
        queue["properties"]["file"] = {"type": "string"}
        queue["properties"]["inline"] = {"type": "string"}
        queue["oneOf"] = [{"required": ["file"]}, {"required": ["inline"]}]
        self.assertNoFinding(self.repo.run(), "CFG-ID-7")

    def test_cfg_id_7_reports_required_branches_that_each_require_two_members(self) -> None:
        queue = self.repo.project["$defs"]["Queue"]
        for name in ("file", "inline", "path", "text"):
            queue["properties"][name] = {"type": "string"}
        queue["oneOf"] = [{"required": ["file", "path"]}, {"required": ["inline", "text"]}]
        self.assertFinding(self.repo.run(), "CFG-ID-7", P, at(PROJECT_SCHEMA, "/$defs/Queue"))

    def test_cfg_id_7_reports_unit_variants_mixed_with_struct_variants(self) -> None:
        self.union([{"type": "string", "enum": ["none"]}, self.variant("type", "file", "path")])
        self.assertFinding(self.repo.run(), "CFG-ID-7", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/source"))

    def test_cfg_id_7_accepts_none_beside_an_untagged_single_key_mapping(self) -> None:
        elapsed = {
            "type": "object",
            "additionalProperties": False,
            "required": ["elapsedMinutes"],
            "properties": {"elapsedMinutes": {"type": "integer", "minimum": 1, "maximum": 10}},
        }
        self.union([{"type": "string", "enum": ["none"]}, elapsed], "anyOf")
        self.assertNoFinding(self.repo.run(), "CFG-ID-7")
        self.union([{"type": "string", "enum": ["never"]}, elapsed], "anyOf")
        self.assertFinding(self.repo.run(), "CFG-ID-7", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/source"))

    def test_cfg_id_7_reports_an_untagged_union_of_one_node_kind(self) -> None:
        plain = {"type": "object", "additionalProperties": False, "properties": {"path": {"type": "string"}}}
        other = {"type": "object", "additionalProperties": False, "properties": {"text": {"type": "string"}}}
        self.union([plain, other], "anyOf")
        self.assertFinding(self.repo.run(), "CFG-ID-7", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/source"))

    def test_cfg_id_7_accepts_an_any_of_that_only_requires_one_of_its_members(self) -> None:
        self.repo.project["properties"]["tls"] = {
            "type": "object",
            "additionalProperties": False,
            "properties": {"caBundleRef": {"type": "string"}, "clientIdentityRef": {"type": "string"}},
            "anyOf": [{"required": ["caBundleRef"]}, {"required": ["clientIdentityRef"]}],
        }
        self.assertNoFinding(self.repo.run(), "CFG-ID-7")

    def test_cfg_id_7_accepts_an_exclusive_choice_of_one_member_as_a_single_key_mapping(self) -> None:
        self.repo.project["properties"]["credential"] = {
            "type": "object",
            "additionalProperties": False,
            "properties": {"tokenRef": {"type": "string"}, "privateKeyJwt": {"type": "string"}},
            "oneOf": [{"required": ["tokenRef"]}, {"required": ["privateKeyJwt"]}],
        }
        self.assertNoFinding(self.repo.run(), "CFG-ID-7")

    def test_cfg_id_7_accepts_an_untagged_union_of_distinct_node_kinds_and_nullables(self) -> None:
        self.union([{"type": "string"}, {"type": "array", "uniqueItems": True, "items": {"type": "string"}}])
        self.repo.project["properties"]["note"] = {"anyOf": [{"type": "string"}, {"type": "null"}]}
        self.assertNoFinding(self.repo.run(), "CFG-ID-7")


class QuantityTests(ConventionsTestCase):
    def queue(self) -> dict:
        return self.repo.project["$defs"]["Queue"]["properties"]

    def test_cfg_qty_1_reports_a_duration_string(self) -> None:
        self.queue()["targetElapsed"] = {"type": "string", "pattern": "^PT[0-9]+H$"}
        self.assertFinding(
            self.repo.run(), "CFG-QTY-1", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/targetElapsed")
        )

    def test_cfg_qty_2_reports_the_minority_unit_of_a_stem(self) -> None:
        self.queue()["pollSeconds"] = {"type": "integer", "minimum": 1, "maximum": 10}
        self.repo.project["properties"]["pollSeconds"] = {"type": "integer", "minimum": 1, "maximum": 10}
        self.repo.project["properties"]["pollMinutes"] = {"type": "integer", "minimum": 1, "maximum": 10}
        report = self.repo.run()
        self.assertFinding(report, "CFG-QTY-2", P, at(PROJECT_SCHEMA, "/properties/pollMinutes"))
        self.assertEqual(len([key for key in keys(report.findings) if key[0] == "CFG-QTY-2"]), 1)

    def test_cfg_qty_3_reports_a_size_written_as_text(self) -> None:
        self.queue()["maximumBodyBytes"] = {"type": "string", "pattern": "^[0-9]+(KB|MB)$"}
        self.assertFinding(
            self.repo.run(), "CFG-QTY-3", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/maximumBodyBytes")
        )

    def test_cfg_qty_4_reports_an_integer_without_both_bounds(self) -> None:
        self.queue()["attemptTimeoutMilliseconds"] = {"type": "integer", "format": "uint32", "minimum": 0}
        self.assertFinding(
            self.repo.run(),
            "CFG-QTY-4",
            P,
            at(PROJECT_SCHEMA, "/$defs/Queue/properties/attemptTimeoutMilliseconds"),
        )

    def test_cfg_qty_4_reports_an_unsigned_type_s_own_range_as_unstated(self) -> None:
        self.queue()["retryCount"] = {"type": "integer", "format": "uint16", "minimum": 0, "maximum": 65535}
        self.assertFinding(self.repo.run(), "CFG-QTY-4", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/retryCount"))

    def test_cfg_qty_4_accepts_a_bounded_type_whose_stated_minimum_is_zero(self) -> None:
        self.queue()["leewayMilliseconds"] = {"type": "integer", "format": "uint64", "minimum": 0, "maximum": 300000}
        self.assertNoFinding(self.repo.run(), "CFG-QTY-4")


class ValueTests(ConventionsTestCase):
    def test_cfg_val_6_reports_a_digest_without_the_digest_type(self) -> None:
        self.repo.project["properties"]["sourceDigest"] = {"type": "string"}
        self.assertFinding(self.repo.run(), "CFG-VAL-6", P, at(PROJECT_SCHEMA, "/properties/sourceDigest"))

    def test_cfg_val_7_reports_a_url_without_the_url_type(self) -> None:
        self.repo.project["properties"]["homepageUrl"] = {"type": "string", "format": "uri"}
        self.assertFinding(self.repo.run(), "CFG-VAL-7", P, at(PROJECT_SCHEMA, "/properties/homepageUrl"))

    def test_cfg_val_7_reports_an_issuer_without_the_url_type(self) -> None:
        self.repo.project["properties"]["issuer"] = {"type": "string", "minLength": 1}
        self.assertFinding(self.repo.run(), "CFG-VAL-7", P, at(PROJECT_SCHEMA, "/properties/issuer"))

    def test_cfg_val_7_leaves_uri_identifiers_and_non_text_members(self) -> None:
        self.repo.project["properties"]["conceptUri"] = {"type": "string", "format": "uri"}
        self.repo.project["properties"]["evidenceType"] = {"type": "string", "format": "uri"}
        self.repo.project["properties"]["valueOrigin"] = {"type": "string", "enum": ["claim", "request"]}
        self.repo.project["properties"]["callbackUrl"] = {"type": "object", "properties": {}}
        self.assertNoFinding(self.repo.run(), "CFG-VAL-7")


class EmptyTests(ConventionsTestCase):
    def scopes(self) -> dict:
        return self.repo.project["$defs"]["AccessProfile"]["properties"]["requiredScopes"]

    def test_cfg_empty_2_reports_a_sentinel_list_that_accepts_empty(self) -> None:
        del self.scopes()["anyOf"][1]["minItems"]
        self.assertFinding(
            self.repo.run(),
            "CFG-EMPTY-2",
            P,
            at(PROJECT_SCHEMA, "/$defs/AccessProfile/properties/requiredScopes"),
        )

    def test_cfg_empty_2_reports_a_restricting_member_that_defaults_to_empty(self) -> None:
        self.repo.project["$defs"]["AccessProfile"]["properties"]["requiredScopes"] = {
            "type": "array",
            "uniqueItems": True,
            "default": [],
            "items": {"$ref": "#/$defs/ExternalId"},
        }
        self.assertFinding(
            self.repo.run(),
            "CFG-EMPTY-2",
            P,
            at(PROJECT_SCHEMA, "/$defs/AccessProfile/properties/requiredScopes"),
        )

    def test_cfg_empty_1_reports_a_member_that_accepts_null_through_data_literal(self) -> None:
        self.repo.project["$defs"]["DataLiteral"] = {"type": ["null", "boolean", "number", "string"]}
        self.repo.project["properties"]["afterEquals"] = {
            "type": "object",
            "propertyNames": {"$ref": "#/$defs/LocalId"},
            "additionalProperties": {"$ref": "#/$defs/DataLiteral"},
        }
        report = self.repo.run()
        self.assertFinding(report, "CFG-EMPTY-1", P, at(PROJECT_SCHEMA, "/properties/afterEquals/additionalProperties"))
        self.assertNotIn(("CFG-EMPTY-1", P, at(PROJECT_SCHEMA, "/$defs/DataLiteral")), keys(report.findings))

    def test_cfg_empty_4_reports_a_null_default(self) -> None:
        self.repo.project["properties"]["description"]["default"] = None
        self.assertFinding(self.repo.run(), "CFG-EMPTY-4", P, at(PROJECT_SCHEMA, "/properties/description"))

    def test_cfg_empty_4_reports_a_default_its_schema_refuses(self) -> None:
        self.repo.project["properties"]["queues"]["default"] = []
        self.repo.project["$defs"]["Queue"]["properties"]["mode"]["default"] = "lifo"
        report = self.repo.run()
        self.assertFinding(report, "CFG-EMPTY-4", P, at(PROJECT_SCHEMA, "/properties/queues"))
        self.assertFinding(report, "CFG-EMPTY-4", P, at(PROJECT_SCHEMA, "/$defs/Queue/properties/mode"))


class SecretTests(ConventionsTestCase):
    def test_cfg_sec_1_reports_inline_secrets_key_files_and_untyped_references(self) -> None:
        properties = self.repo.project["properties"]
        properties["clientSecret"] = {"type": "string"}
        properties["privateKeyFile"] = {"type": "string"}
        properties["tokenRef"] = {"type": "string"}
        properties["credential"] = {"$ref": "#/$defs/SecretReference"}
        report = self.repo.run()
        for key in ("clientSecret", "privateKeyFile", "tokenRef", "credential"):
            self.assertFinding(report, "CFG-SEC-1", P, at(PROJECT_SCHEMA, f"/properties/{key}"))

    def test_cfg_sec_1_allows_a_key_file_path_in_a_report_nothing_reads(self) -> None:
        self.repo.report["properties"]["assertionKeyFile"] = {"type": "string"}
        self.repo.report["properties"]["clientSecret"] = {"type": "string"}
        report = self.repo.run()
        self.assertNotIn(
            ("CFG-SEC-1", R, at(REPORT_SCHEMA, "/properties/assertionKeyFile")), keys(report.findings)
        )
        self.assertFinding(report, "CFG-SEC-1", R, at(REPORT_SCHEMA, "/properties/clientSecret"))


class EmbedTests(ConventionsTestCase):
    def test_cfg_embed_2_reports_an_unmarked_embedded_schema(self) -> None:
        self.repo.project["properties"]["dataSchema"] = {"type": "object"}
        self.assertFinding(self.repo.run(), "CFG-EMBED-2", P, at(PROJECT_SCHEMA, "/properties/dataSchema"))

    def test_cfg_embed_2_skips_the_interior_of_a_marked_member(self) -> None:
        self.repo.project["properties"]["dataSchema"] = {
            "type": "object",
            "x-registry-foreign": "json-schema-2020-12",
            "properties": {"min_length": {"type": "integer"}},
        }
        report = self.repo.run()
        self.assertNoFinding(report, "CFG-EMBED-2")
        self.assertNoFinding(report, "CFG-NAME-1")
        self.assertNoFinding(report, "CFG-QTY-4")
        self.assertNoFinding(report, "CFG-SCHEMA-4")


class SchemaTests(ConventionsTestCase):
    def test_cfg_schema_1_reports_a_read_format_without_an_example(self) -> None:
        entry = self.repo.fmt()
        entry["example"] = "none"
        entry["conformance"] = {key: "none" for key in entry["conformance"]}
        self.assertFinding(self.repo.run(), "CFG-SCHEMA-1", P, at(REGISTRY, "/example"))

    def test_cfg_schema_1_reports_an_output_format_without_an_example(self) -> None:
        self.repo.fmt(R)["example"] = "none"
        self.assertFinding(self.repo.run(), "CFG-SCHEMA-1", R, at(REGISTRY, "/example"))

    def test_cfg_schema_2_reports_an_authored_format_without_a_generated_schema(self) -> None:
        self.repo.fmt()["schema"]["origin"] = "hand-written"
        self.repo.fmt()["schema"].pop("generator")
        self.repo.fmt()["schema"]["differentialTest"] = self.repo.fmt()["schema"].pop("driftCheck")
        self.assertFinding(self.repo.run(), "CFG-SCHEMA-2", P, at(REGISTRY, "/schema"))

    def test_cfg_schema_2_exempts_output_formats(self) -> None:
        self.assertNoFinding(self.repo.run(), "CFG-SCHEMA-2")

    def test_cfg_schema_3_reports_an_id_outside_the_pattern(self) -> None:
        wrong = "https://id.registrystack.org/schemas/casework/authoring/casework.v1alpha1.schema.json"
        self.repo.project["$id"] = wrong
        self.repo.fmt()["schema"]["id"] = wrong
        self.assertFinding(self.repo.run(), "CFG-SCHEMA-3", P, at(PROJECT_SCHEMA, "/$id"))

    def test_cfg_schema_4_reports_an_open_object(self) -> None:
        del self.repo.project["$defs"]["Queue"]["additionalProperties"]
        self.assertFinding(self.repo.run(), "CFG-SCHEMA-4", P, at(PROJECT_SCHEMA, "/$defs/Queue"))

    def test_cfg_schema_4_reports_spread_members_without_unevaluated_properties(self) -> None:
        self.repo.project["$defs"]["Queue"]["allOf"] = [
            {"properties": {"priority": {"type": "integer", "minimum": 1, "maximum": 9}}}
        ]
        self.assertFinding(self.repo.run(), "CFG-SCHEMA-4", P, at(PROJECT_SCHEMA, "/$defs/Queue"))

    def test_cfg_schema_4_accepts_spread_members_under_unevaluated_properties(self) -> None:
        queue = self.repo.project["$defs"]["Queue"]
        del queue["additionalProperties"]
        queue["unevaluatedProperties"] = False
        queue["allOf"] = [{"properties": {"priority": {"type": "integer", "minimum": 1, "maximum": 9}}}]
        self.assertNoFinding(self.repo.run(), "CFG-SCHEMA-4")

    def test_cfg_schema_4_accepts_a_passthrough_with_a_reason(self) -> None:
        self.repo.report["properties"]["details"] = {
            "type": "object",
            "x-registry-passthrough": "The compiled model the command serializes as it stands.",
        }
        self.assertNoFinding(self.repo.run(), "CFG-SCHEMA-4")

    def test_cfg_schema_4_accepts_a_passthrough_in_an_unpromised_format(self) -> None:
        self.repo.fmt()["stability"] = "experimental"
        queue = self.repo.project["$defs"]["Queue"]
        del queue["additionalProperties"]
        queue["x-registry-passthrough"] = "Queue options a later version describes."
        self.assertNoFinding(self.repo.run(), "CFG-SCHEMA-4")

    def test_cfg_schema_4_refuses_a_passthrough_without_a_reason(self) -> None:
        self.repo.report["properties"]["details"] = {"type": "object", "x-registry-passthrough": " "}
        report = self.repo.run()
        self.assertFinding(report, "CFG-SCHEMA-4", R, at(REPORT_SCHEMA, "/properties/details"))
        finding = next(item for item in report.findings if item.location == at(REPORT_SCHEMA, "/properties/details"))
        self.assertIn("x-registry-passthrough", finding.message)

    def test_cfg_schema_4_refuses_a_passthrough_in_a_promised_format_its_product_reads(self) -> None:
        queue = self.repo.project["$defs"]["Queue"]
        del queue["additionalProperties"]
        queue["x-registry-passthrough"] = "Queue options a later version describes."
        report = self.repo.run()
        self.assertFinding(report, "CFG-SCHEMA-4", P, at(PROJECT_SCHEMA, "/$defs/Queue"))
        finding = next(item for item in report.findings if item.location == at(PROJECT_SCHEMA, "/$defs/Queue"))
        self.assertIn("promised", finding.message)

    def test_cfg_schema_4_exempts_conditional_branches(self) -> None:
        self.repo.project["$defs"]["Queue"]["if"] = {"properties": {"mode": {"const": "first-come"}}}
        self.repo.project["$defs"]["Queue"]["then"] = {"required": ["enabled"]}
        self.assertNoFinding(self.repo.run(), "CFG-SCHEMA-4")

    def test_cfg_schema_5_reports_a_product_copy_of_a_shared_block(self) -> None:
        self.repo.project["$defs"]["RawListenerConfig"] = copy.deepcopy(CANONICAL_DEFS["ListenerConfig"])
        changed = copy.deepcopy(CANONICAL_DEFS["ProjectIdentity"])
        changed["properties"]["version"]["maxLength"] = 99
        self.repo.project["$defs"]["ProjectIdentity"] = changed
        report = self.repo.run()
        self.assertFinding(report, "CFG-SCHEMA-5", P, at(PROJECT_SCHEMA, "/$defs/RawListenerConfig"))
        self.assertFinding(report, "CFG-SCHEMA-5", P, at(PROJECT_SCHEMA, "/$defs/ProjectIdentity"))

    def test_cfg_schema_6_reports_a_format_editors_do_not_map(self) -> None:
        self.repo.write("editors/configure.py", "SCHEMAS = {}\n")
        self.assertFinding(self.repo.run(), "CFG-SCHEMA-6", P, at("editors/configure.py", "/SCHEMAS/casework"))

    def test_cfg_schema_6_reports_a_registered_file_pattern_editors_do_not_map(self) -> None:
        self.repo.fmt()["files"] = ["casework.yaml", "casework-test.yaml", "queues/*.yaml"]
        report = self.repo.run()
        self.assertFinding(report, "CFG-SCHEMA-6", P, at(REGISTRY, "/files/1"))
        self.assertFinding(report, "CFG-SCHEMA-6", P, at(REGISTRY, "/files/2"))
        self.assertEqual(len([key for key in keys(report.findings) if key[0] == "CFG-SCHEMA-6"]), 2)

    def test_cfg_schema_6_reports_a_mapping_narrower_than_the_registered_pattern(self) -> None:
        for registered, mapped in (
            ("*.casework.yaml", "intake*.casework.yaml"),
            ("queues/casework.yaml", "casework.yaml"),
            ("*/casework.yaml", "queues/casework.yaml"),
        ):
            with self.subTest(registered=registered, mapped=mapped):
                self.setUp()
                self.repo.fmt()["files"] = ["casework.yaml", registered]
                self.repo.write("editors/configure.py", CONFIGURE_TEXT.replace(
                    '"casework.yaml"),', f'"casework.yaml"),\n        ("{PROJECT_SCHEMA}", "{mapped}"),'))
                self.assertFinding(self.repo.run(), "CFG-SCHEMA-6", P, at(REGISTRY, "/files/1"))

    def test_cfg_schema_6_accepts_a_mapping_that_covers_the_registered_pattern(self) -> None:
        for registered, mapped in (
            ("casework.yaml", "**/casework.yaml"),
            ("casework.yaml", "project/casework.yaml"),
            ("casework.yaml", "{document}"),
            ("casework.yaml", "case*.yaml"),
            ("queues/*/casework.yaml", "queues/**/casework.yaml"),
            ("queues/*.yaml", "queues/*.yaml"),
        ):
            with self.subTest(registered=registered, mapped=mapped):
                self.setUp()
                self.repo.fmt()["files"] = [registered]
                self.repo.write("editors/configure.py", CONFIGURE_TEXT.replace('"casework.yaml"),', f'"{mapped}"),'))
                self.assertNoFinding(self.repo.run(), "CFG-SCHEMA-6")

    def test_cfg_schema_6_holds_a_schema_the_adopter_tool_maps_to_its_own_pattern(self) -> None:
        self.repo.write("editors/configure.py", "SCHEMAS = {}\n")
        catalog = (
            'EditorSchema {{\n    filename: "project.schema.json",\n    file_glob: "{glob}",\n'
            '    document: include_str!("../../../{schema}"),\n}},\n'
        )
        self.repo.write("crates/registry-evidencectl/src/tooling_editor.rs",
                        catalog.format(glob="casework.yaml", schema=PROJECT_SCHEMA))
        self.assertNoFinding(self.repo.run(), "CFG-SCHEMA-6")
        self.repo.write("crates/registry-evidencectl/src/tooling_editor.rs",
                        catalog.format(glob="questions/*.yml", schema=PROJECT_SCHEMA))
        self.assertFinding(self.repo.run(), "CFG-SCHEMA-6", P, at(REGISTRY, "/files/0"))

    def test_cfg_schema_6_and_2_exempt_read_back_formats(self) -> None:
        state = copy.deepcopy(project_format())
        state.update(
            id="casework/dev-state",
            audience="generated",
            stability="unpromised",
            schema="none",
            topLevel=None,
            securityMembers=[],
            restrictingMembers=[],
        )
        del state["topLevel"]
        state["current"] = {"apiVersion": "none", "kind": "none", "checkedBy": "none"}
        state["target"] = {
            "apiVersion": "id.registrystack.org/formats/casework/dev-state/v1alpha1",
            "kind": "CaseworkDevState",
        }
        self.repo.formats.append(state)
        report = self.repo.run()
        self.assertEqual(report.errors, [])
        self.assertFalse(
            [key for key in keys(report.findings) if key[1] == "casework/dev-state" and key[0] in ("CFG-SCHEMA-2", "CFG-SCHEMA-6")]
        )
        self.assertFinding(report, "CFG-ENV-1", "casework/dev-state", at(REGISTRY, "/current/apiVersion"))


class CheckAndReaderTests(ConventionsTestCase):
    def test_cfg_check_1_reports_a_read_format_without_an_offline_check(self) -> None:
        self.repo.fmt()["check"] = "none"
        self.assertFinding(self.repo.run(), "CFG-CHECK-1", P, at(REGISTRY, "/check"))

    def test_cfg_yaml_1_reports_a_reader_outside_the_shared_reader(self) -> None:
        self.repo.write(CONFIG_RS, CONFIG_RS_TEXT.replace("registry_platform_yaml", "serde_yaml_ng"))
        self.assertFinding(self.repo.run(), "CFG-YAML-1", P, at(CONFIG_RS, "load()"))


class SourceLintTests(ConventionsTestCase):
    def plant(self, text: str) -> None:
        self.repo.write(CONFIG_RS, CONFIG_RS_TEXT + text)
        self.repo.write(
            CONFIG_RS,
            (self.repo.root / CONFIG_RS)
            .read_text()
            .replace("    queues: Vec<Queue>,\n", "    queues: Vec<Queue>,\n    extra: Extra,\n", 1),
        )

    def test_cfg_schema_8_reports_flatten_outside_a_shared_block(self) -> None:
        self.plant(
            "\n#[derive(Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct Extra {\n"
            "    #[serde(flatten)]\n    more: More,\n    #[serde(flatten)]\n"
            "    listener: registry_platform_config::ListenerConfig,\n}\n"
            "#[derive(Deserialize)]\npub struct More { a: String }\n"
        )
        report = self.repo.run()
        self.assertFinding(report, "CFG-SCHEMA-8", P, at(CONFIG_RS, "Extra/more"))
        sources = {key for key in keys(report.findings) if key[0] == "CFG-SCHEMA-8"}
        self.assertEqual(len(sources), 1, sources)

    def test_cfg_schema_8_reports_serde_tag_untagged_and_unit_variants(self) -> None:
        self.plant(
            '\n#[derive(Deserialize)]\n#[serde(tag = "type", rename_all = "kebab-case")]\n'
            "pub enum Extra {\n    Inline { text: Plain },\n    Empty,\n}\n"
            "#[derive(Deserialize)]\n#[serde(untagged)]\npub enum Plain { Text(String), Many(Vec<String>) }\n"
        )
        report = self.repo.run()
        self.assertFinding(report, "CFG-SCHEMA-8", P, at(CONFIG_RS, "Extra"))
        self.assertFinding(report, "CFG-SCHEMA-8", P, at(CONFIG_RS, "Extra/Empty"))
        self.assertFinding(report, "CFG-SCHEMA-8", P, at(CONFIG_RS, "Plain"))

    def test_cfg_change_1_reports_an_alias(self) -> None:
        self.plant(
            '\n#[derive(Deserialize)]\npub struct Extra {\n    #[serde(alias = "old_name")]\n    name: String,\n}\n'
        )
        self.assertFinding(self.repo.run(), "CFG-CHANGE-1", P, at(CONFIG_RS, "Extra/name"))

    def test_cfg_id_6_reports_a_set_type_in_a_reader_type(self) -> None:
        self.plant(
            "\n#[derive(Deserialize)]\npub struct Extra {\n    names: std::collections::BTreeSet<String>,\n}\n"
        )
        self.assertFinding(self.repo.run(), "CFG-ID-6", P, at(CONFIG_RS, "Extra/names"))

    def test_cfg_id_6_reports_a_set_type_behind_a_type_alias(self) -> None:
        self.plant(
            "\n#[derive(Deserialize)]\npub struct Extra {\n    names: Names,\n    groups: Groups,\n    plain: Plain,\n}\n"
            "type Names = std::collections::BTreeSet<String>;\n"
            "pub(crate) type Groups = Vec<Inner>;\n"
            "type Inner = HashSet<String>;\n"
            "type Plain = Vec<String>;\n"
        )
        report = self.repo.run()
        self.assertFinding(report, "CFG-ID-6", P, at(CONFIG_RS, "Names"))
        self.assertFinding(report, "CFG-ID-6", P, at(CONFIG_RS, "Inner"))
        self.assertEqual(
            sorted(key[2] for key in keys(report.findings) if key[0] == "CFG-ID-6"),
            [at(CONFIG_RS, "Inner"), at(CONFIG_RS, "Names")],
        )

    def build_artifact(self) -> dict:
        entry = self.repo.fmt()
        entry.update(audience="generated", stability="unpromised")
        del entry["topLevel"]
        return entry

    def test_build_artifact_skips_the_authoring_rules(self) -> None:
        self.plant("\n#[derive(Deserialize)]\npub struct Extra {\n    names: std::collections::BTreeSet<String>,\n}\n")
        self.repo.write(CONFIG_RS, (self.repo.root / CONFIG_RS).read_text().replace("registry_platform_yaml", "serde_yaml_ng"))
        entry = self.build_artifact()
        planted = {("CFG-ID-6", P, at(CONFIG_RS, "Extra/names")), ("CFG-YAML-1", P, at(CONFIG_RS, "load()"))}
        self.assertLessEqual(planted, keys(self.repo.run().findings))
        entry["buildArtifact"] = True
        report = self.repo.run()
        self.assertEqual(report.errors, [])
        self.assertEqual(sorted(key for key in keys(report.findings) if key[1] == P), [])

    def test_build_artifact_keeps_the_registry_accuracy_checks(self) -> None:
        entry = self.build_artifact()
        entry["buildArtifact"] = True
        entry["reader"]["function"] = "parse"
        self.assertError(self.repo.run(), "does not define fn parse")

    def test_cfg_schema_8_ignores_test_only_items(self) -> None:
        report = self.repo.run()
        self.assertNoFinding(report, "CFG-SCHEMA-8")
        self.assertNoFinding(report, "CFG-ID-6")


class RegisterTestCase(ConventionsTestCase):
    def plant(self) -> None:
        self.repo.project["$defs"]["Queue"]["properties"]["maxItems"] = {
            "type": "integer",
            "minimum": 1,
            "maximum": 10,
        }

    def entry(self, **changes) -> dict:
        entry = {
            "rule": "CFG-NAME-3",
            "format": P,
            "location": at(PROJECT_SCHEMA, "/$defs/Queue/properties/maxItems"),
            "class": "pending",
            "wp": "WP8",
            "reason": "Spelled before the convention.",
            "resolution": "Rename to maximumItems.",
        }
        entry.update(changes)
        return {key: value for key, value in entry.items() if value is not None}


class RegisterTests(RegisterTestCase):
    def test_an_unrecorded_finding_fails_with_one_line(self) -> None:
        self.plant()
        code, stdout, _ = self.repo.main()
        self.assertEqual(code, 1)
        line = next(line for line in stdout.splitlines() if "CFG-NAME-3" in line)
        self.assertIn("unrecorded", line)
        self.assertIn(at(PROJECT_SCHEMA, "/$defs/Queue/properties/maxItems"), line)
        self.assertIn("maximumItems", line)

    def test_a_recorded_finding_passes_and_counts_as_pending(self) -> None:
        self.plant()
        self.repo.exceptions.append(self.entry())
        code, stdout, _ = self.repo.main()
        self.assertEqual(code, 0, stdout)
        self.assertIn("pending casework WP8: 1", stdout)
        report = self.repo.run()
        self.assertEqual(dict(report.pending), {("casework", "WP8"): 1})

    def test_strict_refuses_a_pending_entry(self) -> None:
        self.plant()
        self.repo.exceptions.append(self.entry())
        code, stdout, _ = self.repo.main("--strict")
        self.assertEqual(code, 1, stdout)
        self.assertIn("pending", stdout)

    def test_a_stale_entry_fails(self) -> None:
        self.repo.exceptions.append(self.entry())
        code, stdout, _ = self.repo.main()
        self.assertEqual(code, 1)
        self.assertIn("stale", stdout)

    def test_register_entries_are_validated(self) -> None:
        self.plant()
        self.repo.exceptions.append(self.entry(wp=None))
        self.assertError(self.repo.run(), "pending entry needs wp")
        self.repo.exceptions[0] = self.entry(**{"class": "stable-move", "wp": None})
        self.repo.fmt()["stability"] = "experimental"
        self.assertError(self.repo.run(), "stable-move applies only to a promised format")
        self.repo.fmt()["stability"] = "promised"
        self.repo.exceptions[0] = self.entry(**{"class": "decision", "wp": None, "resolution": "Later."})
        self.assertError(self.repo.run(), "decision entry names a dated decision")
        self.repo.exceptions[0] = self.entry(**{"class": "someday"})
        self.assertError(self.repo.run(), "class 'someday'")
        self.repo.exceptions[0] = self.entry()
        self.repo.exceptions.append(self.entry())
        self.assertError(self.repo.run(), "duplicate entry")

    def test_json_output_carries_every_finding(self) -> None:
        self.plant()
        code, stdout, _ = self.repo.main("--format", "json", "--list")
        self.assertEqual(code, 1)
        document = json.loads(stdout)
        finding = next(item for item in document["findings"] if item["rule"] == "CFG-NAME-3")
        self.assertEqual(finding["format"], P)
        self.assertEqual(finding["file"], PROJECT_SCHEMA)
        self.assertEqual(finding["pointer"], "/$defs/Queue/properties/maxItems")
        self.assertEqual(finding["status"], "unrecorded")
        self.assertIn("fix", finding)


class RatchetTests(RegisterTestCase):
    """CFG-CHANGE-5: the register only shrinks outside the growth classes."""

    def git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo.root), *arguments],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def commit(self) -> str:
        self.repo.save()
        self.git("add", "-A")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.org", "commit", "-qm", "base")
        return self.git("rev-parse", "HEAD")

    def setUp(self) -> None:
        super().setUp()
        self.git("init", "-q")

    def test_cfg_change_5_refuses_a_new_pending_entry(self) -> None:
        base = self.commit()
        self.plant()
        self.repo.exceptions.append(self.entry())
        report = self.repo.run(base=base)
        self.assertTrue(report.change5, report.change5)
        self.assertIn("CFG-NAME-3", report.change5[0])

    def test_cfg_change_5_accepts_a_new_protocol_constant(self) -> None:
        base = self.commit()
        self.plant()
        self.repo.exceptions.append(
            self.entry(**{"class": "protocol-constant", "wp": None})
        )
        self.assertEqual(self.repo.run(base=base).change5, [])

    def test_cfg_change_5_refuses_a_moved_entry(self) -> None:
        self.plant()
        self.repo.exceptions.append(self.entry())
        base = self.commit()
        queue = self.repo.project["$defs"]["Queue"]["properties"]
        queue["maxEntries"] = queue.pop("maxItems")
        self.repo.exceptions[0]["location"] = at(PROJECT_SCHEMA, "/$defs/Queue/properties/maxEntries")
        report = self.repo.run(base=base)
        self.assertEqual(report.errors, [])
        self.assertEqual(len(report.change5), 1, report.change5)
        self.assertIn("/$defs/Queue/properties/maxEntries", report.change5[0])

    def test_cfg_change_5_accepts_a_deleted_entry(self) -> None:
        self.plant()
        self.repo.exceptions.append(self.entry())
        base = self.commit()
        del self.repo.project["$defs"]["Queue"]["properties"]["maxItems"]
        self.repo.exceptions.clear()
        report = self.repo.run(base=base)
        self.assertEqual(report.change5, [])
        self.assertEqual(report.errors, [])

    def test_cfg_change_5_accepts_a_reworded_entry(self) -> None:
        self.plant()
        self.repo.exceptions.append(self.entry())
        base = self.commit()
        self.repo.exceptions[0] = self.entry(reason="Spelled before the convention was approved.")
        self.assertEqual(self.repo.run(base=base).change5, [])

    def test_cfg_change_5_refuses_a_class_change(self) -> None:
        self.plant()
        self.repo.exceptions.append(self.entry())
        base = self.commit()
        for cls in ("stable-move", "protocol-constant"):
            self.repo.exceptions[0] = self.entry(**{"class": cls, "wp": None})
            report = self.repo.run(base=base)
            self.assertEqual(report.errors, [])
            self.assertEqual(len(report.change5), 1, report.change5)
            self.assertIn(f"pending to {cls}", report.change5[0])

    def first_schema(self, **changes) -> str:
        published = self.repo.fmt()["schema"]
        self.repo.fmt()["schema"] = "none"
        base = self.commit()
        self.repo.fmt()["schema"] = published
        self.plant()
        self.repo.exceptions.append(self.entry(**changes))
        return base

    def test_cfg_change_5_accepts_a_stable_move_a_first_schema_reveals(self) -> None:
        base = self.first_schema(**{"class": "stable-move", "wp": None})
        report = self.repo.run(base=base)
        self.assertEqual(report.change5, [])
        self.assertEqual(report.errors, [])

    def test_cfg_change_5_refuses_a_pending_entry_a_first_schema_reveals(self) -> None:
        base = self.first_schema()
        report = self.repo.run(base=base)
        self.assertTrue(report.change5, report.change5)
        self.assertIn("CFG-NAME-3", report.change5[0])

    def test_cfg_change_5_refuses_a_new_stable_move_in_a_published_schema(self) -> None:
        base = self.commit()
        self.plant()
        self.repo.exceptions.append(self.entry(**{"class": "stable-move", "wp": None}))
        report = self.repo.run(base=base)
        self.assertTrue(report.change5, report.change5)
        self.assertIn("CFG-NAME-3", report.change5[0])

    def test_cfg_change_5_fails_when_an_explicit_base_lacks_the_register(self) -> None:
        self.git("-c", "user.name=t", "-c", "user.email=t@example.org",
                 "commit", "-q", "--allow-empty", "-m", "empty")
        report = lint.run(self.repo.root, base="HEAD")
        self.assertEqual(len(report.change5), 1, report.change5)
        self.assertIn("has no products/platform/config-conventions-exceptions.yaml", report.change5[0])
        code, stdout, _ = self.repo.main("--base", "HEAD")
        self.assertEqual(code, 1)
        self.assertIn("CFG-CHANGE-5", stdout)

    def test_cfg_change_5_fails_on_an_unknown_base(self) -> None:
        self.commit()
        code, _, stderr = self.repo.main("--base", "no-such-ref")
        self.assertEqual(code, 2)
        self.assertIn("no-such-ref", stderr)


class RuleCoverageTests(ConventionsTestCase):
    def coverage(self) -> tuple[int, str]:
        code, stdout, stderr = self.repo.main("--rule-coverage")
        return code, stdout + stderr

    def cover_everything(self) -> None:
        self.repo.write("crates/registry-casework-core/tests/envelope.rs", "#[test]\nfn cfg_env_1_refuses() {}\n")
        self.repo.write("products/platform/conformance/yaml/env-1.yaml", "# CFG-ENV-1\n")
        self.repo.write(
            "products/platform/scripts/test_check_config_conventions.py",
            "def test_cfg_env_1_x(): pass\ndef test_cfg_name_3_x(): pass\n"
            "def test_cfg_name_5_x(): pass\ndef test_cfg_schema_8_x(): pass\n",
        )

    def test_reports_every_gap_and_fails(self) -> None:
        code, output = self.coverage()
        self.assertEqual(code, 1)
        self.assertIn("CFG-ENV-1: reader unit tests", output)
        self.assertIn("CFG-ENV-1: conformance corpus", output)

    def test_passes_when_every_gate_exists(self) -> None:
        self.cover_everything()
        code, output = self.coverage()
        self.assertEqual(code, 0, output)

    def test_reports_a_must_rule_missing_from_the_summary(self) -> None:
        self.cover_everything()
        self.repo.write(
            CONVENTION,
            CONVENTION_TEXT.replace("**CFG-ENV-5 (SHOULD)", "**CFG-ENV-4 (MUST). One document.**\n\n**CFG-ENV-5 (SHOULD)"),
        )
        code, output = self.coverage()
        self.assertEqual(code, 1)
        self.assertIn("CFG-ENV-4: no Enforcement summary row", output)

    def test_reports_a_rule_listed_twice_and_a_should_rule_outside_review(self) -> None:
        self.cover_everything()
        self.repo.write(
            CONVENTION,
            CONVENTION_TEXT.replace("| CFG-SCHEMA-8 |", "| CFG-SCHEMA-8; CFG-NAME-3; CFG-ENV-5 |"),
        )
        code, output = self.coverage()
        self.assertEqual(code, 1)
        self.assertIn("CFG-NAME-3: listed in 2 Enforcement summary rows", output)
        self.assertIn("CFG-ENV-5: a SHOULD rule outside the SHOULD row", output)

    def test_reports_a_lint_rule_the_lint_does_not_test(self) -> None:
        self.cover_everything()
        self.repo.write(
            "products/platform/scripts/test_check_config_conventions.py",
            "def test_cfg_env_1_x(): pass\ndef test_cfg_schema_8_x(): pass\n",
        )
        code, output = self.coverage()
        self.assertEqual(code, 1)
        self.assertIn("CFG-NAME-3: check-config-conventions.py", output)


if __name__ == "__main__":
    unittest.main()
