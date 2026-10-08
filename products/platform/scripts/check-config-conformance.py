#!/usr/bin/env python3
"""Hold every runtime to the shared runtime configuration surface.

Each row names one product runtime and the evidence that it conforms:

- its generated runtime schema embeds every shared configuration block it
  uses unchanged from the canonical platform schema, and any block it carries
  under a shared name matches that schema too;
- a runtime without a generated schema holds each shared block as a field of
  its runtime struct, typed with the `registry_platform_config` type itself,
  and a hand-written schema carrying a shared block keeps every canonical
  keyword unchanged and narrows it only with `allOf`;
- its non-test code reads `runtime.yaml` through `RuntimeConfigLoader` and no
  source calls the legacy `expand_config_env_vars` expansion;
- named tests prove a `*Ref` field refuses `${VAR}` substitution, an authored
  project file refuses an environment expression, and a mismatched package pin
  reports the shared expected-and-found digest shape. The Rust test jobs run
  those tests; this gate fails when one is renamed or removed.

A row may exempt one of these only with a stated reason. A product adopting the
loader adds a row. Rows for the shared ctl verbs, `--format`, and exit classes
join when those surfaces land.

With `--check-generated`, the gate also regenerates the canonical schema and
fails when the committed copy differs.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[3]
CANONICAL_SCHEMA = "products/platform/generated/runtime-config-blocks.schema.json"
GENERATOR_OUTPUT = "products/platform/generated"
GENERATOR_ARGUMENTS: tuple[str, ...] = (
    "cargo",
    "run",
    "--locked",
    "-p",
    "registry-platform-config",
    "--features",
    "schema",
    "--example",
    "shared-blocks-schema",
    "--",
    "--output",
)
GENERATOR_COMMAND = " ".join((*GENERATOR_ARGUMENTS, GENERATOR_OUTPUT))
LEGACY_EXPANSION = re.compile(r"\bexpand_config_env_vars\w*\b")
LOADER_USE = re.compile(r"\bRuntimeConfigLoader\s*::\s*new\s*\(")
PLATFORM_CRATE = "registry_platform_config"
# Keywords a hand-written copy of a shared block may add: each one only
# describes or narrows what the canonical block accepts.
NARROWING_KEYWORDS = frozenset({"$comment", "allOf", "description", "title"})


@dataclass(frozen=True)
class TestRef:
    path: str
    name: str


@dataclass(frozen=True)
class Exemption:
    reason: str


@dataclass(frozen=True)
class RustBlock:
    """A runtime struct field that must hold a shared block type."""

    path: str
    struct: str
    field: str
    block: str


@dataclass(frozen=True)
class HandSchema:
    """A shared block written by hand inside a product schema."""

    path: str
    pointer: tuple[str, ...]
    block: str


@dataclass(frozen=True)
class Row:
    product: str
    loader_sources: tuple[str, ...]
    runtime_schema: str | Exemption
    shared_blocks: tuple[str, ...]
    reference_refusal: TestRef | Exemption
    authored_refusal: TestRef | Exemption
    digest_mismatch: TestRef | Exemption
    rust_blocks: tuple[RustBlock, ...] = ()
    hand_schemas: tuple[HandSchema, ...] = ()


ROWS: tuple[Row, ...] = (
    Row(
        product="render",
        loader_sources=("crates/registry-render/src",),
        runtime_schema="products/render/schemas/runtime.schema.json",
        shared_blocks=(
            "Digest",
            "EnvironmentSecretProviderConfig",
            "FileSecretProviderConfig",
            "ListenerBind",
            "PackageConfig",
            "SecretProvidersConfig",
            "SecretReference",
        ),
        reference_refusal=TestRef(
            "crates/registry-render/src/runtime.rs",
            "environment_expressions_substitute_values_but_never_secret_references",
        ),
        authored_refusal=TestRef(
            "crates/registry-render/src/manifest.rs",
            "cfg_sec_2_an_authored_manifest_carrying_an_environment_expression_is_refused",
        ),
        digest_mismatch=TestRef(
            "crates/registry-render/tests/serve.rs",
            "serve_startup_package_digest_mismatch_uses_common_expected_and_found_shape",
        ),
        rust_blocks=(
            RustBlock(
                "crates/registry-render/src/runtime.rs",
                "RenderRuntime",
                "package",
                "PackageConfig",
            ),
            RustBlock(
                "crates/registry-render/src/runtime.rs",
                "RenderRuntime",
                "secret_providers",
                "SecretProvidersConfig",
            ),
            RustBlock(
                "crates/registry-render/src/runtime.rs",
                "ListenerRuntime",
                "bind",
                "ListenerBind",
            ),
        ),
    ),
    Row(
        product="discovery",
        loader_sources=("crates/registry-discovery/src",),
        runtime_schema="products/discovery/schemas/runtime.schema.json",
        shared_blocks=("Digest", "ListenerBind", "ListenerConfig", "PackageConfig"),
        reference_refusal=Exemption("the Discovery runtime has no *Ref field"),
        authored_refusal=TestRef(
            "crates/registry-discoveryctl/src/project.rs",
            "cfg_sec_2_authored_files_refuse_substitution_at_its_position",
        ),
        digest_mismatch=TestRef(
            "crates/registry-discovery/src/startup.rs",
            "startup_verifies_package_and_refuses_expected_digest_mismatch_with_common_shape",
        ),
        rust_blocks=(
            RustBlock(
                "crates/registry-discovery/src/runtime_config.rs",
                "RuntimeConfig",
                "listener",
                "ListenerConfig",
            ),
            RustBlock(
                "crates/registry-discovery/src/runtime_config.rs",
                "RuntimeConfig",
                "package",
                "PackageConfig",
            ),
        ),
    ),
    Row(
        product="evidence",
        loader_sources=("crates/registry-evidence/src",),
        runtime_schema=Exemption(
            "Evidence publishes the frozen hand-written "
            "products/evidence/contracts/runtime.schema.yaml, held by its own "
            "contract checks, not a generated runtime schema"
        ),
        shared_blocks=(),
        reference_refusal=TestRef(
            "crates/registry-evidence/src/config.rs",
            "environment_substitution_fills_values_and_never_a_secret_reference",
        ),
        authored_refusal=TestRef(
            "crates/registry-evidence/src/config.rs",
            "an_authored_bundle_carrying_an_environment_expression_is_refused",
        ),
        digest_mismatch=TestRef(
            "crates/registry-evidence/src/runtime_tests.rs",
            "an_expected_package_digest_admits_only_the_bundle_it_names",
        ),
        rust_blocks=(
            RustBlock(
                "crates/registry-evidence/src/config.rs",
                "RuntimeConfig",
                "package",
                "PackageConfig",
            ),
            RustBlock(
                "crates/registry-evidence/src/config.rs",
                "RuntimeConfig",
                "secret_providers",
                "SecretProvidersConfig",
            ),
            RustBlock(
                "crates/registry-evidence/src/config.rs",
                "ListenerConfig",
                "bind",
                "ListenerBind",
            ),
            RustBlock(
                "crates/registry-evidence/src/config.rs",
                "MetricsListenerConfig",
                "bind",
                "ListenerBind",
            ),
            RustBlock(
                "crates/registry-evidence/src/config.rs",
                "OidcAuthenticationConfig",
                "provider",
                "OidcIssuerConfig",
            ),
            RustBlock(
                "crates/registry-evidence/src/config.rs",
                "AuditConfig",
                "key",
                "AuditKeyConfig",
            ),
        ),
    ),
    Row(
        product="breg",
        loader_sources=("crates/registry-breg/src",),
        runtime_schema="products/breg/generated/runtime/runtime.schema.json",
        shared_blocks=(
            "EnvironmentSecretProviderConfig",
            "FileSecretProviderConfig",
            "JwksSource",
            "ListenerBind",
            "SecretProvidersConfig",
            "SecretReference",
        ),
        reference_refusal=TestRef(
            "crates/registry-breg/tests/runtime_config.rs",
            "a_substitution_inside_a_secret_reference_is_refused",
        ),
        authored_refusal=TestRef(
            "crates/registry-breg/tests/compiler_contract.rs",
            "an_authored_project_carrying_an_environment_expression_is_refused",
        ),
        digest_mismatch=TestRef(
            "crates/registry-breg/tests/runtime_config.rs",
            "shared_package_envelope_and_pin_are_checked_before_startup",
        ),
        rust_blocks=(
            RustBlock(
                "crates/registry-breg/src/runtime_config.rs",
                "RawRuntimeConfig",
                "secret_providers",
                "SecretProvidersConfig",
            ),
            RustBlock(
                "crates/registry-breg/src/runtime_config.rs",
                "RawListenerConfig",
                "bind",
                "ListenerBind",
            ),
            RustBlock(
                "crates/registry-breg/src/runtime_config.rs",
                "RawMetricsListenerConfig",
                "bind",
                "ListenerBind",
            ),
            RustBlock(
                "crates/registry-breg/src/runtime_config.rs",
                "RawOidcVerifierConfig",
                "provider",
                "OidcIssuerConfig",
            ),
            RustBlock(
                "crates/registry-breg/src/runtime_config.rs",
                "RawAuditConfig",
                "key",
                "AuditKeyConfig",
            ),
        ),
    ),
    Row(
        product="casework",
        loader_sources=("crates/registry-casework/src",),
        runtime_schema="products/casework/generated/runtime/runtime.schema.json",
        shared_blocks=(
            "DatabaseConfig",
            "EnvironmentSecretProviderConfig",
            "FileSecretProviderConfig",
            "JwksSource",
            "ListenerBind",
            "ListenerNetworkExposure",
            "PrivateListenerConfig",
            "SecretProvidersConfig",
            "SecretReference",
            "TlsTermination",
        ),
        reference_refusal=TestRef(
            "crates/registry-casework/src/config.rs",
            "environment_expressions_substitute_values_but_never_secret_references",
        ),
        authored_refusal=TestRef(
            "crates/registry-casework/src/config.rs",
            "an_authored_project_carrying_an_environment_expression_is_refused",
        ),
        digest_mismatch=TestRef(
            "crates/registry-casework/src/config.rs",
            "a_package_digest_mismatch_is_refused_in_the_shared_shape",
        ),
        rust_blocks=(
            RustBlock(
                "crates/registry-casework/src/config.rs",
                "OidcConfig",
                "provider",
                "OidcIssuerConfig",
            ),
            RustBlock(
                "crates/registry-casework/src/config.rs",
                "OidcConfig",
                "clients",
                "OidcClientsConfig",
            ),
            RustBlock(
                "crates/registry-casework/src/config.rs",
                "AuditConfig",
                "key",
                "AuditKeyConfig",
            ),
        ),
    ),
    Row(
        product="scheduling",
        loader_sources=("crates/registry-scheduling/src",),
        runtime_schema="products/scheduling/generated/runtime/runtime.schema.json",
        shared_blocks=(
            "DatabaseConfig",
            "EnvironmentSecretProviderConfig",
            "FileSecretProviderConfig",
            "JwksSource",
            "ListenerBind",
            "ListenerNetworkExposure",
            "PackageConfig",
            "PrivateListenerConfig",
            "SecretProvidersConfig",
            "SecretReference",
            "TlsTermination",
        ),
        reference_refusal=TestRef(
            "crates/registry-scheduling/src/config.rs",
            "environment_expressions_substitute_values_but_never_secret_references",
        ),
        authored_refusal=TestRef(
            "crates/registry-scheduling/src/config.rs",
            "an_authored_policy_carrying_an_environment_expression_is_refused",
        ),
        digest_mismatch=TestRef(
            "crates/registry-scheduling/src/config.rs",
            "a_pinned_package_digest_must_match_the_verified_package",
        ),
        rust_blocks=(
            RustBlock(
                "crates/registry-scheduling/src/config.rs",
                "OidcConfig",
                "provider",
                "OidcIssuerConfig",
            ),
            RustBlock(
                "crates/registry-scheduling/src/config.rs",
                "OidcConfig",
                "clients",
                "OidcClientsConfig",
            ),
            RustBlock(
                "crates/registry-scheduling/src/config.rs",
                "AuditConfig",
                "key",
                "AuditKeyConfig",
            ),
        ),
    ),
    Row(
        product="messaging",
        loader_sources=("crates/registry-messaging/src",),
        runtime_schema="products/messaging/generated/runtime/runtime.schema.json",
        shared_blocks=(
            "DatabaseConfig",
            "EnvironmentSecretProviderConfig",
            "FileSecretProviderConfig",
            "JwksSource",
            "ListenerBind",
            "ListenerConfig",
            "ListenerNetworkExposure",
            "PackageConfig",
            "PrivateListenerConfig",
            "SecretProvidersConfig",
            "SecretReference",
            "TlsTermination",
        ),
        reference_refusal=TestRef(
            "crates/registry-messaging/src/config.rs",
            "shared_runtime_loader_refuses_environment_expressions_in_secret_references",
        ),
        authored_refusal=TestRef(
            "crates/registry-messaging/src/package.rs",
            "authored_project_environment_expressions_are_refused_in_structured_yaml",
        ),
        digest_mismatch=TestRef(
            "crates/registry-messaging/src/config.rs",
            "runtime_package_digest_pin_reports_expected_and_found",
        ),
        rust_blocks=(
            RustBlock(
                "crates/registry-messaging/src/config.rs",
                "OidcConfig",
                "provider",
                "OidcIssuerConfig",
            ),
            RustBlock(
                "crates/registry-messaging/src/config.rs",
                "OidcConfig",
                "clients",
                "OidcClientsConfig",
            ),
            RustBlock(
                "crates/registry-messaging/src/config.rs",
                "AuditConfig",
                "key",
                "AuditKeyConfig",
            ),
        ),
    ),
    Row(
        product="breg-mcp",
        loader_sources=("crates/registry-breg-mcp/src",),
        runtime_schema="products/breg/generated/mcp-runtime/mcp-runtime.schema.json",
        shared_blocks=(
            "EnvironmentSecretProviderConfig",
            "FileSecretProviderConfig",
            "JwksSource",
            "ListenerBind",
            "ListenerNetworkExposure",
            "PrivateListenerConfig",
            "SecretProvidersConfig",
            "SecretReference",
            "TlsTermination",
        ),
        reference_refusal=TestRef(
            "crates/registry-breg-mcp/src/config.rs",
            "runtime_loader_refuses_environment_expressions_in_secret_references",
        ),
        authored_refusal=Exemption(
            "the citizen service reads runtime configuration and registry HTTP metadata, "
            "not authored package files"
        ),
        digest_mismatch=Exemption(
            "the citizen service owns no installed package; the separate BReg runtime "
            "verifies the package it serves"
        ),
        rust_blocks=(
            RustBlock(
                "crates/registry-breg-mcp/src/config.rs", "RuntimeConfig", "listener", "PrivateListenerConfig",
            ),
            RustBlock(
                "crates/registry-breg-mcp/src/config.rs", "RuntimeConfig", "secret_providers", "SecretProvidersConfig",
            ),
            RustBlock(
                "crates/registry-breg-mcp/src/config.rs", "AuditConfig", "key", "AuditKeyConfig",
            ),
            RustBlock(
                "crates/registry-breg-mcp/src/config.rs", "ResourceServerConfig", "jwks_source", "JwksSource",
            ),
        ),
    ),
    Row(
        product="breg-review",
        loader_sources=("crates/registry-breg-review/src",),
        runtime_schema="products/breg/generated/review-runtime/review-runtime.schema.json",
        shared_blocks=(
            "EnvironmentSecretProviderConfig",
            "FileSecretProviderConfig",
            "ListenerBind",
            "ListenerNetworkExposure",
            "PrivateListenerConfig",
            "SecretProvidersConfig",
            "SecretReference",
            "TlsTermination",
        ),
        reference_refusal=TestRef(
            "crates/registry-breg-review/src/config.rs",
            "runtime_loader_refuses_environment_expressions_in_secret_references",
        ),
        authored_refusal=Exemption(
            "the citizen service reads runtime configuration and registry HTTP metadata, "
            "not authored package files"
        ),
        digest_mismatch=Exemption(
            "the citizen service owns no installed package; the separate BReg runtime "
            "verifies the package it serves"
        ),
        rust_blocks=(
            RustBlock(
                "crates/registry-breg-review/src/config.rs", "RuntimeConfig", "listener", "PrivateListenerConfig",
            ),
            RustBlock(
                "crates/registry-breg-review/src/config.rs", "RuntimeConfig", "secret_providers", "SecretProvidersConfig",
            ),
            RustBlock(
                "crates/registry-breg-review/src/config.rs", "AuditConfig", "key", "AuditKeyConfig",
            ),
        ),
    ),
    Row(
        product="evidence-oid4vci",
        loader_sources=("crates/registry-evidence-oid4vci/src",),
        runtime_schema="products/evidence/generated/oid4vci-runtime/oid4vci-runtime.schema.json",
        shared_blocks=(
            "EnvironmentSecretProviderConfig",
            "FileSecretProviderConfig",
            "ListenerBind",
            "ListenerConfig",
            "SecretProvidersConfig",
            "SecretReference",
        ),
        reference_refusal=TestRef(
            "crates/registry-evidence-oid4vci/src/config.rs",
            "runtime_loader_refuses_environment_expressions_in_secret_references",
        ),
        authored_refusal=Exemption(
            "the wallet delivery service reads only its runtime configuration, "
            "not authored package files"
        ),
        digest_mismatch=Exemption(
            "the wallet delivery service owns no installed package; the Evidence "
            "runtime it calls verifies the bundle it serves"
        ),
    ),
)

EXPECTED_PRODUCTS = frozenset(
    {"render", "discovery", "evidence", "breg", "casework", "scheduling",
     "messaging", "breg-mcp", "breg-review", "evidence-oid4vci"}
)


class GeneratorFailed(Exception):
    pass


def read_defs(path: Path) -> dict[str, object] | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    defs = document.get("$defs") if isinstance(document, dict) else None
    return defs if isinstance(defs, dict) else None


def rust_sources(root: Path, directories: tuple[str, ...]) -> list[Path]:
    return sorted(
        path for directory in directories for path in (root / directory).rglob("*.rs")
    )


RUST_LITERAL_OR_COMMENT = re.compile(
    r"//[^\n]*"
    r"|/\*.*?\*/"
    r'|b?r(?P<hashes>#*)".*?"(?P=hashes)'
    r'|b?"(?:\\.|[^"\\])*"'
    r"|b?'(?:\\.|[^'\\])'",
    re.DOTALL,
)
TEST_ONLY_ITEM = re.compile(r"#\[cfg\(test\)\]((?:\s*#\[[^\]]*\])*)\s*")
MODULE_DECLARATION = re.compile(
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>\w+)\s*(?P<end>[;{])"
)
PATH_ATTRIBUTE = re.compile(r"#\[path\s*=\s*\"(?P<path>[^\"]+)\"\s*\]")


def blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def code_only(text: str) -> str:
    """Blank Rust comments and string and character literals, keeping offsets.

    Nested block comments are not modelled; the product sources carry none.
    """
    return RUST_LITERAL_OR_COMMENT.sub(blank, text)


def matching_brace(code: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(code) - 1


def module_file(declaring: Path, name: str, path_attribute: str | None) -> list[Path]:
    if path_attribute is not None:
        return [declaring.parent / path_attribute]
    if declaring.name in {"lib.rs", "main.rs", "mod.rs"}:
        base = declaring.parent
    else:
        base = declaring.parent / declaring.stem
    return [base / f"{name}.rs", base / name / "mod.rs"]


def strip_test_items(path: Path, text: str) -> tuple[str, list[Path]]:
    """Blank every `#[cfg(test)]` item and name the files of test-only modules."""

    code = code_only(text)
    test_files: list[Path] = []
    position = 0
    while (found := TEST_ONLY_ITEM.search(code, position)) is not None:
        rest = found.end()
        declaration = MODULE_DECLARATION.match(code, rest)
        if declaration is not None and declaration.group("end") == ";":
            # `code` blanks string literals; the `#[path]` value is read from
            # the same offsets of the original text.
            attribute = PATH_ATTRIBUTE.search(text, found.start(1), found.end(1))
            test_files += module_file(
                path,
                declaration.group("name"),
                attribute.group("path") if attribute else None,
            )
            end = declaration.end()
        else:
            opening = code.find("{", rest)
            semicolon = code.find(";", rest)
            if opening == -1 or (semicolon != -1 and semicolon < opening):
                end = semicolon + 1 if semicolon != -1 else len(code)
            else:
                end = matching_brace(code, opening) + 1
        code = code[: found.start()] + re.sub(
            r"[^\n]", " ", code[found.start() : end]
        ) + code[end:]
        position = end
    return code, test_files


def production_code(paths: list[Path]) -> dict[Path, str]:
    """Return the non-test code of each source, dropping test-only module files."""

    stripped: dict[Path, str] = {}
    test_files: set[Path] = set()
    for path in paths:
        code, files = strip_test_items(path, path.read_text(encoding="utf-8"))
        stripped[path] = code
        test_files.update(file.resolve() for file in files)
    return {
        path: code for path, code in stripped.items() if path.resolve() not in test_files
    }


def has_test(text: str, name: str) -> bool:
    attribute = r"#\[[^\]]*\]\s*"
    test = rf"#\[(?:tokio::)?test(?:\([^\]]*\))?\]\s*(?:{attribute})*(?:async\s+)?fn\s+{name}\s*\("
    return re.search(test, text) is not None


def check_exemption(row: Row, field: str, value: object) -> list[str]:
    if isinstance(value, Exemption) and not value.reason.strip():
        return [f"{row.product}: the {field} exemption needs a reason"]
    return []


def check_schema(root: Path, row: Row, canonical: dict[str, object]) -> list[str]:
    if isinstance(row.runtime_schema, Exemption):
        if row.shared_blocks:
            return [
                f"{row.product}: a product without a runtime schema declares no "
                "shared blocks"
            ]
        return []
    problems = [
        f"{row.product}: shared block {name} is not in {CANONICAL_SCHEMA}"
        for name in row.shared_blocks
        if name not in canonical
    ]
    schema = row.runtime_schema
    if not (root / schema).is_file():
        return problems + [f"{row.product}: runtime schema {schema} is missing"]
    defs = read_defs(root / schema)
    if defs is None:
        return problems + [f"{row.product}: runtime schema {schema} has no $defs"]
    for name in row.shared_blocks:
        if name in canonical and name not in defs:
            problems.append(
                f"{row.product}: {schema} does not embed shared block {name}"
            )
    for name in sorted(set(defs) & set(canonical)):
        if defs[name] != canonical[name]:
            problems.append(
                f"{row.product}: {schema} re-declares shared block {name} instead "
                "of embedding it unchanged"
            )
    return problems


def check_loader(root: Path, row: Row) -> list[str]:
    sources = rust_sources(root, row.loader_sources)
    problems = []
    texts = {path: path.read_text(encoding="utf-8") for path in sources}
    production = production_code(sources)
    if not any(LOADER_USE.search(code) for code in production.values()):
        problems.append(
            f"{row.product}: no source under {', '.join(row.loader_sources)} reads "
            "runtime.yaml through RuntimeConfigLoader"
        )
    for path, text in texts.items():
        if LEGACY_EXPANSION.search(text):
            problems.append(
                f"{row.product}: {path.relative_to(root).as_posix()} calls "
                "expand_config_env_vars; read runtime.yaml through "
                "RuntimeConfigLoader instead"
            )
    return problems


def struct_fields(code: str, struct: str) -> dict[str, str] | None:
    declaration = re.search(
        rf"\bstruct\s+{struct}\b[^{{;]*\{{", code
    )
    if declaration is None:
        return None
    body = code[declaration.end() : matching_brace(code, declaration.end() - 1)]
    body = re.sub(r"#\[[^\]]*\]", " ", body)
    fields: dict[str, str] = {}
    depth = 0
    current = ""
    for character in body + ",":
        if character in "<([":
            depth += 1
        elif character in ">)]":
            depth -= 1
        if character == "," and depth == 0:
            field = re.fullmatch(
                r"\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*(.+?)\s*", current, re.DOTALL
            )
            if field is not None:
                fields[field.group(1)] = re.sub(r"\s+", "", field.group(2))
            current = ""
        else:
            current += character
    return fields


def imports_from_platform(code: str, block: str) -> bool:
    for use in re.finditer(rf"\buse\s+{PLATFORM_CRATE}\s*::\s*([^;]*);", code):
        if re.search(rf"(?<![\w:]){block}\b(?!\s*as\b)", use.group(1)):
            return True
    return False


def check_rust_blocks(root: Path, row: Row, canonical: dict[str, object]) -> list[str]:
    problems: list[str] = []
    for entry in row.rust_blocks:
        if entry.block not in canonical:
            problems.append(
                f"{row.product}: shared block {entry.block} is not in {CANONICAL_SCHEMA}"
            )
            continue
        path = root / entry.path
        if not path.is_file():
            problems.append(f"{row.product}: runtime source {entry.path} is missing")
            continue
        code = production_code([path]).get(path, "")
        fields = struct_fields(code, entry.struct)
        if fields is None:
            problems.append(f"{row.product}: {entry.path} has no struct {entry.struct}")
            continue
        written = fields.get(entry.field)
        if written == f"{PLATFORM_CRATE}::{entry.block}":
            continue
        if written != entry.block:
            problems.append(
                f"{row.product}: {entry.path} {entry.struct}.{entry.field} is not "
                f"typed {entry.block}"
            )
            continue
        if re.search(rf"\b(?:struct|enum|type|union)\s+{entry.block}\b", code):
            problems.append(
                f"{row.product}: {entry.path} declares its own {entry.block} "
                "instead of using the shared block"
            )
        if not imports_from_platform(code, entry.block):
            problems.append(
                f"{row.product}: {entry.path} does not import {entry.block} from "
                f"{PLATFORM_CRATE}"
            )
    return problems


def resolve(node: object, canonical: dict[str, object]) -> object:
    while isinstance(node, dict) and set(node) == {"$ref"}:
        reference = node["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
            break
        node = canonical.get(reference.removeprefix("#/$defs/"))
    return node


def narrowing_drift(
    hand: object, shared: object, canonical: dict[str, object], at: str
) -> str | None:
    """Name the first way `hand` departs from the shared block, or None."""

    shared = resolve(shared, canonical)
    if not isinstance(hand, dict) or not isinstance(shared, dict):
        return None if hand == shared else f"the schema differs at {at}"
    for keyword, expected in shared.items():
        if keyword == "description":
            continue
        if keyword not in hand:
            return f"{keyword} is missing at {at}"
        if keyword == "properties" and isinstance(expected, dict):
            written = hand[keyword]
            if not isinstance(written, dict) or set(written) != set(expected):
                return f"properties differ at {at}"
            for name in sorted(expected):
                inner = f"{at.rstrip('/')}/properties/{name}"
                drift = narrowing_drift(written[name], expected[name], canonical, inner)
                if drift is not None:
                    return drift
        elif hand[keyword] != expected:
            return f"{keyword} differs at {at}"
    for keyword in sorted(set(hand) - set(shared)):
        if keyword not in NARROWING_KEYWORDS:
            return f"{keyword} is not a narrowing keyword at {at}"
    return None


def check_hand_schemas(root: Path, row: Row, canonical: dict[str, object]) -> list[str]:
    problems: list[str] = []
    for entry in row.hand_schemas:
        pointer = "/" + "/".join(entry.pointer)
        if entry.block not in canonical:
            problems.append(
                f"{row.product}: shared block {entry.block} is not in {CANONICAL_SCHEMA}"
            )
            continue
        try:
            node: object = json.loads((root / entry.path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            problems.append(f"{row.product}: schema {entry.path} is missing or invalid")
            continue
        for step in entry.pointer:
            node = node.get(step) if isinstance(node, dict) else None
        if node is None:
            problems.append(f"{row.product}: {entry.path} has no schema at {pointer}")
            continue
        drift = narrowing_drift(node, canonical[entry.block], canonical, "/")
        if drift is not None:
            problems.append(
                f"{row.product}: {entry.path} at {pointer} does not match shared "
                f"block {entry.block}: {drift}"
            )
    return problems


def check_test(root: Path, row: Row, value: TestRef | Exemption, duty: str) -> list[str]:
    if isinstance(value, Exemption):
        return []
    path = root / value.path
    if not path.is_file():
        return [f"{row.product}: test file {value.path} is missing"]
    if not has_test(path.read_text(encoding="utf-8"), value.name):
        return [f"{row.product}: {value.path} has no test named {value.name} ({duty})"]
    return []


def check(root: Path, rows: tuple[Row, ...] = ROWS) -> list[str]:
    canonical = read_defs(root / CANONICAL_SCHEMA)
    if canonical is None:
        return [f"{CANONICAL_SCHEMA} is missing; run {GENERATOR_COMMAND}"]
    problems: list[str] = []
    for row in rows:
        problems += check_exemption(row, "runtime_schema", row.runtime_schema)
        problems += check_exemption(row, "reference_refusal", row.reference_refusal)
        problems += check_exemption(row, "authored_refusal", row.authored_refusal)
        problems += check_exemption(row, "digest_mismatch", row.digest_mismatch)
        if isinstance(row.digest_mismatch, Exemption) and (
            "PackageConfig" in row.shared_blocks
            or any(block.block == "PackageConfig" for block in row.rust_blocks)
        ):
            problems.append(
                f"{row.product}: a runtime holding PackageConfig must name a digest mismatch test"
            )
        problems += check_schema(root, row, canonical)
        problems += check_rust_blocks(root, row, canonical)
        problems += check_hand_schemas(root, row, canonical)
        problems += check_loader(root, row)
        problems += check_test(
            root, row, row.reference_refusal, "a *Ref field must refuse ${VAR}"
        )
        problems += check_test(
            root,
            row,
            row.authored_refusal,
            "an authored project file must refuse ${VAR}",
        )
        problems += check_test(
            root,
            row,
            row.digest_mismatch,
            "a package digest mismatch must report the shared expected-and-found shape",
        )
    return problems


def check_inventory(rows: tuple[Row, ...] = ROWS) -> list[str]:
    products = [row.product for row in rows]
    problems = []
    duplicates = sorted({product for product in products if products.count(product) > 1})
    if duplicates:
        problems.append(f"duplicate conformance rows: {', '.join(duplicates)}")
    missing = sorted(EXPECTED_PRODUCTS - set(products))
    extra = sorted(set(products) - EXPECTED_PRODUCTS)
    if missing:
        problems.append(f"missing conformance rows: {', '.join(missing)}")
    if extra:
        problems.append(f"unexpected conformance rows: {', '.join(extra)}")
    return problems


def run_generator(root: Path) -> Callable[[Path], None]:
    def generate(output: Path) -> None:
        command = [*GENERATOR_ARGUMENTS, str(output)]
        completed = subprocess.run(command, cwd=root, check=False)
        if completed.returncode != 0:
            raise GeneratorFailed(
                f"generator exited with status {completed.returncode}"
            )

    return generate


def check_canonical_freshness(
    root: Path, generate: Callable[[Path], None] | None = None
) -> list[str]:
    generate = generate or run_generator(root)
    committed = root / CANONICAL_SCHEMA
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary)
        try:
            generate(output)
        except GeneratorFailed as error:
            return [f"{CANONICAL_SCHEMA} could not be regenerated: {error}"]
        regenerated = output / committed.name
        if not regenerated.is_file() or regenerated.read_bytes() != committed.read_bytes():
            return [f"{CANONICAL_SCHEMA} differs from its generator; run {GENERATOR_COMMAND}"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--check-generated",
        action="store_true",
        help="also regenerate the canonical shared-blocks schema and compare",
    )
    arguments = parser.parse_args(argv)
    root = arguments.root.resolve()
    problems = check_inventory() + check(root)
    if arguments.check_generated and not problems:
        problems = check_canonical_freshness(root)
    if problems:
        print("runtime configuration conformance failed:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    print(f"runtime configuration conformance holds for {len(ROWS)} products")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
