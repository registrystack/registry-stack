#!/usr/bin/env python3
"""Hold every runtime to the shared runtime configuration surface.

Each row names one product runtime and the evidence that it conforms:

- its generated runtime schema embeds every shared configuration block it
  uses unchanged from the canonical platform schema, and any block it carries
  under a shared name matches that schema too;
- its runtime reads `runtime.yaml` through `RuntimeConfigLoader` and no longer
  calls the legacy `expand_config_env_vars` expansion;
- a named test proves a `*Ref` field refuses `${VAR}` substitution, and a named
  test proves an authored project file refuses an environment expression. The
  Rust test jobs run those tests; this gate fails when one is renamed or
  removed.

A row may exempt one of these only with a stated reason. A product adopting the
loader adds a row. Rows for the shared ctl verbs, `--format`, and exit classes,
and for the shared digest-mismatch refusal, join when those surfaces land.

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
GENERATOR_COMMAND = (
    "cargo run --locked -p registry-platform-config --features schema "
    "--example shared-blocks-schema -- --output products/platform/generated"
)
LEGACY_EXPANSION = re.compile(r"\bexpand_config_env_vars\w*\b")
LOADER_USE = "RuntimeConfigLoader::new("


@dataclass(frozen=True)
class TestRef:
    path: str
    name: str


@dataclass(frozen=True)
class Exemption:
    reason: str


@dataclass(frozen=True)
class Row:
    product: str
    loader_sources: tuple[str, ...]
    runtime_schema: str | Exemption
    shared_blocks: tuple[str, ...]
    reference_refusal: TestRef | Exemption
    authored_refusal: TestRef | Exemption


ROWS: tuple[Row, ...] = (
    Row(
        product="relay",
        loader_sources=("crates/registry-relay-v2/src",),
        runtime_schema="crates/registry-relayctl/schemas/authoring/runtime.schema.json",
        shared_blocks=(
            "EnvironmentSecretProviderConfig",
            "FileSecretProviderConfig",
            "JwksSource",
            "ListenerBind",
            "ListenerConfig",
            "PackageConfig",
            "SecretProvidersConfig",
        ),
        reference_refusal=TestRef(
            "crates/registry-relay-v2/src/contract.rs",
            "environment_substitution_never_reaches_a_secret_reference",
        ),
        authored_refusal=TestRef(
            "crates/registry-relay-v2/src/contract.rs",
            "an_authored_contract_carrying_an_environment_expression_is_refused",
        ),
    ),
    Row(
        product="render",
        loader_sources=("crates/registry-render/src",),
        runtime_schema=Exemption("Render publishes no generated runtime schema"),
        shared_blocks=(),
        reference_refusal=TestRef(
            "crates/registry-render/src/runtime.rs",
            "environment_expressions_substitute_values_but_never_secret_references",
        ),
        authored_refusal=TestRef(
            "crates/registry-render/src/manifest.rs",
            "an_authored_manifest_carrying_an_environment_expression_is_refused",
        ),
    ),
    Row(
        product="discovery",
        loader_sources=("crates/registry-discovery/src",),
        runtime_schema=Exemption("Discovery publishes no generated runtime schema"),
        shared_blocks=(),
        reference_refusal=Exemption("the Discovery runtime has no *Ref field"),
        authored_refusal=Exemption(
            "the Discovery runtime serves a built index and reads no authored "
            "project file"
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
    ),
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
    if not any(LOADER_USE in text for text in texts.values()):
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
        problems += check_schema(root, row, canonical)
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
    return problems


def run_generator(root: Path) -> Callable[[Path], None]:
    def generate(output: Path) -> None:
        command = GENERATOR_COMMAND.split()
        command[command.index("products/platform/generated")] = str(output)
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
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--check-generated",
        action="store_true",
        help="also regenerate the canonical shared-blocks schema and compare",
    )
    arguments = parser.parse_args(argv)
    root = arguments.root.resolve()
    problems = check(root)
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
