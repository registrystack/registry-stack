#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""List demo API-key personas and their raw local bearer tokens."""

import argparse
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path


BRUNO_VAR_MAP = {
    "catalog_viewer": "metadataKey",
    "planning_analyst": "aggregateKey",
    "casework_system": "rowsKey",
    "verification_service": "verifyKey",
    "linkage_service": "linkageKey",
    "operations_admin": "adminKey",
}

PERSONA_LABELS = {
    "catalog_viewer": "Catalog viewer",
    "planning_analyst": "Planning analyst",
    "casework_system": "Casework system",
    "verification_service": "Verification service",
    "linkage_service": "Linkage service",
    "operations_admin": "Operations admin",
}

PERSONA_HINTS = {
    "catalog_viewer": "Discovery only: catalog and metadata, no rows.",
    "planning_analyst": "Planning reads: metadata and, when granted, disclosure-controlled aggregates.",
    "casework_system": "Operational follow-up: row reads, relationships, and selected verification.",
    "verification_service": "Verification reads: existence checks and, when granted, submitted-claim checks.",
    "linkage_service": "Subject linkage: resolve cross-dataset aliases without reading source records.",
    "operations_admin": "Operations: admin scope plus metadata discovery.",
}

OPENAPI_WORDS = {
    "metadata": [
        "Get metadata landing",
        "Get portable metadata catalog",
        "Get base DCAT",
        "Get profile DCAT",
        "Get SHACL graph",
        "List datasets",
        "Get dataset metadata",
        "Get entity JSON Schema",
        "Get entity SHACL",
        "Get OGC records metadata",
    ],
    "aggregate": ["List aggregates", "Run aggregate"],
    "rows": ["List records", "Get record", "Get relationship"],
    "verify": ["Verify record exists"],
    "claim_verification": [
        "List claim-verification rulesets",
        "Get claim-verification ruleset",
        "Create claim verification",
    ],
    "admin": ["Admin operation"],
}


@dataclass
class DemoKey:
    key_id: str
    hash_env: str
    scopes: list[str]

    @property
    def raw_env(self) -> str:
        if self.hash_env.endswith("_HASH"):
            return f"{self.hash_env[:-5]}_RAW"
        return f"{self.key_id.upper()}_RAW"

    @property
    def bruno_var(self) -> str:
        return BRUNO_VAR_MAP.get(self.key_id, "-")

    @property
    def label(self) -> str:
        return PERSONA_LABELS.get(self.key_id, self.key_id.replace("_", " ").title())


def parse_demo_keys(config_path: Path) -> list[DemoKey]:
    lines = config_path.read_text(encoding="utf-8").splitlines()
    keys: list[DemoKey] = []
    in_api_keys = False
    current: DemoKey | None = None
    in_scopes = False

    def finish_current() -> None:
        nonlocal current
        if current is not None:
            keys.append(current)
            current = None

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if in_api_keys and indent == 0:
            finish_current()
            break
        if stripped == "api_keys:":
            in_api_keys = True
            continue
        if not in_api_keys:
            continue

        if indent == 4 and stripped.startswith("- id: "):
            finish_current()
            key_id = stripped.removeprefix("- id: ").strip().strip("'\"")
            current = DemoKey(key_id=key_id, hash_env="", scopes=[])
            in_scopes = False
            continue
        if current is None:
            continue
        if indent == 6 and stripped.startswith("hash_env: "):
            current.hash_env = stripped.removeprefix("hash_env: ").strip().strip("'\"")
            continue
        if indent == 6 and stripped == "scopes:":
            in_scopes = True
            continue
        if in_scopes and indent == 8 and stripped.startswith("- "):
            current.scopes.append(stripped.removeprefix("- ").strip().strip("'\""))
            continue
        if indent <= 6:
            in_scopes = False

    finish_current()
    return keys


def parse_demo_raw_keys(env_path: Path, keys: list[DemoKey]) -> dict[str, str]:
    if not env_path.exists():
        return {}

    wanted = {key.raw_env for key in keys}
    raw_keys: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped.removeprefix("export ").strip()
        if "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        name = name.strip()
        if name not in wanted:
            continue
        try:
            parsed = shlex.split(value, comments=False, posix=True)
        except ValueError:
            parsed = []
        raw_keys[name] = parsed[0] if parsed else value.strip().strip("'\"")
    return raw_keys


def split_scope(scope: str) -> tuple[str, str]:
    if scope == "admin":
        return ("admin", "all")
    if ":" not in scope:
        return ("other", scope)
    dataset, level = scope.split(":", 1)
    return (level, dataset)


def levels_for(key: DemoKey) -> list[str]:
    seen = []
    for scope in key.scopes:
        level, _dataset = split_scope(scope)
        if level not in seen:
            seen.append(level)
    order = [
        "metadata",
        "aggregate",
        "rows",
        "verify",
        "claim_verification",
        "admin",
        "other",
    ]
    return sorted(seen, key=lambda level: order.index(level) if level in order else len(order))


def operations_for(key: DemoKey) -> list[str]:
    operations: list[str] = []
    for level in levels_for(key):
        for operation in OPENAPI_WORDS.get(level, [level]):
            if operation not in operations:
                operations.append(operation)
    return operations


def concise_operations_for(key: DemoKey) -> list[str]:
    levels = set(levels_for(key))
    if key.key_id == "catalog_viewer":
        return [
            "Get metadata landing",
            "Get portable metadata catalog",
            "Get entity JSON Schema",
        ]
    if key.key_id == "planning_analyst":
        if "aggregate" in levels:
            return ["Run aggregate", "List aggregates"]
        return ["Get metadata landing", "Get dataset metadata"]
    if key.key_id == "casework_system":
        operations = ["Get record", "Get relationship"]
        if "verify" in levels:
            operations.append("Verify record exists")
        if "claim_verification" in levels:
            operations.append("Create claim verification")
        return operations
    if key.key_id == "verification_service":
        operations = ["Verify record exists"]
        if "claim_verification" in levels:
            operations.append("Create claim verification")
        return operations
    if key.key_id == "linkage_service":
        return ["Get record", "Get relationship", "Run aggregate"]
    if key.key_id == "operations_admin":
        return ["Admin operation", "List datasets"]
    return operations_for(key)


def datasets_by_level(key: DemoKey) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for scope in key.scopes:
        level, dataset = split_scope(scope)
        grouped.setdefault(level, [])
        if dataset not in grouped[level]:
            grouped[level].append(dataset)
    return grouped


def wrap_words(words: list[str], width: int = 88, prefix: str = "    ") -> list[str]:
    lines: list[str] = []
    current = prefix
    for word in words:
        part = word if current == prefix else f"; {word}"
        if len(current) + len(part) > width and current != prefix:
            lines.append(current)
            current = prefix + word
        else:
            current += part
    if current != prefix:
        lines.append(current)
    return lines


def raw_key_display(key: DemoKey, raw_keys: dict[str, str]) -> str:
    return raw_keys.get(key.raw_env, "(missing; run `just demo-keys`)")


def print_key_list(config_path: Path, env_file: Path, keys: list[DemoKey], verbose: bool) -> None:
    env_status = "present" if env_file.exists() else "missing; run `just demo-keys`"
    raw_keys = parse_demo_raw_keys(env_file, keys)

    print(f"Demo API keys for {config_path}")
    print(f"Local key file: {env_file} ({env_status})")
    print()

    header = f"{'Key id':<22} {'Bruno':<12} {'Raw bearer key':<45} Choose this for"
    print(header)
    print("-" * len(header))
    for key in keys:
        operations = "; ".join(concise_operations_for(key))
        raw_key = raw_key_display(key, raw_keys)
        print(f"{key.key_id:<22} {key.bruno_var:<12} {raw_key:<45} {operations}")

    print()
    print("Use raw keys as Bearer tokens. Re-run `just demo-keys` to rotate them.")

    if not verbose:
        return

    print()
    for key in keys:
        print(f"{key.label} ({key.key_id})")
        print(f"  Bruno key: {key.bruno_var}")
        print(f"  Server env var: ${key.raw_env}")
        print(f"  Raw bearer key: {raw_key_display(key, raw_keys)}")
        hint = PERSONA_HINTS.get(key.key_id)
        if hint:
            print(f"  Plain-language use: {hint}")
        print("  OpenAPI-style operations:")
        for line in wrap_words(operations_for(key)):
            print(line)
        print("  Scope coverage:")
        for level in levels_for(key):
            datasets = datasets_by_level(key).get(level, [])
            if level == "admin":
                print("    admin: all admin routes")
            else:
                print(f"    {level}: {', '.join(datasets)}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        default="demo/config/all_standards.yaml",
        type=Path,
        help="demo config to inspect (default: demo/config/all_standards.yaml)",
    )
    parser.add_argument(
        "--env-file",
        default="demo/.env.local",
        type=Path,
        help="demo env file containing generated raw keys (default: demo/.env.local)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="include per-key env vars, plain-language hints, and scope coverage",
    )
    args = parser.parse_args()

    try:
        keys = parse_demo_keys(args.config)
    except OSError as exc:
        print(f"error: failed to read {args.config}: {exc}", file=sys.stderr)
        return 1

    if not keys:
        print(f"error: no auth.api_keys entries found in {args.config}", file=sys.stderr)
        return 1

    print_key_list(args.config, args.env_file, keys, args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
