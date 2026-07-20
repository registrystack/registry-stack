#!/usr/bin/env python3
"""Check marked release-manual examples against the public CLI parser."""

from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import json
import re
import shlex
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANUAL = ROOT / "release" / "MANUAL.md"
REGISTRY_RELEASE = ROOT / "release" / "scripts" / "registry-release"
MARKED_BLOCK = re.compile(
    r"<!--\s*registry-release-check\s*-->\s*```(?:bash|sh)\s*\n(.*?)```",
    re.DOTALL,
)
VARIABLE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*")


def load_release_module() -> Any:
    loader = importlib.machinery.SourceFileLoader("registry_release", str(REGISTRY_RELEASE))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise ImportError(f"could not load {REGISTRY_RELEASE}")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def extract_examples(text: str) -> list[str]:
    return [match.group(1).strip() for match in MARKED_BLOCK.finditer(text)]


def example_argv(example: str) -> list[str]:
    flattened = re.sub(r"\\\s*\n", " ", example)
    tokens = shlex.split(flattened, comments=True, posix=True)
    command_index = next(
        (
            index
            for index, token in enumerate(tokens)
            if Path(token).name == "registry-release"
        ),
        None,
    )
    if command_index is None:
        raise ValueError("marked block does not invoke registry-release")
    args = tokens[command_index + 1 :]
    if not args:
        raise ValueError("marked block does not select a registry-release command")
    return [VARIABLE.sub("example", token) for token in args]


def check_manual(manual: Path) -> dict[str, Any]:
    errors: list[str] = []
    commands: list[dict[str, Any]] = []
    try:
        text = manual.read_text(encoding="utf-8")
        examples = extract_examples(text)
        if not examples:
            errors.append("manual contains no marked registry-release examples")
            examples = []
        module = load_release_module()
        parser = module.build_parser()
        help_text = parser.format_help()
        if not help_text.startswith("usage: registry-release"):
            errors.append("public CLI help has an unexpected program name")
        for index, example in enumerate(examples, start=1):
            try:
                argv = example_argv(example)
                with redirect_stderr(StringIO()):
                    parsed = parser.parse_args(argv)
                command = str(parsed.command)
                commands.append({"index": index, "command": command, "argv": argv})
            except (SystemExit, ValueError) as exc:
                errors.append(f"example {index} is not accepted by public CLI help: {exc}")
    except (OSError, UnicodeError, ImportError, AttributeError) as exc:
        errors.append(f"cannot check release manual {manual}: {exc}")
    try:
        manual_identity = manual.resolve().relative_to(ROOT).as_posix()
    except (OSError, ValueError):
        manual_identity = str(manual)
    return {
        "schema_version": "registry-stack.release-manual-check.v1",
        "manual": manual_identity,
        "status": "passed" if not errors else "failed",
        "commands_checked": commands,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate marked release manual commands against registry-release help."
    )
    parser.add_argument("--manual", type=Path, default=DEFAULT_MANUAL)
    args = parser.parse_args()
    result = check_manual(args.manual)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
