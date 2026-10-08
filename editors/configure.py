#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Set up version-matched Registry Stack schemas and check tasks for a project."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
MANAGED = ".registry-stack-editor"
PRODUCT_FILES = {
    "breg": "registry.yaml",
    "breg-mcp": "runtime.yaml",
    "breg-review": "runtime.yaml",
    "casework": "casework.yaml",
    "scheduling": "scheduling.yaml",
    "messaging": "messaging.yaml",
    "discovery": "origins.yaml",
    "manifest": "metadata.yaml",
    "render": "manifest.yaml",
    "evidence": "evidence-project.yaml",
    "platform": "task-connection.yaml",
}
PRODUCTS = (*PRODUCT_FILES, "evidence-oid4vci")
SCHEMAS = {
    "breg": (
        ("products/breg/generated/authoring/registry-project.schema.json", "registry.yaml"),
        ("products/breg/generated/authoring/registry-module.schema.json", "modules/**/module.yaml"),
        ("products/breg/generated/runtime/runtime.schema.json", "runtime.yaml"),
        ("products/breg/generated/runtime/runtime.schema.json", "runtime.example.yaml"),
        ("products/breg/generated/tools/journeys.v1.schema.json", "tests/journeys.yaml"),
        ("products/breg/generated/tools/schema-test-credentials.v1.schema.json", "credentials.yaml"),
        ("products/breg/generated/tools/model-selection.v1alpha1.schema.json", "model/selection.yaml"),
    ),
    "breg-mcp": (("products/breg/generated/mcp-runtime/mcp-runtime.schema.json", "runtime.yaml"),),
    "breg-review": (("products/breg/generated/review-runtime/review-runtime.schema.json", "runtime.yaml"),),
    "casework": (
        ("products/casework/generated/project/project.schema.json", "casework.yaml"),
        ("products/casework/generated/runtime/runtime.schema.json", "runtime.yaml"),
        ("products/casework/generated/runtime/runtime.schema.json", "runtime.example.yaml"),
        ("products/casework/generated/fixture/fixture.schema.json", "fixtures/*.yaml"),
        ("products/casework/generated/fixture/fixture.schema.json", "fixtures/*.yml"),
        ("products/casework/generated/simulation/simulation.schema.json", "simulations/*.yaml"),
        ("products/casework/generated/simulation/simulation.schema.json", "simulations/*.yml"),
        (
            "products/casework/generated/holiday-set/holiday-set.schema.json",
            "simulations/holiday-sets/*.yaml",
        ),
        (
            "products/casework/generated/holiday-set/holiday-set.schema.json",
            "simulations/holiday-sets/*.yml",
        ),
        ("products/casework/generated/dev-clients/dev-clients.schema.json", "dev-clients.yaml"),
    ),
    "scheduling": (
        ("products/scheduling/generated/project/project.schema.json", "scheduling.yaml"),
        ("products/scheduling/generated/runtime/runtime.schema.json", "runtime.yaml"),
        ("products/scheduling/generated/runtime/runtime.schema.json", "runtime.example.yaml"),
        ("products/scheduling/generated/records/records.schema.json", "records.yaml"),
        ("products/scheduling/generated/fixture/fixture.schema.json", "fixtures/*.yaml"),
        ("products/scheduling/generated/fixture/fixture.schema.json", "fixtures/*.yml"),
    ),
    "messaging": (
        ("products/messaging/generated/authoring/project.schema.json", "messaging.yaml"),
        ("products/messaging/generated/authoring/template.schema.json", "templates/*/*/template.yaml"),
        ("products/messaging/generated/authoring/provider.schema.json", "providers/*/provider.yaml"),
        ("products/messaging/generated/runtime/runtime.schema.json", "runtime.yaml"),
        ("products/messaging/generated/runtime/runtime.schema.json", "runtime.example.yaml"),
    ),
    "evidence-oid4vci": (
        ("products/evidence/generated/oid4vci-runtime/oid4vci-runtime.schema.json", "{document}"),
    ),
    "discovery": (
        ("products/discovery/schemas/origins.schema.json", "origins.yaml"),
        ("products/discovery/schemas/runtime.schema.json", "runtime.yaml"),
        ("products/discovery/schemas/evidence-mapping.schema.json", "mappings/*.yaml"),
        ("products/discovery/schemas/evidence-mapping.schema.json", "mappings/*.yml"),
    ),
    "render": (
        ("products/render/schemas/bundle.schema.json", "manifest.yaml"),
        ("products/render/schemas/labels.schema.json", "labels/*.yaml"),
        ("products/render/schemas/runtime.schema.json", "runtime.yaml"),
    ),
    "manifest": (
        ("products/manifest/schemas/metadata.schema.json", "{document}"),
        ("products/manifest/schemas/profile.schema.json", "**/profile.yaml"),
    ),
    "platform": (
        ("products/platform/schemas/task-connection.schema.json", "task-connection.yaml"),
    ),
}
CHECKS = {
    "breg": ("bregctl", "check", "{project}"),
    "breg-mcp": ("breg-mcp", "--runtime-config", "{entry}", "check"),
    "breg-review": ("breg-review", "--runtime-config", "{entry}", "check"),
    "casework": ("caseworkctl", "check", "{project}"),
    "scheduling": ("schedulingctl", "check", "{project}"),
    "messaging": ("messagingctl", "check", "--project", "{project}"),
    "discovery": ("discoveryctl", "check", "--project", "{project}"),
    "manifest": ("registry-manifest", "validate", "{document}"),
    "render": ("registry-render", "check", "--bundle", "{project}"),
    "evidence": ("evidencectl", "check", "{project}"),
    "platform": ("evidencectl", "dev", "check", "task-connection.yaml"),
    "evidence-oid4vci": ("evidence-oid4vci", "check", "--config", "{document}"),
}


class SetupError(Exception):
    pass


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode()


def refuse_symlink_below(path: Path, root: Path) -> None:
    if not path.is_relative_to(root):
        raise SetupError(f"refusing path outside managed root: {path}")
    current = path
    while True:
        refuse_symlink(current)
        if current == root:
            break
        current = current.parent


def read_json(path: Path, default: Any, root: Path) -> Any:
    refuse_symlink_below(path, root)
    if not path.exists() and not path.is_symlink():
        return default
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeError) as error:
        raise SetupError(
            f"{path} is not strict JSON; remove JSONC comments or edit it manually. Nothing was changed."
        ) from error


def refuse_symlink(path: Path) -> None:
    if path.is_symlink():
        raise SetupError(f"refusing symbolic link: {path}")


def safe_document(project: Path, raw: str) -> tuple[str, Path]:
    if "\\" in raw:
        raise SetupError("--document must use forward slashes")
    relative = PurePosixPath(raw)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in raw.split("/")):
        raise SetupError("--document must be a safe project-relative YAML path")
    if relative.suffix not in (".yaml", ".yml"):
        raise SetupError("--document must name a YAML file")
    target = project
    for part in relative.parts:
        target /= part
        refuse_symlink(target)
    if not target.is_file():
        raise SetupError(f"authored document does not exist: {target}")
    return str(relative), target


def workspace_version() -> str:
    import re

    cargo = (ROOT / "Cargo.toml").read_text()
    section = cargo.split("[workspace.package]", 1)[1].split("\n[", 1)[0]
    match = re.search(r'^version\s*=\s*"([^"]+)"', section, re.MULTILINE)
    if match is None:
        raise SetupError("could not read the Registry Stack workspace version")
    return match.group(1)


def matching_cli(name: str) -> str:
    command = shutil.which(name)
    if command is None:
        raise SetupError(f"{name} is required for this product's editor schemas")
    result = subprocess.run(
        [command, "--version"], capture_output=True, text=True, timeout=5, check=False
    )
    expected = workspace_version()
    version = result.stdout.strip().split()
    if (
        result.returncode != 0
        or len(version) < 2
        or version[0] != name
        or version[1] not in (expected, f"{expected}-dev")
    ):
        raise SetupError(f"{name} must report Registry Stack {expected} or {expected}-dev")
    return command


def check_project(product: str, project: Path, document_arg: str | None) -> tuple[str | None, Path | None]:
    if not project.is_dir() or project.is_symlink():
        raise SetupError(f"project must be a real directory: {project}")
    if document_arg is not None and product not in ("manifest", "evidence-oid4vci"):
        raise SetupError("--document applies only to manifest and evidence-oid4vci")
    if product == "evidence-oid4vci" and document_arg is None:
        raise SetupError("evidence-oid4vci requires --document for its authored YAML file")
    if product == "manifest" or product == "evidence-oid4vci":
        return safe_document(project, document_arg or PRODUCT_FILES["manifest"])
    marker = PRODUCT_FILES[product]
    if product == "evidence" and not (project / marker).is_file():
        if (project / "source.openapi.yaml").is_file() and (project / "questions").is_dir():
            return None, None
    if not (project / marker).is_file() or (project / marker).is_symlink():
        raise SetupError(f"{product} project needs {marker}: {project}")
    return None, None


def task_for(product: str, project: Path, document: Path | None) -> tuple[dict[str, Any], dict[str, Any]] | None:
    spec = CHECKS.get(product)
    if spec is None:
        return None
    command = spec[0]
    args = [
        str(project) if arg == "{project}"
        else str(document) if arg == "{document}"
        else str(project / PRODUCT_FILES[product]) if arg == "{entry}"
        else arg
        for arg in spec[1:]
    ]
    label = f"Registry Stack: check {product} ({project})"
    vscode = {
        "label": label,
        "type": "process",
        "command": command,
        "args": args,
        "options": {"cwd": str(project)},
        "problemMatcher": [],
    }
    zed = {"label": label, "command": command, "args": args, "cwd": str(project)}
    return vscode, zed


def updated_settings(
    original: dict[str, Any], previous: dict[str, list[str]], desired: dict[str, list[str]], zed: bool
) -> dict[str, Any]:
    result = json.loads(json.dumps(original))
    if zed:
        lsp = result.setdefault("lsp", {})
        if not isinstance(lsp, dict):
            raise SetupError("Zed lsp setting must be an object")
        server = lsp.setdefault("yaml-language-server", {})
        if not isinstance(server, dict):
            raise SetupError("Zed yaml-language-server setting must be an object")
        settings = server.setdefault("settings", {})
        if not isinstance(settings, dict):
            raise SetupError("Zed language-server settings must be an object")
        yaml = settings.setdefault("yaml", {})
        if not isinstance(yaml, dict):
            raise SetupError("Zed yaml settings must be an object")
        mappings = yaml.setdefault("schemas", {})
    else:
        mappings = result.setdefault("yaml.schemas", {})
    if not isinstance(mappings, dict):
        raise SetupError("YAML schema mappings must be an object")
    for key, value in previous.items():
        if key in mappings:
            if mappings[key] != value:
                raise SetupError(f"managed schema mapping was edited: {key}")
            del mappings[key]
    for key, value in desired.items():
        if key in mappings and mappings[key] != value:
            raise SetupError(f"schema mapping already exists: {key}")
        mappings[key] = value
    return result


def updated_tasks(
    original: Any, previous: dict[str, Any] | None, desired: dict[str, Any] | None, zed: bool
) -> Any:
    if zed:
        if not isinstance(original, list):
            raise SetupError("Zed tasks.json must be an array")
        tasks = list(original)
        result = tasks
    else:
        if not isinstance(original, dict):
            raise SetupError("VS Code tasks.json must be an object")
        result = json.loads(json.dumps(original))
        tasks = result.setdefault("tasks", [])
        if not isinstance(tasks, list):
            raise SetupError("VS Code tasks must be an array")
    if previous is not None:
        for index, task in enumerate(tasks):
            if isinstance(task, dict) and task.get("label") == previous["label"]:
                if task != previous:
                    raise SetupError(f"managed task was edited: {previous['label']}")
                del tasks[index]
                break
    if desired is not None:
        if any(isinstance(task, dict) and task.get("label") == desired["label"] for task in tasks):
            raise SetupError(f"task label already exists: {desired['label']}")
        tasks.append(desired)
    return result


def prepare_file(path: Path, value: bytes, writes: dict[Path, bytes], root: Path) -> None:
    refuse_symlink_below(path, root)
    writes[path] = value


def publish(writes: dict[Path, bytes], project: Path, workspace: Path) -> None:
    for path in writes:
        if not path.is_relative_to(project) and not path.is_relative_to(workspace):
            raise SetupError(f"refusing write outside project or workspace: {path}")
        refuse_symlink_below(path, project if path.is_relative_to(project) else workspace)
    for path, content in writes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.read_bytes() == content:
            continue
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".registry-stack-editor-", delete=False) as staged:
            staged.write(content)
            staged_path = Path(staged.name)
        os.replace(staged_path, path)


def configure(product: str, project: Path, workspace: Path, document_arg: str | None) -> None:
    project = project.absolute()
    workspace = workspace.absolute()
    if not workspace.is_dir() or workspace.is_symlink() or not project.is_relative_to(workspace):
        raise SetupError("--workspace must be a real ancestor of the project")
    document_name, document = check_project(product, project, document_arg)
    state_path = project / MANAGED / "state.json"
    prior = read_json(state_path, {}, project)
    if not isinstance(prior, dict) or (
        prior
        and (
            prior.get("format") != "registry-stack-editor/v1"
            or prior.get("product") != product
            or prior.get("project") != str(project)
            or prior.get("workspace") != str(workspace)
            or not isinstance(prior.get("mappings"), dict)
            or not isinstance(prior.get("schema_hashes"), dict)
        )
    ):
        raise SetupError("editor setup state does not match this product, project, and workspace")

    schema_bytes: dict[Path, bytes] = {}
    mappings: dict[str, list[str]] = {}
    for source_name, relative_pattern in SCHEMAS.get(product, ()):
        source = ROOT / source_name
        if not source.is_file():
            raise SetupError(f"maintained schema is missing: {source}")
        destination = project / MANAGED / "schemas" / source.name
        content = source.read_bytes()
        expected_hash = prior.get("schema_hashes", {}).get(str(destination))
        if destination.exists() or destination.is_symlink():
            refuse_symlink_below(destination, project)
            current_hash = hashlib.sha256(destination.read_bytes()).hexdigest()
            if expected_hash is None or current_hash != expected_hash:
                raise SetupError(f"managed schema was edited or not owned: {destination}")
        schema_bytes[destination] = content
        pattern = document_name if relative_pattern == "{document}" else relative_pattern
        mappings.setdefault(destination.as_uri(), []).append(str(project / pattern))

    task_pair = task_for(product, project, document)
    vscode_task, zed_task = task_pair if task_pair else (None, None)
    writes: dict[Path, bytes] = {}
    old_mappings = prior.get("mappings", {})
    old_vscode_task = prior.get("vscode_task")
    old_zed_task = prior.get("zed_task")
    for editor, is_zed, task, old_task in (
        ("vscode", False, vscode_task, old_vscode_task),
        ("zed", True, zed_task, old_zed_task),
    ):
        settings_path = workspace / f".{editor}" / "settings.json"
        if mappings or old_mappings:
            original = read_json(settings_path, {}, workspace)
            if not isinstance(original, dict):
                raise SetupError(f"{settings_path} must contain an object")
            prepare_file(
                settings_path,
                json_bytes(updated_settings(original, old_mappings, mappings, is_zed)),
                writes,
                workspace,
            )
        tasks_path = workspace / f".{editor}" / "tasks.json"
        if task is not None or old_task is not None:
            original_tasks = read_json(
                tasks_path, [] if is_zed else {"version": "2.0.0", "tasks": []}, workspace
            )
            prepare_file(
                tasks_path,
                json_bytes(updated_tasks(original_tasks, old_task, task, is_zed)),
                writes,
                workspace,
            )

    if product in ("manifest", "evidence-oid4vci"):
        marker_path = project / MANAGED / "project.json"
        marker = {"product": product, "document": document_name}
        current_marker = read_json(marker_path, None, project)
        if current_marker is not None and current_marker != marker:
            raise SetupError(f"editor project marker was edited: {marker_path}")
        prepare_file(marker_path, json_bytes(marker), writes, project)

    for path, content in schema_bytes.items():
        prepare_file(path, content, writes, project)
    state = {
        "format": "registry-stack-editor/v1",
        "product": product,
        "project": str(project),
        "workspace": str(workspace),
        "source_version": workspace_version(),
        "source_schemas": {
            str(project / MANAGED / "schemas" / Path(source_name).name): source_name
            for source_name, _ in SCHEMAS.get(product, ())
        },
        "mappings": mappings,
        "schema_hashes": {
            str(path): hashlib.sha256(content).hexdigest() for path, content in schema_bytes.items()
        },
        "vscode_task": vscode_task,
        "zed_task": zed_task,
    }
    prepare_file(state_path, json_bytes(state), writes, project)

    # The two established authoring CLIs own their schema snapshots and editor mappings.
    # Run them only after validating our settings and task files.
    if product == "evidence":
        name = "evidencectl"
        command = matching_cli(name)
        args = [command, "tooling", "editor", str(project)]
        if product == "evidence" and workspace != project:
            args.extend(["--workspace", str(workspace)])
        result = subprocess.run(args, check=False)
        if result.returncode != 0:
            raise SetupError(f"{name} tooling editor failed; no Registry Stack tasks were changed")
    publish(writes, project, workspace)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("product", choices=PRODUCTS)
    parser.add_argument("project", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--document")
    args = parser.parse_args()
    try:
        configure(args.product, args.project, args.workspace or args.project, args.document)
    except (OSError, SetupError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"Configured Registry Stack {args.product} editor support for {args.project.absolute()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
