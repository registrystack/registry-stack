#!/usr/bin/env python3
"""Render chart values from a saved Studio handover and operator bindings."""

import argparse
import copy
import hashlib
import json
import os
import re
import unicodedata
from pathlib import Path

from extension_endpoints import EndpointError, extension_values

INDEX_FORMAT = "id.registrystack.org/formats/platform/workspace-generated/v1alpha1"
CHART_KEYS = {"breg": "breg", "casework": "casework", "evidence": "evidence", "app-kit": "appKit"}
HANDOVER_METADATA = {"service-artifacts", "composition", "workspace", "dev", "rstack", "deployment"}
ENDPOINTS_PATH = "deployment/endpoints.json"
SHA256 = re.compile(r"[0-9a-f]{64}")


class WorkspaceError(Exception):
    """The published workspace or its deployment bindings were refused."""


def unique_members(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise WorkspaceError("A JSON object contains a duplicate member.")
    return result


def real_file(root, parts):
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise WorkspaceError("Published workspace files must be real files inside the handover.")
    if not path.is_file():
        raise WorkspaceError(f"Published file {path.relative_to(root)} is missing.")
    return path


def published_handover(root):
    index_path = real_file(root, ("workspace", "generated.json"))
    index = json.loads(index_path.read_text(), object_pairs_hook=unique_members)
    if (
        index.get("apiVersion") != INDEX_FORMAT or index.get("kind") != "WorkspaceGenerated"
        or not isinstance(index.get("sourceVersion"), str) or not index["sourceVersion"].strip()
        or not SHA256.fullmatch(index.get("sourceHash", ""))
        or not isinstance(index.get("files"), list) or not index["files"]
    ):
        raise WorkspaceError("Publish a saved workspace with a source hash and generated file index.")
    products = {}
    seen = set()
    endpoint_intent = None
    for entry in index["files"]:
        relative = entry.get("path", "")
        parts = relative.split("/")
        canonical = unicodedata.normalize("NFC", relative).casefold()
        if (
            not relative or any(not part or part.startswith(".") for part in parts)
            or any(character in relative for character in ("\\", ":", "\0"))
            or unicodedata.normalize("NFKC", parts[0]).lower() == "workspace"
            or canonical in seen
        ):
            raise WorkspaceError("The generated index contains an unsafe or duplicate path.")
        seen.add(canonical)
        path = real_file(root, parts)
        if relative == ENDPOINTS_PATH:
            endpoint_bytes = path.read_bytes()
            actual = hashlib.sha256(endpoint_bytes).hexdigest()
        else:
            with path.open("rb") as content:
                actual = hashlib.file_digest(content, "sha256").hexdigest()
        if actual != entry.get("sha256"):
            raise WorkspaceError(f"The hash differs for {relative}. Republish the saved workspace.")
        source = entry.get("source", {})
        if source.get("type") not in {"native", "product"} or not isinstance(source.get("product"), str):
            raise WorkspaceError(f"The index does not identify the owning product for {relative}.")
        if relative == ENDPOINTS_PATH:
            if source["product"] != "deployment":
                raise WorkspaceError("Publish the endpoint declaration as a deployment native mapping.")
            endpoint_intent = json.loads(endpoint_bytes, object_pairs_hook=unique_members)
            if not isinstance(endpoint_intent, dict):
                raise WorkspaceError("The published endpoint declaration must be an object.")
        products.setdefault(source["product"], []).append(relative)
    if endpoint_intent is None and (root / ENDPOINTS_PATH).exists():
        raise WorkspaceError("Publish the endpoint declaration in the generated file index.")
    return index["sourceHash"], products, endpoint_intent


def render_workspace(root, bindings, selected=None):
    source_hash, products, endpoint_intent = published_handover(root)
    if bindings.get("workspaceSourceHash") != source_hash:
        raise WorkspaceError("Operator bindings must identify the selected saved workspace source hash.")
    selected = set(selected) if selected else products.keys() - HANDOVER_METADATA
    missing = selected - products.keys()
    if missing:
        raise WorkspaceError(f"Requested products are absent from the handover: {', '.join(sorted(missing))}.")
    unsupported = selected - CHART_KEYS.keys()
    if unsupported:
        raise WorkspaceError(f"The chart has no module for {', '.join(sorted(unsupported))}.")
    if not selected:
        raise WorkspaceError("Select at least one deployed product from the handover.")
    if "breg" in selected and sum(path.split("/")[-1] == "registry.yaml" for path in products["breg"]) != 1:
        raise WorkspaceError("This chart release requires exactly one published BReg registry project.")

    result = copy.deepcopy(bindings)
    result.pop("workspaceSourceHash")
    endpoint_bindings = result.pop("extensions", None)
    for product, chart_key in CHART_KEYS.items():
        if product in selected and (chart_key not in result or not isinstance(result[chart_key], dict)):
            raise WorkspaceError(f"Provide operator Helm bindings for {product}.")
        if chart_key in result:
            component = result[chart_key]
            if not isinstance(component, dict):
                raise WorkspaceError(f"Operator Helm bindings for {product} must be an object.")
            component["enabled"] = product in selected
            component["serve"] = product in selected
    if endpoint_intent is None:
        if endpoint_bindings is not None:
            raise WorkspaceError("Publish the endpoint declaration in the generated file index.")
        return result, None
    extensions = extension_values(endpoint_intent, endpoint_bindings)
    for product in selected:
        ingress = result[CHART_KEYS[product]].get("ingress", {})
        if ingress.get("enabled") and ingress.get("host") == extensions["publicHost"]:
            raise WorkspaceError("Give the extensions a separate HTTPS hostname from the Registry Stack products.")
    pull_secrets = extensions.pop("imagePullSecrets", None)
    extension_release = {"extensions": extensions}
    if pull_secrets is not None:
        extension_release["global"] = {"imagePullSecrets": pull_secrets}
    return result, extension_release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--bindings", type=Path, required=True, help="Operator Helm values in JSON.")
    parser.add_argument("--product", action="append", choices=sorted(CHART_KEYS), help="Select a published product.")
    parser.add_argument("--extension-values", type=Path, help="Write values for the separate endpoint release to a new file.")
    args = parser.parse_args()
    try:
        bindings = json.loads(args.bindings.read_text(), object_pairs_hook=unique_members)
        if not isinstance(bindings, dict):
            raise WorkspaceError("Operator Helm values must be an object.")
        result, extensions = render_workspace(args.workspace_root.resolve(strict=True), bindings, args.product)
        if (extensions is None) != (args.extension_values is None):
            raise WorkspaceError("Use --extension-values when the handover declares extensions.")
        if extensions is not None:
            os.umask(0o077)
            with args.extension_values.open("x") as output:
                output.write(json.dumps(extensions, indent=2) + "\n")
    except (OSError, WorkspaceError, EndpointError, ValueError, AttributeError, TypeError) as error:
        parser.exit(1, f"workspace-values: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
