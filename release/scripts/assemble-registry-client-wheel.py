#!/usr/bin/env python3
"""Combine the four internal client wheels into one public wheel."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import re
import tomllib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FACADE = ROOT / "crates" / "registry-stack-client-py"
PRODUCTS = ("discovery", "evidence", "relay", "breg")
WHEEL_PATTERN = re.compile(r"^[^-]+-(?P<version>[^-]+)-(?P<tag>.+)\.whl$")


def digest(data: bytes) -> str:
    value = (
        base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    )
    return f"sha256={value}"


def metadata(version: str) -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        "Name: registry-stack-client\n"
        f"Version: {version}\n"
        "Summary: Unified Python client for Registry Stack products.\n"
        "License-Expression: Apache-2.0\n"
        "Requires-Python: >=3.10\n"
        "Project-URL: Documentation, https://docs.registrystack.org/\n"
        "Project-URL: Issues, https://github.com/registrystack/registry-stack/issues\n"
        "Project-URL: Repository, https://github.com/registrystack/registry-stack\n"
        "Classifier: Development Status :: 4 - Beta\n"
        "Classifier: License :: OSI Approved :: Apache Software License\n"
        "Classifier: Programming Language :: Python :: 3\n\n"
        "One versioned Python entry point for Registry Stack client APIs.\n"
    ).encode()


def wheel_metadata(tag: str) -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: registry-stack-client-assembler\n"
        "Root-Is-Purelib: false\n"
        f"Tag: {tag}\n"
    ).encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    for product in PRODUCTS:
        parser.add_argument(f"--{product}-wheel", type=Path, required=True)
    args = parser.parse_args()

    configured_version = None
    try:
        configured_version = tomllib.loads(
            (FACADE / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        parser.error(f"cannot read the unified client version: {exc}")
    if configured_version != args.version:
        parser.error(
            "the unified Python facade version does not match "
            f"{args.version}: {configured_version}"
        )

    inputs = {product: getattr(args, f"{product}_wheel") for product in PRODUCTS}
    tags = set()
    files: dict[str, bytes] = {}
    for product, wheel in inputs.items():
        match = WHEEL_PATTERN.match(wheel.name)
        if match is None or match.group("version") != args.version:
            parser.error(
                f"{product} wheel does not match version {args.version}: {wheel.name}"
            )
        tags.add(match.group("tag"))
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                if ".dist-info/" in name or name.endswith("/"):
                    continue
                data = archive.read(name)
                package_prefix = f"registry_{product}_client/"
                if name.startswith(package_prefix):
                    destination = (
                        f"registry_client/{product}/{name[len(package_prefix) :]}"
                    )
                else:
                    # Preserve any wheel-owned sibling layout (for example an
                    # auditwheel `.libs` directory) relative to the relocated
                    # extension package while keeping it under our one owner.
                    destination = f"registry_client/{name}"
                if destination in files and files[destination] != data:
                    parser.error(f"conflicting wheel member: {destination}")
                files[destination] = data
    if len(tags) != 1:
        parser.error(f"input wheels have different compatibility tags: {sorted(tags)}")
    tag = tags.pop()

    facade_root = FACADE / "python" / "registry_client"
    for path in sorted(facade_root.iterdir()):
        if path.is_file():
            files[f"registry_client/{path.name}"] = path.read_bytes()
    dist_info = f"registry_stack_client-{args.version}.dist-info"
    files[f"{dist_info}/METADATA"] = metadata(args.version)
    files[f"{dist_info}/WHEEL"] = wheel_metadata(tag)
    files[f"{dist_info}/licenses/LICENSE"] = (ROOT / "LICENSE").read_bytes()

    rows = [
        [name, digest(data), str(len(data))] for name, data in sorted(files.items())
    ]
    rows.append([f"{dist_info}/RECORD", "", ""])
    record = io.StringIO(newline="")
    csv.writer(record, lineterminator="\n").writerows(rows)
    files[f"{dist_info}/RECORD"] = record.getvalue().encode()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / f"registry_stack_client-{args.version}-{tag}.whl"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = 0o100644 << 16
            archive.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
