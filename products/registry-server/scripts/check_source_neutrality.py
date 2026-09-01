#!/usr/bin/env python3
"""Reject authored fixture identifiers in shipped Registry Server source."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


FORBIDDEN_FIXTURE_IDENTIFIERS = (
    "business-establishments-core",
    "business-establishment-summary",
    "operator-assignment",
    "public-authority",
    "facility-core",
    "inspection-core",
    "inspection-observation",
    "discharge-report",
    "/v1/records/businesses",
    "/v1/records/authorities",
    "/v1/records/establishments",
    "/v1/records/operator-assignments",
    "/v1/records/facilities",
    "/v1/records/permits",
    "/v1/records/installations",
    "/v1/records/discharge-reports",
    "asset-site-placement",
    "asset-site-placement-core",
    "asset-item",
    "asset-site",
    "asset-placement",
    "inspection-event",
    "/v1/records/assets",
    "/v1/records/sites",
    "/v1/records/placements",
    "household-core",
    "publicschema-household-core",
    "publicschema-household-demographics",
    "group-membership",
    "/v1/records/persons",
    "/v1/records/households",
    "/v1/records/group-memberships",
    "disability-core",
    "assessment-episode",
    "functioning-observation",
    "/v1/records/assessment-episodes",
    "/v1/records/functioning-observations",
    "/v1/records/certifications",
    "farmer-core",
    "seasonal-activity",
    "/v1/records/farmers",
    "/v1/records/holdings",
    "/v1/records/plots",
    "/v1/records/seasonal-activities",
    "business-core",
    "legal-entity",
    "officer-appointment",
    "/v1/records/legal-entities",
    "/v1/records/filings",
    "/v1/records/officer-appointments",
)
FORBIDDEN_RUST_TYPE_IDENTIFIERS = (
    "Establishment",
    "Business",
    "PublicAuthority",
    "OperatorAssignment",
    "Facility",
    "Installation",
    "InspectionObservation",
    "DischargeReport",
    "Asset",
    "Site",
    "Placement",
    "InspectionEvent",
    "Person",
    "Household",
    "GroupMembership",
    "AssessmentEpisode",
    "FunctioningObservation",
    "Certification",
    "Farmer",
    "Holding",
    "Plot",
    "SeasonalActivity",
    "LegalEntity",
    "Filing",
    "OfficerAppointment",
)
FORBIDDEN_DOMAIN_COMPONENTS = (
    "site",
    "sites",
    "placement",
    "placements",
    "inspection",
    "inspections",
    "person",
    "persons",
    "household",
    "households",
    "membership",
    "memberships",
    "assessment",
    "assessments",
    "observation",
    "observations",
    "certification",
    "certifications",
    "disability",
    "farmer",
    "farmers",
    "holding",
    "holdings",
    "plot",
    "plots",
    "seasonal",
    "business",
    "filing",
    "filings",
    "appointment",
    "appointments",
)
SOURCE_ROOTS = (
    "crates/registry-relay-client",
    "crates/registry-server",
    "crates/registry-serverctl",
)
SOURCE_SUFFIXES = {".rs"}
PRODUCTION_INPUT_DIRECTORIES = ("resources", "schemas", "migrations", "templates")
EXCLUDED_SOURCE_DIRECTORIES = {"tests", "fixtures", "examples", "benches"}
PUBLIC_KERNEL_CONTRACTS = ("products/registry-server/contracts/package-layout.yaml",)
DOMAIN_COMPONENT = re.compile(
    r"(?i)(?:^|[._:/-])(?:"
    + "|".join(re.escape(value) for value in FORBIDDEN_DOMAIN_COMPONENTS)
    + r")(?=$|[._:/-])"
)
DOMAIN_WORD = re.compile(
    r"(?i)\b(?:"
    + "|".join(re.escape(value) for value in FORBIDDEN_DOMAIN_COMPONENTS)
    + r")\b"
)


def source_files(repository_root: Path) -> list[Path]:
    files: list[Path] = []
    for relative_root in SOURCE_ROOTS:
        root = repository_root / relative_root
        if root.is_dir():
            source_root = root / "src"
            if source_root.is_dir():
                files.extend(
                    path
                    for path in source_root.rglob("*")
                    if path.is_file()
                    and path.suffix in SOURCE_SUFFIXES
                    and not (set(path.relative_to(root).parts) & EXCLUDED_SOURCE_DIRECTORIES)
                )
            build_script = root / "build.rs"
            if build_script.is_file():
                files.append(build_script)
            manifest = root / "Cargo.toml"
            if manifest.is_file():
                files.append(manifest)
            for directory_name in PRODUCTION_INPUT_DIRECTORIES:
                directory = root / directory_name
                if directory.is_dir():
                    files.extend(
                        path
                        for path in directory.rglob("*")
                        if path.is_file() and not (set(path.relative_to(root).parts) & EXCLUDED_SOURCE_DIRECTORIES)
                    )
    for relative_path in PUBLIC_KERNEL_CONTRACTS:
        contract = repository_root / relative_path
        if contract.is_file():
            files.append(contract)
    return sorted(set(files))


def rust_structure(source: str) -> str:
    """Blank Rust comments and literals while preserving code positions."""
    masked = list(source)
    index = 0
    block_depth = 0
    while index < len(source):
        if block_depth:
            if source.startswith("/*", index):
                masked[index : index + 2] = "  "
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                masked[index : index + 2] = "  "
                block_depth -= 1
                index += 2
            else:
                if source[index] != "\n":
                    masked[index] = " "
                index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end < 0 else end
            masked[index:end] = " " * (end - index)
            index = end
            continue
        if source.startswith("/*", index):
            masked[index : index + 2] = "  "
            block_depth = 1
            index += 2
            continue
        raw = re.match(r"(?:br|r)(?P<hashes>#{0,255})\"", source[index:])
        if raw:
            delimiter = '"' + raw.group("hashes")
            end = source.find(delimiter, index + len(raw.group(0)))
            end = len(source) if end < 0 else end + len(delimiter)
            for position in range(index, end):
                if source[position] != "\n":
                    masked[position] = " "
            index = end
            continue
        if source[index] == "'" and not (
            index + 2 < len(source) and (source[index + 2] == "'" or source[index + 1] == "\\")
        ):
            index += 1
            continue
        if source[index] in {'"', "'"} or source.startswith('b"', index) or source.startswith("b'", index):
            quote_index = index + 1 if source.startswith("b", index) else index
            quote = source[quote_index]
            end = quote_index + 1
            escaped = False
            while end < len(source):
                character = source[end]
                if character == quote and not escaped:
                    end += 1
                    break
                escaped = character == "\\" and not escaped
                if character != "\\":
                    escaped = False
                end += 1
            for position in range(index, end):
                if source[position] != "\n":
                    masked[position] = " "
            index = end
            continue
        index += 1
    return "".join(masked)


def without_cfg_test_items(source: str) -> str:
    """Remove Rust items gated by cfg(test), including their nested braces."""
    structure = rust_structure(source)
    masked = list(source)
    attribute = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    for match in attribute.finditer(structure):
        brace = structure.find("{", match.end())
        semicolon = structure.find(";", match.end())
        if brace < 0 or (semicolon >= 0 and semicolon < brace):
            end = semicolon + 1 if semicolon >= 0 else len(source)
        else:
            depth = 0
            end = brace
            while end < len(structure):
                if structure[end] == "{":
                    depth += 1
                elif structure[end] == "}":
                    depth -= 1
                    if depth == 0:
                        end += 1
                        break
                end += 1
        for position in range(match.start(), end):
            if source[position] != "\n":
                masked[position] = " "
    return "".join(masked)


def rust_string_literals(source: str) -> list[str]:
    """Return simple and raw Rust string bodies for identifier inspection."""
    literals: list[str] = []
    index = 0
    while index < len(source):
        raw = re.match(r"(?:br|r)(?P<hashes>#{0,255})\"", source[index:])
        if raw:
            body_start = index + len(raw.group(0))
            delimiter = '"' + raw.group("hashes")
            end = source.find(delimiter, body_start)
            if end < 0:
                break
            literals.append(source[body_start:end])
            index = end + len(delimiter)
            continue
        if source.startswith('b"', index) or source[index] == '"':
            quote_index = index + 1 if source.startswith("b", index) else index
            body_start = quote_index + 1
            body: list[str] = []
            position = body_start
            while position < len(source):
                character = source[position]
                if character == "\\":
                    if position + 1 < len(source):
                        body.append(source[position : position + 2])
                        position += 2
                        continue
                    body.append(character)
                    position += 1
                    continue
                if character == '"':
                    break
                body.append(character)
                position += 1
            literals.append("".join(body))
            index = position + 1
            continue
        if source.startswith("b'", index) or source[index] == "'":
            quote_index = index + 1 if source.startswith("b", index) else index
            position = quote_index + 1
            saw_body = False
            while position < len(source):
                character = source[position]
                if character == "\\":
                    saw_body = True
                    position += 2
                    continue
                if character == "'":
                    position += 1
                    break
                if character.isspace():
                    break
                saw_body = True
                position += 1
            if saw_body and position <= len(source) and source[position - 1 : position] == "'":
                index = position
                continue
        index += 1
    return literals


def cargo_feature_names(source: str) -> list[str]:
    names: list[str] = []
    in_features = False
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_features = line == "[features]"
            continue
        if not in_features or not line or line.startswith("#") or "=" not in line:
            continue
        names.append(line.split("=", 1)[0].strip().strip('"'))
    return names


def domain_identifier(value: str) -> str | None:
    match = DOMAIN_COMPONENT.search(value)
    return match.group(0).strip("._:/-") if match else None


def domain_word(value: str) -> str | None:
    match = DOMAIN_WORD.search(value)
    return match.group(0) if match else None


def is_production_input(path: Path, crate_root: Path) -> bool:
    return bool(set(path.relative_to(crate_root).parts) & set(PRODUCTION_INPUT_DIRECTORIES))


def find_violations(repository_root: Path) -> list[str]:
    violations: list[str] = []
    for source in source_files(repository_root):
        try:
            text = source.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        relative = source.relative_to(repository_root)
        crate_root = next(
            (repository_root / root for root in SOURCE_ROOTS if source.is_relative_to(repository_root / root)),
            None,
        )
        inspected = without_cfg_test_items(text) if source.suffix == ".rs" else text
        lowered = inspected.lower()
        for marker in FORBIDDEN_FIXTURE_IDENTIFIERS:
            if marker in lowered:
                violations.append(f"{relative}: contains fixture identifier {marker}")
        if source.suffix == ".rs":
            structure = rust_structure(inspected)
            for identifier in FORBIDDEN_RUST_TYPE_IDENTIFIERS:
                if re.search(rf"\b{re.escape(identifier)}\b", structure):
                    violations.append(
                        f"{relative}: contains fixture Rust type identifier {identifier}"
                    )
            for literal in rust_string_literals(inspected):
                identifier = domain_identifier(literal)
                if identifier is not None:
                    violations.append(
                        f"{relative}: contains fixture metric/error identifier {identifier}"
                    )
        elif source.name == "Cargo.toml":
            for feature in cargo_feature_names(inspected):
                identifier = domain_identifier(feature)
                if identifier is not None:
                    violations.append(
                        f"{relative}: contains fixture Cargo feature {feature}"
                    )
        elif crate_root is not None and is_production_input(source, crate_root):
            identifier = domain_word(inspected)
            if identifier is not None:
                violations.append(
                    f"{relative}: contains fixture production identifier {identifier}"
                )
        elif str(relative) in PUBLIC_KERNEL_CONTRACTS:
            identifier = domain_identifier(inspected)
            if identifier is not None:
                violations.append(
                    f"{relative}: contains fixture production identifier {identifier}"
                )
    return sorted(set(violations))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()
    violations = find_violations(args.repository_root.resolve())
    if violations:
        print("Registry Server source-neutrality check failed:", file=sys.stderr)
        print("\n".join(f"- {item}" for item in violations), file=sys.stderr)
        return 1
    print("Registry Server source-neutrality check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
