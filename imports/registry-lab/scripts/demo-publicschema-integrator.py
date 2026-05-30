#!/usr/bin/env python3
"""PublicSchema-shaped projection consumer for the agriculture demo."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from pathlib import Path
from typing import Any

from agri_demo_common import (
    PURPOSE,
    DemoError,
    assert_no_secret_values,
    env,
    load_dotenv,
    prepare_output_dir,
    request,
    require,
    save_json,
)


MAPPING_PATH = Path("config/publicschema/agri-publicschema-projection.json")
MAPPING_DIR = Path("config/publicschema/agri-publicschema-projection")
TARGET_MAPPINGS = {
    "Persons": MAPPING_DIR / "person.yaml",
    "Identifiers": MAPPING_DIR / "identifier.yaml",
    "Farms": MAPPING_DIR / "farm.yaml",
    "GroupMemberships": MAPPING_DIR / "group-membership.yaml",
    "Locations": MAPPING_DIR / "location.yaml",
}


def rows(body: Any) -> list[dict[str, Any]]:
    data = body.get("data") if isinstance(body, dict) else None
    return [row for row in data if isinstance(row, dict)] if isinstance(data, list) else []


def fetch_entity(relay_url: str, token: str, entity: str, limit: int = 100) -> list[dict[str, Any]]:
    body = require(
        request(
            "GET",
            relay_url,
            f"/v1/datasets/agri_registry/entities/{entity}/records?limit={limit}",
            token,
            headers={"Data-Purpose": PURPOSE},
        ),
        200,
        f"{entity} rows",
    )
    return rows(body)


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_crosswalk(require_crosswalk: bool) -> tuple[Any | None, dict[str, Any]]:
    diagnostics: dict[str, Any] = {
        "artifact_type": "nagdi.publicschema-crosswalk-diagnostics.v1",
        "mapping_index_path": str(MAPPING_PATH),
        "mapping_paths": {name: str(path) for name, path in TARGET_MAPPINGS.items()},
        "blocking_errors": [],
        "warnings": [],
    }
    try:
        crosswalk = importlib.import_module("crosswalk")
    except ModuleNotFoundError:
        diagnostics["adapter"] = "fallback_publicschema_projection"
        message = "crosswalk Python binding is not installed in registry-lab"
        if require_crosswalk:
            diagnostics["blocking_errors"].append(message)
        else:
            diagnostics["warnings"].append(f"{message}; using deterministic local projection adapter for this demo run")
        return None, diagnostics

    runtime = crosswalk.MappingRuntime()
    diagnostics["adapter"] = "crosswalk-python"
    return runtime, diagnostics


def compile_mappings(runtime: Any | None, diagnostics: dict[str, Any]) -> dict[str, Any]:
    compiled = {}
    for name, path in TARGET_MAPPINGS.items():
        text = path.read_text(encoding="utf-8")
        if runtime is None:
            continue
        try:
            compiled[name] = runtime.compile_publicschema_mapping(text)
        except Exception as exc:  # noqa: BLE001
            diagnostics["blocking_errors"].append(f"{path}: {exc}")
    diagnostics["compiled_mapping_count"] = len(compiled)
    return compiled


def projection_sources(
    farmers: list[dict[str, Any]],
    identifiers: list[dict[str, Any]],
    memberships: list[dict[str, Any]],
    holdings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    persons = [
        {
            "id": f"person:{row['id']}",
            "source_farmer_id": row["id"],
            "given_name": row.get("given_name"),
            "family_name": row.get("family_name"),
            "sex": row.get("sex"),
            "district_code": row.get("district_code"),
            "preferred_language": row.get("preferred_language"),
            "concept_uri": "https://publicschema.org/Person",
        }
        for row in farmers
    ]
    farmer_ids = {row["source_farmer_id"] for row in persons}
    identifier_docs = [
        {
            "id": f"identifier:{row['id']}",
            "party_id": f"person:{row['farmer_id']}",
            "identifier_scheme": row.get("identifier_type"),
            "identifier_value_hash": stable_hash(str(row.get("identifier_value", ""))),
            "issuing_authority": row.get("issuing_authority"),
            "concept_uri": "https://publicschema.org/Identifier",
        }
        for row in identifiers
        if row.get("farmer_id") in farmer_ids
    ]
    farms = [
        {
            "id": f"farm:{row['id']}",
            "source_holding_id": row["id"],
            "name": f"{row.get('district')} farm holding",
            "group_type": "farm",
            "farm_area_hectares": row.get("total_area_ha"),
            "primary_crop": row.get("primary_livelihood"),
            "location_id": f"location:{row.get('district_code')}",
            "operator_person_id": f"person:{row.get('farmer_id')}",
            "concept_uri": "https://publicschema.org/Farm",
        }
        for row in holdings
        if row.get("farmer_id") in farmer_ids
    ]
    group_memberships = [
        {
            "id": f"membership:{row['id']}",
            "person_id": f"person:{row['farmer_id']}",
            "group_id": row.get("group_id"),
            "group_name": row.get("group_name"),
            "role": row.get("role"),
            "start_date": row.get("joined_on"),
            "concept_uri": "https://publicschema.org/GroupMembership",
        }
        for row in memberships
        if row.get("farmer_id") in farmer_ids
    ]
    group_memberships.extend(
        {
            "id": f"membership:farm-operator:{row['id']}",
            "person_id": f"person:{row['farmer_id']}",
            "group_id": f"farm:{row['id']}",
            "group_name": f"{row.get('district')} farm holding",
            "role": "operator",
            "start_date": row.get("last_verified_on"),
            "concept_uri": "https://publicschema.org/GroupMembership",
        }
        for row in holdings
        if row.get("farmer_id") in farmer_ids
    )
    locations_by_id: dict[str, dict[str, Any]] = {}
    for row in [*farmers, *holdings]:
        district_code = row.get("district_code")
        if district_code:
            locations_by_id[f"location:{district_code}"] = {
                "id": f"location:{district_code}",
                "admin_code": district_code,
                "name": row.get("district"),
                "concept_uri": "https://publicschema.org/Location",
            }
    return {
        "Persons": persons,
        "Identifiers": identifier_docs,
        "Farms": farms,
        "GroupMemberships": group_memberships,
        "Locations": list(locations_by_id.values()),
    }


def apply_publicschema_mappings(
    runtime: Any | None,
    compiled: dict[str, Any],
    sources: dict[str, list[dict[str, Any]]],
    diagnostics: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    if runtime is None:
        return sources

    projection: dict[str, list[dict[str, Any]]] = {}
    status_counts: dict[str, dict[str, int]] = {}
    for name, docs in sources.items():
        compiled_mapping = compiled.get(name)
        if compiled_mapping is None:
            raise DemoError(f"missing compiled PublicSchema mapping for {name}")
        projected_docs = []
        counts: dict[str, int] = {}
        for doc in docs:
            out = runtime.evaluate_publicschema_compiled(compiled_mapping, doc)
            if not out.get("ok"):
                raise DemoError(f"PublicSchema mapping failed for {name} {doc.get('id')}: {out.get('errors')}")
            for entry in out.get("log", []):
                status = str(entry.get("status"))
                counts[status] = counts.get(status, 0) + 1
            projected_docs.append(out["output"])
        projection[name] = projected_docs
        status_counts[name] = counts
    diagnostics["mapping_status_counts"] = status_counts
    return projection


def validate_projection(projection: dict[str, list[dict[str, Any]]]) -> None:
    person_ids = {row["id"] for row in projection["Persons"]}
    farm_ids = {row["id"] for row in projection["Farms"]}
    location_ids = {row["id"] for row in projection["Locations"]}
    for row in projection["Identifiers"]:
        if row["party_id"] not in person_ids:
            raise DemoError(f"identifier link does not resolve: {row}")
    for row in projection["Farms"]:
        if row["operator_person_id"] not in person_ids or row["location_id"] not in location_ids:
            raise DemoError(f"farm links do not resolve: {row}")
    for row in projection["GroupMemberships"]:
        if row["person_id"] not in person_ids:
            raise DemoError(f"group membership person link does not resolve: {row}")
        if str(row["group_id"]).startswith("farm:") and row["group_id"] not in farm_ids:
            raise DemoError(f"farm membership group link does not resolve: {row}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("output/agri-publicschema-integrator"))
    parser.add_argument("--require-crosswalk", action="store_true", help="fail if the crosswalk Python binding is unavailable")
    args = parser.parse_args()

    load_dotenv()
    out = prepare_output_dir(args.output_dir)
    mapping_text = MAPPING_PATH.read_text(encoding="utf-8")
    mapping = json.loads(mapping_text)
    runtime, diagnostics = load_crosswalk(args.require_crosswalk)
    compiled = compile_mappings(runtime, diagnostics)
    if diagnostics["blocking_errors"]:
        save_json(out / "publicschema-crosswalk-diagnostics.json", diagnostics)
        raise DemoError("PublicSchema mapping has blocking crosswalk diagnostics")

    relay_url = env("AGRI_RELAY_URL", "http://127.0.0.1:4341")
    token = env("AGRI_ROW_READER_RAW")
    sources = projection_sources(
        fetch_entity(relay_url, token, "farmer"),
        fetch_entity(relay_url, token, "farmer_identifier"),
        fetch_entity(relay_url, token, "farmer_group_membership"),
        fetch_entity(relay_url, token, "holding"),
    )
    projection = apply_publicschema_mappings(runtime, compiled, sources, diagnostics)
    validate_projection(projection)
    for name, docs in projection.items():
        save_json(out / f"{name}.json", docs)

    summary = {
        "artifact_type": "nagdi.publicschema-projection-summary.v1",
        "mapping_id": mapping["mapping_id"],
        "mapping_path": str(MAPPING_PATH),
        "mapping_adapter": diagnostics["adapter"],
        "compiled_mapping_count": diagnostics["compiled_mapping_count"],
        "row_counts": {name: len(docs) for name, docs in projection.items()},
        "sample_ids": {name: [doc["id"] for doc in docs[:5]] for name, docs in projection.items()},
        "links_resolved": True,
        "source_workbooks_read": False,
    }
    save_json(out / "publicschema-crosswalk-diagnostics.json", diagnostics)
    save_json(out / "publicschema-projection-summary.json", summary)
    assert_no_secret_values(out)
    print(f"PublicSchema integrator demo OK: {out}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
