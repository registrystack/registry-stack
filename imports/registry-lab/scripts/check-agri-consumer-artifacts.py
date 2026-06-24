#!/usr/bin/env python3
"""Validate agriculture consumer demo artifacts."""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from agri_demo_common import DemoError, assert_no_secret_values, load_dotenv


ROOT = Path("output")


def load_json(path: Path) -> Any:
    if not path.exists():
        raise DemoError(f"missing artifact: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DemoError(message)


def check_voucher_mis() -> None:
    summary = load_json(ROOT / "agri-voucher-mis" / "voucher-mis-summary.json")
    expected = {
        "FARMER-1001": ("ready_for_program_review", None),
        "FARMER-1002": ("not_ready_for_program_review", "parcel.status:not_active"),
        "FARMER-1003": ("not_ready_for_program_review", "voucher.redemption:already_redeemed"),
        "FARMER-1004": ("not_ready_for_program_review", "farmer.registration_status:not_active"),
        "FARMER-1005": ("manual_review_required", "data_quality:manual_review_required"),
    }
    cases = summary.get("cases", {})
    for farmer_id, (state, reason) in expected.items():
        case = cases.get(farmer_id)
        require(isinstance(case, dict), f"voucher MIS missing case {farmer_id}")
        require(case.get("program_review_state") == state, f"voucher MIS wrong state for {farmer_id}")
        require(case.get("reason_code") == reason, f"voucher MIS wrong reason for {farmer_id}")
    denials = summary.get("denial_controls", {})
    require(denials.get("evidence_only_row_read") == 403, "voucher MIS evidence-only denial should be 403")
    require(denials.get("missing_data_purpose") == 400, "voucher MIS missing-purpose denial should be 400")
    require(summary.get("source_workbooks_read") is False, "voucher MIS must not read source workbooks")


def check_geojson(path: Path) -> int:
    body = load_json(path)
    require(body.get("type") == "FeatureCollection", f"{path} is not a FeatureCollection")
    features = body.get("features")
    require(isinstance(features, list) and features, f"{path} has no features")
    for feature in features:
        require(feature.get("geometry", {}).get("type") == "Polygon", f"{path} contains non-polygon geometry")
        props = feature.get("properties", {})
        require(props.get("district_code"), f"{path} feature missing district_code")
        require(props.get("qgis_layer") == "aggregate_only", f"{path} feature missing aggregate_only marker")
    return len(features)


def check_qgis() -> None:
    out = ROOT / "agri-qgis-planner"
    summary = load_json(out / "qgis-planner-summary.json")
    package = load_json(out / "qgis-planner-package.json")
    voucher_count = check_geojson(out / "qgis-planner-voucher-opportunities.geojson")
    livestock_count = check_geojson(out / "qgis-planner-livestock-herds.geojson")
    ET.parse(out / "qgis-planner-project.qgs")
    require(summary.get("voucher_feature_count") == voucher_count, "QGIS voucher count mismatch")
    require(summary.get("livestock_feature_count") == livestock_count, "QGIS livestock count mismatch")
    require(summary.get("suppressed_or_denied_cell_count", 0) >= 1, "QGIS summary missing suppression proof")
    require(summary.get("source_workbooks_read") is False, "QGIS planner must not read source workbooks")
    require(package.get("contains_direct_identifiers") is False, "QGIS package must not contain direct identifiers")
    require(package.get("project_file") == "qgis-planner-project.qgs", "QGIS package points to wrong project file")


def check_publicschema(require_crosswalk: bool) -> None:
    out = ROOT / "agri-publicschema-integrator"
    summary = load_json(out / "publicschema-projection-summary.json")
    diagnostics = load_json(out / "publicschema-crosswalk-diagnostics.json")
    require(summary.get("links_resolved") is True, "PublicSchema links are not resolved")
    require(summary.get("source_workbooks_read") is False, "PublicSchema integrator must not read source workbooks")
    for name in ["Persons", "Identifiers", "Farms", "GroupMemberships", "Locations"]:
        require(summary.get("row_counts", {}).get(name, 0) > 0, f"PublicSchema output missing {name}")
        docs = load_json(out / f"{name}.json")
        require(len(docs) == summary["row_counts"][name], f"PublicSchema {name} row count mismatch")
    require(diagnostics.get("blocking_errors") == [], "PublicSchema diagnostics contain blocking errors")
    if require_crosswalk:
        require(summary.get("mapping_adapter") == "crosswalk-python", "PublicSchema did not use crosswalk-python")
        require(summary.get("compiled_mapping_count") == 5, "PublicSchema did not compile all five mappings")
        require(diagnostics.get("warnings") == [], "strict PublicSchema run should have no warnings")


def check_wallet() -> None:
    summary = load_json(ROOT / "agri-wallet" / "wallet-holder-summary.json")
    require(summary.get("holder_bound_credential_issued") is True, "wallet did not issue holder-bound credential")
    controls = summary.get("negative_controls", {})
    for subject in ["FARMER-1002", "FARMER-1005"]:
        control = controls.get(subject)
        require(isinstance(control, dict), f"wallet missing negative control {subject}")
        require(control.get("credential_issued") is False, f"wallet incorrectly issued credential for {subject}")
    require(summary.get("source_workbooks_read") is False, "wallet demo must not read source workbooks")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-crosswalk", action="store_true")
    args = parser.parse_args()

    load_dotenv()
    check_voucher_mis()
    check_qgis()
    check_publicschema(args.require_crosswalk)
    check_wallet()
    for output_dir in ["agri-voucher-mis", "agri-qgis-planner", "agri-publicschema-integrator", "agri-wallet"]:
        assert_no_secret_values(ROOT / output_dir)
    print("agriculture consumer artifact checks OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
