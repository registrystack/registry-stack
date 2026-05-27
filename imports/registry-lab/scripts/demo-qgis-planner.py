#!/usr/bin/env python3
"""QGIS-ready aggregate layer exporter for the agriculture demo."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from agri_demo_common import (
    LIVESTOCK_PURPOSE,
    MARKET_PURPOSE,
    DemoError,
    assert_no_secret_values,
    env,
    load_dotenv,
    prepare_output_dir,
    request,
    require,
    require_denial,
    save_json,
)


PH_GEOMETRIES = {
    "D-PH-ILOCOS-NORTE": (120.5932, 18.1978),
    "D-PH-CAGAYAN": (121.7270, 17.6132),
    "D-PH-NUEVA-ECIJA": (121.0848, 15.5415),
    "D-PH-CAMARINES-SUR": (123.1948, 13.6218),
    "D-PH-ILOILO": (122.5621, 10.7202),
    "D-PH-SOUTH-COTABATO": (124.8469, 6.5031),
}


def square(lon: float, lat: float, size: float = 0.18) -> dict[str, Any]:
    return {
        "type": "Polygon",
        "coordinates": [
            [
                [lon - size, lat - size],
                [lon + size, lat - size],
                [lon + size, lat + size],
                [lon - size, lat + size],
                [lon - size, lat - size],
            ]
        ],
    }


def rows(body: Any) -> list[dict[str, Any]]:
    data = body.get("data") if isinstance(body, dict) else None
    return [row for row in data if isinstance(row, dict)] if isinstance(data, list) else []


def disclosure_suppressed(body: Any) -> int:
    disclosure = body.get("disclosure_control") if isinstance(body, dict) else None
    value = disclosure.get("suppressed_rows") if isinstance(disclosure, dict) else 0
    return value if isinstance(value, int) else 0


def measure(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in row:
            return row[name]
    return None


def geojson(rows_in: list[dict[str, Any]], properties: list[str]) -> dict[str, Any]:
    features = []
    for row in rows_in:
        district_code = str(row.get("district_code") or "")
        if district_code not in PH_GEOMETRIES:
            continue
        lon, lat = PH_GEOMETRIES[district_code]
        safe_props = {key: row.get(key) for key in properties if key in row}
        safe_props["district_code"] = district_code
        safe_props["qgis_layer"] = "aggregate_only"
        features.append(
            {
                "type": "Feature",
                "geometry": square(lon, lat),
                "properties": safe_props,
            }
        )
    return {"type": "FeatureCollection", "features": features}


def write_qgis_project(out: Path) -> None:
    qgis = ET.Element("qgis", {"version": "3.34.0", "projectname": "NAgDI Agriculture Aggregate Planner"})
    title = ET.SubElement(qgis, "title")
    title.text = "NAgDI Agriculture Aggregate Planner"
    layers = ET.SubElement(qgis, "projectlayers")
    layer_specs = [
        (
            "nagdi_voucher_opportunities",
            "Voucher opportunities by district, crop, risk, and input",
            "qgis-planner-voucher-opportunities.geojson",
        ),
        (
            "nagdi_livestock_herds",
            "Livestock herds by species and district",
            "qgis-planner-livestock-herds.geojson",
        ),
    ]
    for layer_id, layer_name, datasource in layer_specs:
        maplayer = ET.SubElement(layers, "maplayer", {"type": "vector", "geometry": "Polygon", "hasScaleBasedVisibilityFlag": "0"})
        ET.SubElement(maplayer, "id").text = layer_id
        ET.SubElement(maplayer, "layername").text = layer_name
        ET.SubElement(maplayer, "datasource").text = datasource
        ET.SubElement(maplayer, "provider", {"encoding": "UTF-8"}).text = "ogr"
    tree = ET.ElementTree(qgis)
    ET.indent(tree, space="  ")
    tree.write(out / "qgis-planner-project.qgs", encoding="utf-8", xml_declaration=True)


def write_qgis_manifest(out: Path, voucher_layer: dict[str, Any], livestock_layer: dict[str, Any]) -> None:
    save_json(
        out / "qgis-planner-package.json",
        {
            "artifact_type": "nagdi.qgis-planner-package.v1",
            "project_file": "qgis-planner-project.qgs",
            "layers": [
                {
                    "name": "Voucher opportunities by district, crop, risk, and input",
                    "path": "qgis-planner-voucher-opportunities.geojson",
                    "feature_count": len(voucher_layer["features"]),
                    "geometry_type": "Polygon",
                    "classification": "aggregate_only",
                },
                {
                    "name": "Livestock herds by species and district",
                    "path": "qgis-planner-livestock-herds.geojson",
                    "feature_count": len(livestock_layer["features"]),
                    "geometry_type": "Polygon",
                    "classification": "aggregate_only",
                },
            ],
            "crs": "EPSG:4326",
            "contains_direct_identifiers": False,
            "source_workbooks_read": False,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("output/agri-qgis-planner"))
    args = parser.parse_args()

    load_dotenv()
    out = prepare_output_dir(args.output_dir)
    relay_url = env("AGRI_RELAY_URL", "http://127.0.0.1:4341")
    aggregate_token = env("AGRI_AGGREGATE_READER_RAW")

    market_path = env(
        "AGRI_MARKET_SIZING_PATH",
        "/datasets/agri_registry/aggregates/voucher_opportunities_by_district_crop_risk_input",
    )
    livestock_path = env(
        "AGRI_LIVESTOCK_AGGREGATE_PATH",
        "/datasets/agri_registry/aggregates/livestock_herds_by_species_district",
    )

    market = require(
        request("GET", relay_url, market_path, aggregate_token, headers={"Data-Purpose": MARKET_PURPOSE}),
        200,
        "market sizing aggregate",
    )
    livestock = require(
        request("GET", relay_url, livestock_path, aggregate_token, headers={"Data-Purpose": LIVESTOCK_PURPOSE}),
        200,
        "livestock herd aggregate",
    )
    suppressed = require(
        request(
            "POST",
            relay_url,
            f"{market_path.rstrip('/')}/query",
            aggregate_token,
            {"filters": {"district_code": "D-PH-SOUTH-COTABATO"}},
            headers={"Data-Purpose": MARKET_PURPOSE},
        ),
        200,
        "Philippines suppressed aggregate query",
    )

    planner_row = request(
        "GET",
        relay_url,
        "/datasets/agri_registry/farmer?limit=1",
        aggregate_token,
        headers={"Data-Purpose": MARKET_PURPOSE},
    )
    require_denial(planner_row, "planner row-level farmer access")
    save_json(out / "qgis-planner-row-denial.json", {"status": planner_row.status, "body": planner_row.body})

    market_rows = rows(market)
    livestock_rows = rows(livestock)
    voucher_layer = geojson(
        market_rows,
        [
            "district",
            "crop",
            "risk_band",
            "input_type",
            "season",
            "eligible_opportunity_count",
            "opportunity_count",
            "estimated_area_ha",
            "market_sizing_cell_count",
        ],
    )
    livestock_layer = geojson(
        livestock_rows,
        ["district", "species", "production_system", "herd_count", "animal_count"],
    )
    if not voucher_layer["features"]:
        raise DemoError("no Philippines voucher aggregate features found; run just agri-generate-planning and restart the agri services")
    if not livestock_layer["features"]:
        raise DemoError("no Philippines livestock aggregate features found; run just agri-generate-planning and restart the agri services")

    save_json(out / "qgis-planner-voucher-opportunities.geojson", voucher_layer)
    save_json(out / "qgis-planner-livestock-herds.geojson", livestock_layer)
    write_qgis_project(out)
    write_qgis_manifest(out, voucher_layer, livestock_layer)
    suppressed_count = disclosure_suppressed(suppressed)
    if suppressed_count < 1:
        raise DemoError("Philippines suppressed aggregate query did not report suppressed rows")

    summary = {
        "artifact_type": "nagdi.qgis-planner-summary.v1",
        "consumer": "qgis-planner",
        "geography": "Philippines province or municipality demo geometry",
        "voucher_feature_count": len(voucher_layer["features"]),
        "livestock_feature_count": len(livestock_layer["features"]),
        "suppressed_or_denied_cell_count": suppressed_count,
        "qgis_project_file": "qgis-planner-project.qgs",
        "qgis_package_manifest": "qgis-planner-package.json",
        "planner_row_level_farmer_access": "denied",
        "contains_direct_identifiers": False,
        "source_workbooks_read": False,
        "example_metrics": {
            "first_voucher_count": measure(voucher_layer["features"][0]["properties"], "eligible_opportunity_count", "opportunity_count"),
            "first_livestock_herd_count": measure(livestock_layer["features"][0]["properties"], "herd_count"),
        },
    }
    save_json(out / "qgis-planner-summary.json", summary)
    assert_no_secret_values(out)
    print(f"QGIS planner demo OK: {out}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
