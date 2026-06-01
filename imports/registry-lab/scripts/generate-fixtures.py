#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "openpyxl>=3.1",
#   "pyarrow>=16",
# ]
# ///
# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic synthetic fixtures for the decentralized demo."""

from __future__ import annotations

import csv
import datetime as dt
import io
import re
import zipfile
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from openpyxl import Workbook
from openpyxl.packaging.core import DocumentProperties

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
FIXED_TIMESTAMP = dt.datetime(2026, 1, 1, 0, 0, 0)
FIXED_ZIP_DATE = (1980, 1, 1, 0, 0, 0)
CORE_XML_MODIFIED_RE = re.compile(
    rb"<dcterms:modified[^>]*>.*?</dcterms:modified>", re.DOTALL
)
CORE_XML_CREATED_RE = re.compile(
    rb"<dcterms:created[^>]*>.*?</dcterms:created>", re.DOTALL
)
FIXED_CORE_MODIFIED = (
    b'<dcterms:modified xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    b'xsi:type="dcterms:W3CDTF">2026-01-01T00:00:00Z</dcterms:modified>'
)
FIXED_CORE_CREATED = (
    b'<dcterms:created xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    b'xsi:type="dcterms:W3CDTF">2026-01-01T00:00:00Z</dcterms:created>'
)

CIVIL_ROWS = [
    ["national_id", "given_name", "surname", "birth_date", "civil_status", "deceased", "district"],
    ["NID-1001", "Miguel", "Santos", "2016-01-15", "child", "false", "north"],
    ["NID-1002", "Maria", "Dela Cruz", "2018-01-15", "child", "false", "south"],
    ["NID-1003", "Cara", "Okafor", "1957-02-14", "adult", "true", "central"],
    ["NID-1004", "Rafael", "Aquino", "2019-01-15", "child", "false", "east"],
    ["NID-1005", "Rosalie", "Bautista", "2013-01-15", "child", "false", "west"],
    ["NID-1006", "Miguel", "Martinez", "2014-01-15", "child", "false", "north"],
    ["NID-1007", "Lola", "Santos", "1958-01-15", "elderly", "false", "north"],
    ["NID-1008", "Rosa", "Garcia", "1954-01-15", "elderly", "false", "west"],
    ["NID-1009", "Ana", "Mendoza", "1998-01-15", "adult", "false", "east"],
    ["NID-1010", "Pedro", "Reyes", "1971-01-15", "adult", "false", "central"],
    ["NID-2001", "Maria", "Santos", "1984-01-15", "adult", "false", "north"],
    ["NID-2002", "Juan", "Dela Cruz", "1988-01-15", "adult", "false", "south"],
    ["NID-2004", "Rosario", "Aquino", "1988-01-15", "adult", "false", "east"],
    ["NID-2005", "Eduardo", "Bautista", "1978-01-15", "adult", "false", "west"],
    ["NID-2006", "David", "Martinez", "1978-01-15", "adult", "false", "north"],
]

HOUSEHOLDS = [
    ["household_id", "national_id", "district", "poverty_score", "eligibility_band", "household_size", "active_members", "deceased_member_count"],
    ["HH-100", "NID-1001", "north", 29.0, "priority", 5, 5, 0],
    ["HH-200", "NID-1002", "south", 45.0, "standard", 4, 4, 0],
    ["HH-300", "NID-1003", "central", 82.0, "not_eligible", 2, 1, 1],
    ["HH-400", "NID-1004", "east", 18.0, "priority", 4, 4, 0],
    ["HH-500", "NID-1005", "west", 61.0, "standard", 6, 6, 0],
    ["HH-600", "NID-1006", "north", 38.0, "priority", 3, 3, 0],
    ["HH-700", "NID-1008", "west", 42.0, "standard", 1, 1, 0],
    ["HH-800", "NID-1010", "central", 54.0, "standard", 6, 6, 0],
]

PERSONS = [
    ["person_id", "household_id", "national_id", "relationship", "age", "alive", "disability_status"],
    ["PER-1001", "HH-100", "NID-1001", "child", 10, True, "none"],
    ["PER-1007", "HH-100", "NID-1007", "grandparent", 68, True, "none"],
    ["PER-2001", "HH-100", "NID-2001", "caregiver", 42, True, "none"],
    ["PER-3001", "HH-100", "NID-3001", "sibling", 14, True, "none"],
    ["PER-3002", "HH-100", "NID-3002", "sibling", 12, True, "hearing"],
    ["PER-1002", "HH-200", "NID-1002", "child", 8, True, "none"],
    ["PER-2002", "HH-200", "NID-2002", "caregiver", 38, True, "none"],
    ["PER-3003", "HH-200", "NID-3003", "caregiver", 35, True, "none"],
    ["PER-3004", "HH-200", "NID-3004", "sibling", 12, True, "none"],
    ["PER-1003", "HH-300", "NID-1003", "adult", 69, False, "physical"],
    ["PER-3005", "HH-300", "NID-3005", "spouse", 66, True, "none"],
    ["PER-1004", "HH-400", "NID-1004", "child", 7, True, "none"],
    ["PER-2004", "HH-400", "NID-2004", "caregiver", 38, True, "none"],
    ["PER-3006", "HH-400", "NID-3006", "sibling", 15, True, "none"],
    ["PER-3007", "HH-400", "NID-3007", "sibling", 11, True, "none"],
    ["PER-1005", "HH-500", "NID-1005", "child", 13, True, "none"],
    ["PER-2005", "HH-500", "NID-2005", "caregiver", 48, True, "none"],
    ["PER-3008", "HH-500", "NID-3008", "caregiver", 44, True, "none"],
    ["PER-3009", "HH-500", "NID-3009", "sibling", 22, True, "none"],
    ["PER-3010", "HH-500", "NID-3010", "sibling", 16, True, "none"],
    ["PER-3011", "HH-500", "NID-3011", "sibling", 9, True, "none"],
    ["PER-1006", "HH-600", "NID-1006", "child", 12, True, "physical"],
    ["PER-2006", "HH-600", "NID-2006", "caregiver", 48, True, "none"],
    ["PER-3012", "HH-600", "NID-3012", "caregiver", 45, True, "none"],
    ["PER-1008", "HH-700", "NID-1008", "single_adult", 72, True, "none"],
    ["PER-1010", "HH-800", "NID-1010", "caregiver", 55, True, "none"],
    ["PER-1009", "HH-800", "NID-1009", "adult", 28, True, "none"],
    ["PER-3013", "HH-800", "NID-3013", "household_member", 50, True, "none"],
    ["PER-3014", "HH-800", "NID-3014", "household_member", 45, True, "none"],
    ["PER-3015", "HH-800", "NID-3015", "child", 14, True, "none"],
    ["PER-3016", "HH-800", "NID-3016", "child", 10, True, "none"],
]

ENROLLMENTS = [
    ["enrollment_id", "household_id", "person_id", "national_id", "program_code", "status", "benefit_amount", "enrolled_on"],
    ["ENR-100", "HH-100", "PER-1001", "NID-1001", "CHILD_SUPPORT", "active", 85.50, dt.date(2025, 1, 1)],
    ["ENR-200", "HH-200", "PER-1002", "NID-1002", "CHILD_SUPPORT", "inactive", 0.0, dt.date(2024, 3, 1)],
    ["ENR-300", "HH-300", "PER-1003", "NID-1003", "HEALTH_LINKED_SUPPORT", "review_required", 0.0, dt.date(2025, 6, 1)],
    ["ENR-400", "HH-400", "PER-1004", "NID-1004", "CHILD_SUPPORT", "active", 110.00, dt.date(2025, 8, 15)],
    ["ENR-500", "HH-500", "PER-1005", "NID-1005", "CHILD_SUPPORT", "active", 60.00, dt.date(2025, 2, 10)],
    ["ENR-600", "HH-600", "PER-1006", "NID-1006", "DISABILITY_SUPPORT", "active", 175.00, dt.date(2024, 12, 20)],
    ["ENR-700", "HH-100", "PER-1007", "NID-1007", "ELDERLY_PENSION", "inactive", 0.0, dt.date(2025, 9, 1)],
    ["ENR-800", "HH-700", "PER-1008", "NID-1008", "ELDERLY_PENSION", "active", 100.00, dt.date(2025, 4, 4)],
    ["ENR-900", "HH-800", "PER-1009", "NID-1009", "COMMUNITY_REGISTRY", "none", 0.0, dt.date(2025, 5, 1)],
    ["ENR-1000", "HH-800", "PER-1010", "NID-1010", "COMMUNITY_REGISTRY", "none", 0.0, dt.date(2025, 5, 1)],
]

DISTRICT_GEOMETRIES = [
    ["district", "geometry"],
    ["north", '{"type":"Polygon","coordinates":[[[0,1],[1,1],[1,2],[0,2],[0,1]]]}'],
    ["south", '{"type":"Polygon","coordinates":[[[0,-1],[1,-1],[1,0],[0,0],[0,-1]]]}'],
    ["central", '{"type":"Polygon","coordinates":[[[0,0],[1,0],[1,1],[0,1],[0,0]]]}'],
    ["east", '{"type":"Polygon","coordinates":[[[1,0],[2,0],[2,1],[1,1],[1,0]]]}'],
    ["west", '{"type":"Polygon","coordinates":[[[-1,0],[0,0],[0,1],[-1,1],[-1,0]]]}'],
]

HEALTH_ROWS = [
    {
        "facility_id": "HF-10",
        "national_id": "NID-1001",
        "facility_name": "North Clinic",
        "district": "north",
        "license_status": "active",
        "maternal_service_available": True,
        "pediatric_service_available": True,
        "practitioner_credential_active": True,
        "updated_on": dt.date(2026, 1, 15),
    },
    {
        "facility_id": "HF-20",
        "national_id": "NID-1002",
        "facility_name": "South Outreach Post",
        "district": "south",
        "license_status": "suspended",
        "maternal_service_available": True,
        "pediatric_service_available": False,
        "practitioner_credential_active": False,
        "updated_on": dt.date(2026, 1, 10),
    },
    {
        "facility_id": "HF-30",
        "national_id": "NID-1003",
        "facility_name": "Central Hospital",
        "district": "central",
        "license_status": "active",
        "maternal_service_available": False,
        "pediatric_service_available": True,
        "practitioner_credential_active": True,
        "updated_on": dt.date(2026, 1, 20),
    },
    {
        "facility_id": "HF-40",
        "national_id": "NID-1004",
        "facility_name": "East Family Health Center",
        "district": "east",
        "license_status": "active",
        "maternal_service_available": True,
        "pediatric_service_available": True,
        "practitioner_credential_active": True,
        "updated_on": dt.date(2026, 1, 18),
    },
    {
        "facility_id": "HF-50",
        "national_id": "NID-1005",
        "facility_name": "West Community Clinic",
        "district": "west",
        "license_status": "active",
        "maternal_service_available": False,
        "pediatric_service_available": True,
        "practitioner_credential_active": False,
        "updated_on": dt.date(2026, 1, 12),
    },
    {
        "facility_id": "HF-60",
        "national_id": "NID-1006",
        "facility_name": "North Mobile Outreach",
        "district": "north",
        "license_status": "active",
        "maternal_service_available": True,
        "pediatric_service_available": True,
        "practitioner_credential_active": True,
        "updated_on": dt.date(2026, 1, 8),
    },
    {
        "facility_id": "HF-70",
        "national_id": "NID-1007",
        "facility_name": "North Eldercare Clinic",
        "district": "north",
        "license_status": "active",
        "maternal_service_available": True,
        "pediatric_service_available": True,
        "practitioner_credential_active": True,
        "updated_on": dt.date(2026, 1, 22),
    },
    {
        "facility_id": "HF-80",
        "national_id": "NID-1008",
        "facility_name": "West Referral Hospital",
        "district": "west",
        "license_status": "active",
        "maternal_service_available": True,
        "pediatric_service_available": True,
        "practitioner_credential_active": True,
        "updated_on": dt.date(2026, 1, 17),
    },
    {
        "facility_id": "HF-90",
        "national_id": "NID-1009",
        "facility_name": "East Community Health Desk",
        "district": "east",
        "license_status": "active",
        "maternal_service_available": True,
        "pediatric_service_available": True,
        "practitioner_credential_active": True,
        "updated_on": dt.date(2026, 1, 19),
    },
    {
        "facility_id": "HF-100",
        "national_id": "NID-1010",
        "facility_name": "Central Outreach Desk",
        "district": "central",
        "license_status": "suspended",
        "maternal_service_available": True,
        "pediatric_service_available": False,
        "practitioner_credential_active": False,
        "updated_on": dt.date(2026, 1, 16),
    },
]


def data_rows(rows: list[list[object]]) -> list[list[object]]:
    return rows[1:]


def require_unique(rows: list[list[object]], column_name: str) -> None:
    header = rows[0]
    index = header.index(column_name)
    values = [row[index] for row in data_rows(rows)]
    if len(values) != len(set(values)):
        raise ValueError(f"{column_name} values must be unique")


def validate_fixture_coverage() -> None:
    require_unique(CIVIL_ROWS, "national_id")
    require_unique(HOUSEHOLDS, "household_id")
    require_unique(PERSONS, "person_id")
    require_unique(ENROLLMENTS, "enrollment_id")
    require_unique(ENROLLMENTS, "national_id")
    require_unique(DISTRICT_GEOMETRIES, "district")
    facility_ids = [row["facility_id"] for row in HEALTH_ROWS]
    if len(facility_ids) != len(set(facility_ids)):
        raise ValueError("facility_id values must be unique")

    civil_ids = {row[0] for row in data_rows(CIVIL_ROWS)}
    household_ids = {row[0] for row in data_rows(HOUSEHOLDS)}
    person_ids = {row[0] for row in data_rows(PERSONS)}
    for row in data_rows(HOUSEHOLDS):
        if row[1] not in civil_ids:
            raise ValueError(f"household anchor {row[1]} is missing from civil rows")
    for row in data_rows(PERSONS):
        if row[1] not in household_ids:
            raise ValueError(f"person {row[0]} references unknown household {row[1]}")
    for row in data_rows(ENROLLMENTS):
        if row[1] not in household_ids:
            raise ValueError(f"enrollment {row[0]} references unknown household {row[1]}")
        if row[2] not in person_ids:
            raise ValueError(f"enrollment {row[0]} references unknown person {row[2]}")
    geometry_districts = {row[0] for row in data_rows(DISTRICT_GEOMETRIES)}
    household_districts = {row[2] for row in data_rows(HOUSEHOLDS)}
    if not household_districts.issubset(geometry_districts):
        missing = sorted(household_districts - geometry_districts)
        raise ValueError(f"district geometries missing household districts: {missing}")

    if len(data_rows(CIVIL_ROWS)) < 10 or len(data_rows(HOUSEHOLDS)) < 8 or len(HEALTH_ROWS) < 8:
        raise ValueError("fixture set is too small for the decentralized demo")
    if not any(row[5] == "true" for row in data_rows(CIVIL_ROWS)):
        raise ValueError("civil fixture must include a deceased subject")
    if not any(row[4] == "not_eligible" for row in data_rows(HOUSEHOLDS)):
        raise ValueError("household fixture must include a failed eligibility band")
    if not any(row[5] != "active" for row in data_rows(ENROLLMENTS)):
        raise ValueError("enrollment fixture must include a non-active status")
    if not any(row["license_status"] != "active" for row in HEALTH_ROWS):
        raise ValueError("health fixture must include a non-active license")


def write_civil_csv() -> None:
    path = DATA_DIR / "civil" / "civil-persons.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerows(CIVIL_ROWS)


def canonicalize_xlsx(raw: bytes) -> bytes:
    with zipfile.ZipFile(io.BytesIO(raw), "r") as src:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as dst:
            for info in sorted(src.infolist(), key=lambda item: item.filename):
                data = src.read(info.filename)
                if info.filename == "docProps/core.xml":
                    data = CORE_XML_MODIFIED_RE.sub(FIXED_CORE_MODIFIED, data)
                    data = CORE_XML_CREATED_RE.sub(FIXED_CORE_CREATED, data)
                new_info = zipfile.ZipInfo(filename=info.filename, date_time=FIXED_ZIP_DATE)
                new_info.compress_type = zipfile.ZIP_DEFLATED
                new_info.external_attr = info.external_attr
                dst.writestr(new_info, data)
    return buffer.getvalue()


def write_social_xlsx() -> None:
    path = DATA_DIR / "social-protection" / "social-protection.xlsx"
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook = Workbook()
    props = DocumentProperties()
    props.creator = "registry-relay-decentralized-demo-generator"
    props.lastModifiedBy = "registry-relay-decentralized-demo-generator"
    props.created = FIXED_TIMESTAMP
    props.modified = FIXED_TIMESTAMP
    workbook.properties = props
    workbook.remove(workbook.active)
    for title, rows in [
        ("Households", HOUSEHOLDS),
        ("Persons", PERSONS),
        ("Enrollments", ENROLLMENTS),
        ("DistrictGeometries", DISTRICT_GEOMETRIES),
    ]:
        sheet = workbook.create_sheet(title)
        for row in rows:
            sheet.append(row)
    buffer = io.BytesIO()
    workbook.save(buffer)
    path.write_bytes(canonicalize_xlsx(buffer.getvalue()))


def write_health_parquet() -> None:
    path = DATA_DIR / "health" / "health-facilities.parquet"
    path.parent.mkdir(parents=True, exist_ok=True)
    schema = pa.schema(
        [
            ("facility_id", pa.string()),
            ("national_id", pa.string()),
            ("facility_name", pa.string()),
            ("district", pa.string()),
            ("license_status", pa.string()),
            ("maternal_service_available", pa.bool_()),
            ("pediatric_service_available", pa.bool_()),
            ("practitioner_credential_active", pa.bool_()),
            ("updated_on", pa.date32()),
        ]
    )
    table = pa.Table.from_pydict(
        {name: [row[name] for row in HEALTH_ROWS] for name in schema.names},
        schema=schema,
    )
    pq.write_table(table, path, compression="zstd", version="2.6")


def main() -> int:
    validate_fixture_coverage()
    write_civil_csv()
    write_social_xlsx()
    write_health_parquet()
    print(f"Generated decentralized demo fixtures under {DATA_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
