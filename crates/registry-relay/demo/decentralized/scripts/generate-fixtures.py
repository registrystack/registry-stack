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
    ["NID-1001", "Amina", "Diallo", "2020-04-12", "child", "false", "north"],
    ["NID-1002", "Ben", "Mensah", "2017-11-02", "child", "false", "south"],
    ["NID-1003", "Cara", "Okafor", "1957-02-14", "adult", "true", "central"],
    ["NID-2001", "Dara", "Diallo", "1994-08-19", "adult", "false", "north"],
    ["NID-2002", "Esi", "Mensah", "1990-12-01", "adult", "false", "south"],
    ["NID-1004", "Femi", "Okeke", "2021-07-30", "child", "false", "east"],
    ["NID-2004", "Gita", "Okeke", "1988-03-21", "adult", "false", "east"],
    ["NID-1005", "Hana", "Njoroge", "2019-09-09", "child", "false", "west"],
    ["NID-2005", "Idris", "Njoroge", "1985-05-17", "adult", "false", "west"],
    ["NID-1006", "Jona", "Abebe", "2015-01-25", "child", "false", "north"],
    ["NID-2006", "Kaya", "Abebe", "1982-10-02", "adult", "true", "north"],
    ["NID-2008", "Lina", "Santos", "1984-06-06", "adult", "false", "west"],
]

HOUSEHOLDS = [
    ["household_id", "national_id", "district", "poverty_score", "eligibility_band", "household_size", "active_members", "deceased_member_count"],
    ["HH-100", "NID-1001", "north", 29.0, "priority", 4, 4, 0],
    ["HH-200", "NID-1002", "south", 45.0, "standard", 3, 3, 0],
    ["HH-300", "NID-1003", "central", 82.0, "not_eligible", 2, 1, 1],
    ["HH-400", "NID-1004", "east", 18.0, "priority", 5, 5, 0],
    ["HH-500", "NID-1005", "west", 61.0, "standard", 4, 3, 1],
    ["HH-600", "NID-1006", "north", 72.0, "not_eligible", 2, 1, 1],
    ["HH-700", "NID-2002", "south", 36.0, "priority", 6, 6, 0],
    ["HH-800", "NID-2008", "west", 54.0, "standard", 1, 1, 0],
]

PERSONS = [
    ["person_id", "household_id", "national_id", "relationship", "age", "alive", "disability_status"],
    ["PER-1001", "HH-100", "NID-1001", "child", 6, True, "none"],
    ["PER-2001", "HH-100", "NID-2001", "caregiver", 31, True, "none"],
    ["PER-3001", "HH-100", "NID-3001", "sibling", 10, True, "none"],
    ["PER-3002", "HH-100", "NID-3002", "sibling", 12, True, "hearing"],
    ["PER-1002", "HH-200", "NID-1002", "child", 8, True, "none"],
    ["PER-2002", "HH-200", "NID-2002", "caregiver", 35, True, "none"],
    ["PER-3003", "HH-200", "NID-3003", "grandparent", 68, True, "physical"],
    ["PER-1003", "HH-300", "NID-1003", "adult", 69, False, "physical"],
    ["PER-3004", "HH-300", "NID-3004", "spouse", 66, True, "none"],
    ["PER-1004", "HH-400", "NID-1004", "child", 5, True, "none"],
    ["PER-2004", "HH-400", "NID-2004", "caregiver", 38, True, "none"],
    ["PER-3005", "HH-400", "NID-3005", "child", 3, True, "none"],
    ["PER-3006", "HH-400", "NID-3006", "child", 12, True, "visual"],
    ["PER-3007", "HH-400", "NID-3007", "grandparent", 71, True, "none"],
    ["PER-1005", "HH-500", "NID-1005", "child", 7, True, "none"],
    ["PER-2005", "HH-500", "NID-2005", "caregiver", 41, True, "none"],
    ["PER-3008", "HH-500", "NID-3008", "adult", 74, False, "physical"],
    ["PER-3009", "HH-500", "NID-3009", "sibling", 15, True, "none"],
    ["PER-1006", "HH-600", "NID-1006", "child", 11, True, "none"],
    ["PER-2006", "HH-600", "NID-2006", "caregiver", 43, False, "none"],
    ["PER-2010", "HH-700", "NID-2010", "caregiver", 33, True, "none"],
    ["PER-2011", "HH-700", "NID-2011", "child", 2, True, "none"],
    ["PER-2012", "HH-700", "NID-2012", "child", 4, True, "none"],
    ["PER-2013", "HH-700", "NID-2013", "child", 6, True, "cognitive"],
    ["PER-2014", "HH-700", "NID-2014", "child", 9, True, "none"],
    ["PER-2015", "HH-700", "NID-2015", "adult", 29, True, "none"],
    ["PER-2008", "HH-800", "NID-2008", "single_adult", 41, True, "none"],
]

ENROLLMENTS = [
    ["enrollment_id", "household_id", "person_id", "national_id", "program_code", "status", "benefit_amount", "enrolled_on"],
    ["ENR-100", "HH-100", "PER-1001", "NID-1001", "CHILD_SUPPORT", "active", 85.50, dt.date(2025, 1, 1)],
    ["ENR-200", "HH-200", "PER-1002", "NID-1002", "CHILD_SUPPORT", "inactive", 0.0, dt.date(2024, 3, 1)],
    ["ENR-300", "HH-300", "PER-1003", "NID-1003", "HEALTH_LINKED_SUPPORT", "review_required", 0.0, dt.date(2025, 6, 1)],
    ["ENR-400", "HH-400", "PER-1004", "NID-1004", "CHILD_SUPPORT", "active", 110.00, dt.date(2025, 8, 15)],
    ["ENR-500", "HH-500", "PER-1005", "NID-1005", "CHILD_SUPPORT", "active", 60.00, dt.date(2025, 2, 10)],
    ["ENR-600", "HH-600", "PER-1006", "NID-1006", "CHILD_SUPPORT", "suspended", 0.0, dt.date(2024, 12, 20)],
    ["ENR-700", "HH-700", "PER-2011", "NID-2011", "CHILD_SUPPORT", "active", 140.00, dt.date(2025, 9, 1)],
    ["ENR-800", "HH-800", "PER-2008", "NID-2008", "HEALTH_LINKED_SUPPORT", "inactive", 0.0, dt.date(2025, 4, 4)],
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
        "license_status": "pending_renewal",
        "maternal_service_available": True,
        "pediatric_service_available": True,
        "practitioner_credential_active": True,
        "updated_on": dt.date(2026, 1, 8),
    },
    {
        "facility_id": "HF-70",
        "national_id": "NID-2011",
        "facility_name": "South Pediatric Unit",
        "district": "south",
        "license_status": "active",
        "maternal_service_available": True,
        "pediatric_service_available": True,
        "practitioner_credential_active": True,
        "updated_on": dt.date(2026, 1, 22),
    },
    {
        "facility_id": "HF-80",
        "national_id": "NID-2008",
        "facility_name": "West Referral Hospital",
        "district": "west",
        "license_status": "active",
        "maternal_service_available": True,
        "pediatric_service_available": False,
        "practitioner_credential_active": True,
        "updated_on": dt.date(2026, 1, 17),
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
