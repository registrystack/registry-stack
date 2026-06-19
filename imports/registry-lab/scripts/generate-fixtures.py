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
SOURCE_OBSERVED_AT_NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
FRESH_SOURCE_OBSERVED_AT = SOURCE_OBSERVED_AT_NOW.isoformat().replace("+00:00", "Z")
STALE_SOURCE_OBSERVED_AT = (
    SOURCE_OBSERVED_AT_NOW - dt.timedelta(days=2)
).isoformat().replace("+00:00", "Z")
MISSING_SOURCE_OBSERVED_AT_NATIONAL_ID = "NID-1011"


def observed_at_for_national_id(national_id: str) -> str:
    if national_id == "NID-1010":
        return STALE_SOURCE_OBSERVED_AT
    if national_id == MISSING_SOURCE_OBSERVED_AT_NATIONAL_ID:
        return ""
    return FRESH_SOURCE_OBSERVED_AT


def append_observed_at(rows: list[list[object]], *, national_id_index: int) -> list[list[object]]:
    return [
        rows[0] + ["observed_at"],
        *[row + [observed_at_for_national_id(str(row[national_id_index]))] for row in rows[1:]],
    ]


CIVIL_ROWS = append_observed_at([
    ["national_id", "given_name", "surname", "birth_date", "life_stage", "deceased", "district"],
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
    ["NID-1011", "Miguel", "Santos", "2016-01-15", "child", "false", "south"],
], national_id_index=0)

# PublicSchema anchors:
# Person / Identifier / CivilStatusRecord / Birth / Death / Certificate / Relationship.
CIVIL_PERSON_DETAILS = [
    [
        "person_id",
        "national_id",
        "given_name",
        "surname",
        "birth_date",
        "sex",
        "district",
        "place_of_birth",
        "life_stage",
        "deceased",
        "death_date",
    ],
    ["CP-1001", "NID-1001", "Miguel", "Santos", "2016-01-15", "M", "north", "North City", "child", "false", ""],
    ["CP-1002", "NID-1002", "Maria", "Dela Cruz", "2018-01-15", "F", "south", "South Town", "child", "false", ""],
    ["CP-1003", "NID-1003", "Cara", "Okafor", "1957-02-14", "F", "central", "Central City", "adult", "true", "2025-11-02"],
    ["CP-1004", "NID-1004", "Rafael", "Aquino", "2019-01-15", "M", "east", "East City", "child", "false", ""],
    ["CP-1005", "NID-1005", "Rosalie", "Bautista", "2013-01-15", "F", "west", "West City", "child", "false", ""],
    ["CP-1006", "NID-1006", "Miguel", "Martinez", "2014-01-15", "M", "north", "North City", "child", "false", ""],
    ["CP-1007", "NID-1007", "Lola", "Santos", "1958-01-15", "F", "north", "North City", "elderly", "false", ""],
    ["CP-1008", "NID-1008", "Rosa", "Garcia", "1954-01-15", "F", "west", "West City", "elderly", "false", ""],
    ["CP-1009", "NID-1009", "Ana", "Mendoza", "1998-01-15", "F", "east", "East City", "adult", "false", ""],
    ["CP-1010", "NID-1010", "Pedro", "Reyes", "1971-01-15", "M", "central", "Central City", "adult", "false", ""],
    ["CP-2001", "NID-2001", "Maria", "Santos", "1984-01-15", "F", "north", "North City", "adult", "false", ""],
    ["CP-2002", "NID-2002", "Juan", "Dela Cruz", "1988-01-15", "M", "south", "South Town", "adult", "false", ""],
    ["CP-2004", "NID-2004", "Rosario", "Aquino", "1988-01-15", "F", "east", "East City", "adult", "false", ""],
    ["CP-2005", "NID-2005", "Eduardo", "Bautista", "1978-01-15", "M", "west", "West City", "adult", "false", ""],
    ["CP-2006", "NID-2006", "David", "Martinez", "1978-01-15", "M", "north", "North City", "adult", "false", ""],
    ["CP-1011", "NID-1011", "Miguel", "Santos", "2016-01-15", "M", "south", "South Town", "child", "false", ""],
]

CIVIL_IDENTIFIERS = [
    ["identifier_id", "person_id", "scheme", "value", "status", "issued_on", "valid_until"],
    *[
        [f"ID-{row[1][4:]}", row[0], "national_id", row[1], "active", "2020-01-01", ""]
        for row in CIVIL_PERSON_DETAILS[1:]
    ],
]

BIRTH_EVENTS = [
    [
        "event_id",
        "child_person_id",
        "mother_person_id",
        "father_person_id",
        "place_of_birth",
        "date_of_birth",
        "sex_at_birth",
        "attendant_or_place_type",
    ],
    ["BE-1001", "CP-1001", "CP-2001", "", "North City", "2016-01-15", "M", "clinic"],
    ["BE-1002", "CP-1002", "", "CP-2002", "South Town", "2018-01-15", "F", "clinic"],
    ["BE-1004", "CP-1004", "CP-2004", "", "East City", "2019-01-15", "M", "clinic"],
    ["BE-1005", "CP-1005", "", "CP-2005", "West City", "2013-01-15", "F", "clinic"],
    ["BE-1006", "CP-1006", "", "CP-2006", "North City", "2014-01-15", "M", "clinic"],
    ["BE-1011", "CP-1011", "", "", "South Town", "2016-01-15", "M", "clinic"],
]

DEATH_EVENTS = [
    ["event_id", "deceased_person_id", "date_of_death", "place_of_death", "registration_date", "authority"],
    ["DE-1003", "CP-1003", "2025-11-02", "Central City", "2025-11-03", "Civil Registry Authority"],
]

CIVIL_STATUS_RECORDS = [
    [
        "record_id",
        "record_type",
        "registration_number",
        "person_id",
        "event_id",
        "authority",
        "registration_status",
        "registration_date",
    ],
    ["CSR-BIRTH-1001", "birth", "B-2016-N-1001", "CP-1001", "BE-1001", "Civil Registry Authority", "registered", "2016-01-17"],
    ["CSR-BIRTH-1002", "birth", "B-2018-S-1002", "CP-1002", "BE-1002", "Civil Registry Authority", "registered", "2018-01-16"],
    ["CSR-BIRTH-1004", "birth", "B-2019-E-1004", "CP-1004", "BE-1004", "Civil Registry Authority", "registered", "2019-01-17"],
    ["CSR-BIRTH-1005", "birth", "B-2013-W-1005", "CP-1005", "BE-1005", "Civil Registry Authority", "registered", "2013-01-18"],
    ["CSR-BIRTH-1006", "birth", "B-2014-N-1006", "CP-1006", "BE-1006", "Civil Registry Authority", "registered", "2014-01-17"],
    ["CSR-BIRTH-1011", "birth", "B-2016-S-1011", "CP-1011", "BE-1011", "Civil Registry Authority", "registered", "2016-01-20"],
    ["CSR-DEATH-1003", "death", "D-2025-C-1003", "CP-1003", "DE-1003", "Civil Registry Authority", "registered", "2025-11-03"],
]

CERTIFICATES = [
    ["certificate_number", "record_id", "issue_date", "issuing_office", "certificate_type", "valid_until"],
    ["CERT-B-1001", "CSR-BIRTH-1001", "2016-01-18", "North Civil Office", "birth", ""],
    ["CERT-B-1002", "CSR-BIRTH-1002", "2018-01-17", "South Civil Office", "birth", ""],
    ["CERT-B-1004", "CSR-BIRTH-1004", "2019-01-18", "East Civil Office", "birth", ""],
    ["CERT-B-1011", "CSR-BIRTH-1011", "2016-01-21", "South Civil Office", "birth", ""],
    ["CERT-D-1003", "CSR-DEATH-1003", "2025-11-04", "Central Civil Office", "death", ""],
]

RELATIONSHIPS = [
    [
        "relationship_id",
        "subject_person_id",
        "related_person_id",
        "relationship_type",
        "source_record_id",
        "effective_from",
        "effective_until",
        "relationship_status",
    ],
    ["REL-1001-MOTHER", "CP-1001", "CP-2001", "mother", "CSR-BIRTH-1001", "2016-01-15", "", "established"],
    ["REL-1002-FATHER", "CP-1002", "CP-2002", "father", "CSR-BIRTH-1002", "2018-01-15", "", "established"],
    ["REL-1004-MOTHER", "CP-1004", "CP-2004", "mother", "CSR-BIRTH-1004", "2019-01-15", "", "established"],
    ["REL-1005-FATHER", "CP-1005", "CP-2005", "father", "CSR-BIRTH-1005", "2013-01-15", "", "established"],
    ["REL-1006-FATHER", "CP-1006", "CP-2006", "father", "CSR-BIRTH-1006", "2014-01-15", "", "established"],
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
    ["HH-900", "NID-1011", "south", 28.0, "priority", 3, 3, 0],
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
    ["PER-1011", "HH-900", "NID-1011", "child", 10, True, "none"],
]

ENROLLMENTS = append_observed_at([
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
    ["ENR-1011", "HH-900", "PER-1011", "NID-1011", "CHILD_SUPPORT", "active", 85.50, dt.date(2025, 1, 1)],
], national_id_index=3)

# PublicSchema anchors:
# Household / GroupMembership / SocioEconomicProfile / ScoringEvent /
# Program / Enrollment / Entitlement / PaymentEvent.
GROUP_MEMBERSHIPS = [
    ["membership_id", "household_id", "person_id", "relationship_type", "start_date", "end_date", "membership_status"],
    *[
        [f"GM-{person[0][4:]}", person[1], person[0], person[3], dt.date(2025, 1, 1), None, "active" if person[5] else "ended_deceased"]
        for person in PERSONS[1:]
    ],
]

SOCIO_ECONOMIC_PROFILES = [
    ["profile_id", "household_id", "observation_date", "instrument", "collected_by", "source_version", "profile_status"],
    ["SEP-100", "HH-100", dt.date(2025, 12, 1), "PMT-CHILD-2025", "municipal_social_worker", "2025.4", "current"],
    ["SEP-200", "HH-200", dt.date(2025, 11, 15), "PMT-CHILD-2025", "municipal_social_worker", "2025.4", "current"],
    ["SEP-300", "HH-300", dt.date(2025, 10, 1), "PMT-ADULT-2025", "central_review_team", "2025.3", "current"],
    ["SEP-400", "HH-400", dt.date(2025, 12, 10), "PMT-CHILD-2025", "municipal_social_worker", "2025.4", "current"],
    ["SEP-500", "HH-500", dt.date(2024, 1, 10), "PMT-CHILD-2024", "municipal_social_worker", "2024.1", "stale"],
    ["SEP-600", "HH-600", dt.date(2025, 12, 5), "PMT-DISABILITY-2025", "assessment_registry", "2025.4", "current"],
    ["SEP-700", "HH-700", dt.date(2025, 3, 1), "PMT-ELDERLY-2025", "municipal_social_worker", "2025.2", "current"],
    ["SEP-800", "HH-800", dt.date(2025, 7, 1), "PMT-COMMUNITY-2025", "central_review_team", "2025.2", "current"],
]

SCORING_EVENTS = [
    ["scoring_id", "profile_id", "scoring_rule", "scoring_version", "score_band", "valid_from", "valid_until", "scoring_status"],
    ["SCOR-100", "SEP-100", "child-benefit-priority", "2025.4", "priority", dt.date(2025, 12, 1), dt.date(2026, 12, 1), "current"],
    ["SCOR-200", "SEP-200", "child-benefit-standard", "2025.4", "standard", dt.date(2025, 11, 15), dt.date(2026, 11, 15), "current"],
    ["SCOR-300", "SEP-300", "death-review", "2025.3", "not_eligible", dt.date(2025, 10, 1), dt.date(2026, 10, 1), "current"],
    ["SCOR-400", "SEP-400", "child-benefit-priority", "2025.4", "priority", dt.date(2025, 12, 10), dt.date(2026, 12, 10), "current"],
    ["SCOR-500", "SEP-500", "child-benefit-standard", "2024.1", "standard", dt.date(2024, 1, 10), dt.date(2025, 1, 10), "stale"],
    ["SCOR-600", "SEP-600", "disability-top-up", "2025.4", "priority", dt.date(2025, 12, 5), dt.date(2026, 12, 5), "current"],
    ["SCOR-700", "SEP-700", "elderly-pension", "2025.2", "standard", dt.date(2025, 3, 1), dt.date(2025, 12, 31), "expired"],
    ["SCOR-800", "SEP-800", "community-review", "2025.2", "not_eligible", dt.date(2025, 7, 1), dt.date(2026, 7, 1), "policy_denied"],
]

PROGRAMS = [
    ["program_code", "display_name", "authority", "benefit_type"],
    ["CHILD_SUPPORT", "Child Support Grant", "Social Protection Authority", "cash_transfer"],
    ["HEALTH_LINKED_SUPPORT", "Health-Linked Support", "Social Protection Authority", "conditional_cash_transfer"],
    ["DISABILITY_SUPPORT", "Disability Support Top-Up", "Disability Assessment Authority", "cash_top_up"],
    ["ELDERLY_PENSION", "Elderly Pension", "Social Protection Authority", "pension"],
    ["COMMUNITY_REGISTRY", "Community Registry", "Social Registry Authority", "registry_only"],
]

ENTITLEMENTS = [
    [
        "entitlement_id",
        "enrollment_id",
        "benefit_modality",
        "amount",
        "amount_band",
        "currency",
        "coverage_start",
        "coverage_end",
        "entitlement_status",
    ],
    ["ENT-100", "ENR-100", "cash", 85.50, "standard_child", "USD", dt.date(2026, 1, 1), dt.date(2026, 12, 31), "active"],
    ["ENT-200", "ENR-200", "cash", 0.0, "none", "USD", dt.date(2024, 3, 1), dt.date(2024, 12, 31), "inactive"],
    ["ENT-300", "ENR-300", "cash", 0.0, "review", "USD", dt.date(2025, 6, 1), dt.date(2026, 5, 31), "review_required"],
    ["ENT-400", "ENR-400", "cash", 110.00, "priority_child", "USD", dt.date(2026, 1, 1), dt.date(2026, 12, 31), "active"],
    ["ENT-500", "ENR-500", "cash", 60.00, "standard_child", "USD", dt.date(2025, 1, 1), dt.date(2025, 12, 31), "stale_source"],
    ["ENT-600", "ENR-600", "cash", 175.00, "disability_top_up", "USD", dt.date(2026, 1, 1), dt.date(2026, 12, 31), "active"],
    ["ENT-700", "ENR-700", "cash", 0.0, "elderly_pension", "USD", dt.date(2025, 9, 1), dt.date(2025, 12, 31), "expired"],
    ["ENT-800", "ENR-800", "cash", 100.00, "elderly_pension", "USD", dt.date(2026, 1, 1), dt.date(2026, 12, 31), "active"],
    ["ENT-900", "ENR-900", "none", 0.0, "none", "USD", dt.date(2025, 5, 1), dt.date(2026, 5, 1), "policy_denied"],
]

PAYMENT_EVENTS = [
    ["payment_id", "entitlement_id", "cycle", "status", "delivery_channel", "payment_date", "reconciled"],
    ["PAY-100-JAN", "ENT-100", "2026-01", "paid", "mobile_money", dt.date(2026, 1, 15), True],
    ["PAY-400-JAN", "ENT-400", "2026-01", "paid", "bank_transfer", dt.date(2026, 1, 15), True],
    ["PAY-500-DEC", "ENT-500", "2025-12", "held_stale_profile", "mobile_money", dt.date(2025, 12, 15), False],
    ["PAY-600-JAN", "ENT-600", "2026-01", "paid", "cash_agent", dt.date(2026, 1, 16), True],
    ["PAY-700-JAN", "ENT-700", "2026-01", "not_paid_expired", "cash_agent", dt.date(2026, 1, 16), False],
    ["PAY-900-JAN", "ENT-900", "2026-01", "not_paid_policy_denied", "none", dt.date(2026, 1, 16), False],
]

FUNCTIONING_PROFILES = [
    [
        "profile_id",
        "person_id",
        "national_id",
        "instrument_code",
        "administration_date",
        "respondent_relationship",
        "domain_severities",
        "disability_identifier_met",
        "domains_triggering_identifier",
        "source_version",
    ],
    ["FUNC-1006", "PER-1006", "NID-1006", "WG-SS-2025", dt.date(2025, 12, 5), "caregiver", "mobility=severe;self_care=moderate", True, "mobility;self_care", "2025.4"],
    ["FUNC-1003", "PER-1003", "NID-1003", "WG-SS-2025", dt.date(2025, 6, 1), "self", "mobility=severe", True, "mobility", "2025.2"],
]

DISABILITY_DETERMINATIONS = [
    ["determination_id", "person_id", "national_id", "authority", "determination_status", "support_category", "valid_from", "valid_until", "review_due"],
    ["DIS-1006", "PER-1006", "NID-1006", "Disability Assessment Authority", "approved", "top_up", dt.date(2025, 12, 20), dt.date(2026, 12, 20), dt.date(2026, 10, 20)],
    ["DIS-1003", "PER-1003", "NID-1003", "Disability Assessment Authority", "closed_deceased", "none", dt.date(2025, 6, 1), dt.date(2025, 11, 2), dt.date(2025, 11, 2)],
]

DISTRICT_GEOMETRIES = [
    ["district", "geometry"],
    ["north", '{"type":"Polygon","coordinates":[[[0,1],[1,1],[1,2],[0,2],[0,1]]]}'],
    ["south", '{"type":"Polygon","coordinates":[[[0,-1],[1,-1],[1,0],[0,0],[0,-1]]]}'],
    ["central", '{"type":"Polygon","coordinates":[[[0,0],[1,0],[1,1],[0,1],[0,0]]]}'],
    ["east", '{"type":"Polygon","coordinates":[[[1,0],[2,0],[2,1],[1,1],[1,0]]]}'],
    ["west", '{"type":"Polygon","coordinates":[[[-1,0],[0,0],[0,1],[-1,1],[-1,0]]]}'],
]

HEALTH_PROJECTION_NAME = "ApplicantServiceAvailabilityProjection"

APPLICANT_SERVICE_AVAILABILITY_PROJECTION = [
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
    {
        "facility_id": "HF-110",
        "national_id": "NID-1011",
        "facility_name": "South Pediatric Clinic",
        "district": "south",
        "license_status": "active",
        "maternal_service_available": True,
        "pediatric_service_available": True,
        "practitioner_credential_active": True,
        "updated_on": dt.date(2026, 1, 16),
    },
]

for row in APPLICANT_SERVICE_AVAILABILITY_PROJECTION:
    row["observed_at"] = observed_at_for_national_id(row["national_id"])

# Compatibility alias for existing relay and notary configs.
HEALTH_ROWS = APPLICANT_SERVICE_AVAILABILITY_PROJECTION

FIXTURE_PERSONAS = {
    "positive_child_benefit": {
        "national_id": "NID-1001",
        "person_id": "PER-1001",
        "civil_record_id": "CSR-BIRTH-1001",
        "relationship_id": "REL-1001-MOTHER",
        "profile_id": "SEP-100",
        "scoring_id": "SCOR-100",
        "enrollment_id": "ENR-100",
        "entitlement_id": "ENT-100",
        "expected_outcome": "positive",
    },
    "negative_deceased": {
        "national_id": "NID-1003",
        "person_id": "PER-1003",
        "civil_record_id": "CSR-DEATH-1003",
        "death_event_id": "DE-1003",
        "expected_outcome": "negative",
    },
    "ambiguous_demographic": {
        "national_id": "NID-1011",
        "ambiguous_with": "NID-1001",
        "civil_record_id": "CSR-BIRTH-1011",
        "expected_outcome": "ambiguous_match",
    },
    "stale_welfare": {
        "national_id": "NID-1005",
        "person_id": "PER-1005",
        "profile_id": "SEP-500",
        "scoring_id": "SCOR-500",
        "entitlement_id": "ENT-500",
        "expected_outcome": "stale",
    },
    "expired_entitlement": {
        "national_id": "NID-1007",
        "person_id": "PER-1007",
        "enrollment_id": "ENR-700",
        "entitlement_id": "ENT-700",
        "expected_outcome": "expired",
    },
    "policy_denied": {
        "national_id": "NID-1009",
        "person_id": "PER-1009",
        "profile_id": "SEP-800",
        "scoring_id": "SCOR-800",
        "enrollment_id": "ENR-900",
        "entitlement_id": "ENT-900",
        "expected_outcome": "policy_denied",
    },
    "disability_top_up": {
        "national_id": "NID-1006",
        "person_id": "PER-1006",
        "functioning_profile_id": "FUNC-1006",
        "determination_id": "DIS-1006",
        "enrollment_id": "ENR-600",
        "entitlement_id": "ENT-600",
        "expected_outcome": "positive",
    },
}


def data_rows(rows: list[list[object]]) -> list[list[object]]:
    return rows[1:]


def require_unique(rows: list[list[object]], column_name: str) -> None:
    header = rows[0]
    index = header.index(column_name)
    values = [row[index] for row in data_rows(rows)]
    if len(values) != len(set(values)):
        raise ValueError(f"{column_name} values must be unique")


def require_refs(
    rows: list[list[object]],
    column_name: str,
    allowed_values: set[object],
    target_name: str,
) -> None:
    header = rows[0]
    index = header.index(column_name)
    for row in data_rows(rows):
        value = row[index]
        if value in ("", None):
            continue
        if value not in allowed_values:
            raise ValueError(f"{column_name} {value} is missing from {target_name}")


def validate_fixture_coverage() -> None:
    require_unique(CIVIL_ROWS, "national_id")
    require_unique(CIVIL_PERSON_DETAILS, "person_id")
    require_unique(CIVIL_PERSON_DETAILS, "national_id")
    require_unique(CIVIL_IDENTIFIERS, "identifier_id")
    require_unique(BIRTH_EVENTS, "event_id")
    require_unique(DEATH_EVENTS, "event_id")
    require_unique(CIVIL_STATUS_RECORDS, "record_id")
    require_unique(CIVIL_STATUS_RECORDS, "registration_number")
    require_unique(CERTIFICATES, "certificate_number")
    require_unique(RELATIONSHIPS, "relationship_id")
    require_unique(HOUSEHOLDS, "household_id")
    require_unique(PERSONS, "person_id")
    require_unique(ENROLLMENTS, "enrollment_id")
    require_unique(ENROLLMENTS, "national_id")
    require_unique(GROUP_MEMBERSHIPS, "membership_id")
    require_unique(SOCIO_ECONOMIC_PROFILES, "profile_id")
    require_unique(SCORING_EVENTS, "scoring_id")
    require_unique(PROGRAMS, "program_code")
    require_unique(ENTITLEMENTS, "entitlement_id")
    require_unique(PAYMENT_EVENTS, "payment_id")
    require_unique(FUNCTIONING_PROFILES, "profile_id")
    require_unique(DISABILITY_DETERMINATIONS, "determination_id")
    require_unique(DISTRICT_GEOMETRIES, "district")
    facility_ids = [row["facility_id"] for row in HEALTH_ROWS]
    if len(facility_ids) != len(set(facility_ids)):
        raise ValueError("facility_id values must be unique")

    civil_ids = {row[0] for row in data_rows(CIVIL_ROWS)}
    civil_person_ids = {row[0] for row in data_rows(CIVIL_PERSON_DETAILS)}
    birth_event_ids = {row[0] for row in data_rows(BIRTH_EVENTS)}
    death_event_ids = {row[0] for row in data_rows(DEATH_EVENTS)}
    civil_record_ids = {row[0] for row in data_rows(CIVIL_STATUS_RECORDS)}
    household_ids = {row[0] for row in data_rows(HOUSEHOLDS)}
    person_ids = {row[0] for row in data_rows(PERSONS)}
    profile_ids = {row[0] for row in data_rows(SOCIO_ECONOMIC_PROFILES)}
    program_codes = {row[0] for row in data_rows(PROGRAMS)}
    enrollment_ids = {row[0] for row in data_rows(ENROLLMENTS)}
    entitlement_ids = {row[0] for row in data_rows(ENTITLEMENTS)}

    require_refs(CIVIL_IDENTIFIERS, "person_id", civil_person_ids, "CIVIL_PERSON_DETAILS.person_id")
    require_refs(BIRTH_EVENTS, "child_person_id", civil_person_ids, "CIVIL_PERSON_DETAILS.person_id")
    require_refs(BIRTH_EVENTS, "mother_person_id", civil_person_ids, "CIVIL_PERSON_DETAILS.person_id")
    require_refs(BIRTH_EVENTS, "father_person_id", civil_person_ids, "CIVIL_PERSON_DETAILS.person_id")
    require_refs(DEATH_EVENTS, "deceased_person_id", civil_person_ids, "CIVIL_PERSON_DETAILS.person_id")
    require_refs(CIVIL_STATUS_RECORDS, "person_id", civil_person_ids, "CIVIL_PERSON_DETAILS.person_id")
    for row in data_rows(CIVIL_STATUS_RECORDS):
        event_id = row[4]
        allowed_events = birth_event_ids if row[1] == "birth" else death_event_ids
        if event_id not in allowed_events:
            raise ValueError(f"civil status record {row[0]} references unknown {row[1]} event {event_id}")
    require_refs(CERTIFICATES, "record_id", civil_record_ids, "CIVIL_STATUS_RECORDS.record_id")
    require_refs(RELATIONSHIPS, "subject_person_id", civil_person_ids, "CIVIL_PERSON_DETAILS.person_id")
    require_refs(RELATIONSHIPS, "related_person_id", civil_person_ids, "CIVIL_PERSON_DETAILS.person_id")
    require_refs(RELATIONSHIPS, "source_record_id", civil_record_ids, "CIVIL_STATUS_RECORDS.record_id")

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
        if row[4] not in program_codes:
            raise ValueError(f"enrollment {row[0]} references unknown program {row[4]}")
    require_refs(GROUP_MEMBERSHIPS, "household_id", household_ids, "HOUSEHOLDS.household_id")
    require_refs(GROUP_MEMBERSHIPS, "person_id", person_ids, "PERSONS.person_id")
    require_refs(SOCIO_ECONOMIC_PROFILES, "household_id", household_ids, "HOUSEHOLDS.household_id")
    require_refs(SCORING_EVENTS, "profile_id", profile_ids, "SOCIO_ECONOMIC_PROFILES.profile_id")
    require_refs(ENTITLEMENTS, "enrollment_id", enrollment_ids, "ENROLLMENTS.enrollment_id")
    require_refs(PAYMENT_EVENTS, "entitlement_id", entitlement_ids, "ENTITLEMENTS.entitlement_id")
    require_refs(FUNCTIONING_PROFILES, "person_id", person_ids, "PERSONS.person_id")
    require_refs(DISABILITY_DETERMINATIONS, "person_id", person_ids, "PERSONS.person_id")
    require_refs(FUNCTIONING_PROFILES, "national_id", civil_ids, "CIVIL_ROWS.national_id")
    require_refs(DISABILITY_DETERMINATIONS, "national_id", civil_ids, "CIVIL_ROWS.national_id")
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
    allowed_missing = {MISSING_SOURCE_OBSERVED_AT_NATIONAL_ID}
    for row in data_rows(CIVIL_ROWS):
        if row[0] not in allowed_missing and not str(row[7]).endswith("Z"):
            raise ValueError("civil fixture observed_at values must be RFC3339 UTC timestamps")
    for row in data_rows(ENROLLMENTS):
        if row[3] not in allowed_missing and not str(row[8]).endswith("Z"):
            raise ValueError("enrollment fixture observed_at values must be RFC3339 UTC timestamps")
    for row in HEALTH_ROWS:
        if row["national_id"] not in allowed_missing and not row["observed_at"].endswith("Z"):
            raise ValueError("health fixture observed_at values must be RFC3339 UTC timestamps")
    if HEALTH_PROJECTION_NAME != "ApplicantServiceAvailabilityProjection":
        raise ValueError("health national_id compatibility data must be framed as ApplicantServiceAvailabilityProjection")
    expected_persona_outcomes = {"positive", "negative", "ambiguous_match", "stale", "expired", "policy_denied"}
    actual_persona_outcomes = {row["expected_outcome"] for row in FIXTURE_PERSONAS.values()}
    if not expected_persona_outcomes.issubset(actual_persona_outcomes):
        missing = sorted(expected_persona_outcomes - actual_persona_outcomes)
        raise ValueError(f"fixture personas missing expected outcomes: {missing}")


def write_csv(path: Path, rows: list[list[object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerows(rows)


def write_civil_csv() -> None:
    civil_dir = DATA_DIR / "civil"
    for filename, rows in [
        ("civil-persons.csv", CIVIL_ROWS),
        ("civil-person-details.csv", CIVIL_PERSON_DETAILS),
        ("civil-identifiers.csv", CIVIL_IDENTIFIERS),
        ("birth-events.csv", BIRTH_EVENTS),
        ("death-events.csv", DEATH_EVENTS),
        ("civil-status-records.csv", CIVIL_STATUS_RECORDS),
        ("certificates.csv", CERTIFICATES),
        ("relationships.csv", RELATIONSHIPS),
    ]:
        write_csv(civil_dir / filename, rows)


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
        ("GroupMemberships", GROUP_MEMBERSHIPS),
        ("SocioEconomicProfiles", SOCIO_ECONOMIC_PROFILES),
        ("ScoringEvents", SCORING_EVENTS),
        ("Programs", PROGRAMS),
        ("Entitlements", ENTITLEMENTS),
        ("PaymentEvents", PAYMENT_EVENTS),
        ("FunctioningProfiles", FUNCTIONING_PROFILES),
        ("DisabilityDeterminations", DISABILITY_DETERMINATIONS),
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
            ("observed_at", pa.string()),
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
