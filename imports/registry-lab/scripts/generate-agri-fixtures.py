#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "openpyxl>=3.1",
# ]
# ///
# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic XLSX fixtures for the NAgDI agriculture demo."""

from __future__ import annotations

import datetime as dt
import io
import re
import zipfile
from pathlib import Path
from typing import Iterable

from openpyxl import Workbook
from openpyxl.packaging.core import DocumentProperties

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "agriculture"
EVALUATION_AS_OF = dt.date(2026, 5, 1)
SEASON = "2026A"
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


def d(value: str) -> dt.date:
    return dt.date.fromisoformat(value)


FARMERS = [
    {
        "farmer_id": "FARMER-1001",
        "national_id": "AG-NID-1001",
        "given_name": "Amina",
        "family_name": "Kone",
        "sex": "female",
        "birth_date": d("1988-04-13"),
        "district": "North Valley",
        "district_code": "D-NORTH",
        "village": "Mango Village",
        "village_code": "V-NOR-01",
        "phone_present": True,
        "registration_status": "active",
        "registered_on": d("2023-02-15"),
        "smallholder_status": "smallholder",
        "household_id": "AG-HH-1001",
        "role_in_household": "head",
        "age_band": "35-44",
        "youth_status": "not_youth",
        "disability_status": "none",
        "vulnerability_category": "climate_exposed",
        "producer_type": "crop",
        "contactable_by_sms": True,
        "preferred_language": "en",
        "data_quality_status": "verified",
        "source_submission_id": "SUB-FARM-2026-01",
        "last_verified_on": d("2026-03-10"),
        "source_office": "North District Agriculture Office",
    },
    {
        "farmer_id": "FARMER-1002",
        "national_id": "AG-NID-1002",
        "given_name": "Bako",
        "family_name": "Mensah",
        "sex": "male",
        "birth_date": d("1979-09-20"),
        "district": "East Ridge",
        "district_code": "D-EAST",
        "village": "Riverbend",
        "village_code": "V-EAS-01",
        "phone_present": True,
        "registration_status": "active",
        "registered_on": d("2022-11-05"),
        "smallholder_status": "smallholder",
        "household_id": "AG-HH-1002",
        "role_in_household": "head",
        "age_band": "45-54",
        "youth_status": "not_youth",
        "disability_status": "none",
        "vulnerability_category": "standard",
        "producer_type": "crop",
        "contactable_by_sms": True,
        "preferred_language": "en",
        "data_quality_status": "verified",
        "source_submission_id": "SUB-FARM-2026-01",
        "last_verified_on": d("2026-02-20"),
        "source_office": "East District Agriculture Office",
    },
    {
        "farmer_id": "FARMER-1003",
        "national_id": "AG-NID-1003",
        "given_name": "Chipo",
        "family_name": "Ndlovu",
        "sex": "female",
        "birth_date": d("1991-01-07"),
        "district": "North Valley",
        "district_code": "D-NORTH",
        "village": "Mango Village",
        "village_code": "V-NOR-01",
        "phone_present": False,
        "registration_status": "active",
        "registered_on": d("2023-03-11"),
        "smallholder_status": "smallholder",
        "household_id": "AG-HH-1003",
        "role_in_household": "head",
        "age_band": "35-44",
        "youth_status": "not_youth",
        "disability_status": "none",
        "vulnerability_category": "climate_exposed",
        "producer_type": "crop",
        "contactable_by_sms": False,
        "preferred_language": "en",
        "data_quality_status": "verified",
        "source_submission_id": "SUB-FARM-2026-01",
        "last_verified_on": d("2026-02-28"),
        "source_office": "North District Agriculture Office",
    },
    {
        "farmer_id": "FARMER-1004",
        "national_id": "AG-NID-1004",
        "given_name": "Dara",
        "family_name": "Okoro",
        "sex": "male",
        "birth_date": d("1985-06-18"),
        "district": "South Plains",
        "district_code": "D-SOUTH",
        "village": "Acacia",
        "village_code": "V-SOU-01",
        "phone_present": True,
        "registration_status": "pending_verification",
        "registered_on": d("2024-04-10"),
        "smallholder_status": "smallholder",
        "household_id": "AG-HH-1004",
        "role_in_household": "head",
        "age_band": "35-44",
        "youth_status": "not_youth",
        "disability_status": "none",
        "vulnerability_category": "standard",
        "producer_type": "crop",
        "contactable_by_sms": True,
        "preferred_language": "en",
        "data_quality_status": "stale_verification",
        "source_submission_id": "SUB-FARM-2024-02",
        "last_verified_on": d("2024-01-15"),
        "source_office": "South District Agriculture Office",
    },
    {
        "farmer_id": "FARMER-1005",
        "national_id": "AG-NID-1005",
        "given_name": "Esi",
        "family_name": "Abebe",
        "sex": "female",
        "birth_date": d("1997-12-03"),
        "district": "West Basin",
        "district_code": "D-WEST",
        "village": "Lowland",
        "village_code": "V-WES-01",
        "phone_present": True,
        "registration_status": "active",
        "registered_on": d("2023-08-22"),
        "smallholder_status": "smallholder",
        "household_id": "AG-HH-1005",
        "role_in_household": "head",
        "age_band": "25-34",
        "youth_status": "youth",
        "disability_status": "none",
        "vulnerability_category": "climate_exposed",
        "producer_type": "crop",
        "contactable_by_sms": True,
        "preferred_language": "fr",
        "data_quality_status": "manual_review",
        "source_submission_id": "SUB-FARM-2026-02",
        "last_verified_on": d("2026-03-15"),
        "source_office": "West District Agriculture Office",
    },
    {
        "farmer_id": "FARMER-2001",
        "national_id": "AG-NID-2001",
        "given_name": "Farai",
        "family_name": "Diallo",
        "sex": "male",
        "birth_date": d("1976-05-30"),
        "district": "Central Grazing",
        "district_code": "D-CENTRAL",
        "village": "Cattle Post",
        "village_code": "V-CEN-01",
        "phone_present": True,
        "registration_status": "active",
        "registered_on": d("2022-07-19"),
        "smallholder_status": "not_applicable",
        "household_id": "AG-HH-2001",
        "role_in_household": "head",
        "age_band": "45-54",
        "youth_status": "not_youth",
        "disability_status": "none",
        "vulnerability_category": "standard",
        "producer_type": "livestock",
        "contactable_by_sms": True,
        "preferred_language": "en",
        "data_quality_status": "verified",
        "source_submission_id": "SUB-FARM-2026-01",
        "last_verified_on": d("2026-02-12"),
        "source_office": "Central Animal Health Office",
    },
    {
        "farmer_id": "FARMER-2002",
        "national_id": "AG-NID-2002",
        "given_name": "Gita",
        "family_name": "Mwangi",
        "sex": "female",
        "birth_date": d("1982-08-09"),
        "district": "Central Grazing",
        "district_code": "D-CENTRAL",
        "village": "Cattle Post",
        "village_code": "V-CEN-01",
        "phone_present": True,
        "registration_status": "active",
        "registered_on": d("2022-09-30"),
        "smallholder_status": "not_applicable",
        "household_id": "AG-HH-2002",
        "role_in_household": "head",
        "age_band": "35-44",
        "youth_status": "not_youth",
        "disability_status": "none",
        "vulnerability_category": "standard",
        "producer_type": "mixed",
        "contactable_by_sms": True,
        "preferred_language": "en",
        "data_quality_status": "verified",
        "source_submission_id": "SUB-FARM-2026-01",
        "last_verified_on": d("2026-02-14"),
        "source_office": "Central Animal Health Office",
    },
    {
        "farmer_id": "FARMER-2003",
        "national_id": "AG-NID-2003",
        "given_name": "Hana",
        "family_name": "Tesfaye",
        "sex": "female",
        "birth_date": d("1990-11-26"),
        "district": "North Valley",
        "district_code": "D-NORTH",
        "village": "Hill Camp",
        "village_code": "V-NOR-02",
        "phone_present": False,
        "registration_status": "active",
        "registered_on": d("2023-05-12"),
        "smallholder_status": "not_applicable",
        "household_id": "AG-HH-2003",
        "role_in_household": "head",
        "age_band": "35-44",
        "youth_status": "not_youth",
        "disability_status": "none",
        "vulnerability_category": "standard",
        "producer_type": "livestock",
        "contactable_by_sms": False,
        "preferred_language": "en",
        "data_quality_status": "verified",
        "source_submission_id": "SUB-FARM-2026-01",
        "last_verified_on": d("2026-03-01"),
        "source_office": "North Animal Health Office",
    },
]

FARMER_IDENTIFIERS = [
    {
        "identifier_id": f"FID-{farmer['farmer_id'][-4:]}",
        "farmer_id": farmer["farmer_id"],
        "identifier_type": "synthetic_national_id",
        "identifier_value": farmer["national_id"],
        "issuing_authority": "Agricultural Registry Authority",
        "active": True,
        "recorded_on": farmer["registered_on"],
    }
    for farmer in FARMERS
]

FARMER_GROUPS = [
    {
        "membership_id": "MEM-1001",
        "farmer_id": "FARMER-1001",
        "group_id": "GRP-NORTH-MAIZE",
        "group_name": "North Maize Cooperative",
        "group_type": "producer_cooperative",
        "registration_number": "COOP-2023-011",
        "role": "member",
        "active": True,
        "joined_on": d("2023-06-01"),
    },
    {
        "membership_id": "MEM-1005",
        "farmer_id": "FARMER-1005",
        "group_id": "GRP-WEST-SEED",
        "group_name": "West Seed Growers",
        "group_type": "association",
        "registration_number": "ASSOC-2024-004",
        "role": "treasurer",
        "active": True,
        "joined_on": d("2024-02-01"),
    },
    {
        "membership_id": "MEM-2001",
        "farmer_id": "FARMER-2001",
        "group_id": "GRP-CENTRAL-CATTLE",
        "group_name": "Central Cattle Keepers",
        "group_type": "livestock_association",
        "registration_number": "LIV-2022-018",
        "role": "member",
        "active": True,
        "joined_on": d("2022-10-15"),
    },
]

DATA_USE_AUTHORIZATIONS = [
    {
        "authorization_id": "AUTH-1001-VOUCHER",
        "subject_id": "FARMER-1001",
        "subject_type": "farmer",
        "purpose_code": "climate-smart-input-support",
        "lawful_basis_code": "program_rule",
        "legal_instrument_reference": "AG-PROG-2026A-RULES",
        "grantee_type": "government_program",
        "disclosure_mode": "predicate",
        "status": "active",
        "valid_from": d("2026-01-01"),
        "valid_until": d("2026-12-31"),
        "captured_by": "North District Agriculture Office",
        "withdrawal_allowed": False,
    },
    {
        "authorization_id": "AUTH-1002-VOUCHER",
        "subject_id": "FARMER-1002",
        "subject_type": "farmer",
        "purpose_code": "climate-smart-input-support",
        "lawful_basis_code": "public_task",
        "legal_instrument_reference": "NAGDI-PUBLIC-SERVICE-2026",
        "grantee_type": "government_program",
        "disclosure_mode": "predicate",
        "status": "active",
        "valid_from": d("2026-01-01"),
        "valid_until": d("2026-12-31"),
        "captured_by": "East District Agriculture Office",
        "withdrawal_allowed": False,
    },
    {
        "authorization_id": "AUTH-1003-VOUCHER",
        "subject_id": "FARMER-1003",
        "subject_type": "farmer",
        "purpose_code": "climate-smart-input-support",
        "lawful_basis_code": "program_rule",
        "legal_instrument_reference": "AG-PROG-2026A-RULES",
        "grantee_type": "government_program",
        "disclosure_mode": "predicate",
        "status": "active",
        "valid_from": d("2026-01-01"),
        "valid_until": d("2026-12-31"),
        "captured_by": "North District Agriculture Office",
        "withdrawal_allowed": False,
    },
    {
        "authorization_id": "AUTH-1004-VOUCHER",
        "subject_id": "FARMER-1004",
        "subject_type": "farmer",
        "purpose_code": "climate-smart-input-support",
        "lawful_basis_code": "program_rule",
        "legal_instrument_reference": "AG-PROG-2026A-RULES",
        "grantee_type": "government_program",
        "disclosure_mode": "predicate",
        "status": "expired",
        "valid_from": d("2025-01-01"),
        "valid_until": d("2025-12-31"),
        "captured_by": "South District Agriculture Office",
        "withdrawal_allowed": False,
    },
    {
        "authorization_id": "AUTH-1005-VOUCHER",
        "subject_id": "FARMER-1005",
        "subject_type": "farmer",
        "purpose_code": "climate-smart-input-support",
        "lawful_basis_code": "consent",
        "legal_instrument_reference": "CONSENT-CAPTURE-2026-03",
        "grantee_type": "government_program",
        "disclosure_mode": "predicate",
        "status": "active",
        "valid_from": d("2026-03-01"),
        "valid_until": d("2026-09-30"),
        "captured_by": "West District Agriculture Office",
        "withdrawal_allowed": True,
    },
    {
        "authorization_id": "AUTH-2001-MOVE",
        "subject_id": "FARMER-2001",
        "subject_type": "farmer",
        "purpose_code": "livestock-movement-permit-review",
        "lawful_basis_code": "permit_condition",
        "legal_instrument_reference": "ANIMAL-HEALTH-PERMIT-REG-2026",
        "grantee_type": "animal_health_authority",
        "disclosure_mode": "redacted_result",
        "status": "active",
        "valid_from": d("2026-01-01"),
        "valid_until": d("2026-12-31"),
        "captured_by": "Central Animal Health Office",
        "withdrawal_allowed": False,
    },
    {
        "authorization_id": "AUTH-2002-MOVE",
        "subject_id": "FARMER-2002",
        "subject_type": "farmer",
        "purpose_code": "livestock-movement-permit-review",
        "lawful_basis_code": "legal_mandate",
        "legal_instrument_reference": "ANIMAL-HEALTH-ACT-14",
        "grantee_type": "animal_health_authority",
        "disclosure_mode": "redacted_result",
        "status": "active",
        "valid_from": d("2026-01-01"),
        "valid_until": d("2026-12-31"),
        "captured_by": "Central Animal Health Office",
        "withdrawal_allowed": False,
    },
    {
        "authorization_id": "AUTH-2003-MOVE",
        "subject_id": "FARMER-2003",
        "subject_type": "farmer",
        "purpose_code": "livestock-movement-permit-review",
        "lawful_basis_code": "vital_public_interest",
        "legal_instrument_reference": "ANIMAL-HEALTH-OUTBREAK-ORDER-2026-04",
        "grantee_type": "animal_health_authority",
        "disclosure_mode": "redacted_result",
        "status": "active",
        "valid_from": d("2026-01-01"),
        "valid_until": d("2026-12-31"),
        "captured_by": "North Animal Health Office",
        "withdrawal_allowed": False,
    },
]

FARMER_CHANGE_LOG = [
    {
        "change_id": "FCHG-001",
        "sheet_name": "Farmers",
        "record_id": "FARMER-1004",
        "change_type": "verification_pending",
        "changed_on": d("2026-01-10"),
        "changed_by_office": "South District Agriculture Office",
        "note": "Registration still awaiting field re-verification.",
    },
    {
        "change_id": "FCHG-002",
        "sheet_name": "Farmers",
        "record_id": "FARMER-1005",
        "change_type": "manual_review_flag",
        "changed_on": d("2026-03-16"),
        "changed_by_office": "West District Agriculture Office",
        "note": "Potential duplicate and parcel conflict require manual review.",
    },
]

HOLDINGS = [
    {
        "holding_id": "HOLD-1001",
        "farmer_id": "FARMER-1001",
        "district": "North Valley",
        "district_code": "D-NORTH",
        "village": "Mango Village",
        "village_code": "V-NOR-01",
        "holding_status": "active",
        "total_area_ha": 1.8,
        "primary_livelihood": "maize",
        "last_verified_on": d("2026-03-05"),
        "data_quality_status": "verified",
        "source_submission_id": "SUB-HOLD-2026-01",
    },
    {
        "holding_id": "HOLD-1002",
        "farmer_id": "FARMER-1002",
        "district": "East Ridge",
        "district_code": "D-EAST",
        "village": "Riverbend",
        "village_code": "V-EAS-01",
        "holding_status": "inactive",
        "total_area_ha": 0.6,
        "primary_livelihood": "maize",
        "last_verified_on": d("2025-12-20"),
        "data_quality_status": "verified",
        "source_submission_id": "SUB-HOLD-2026-01",
    },
    {
        "holding_id": "HOLD-1003",
        "farmer_id": "FARMER-1003",
        "district": "North Valley",
        "district_code": "D-NORTH",
        "village": "Mango Village",
        "village_code": "V-NOR-01",
        "holding_status": "active",
        "total_area_ha": 2.2,
        "primary_livelihood": "maize",
        "last_verified_on": d("2026-02-25"),
        "data_quality_status": "verified",
        "source_submission_id": "SUB-HOLD-2026-01",
    },
    {
        "holding_id": "HOLD-1004",
        "farmer_id": "FARMER-1004",
        "district": "South Plains",
        "district_code": "D-SOUTH",
        "village": "Acacia",
        "village_code": "V-SOU-01",
        "holding_status": "active",
        "total_area_ha": 1.1,
        "primary_livelihood": "sorghum",
        "last_verified_on": d("2024-01-15"),
        "data_quality_status": "stale_verification",
        "source_submission_id": "SUB-HOLD-2024-02",
    },
    {
        "holding_id": "HOLD-1005",
        "farmer_id": "FARMER-1005",
        "district": "West Basin",
        "district_code": "D-WEST",
        "village": "Lowland",
        "village_code": "V-WES-01",
        "holding_status": "active",
        "total_area_ha": 1.4,
        "primary_livelihood": "maize",
        "last_verified_on": d("2026-03-12"),
        "data_quality_status": "manual_review",
        "source_submission_id": "SUB-HOLD-2026-02",
    },
]

PARCELS = [
    {
        "parcel_id": "PAR-1001-A",
        "holding_id": "HOLD-1001",
        "plot_reference": "NV-MANGO-001",
        "district": "North Valley",
        "district_code": "D-NORTH",
        "area_ha": 1.2,
        "irrigation_type": "rainfed",
        "soil_zone": "loam",
        "geometry_wkt": "POLYGON ((30.10 1.10, 30.11 1.10, 30.11 1.11, 30.10 1.11, 30.10 1.10))",
        "active": True,
        "last_surveyed_on": d("2026-02-20"),
    },
    {
        "parcel_id": "PAR-1002-A",
        "holding_id": "HOLD-1002",
        "plot_reference": "ER-RIVER-014",
        "district": "East Ridge",
        "district_code": "D-EAST",
        "area_ha": 0.6,
        "irrigation_type": "rainfed",
        "soil_zone": "sandy",
        "geometry_wkt": "POINT (31.20 0.90)",
        "active": False,
        "last_surveyed_on": d("2025-10-01"),
    },
    {
        "parcel_id": "PAR-1003-A",
        "holding_id": "HOLD-1003",
        "plot_reference": "NV-MANGO-017",
        "district": "North Valley",
        "district_code": "D-NORTH",
        "area_ha": 1.7,
        "irrigation_type": "rainfed",
        "soil_zone": "loam",
        "geometry_wkt": "POLYGON ((30.12 1.12, 30.13 1.12, 30.13 1.13, 30.12 1.13, 30.12 1.12))",
        "active": True,
        "last_surveyed_on": d("2026-02-21"),
    },
    {
        "parcel_id": "PAR-1004-A",
        "holding_id": "HOLD-1004",
        "plot_reference": "SP-ACACIA-003",
        "district": "South Plains",
        "district_code": "D-SOUTH",
        "area_ha": 1.1,
        "irrigation_type": "borehole",
        "soil_zone": "clay",
        "geometry_wkt": "POINT (30.50 -0.75)",
        "active": True,
        "last_surveyed_on": d("2024-01-15"),
    },
    {
        "parcel_id": "PAR-1005-A",
        "holding_id": "HOLD-1005",
        "plot_reference": "WB-LOW-009",
        "district": "West Basin",
        "district_code": "D-WEST",
        "area_ha": 1.4,
        "irrigation_type": "rainfed",
        "soil_zone": "alluvial",
        "geometry_wkt": "POLYGON ((29.90 0.80, 29.91 0.80, 29.91 0.81, 29.90 0.81, 29.90 0.80))",
        "active": True,
        "last_surveyed_on": d("2026-03-12"),
    },
]

CROP_DECLARATIONS = [
    {
        "crop_declaration_id": "CROP-1001-MAIZE",
        "parcel_id": "PAR-1001-A",
        "season": SEASON,
        "crop": "maize",
        "planted_area_ha": 1.0,
        "declared_on": d("2026-03-18"),
        "declaration_status": "accepted",
    },
    {
        "crop_declaration_id": "CROP-1002-MAIZE",
        "parcel_id": "PAR-1002-A",
        "season": SEASON,
        "crop": "maize",
        "planted_area_ha": 0.5,
        "declared_on": d("2026-03-22"),
        "declaration_status": "accepted",
    },
    {
        "crop_declaration_id": "CROP-1003-MAIZE",
        "parcel_id": "PAR-1003-A",
        "season": SEASON,
        "crop": "maize",
        "planted_area_ha": 1.5,
        "declared_on": d("2026-03-18"),
        "declaration_status": "accepted",
    },
    {
        "crop_declaration_id": "CROP-1004-SORGHUM",
        "parcel_id": "PAR-1004-A",
        "season": SEASON,
        "crop": "sorghum",
        "planted_area_ha": 0.9,
        "declared_on": d("2026-03-19"),
        "declaration_status": "pending_verification",
    },
    {
        "crop_declaration_id": "CROP-1005-MAIZE",
        "parcel_id": "PAR-1005-A",
        "season": SEASON,
        "crop": "maize",
        "planted_area_ha": 1.2,
        "declared_on": d("2026-03-21"),
        "declaration_status": "manual_review",
    },
]

TENURE_CLAIMS = [
    {
        "tenure_id": "TEN-1001",
        "parcel_id": "PAR-1001-A",
        "tenure_type": "customary_use",
        "verified_status": "verified",
        "claim_source": "village_committee",
        "claim_confidence": "high",
        "adjudication_status": "not_title",
        "dispute_flag": False,
        "document_type": "committee_letter",
        "valid_from": d("2023-01-01"),
        "valid_until": d("2028-12-31"),
        "issuing_office": "North Farm Services Office",
    },
    {
        "tenure_id": "TEN-1005",
        "parcel_id": "PAR-1005-A",
        "tenure_type": "lease_use",
        "verified_status": "conflict_reported",
        "claim_source": "farmer_submission",
        "claim_confidence": "medium",
        "adjudication_status": "review_open",
        "dispute_flag": True,
        "document_type": "lease_copy",
        "valid_from": d("2025-01-01"),
        "valid_until": d("2027-12-31"),
        "issuing_office": "West Farm Services Office",
    },
]

HOLDINGS_CHANGE_LOG = [
    {
        "change_id": "HCHG-001",
        "sheet_name": "Parcels",
        "record_id": "PAR-1005-A",
        "change_type": "conflict_flagged",
        "changed_on": d("2026-03-16"),
        "changed_by_office": "West Farm Services Office",
        "note": "Lease claim conflicts with a duplicate candidate in reference data.",
    }
]

PROGRAMS = [
    {
        "program_code": "CSI-VOUCHER",
        "program_name": "Climate-Smart Input Voucher",
        "season": SEASON,
        "input_type": "climate_smart_seed",
        "district_scope": "D-NORTH,D-EAST,D-SOUTH,D-WEST",
        "status": "active",
        "starts_on": d("2026-02-01"),
        "ends_on": d("2026-07-31"),
    }
]

PROGRAM_RULES = [
    {
        "rule_id": "RULE-CSI-MAIZE-DROUGHT",
        "program_code": "CSI-VOUCHER",
        "season": SEASON,
        "target_crop": "maize",
        "target_risk_level": "high",
        "max_area_ha": 2.5,
        "household_cap": 1,
        "package_code": "PKG-MAIZE-DRT-10KG",
        "active": True,
    }
]

INPUT_PACKAGES = [
    {
        "package_code": "PKG-MAIZE-DRT-10KG",
        "input_type": "climate_smart_seed",
        "package_name": "Drought-tolerant maize seed 10kg",
        "quantity_limit": 10,
        "unit": "kg",
        "max_value": 75,
        "currency": "USD",
        "active": True,
    }
]

VOUCHER_ENTITLEMENTS = [
    {
        "entitlement_id": "ENT-1001",
        "farmer_id": "FARMER-1001",
        "program_code": "CSI-VOUCHER",
        "season": SEASON,
        "entitlement_status": "issued",
        "approval_status": "approved",
        "approved_by_office": "North Program Office",
        "eligible_input_type": "climate_smart_seed",
        "package_code": "PKG-MAIZE-DRT-10KG",
        "max_value": 75,
        "currency": "USD",
        "issued_on": d("2026-04-01"),
        "expires_on": d("2026-06-30"),
    },
    {
        "entitlement_id": "ENT-1002",
        "farmer_id": "FARMER-1002",
        "program_code": "CSI-VOUCHER",
        "season": SEASON,
        "entitlement_status": "issued",
        "approval_status": "approved",
        "approved_by_office": "East Program Office",
        "eligible_input_type": "climate_smart_seed",
        "package_code": "PKG-MAIZE-DRT-10KG",
        "max_value": 75,
        "currency": "USD",
        "issued_on": d("2026-04-02"),
        "expires_on": d("2026-06-30"),
    },
    {
        "entitlement_id": "ENT-1003",
        "farmer_id": "FARMER-1003",
        "program_code": "CSI-VOUCHER",
        "season": SEASON,
        "entitlement_status": "issued",
        "approval_status": "approved",
        "approved_by_office": "North Program Office",
        "eligible_input_type": "climate_smart_seed",
        "package_code": "PKG-MAIZE-DRT-10KG",
        "max_value": 75,
        "currency": "USD",
        "issued_on": d("2026-04-01"),
        "expires_on": d("2026-06-30"),
    },
    {
        "entitlement_id": "ENT-1004",
        "farmer_id": "FARMER-1004",
        "program_code": "CSI-VOUCHER",
        "season": SEASON,
        "entitlement_status": "pending",
        "approval_status": "pending_verification",
        "approved_by_office": "South Program Office",
        "eligible_input_type": "climate_smart_seed",
        "package_code": "PKG-MAIZE-DRT-10KG",
        "max_value": 75,
        "currency": "USD",
        "issued_on": d("2026-04-03"),
        "expires_on": d("2026-06-30"),
    },
    {
        "entitlement_id": "ENT-1005",
        "farmer_id": "FARMER-1005",
        "program_code": "CSI-VOUCHER",
        "season": SEASON,
        "entitlement_status": "review_required",
        "approval_status": "manual_review",
        "approved_by_office": "West Program Office",
        "eligible_input_type": "climate_smart_seed",
        "package_code": "PKG-MAIZE-DRT-10KG",
        "max_value": 75,
        "currency": "USD",
        "issued_on": d("2026-04-04"),
        "expires_on": d("2026-06-30"),
    },
]

VOUCHER_REDEMPTIONS = [
    {
        "redemption_id": "RED-1003-A",
        "entitlement_id": "ENT-1003",
        "farmer_id": "FARMER-1003",
        "supplier_id": "SUP-NORTH-01",
        "redemption_location": "North Depot",
        "redeemed_on": d("2026-04-18"),
        "redeemed_value": 75,
        "currency": "USD",
        "redemption_status": "accepted",
    },
    {
        "redemption_id": "RED-1003-B",
        "entitlement_id": "ENT-1003",
        "farmer_id": "FARMER-1003",
        "supplier_id": "SUP-NORTH-01",
        "redemption_location": "North Depot",
        "redeemed_on": d("2026-04-19"),
        "redeemed_value": 75,
        "currency": "USD",
        "redemption_status": "duplicate_attempt",
    },
    {
        "redemption_id": "RED-1002-A",
        "entitlement_id": "ENT-1002",
        "farmer_id": "FARMER-1002",
        "supplier_id": "SUP-EAST-EXPIRED",
        "redemption_location": "East Agro Shop",
        "redeemed_on": d("2026-04-22"),
        "redeemed_value": 0,
        "currency": "USD",
        "redemption_status": "rejected_supplier_license_expired",
    },
]

EXTENSION_VISITS = [
    {
        "visit_id": "VIS-1001",
        "farmer_id": "FARMER-1001",
        "parcel_id": "PAR-1001-A",
        "extension_officer_id": "EXT-NORTH-01",
        "visit_date": d("2026-03-24"),
        "advisory_topic": "drought_tolerant_maize",
        "recommendation_code": "REC-MAIZE-DRT",
        "follow_up_required": False,
    },
    {
        "visit_id": "VIS-1005",
        "farmer_id": "FARMER-1005",
        "parcel_id": "PAR-1005-A",
        "extension_officer_id": "EXT-WEST-02",
        "visit_date": d("2026-03-25"),
        "advisory_topic": "parcel_conflict_review",
        "recommendation_code": "REC-MANUAL-REVIEW",
        "follow_up_required": True,
    },
]

SUPPLIERS = [
    {
        "supplier_id": "SUP-NORTH-01",
        "supplier_name": "North Valley Agro Supplies",
        "district": "North Valley",
        "district_code": "D-NORTH",
        "license_status": "active",
        "last_verified_on": d("2026-04-10"),
    },
    {
        "supplier_id": "SUP-EAST-EXPIRED",
        "supplier_name": "East Ridge Farm Inputs",
        "district": "East Ridge",
        "district_code": "D-EAST",
        "license_status": "expired",
        "last_verified_on": d("2025-11-30"),
    },
]

BUDGET_ALLOCATIONS = [
    {
        "allocation_id": "ALLOC-NORTH-CSI",
        "program_code": "CSI-VOUCHER",
        "season": SEASON,
        "district_code": "D-NORTH",
        "package_code": "PKG-MAIZE-DRT-10KG",
        "allocated_quantity": 250,
        "allocated_value": 18750,
        "currency": "USD",
        "allocation_status": "approved",
    },
    {
        "allocation_id": "ALLOC-WEST-CSI",
        "program_code": "CSI-VOUCHER",
        "season": SEASON,
        "district_code": "D-WEST",
        "package_code": "PKG-MAIZE-DRT-10KG",
        "allocated_quantity": 40,
        "allocated_value": 3000,
        "currency": "USD",
        "allocation_status": "review_hold",
    },
]

REDEMPTION_RECONCILIATION = [
    {
        "reconciliation_id": "RECON-1003-A",
        "redemption_id": "RED-1003-A",
        "payment_batch_id": "PAY-2026-04-NORTH",
        "reconciliation_status": "matched",
        "reconciled_on": d("2026-04-25"),
        "exception_reason": "",
    },
    {
        "reconciliation_id": "RECON-1003-B",
        "redemption_id": "RED-1003-B",
        "payment_batch_id": "PAY-2026-04-NORTH",
        "reconciliation_status": "exception",
        "reconciled_on": d("2026-04-25"),
        "exception_reason": "duplicate_redemption_attempt",
    },
]

GRIEVANCES = [
    {
        "grievance_id": "GRV-1005",
        "farmer_id": "FARMER-1005",
        "program_code": "CSI-VOUCHER",
        "season": SEASON,
        "grievance_type": "duplicate_or_parcel_conflict",
        "status": "open",
        "opened_on": d("2026-04-12"),
        "closed_on": None,
        "resolution_code": "",
    }
]

SANCTIONS = [
    {
        "sanction_id": "SAN-1003",
        "farmer_id": "FARMER-1003",
        "program_code": "CSI-VOUCHER",
        "sanction_type": "duplicate_redemption_warning",
        "status": "pending_review",
        "effective_from": d("2026-04-20"),
        "effective_until": d("2026-07-31"),
        "issuing_office": "North Program Integrity Unit",
    }
]

DISTRICT_CLIMATE_RISK = [
    {
        "risk_id": "RISK-NORTH-2026A",
        "district": "North Valley",
        "district_code": "D-NORTH",
        "season": SEASON,
        "drought_risk_level": "high",
        "flood_risk_level": "low",
        "rainfall_percentile": 18,
        "recommended_input_type": "climate_smart_seed",
        "updated_on": d("2026-04-15"),
    },
    {
        "risk_id": "RISK-EAST-2026A",
        "district": "East Ridge",
        "district_code": "D-EAST",
        "season": SEASON,
        "drought_risk_level": "medium",
        "flood_risk_level": "low",
        "rainfall_percentile": 36,
        "recommended_input_type": "soil_moisture_extension",
        "updated_on": d("2026-04-15"),
    },
    {
        "risk_id": "RISK-SOUTH-2026A",
        "district": "South Plains",
        "district_code": "D-SOUTH",
        "season": SEASON,
        "drought_risk_level": "low",
        "flood_risk_level": "medium",
        "rainfall_percentile": 52,
        "recommended_input_type": "none",
        "updated_on": d("2026-04-15"),
    },
    {
        "risk_id": "RISK-WEST-2026A",
        "district": "West Basin",
        "district_code": "D-WEST",
        "season": SEASON,
        "drought_risk_level": "high",
        "flood_risk_level": "medium",
        "rainfall_percentile": 21,
        "recommended_input_type": "climate_smart_seed",
        "updated_on": d("2026-04-15"),
    },
]

RAINFALL_OBSERVATIONS = [
    {
        "observation_id": "RAIN-NORTH-2026-04-01",
        "district": "North Valley",
        "station_id": "WX-NORTH-01",
        "observed_on": d("2026-04-01"),
        "rainfall_mm": 12.5,
        "source_quality": "validated",
    },
    {
        "observation_id": "RAIN-WEST-2026-04-01",
        "district": "West Basin",
        "station_id": "WX-WEST-01",
        "observed_on": d("2026-04-01"),
        "rainfall_mm": 15.0,
        "source_quality": "validated",
    },
]

MARKET_PRICES = [
    {
        "price_id": "PRICE-NORTH-MAIZE-2026-04-30",
        "district": "North Valley",
        "market_name": "North Depot Market",
        "commodity": "maize",
        "price_date": d("2026-04-30"),
        "unit": "kg",
        "price": 0.42,
        "currency": "USD",
    },
    {
        "price_id": "PRICE-WEST-MAIZE-2026-04-30",
        "district": "West Basin",
        "market_name": "Lowland Market",
        "commodity": "maize",
        "price_date": d("2026-04-30"),
        "unit": "kg",
        "price": 0.45,
        "currency": "USD",
    },
]

CROP_CALENDAR = [
    {
        "calendar_id": "CAL-NORTH-MAIZE-2026A",
        "district": "North Valley",
        "crop": "maize",
        "season": SEASON,
        "planting_window_start": d("2026-03-01"),
        "planting_window_end": d("2026-04-30"),
        "harvest_window_start": d("2026-08-01"),
        "harvest_window_end": d("2026-09-30"),
    },
    {
        "calendar_id": "CAL-WEST-MAIZE-2026A",
        "district": "West Basin",
        "crop": "maize",
        "season": SEASON,
        "planting_window_start": d("2026-03-10"),
        "planting_window_end": d("2026-05-05"),
        "harvest_window_start": d("2026-08-15"),
        "harvest_window_end": d("2026-10-10"),
    },
]

ADVISORY_RULES = [
    {
        "rule_id": "ADV-NORTH-MAIZE-HIGH",
        "district": "North Valley",
        "season": SEASON,
        "crop": "maize",
        "risk_level": "high",
        "recommended_input_type": "climate_smart_seed",
        "advisory_text_code": "ADV-DRT-SEED",
        "active": True,
    },
    {
        "rule_id": "ADV-WEST-MAIZE-HIGH",
        "district": "West Basin",
        "season": SEASON,
        "crop": "maize",
        "risk_level": "high",
        "recommended_input_type": "climate_smart_seed",
        "advisory_text_code": "ADV-DRT-SEED",
        "active": True,
    },
]

VOUCHER_MARKET_SIZING_CELLS = [
    {
        "cell_id": "CELL-NORTH-MAIZE-HIGH-SEED",
        "district_code": "D-NORTH",
        "district": "North Valley",
        "village_code": "",
        "crop": "maize",
        "risk_band": "high",
        "input_type": "climate_smart_seed",
        "season": SEASON,
        "eligible_count": 6,
        "minimum_cell_count": 5,
        "suppression_status": "emitted",
        "suppression_reason": "",
        "recipient_type": "licensed_service_provider",
        "purpose_code": "agricultural-market-sizing",
    },
    {
        "cell_id": "CELL-WEST-MAIZE-HIGH-SEED",
        "district_code": "D-WEST",
        "district": "West Basin",
        "village_code": "",
        "crop": "maize",
        "risk_band": "high",
        "input_type": "climate_smart_seed",
        "season": SEASON,
        "eligible_count": None,
        "minimum_cell_count": 5,
        "suppression_status": "suppressed",
        "suppression_reason": "minimum_cell_count",
        "recipient_type": "licensed_service_provider",
        "purpose_code": "agricultural-market-sizing",
    },
    {
        "cell_id": "CELL-NORTH-TEFF-HIGH-SEED",
        "district_code": "D-NORTH",
        "district": "North Valley",
        "village_code": "V-NOR-01",
        "crop": "teff",
        "risk_band": "high",
        "input_type": "climate_smart_seed",
        "season": SEASON,
        "eligible_count": None,
        "minimum_cell_count": 5,
        "suppression_status": "suppressed",
        "suppression_reason": "rare_category_or_geography_floor",
        "recipient_type": "licensed_service_provider",
        "purpose_code": "agricultural-market-sizing",
    },
]

LIVESTOCK_HOLDINGS = [
    {
        "livestock_holding_id": "LH-2001",
        "farmer_id": "FARMER-2001",
        "district": "Central Grazing",
        "district_code": "D-CENTRAL",
        "village": "Cattle Post",
        "village_code": "V-CEN-01",
        "holding_status": "active",
        "premises_code": "PREM-2001",
        "last_verified_on": d("2026-03-01"),
    },
    {
        "livestock_holding_id": "LH-2002",
        "farmer_id": "FARMER-2002",
        "district": "Central Grazing",
        "district_code": "D-CENTRAL",
        "village": "Cattle Post",
        "village_code": "V-CEN-01",
        "holding_status": "active",
        "premises_code": "PREM-2002",
        "last_verified_on": d("2026-03-01"),
    },
    {
        "livestock_holding_id": "LH-2003",
        "farmer_id": "FARMER-2003",
        "district": "North Valley",
        "district_code": "D-NORTH",
        "village": "Hill Camp",
        "village_code": "V-NOR-02",
        "holding_status": "active",
        "premises_code": "PREM-2003",
        "last_verified_on": d("2026-03-05"),
    },
]

PREMISES = [
    {
        "premises_code": "PREM-2001",
        "district_code": "D-CENTRAL",
        "village_code": "V-CEN-01",
        "premises_type": "farm",
        "registration_status": "active",
        "last_verified_on": d("2026-03-01"),
    },
    {
        "premises_code": "PREM-2002",
        "district_code": "D-CENTRAL",
        "village_code": "V-CEN-01",
        "premises_type": "farm",
        "registration_status": "active",
        "last_verified_on": d("2026-03-01"),
    },
    {
        "premises_code": "PREM-2003",
        "district_code": "D-NORTH",
        "village_code": "V-NOR-02",
        "premises_type": "farm",
        "registration_status": "active",
        "last_verified_on": d("2026-03-05"),
    },
    {
        "premises_code": "PREM-DEST-01",
        "district_code": "D-SOUTH",
        "village_code": "V-SOU-01",
        "premises_type": "market",
        "registration_status": "active",
        "last_verified_on": d("2026-03-20"),
    },
]

HERDS = [
    {
        "herd_id": "HERD-2001",
        "farmer_id": "FARMER-2001",
        "livestock_holding_id": "LH-2001",
        "district": "Central Grazing",
        "district_code": "D-CENTRAL",
        "village_code": "V-CEN-01",
        "species": "cattle",
        "count": 18,
        "production_system": "pastoral",
        "registration_status": "registered",
        "updated_on": d("2026-03-01"),
    },
    {
        "herd_id": "HERD-2002",
        "farmer_id": "FARMER-2002",
        "livestock_holding_id": "LH-2002",
        "district": "Central Grazing",
        "district_code": "D-CENTRAL",
        "village_code": "V-CEN-01",
        "species": "cattle",
        "count": 9,
        "production_system": "mixed",
        "registration_status": "registered",
        "updated_on": d("2026-03-01"),
    },
    {
        "herd_id": "HERD-2003",
        "farmer_id": "FARMER-2003",
        "livestock_holding_id": "LH-2003",
        "district": "North Valley",
        "district_code": "D-NORTH",
        "village_code": "V-NOR-02",
        "species": "cattle",
        "count": 12,
        "production_system": "pastoral",
        "registration_status": "registered",
        "updated_on": d("2026-03-05"),
    },
    {
        "herd_id": "HERD-2004",
        "farmer_id": "FARMER-2001",
        "livestock_holding_id": "LH-2001",
        "district": "Central Grazing",
        "district_code": "D-CENTRAL",
        "village_code": "V-CEN-01",
        "species": "cattle",
        "count": 7,
        "production_system": "pastoral",
        "registration_status": "registered",
        "updated_on": d("2026-03-02"),
    },
    {
        "herd_id": "HERD-2005",
        "farmer_id": "FARMER-2002",
        "livestock_holding_id": "LH-2002",
        "district": "Central Grazing",
        "district_code": "D-CENTRAL",
        "village_code": "V-CEN-01",
        "species": "cattle",
        "count": 11,
        "production_system": "mixed",
        "registration_status": "registered",
        "updated_on": d("2026-03-02"),
    },
    {
        "herd_id": "HERD-2006",
        "farmer_id": "FARMER-2001",
        "livestock_holding_id": "LH-2001",
        "district": "Central Grazing",
        "district_code": "D-CENTRAL",
        "village_code": "V-CEN-01",
        "species": "cattle",
        "count": 5,
        "production_system": "pastoral",
        "registration_status": "registered",
        "updated_on": d("2026-03-03"),
    },
]

ANIMALS = [
    {
        "animal_id": "ANM-2001-001",
        "herd_id": "HERD-2001",
        "tag_id": "TAG-CEN-2001-001",
        "species": "cattle",
        "breed": "local",
        "sex": "female",
        "birth_date": d("2023-02-01"),
        "status": "active",
    },
    {
        "animal_id": "ANM-2002-001",
        "herd_id": "HERD-2002",
        "tag_id": "TAG-CEN-2002-001",
        "species": "cattle",
        "breed": "local",
        "sex": "male",
        "birth_date": d("2022-11-01"),
        "status": "active",
    },
    {
        "animal_id": "ANM-2003-001",
        "herd_id": "HERD-2003",
        "tag_id": "TAG-NOR-2003-001",
        "species": "cattle",
        "breed": "local",
        "sex": "female",
        "birth_date": d("2021-07-01"),
        "status": "active",
    },
]

VACCINATIONS = [
    {
        "vaccination_id": "VAC-2001-HERD",
        "herd_id": "HERD-2001",
        "animal_id": "",
        "vaccine_code": "FMD-6M",
        "vaccinated_on": d("2026-02-15"),
        "valid_until": d("2026-08-15"),
        "administered_by_office": "Central Animal Health Office",
        "status": "valid",
    },
    {
        "vaccination_id": "VAC-2002-HERD",
        "herd_id": "HERD-2002",
        "animal_id": "",
        "vaccine_code": "FMD-6M",
        "vaccinated_on": d("2025-08-01"),
        "valid_until": d("2026-02-01"),
        "administered_by_office": "Central Animal Health Office",
        "status": "expired",
    },
    {
        "vaccination_id": "VAC-2003-HERD",
        "herd_id": "HERD-2003",
        "animal_id": "",
        "vaccine_code": "FMD-6M",
        "vaccinated_on": d("2026-02-20"),
        "valid_until": d("2026-08-20"),
        "administered_by_office": "North Animal Health Office",
        "status": "valid",
    },
    {
        "vaccination_id": "VAC-2001-ANIMAL",
        "herd_id": "HERD-2001",
        "animal_id": "ANM-2001-001",
        "vaccine_code": "BRU-12M",
        "vaccinated_on": d("2026-01-20"),
        "valid_until": d("2027-01-20"),
        "administered_by_office": "Central Animal Health Office",
        "status": "valid",
    },
]

QUARANTINE_ZONES = [
    {
        "zone_id": "QZ-NORTH-FMD-2026",
        "district": "North Valley",
        "disease_code": "FMD",
        "status": "active",
        "effective_from": d("2026-04-01"),
        "effective_until": d("2026-06-15"),
        "declared_by_office": "National Animal Health Authority",
        "district_code": "D-NORTH",
    },
    {
        "zone_id": "QZ-CENTRAL-FMD-2025",
        "district": "Central Grazing",
        "disease_code": "FMD",
        "status": "expired",
        "effective_from": d("2025-08-01"),
        "effective_until": d("2025-09-01"),
        "declared_by_office": "National Animal Health Authority",
        "district_code": "D-CENTRAL",
    },
]

MOVEMENT_APPLICATIONS = [
    {
        "application_id": "MAPP-2001",
        "herd_id": "HERD-2001",
        "origin_premises_code": "PREM-2001",
        "destination_premises_code": "PREM-DEST-01",
        "species": "cattle",
        "animal_count": 5,
        "requested_movement_date": d("2026-05-10"),
        "movement_purpose": "market_sale",
        "application_status": "submitted",
    },
    {
        "application_id": "MAPP-2002",
        "herd_id": "HERD-2002",
        "origin_premises_code": "PREM-2002",
        "destination_premises_code": "PREM-DEST-01",
        "species": "cattle",
        "animal_count": 3,
        "requested_movement_date": d("2026-05-10"),
        "movement_purpose": "market_sale",
        "application_status": "submitted",
    },
    {
        "application_id": "MAPP-2003",
        "herd_id": "HERD-2003",
        "origin_premises_code": "PREM-2003",
        "destination_premises_code": "PREM-DEST-01",
        "species": "cattle",
        "animal_count": 4,
        "requested_movement_date": d("2026-05-10"),
        "movement_purpose": "market_sale",
        "application_status": "submitted",
    },
]

MOVEMENT_PERMITS = [
    {
        "permit_id": "MP-OLD-2001",
        "herd_id": "HERD-2001",
        "origin_district": "Central Grazing",
        "destination_district": "South Plains",
        "permit_status": "expired",
        "issued_on": d("2026-03-01"),
        "valid_until": d("2026-03-20"),
        "revoked_on": None,
    }
]

MOVEMENT_EVENTS = [
    {
        "movement_event_id": "MEV-OLD-2001",
        "permit_id": "MP-OLD-2001",
        "origin_premises_code": "PREM-2001",
        "destination_premises_code": "PREM-DEST-01",
        "moved_on": d("2026-03-12"),
        "animal_count": 2,
        "transporter_id": "TRANS-LOCAL-01",
        "confirmed_by_office": "South Animal Health Office",
    }
]

LIVESTOCK_CHANGE_LOG = [
    {
        "change_id": "LCHG-001",
        "sheet_name": "Vaccinations",
        "record_id": "VAC-2002-HERD",
        "change_type": "expired_for_review",
        "changed_on": d("2026-05-01"),
        "changed_by_office": "Central Animal Health Office",
        "note": "Expired vaccination should fail movement permit review.",
    }
]

ADMIN_AREAS = [
    {
        "admin_code": "D-NORTH",
        "admin_level": "district",
        "admin_name": "North Valley",
        "parent_admin_code": "COUNTRY-DEMO",
        "active": True,
        "valid_from": d("2020-01-01"),
        "valid_until": None,
    },
    {
        "admin_code": "D-EAST",
        "admin_level": "district",
        "admin_name": "East Ridge",
        "parent_admin_code": "COUNTRY-DEMO",
        "active": True,
        "valid_from": d("2020-01-01"),
        "valid_until": None,
    },
    {
        "admin_code": "D-SOUTH",
        "admin_level": "district",
        "admin_name": "South Plains",
        "parent_admin_code": "COUNTRY-DEMO",
        "active": True,
        "valid_from": d("2020-01-01"),
        "valid_until": None,
    },
    {
        "admin_code": "D-WEST",
        "admin_level": "district",
        "admin_name": "West Basin",
        "parent_admin_code": "COUNTRY-DEMO",
        "active": True,
        "valid_from": d("2020-01-01"),
        "valid_until": None,
    },
    {
        "admin_code": "D-CENTRAL",
        "admin_level": "district",
        "admin_name": "Central Grazing",
        "parent_admin_code": "COUNTRY-DEMO",
        "active": True,
        "valid_from": d("2020-01-01"),
        "valid_until": None,
    },
    {
        "admin_code": "V-NOR-01",
        "admin_level": "village",
        "admin_name": "Mango Village",
        "parent_admin_code": "D-NORTH",
        "active": True,
        "valid_from": d("2020-01-01"),
        "valid_until": None,
    },
    {
        "admin_code": "V-NOR-02",
        "admin_level": "village",
        "admin_name": "Hill Camp",
        "parent_admin_code": "D-NORTH",
        "active": True,
        "valid_from": d("2020-01-01"),
        "valid_until": None,
    },
    {
        "admin_code": "V-EAS-01",
        "admin_level": "village",
        "admin_name": "Riverbend",
        "parent_admin_code": "D-EAST",
        "active": True,
        "valid_from": d("2020-01-01"),
        "valid_until": None,
    },
    {
        "admin_code": "V-SOU-01",
        "admin_level": "village",
        "admin_name": "Acacia",
        "parent_admin_code": "D-SOUTH",
        "active": True,
        "valid_from": d("2020-01-01"),
        "valid_until": None,
    },
    {
        "admin_code": "V-WES-01",
        "admin_level": "village",
        "admin_name": "Lowland",
        "parent_admin_code": "D-WEST",
        "active": True,
        "valid_from": d("2020-01-01"),
        "valid_until": None,
    },
    {
        "admin_code": "V-CEN-01",
        "admin_level": "village",
        "admin_name": "Cattle Post",
        "parent_admin_code": "D-CENTRAL",
        "active": True,
        "valid_from": d("2020-01-01"),
        "valid_until": None,
    },
]

CROP_CODES = [
    {"crop_code": "maize", "crop_name": "Maize", "active": True},
    {"crop_code": "sorghum", "crop_name": "Sorghum", "active": True},
    {"crop_code": "teff", "crop_name": "Teff", "active": True},
]

COMMODITY_CODES = [
    {"commodity_code": "maize", "commodity_name": "Maize grain", "unit": "kg", "active": True}
]

INPUT_CATALOG = [
    {
        "input_code": "climate_smart_seed",
        "input_name": "Climate-smart seed",
        "unit": "kg",
        "active": True,
    }
]

DISEASE_CODES = [
    {"disease_code": "FMD", "disease_name": "Foot and mouth disease", "species": "cattle", "active": True}
]

VACCINE_CODES = [
    {"vaccine_code": "FMD-6M", "disease_code": "FMD", "validity_days": 181, "active": True},
    {"vaccine_code": "BRU-12M", "disease_code": "BRU", "validity_days": 365, "active": True},
]

SERVICE_PROVIDERS = [
    {
        "provider_id": "SP-MARKET-01",
        "provider_name": "Demo Licensed Market Analytics Provider",
        "provider_type": "licensed_service_provider",
        "license_status": "active",
        "valid_until": d("2026-12-31"),
    }
]

PURPOSE_POLICIES = [
    {
        "purpose_code": "climate-smart-input-support",
        "public_service_code": "climate_smart_input_voucher",
        "lawful_basis_code": "program_rule",
        "allowed_recipient_types": "government_program,extension_authority",
        "allowed_disclosure_modes": "predicate,redacted_result",
        "retention_days": 365,
        "minimum_cell_count": 0,
        "geography_floor": "",
        "suppression_policy": "",
        "rare_category_suppression": False,
        "onward_sharing_allowed": False,
        "automated_decision_allowed": False,
        "appeal_contact": "agri-appeals@example.gov",
        "audit_required": True,
    },
    {
        "purpose_code": "livestock-movement-permit-review",
        "public_service_code": "livestock_movement_permit",
        "lawful_basis_code": "permit_condition",
        "allowed_recipient_types": "animal_health_authority",
        "allowed_disclosure_modes": "predicate,redacted_result",
        "retention_days": 730,
        "minimum_cell_count": 0,
        "geography_floor": "",
        "suppression_policy": "",
        "rare_category_suppression": False,
        "onward_sharing_allowed": False,
        "automated_decision_allowed": False,
        "appeal_contact": "animal-health-appeals@example.gov",
        "audit_required": True,
    },
    {
        "purpose_code": "agricultural-market-sizing",
        "public_service_code": "agricultural_market_sizing",
        "lawful_basis_code": "public_task",
        "allowed_recipient_types": "licensed_service_provider,planning_unit",
        "allowed_disclosure_modes": "aggregate",
        "retention_days": 90,
        "minimum_cell_count": 5,
        "geography_floor": "district",
        "suppression_policy": "suppress_cells_below_minimum_or_below_geography_floor",
        "rare_category_suppression": True,
        "onward_sharing_allowed": False,
        "automated_decision_allowed": False,
        "appeal_contact": "nagdi-governance@example.gov",
        "audit_required": True,
    },
]

SOURCE_SUBMISSIONS = [
    {
        "source_submission_id": "SUB-FARM-2026-01",
        "source_office": "District agriculture offices",
        "submitted_by_role": "registry_officer",
        "submitted_on": d("2026-03-20"),
        "source_file_label": "farmer-register-march-2026.xlsx",
        "record_count": 7,
        "validation_status": "accepted",
    },
    {
        "source_submission_id": "SUB-FARM-2026-02",
        "source_office": "West District Agriculture Office",
        "submitted_by_role": "registry_officer",
        "submitted_on": d("2026-03-16"),
        "source_file_label": "west-farmer-corrections.xlsx",
        "record_count": 1,
        "validation_status": "manual_review",
    },
    {
        "source_submission_id": "SUB-HOLD-2026-01",
        "source_office": "Farm services offices",
        "submitted_by_role": "extension_supervisor",
        "submitted_on": d("2026-03-23"),
        "source_file_label": "holdings-season-2026A.xlsx",
        "record_count": 4,
        "validation_status": "accepted",
    },
    {
        "source_submission_id": "SUB-HOLD-2026-02",
        "source_office": "West Farm Services Office",
        "submitted_by_role": "extension_supervisor",
        "submitted_on": d("2026-03-16"),
        "source_file_label": "west-holdings-conflict.xlsx",
        "record_count": 1,
        "validation_status": "manual_review",
    },
    {
        "source_submission_id": "SUB-FARM-2024-02",
        "source_office": "South District Agriculture Office",
        "submitted_by_role": "registry_officer",
        "submitted_on": d("2024-01-15"),
        "source_file_label": "south-register-legacy.xlsx",
        "record_count": 1,
        "validation_status": "stale",
    },
    {
        "source_submission_id": "SUB-HOLD-2024-02",
        "source_office": "South Farm Services Office",
        "submitted_by_role": "extension_supervisor",
        "submitted_on": d("2024-01-15"),
        "source_file_label": "south-holdings-legacy.xlsx",
        "record_count": 1,
        "validation_status": "stale",
    },
]

VALIDATION_ISSUES = [
    {
        "issue_id": "ISSUE-1005-DUP",
        "source_submission_id": "SUB-FARM-2026-02",
        "sheet_name": "Farmers",
        "record_id": "FARMER-1005",
        "issue_type": "possible_duplicate",
        "severity": "high",
        "status": "open",
        "detected_on": d("2026-03-16"),
    },
    {
        "issue_id": "ISSUE-1005-PARCEL",
        "source_submission_id": "SUB-HOLD-2026-02",
        "sheet_name": "TenureClaims",
        "record_id": "TEN-1005",
        "issue_type": "parcel_conflict",
        "severity": "high",
        "status": "open",
        "detected_on": d("2026-03-16"),
    },
]

DUPLICATE_CANDIDATES = [
    {
        "candidate_id": "DUP-1005",
        "source_submission_id": "SUB-FARM-2026-02",
        "farmer_id": "FARMER-1005",
        "matched_farmer_id": "FARMER-1001",
        "match_basis": "similar_name_same_group",
        "match_score": 0.72,
        "status": "manual_review",
    }
]

CORRECTION_REQUESTS = [
    {
        "correction_request_id": "CORR-1005",
        "issue_id": "ISSUE-1005-DUP",
        "requested_from_office": "West District Agriculture Office",
        "requested_on": d("2026-03-17"),
        "status": "open",
        "resolution_note": "",
    }
]

VOUCHER_ELIGIBILITY_SNAPSHOTS = [
    {
        "farmer_id": "FARMER-1001",
        "season": SEASON,
        "purpose_code": "climate-smart-input-support",
        "farmer_registered": True,
        "data_use_authorized": True,
        "active_smallholder_farmer": True,
        "active_farm_parcel": True,
        "crop_declared_for_season": True,
        "district_climate_risk_active": True,
        "voucher_entitlement_current": True,
        "voucher_not_redeemed": True,
        "supplier_license_active": True,
        "manual_review_required": False,
        "reason_code": "eligible",
        "evaluation_as_of": EVALUATION_AS_OF,
    },
    {
        "farmer_id": "FARMER-1002",
        "season": SEASON,
        "purpose_code": "climate-smart-input-support",
        "farmer_registered": True,
        "data_use_authorized": True,
        "active_smallholder_farmer": True,
        "active_farm_parcel": False,
        "crop_declared_for_season": True,
        "district_climate_risk_active": True,
        "voucher_entitlement_current": True,
        "voucher_not_redeemed": False,
        "supplier_license_active": False,
        "manual_review_required": False,
        "reason_code": "parcel.status:not_active",
        "evaluation_as_of": EVALUATION_AS_OF,
    },
    {
        "farmer_id": "FARMER-1003",
        "season": SEASON,
        "purpose_code": "climate-smart-input-support",
        "farmer_registered": True,
        "data_use_authorized": True,
        "active_smallholder_farmer": True,
        "active_farm_parcel": True,
        "crop_declared_for_season": True,
        "district_climate_risk_active": True,
        "voucher_entitlement_current": True,
        "voucher_not_redeemed": False,
        "supplier_license_active": True,
        "manual_review_required": False,
        "reason_code": "voucher.redemption:already_redeemed",
        "evaluation_as_of": EVALUATION_AS_OF,
    },
    {
        "farmer_id": "FARMER-1004",
        "season": SEASON,
        "purpose_code": "climate-smart-input-support",
        "farmer_registered": False,
        "data_use_authorized": True,
        "active_smallholder_farmer": True,
        "active_farm_parcel": True,
        "crop_declared_for_season": True,
        "district_climate_risk_active": False,
        "voucher_entitlement_current": False,
        "voucher_not_redeemed": True,
        "supplier_license_active": True,
        "manual_review_required": False,
        "reason_code": "farmer.registration_status:not_active",
        "evaluation_as_of": EVALUATION_AS_OF,
    },
    {
        "farmer_id": "FARMER-1005",
        "season": SEASON,
        "purpose_code": "climate-smart-input-support",
        "farmer_registered": True,
        "data_use_authorized": True,
        "active_smallholder_farmer": True,
        "active_farm_parcel": True,
        "crop_declared_for_season": True,
        "district_climate_risk_active": True,
        "voucher_entitlement_current": True,
        "voucher_not_redeemed": True,
        "supplier_license_active": True,
        "manual_review_required": True,
        "reason_code": "data_quality:manual_review_required",
        "evaluation_as_of": EVALUATION_AS_OF,
    },
]

LIVESTOCK_MOVEMENT_SNAPSHOTS = [
    {
        "movement_snapshot_id": "HERD-2001",
        "farmer_id": "FARMER-2001",
        "herd_id": "HERD-2001",
        "registered_livestock_holder": True,
        "registered_herd": True,
        "herd_vaccination_current": True,
        "origin_district_not_quarantined": True,
        "destination_district_open": True,
        "no_conflicting_open_movement_permit": True,
        "manual_review_required": False,
        "reason_code": "eligible",
        "evaluation_as_of": EVALUATION_AS_OF,
    },
    {
        "movement_snapshot_id": "HERD-2002",
        "farmer_id": "FARMER-2002",
        "herd_id": "HERD-2002",
        "registered_livestock_holder": True,
        "registered_herd": True,
        "herd_vaccination_current": False,
        "origin_district_not_quarantined": True,
        "destination_district_open": True,
        "no_conflicting_open_movement_permit": True,
        "manual_review_required": False,
        "reason_code": "livestock.vaccination:expired",
        "evaluation_as_of": EVALUATION_AS_OF,
    },
    {
        "movement_snapshot_id": "HERD-2003",
        "farmer_id": "FARMER-2003",
        "herd_id": "HERD-2003",
        "registered_livestock_holder": True,
        "registered_herd": True,
        "herd_vaccination_current": True,
        "origin_district_not_quarantined": False,
        "destination_district_open": True,
        "no_conflicting_open_movement_permit": True,
        "manual_review_required": False,
        "reason_code": "quarantine.origin:active",
        "evaluation_as_of": EVALUATION_AS_OF,
    },
]

SNAPSHOT_MARKET_SIZING_CELLS = [
    {
        "cell_id": f"CELL-NORTH-MAIZE-HIGH-SEED-{index}",
        "district": "North Valley",
        "district_code": "D-NORTH",
        "season": SEASON,
        "crop": "maize",
        "risk_band": "high",
        "input_type": "climate_smart_seed",
        "eligible_opportunity_count": 1 + index,
        "estimated_area_ha": 0.7 + (index * 0.1),
        "cell_farmer_count": 6,
        "recipient_authorization_required": True,
        "geography_floor": "district",
    }
    for index in range(1, 6)
] + [
    {
        "cell_id": "CELL-WEST-MAIZE-HIGH-SEED-SUPPRESSED",
        "district": "West Basin",
        "district_code": "D-WEST",
        "season": SEASON,
        "crop": "maize",
        "risk_band": "high",
        "input_type": "climate_smart_seed",
        "eligible_opportunity_count": 1,
        "estimated_area_ha": 0.5,
        "cell_farmer_count": 1,
        "recipient_authorization_required": True,
        "geography_floor": "district",
    }
]

WORKBOOKS = {
    "farmer-registry.xlsx": [
        ("Farmers", FARMERS),
        ("FarmerIdentifiers", FARMER_IDENTIFIERS),
        ("FarmerGroups", FARMER_GROUPS),
        ("DataUseAuthorizations", DATA_USE_AUTHORIZATIONS),
        ("ChangeLog", FARMER_CHANGE_LOG),
    ],
    "farm-holdings-registry.xlsx": [
        ("Holdings", HOLDINGS),
        ("Parcels", PARCELS),
        ("CropDeclarations", CROP_DECLARATIONS),
        ("TenureClaims", TENURE_CLAIMS),
        ("ChangeLog", HOLDINGS_CHANGE_LOG),
    ],
    "agri-program-registry.xlsx": [
        ("Programs", PROGRAMS),
        ("VoucherEntitlements", VOUCHER_ENTITLEMENTS),
        ("VoucherRedemptions", VOUCHER_REDEMPTIONS),
        ("ExtensionVisits", EXTENSION_VISITS),
        ("Suppliers", SUPPLIERS),
        ("ProgramRules", PROGRAM_RULES),
        ("InputPackages", INPUT_PACKAGES),
        ("BudgetAllocations", BUDGET_ALLOCATIONS),
        ("RedemptionReconciliation", REDEMPTION_RECONCILIATION),
        ("Grievances", GRIEVANCES),
        ("Sanctions", SANCTIONS),
        ("ChangeLog", []),
    ],
    "agroclimate-market-registry.xlsx": [
        ("DistrictClimateRisk", DISTRICT_CLIMATE_RISK),
        ("RainfallObservations", RAINFALL_OBSERVATIONS),
        ("MarketPrices", MARKET_PRICES),
        ("CropCalendar", CROP_CALENDAR),
        ("AdvisoryRules", ADVISORY_RULES),
        ("VoucherMarketSizingCells", VOUCHER_MARKET_SIZING_CELLS),
    ],
    "livestock-registry.xlsx": [
        ("LivestockHoldings", LIVESTOCK_HOLDINGS),
        ("Premises", PREMISES),
        ("Herds", HERDS),
        ("Animals", ANIMALS),
        ("Vaccinations", VACCINATIONS),
        ("QuarantineZones", QUARANTINE_ZONES),
        ("MovementApplications", MOVEMENT_APPLICATIONS),
        ("MovementPermits", MOVEMENT_PERMITS),
        ("MovementEvents", MOVEMENT_EVENTS),
        ("ChangeLog", LIVESTOCK_CHANGE_LOG),
    ],
    "nagdi-reference-data.xlsx": [
        ("AdminAreas", ADMIN_AREAS),
        ("CropCodes", CROP_CODES),
        ("CommodityCodes", COMMODITY_CODES),
        ("InputCatalog", INPUT_CATALOG),
        ("DiseaseCodes", DISEASE_CODES),
        ("VaccineCodes", VACCINE_CODES),
        ("ServiceProviders", SERVICE_PROVIDERS),
        ("PurposePolicies", PURPOSE_POLICIES),
        ("SourceSubmissions", SOURCE_SUBMISSIONS),
        ("ValidationIssues", VALIDATION_ISSUES),
        ("DuplicateCandidates", DUPLICATE_CANDIDATES),
        ("CorrectionRequests", CORRECTION_REQUESTS),
    ],
    "nagdi-evidence-snapshots.xlsx": [
        ("VoucherEligibilitySnapshots", VOUCHER_ELIGIBILITY_SNAPSHOTS),
        ("LivestockMovementSnapshots", LIVESTOCK_MOVEMENT_SNAPSHOTS),
        ("MarketSizingCells", SNAPSHOT_MARKET_SIZING_CELLS),
    ],
}


def require_unique(rows: list[dict[str, object]], key: str) -> None:
    values = [row[key] for row in rows]
    if len(values) != len(set(values)):
        raise ValueError(f"{key} values must be unique")


def require_refs(
    rows: Iterable[dict[str, object]],
    local_key: str,
    foreign_values: set[object],
    foreign_label: str,
) -> None:
    for row in rows:
        value = row[local_key]
        if value not in foreign_values:
            raise ValueError(f"{local_key} {value} does not reference {foreign_label}")


def require_window(name: str, starts_on: dt.date, ends_on: dt.date | None) -> None:
    if starts_on > EVALUATION_AS_OF:
        raise ValueError(f"{name} starts after evaluation date {EVALUATION_AS_OF}")
    if ends_on is not None and ends_on < EVALUATION_AS_OF:
        raise ValueError(f"{name} ended before evaluation date {EVALUATION_AS_OF}")


def assert_crop_subject(farmer_id: str, expected: str) -> None:
    farmer = one(FARMERS, "farmer_id", farmer_id)
    holding = next((row for row in HOLDINGS if row["farmer_id"] == farmer_id), None)
    parcel = None
    crop = None
    if holding is not None:
        parcel = next((row for row in PARCELS if row["holding_id"] == holding["holding_id"]), None)
    if parcel is not None:
        crop = next((row for row in CROP_DECLARATIONS if row["parcel_id"] == parcel["parcel_id"]), None)
    auth = next(
        (
            row
            for row in DATA_USE_AUTHORIZATIONS
            if row["subject_id"] == farmer_id
            and row["purpose_code"] == "climate-smart-input-support"
            and row["status"] == "active"
            and row["valid_from"] <= EVALUATION_AS_OF <= row["valid_until"]
        ),
        None,
    )
    entitlement = next((row for row in VOUCHER_ENTITLEMENTS if row["farmer_id"] == farmer_id), None)
    accepted_redemption = any(
        row["farmer_id"] == farmer_id and row["redemption_status"] == "accepted"
        for row in VOUCHER_REDEMPTIONS
    )
    open_issue = any(row["record_id"] == farmer_id and row["status"] == "open" for row in VALIDATION_ISSUES)
    stale_farmer = farmer["last_verified_on"] < EVALUATION_AS_OF - dt.timedelta(days=365)
    is_eligible = (
        farmer["registration_status"] == "active"
        and farmer["smallholder_status"] == "smallholder"
        and farmer["data_quality_status"] == "verified"
        and not stale_farmer
        and auth is not None
        and holding is not None
        and holding["holding_status"] == "active"
        and parcel is not None
        and parcel["active"] is True
        and crop is not None
        and crop["season"] == SEASON
        and crop["crop"] == "maize"
        and entitlement is not None
        and entitlement["entitlement_status"] == "issued"
        and entitlement["approval_status"] == "approved"
        and entitlement["issued_on"] <= EVALUATION_AS_OF <= entitlement["expires_on"]
        and not accepted_redemption
        and not open_issue
    )
    if expected == "eligible" and not is_eligible:
        raise ValueError(f"{farmer_id} must be eligible for crop/input voucher")
    if expected == "not_eligible" and is_eligible:
        raise ValueError(f"{farmer_id} must be a negative crop/input voucher control")
    if expected == "manual_review" and not open_issue:
        raise ValueError(f"{farmer_id} must have an open manual-review data-quality issue")


def assert_livestock_subject(farmer_id: str, herd_id: str, expected: str) -> None:
    holding = one(LIVESTOCK_HOLDINGS, "farmer_id", farmer_id)
    herd = one(HERDS, "herd_id", herd_id)
    premises = one(PREMISES, "premises_code", holding["premises_code"])
    vaccination_current = any(
        row["herd_id"] == herd_id
        and row["status"] == "valid"
        and row["valid_until"] >= EVALUATION_AS_OF
        for row in VACCINATIONS
    )
    origin_quarantined = any(
        row["district_code"] == premises["district_code"]
        and row["status"] == "active"
        and row["effective_from"] <= EVALUATION_AS_OF <= row["effective_until"]
        for row in QUARANTINE_ZONES
    )
    open_permit = any(
        row["herd_id"] == herd_id
        and row["permit_status"] in {"issued", "active"}
        and row["valid_until"] >= EVALUATION_AS_OF
        for row in MOVEMENT_PERMITS
    )
    is_eligible = (
        holding["holding_status"] == "active"
        and herd["registration_status"] == "registered"
        and vaccination_current
        and not origin_quarantined
        and not open_permit
    )
    if expected == "eligible" and not is_eligible:
        raise ValueError(f"{farmer_id}/{herd_id} must be eligible for livestock movement")
    if expected == "not_eligible" and is_eligible:
        raise ValueError(f"{farmer_id}/{herd_id} must be a negative livestock control")


def one(rows: list[dict[str, object]], key: str, value: object) -> dict[str, object]:
    matches = [row for row in rows if row[key] == value]
    if len(matches) != 1:
        raise ValueError(f"expected one {key}={value}, found {len(matches)}")
    return matches[0]


def validate_fixtures() -> None:
    for rows, key in [
        (FARMERS, "farmer_id"),
        (FARMER_IDENTIFIERS, "identifier_id"),
        (FARMER_GROUPS, "membership_id"),
        (DATA_USE_AUTHORIZATIONS, "authorization_id"),
        (HOLDINGS, "holding_id"),
        (PARCELS, "parcel_id"),
        (CROP_DECLARATIONS, "crop_declaration_id"),
        (TENURE_CLAIMS, "tenure_id"),
        (PROGRAMS, "program_code"),
        (PROGRAM_RULES, "rule_id"),
        (INPUT_PACKAGES, "package_code"),
        (VOUCHER_ENTITLEMENTS, "entitlement_id"),
        (VOUCHER_REDEMPTIONS, "redemption_id"),
        (EXTENSION_VISITS, "visit_id"),
        (SUPPLIERS, "supplier_id"),
        (BUDGET_ALLOCATIONS, "allocation_id"),
        (REDEMPTION_RECONCILIATION, "reconciliation_id"),
        (GRIEVANCES, "grievance_id"),
        (SANCTIONS, "sanction_id"),
        (DISTRICT_CLIMATE_RISK, "risk_id"),
        (RAINFALL_OBSERVATIONS, "observation_id"),
        (MARKET_PRICES, "price_id"),
        (CROP_CALENDAR, "calendar_id"),
        (ADVISORY_RULES, "rule_id"),
        (VOUCHER_MARKET_SIZING_CELLS, "cell_id"),
        (LIVESTOCK_HOLDINGS, "livestock_holding_id"),
        (PREMISES, "premises_code"),
        (HERDS, "herd_id"),
        (ANIMALS, "animal_id"),
        (VACCINATIONS, "vaccination_id"),
        (QUARANTINE_ZONES, "zone_id"),
        (MOVEMENT_APPLICATIONS, "application_id"),
        (MOVEMENT_PERMITS, "permit_id"),
        (MOVEMENT_EVENTS, "movement_event_id"),
        (ADMIN_AREAS, "admin_code"),
        (SOURCE_SUBMISSIONS, "source_submission_id"),
        (VALIDATION_ISSUES, "issue_id"),
        (DUPLICATE_CANDIDATES, "candidate_id"),
        (CORRECTION_REQUESTS, "correction_request_id"),
        (VOUCHER_ELIGIBILITY_SNAPSHOTS, "farmer_id"),
        (LIVESTOCK_MOVEMENT_SNAPSHOTS, "movement_snapshot_id"),
        (SNAPSHOT_MARKET_SIZING_CELLS, "cell_id"),
    ]:
        require_unique(rows, key)

    farmer_ids = {row["farmer_id"] for row in FARMERS}
    holding_ids = {row["holding_id"] for row in HOLDINGS}
    parcel_ids = {row["parcel_id"] for row in PARCELS}
    program_codes = {row["program_code"] for row in PROGRAMS}
    package_codes = {row["package_code"] for row in INPUT_PACKAGES}
    entitlement_ids = {row["entitlement_id"] for row in VOUCHER_ENTITLEMENTS}
    supplier_ids = {row["supplier_id"] for row in SUPPLIERS}
    district_codes = {row["admin_code"] for row in ADMIN_AREAS if row["admin_level"] == "district"}
    source_submission_ids = {row["source_submission_id"] for row in SOURCE_SUBMISSIONS}
    livestock_holding_ids = {row["livestock_holding_id"] for row in LIVESTOCK_HOLDINGS}
    premises_codes = {row["premises_code"] for row in PREMISES}
    herd_ids = {row["herd_id"] for row in HERDS}
    animal_ids = {row["animal_id"] for row in ANIMALS}
    permit_ids = {row["permit_id"] for row in MOVEMENT_PERMITS}

    require_refs(FARMER_IDENTIFIERS, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(FARMER_GROUPS, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(HOLDINGS, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(PARCELS, "holding_id", holding_ids, "Holdings.holding_id")
    require_refs(CROP_DECLARATIONS, "parcel_id", parcel_ids, "Parcels.parcel_id")
    require_refs(TENURE_CLAIMS, "parcel_id", parcel_ids, "Parcels.parcel_id")
    require_refs(VOUCHER_ENTITLEMENTS, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(VOUCHER_ENTITLEMENTS, "program_code", program_codes, "Programs.program_code")
    require_refs(VOUCHER_ENTITLEMENTS, "package_code", package_codes, "InputPackages.package_code")
    require_refs(VOUCHER_REDEMPTIONS, "entitlement_id", entitlement_ids, "VoucherEntitlements.entitlement_id")
    require_refs(VOUCHER_REDEMPTIONS, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(VOUCHER_REDEMPTIONS, "supplier_id", supplier_ids, "Suppliers.supplier_id")
    require_refs(EXTENSION_VISITS, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(EXTENSION_VISITS, "parcel_id", parcel_ids, "Parcels.parcel_id")
    require_refs(BUDGET_ALLOCATIONS, "program_code", program_codes, "Programs.program_code")
    require_refs(BUDGET_ALLOCATIONS, "package_code", package_codes, "InputPackages.package_code")
    require_refs(REDEMPTION_RECONCILIATION, "redemption_id", {row["redemption_id"] for row in VOUCHER_REDEMPTIONS}, "VoucherRedemptions.redemption_id")
    require_refs(GRIEVANCES, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(SANCTIONS, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(LIVESTOCK_HOLDINGS, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(LIVESTOCK_HOLDINGS, "premises_code", premises_codes, "Premises.premises_code")
    require_refs(HERDS, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(HERDS, "livestock_holding_id", livestock_holding_ids, "LivestockHoldings.livestock_holding_id")
    require_refs(ANIMALS, "herd_id", herd_ids, "Herds.herd_id")
    require_refs(VACCINATIONS, "herd_id", herd_ids, "Herds.herd_id")
    require_refs(MOVEMENT_APPLICATIONS, "herd_id", herd_ids, "Herds.herd_id")
    require_refs(MOVEMENT_APPLICATIONS, "origin_premises_code", premises_codes, "Premises.premises_code")
    require_refs(MOVEMENT_APPLICATIONS, "destination_premises_code", premises_codes, "Premises.premises_code")
    require_refs(MOVEMENT_PERMITS, "herd_id", herd_ids, "Herds.herd_id")
    require_refs(MOVEMENT_EVENTS, "permit_id", permit_ids, "MovementPermits.permit_id")
    require_refs(VALIDATION_ISSUES, "source_submission_id", source_submission_ids, "SourceSubmissions.source_submission_id")
    require_refs(DUPLICATE_CANDIDATES, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(CORRECTION_REQUESTS, "issue_id", {row["issue_id"] for row in VALIDATION_ISSUES}, "ValidationIssues.issue_id")
    require_refs(VOUCHER_ELIGIBILITY_SNAPSHOTS, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(LIVESTOCK_MOVEMENT_SNAPSHOTS, "farmer_id", farmer_ids, "Farmers.farmer_id")
    require_refs(LIVESTOCK_MOVEMENT_SNAPSHOTS, "herd_id", herd_ids, "Herds.herd_id")

    for row in FARMERS + HOLDINGS + SUPPLIERS + LIVESTOCK_HOLDINGS + PREMISES:
        if "district_code" in row and row["district_code"] not in district_codes:
            raise ValueError(f"{row['district_code']} must reference an AdminAreas district")
    for row in FARMERS + HOLDINGS:
        require_refs([row], "source_submission_id", source_submission_ids, "SourceSubmissions.source_submission_id")
    for row in PROGRAMS:
        require_window(row["program_code"], row["starts_on"], row["ends_on"])
    for row in DATA_USE_AUTHORIZATIONS:
        if row["status"] == "active":
            require_window(row["authorization_id"], row["valid_from"], row["valid_until"])
    for row in VOUCHER_ENTITLEMENTS:
        if row["entitlement_status"] == "issued":
            require_window(row["entitlement_id"], row["issued_on"], row["expires_on"])
    for row in VACCINATIONS:
        if row["status"] == "valid":
            require_window(row["vaccination_id"], row["vaccinated_on"], row["valid_until"])
        if row["animal_id"]:
            require_refs([row], "animal_id", animal_ids, "Animals.animal_id")
    for row in QUARANTINE_ZONES:
        if row["status"] == "active":
            require_window(row["zone_id"], row["effective_from"], row["effective_until"])

    assert_crop_subject("FARMER-1001", "eligible")
    for farmer_id in ["FARMER-1002", "FARMER-1003", "FARMER-1004"]:
        assert_crop_subject(farmer_id, "not_eligible")
    assert_crop_subject("FARMER-1005", "manual_review")
    assert_livestock_subject("FARMER-2001", "HERD-2001", "eligible")
    assert_livestock_subject("FARMER-2002", "HERD-2002", "not_eligible")
    assert_livestock_subject("FARMER-2003", "HERD-2003", "not_eligible")

    if not any(row["suppression_status"] == "suppressed" for row in VOUCHER_MARKET_SIZING_CELLS):
        raise ValueError("market-sizing cells must include suppressed aggregate rows")
    if len([row for row in SNAPSHOT_MARKET_SIZING_CELLS if row["district_code"] == "D-NORTH"]) < 5:
        raise ValueError("snapshot market-sizing cells must include a publishable group")
    if len([row for row in SNAPSHOT_MARKET_SIZING_CELLS if row["district_code"] == "D-WEST"]) != 1:
        raise ValueError("snapshot market-sizing cells must include a suppressed group")
    for row in VOUCHER_MARKET_SIZING_CELLS:
        if row["suppression_status"] == "suppressed" and row["eligible_count"] is not None:
            raise ValueError("suppressed aggregate rows must not expose eligible_count")
        if row["village_code"] and row["suppression_status"] != "suppressed":
            raise ValueError("village-level aggregate rows must be suppressed by geography floor")
    if not any(row["status"] == "open" and row["severity"] == "high" for row in VALIDATION_ISSUES):
        raise ValueError("reference data must include an open high-severity manual-review issue")
    if not any(row["redemption_status"] == "duplicate_attempt" for row in VOUCHER_REDEMPTIONS):
        raise ValueError("program data must include a duplicate redemption attempt")
    if not any(row["license_status"] == "expired" for row in SUPPLIERS):
        raise ValueError("program data must include an expired supplier license control")


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


def write_workbook(path: Path, sheets: list[tuple[str, list[dict[str, object]]]]) -> None:
    workbook = Workbook()
    props = DocumentProperties()
    props.creator = "nagdi-agriculture-fixture-generator"
    props.lastModifiedBy = "nagdi-agriculture-fixture-generator"
    props.created = FIXED_TIMESTAMP
    props.modified = FIXED_TIMESTAMP
    workbook.properties = props
    workbook.remove(workbook.active)
    for title, rows in sheets:
        sheet = workbook.create_sheet(title)
        if not rows:
            sheet.append(["change_id", "sheet_name", "record_id", "change_type", "changed_on", "changed_by_office", "note"])
            continue
        headers = list(rows[0].keys())
        sheet.append(headers)
        for row in rows:
            sheet.append([row.get(header) for header in headers])
        for column_cells in sheet.columns:
            max_length = max(len(str(cell.value)) if cell.value is not None else 0 for cell in column_cells)
            sheet.column_dimensions[column_cells[0].column_letter].width = min(max(max_length + 2, 12), 42)
    buffer = io.BytesIO()
    workbook.save(buffer)
    path.write_bytes(canonicalize_xlsx(buffer.getvalue()))


def main() -> int:
    validate_fixtures()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for filename, sheets in WORKBOOKS.items():
        write_workbook(DATA_DIR / filename, sheets)
    print(
        "Generated NAgDI agriculture fixtures "
        f"for evaluation_as_of={EVALUATION_AS_OF.isoformat()} under {DATA_DIR}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
