#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "openpyxl>=3.1",
# ]
# ///
"""Generate synthetic XLSX workbooks for the registry-relay demo pack.

Reads no inputs. Writes:
  - demo/data/benefits_casework.xlsx
  - demo/data/clinic_capacity.xlsx
  - demo/data/public_works_projects.xlsx
  - demo/data/education_registry.xlsx
  - demo/data/subject_registry.xlsx
  - demo/data/disability_registry.xlsx

Determinism:
  - Single seeded random.Random instance threads through every draw.
  - openpyxl core properties are pinned to a fixed timestamp so the
    produced .xlsx bytes are stable across runs.

After generation the script runs in-process disclosure-control assertions:
for every configured demo aggregate it confirms at least one
group is below the dataset's min_group_size (so suppression triggers) and
at least one group is above it (so non-suppressed output shows). For
datasets that use 'mask' on a measure we also assert at least one masked
group exists.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import random
import re
import sys
import zipfile
from collections import Counter, defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.packaging.core import DocumentProperties

SEED = 42
FIXED_TIMESTAMP = dt.datetime(2026, 1, 1, 0, 0, 0)

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "demo" / "data"

DISTRICTS = ["north", "central", "riverbend", "highlands", "coast", "south"]
MONTHS = [f"2026-{m:02d}" for m in range(1, 13)]
SCHOOL_YEAR = "2026"
FISCAL_YEAR = "FY2026"
QUARTERS = ["Q1", "Q2", "Q3", "Q4"]
DISTRICT_MAP_POINTS = {
    "north": (35.0, 5.0),
    "central": (37.0, 8.0),
    "riverbend": (39.0, 11.0),
    "highlands": (41.0, 14.0),
    "coast": (43.0, 17.0),
    "south": (33.0, 3.0),
}

# Program / support categories shared between benefits and education.
SUPPORT_CATEGORIES = [
    "scholarship",
    "transport",
    "assistive_device",
    "meals",
    "cash_transfer",
    "school_supplies",
]

# Min group sizes per dataset, kept in sync with demo configs.
MIN_GROUP_SIZE = {
    "benefits_casework": 5,
    "clinic_capacity": 3,
    "public_works_projects": 2,
    "education_registry": 5,
    "subject_registry": 5,
}


def pick(rng: random.Random, options: Sequence[Any], weights: Sequence[int] | None = None) -> Any:
    if weights is None:
        return rng.choice(list(options))
    return rng.choices(list(options), weights=list(weights), k=1)[0]


def maybe(rng: random.Random, value: Any, probability_present: float) -> Any:
    """Return value with given probability, else None. Used for nullable date columns."""
    return value if rng.random() < probability_present else None


def daterange(rng: random.Random, start: dt.date, end: dt.date) -> dt.date:
    span = (end - start).days
    return start + dt.timedelta(days=rng.randint(0, span))


def stable_jitter(key: str, salt: str, radius: float = 0.35) -> float:
    digest = hashlib.sha256(f"{salt}:{key}".encode("utf-8")).digest()
    unit = int.from_bytes(digest[:4], "big") / 0xFFFF_FFFF
    return (unit * 2.0 - 1.0) * radius


# ---------------------------------------------------------------------------
# ID pools
# ---------------------------------------------------------------------------


def make_ids(prefix: str, base: int, count: int) -> list[str]:
    return [f"{prefix}-{base + i}" for i in range(count)]


# ---------------------------------------------------------------------------
# Benefits casework
# ---------------------------------------------------------------------------


def build_benefits(
    rng: random.Random,
    household_ids: list[str],
    person_ids_by_household: dict[str, list[str]],
) -> tuple[dict[str, list[list[Any]]], dict[str, str]]:
    """Return (sheet_name -> [header, *rows], household_id -> district) for benefits_casework."""

    sheets: dict[str, list[list[Any]]] = {}

    # Households -----------------------------------------------------------
    household_header = [
        "household_id",
        "district",
        "municipality",
        "household_size",
        "poverty_band",
        "enrollment_status",
        "enrolled_on",
        "address_line",
        "case_notes",
    ]
    # Distribute districts unevenly so disclosure control bites.
    # Heavy weight on a few districts and one very light district.
    district_weights = [25, 30, 22, 12, 9, 2]
    poverty_bands = ["band_1", "band_2", "band_3", "band_4"]
    enrollment_statuses = ["active", "suspended", "pending", "exited"]
    municipalities = {
        "north": ["northtown", "northvale"],
        "central": ["centralia", "midcity"],
        "riverbend": ["riverbend", "river_north"],
        "highlands": ["highvale", "highridge"],
        "coast": ["coastville", "seabridge"],
        "south": ["southton", "southvale"],
    }
    households_rows: list[list[Any]] = [household_header]
    household_district: dict[str, str] = {}
    for hh_id in household_ids:
        district = pick(rng, DISTRICTS, district_weights)
        household_district[hh_id] = district
        municipality = pick(rng, municipalities[district])
        size = rng.randint(1, 8)
        poverty = pick(rng, poverty_bands, weights=[20, 35, 30, 15])
        status = pick(rng, enrollment_statuses, weights=[60, 10, 15, 15])
        enrolled = daterange(rng, dt.date(2024, 1, 1), dt.date(2026, 4, 30))
        addr = f"{rng.randint(1, 999)} Fake St, {municipality}"
        notes = rng.choice(["", "", "needs follow-up", "verified by caseworker"])
        households_rows.append(
            [
                hh_id,
                district,
                municipality,
                size,
                poverty,
                status,
                enrolled,
                addr,
                notes,
            ]
        )
    sheets["Households"] = households_rows

    # Persons --------------------------------------------------------------
    persons_header = [
        "person_id",
        "household_id",
        "age_band",
        "sex",
        "disability_status",
        "benefit_role",
        "eligibility_status",
        "full_name",
        "national_id",
        "phone",
    ]
    age_bands = ["0-4", "5-12", "13-17", "18-29", "30-44", "45-64", "65+"]
    sexes = ["female", "male", "other"]
    disability_statuses = ["none", "physical", "sensory", "cognitive", "multiple", "unknown"]
    benefit_roles = ["applicant", "member", "payee"]
    eligibility_statuses = ["eligible", "ineligible", "pending_review", "appeal"]
    fake_first = ["Ada", "Bo", "Cy", "Dee", "El", "Fae", "Gus", "Hal", "Ivy", "Jo"]
    fake_last = ["Apple", "Birch", "Cedar", "Dale", "Elm", "Fern", "Gray", "Holt", "Iron", "Jade"]
    persons_rows: list[list[Any]] = [persons_header]
    for hh_id, persons in person_ids_by_household.items():
        for person_id in persons:
            age_band = pick(rng, age_bands)
            sex = pick(rng, sexes, weights=[49, 49, 2])
            disab = pick(rng, disability_statuses, weights=[70, 8, 6, 6, 4, 6])
            role = pick(rng, benefit_roles, weights=[20, 70, 10])
            eligibility = pick(rng, eligibility_statuses, weights=[55, 15, 20, 10])
            name = f"{pick(rng, fake_first)} {pick(rng, fake_last)}"
            national_id = f"FAKE-{rng.randint(100000, 999999)}"
            phone = f"555-0{rng.randint(100, 999)}"
            persons_rows.append(
                [
                    person_id,
                    hh_id,
                    age_band,
                    sex,
                    disab,
                    role,
                    eligibility,
                    name,
                    national_id,
                    phone,
                ]
            )
    sheets["Persons"] = persons_rows

    # Cases ----------------------------------------------------------------
    cases_header = [
        "case_id",
        "household_id",
        "case_type",
        "case_status",
        "opened_on",
        "closed_on",
        "priority",
        "caseworker_notes",
    ]
    case_types = ["appeal", "recertification", "grievance"]
    case_statuses = ["open", "in_progress", "closed", "stale"]
    priorities = ["low", "normal", "high", "urgent"]
    cases_rows: list[list[Any]] = [cases_header]
    # Roughly 70% of households have one case; some have two.
    case_id_counter = 6001
    for hh_id in household_ids:
        n_cases = rng.choices([0, 1, 2], weights=[30, 55, 15], k=1)[0]
        for _ in range(n_cases):
            case_id = f"case-{case_id_counter}"
            case_id_counter += 1
            ct = pick(rng, case_types, weights=[30, 50, 20])
            status = pick(rng, case_statuses, weights=[25, 30, 35, 10])
            opened = daterange(rng, dt.date(2024, 6, 1), dt.date(2026, 4, 30))
            if status == "closed":
                closed: dt.date | None = daterange(rng, opened, dt.date(2026, 5, 1))
            else:
                # stale cases sometimes still have a closed date; mostly null.
                closed = maybe(rng, daterange(rng, opened, dt.date(2026, 5, 1)), 0.05)
            priority = pick(rng, priorities, weights=[20, 50, 20, 10])
            notes = rng.choice(["", "internal review", "pending docs", ""])
            cases_rows.append([case_id, hh_id, ct, status, opened, closed, priority, notes])
    sheets["Cases"] = cases_rows

    # Payments -------------------------------------------------------------
    payments_header = [
        "payment_id",
        "household_id",
        "cycle",
        "payment_status",
        "amount",
        "paid_on",
        "payment_channel",
        "bank_account_hint",
    ]
    payment_statuses = ["scheduled", "paid", "failed", "reversed", "pending"]
    payment_channels = ["bank_transfer", "mobile_money", "voucher", "in_person"]
    payments_rows: list[list[Any]] = [payments_header]
    payment_id_counter = 7001
    for hh_id in household_ids:
        # Most households get monthly payments for some span of 2026 months.
        n_payments = rng.choices([0, 1, 2, 3, 4, 6, 8], weights=[5, 10, 15, 20, 20, 20, 10], k=1)[0]
        used_cycles: set[str] = set()
        for _ in range(n_payments):
            cycle = pick(rng, MONTHS)
            # Allow same cycle for retry payments; just unique by id.
            used_cycles.add(cycle)
            pid = f"pay-{payment_id_counter}"
            payment_id_counter += 1
            status = pick(rng, payment_statuses, weights=[10, 65, 8, 4, 13])
            amount = round(rng.uniform(20.0, 480.0), 2)
            if status == "paid":
                paid_on: dt.date | None = daterange(rng, dt.date(2026, 1, 1), dt.date(2026, 5, 31))
            else:
                paid_on = maybe(rng, daterange(rng, dt.date(2026, 1, 1), dt.date(2026, 5, 31)), 0.1)
            channel = pick(rng, payment_channels, weights=[40, 35, 15, 10])
            hint = f"****{rng.randint(1000, 9999)}"
            payments_rows.append(
                [pid, hh_id, cycle, status, amount, paid_on, channel, hint]
            )
    sheets["Payments"] = payments_rows

    return sheets, household_district


# ---------------------------------------------------------------------------
# Clinic capacity
# ---------------------------------------------------------------------------


def build_clinics(
    rng: random.Random, facility_ids: list[str]
) -> tuple[dict[str, list[list[Any]]], dict[str, str]]:
    sheets: dict[str, list[list[Any]]] = {}

    facilities_header = [
        "facility_id",
        "facility_name",
        "district",
        "facility_type",
        "ownership",
        "service_level",
        "latitude_band",
        "longitude_band",
        "map_latitude",
        "map_longitude",
        "exact_latitude",
        "exact_longitude",
    ]
    facility_types = ["clinic", "hospital", "health_post"]
    ownerships = ["public", "private", "mission"]
    service_levels = ["primary", "secondary", "tertiary"]
    # Coarse bands for synthetic geography.
    lat_bands = ["lat_0_5", "lat_5_10", "lat_10_15", "lat_15_20"]
    lon_bands = ["lon_30_35", "lon_35_40", "lon_40_45"]
    name_prefixes = ["Riverside", "Hilltop", "Greenfield", "Northgate", "Lakeview", "Sunrise"]
    name_suffixes = ["Clinic", "Health Centre", "Medical Post", "Hospital"]
    rows: list[list[Any]] = [facilities_header]
    facility_district: dict[str, str] = {}
    # Bias distribution so a couple of districts have very few facilities.
    fac_district_weights = [18, 30, 25, 14, 11, 2]
    for fid in facility_ids:
        district = pick(rng, DISTRICTS, fac_district_weights)
        facility_district[fid] = district
        ftype = pick(rng, facility_types, weights=[55, 15, 30])
        owner = pick(rng, ownerships, weights=[70, 15, 15])
        level = pick(rng, service_levels, weights=[60, 30, 10])
        name = f"{pick(rng, name_prefixes)} {pick(rng, name_suffixes)}"
        lat_b = pick(rng, lat_bands)
        lon_b = pick(rng, lon_bands)
        map_lon, map_lat = DISTRICT_MAP_POINTS[district]
        # Generalized public map points: enough for OGC discovery without
        # exposing operationally sensitive exact coordinates.
        map_lat = round(map_lat + stable_jitter(fid, "lat"), 4)
        map_lon = round(map_lon + stable_jitter(fid, "lon"), 4)
        # Exact lat/lon are sensitive: only roughly inside the band.
        exact_lat = round(rng.uniform(0.0, 20.0), 4)
        exact_lon = round(rng.uniform(30.0, 45.0), 4)
        rows.append(
            [
                fid,
                name,
                district,
                ftype,
                owner,
                level,
                lat_b,
                lon_b,
                map_lat,
                map_lon,
                exact_lat,
                exact_lon,
            ]
        )
    sheets["Facilities"] = rows

    # ServiceCapacity ------------------------------------------------------
    capacity_header = [
        "capacity_id",
        "facility_id",
        "service_type",
        "month",
        "beds_available",
        "staff_on_roster",
        "open_days",
        "internal_roster_notes",
    ]
    service_types = ["maternal", "emergency", "vaccination", "outpatient", "lab"]
    cap_rows: list[list[Any]] = [capacity_header]
    cap_id = 4501
    for fid in facility_ids:
        # 3 to 8 service-capacity rows per facility, across months and service types.
        n = rng.randint(3, 8)
        seen_pairs: set[tuple[str, str]] = set()
        for _ in range(n):
            stype = pick(rng, service_types)
            month = pick(rng, MONTHS)
            key = (stype, month)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            beds = rng.randint(0, 60)
            staff = rng.randint(0, 25)
            open_days = rng.randint(0, 30)
            note = rng.choice(["", "rotation pending", "", "two staff on leave"])
            cap_rows.append(
                [
                    f"cap-{cap_id}",
                    fid,
                    stype,
                    month,
                    beds,
                    staff,
                    open_days,
                    note,
                ]
            )
            cap_id += 1
    sheets["ServiceCapacity"] = cap_rows

    # StockEvents ----------------------------------------------------------
    stock_header = [
        "stock_event_id",
        "facility_id",
        "medicine_code",
        "event_month",
        "stock_status",
        "days_stocked_out",
        "supplier_comment",
    ]
    medicines = ["MED-A1", "MED-B2", "MED-C3", "MED-D4", "MED-E5"]
    stock_statuses = ["in_stock", "low_stock", "stockout"]
    stk_rows: list[list[Any]] = [stock_header]
    stk_id = 8001
    for fid in facility_ids:
        # Some facilities have no stock events (missing optional rows).
        n = rng.choices([0, 1, 2, 3, 4, 6], weights=[15, 25, 25, 15, 12, 8], k=1)[0]
        for _ in range(n):
            med = pick(rng, medicines)
            month = pick(rng, MONTHS)
            status = pick(rng, stock_statuses, weights=[55, 30, 15])
            days = rng.randint(0, 30) if status == "stockout" else (rng.randint(0, 5) if status == "low_stock" else 0)
            comment = rng.choice(["", "supplier delay", "", "rerouted"])
            stk_rows.append(
                [
                    f"sn-{stk_id}",
                    fid,
                    med,
                    month,
                    status,
                    days,
                    comment,
                ]
            )
            stk_id += 1
    sheets["StockEvents"] = stk_rows

    return sheets, facility_district


# ---------------------------------------------------------------------------
# Public works projects
# ---------------------------------------------------------------------------


def build_public_works(
    rng: random.Random,
    project_ids: list[str],
    school_ids: list[str],
    facility_ids: list[str],
) -> dict[str, list[list[Any]]]:
    sheets: dict[str, list[list[Any]]] = {}

    projects_header = [
        "project_id",
        "project_name",
        "sector",
        "district",
        "asset_type",
        "asset_ref",
        "implementing_agency",
        "project_status",
        "start_date",
        "planned_end_date",
        "risk_rating",
        "internal_risk_notes",
    ]
    sectors = ["roads", "water", "schools", "clinics"]
    sector_weights = [40, 30, 20, 10]
    statuses = ["planned", "active", "delayed", "completed", "cancelled"]
    # Skewed so 'cancelled' is rare; combined with rare sectors this gives a
    # (sector, status) combo with count 1, which is what the disclosure
    # check needs for min_group_size=2.
    status_weights = [10, 60, 15, 13, 2]
    risk_ratings = ["low", "medium", "high"]
    agencies = ["AgencyOne", "AgencyTwo", "AgencyThree", "AgencyFour"]
    name_words = ["Bridge", "Road", "School", "Clinic", "Borehole", "Office"]

    proj_rows: list[list[Any]] = [projects_header]
    project_district: dict[str, str] = {}
    project_district_weights = [22, 28, 24, 14, 10, 2]
    # Ensure school and facility asset_refs draw from real ids so cross-demo
    # flows resolve. About half of projects in 'schools' or 'clinics' sectors
    # point to a real sch- or fac- id.
    for pid in project_ids:
        sector = pick(rng, sectors, weights=sector_weights)
        district = pick(rng, DISTRICTS, project_district_weights)
        project_district[pid] = district
        if sector == "schools":
            asset_type = "school"
            asset_ref = pick(rng, school_ids)
        elif sector == "clinics":
            asset_type = "facility"
            asset_ref = pick(rng, facility_ids)
        else:
            asset_type = pick(rng, ["road", "water_point", "admin_building"])
            asset_ref = f"asset-{rng.randint(7000, 7999)}"
        status = pick(rng, statuses, weights=status_weights)
        start = daterange(rng, dt.date(2024, 1, 1), dt.date(2026, 3, 31))
        planned_end = start + dt.timedelta(days=rng.randint(90, 720))
        risk = pick(rng, risk_ratings, weights=[40, 45, 15])
        notes = rng.choice(["", "site access pending", "", "weather risk"])
        name = f"{district.title()} {pick(rng, name_words)} {rng.randint(1, 99)}"
        proj_rows.append(
            [
                pid,
                name,
                sector,
                district,
                asset_type,
                asset_ref,
                pick(rng, agencies),
                status,
                start,
                planned_end,
                risk,
                notes,
            ]
        )
    sheets["Projects"] = proj_rows

    # Contracts ------------------------------------------------------------
    contracts_header = [
        "contract_id",
        "project_id",
        "contractor_ref",
        "procurement_method",
        "contract_status",
        "contract_value",
        "signed_on",
        "contractor_bank_ref",
    ]
    procurement_methods = ["open_tender", "restricted_tender", "direct_award", "framework"]
    contract_statuses = ["draft", "signed", "active", "closed", "terminated"]
    contract_rows: list[list[Any]] = [contracts_header]
    contract_ids_by_project: dict[str, list[str]] = defaultdict(list)
    ctr_id = 9001
    for pid in project_ids:
        # Most projects have 1-2 contracts; some have none.
        n = rng.choices([0, 1, 2, 3], weights=[10, 55, 25, 10], k=1)[0]
        for _ in range(n):
            cid = f"ctr-{ctr_id}"
            ctr_id += 1
            contract_ids_by_project[pid].append(cid)
            # Framework procurement is very rare so the small district has
            # a (district, framework) cell of size 1 for the disclosure
            # control demo.
            method = pick(rng, procurement_methods, weights=[55, 30, 12, 3])
            status = pick(rng, contract_statuses, weights=[8, 22, 40, 25, 5])
            value = round(rng.uniform(5000.0, 750000.0), 2)
            signed = daterange(rng, dt.date(2024, 1, 1), dt.date(2026, 4, 30))
            bank = f"****-{rng.randint(1000, 9999)}"
            contract_rows.append(
                [cid, pid, f"vendor-{rng.randint(100, 999)}", method, status, value, signed, bank]
            )
    sheets["Contracts"] = contract_rows

    # Milestones -----------------------------------------------------------
    milestones_header = [
        "milestone_id",
        "project_id",
        "milestone_name",
        "milestone_status",
        "due_date",
        "completed_on",
        "delay_reason",
        "site_observation_notes",
    ]
    milestone_statuses = ["pending", "in_progress", "completed", "delayed", "blocked"]
    delay_reasons = [
        "weather",
        "supply_chain",
        "permits",
        "community_consultation",
        "funding_gap",
        "none",
    ]
    milestone_names = ["Site preparation", "Foundation", "Walls", "Roofing", "Finishing", "Handover"]
    mil_rows: list[list[Any]] = [milestones_header]
    mil_id = 10001
    for pid in project_ids:
        n = rng.choices([1, 2, 3, 4, 5], weights=[10, 20, 30, 25, 15], k=1)[0]
        for _ in range(n):
            mil_id_str = f"mil-{mil_id}"
            mil_id += 1
            status = pick(rng, milestone_statuses, weights=[15, 25, 30, 20, 10])
            due = daterange(rng, dt.date(2024, 6, 1), dt.date(2026, 12, 31))
            if status == "completed":
                completed = daterange(rng, dt.date(2024, 6, 1), due + dt.timedelta(days=30))
            else:
                completed = maybe(rng, daterange(rng, dt.date(2024, 6, 1), due), 0.05)
            # Most milestones follow status -> reason cleanly, but a small share
            # records the opposite (a delayed milestone with no recorded reason,
            # or a completed milestone that carries a past delay reason). This
            # produces rare (status, delay_reason) combinations the disclosure
            # control demo needs.
            if status in ("delayed", "blocked"):
                if rng.random() < 0.05:
                    reason = "none"
                else:
                    reason = pick(rng, [r for r in delay_reasons if r != "none"])
            else:
                if rng.random() < 0.03:
                    reason = pick(rng, [r for r in delay_reasons if r != "none"])
                else:
                    reason = "none"
            note = rng.choice(["", "inspector visit done", "", "observation pending"])
            mil_rows.append(
                [
                    mil_id_str,
                    pid,
                    pick(rng, milestone_names),
                    status,
                    due,
                    completed,
                    reason,
                    note,
                ]
            )
    sheets["Milestones"] = mil_rows

    # Disbursements --------------------------------------------------------
    disbursements_header = [
        "disbursement_id",
        "project_id",
        "contract_id",
        "fiscal_year",
        "quarter",
        "amount",
        "payment_status",
        "invoice_ref",
    ]
    payment_statuses = ["scheduled", "paid", "pending", "rejected"]
    dsb_rows: list[list[Any]] = [disbursements_header]
    dsb_id = 11001
    for pid in project_ids:
        contracts = contract_ids_by_project.get(pid, [])
        if not contracts:
            continue
        # Spread disbursements across quarters, skewed to Q1 and Q2 of FY2026.
        n = rng.choices([0, 1, 2, 3, 4], weights=[15, 30, 30, 15, 10], k=1)[0]
        for _ in range(n):
            did = f"dsb-{dsb_id}"
            dsb_id += 1
            cid = pick(rng, contracts)
            q = pick(rng, QUARTERS, weights=[45, 30, 15, 10])
            # Mostly FY2026; a tiny share are carryover disbursements from
            # FY2025 so we get sparse fiscal_year x quarter cells (the
            # disclosure-control demo needs at least one cell below
            # min_group_size=2).
            fy = "FY2025" if rng.random() < 0.015 else FISCAL_YEAR
            amount = round(rng.uniform(1000.0, 250000.0), 2)
            status = pick(rng, payment_statuses, weights=[20, 55, 20, 5])
            invoice = f"INV-{rng.randint(10000, 99999)}"
            dsb_rows.append(
                [did, pid, cid, fy, q, amount, status, invoice]
            )
    sheets["Disbursements"] = dsb_rows

    return sheets


# ---------------------------------------------------------------------------
# Education registry
# ---------------------------------------------------------------------------


def build_education(
    rng: random.Random,
    student_ids: list[str],
    school_ids: list[str],
    guardian_ids_by_student: dict[str, list[str]],
) -> tuple[dict[str, list[list[Any]]], dict[str, str]]:
    sheets: dict[str, list[list[Any]]] = {}

    # Schools first so we can map student to school and pick districts.
    schools_header = [
        "school_id",
        "school_name",
        "district",
        "school_type",
        "education_level",
        "has_meal_program",
        "has_accessibility_support",
    ]
    school_types = ["public", "private", "community"]
    edu_levels = ["primary", "lower_secondary", "upper_secondary"]
    school_prefixes = ["Riverside", "Hilltop", "Greenfield", "Northgate", "Lakeview", "Sunrise"]
    school_suffixes = ["Primary", "Secondary School", "Academy", "Community School"]
    school_district: dict[str, str] = {}
    schools_rows: list[list[Any]] = [schools_header]
    school_district_weights = [22, 28, 22, 14, 12, 2]
    for sid in school_ids:
        d = pick(rng, DISTRICTS, school_district_weights)
        school_district[sid] = d
        name = f"{pick(rng, school_prefixes)} {pick(rng, school_suffixes)}"
        st = pick(rng, school_types, weights=[60, 15, 25])
        level = pick(rng, edu_levels, weights=[50, 30, 20])
        meal = rng.choices([True, False], weights=[55, 45], k=1)[0]
        acc = rng.choices([True, False], weights=[40, 60], k=1)[0]
        schools_rows.append([sid, name, d, st, level, meal, acc])
    sheets["Schools"] = schools_rows

    # Students -------------------------------------------------------------
    students_header = [
        "student_id",
        "school_id",
        "current_enrollment_id",
        "date_of_birth",
        "age_band",
        "sex",
        "grade_level",
        "enrollment_status",
        "home_district",
        "language_group",
        "disability_status",
        "scholarship_eligible",
        "student_name",
        "national_id",
        "home_address",
        "guardian_phone",
        "student_notes",
    ]
    age_bands = ["5-7", "8-10", "11-13", "14-16", "17-19"]
    grade_levels = ["g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8", "g9", "g10", "g11", "g12"]
    # Heavy bias toward primary grades. A flat distribution over 12 grades
    # spreads 240 students too thin for the by_school_grade_status aggregate
    # to ever clear the min_group_size=5 threshold.
    grade_weights = [22, 22, 18, 14, 10, 6, 3, 2, 1, 1, 0, 1]
    enrollment_statuses = ["active", "transferred", "completed", "withdrawn"]
    languages = ["lang_a", "lang_b", "lang_c", "lang_d"]
    disability_statuses = ["none", "physical", "sensory", "cognitive", "multiple", "unknown"]
    sexes = ["female", "male", "other"]
    fake_first = ["Sam", "Lee", "Jo", "Kim", "Tay", "Robin", "Alex", "Mo", "Pat", "Bel"]
    fake_last = ["Stone", "River", "Brook", "Vale", "Glen", "Fell", "Wood", "Cliff", "Marsh", "Reed"]
    students_rows: list[list[Any]] = [students_header]
    # Each student references a school and gets one current enrollment id.
    student_to_school: dict[str, str] = {}
    student_district: dict[str, str] = {}
    student_school_year: dict[str, str] = {}
    # Skew school assignment so a handful of schools host most of the students.
    # Without this, 240 students over many schools, 12 grades, and 4 statuses
    # never produces a cell of 5+ for by_school_grade_status.
    school_assign_weights = [max(1, 30 - i * 2) for i in range(len(school_ids))]
    for sid in student_ids:
        school_id = pick(rng, school_ids, weights=school_assign_weights)
        student_to_school[sid] = school_id
        enrol_id = f"enr-{int(sid.split('-')[1]) + 4000}"
        dob = daterange(rng, dt.date(2008, 1, 1), dt.date(2020, 12, 31))
        age_band = pick(rng, age_bands)
        sex = pick(rng, sexes, weights=[49, 49, 2])
        grade = pick(rng, grade_levels, weights=grade_weights)
        # Home district is correlated with school district but not always equal.
        if rng.random() < 0.85:
            home_district = school_district[school_id]
        else:
            home_district = pick(rng, DISTRICTS)
        student_district[sid] = home_district
        lang = pick(rng, languages, weights=[50, 25, 15, 10])
        disab = pick(rng, disability_statuses, weights=[80, 5, 5, 4, 3, 3])
        scholarship = rng.choices([True, False], weights=[20, 80], k=1)[0]
        status = pick(rng, enrollment_statuses, weights=[78, 8, 8, 6])
        student_school_year[sid] = SCHOOL_YEAR
        name = f"{pick(rng, fake_first)} {pick(rng, fake_last)}"
        national_id = f"FAKE-{rng.randint(100000, 999999)}"
        home_address = f"{rng.randint(1, 999)} Fake Ln, {home_district}"
        phone = f"555-0{rng.randint(100, 999)}"
        notes = rng.choice(["", "good attendance", "", "needs check-in"])
        students_rows.append(
            [
                sid,
                school_id,
                enrol_id,
                dob,
                age_band,
                sex,
                grade,
                status,
                home_district,
                lang,
                disab,
                scholarship,
                name,
                national_id,
                home_address,
                phone,
                notes,
            ]
        )
    sheets["Students"] = students_rows

    # Guardians ------------------------------------------------------------
    guardians_header = [
        "guardian_id",
        "student_id",
        "relationship",
        "contact_verified",
        "guardian_name",
        "phone",
        "email",
        "address",
    ]
    relationships = ["parent", "caregiver", "other"]
    g_first = ["Pat", "Sam", "Lee", "Jo", "Kim", "Robin", "Alex", "Mo", "Tay", "Bel"]
    g_last = ["Stone", "River", "Brook", "Vale", "Glen", "Fell", "Wood", "Cliff", "Marsh", "Reed"]
    g_rows: list[list[Any]] = [guardians_header]
    for sid, guardians in guardian_ids_by_student.items():
        for gid in guardians:
            rel = pick(rng, relationships, weights=[75, 20, 5])
            verified = rng.choices([True, False], weights=[70, 30], k=1)[0]
            name = f"{pick(rng, g_first)} {pick(rng, g_last)}"
            phone = f"555-0{rng.randint(100, 999)}"
            email = f"fake.{rng.randint(1000, 9999)}@example.invalid"
            addr = f"{rng.randint(1, 999)} Fake Rd, {student_district[sid]}"
            g_rows.append([gid, sid, rel, verified, name, phone, email, addr])
    sheets["Guardians"] = g_rows

    # Enrollments ----------------------------------------------------------
    enrollments_header = [
        "enrollment_id",
        "student_id",
        "school_id",
        "school_year",
        "grade_level",
        "status",
        "enrolled_on",
        "exited_on",
    ]
    e_statuses = ["active", "transferred", "completed", "withdrawn"]
    e_rows: list[list[Any]] = [enrollments_header]
    for sid in student_ids:
        # Each student has a current enrollment matching current_enrollment_id, plus
        # 0-2 historical ones.
        current_id = f"enr-{int(sid.split('-')[1]) + 4000}"
        n_extra = rng.choices([0, 1, 2], weights=[60, 30, 10], k=1)[0]
        current_status = pick(rng, e_statuses, weights=[80, 8, 8, 4])
        enrolled = daterange(rng, dt.date(2024, 1, 1), dt.date(2025, 8, 30))
        if current_status == "active":
            exited: dt.date | None = None
        elif current_status == "completed":
            exited = daterange(rng, enrolled, dt.date(2026, 5, 31))
        else:
            exited = maybe(rng, daterange(rng, enrolled, dt.date(2026, 5, 31)), 0.7)
        e_rows.append(
            [
                current_id,
                sid,
                student_to_school[sid],
                SCHOOL_YEAR,
                pick(rng, ["g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8"]),
                current_status,
                enrolled,
                exited,
            ]
        )
        for k in range(n_extra):
            prior_id = f"enr-{int(sid.split('-')[1]) + 4000 + (k + 1) * 10000}"
            prior_enrolled = daterange(rng, dt.date(2022, 1, 1), dt.date(2024, 6, 30))
            prior_status = pick(rng, e_statuses, weights=[5, 30, 50, 15])
            prior_exited = (
                daterange(rng, prior_enrolled, dt.date(2024, 12, 31))
                if prior_status != "active"
                else None
            )
            e_rows.append(
                [
                    prior_id,
                    sid,
                    student_to_school[sid],
                    str(int(SCHOOL_YEAR) - 1 - k),
                    pick(rng, ["g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8"]),
                    prior_status,
                    prior_enrolled,
                    prior_exited,
                ]
            )
    sheets["Enrollments"] = e_rows

    # SupportNeeds ---------------------------------------------------------
    support_header = [
        "support_need_id",
        "student_id",
        "support_type",
        "eligibility_status",
        "assessment_date",
        "active",
        "assessment_notes",
    ]
    eligibility_states = ["pending", "eligible", "not_eligible"]
    sup_rows: list[list[Any]] = [support_header]
    sup_id = 12001
    for sid in student_ids:
        # Some students have 0 support needs (missing optional relationship).
        n = rng.choices([0, 1, 2, 3], weights=[40, 35, 18, 7], k=1)[0]
        for _ in range(n):
            sn_id = f"sn-{sup_id}"
            sup_id += 1
            stype = pick(rng, SUPPORT_CATEGORIES)
            estatus = pick(rng, eligibility_states, weights=[25, 55, 20])
            adate = maybe(rng, daterange(rng, dt.date(2024, 1, 1), dt.date(2026, 4, 30)), 0.85)
            active = rng.choices([True, False], weights=[70, 30], k=1)[0]
            notes = rng.choice(["", "follow-up scheduled", "", "documentation pending"])
            sup_rows.append([sn_id, sid, stype, estatus, adate, active, notes])
    sheets["SupportNeeds"] = sup_rows

    # AttendanceSummary ----------------------------------------------------
    att_header = [
        "attendance_id",
        "student_id",
        "school_year",
        "term",
        "attendance_rate",
        "chronic_absence_flag",
    ]
    terms = ["T1", "T2", "T3"]
    att_rows: list[list[Any]] = [att_header]
    att_id = 13001
    for sid in student_ids:
        # Some active students have no attendance summary (stale).
        n_terms = rng.choices([0, 1, 2, 3], weights=[10, 20, 30, 40], k=1)[0]
        chosen_terms = rng.sample(terms, k=n_terms) if n_terms <= len(terms) else terms
        for t in chosen_terms:
            rate = round(rng.uniform(0.4, 1.0), 3)
            chronic = rate < 0.7
            att_rows.append(
                [
                    f"att-{att_id}",
                    sid,
                    SCHOOL_YEAR,
                    t,
                    rate,
                    chronic,
                ]
            )
            att_id += 1
    sheets["AttendanceSummary"] = att_rows

    return sheets, student_district


# ---------------------------------------------------------------------------
# SP DCI Disability Registry
# ---------------------------------------------------------------------------


def build_disability_registry(rng: random.Random, count: int) -> dict[str, list[list[Any]]]:
    """Return sheet data for the optional SP DCI registry demos."""

    header = [
        "person_id",
        "member_identifier",
        "given_name",
        "surname",
        "sex",
        "birth_date",
        "disability_status",
        "disability_level",
        "impairment_type",
        "impairment_level",
        "human_assistance_type",
        "support_frequency",
        "support_status",
        "disability_details",
        "disability_support",
        "home_district",
        "age_band",
        "registration_date",
        "last_updated",
    ]
    statuses = ["Approved", "Approved", "Pending Review", "Suspended", "Not Certified"]
    disability_levels = ["mild", "moderate", "severe", "profound"]
    impairment_types = ["mobility", "visual", "hearing", "cognitive", "psychosocial"]
    impairment_levels = ["low", "medium", "high"]
    assistance_types = ["personal_assistant", "guide", "interpreter", "caregiver", "none"]
    support_frequencies = ["daily", "weekly", "monthly", "as_needed"]
    support_statuses = ["active", "pending", "paused", "completed"]
    age_bands = ["0-17", "18-29", "30-44", "45-64", "65+"]
    sexes = ["female", "male", "other"]
    fake_first = ["Ada", "Bo", "Cy", "Dee", "El", "Fae", "Gus", "Hal", "Ivy", "Jo"]
    fake_last = ["Apple", "Birch", "Cedar", "Dale", "Elm", "Fern", "Gray", "Holt", "Iron", "Jade"]

    rows: list[list[Any]] = [header]
    for i in range(1, count + 1):
        person_id = f"drp-{7000 + i}"
        member_identifier = f"DR-MEMBER-{i:03d}"
        given_name = pick(rng, fake_first)
        surname = pick(rng, fake_last)
        sex = pick(rng, sexes, weights=[49, 49, 2])
        birth_date = daterange(rng, dt.date(1945, 1, 1), dt.date(2018, 12, 31))
        status = statuses[(i - 1) % len(statuses)]
        impairment_type = pick(rng, impairment_types)
        disability_level = pick(rng, disability_levels)
        impairment_level = pick(rng, impairment_levels)
        assistance_type = pick(rng, assistance_types)
        support_frequency = pick(rng, support_frequencies)
        support_status = pick(rng, support_statuses)
        district = pick(rng, DISTRICTS, weights=[20, 18, 25, 12, 10, 15])
        age_band = pick(rng, age_bands, weights=[18, 16, 24, 28, 14])
        registered = daterange(rng, dt.date(2024, 1, 1), dt.date(2026, 3, 31))
        updated = registered + dt.timedelta(days=rng.randint(0, 180))
        details = f"{disability_level} {impairment_type} impairment"
        support = (
            "No recurring assistance registered"
            if assistance_type == "none"
            else f"{support_frequency} {assistance_type.replace('_', ' ')} support"
        )
        rows.append(
            [
                person_id,
                member_identifier,
                given_name,
                surname,
                sex,
                birth_date,
                status,
                disability_level,
                impairment_type,
                impairment_level,
                assistance_type,
                support_frequency,
                support_status,
                details,
                support,
                district,
                age_band,
                registered,
                updated,
            ]
        )

    civil_header = [
        "civil_person_id",
        "national_id",
        "given_name",
        "surname",
        "sex",
        "birth_date",
        "birth_place",
        "address_line",
        "district",
        "phone",
        "email",
        "registration_date",
        "last_updated",
    ]
    civil_rows: list[list[Any]] = [civil_header]
    for i in range(1, count + 1):
        district = pick(rng, DISTRICTS, weights=[20, 18, 25, 12, 10, 15])
        birth_date = daterange(rng, dt.date(1940, 1, 1), dt.date(2022, 12, 31))
        registration_date = birth_date + dt.timedelta(days=rng.randint(30, 365))
        last_updated = daterange(rng, dt.date(2025, 1, 1), dt.date(2026, 4, 30))
        civil_rows.append(
            [
                f"crp-{8000 + i}",
                f"FAKE-{810000 + i}",
                pick(rng, fake_first),
                pick(rng, fake_last),
                pick(rng, sexes, weights=[49, 49, 2]),
                birth_date,
                f"{district} civil office",
                f"{100 + i} Fake St",
                district,
                f"555-1{i:03d}",
                f"civil.{i:03d}@example.invalid",
                registration_date,
                last_updated,
            ]
        )

    social_header = [
        "group_id",
        "group_type",
        "district",
        "address_line",
        "poverty_score",
        "poverty_score_type",
        "group_size",
        "head_member_id",
        "head_national_id",
        "head_given_name",
        "head_surname",
        "head_sex",
        "head_birth_date",
        "head_disability_status",
        "registration_date",
        "last_updated",
    ]
    social_rows: list[list[Any]] = [social_header]
    for i in range(1, count + 1):
        district = pick(rng, DISTRICTS, weights=[20, 18, 25, 12, 10, 15])
        registered = daterange(rng, dt.date(2023, 1, 1), dt.date(2026, 3, 31))
        social_rows.append(
            [
                f"SR-GROUP-{i:03d}",
                pick(rng, ["family", "household"], weights=[35, 65]),
                district,
                f"{200 + i} Fake St, {district}",
                round(rng.uniform(12.0, 88.0), 2),
                "income-based",
                rng.randint(1, 8),
                f"SR-MEMBER-{i:03d}",
                f"FAKE-{820000 + i}",
                pick(rng, fake_first),
                pick(rng, fake_last),
                pick(rng, sexes, weights=[49, 49, 2]),
                daterange(rng, dt.date(1945, 1, 1), dt.date(2006, 12, 31)),
                pick(rng, ["none", "physical", "sensory", "cognitive"], weights=[80, 8, 7, 5]),
                registered,
                registered + dt.timedelta(days=rng.randint(0, 240)),
            ]
        )

    farmer_header = [
        "farmer_id",
        "family_id",
        "national_id",
        "given_name",
        "surname",
        "sex",
        "birth_date",
        "district",
        "farm_place_name",
        "farm_type",
        "crop_type",
        "livestock_type",
        "livestock_count",
        "irrigation",
        "registration_date",
        "last_updated",
    ]
    farm_types = ["Small subsistence-oriented farms", "Market-oriented family farm", "Cooperative farm"]
    crop_types = ["Fruit and nuts", "Cereals", "Vegetables and melons", "Leguminous crops"]
    livestock_types = ["Sheep and goats", "Poultry", "Cattle", "None"]
    farmer_rows: list[list[Any]] = [farmer_header]
    for i in range(1, count + 1):
        district = pick(rng, DISTRICTS, weights=[20, 18, 25, 12, 10, 15])
        registered = daterange(rng, dt.date(2023, 1, 1), dt.date(2026, 3, 31))
        livestock_type = pick(rng, livestock_types, weights=[30, 30, 20, 20])
        farmer_rows.append(
            [
                f"FR-MEMBER-{i:03d}",
                f"FR-FAMILY-{i:03d}",
                f"FAKE-{830000 + i}",
                pick(rng, fake_first),
                pick(rng, fake_last),
                pick(rng, sexes, weights=[49, 49, 2]),
                daterange(rng, dt.date(1945, 1, 1), dt.date(2004, 12, 31)),
                district,
                f"{district} farm plot {i:03d}",
                pick(rng, farm_types, weights=[55, 30, 15]),
                pick(rng, crop_types),
                livestock_type,
                0 if livestock_type == "None" else rng.randint(2, 60),
                pick(rng, [True, False], weights=[45, 55]),
                registered,
                registered + dt.timedelta(days=rng.randint(0, 240)),
            ]
        )

    return {
        "DisabledPeople": rows,
        "CivilPersons": civil_rows,
        "SocialGroups": social_rows,
        "Farmers": farmer_rows,
    }


# ---------------------------------------------------------------------------
# Subject registry
# ---------------------------------------------------------------------------


def build_subject_registry(
    rng: random.Random,
    person_ids: list[str],
    household_for_person: dict[str, str],
    student_ids: list[str],
    guardian_for_student: dict[str, list[str]],
) -> dict[str, list[list[Any]]]:
    sheets: dict[str, list[list[Any]]] = {}

    subjects_header = [
        "canonical_id",
        "benefits_person_alias",
        "benefits_household_alias",
        "education_student_alias",
        "education_guardian_alias",
        "linkage_method",
        "linkage_confidence",
        "linked_on",
        "internal_match_score",
        "match_notes",
    ]
    methods = ["deterministic", "probabilistic", "manual"]
    confidences = ["high", "medium", "low"]

    # Joint (method, confidence) distribution. We weight one cell
    # (manual, low) very low so the by_linkage_method_confidence aggregate
    # has at least one group below min_group_size=5 (needed for the
    # disclosure-control demo to visibly suppress something). Most weight
    # sits on the realistic combinations: deterministic+high dominates,
    # then probabilistic+high and probabilistic+medium.
    method_conf_combos: list[tuple[str, str]] = [
        (m, c) for m in methods for c in confidences
    ]
    method_conf_weights = {
        ("deterministic", "high"): 500,
        ("deterministic", "medium"): 70,
        ("deterministic", "low"): 18,
        ("probabilistic", "high"): 150,
        ("probabilistic", "medium"): 120,
        ("probabilistic", "low"): 30,
        ("manual", "high"): 30,
        ("manual", "medium"): 18,
        ("manual", "low"): 12,
    }
    mc_weight_list = [method_conf_weights[c] for c in method_conf_combos]

    # Build subject rows. Per spec: realistic overlap is approximately one
    # third of benefits persons matched to an education student; the rest
    # appear in one dataset only.
    rows: list[list[Any]] = [subjects_header]

    persons_shuffled = list(person_ids)
    rng.shuffle(persons_shuffled)
    students_shuffled = list(student_ids)
    rng.shuffle(students_shuffled)

    overlap_count = max(1, len(persons_shuffled) // 3)
    overlap_count = min(overlap_count, len(students_shuffled))

    # The registry is not a full enumeration of every person and every
    # student: only a fraction of unmatched subjects are recorded. This
    # keeps the primary sheet within the spec's 50-300 cap and is the
    # more realistic story anyway (not every administrative record gets
    # promoted to the cross-dataset registry).
    benefits_only_sample = persons_shuffled[overlap_count : overlap_count + 90]
    education_only_sample = students_shuffled[overlap_count : overlap_count + 70]

    canonical_counter = 9001
    used_guardians_per_student: dict[str, set[str]] = defaultdict(set)

    # Linked subjects: benefits person + education student aliases for the
    # same human. About a third of those carry a guardian alias too.
    for i in range(overlap_count):
        per_id = persons_shuffled[i]
        stu_id = students_shuffled[i]
        hh_id = household_for_person[per_id]
        guardian_alias: str | None = None
        guardians = guardian_for_student.get(stu_id, [])
        if guardians and rng.random() < 0.4:
            available = [g for g in guardians if g not in used_guardians_per_student[stu_id]]
            if available:
                picked_guardian: str = pick(rng, available)
                guardian_alias = picked_guardian
                used_guardians_per_student[stu_id].add(picked_guardian)
        canonical = f"sub-{canonical_counter}"
        canonical_counter += 1
        method, conf = rng.choices(method_conf_combos, weights=mc_weight_list, k=1)[0]
        linked_on = daterange(rng, dt.date(2024, 1, 1), dt.date(2026, 4, 30))
        score = round(rng.uniform(0.6, 1.0), 4)
        notes = rng.choice(["", "reviewer confirmed", "", "auto-matched"])
        rows.append(
            [
                canonical,
                per_id,
                hh_id,
                stu_id,
                guardian_alias,
                method,
                conf,
                linked_on,
                score,
                notes,
            ]
        )

    # Benefits-only subjects: a sample of unmatched persons.
    for per_id in benefits_only_sample:
        hh_id = household_for_person[per_id]
        # Some of these are recorded as person-only without household alias.
        include_household = rng.random() < 0.7
        canonical = f"sub-{canonical_counter}"
        canonical_counter += 1
        method, conf = rng.choices(method_conf_combos, weights=mc_weight_list, k=1)[0]
        linked_on = daterange(rng, dt.date(2024, 1, 1), dt.date(2026, 4, 30))
        score = round(rng.uniform(0.5, 1.0), 4)
        notes = rng.choice(["", "", "single-dataset record"])
        rows.append(
            [
                canonical,
                per_id,
                hh_id if include_household else None,
                None,
                None,
                method,
                conf,
                linked_on,
                score,
                notes,
            ]
        )

    # Education-only subjects: a sample of unmatched students.
    for stu_id in education_only_sample:
        guardians = guardian_for_student.get(stu_id, [])
        guardian_alias = None
        if guardians and rng.random() < 0.25:
            guardian_alias = pick(rng, guardians)
        canonical = f"sub-{canonical_counter}"
        canonical_counter += 1
        method, conf = rng.choices(method_conf_combos, weights=mc_weight_list, k=1)[0]
        linked_on = daterange(rng, dt.date(2024, 1, 1), dt.date(2026, 4, 30))
        score = round(rng.uniform(0.55, 1.0), 4)
        notes = rng.choice(["", "", "education-only record"])
        rows.append(
            [
                canonical,
                None,
                None,
                stu_id,
                guardian_alias,
                method,
                conf,
                linked_on,
                score,
                notes,
            ]
        )

    sheets["Subjects"] = rows
    return sheets


# ---------------------------------------------------------------------------
# XLSX emission
# ---------------------------------------------------------------------------


_CORE_XML_MODIFIED_RE = re.compile(
    rb"<dcterms:modified[^>]*>[^<]*</dcterms:modified>"
)
_CORE_XML_CREATED_RE = re.compile(
    rb"<dcterms:created[^>]*>[^<]*</dcterms:created>"
)
_FIXED_CORE_MODIFIED = (
    b'<dcterms:modified xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    b'xsi:type="dcterms:W3CDTF">2026-01-01T00:00:00Z</dcterms:modified>'
)
_FIXED_CORE_CREATED = (
    b'<dcterms:created xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    b'xsi:type="dcterms:W3CDTF">2026-01-01T00:00:00Z</dcterms:created>'
)
_FIXED_ZIP_DATE = (1980, 1, 1, 0, 0, 0)


def _canonicalize_xlsx_bytes(raw: bytes) -> bytes:
    """Rewrite a zip archive so every entry uses a fixed date and modified
    times inside core.xml are pinned. Without this, openpyxl save() injects
    the wall-clock time into both the ZIP central directory and the core
    properties, breaking byte-level determinism."""
    src = zipfile.ZipFile(io.BytesIO(raw), "r")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for info in sorted(src.infolist(), key=lambda i: i.filename):
            data = src.read(info.filename)
            if info.filename == "docProps/core.xml":
                data = _CORE_XML_MODIFIED_RE.sub(_FIXED_CORE_MODIFIED, data)
                data = _CORE_XML_CREATED_RE.sub(_FIXED_CORE_CREATED, data)
            new_info = zipfile.ZipInfo(filename=info.filename, date_time=_FIXED_ZIP_DATE)
            new_info.compress_type = zipfile.ZIP_DEFLATED
            new_info.external_attr = info.external_attr
            dst.writestr(new_info, data)
    return buffer.getvalue()


def write_workbook(path: Path, sheets: dict[str, list[list[Any]]], title: str) -> None:
    wb = Workbook()
    # openpyxl resets `modified` on save, but we override the XML after
    # serializing the archive so this is mostly defensive.
    props = DocumentProperties()
    props.creator = "registry-relay-demo-generator"
    props.lastModifiedBy = "registry-relay-demo-generator"
    props.created = FIXED_TIMESTAMP
    props.modified = FIXED_TIMESTAMP
    props.title = title
    wb.properties = props
    default = wb.active
    if default is not None:
        wb.remove(default)
    for sheet_name, rows in sheets.items():
        ws = wb.create_sheet(title=sheet_name)
        for row in rows:
            ws.append(row)

    buffer = io.BytesIO()
    wb.save(buffer)
    canonical = _canonicalize_xlsx_bytes(buffer.getvalue())
    path.write_bytes(canonical)


# ---------------------------------------------------------------------------
# Disclosure-control assertions
# ---------------------------------------------------------------------------


def rows_as_dicts(sheet: list[list[Any]]) -> list[dict[str, Any]]:
    header = sheet[0]
    return [dict(zip(header, r, strict=True)) for r in sheet[1:]]


def assert_disclosure_mix(
    label: str,
    groups: dict[tuple, int],
    min_size: int,
    failures: list[str],
) -> None:
    below = [k for k, n in groups.items() if 0 < n < min_size]
    at_or_above = [k for k, n in groups.items() if n >= min_size]
    if not below:
        failures.append(
            f"{label}: no group below min_group_size={min_size} (all groups would show). "
            f"Group sizes: {sorted(groups.values())}"
        )
    if not at_or_above:
        failures.append(
            f"{label}: no group at or above min_group_size={min_size} (everything would be suppressed). "
            f"Group sizes: {sorted(groups.values())}"
        )


def assert_masked_groups(
    label: str,
    groups: dict[tuple, list[float]],
    min_size: int,
    failures: list[str],
) -> None:
    """A masked measure shows for groups >= min_size (value masked) and is omitted otherwise.

    We need at least one group with count >= min_size so the masked measure is visible.
    """
    visible = [k for k, vals in groups.items() if len(vals) >= min_size]
    if not visible:
        failures.append(
            f"{label}: no group with at least {min_size} observations for masking to apply."
        )


def run_assertions(workbooks: dict[str, dict[str, list[list[Any]]]]) -> None:
    failures: list[str] = []
    summary_lines: list[str] = []

    # -- benefits_casework -----------------------------------------------
    b = workbooks["benefits_casework"]
    households = rows_as_dicts(b["Households"])
    persons = rows_as_dicts(b["Persons"])
    cases = rows_as_dicts(b["Cases"])
    payments = rows_as_dicts(b["Payments"])
    min_b = MIN_GROUP_SIZE["benefits_casework"]

    hh_district = {h["household_id"]: h["district"] for h in households}

    # person.by_district_age_band (joined through household): omit on count.
    g: dict[tuple, int] = Counter()
    for p in persons:
        d = hh_district[p["household_id"]]
        g[(d, p["age_band"])] += 1
    assert_disclosure_mix("benefits.person.by_district_age_band", g, min_b, failures)
    summary_lines.append(f"benefits.person.by_district_age_band: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # case.by_status_priority: omit on count.
    g = Counter()
    for c in cases:
        g[(c["case_status"], c["priority"])] += 1
    assert_disclosure_mix("benefits.case.by_status_priority", g, min_b, failures)
    summary_lines.append(f"benefits.case.by_status_priority: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # payment.by_district_cycle: mask on amount, joined through household.
    g_count: dict[tuple, list[float]] = defaultdict(list)
    for p in payments:
        d = hh_district[p["household_id"]]
        g_count[(d, p["cycle"])].append(float(p["amount"]))
    g_sizes = {k: len(v) for k, v in g_count.items()}
    assert_disclosure_mix("benefits.payment.by_district_cycle (sizes)", g_sizes, min_b, failures)
    assert_masked_groups("benefits.payment.by_district_cycle (masked)", g_count, min_b, failures)
    summary_lines.append(f"benefits.payment.by_district_cycle: {len(g_count)} groups, sizes range {min(g_sizes.values())}..{max(g_sizes.values())}")

    # household.by_poverty_band: omit on count.
    g = Counter()
    for h in households:
        g[(h["district"], h["poverty_band"])] += 1
    assert_disclosure_mix("benefits.household.by_poverty_band", g, min_b, failures)
    summary_lines.append(f"benefits.household.by_poverty_band: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # -- clinic_capacity --------------------------------------------------
    c = workbooks["clinic_capacity"]
    facilities = rows_as_dicts(c["Facilities"])
    service_capacity = rows_as_dicts(c["ServiceCapacity"])
    stock_events = rows_as_dicts(c["StockEvents"])
    min_c = MIN_GROUP_SIZE["clinic_capacity"]
    fac_district = {f["facility_id"]: f["district"] for f in facilities}

    # facility.by_district_type
    g = Counter()
    for f in facilities:
        g[(f["district"], f["facility_type"])] += 1
    assert_disclosure_mix("clinic.facility.by_district_type", g, min_c, failures)
    summary_lines.append(f"clinic.facility.by_district_type: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # service_capacity.by_district_service (sum beds and staff, joined through facility)
    g = Counter()
    for s in service_capacity:
        d = fac_district[s["facility_id"]]
        g[(d, s["service_type"])] += 1
    assert_disclosure_mix("clinic.service_capacity.by_district_service", g, min_c, failures)
    summary_lines.append(f"clinic.service_capacity.by_district_service: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # stock_event.by_medicine_status
    g = Counter()
    for s in stock_events:
        g[(s["medicine_code"], s["stock_status"])] += 1
    assert_disclosure_mix("clinic.stock_event.by_medicine_status", g, min_c, failures)
    summary_lines.append(f"clinic.stock_event.by_medicine_status: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # -- public_works_projects -------------------------------------------
    p = workbooks["public_works_projects"]
    projects = rows_as_dicts(p["Projects"])
    contracts = rows_as_dicts(p["Contracts"])
    milestones = rows_as_dicts(p["Milestones"])
    disbursements = rows_as_dicts(p["Disbursements"])
    min_p = MIN_GROUP_SIZE["public_works_projects"]
    proj_district = {pr["project_id"]: pr["district"] for pr in projects}

    # project.by_sector_status: omit on count.
    g = Counter()
    for pr in projects:
        g[(pr["sector"], pr["project_status"])] += 1
    assert_disclosure_mix("pw.project.by_sector_status", g, min_p, failures)
    summary_lines.append(f"pw.project.by_sector_status: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # contract.by_district_procurement: mask on contract_value, joined through project.
    g_amount: dict[tuple, list[float]] = defaultdict(list)
    for ct in contracts:
        d = proj_district[ct["project_id"]]
        g_amount[(d, ct["procurement_method"])].append(float(ct["contract_value"]))
    g_sizes = {k: len(v) for k, v in g_amount.items()}
    assert_disclosure_mix("pw.contract.by_district_procurement (sizes)", g_sizes, min_p, failures)
    assert_masked_groups("pw.contract.by_district_procurement (masked)", g_amount, min_p, failures)
    summary_lines.append(f"pw.contract.by_district_procurement: {len(g_amount)} groups, sizes range {min(g_sizes.values())}..{max(g_sizes.values())}")

    # milestone.by_status_delay_reason
    g = Counter()
    for m in milestones:
        g[(m["milestone_status"], m["delay_reason"])] += 1
    assert_disclosure_mix("pw.milestone.by_status_delay_reason", g, min_p, failures)
    summary_lines.append(f"pw.milestone.by_status_delay_reason: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # disbursement.by_fiscal_year_quarter: mask on amount.
    g_amount = defaultdict(list)
    for d in disbursements:
        g_amount[(d["fiscal_year"], d["quarter"])].append(float(d["amount"]))
    g_sizes = {k: len(v) for k, v in g_amount.items()}
    assert_disclosure_mix("pw.disbursement.by_fiscal_year_quarter (sizes)", g_sizes, min_p, failures)
    assert_masked_groups("pw.disbursement.by_fiscal_year_quarter (masked)", g_amount, min_p, failures)
    summary_lines.append(f"pw.disbursement.by_fiscal_year_quarter: {len(g_amount)} groups, sizes range {min(g_sizes.values())}..{max(g_sizes.values())}")

    # -- education_registry ---------------------------------------------
    e = workbooks["education_registry"]
    students = rows_as_dicts(e["Students"])
    schools = rows_as_dicts(e["Schools"])
    support_needs = rows_as_dicts(e["SupportNeeds"])
    attendance = rows_as_dicts(e["AttendanceSummary"])
    min_e = MIN_GROUP_SIZE["education_registry"]
    stu_district = {s["student_id"]: s["home_district"] for s in students}
    stu_school = {s["student_id"]: s["school_id"] for s in students}

    # student.by_school_grade_status: omit on count.
    g = Counter()
    for s in students:
        g[(s["school_id"], s["grade_level"], s["enrollment_status"])] += 1
    assert_disclosure_mix("edu.student.by_school_grade_status", g, min_e, failures)
    summary_lines.append(f"edu.student.by_school_grade_status: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # student.by_district_language
    g = Counter()
    for s in students:
        g[(s["home_district"], s["language_group"])] += 1
    assert_disclosure_mix("edu.student.by_district_language", g, min_e, failures)
    summary_lines.append(f"edu.student.by_district_language: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # support_need.by_type_district (joined through student): omit on count.
    g = Counter()
    for sn in support_needs:
        g[(sn["support_type"], stu_district[sn["student_id"]])] += 1
    assert_disclosure_mix("edu.support_need.by_type_district", g, min_e, failures)
    summary_lines.append(f"edu.support_need.by_type_district: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # attendance_summary.by_school_term: mask on attendance_rate.
    g_rate: dict[tuple, list[float]] = defaultdict(list)
    for a in attendance:
        sid = a["student_id"]
        g_rate[(stu_school[sid], a["term"])].append(float(a["attendance_rate"]))
    g_sizes = {k: len(v) for k, v in g_rate.items()}
    assert_disclosure_mix("edu.attendance_summary.by_school_term (sizes)", g_sizes, min_e, failures)
    assert_masked_groups("edu.attendance_summary.by_school_term (masked)", g_rate, min_e, failures)
    summary_lines.append(f"edu.attendance_summary.by_school_term: {len(g_rate)} groups, sizes range {min(g_sizes.values())}..{max(g_sizes.values())}")

    # school.by_district_meal_program
    g = Counter()
    for s in schools:
        g[(s["district"], s["has_meal_program"])] += 1
    assert_disclosure_mix("edu.school.by_district_meal_program", g, min_e, failures)
    summary_lines.append(f"edu.school.by_district_meal_program: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    # -- subject_registry -----------------------------------------------
    sr = workbooks["subject_registry"]
    subjects = rows_as_dicts(sr["Subjects"])
    min_s = MIN_GROUP_SIZE["subject_registry"]

    # subject.by_linkage_method_confidence
    g = Counter()
    for s in subjects:
        g[(s["linkage_method"], s["linkage_confidence"])] += 1
    assert_disclosure_mix("subject.by_linkage_method_confidence", g, min_s, failures)
    summary_lines.append(f"subject.by_linkage_method_confidence: {len(g)} groups, sizes range {min(g.values())}..{max(g.values())}")

    if failures:
        print("DISCLOSURE CONTROL CHECK FAILED:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        sys.exit(1)

    print("Disclosure-control assertions: OK")
    for line in summary_lines:
        print(f"  {line}")


# ---------------------------------------------------------------------------
# Alias-resolution check
# ---------------------------------------------------------------------------


def check_alias_resolution(workbooks: dict[str, dict[str, list[list[Any]]]]) -> None:
    failures: list[str] = []
    person_ids = {r[0] for r in workbooks["benefits_casework"]["Persons"][1:]}
    household_ids = {r[0] for r in workbooks["benefits_casework"]["Households"][1:]}
    student_ids = {r[0] for r in workbooks["education_registry"]["Students"][1:]}
    guardian_ids = {r[0] for r in workbooks["education_registry"]["Guardians"][1:]}
    school_ids = {r[0] for r in workbooks["education_registry"]["Schools"][1:]}
    facility_ids = {r[0] for r in workbooks["clinic_capacity"]["Facilities"][1:]}

    subjects = rows_as_dicts(workbooks["subject_registry"]["Subjects"])
    for s in subjects:
        if s["benefits_person_alias"] is not None and s["benefits_person_alias"] not in person_ids:
            failures.append(f"unknown benefits_person_alias {s['benefits_person_alias']}")
        if s["benefits_household_alias"] is not None and s["benefits_household_alias"] not in household_ids:
            failures.append(f"unknown benefits_household_alias {s['benefits_household_alias']}")
        if s["education_student_alias"] is not None and s["education_student_alias"] not in student_ids:
            failures.append(f"unknown education_student_alias {s['education_student_alias']}")
        if s["education_guardian_alias"] is not None and s["education_guardian_alias"] not in guardian_ids:
            failures.append(f"unknown education_guardian_alias {s['education_guardian_alias']}")

    # asset_ref pointers from public works that target schools or facilities.
    proj_rows = rows_as_dicts(workbooks["public_works_projects"]["Projects"])
    school_refs = [p for p in proj_rows if p["asset_type"] == "school"]
    facility_refs = [p for p in proj_rows if p["asset_type"] == "facility"]
    if not any(p["asset_ref"] in school_ids for p in school_refs):
        failures.append("no public works school project resolves to a real school_id")
    if not any(p["asset_ref"] in facility_ids for p in facility_refs):
        failures.append("no public works facility project resolves to a real facility_id")

    if failures:
        print("ALIAS RESOLUTION CHECK FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        sys.exit(1)
    print("Alias resolution check: OK")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    rng = random.Random(SEED)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Decide row counts up front. All within 50..300 per primary sheet.
    n_households = 110
    n_facilities = 90
    n_projects = 110
    n_schools = 60
    n_students = 240

    # ID pools.
    household_ids = make_ids("hh", 1001, n_households)
    facility_ids = make_ids("fac", 4001, n_facilities)
    project_ids = make_ids("prj", 5001, n_projects)
    school_ids = make_ids("sch", 3001, n_schools)
    student_ids = make_ids("stu", 2001, n_students)

    # Persons per household: 1-6, biased toward 2-4. Total stays < 300 cap? No,
    # persons is not a "primary sheet" per spec; primary sheets are
    # households, facilities, projects, students, subjects. Persons can exceed.
    person_id_counter = 2001
    person_ids_by_household: dict[str, list[str]] = {}
    household_for_person: dict[str, str] = {}
    all_person_ids: list[str] = []
    for hh_id in household_ids:
        n_persons = rng.choices([1, 2, 3, 4, 5, 6], weights=[10, 30, 30, 20, 7, 3], k=1)[0]
        persons: list[str] = []
        for _ in range(n_persons):
            pid = f"per-{person_id_counter}"
            person_id_counter += 1
            persons.append(pid)
            household_for_person[pid] = hh_id
            all_person_ids.append(pid)
        person_ids_by_household[hh_id] = persons

    # Guardians per student: 0-3, mostly 1-2.
    guardian_id_counter = 2501
    guardian_ids_by_student: dict[str, list[str]] = {}
    for sid in student_ids:
        n_g = rng.choices([0, 1, 2, 3], weights=[5, 60, 30, 5], k=1)[0]
        guardians: list[str] = []
        for _ in range(n_g):
            gid = f"gua-{guardian_id_counter}"
            guardian_id_counter += 1
            guardians.append(gid)
        guardian_ids_by_student[sid] = guardians

    # Build each dataset. District maps from benefits/clinic/education are not
    # consumed downstream right now; the cross-dataset alias coordination is
    # handled via the person/household/student id pools instead.
    benefits_sheets, _ = build_benefits(rng, household_ids, person_ids_by_household)
    clinic_sheets, _ = build_clinics(rng, facility_ids)
    pw_sheets = build_public_works(rng, project_ids, school_ids, facility_ids)
    edu_sheets, _ = build_education(rng, student_ids, school_ids, guardian_ids_by_student)
    sub_sheets = build_subject_registry(
        rng,
        all_person_ids,
        household_for_person,
        student_ids,
        guardian_ids_by_student,
    )
    dr_sheets = build_disability_registry(rng, count=80)

    workbooks = {
        "benefits_casework": benefits_sheets,
        "clinic_capacity": clinic_sheets,
        "public_works_projects": pw_sheets,
        "education_registry": edu_sheets,
        "subject_registry": sub_sheets,
        "disability_registry": dr_sheets,
    }

    # Run distribution and alias checks before writing files. Cheap insurance
    # so a broken seed doesn't ship a broken workbook.
    check_alias_resolution(workbooks)
    run_assertions(workbooks)

    # Write workbooks.
    output_paths: dict[str, Path] = {}
    for name, sheets in workbooks.items():
        path = DATA_DIR / f"{name}.xlsx"
        write_workbook(path, sheets, title=name)
        output_paths[name] = path

    # Determinism self-check. The seeded RNG above plus deterministic
    # writer (sorted zip entries, fixed timestamps, canonicalized core
    # properties) means that writing the same in-memory sheet data twice
    # must produce byte-identical output. If it doesn't, ordering has
    # snuck in somewhere and re-running the script would not be byte-stable.
    for name, sheets in workbooks.items():
        first = output_paths[name].read_bytes()
        tmp = output_paths[name].with_suffix(".xlsx.tmp")
        write_workbook(tmp, sheets, title=name)
        second = tmp.read_bytes()
        tmp.unlink()
        if first != second:
            print("DETERMINISM CHECK FAILED: writing a workbook twice produced different bytes", file=sys.stderr)
            sys.exit(1)
    print("Determinism self-check: OK")

    # Report row counts.
    print("\nWorkbooks written:")
    primary_sheet_for = {
        "benefits_casework": "Households",
        "clinic_capacity": "Facilities",
        "public_works_projects": "Projects",
        "education_registry": "Students",
        "subject_registry": "Subjects",
        "disability_registry": "DisabledPeople",
    }
    for name, path in output_paths.items():
        ps = primary_sheet_for[name]
        n = len(workbooks[name][ps]) - 1
        digest = sha256_of(path)
        print(f"  {path.relative_to(REPO_ROOT)}  primary={ps}  rows={n}  sha256={digest}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
