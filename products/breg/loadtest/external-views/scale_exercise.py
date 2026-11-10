#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Scale corpus, independent oracle and native HTTP acceptance driver."""

from hashlib import sha256
import json
import os
import platform
import re
import shutil
import subprocess
import time
from urllib.parse import unquote, urlsplit

import fixture_path  # noqa: F401
from journey import JourneyError, expect, fixture_credential, records, request
from synthetic_source import Fixture, digest, require

ELIGIBLE_ROOTS = 1_000_000
DENIED_ROOTS = 100_000
HOLDER_KEYS = 50_000
ABSENT_KEYS = 2_500
MATCH_KEYS = frozenset((5, 12, 134, 1027, 7132, 19007, 43821))
REFRESH_PAGE_SIZE = 100
BATCH_KEYS = 64
PERSON_REQUEST_BUDGET = 1_100
RELATED_REQUEST_BUDGET = 6
RELATED_PAGE_ROWS = 40
RELATED_ROWS = 120
FRESHNESS_SECONDS = 600
QUERY_SECONDS = 5
READ_PAGE_SIZE = 50
MAX_PLAN_BYTES = 16 * 1024 * 1024
PERSON_VIEW = "/v1/external-views/licence-holder-indexed/holder"
HOLDINGS_VIEW = "/v1/external-views/business-holdings-indexed/holdings"


def root_id(index, business=False):
    family = "4001" if business else "4000"
    return f"00000000-0000-{family}-8000-{index:012x}"


def key_for_root(index):
    return (index - 1) % HOLDER_KEYS + 1


def person_fields(key):
    if key % 20 == 0:
        return None
    surname = "Cohort" if key in MATCH_KEYS else f"Family-{key % 1024:04d}"
    return {"family-name": surname, "given-name": f"Given-{key:06d}"}


def exact_oracle(surname):
    matches = {
        key for key in range(1, HOLDER_KEYS + 1)
        if (person_fields(key) or {}).get("family-name") == surname
    }
    return [root_id(i) for i in range(1, ELIGIBLE_ROOTS + 1) if key_for_root(i) in matches]


def ordered_oracle(descending=False, roots=ELIGIBLE_ROOTS, limit=None):
    groups = {}
    for key in range(1, HOLDER_KEYS + 1):
        surname = (person_fields(key) or {}).get("family-name")
        groups.setdefault(surname, set()).add(key)
    surnames = sorted((name for name in groups if name is not None), reverse=descending)
    ordered = []
    for surname in [*surnames, None]:
        keys = sorted(groups[surname])
        for offset in range(0, roots, HOLDER_KEYS):
            for key in keys:
                if offset + key > roots:
                    break
                ordered.append(root_id(offset + key))
                if limit is not None and len(ordered) == limit:
                    return ordered
    return ordered


def holding_oracle(parent, selected_class=None):
    values = range((parent - 1) * RELATED_ROWS + 1, parent * RELATED_ROWS + 1)
    return [count for count in values if selected_class is None or holding_class(count) == selected_class]


def holding_class(count):
    return "common" if count % 2 == 0 else "preferred"


class ScaleFixture(Fixture):
    def _reset(self):
        super()._reset()
        self._seen_people = set()
        self._collection_calls = {}
        self._largest_batch = 0
        self._denied_selectors = 0
        self._collections = {}
        for parent in range(1, 5):
            key = f"scale-business-{parent}"
            items = []
            for count in holding_oracle(parent):
                props = {"share-class": holding_class(count), "share-count": count,
                         "shareholder-type": "business", "shareholder-key": f"shareholder-{count}",
                         "person-key": None}
                items.append({"holding": f"holding-{count}", "business": key,
                              "revision": digest(props), "properties": props})
            self._collections[key] = (digest([key, items]), items)

    def _one_person(self, key, fields):
        match = re.fullmatch(r"scale-person-([0-9]{6})", key) if isinstance(key, str) else None
        if not match or not 1 <= int(match[1]) <= HOLDER_KEYS + 1:
            self._denied_selectors += 1
            require(False, "selector outside the approved scale scope", 403)
        number = int(match[1])
        self._seen_people.add(number)
        data = person_fields(number)
        if data is None:
            return {"subject": key, "state": "confirmed-absent"}
        return {"subject": key, "state": "found", "revision": digest(data),
                "properties": {field: data[field] for field in fields}}

    def _page(self, parent, cursor, fields):
        if parent not in ("scale-business-1", "scale-business-2"):
            self._denied_selectors += 1
            require(False, "parent outside the approved scale scope", 403)
        self._collection_calls[parent] = self._collection_calls.get(parent, 0) + 1
        snapshot, rows = self._collections[parent]
        offset = 0
        if cursor is not None:
            match = re.fullmatch(r"([0-9a-f]{64}):([0-9]{1,3})", cursor) if isinstance(cursor, str) else None
            require(match and match[1] == snapshot, "invalid scale continuation")
            offset = int(match[2])
            require(offset in range(RELATED_PAGE_ROWS, len(rows), RELATED_PAGE_ROWS))
        end = min(offset + RELATED_PAGE_ROWS, len(rows))
        items = [{**row, "properties": {field: row["properties"][field] for field in fields}}
                 for row in rows[offset:end]]
        return {"state": "snapshot", "business": parent, "snapshotId": snapshot,
                "finished": end == len(rows), "next": None if end == len(rows) else f"{snapshot}:{end}",
                "items": items}

    def acquire(self, operation, body):
        result = super().acquire(operation, body)
        if operation == "person-batch":
            with self._lock:
                self._largest_batch = max(self._largest_batch, len(body["keys"]))
        return result

    def status(self):
        with self._lock:
            return {**super().status(), "uniquePersonKeys": len(self._seen_people),
                    "largestBatch": self._largest_batch, "deniedSelectors": self._denied_selectors,
                    "collections": dict(self._collection_calls)}


def scale_project(project, work):
    target = work / "scale-project"
    (target / "tests").mkdir(parents=True)
    authored = (project / "registry.yaml").read_text()
    expect(authored.count("cacheTtlSeconds: 300") == 2, "the fixture TTL declarations changed")
    (target / "registry.yaml").write_text(
        authored.replace("cacheTtlSeconds: 300", f"cacheTtlSeconds: {FRESHNESS_SECONDS}")
    )
    shutil.copyfile(project / "tests/journeys.yaml", target / "tests/journeys.yaml")
    return target


def quoted(identifier):
    expect(re.fullmatch(r"breg_[a-z0-9_]{1,58}", identifier), "the candidate physical-name inventory changed")
    return f'"{identifier}"'


def seed_sql(inventory):
    licence = inventory["entities"]["licence"]
    business = inventory["entities"]["licensed-business"]

    def target(entity, selector):
        table = "registry_data." + quoted(entity["table"])
        columns = ",".join(quoted(entity["fields"][name]) for name in ("licence-number", selector, "jurisdiction"))
        return table, columns

    licences, licence_columns = target(licence, "holder-key")
    businesses, business_columns = target(business, "business-key")
    return f"""
BEGIN;
SET LOCAL statement_timeout='180s';
SELECT set_config('registry.principal','synthetic-licensing-editor',true),
       set_config('registry.access_profile','fixture-editor',true),
       set_config('registry.purpose','licensing',true),
       set_config('registry.row_boundaries','[]',true),
       set_config('registry.recipients','[]',true),
       set_config('registry.active_package_revision',
          (SELECT active_activation_id::text FROM registry_internal.registry_state WHERE singleton),true);
DO $fixture$ BEGIN
  IF EXISTS (SELECT 1 FROM {licences}) OR EXISTS (SELECT 1 FROM {businesses}) THEN
    RAISE EXCEPTION 'scale fixture tables must be empty';
  END IF;
END; $fixture$;
INSERT INTO {licences} (record_id,{licence_columns})
SELECT ('00000000-0000-4000-8000-'||lpad(to_hex(i),12,'0'))::uuid, 'L-scale-'||i,
       CASE WHEN i<={ELIGIBLE_ROOTS} THEN 'scale-person-'||lpad((((i-1)%{HOLDER_KEYS})+1)::text,6,'0')
            ELSE 'scale-denied-'||lpad((i-{ELIGIBLE_ROOTS})::text,6,'0') END,
       CASE WHEN i<={ELIGIBLE_ROOTS} THEN 'zone-a' ELSE 'zone-b' END
FROM generate_series(1, {ELIGIBLE_ROOTS + DENIED_ROOTS}) AS i;
INSERT INTO {businesses} (record_id,{business_columns})
SELECT ('00000000-0000-4001-8000-'||lpad(to_hex(i),12,'0'))::uuid,
       'B-scale-'||i,'scale-business-'||i,CASE WHEN i<=2 THEN 'zone-a' ELSE 'zone-b' END
FROM generate_series(1,4) AS i;
ANALYZE {licences};
ANALYZE {businesses};
COMMIT;
"""


def postgres(work, url_name, sql, name):
    target = urlsplit((work / "secrets" / url_name).read_text())
    env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    env.update(PGHOST=target.hostname, PGPORT=str(target.port), PGUSER=unquote(target.username),
               PGDATABASE=target.path[1:], PGSSLMODE="verify-full",
               PGSSLROOTCERT=str(work / "secrets/postgres-ca"), PGCONNECT_TIMEOUT="5", PGPASSFILE="/dev/null")
    if target.password is not None:
        env["PGPASSWORD"] = unquote(target.password)
    with (work / f"{name}.stderr").open("xb") as stderr:
        result = subprocess.run(["psql", "-XqwAt", "-v", "ON_ERROR_STOP=1"], input=sql, text=True,
                                env=env, stderr=stderr, stdout=subprocess.PIPE, timeout=185, check=False)
    expect(result.returncode == 0, f"{name} failed. See the owner-only PostgreSQL log.")
    return result.stdout


def native_plans(log, database, role):
    prefix = f"{database} {role} "
    return [entry for entry in log.split("[breg-plan] ") if entry.startswith(prefix)
            and "Query Text: WITH projection_state AS MATERIALIZED" in entry
            and "CTE coverage" in entry and "CTE page" in entry and "Buffers:" in entry]


def capture_plans(path, start, database, role, work):
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        expect(info.st_ino == start.st_ino and info.st_size >= start.st_size,
               "the PostgreSQL plan log rotated during the fixture")
        stream.seek(start.st_size)
        data = stream.read(MAX_PLAN_BYTES + 1)
    expect(len(data) <= MAX_PLAN_BYTES, "the plan log slice exceeded the fixture limit")
    entries = native_plans(data.decode("utf-8", errors="replace"), database, role)
    if entries:
        with (work / "scale-native-plans.log").open("x") as output:
            output.write("".join("[breg-plan] " + entry for entry in entries))
    return len(entries)


def refresh(origin, path, headers, measurements, start, page_budget):
    query = {"accessProfile": "projection-refresh", "$top": str(REFRESH_PAGE_SIZE)}
    cursor = None
    for _ in range(page_budget):
        expect(time.monotonic() - start < FRESHNESS_SECONDS, "refresh exceeded the freshness window")
        if cursor:
            query = {"accessProfile": "projection-refresh", "$skiptoken": cursor}
        status, doc = request(origin, path + "/refresh", headers, method="POST", query=query)
        expect(status == 200 and isinstance(doc, dict), "a native refresh failed")
        measurements["httpRequests"] += 1
        for field in ("processed", "published", "reused", "unavailable"):
            value = doc.get(field)
            expect(type(value) is int and value >= 0, "the refresh returned an invalid count")
            measurements[field] += value
        if measurements["httpRequests"] % 1_000 == 0:
            print(f"Native refresh processed {measurements['processed']:,} roots", flush=True)
        previous, cursor = cursor, doc.get("nextCursor")
        if cursor is None:
            return
        expect(isinstance(cursor, str) and cursor != previous, "native refresh repeated its cursor")
    expect(False, "native refresh exceeded its predeclared page budget")


def observe(origin, path, query, headers, timings, name):
    started = time.monotonic()
    result = request(origin, path, headers, query={"accessProfile": "officer", **query})
    elapsed = time.monotonic() - started
    timings.append({"operation": name, "status": result[0], "wallSeconds": round(elapsed, 6)})
    expect(elapsed <= QUERY_SECONDS, f"{name} exceeded its HTTP response target")
    return result


def person_page(response, expected):
    rows = records(response)
    expect([row["rootId"] for row in rows] == expected, "native Person page differed from the local-id oracle")
    for row in rows:
        index = int(row["rootId"][-12:], 16)
        fields = person_fields(key_for_root(index))
        expect(row["fields"] == (fields or {}) and row["availability"] == ("available" if fields else "absent"),
               "native Person value or absence differed from the fixture oracle")
    return response[1]


def holding_page(response, expected):
    rows = records(response)
    expect([row["fields"]["share-count"] for row in rows] == expected,
           "native holding filter or ordering differed from the independent oracle")
    for row, count in zip(rows, expected):
        expect(row["fields"]["share-class"] == holding_class(count) and row.get("label") is None,
               "native holding class or company label differed from the fixture")
        expect(isinstance(row.get("rowId"), str) and row["rowId"], "a holding row lacked its stable identity")
    return response[1]


def sweep_counts():
    return dict.fromkeys(("httpRequests", "processed", "published", "reused", "unavailable"), 0)


def file_digest(path):
    digestor = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digestor.update(chunk)
    return digestor.hexdigest()


def run_scale(work, package, origin, tokens, source, plan_log, binaries):
    report = {
        "passed": False, "environment": {"host": platform.platform(), "cpuCount": os.cpu_count()},
        "candidateBinarySha256": {
            name: file_digest(binary) for name, binary in binaries.items()
        },
        "corpus": {"eligibleRoots": ELIGIBLE_ROOTS, "deniedRoots": DENIED_ROOTS,
                   "distinctHolderKeys": HOLDER_KEYS, "authorizedAbsentKeys": ABSENT_KEYS,
                   "authorizedRelatedRows": RELATED_ROWS * 2, "deniedRelatedRows": RELATED_ROWS * 2},
        "budgets": {"freshnessSeconds": FRESHNESS_SECONDS,
                    "querySeconds": QUERY_SECONDS, "personSourceRequests": PERSON_REQUEST_BUDGET,
                    "relatedSourceRequests": RELATED_REQUEST_BUDGET, "adapterBatchKeys": BATCH_KEYS},
        "personRefresh": sweep_counts(), "holdingsRefresh": sweep_counts(), "queries": [],
        "seeding": "Migration role inserted only fixture-owned base rows under fixture-editor RLS. No projection cache or revision history was fabricated.",
    }
    started = None
    log_start = None
    try:
        runtime_url = urlsplit((work / "secrets/runtime-url").read_text())
        database, role = runtime_url.path[1:], unquote(runtime_url.username)
        environment = postgres(work, "runtime-url", """
SELECT jsonb_build_object('version',current_setting('server_version'),
       'workMem',current_setting('work_mem'),'statementTimeout',current_setting('statement_timeout'),
       'planLogging',current_setting('auto_explain.log_analyze',true));
""", "scale-environment")
        report["environment"]["postgres"] = json.loads(environment)
        expect(report["environment"]["postgres"]["version"].split(".", 1)[0] == "18"
               and report["environment"]["postgres"]["workMem"] == "64MB"
               and report["environment"]["postgres"]["statementTimeout"] == "10s",
               "runtime work_mem and statement_timeout do not match the predeclared environment")
        report["packageInventorySha256"] = sha256((package / "inventories/physical-names.json").read_bytes()).hexdigest()
        report["packDigest"] = json.loads((work / "runtime.json").read_text())["externalSources"][0]["packDigest"]
        names = json.loads((package / "inventories/physical-names.json").read_text())
        print("Loading the scale corpus into its fixture-owned PostgreSQL tables", flush=True)
        seeded_at = time.monotonic()
        postgres(work, "migration-url", seed_sql(names), "scale-seed")
        report["seedSeconds"] = round(time.monotonic() - seeded_at, 6)
        officer = {"Authorization": "Bearer " + fixture_credential(tokens["officer"])}
        refresh_actor = {"Authorization": "Bearer " + fixture_credential(tokens["licensing-refresh"])}
        editor = {"Authorization": "Bearer " + fixture_credential(tokens["fixture-editor"])}
        exact = exact_oracle("Cohort")
        absent = exact_oracle(None)
        ascending = ordered_oracle(limit=2 * READ_PAGE_SIZE)
        descending = ordered_oracle(descending=True, limit=2 * READ_PAGE_SIZE)

        print("Refreshing indexed projections through the candidate HTTP service", flush=True)
        started = time.monotonic()
        refresh(origin, PERSON_VIEW, refresh_actor, report["personRefresh"], started, ELIGIBLE_ROOTS // REFRESH_PAGE_SIZE)
        refresh(origin, HOLDINGS_VIEW, refresh_actor, report["holdingsRefresh"], started, 1)
        report["refreshSeconds"] = round(time.monotonic() - started, 6)
        before = source.status()
        report["sourceAtEndOfRefresh"] = before
        expect(report["personRefresh"]["processed"] == ELIGIBLE_ROOTS
               and report["personRefresh"]["published"] == HOLDER_KEYS
               and report["personRefresh"]["unavailable"] == 0
               and report["personRefresh"]["reused"] == ELIGIBLE_ROOTS - HOLDER_KEYS
               and before["uniquePersonKeys"] == HOLDER_KEYS and before["largestBatch"] == BATCH_KEYS
               and before["operations"].get("person-batch", 0) <= PERSON_REQUEST_BUDGET,
               "Person refresh did not meet the predeclared population or source budget")
        expect(report["holdingsRefresh"]["processed"] == 2 and report["holdingsRefresh"]["published"] == 2
               and report["holdingsRefresh"]["unavailable"] == 0
               and before["collections"] == {"scale-business-1": 3, "scale-business-2": 3}
               and before["operations"].get("holdings-by-business", 0) == RELATED_REQUEST_BUDGET
               and before["deniedSelectors"] == 0 and before["operations"].get("person-exact", 0) == 0,
               "related refresh crossed its parent or request boundary")

        log_start = plan_log.stat()
        timing = report["queries"]
        print("Checking native indexed queries against the independent oracle", flush=True)
        initial = {"$filter": "family-name eq 'Cohort'", "$orderby": "family-name",
                   "$count": "true", "$top": str(READ_PAGE_SIZE)}
        for _ in range(3):
            document = person_page(observe(origin, PERSON_VIEW + "/records", initial, officer, timing, "exact-first"),
                                   exact[:READ_PAGE_SIZE])
            expect(document.get("count") == len(exact), "native surname count differed from the oracle")
        for offset in range(READ_PAGE_SIZE, len(exact), READ_PAGE_SIZE):
            document = person_page(observe(origin, PERSON_VIEW + "/records", {"$skiptoken": document["nextCursor"]},
                                           officer, timing, "exact-continuation"),
                                   exact[offset:offset + READ_PAGE_SIZE])
        expect("nextCursor" not in document, "native surname results have additional rows")
        for direction, expected in (("asc", ascending), ("desc", descending)):
            query = {"$orderby": f"family-name {direction}", "$top": str(READ_PAGE_SIZE), "$count": "true"}
            document = person_page(observe(origin, PERSON_VIEW + "/records", query, officer, timing, "ordered-first"),
                                   expected[:READ_PAGE_SIZE])
            expect(document.get("count") == ELIGIBLE_ROOTS, "the native root count included denied roots")
            person_page(observe(origin, PERSON_VIEW + "/records", {"$skiptoken": document["nextCursor"]},
                                officer, timing, "ordered-continuation"), expected[READ_PAGE_SIZE:])
        document = person_page(observe(origin, PERSON_VIEW + "/records", {
            "$filter": "family-name eq null", "$orderby": "family-name desc",
            "$top": str(READ_PAGE_SIZE), "$count": "true",
        }, officer, timing, "missing-sort-first"), absent[:READ_PAGE_SIZE])
        expect(document.get("count") == len(absent), "authorized missing-value count differed from the oracle")
        person_page(observe(origin, PERSON_VIEW + "/records", {"$skiptoken": document["nextCursor"]},
                            officer, timing, "missing-sort-continuation"), absent[READ_PAGE_SIZE:2 * READ_PAGE_SIZE])

        for parent in (1, 2):
            path = HOLDINGS_VIEW + "/records/" + root_id(parent, business=True)
            all_counts = holding_oracle(parent)
            related_query = {"$orderby": "share-count asc", "$count": "true", "$top": str(READ_PAGE_SIZE)}
            row_ids = []
            for offset in range(0, len(all_counts), READ_PAGE_SIZE):
                response = observe(origin, path, related_query, officer, timing, "related-snapshot")
                document = holding_page(response, all_counts[offset:offset + READ_PAGE_SIZE])
                row_ids.extend(row["rowId"] for row in document["records"])
                if offset == 0:
                    expect(document.get("count") == len(all_counts), "complete related count differed from the oracle")
                if offset + READ_PAGE_SIZE < len(all_counts):
                    related_query = {"$skiptoken": document["nextCursor"]}
            expect("nextCursor" not in document and len(set(row_ids)) == len(all_counts),
                   "complete related pages repeated or omitted stable row identities")
            expected = list(reversed(holding_oracle(parent, "common")))
            document = holding_page(observe(origin, path, {"$filter": "share-class eq 'common'",
                                                           "$orderby": "share-count desc", "$count": "true",
                                                           "$top": str(READ_PAGE_SIZE)}, officer, timing, "related-first"),
                                    expected[:READ_PAGE_SIZE])
            expect(document.get("count") == len(expected), "related count differed from the parent oracle")
            holding_page(observe(origin, path, {"$skiptoken": document["nextCursor"]}, officer, timing,
                                 "related-continuation"), expected[READ_PAGE_SIZE:])
        for parent in (3, 4):
            expect(observe(origin, HOLDINGS_VIEW + "/records/" + root_id(parent, business=True), {},
                           officer, timing, "denied-parent")[0] == 404, "denied collection was disclosed")

        status, _ = request(origin, "/v1/records/licences", {**editor, "Idempotency-Key": "external-scale-deficit"},
                            method="POST", query={"accessProfile": "fixture-editor"}, body={"data": {
                                "licenceNumber": "L-scale-deficit", "holderKey": f"scale-person-{HOLDER_KEYS + 1:06}",
                                "jurisdiction": "zone-a",
                            }})
        expect(status == 201, "the native fixture could not insert the uncovered root")
        expect(observe(origin, PERSON_VIEW + "/records", initial, officer, timing, "coverage-deficit")
               == (503, {"status": "incomplete"}), "the native predicate masked missing coverage")
        expect(source.status() == before, "indexed or concealed reads contacted the upstream source")
        expect(time.monotonic() - started < FRESHNESS_SECONDS, "indexed verification exceeded the freshness window")
        report["nativePlans"] = capture_plans(plan_log, log_start, database, role, work)
        expect(report["nativePlans"] >= 3, "the plan log lacks native coverage and page plans with buffers")
        report["passed"] = True
    except JourneyError as error:
        report["failure"] = str(error)
        raise
    finally:
        if log_start is not None and "nativePlans" not in report:
            try:
                report["nativePlans"] = capture_plans(plan_log, log_start, database, role, work)
            except (JourneyError, OSError):
                report["nativePlans"] = None
        report["sourceFinal"] = source.status()
        if started is not None:
            report["elapsedFromRefreshSeconds"] = round(time.monotonic() - started, 6)
        with (work / "scale-report.json").open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
