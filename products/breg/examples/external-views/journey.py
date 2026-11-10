#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check the projection journey against a fresh synthetic BReg deployment."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import time
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID


class JourneyError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


HTTP = build_opener(ProxyHandler({}), NoRedirect())


def expect(condition, name):
    if not condition:
        raise JourneyError(name)


def origin(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
        or parsed.port is None or parsed.username is not None
        or parsed.path not in ("", "/") or parsed.query or parsed.fragment
    ):
        raise argparse.ArgumentTypeError("use an explicit numeric loopback HTTP origin")
    return value.rstrip("/")


def fixture_credential(path):
    with path.open("rb") as stream:
        value = stream.read(16_385).strip()
    expect(0 < len(value) <= 16_384 and all(33 <= byte <= 126 for byte in value),
           "a fixture credential file has an invalid shape")
    return value.decode("ascii")


def request(base, path, headers, method="GET", query=None, body=None):
    url = base + path + (("?" + urlencode(query)) if query else "")
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers = {**headers, "Content-Type": "application/json"}
    target = Request(url, headers=headers, data=data, method=method)
    try:
        response = HTTP.open(target, timeout=15)
    except HTTPError as error:
        response = error
    except URLError as error:
        raise JourneyError("a loopback fixture service could not be reached") from error
    with response:
        payload = response.read(1_048_577)
        expect(len(payload) <= 1_048_576, "fixture response exceeded its byte limit")
        try:
            document = json.loads(payload) if payload else None
        except (UnicodeError, json.JSONDecodeError) as error:
            raise JourneyError("fixture response was not JSON") from error
        return response.status, document


class Journey:
    def __init__(self, args):
        self.args = args
        self.auth = {
            "officer": {"Authorization": "Bearer " + fixture_credential(args.officer_token_file)},
            "local-facts": {"Authorization": "Bearer " + fixture_credential(args.restricted_token_file)},
            "projection-refresh": {"Authorization": "Bearer " + fixture_credential(args.refresh_token_file)},
        }
        self.control_auth = {"x-fixture-control-key": fixture_credential(args.control_key_file)}

    def view(self, view, link, root=None, profile="officer", query=None):
        path = f"/v1/external-views/{view}/{link}/records"
        if root is not None:
            path += f"/{root}"
        return request(self.args.breg_origin, path, self.auth[profile],
                       query={"accessProfile": profile, **(query or {})})

    def refresh(self, view, link, *, labels=False):
        operation = "refresh-labels" if labels else "refresh"
        path = f"/v1/external-views/{view}/{link}/{operation}"
        query = {"accessProfile": "projection-refresh"}
        totals = {field: 0 for field in ("processed", "published", "unavailable")}
        seen = set()
        for _ in range(20):
            status, report = request(
                self.args.breg_origin, path, self.auth["projection-refresh"],
                method="POST", query=query,
            )
            expect(status == 200 and isinstance(report, dict), "a refresh request failed")
            for field in totals:
                count = report.get(field)
                expect(type(count) is int and count >= 0, "refresh returned an invalid count")
                totals[field] += count
            cursor = report.get("nextCursor")
            if cursor is None:
                return totals
            expect(isinstance(cursor, str) and cursor not in seen, "refresh cursor repeated")
            seen.add(cursor)
            query["$skiptoken"] = cursor
        raise JourneyError("refresh exceeded the fixture's page budget")

    def control(self, action, **options):
        status, report = request(
            self.args.source_origin, "/fixture/control", self.control_auth,
            method="POST", body={"action": action, **options},
        )
        expect(status == 200, "fixture control was refused")
        return report

    def source_calls(self):
        status, report = request(
            self.args.source_origin, "/fixture/status", self.control_auth,
        )
        expect(status == 200 and isinstance(report, dict), "fixture status was unavailable")
        return report["operations"]

    def while_person_refresh_is_held(self, action):
        self.control("hold-next", operation="person-batch")
        with ThreadPoolExecutor(max_workers=1) as workers:
            older = workers.submit(self.refresh, "licence-holder-indexed", "holder")
            try:
                deadline = time.monotonic() + 2
                while True:
                    status, report = request(self.args.source_origin, "/fixture/status", self.control_auth)
                    expect(status == 200, "fixture status was unavailable")
                    if report.get("held"):
                        break
                    expect(time.monotonic() < deadline, "the older refresh did not reach the source barrier")
                    time.sleep(0.02)
                action()
            finally:
                self.control("release")
            return older.result(timeout=5)

    def licence_filter(self, surname_literal, **extra):
        return self.view("licence-holder-indexed", "holder",
                         query={"$filter": f"family-name eq {surname_literal}", "$count": "true", **extra})

    def business(self, live=False):
        return self.view("business-holdings-live" if live else "business-holdings-indexed",
                         "holdings", self.args.business_root)

    def run(self):
        self.control("reset")
        baseline = self.source_calls()
        expect(self.licence_filter("'Lee'")[0] == 503, "unbuilt indexed view reported coverage")
        expect(self.source_calls() == baseline, "indexed query contacted the source")

        restricted_root = request(
            self.args.breg_origin, f"/v1/records/licences/{self.args.licence_root}",
            self.auth["local-facts"], query={"accessProfile": "local-facts"},
        )
        expect(restricted_root[0] == 200, "restricted caller could not read the local licence")
        expect(self.view("licence-holder-live", "holder", self.args.licence_root,
                         profile="local-facts")[0] == 404, "restricted caller reached a live view")
        for query in ({"$filter": "family-name eq 'Lee'"}, {"$orderby": "family-name"}, {"$count": "true"}):
            expect(self.view("licence-holder-indexed", "holder", profile="local-facts", query=query)[0] == 404,
                   "restricted caller processed an external field")
        expect(self.source_calls() == baseline, "denied reads contacted the source")

        live = records(self.view("licence-holder-live", "holder", self.args.licence_root))
        expect(len(live) == 1 and live[0]["fields"]["family-name"] == "Lee", "live Person lookup failed")
        live_holdings = records(self.business(live=True))
        expect({row["fields"]["shareholder-type"] for row in live_holdings} == {"person", "business"},
               "live list did not return both shareholder types")
        expect(self.licence_filter("'Lee'")[0] == 503, "live read retained indexed data")

        expect(self.refresh("licence-holder-indexed", "holder")["published"] > 0, "Person refresh published nothing")
        expect(self.refresh("business-holdings-indexed", "holdings")["published"] > 0,
               "holdings refresh published nothing")

        reads_before = self.source_calls()
        response = self.licence_filter("'Lee'", **{"$orderby": "family-name", "$top": "1"})
        first = records(response)
        expect(len(first) == 1 and response[1].get("count") == 2, "surname filtering or count is incorrect")
        cursor = response[1].get("nextCursor")
        expect(isinstance(cursor, str) and cursor, "surname page has no cursor")
        second = records(self.view("licence-holder-indexed", "holder", query={"$skiptoken": cursor}))
        expect(len(second) == 1 and first[0]["rootId"] != second[0]["rootId"], "surname pages overlap")
        unopened = self.licence_filter("'Rivera'")
        expect(len(records(unopened)) == 1 and unopened[1].get("count") == 1, "unopened licence was not indexed")
        absent = self.licence_filter("null")
        expect(len(records(absent)) == 1 and absent[1].get("count") == 1, "keyed absence did not count as coverage")
        expect(self.view("licence-holder-indexed", "holder", self.args.licence_root,
                         profile="local-facts")[0] == 404, "a cache hit bypassed the restricted profile")
        after_refresh = request(
            self.args.breg_origin, f"/v1/records/licences/{self.args.licence_root}",
            self.auth["local-facts"], query={"accessProfile": "local-facts"},
        )
        expect(after_refresh == restricted_root, "refresh changed the owned licence response")
        expect(self.source_calls() == reads_before, "indexed pages contacted the source")

        original_holdings = records(self.business())
        expect(len(original_holdings) == 2 and surname_from_label(original_holdings) == "Lee",
               "the indexed holding did not reuse the Person projection")

        self.control("add-label-only")
        self.refresh("business-holdings-indexed", "holdings")
        indirect = next((row for row in records(self.business()) if row["fields"]["shareholder-key"] == "person-12"), {})
        expect(indirect.get("label", {}).get("availability") == "unavailable",
               "a new related-only label was already populated")
        calls = self.source_calls()
        denied = request(
            self.args.breg_origin, "/v1/external-views/business-holdings-indexed/holdings/refresh-labels",
            self.auth["officer"], method="POST", query={"accessProfile": "officer"},
        )
        expect(denied[0] == 404 and self.source_calls() == calls,
               "a reader acquired an independent label")
        expect(self.refresh("business-holdings-indexed", "holdings", labels=True)["published"] >= 1,
               "no authorised related label was published")
        indirect = next((row for row in records(self.business()) if row["fields"]["shareholder-key"] == "person-12"), {})
        expect(indirect.get("label", {}).get("fields", {}).get("family-name") == "Solano",
               "the approved label required a separate local licence root")
        expect(not records(self.licence_filter("'Solano'")),
               "a related label created a new local licence association")

        def refuse_newer_retention():
            self.control("rename-holder")
            self.control("set-no-store", operation="person-batch", enabled=True)
            expect(self.refresh("licence-holder-indexed", "holder")["unavailable"] > 0,
                   "the indexed operation did not report a no-store refusal")

        older = self.while_person_refresh_is_held(refuse_newer_retention)
        expect(older["published"] == 0 and self.licence_filter("'Lee'")[0] == 503,
               "a delayed response revived values after a later no-store refusal")
        current = self.view("licence-holder-indexed", "holder", self.args.licence_root)
        if current[0] == 200:
            expect(all(row.get("fields", {}).get("family-name") != "Ng" for row in records(current)),
                   "a no-store value entered the indexed view")
        else:
            expect(current[0] == 503, "no-store lookup returned an unexpected outcome")
        self.control("set-no-store", operation="person-batch", enabled=False)
        expect(self.refresh("licence-holder-indexed", "holder")["published"] > 0, "Person recovery did not publish")
        expect(len(records(self.licence_filter("'Ng'"))) == 2, "one Person refresh did not update both licences")
        expect(surname_from_label(records(self.business())) == "Ng", "one Person refresh did not update the holding label")
        expect(self.view("licence-holder-indexed", "holder", query={"$skiptoken": cursor})[0] == 400,
               "a cursor survived a newer projection generation")

        def publish_newer_person():
            self.control("restore-holder")
            expect(self.refresh("licence-holder-indexed", "holder")["published"] > 0,
                   "the newer Person refresh did not publish")

        older = self.while_person_refresh_is_held(publish_newer_person)
        expect(older["published"] == 0
               and len(records(self.licence_filter("'Lee'"))) == 2
               and not records(self.licence_filter("'Ng'")),
               "the older refresh replaced a newer Person publication")

        before_interruption = records(self.business())
        self.control("interrupt-collection", enabled=True)
        expect(self.refresh("business-holdings-indexed", "holdings")["unavailable"] > 0,
               "interrupted collection was not reported")
        expect(records(self.business()) == before_interruption,
               "interruption displaced the last complete holdings snapshot")
        self.control("interrupt-collection", enabled=False)
        self.control("replace-holdings")
        self.refresh("business-holdings-indexed", "holdings")
        remaining = records(self.business())
        expect(len(remaining) == 1 and remaining[0]["fields"]["shareholder-type"] == "business",
               "complete refresh did not remove the old holding")
        self.control("empty-holdings")
        self.refresh("business-holdings-indexed", "holdings")
        expect(not records(self.business()), "complete empty snapshot was not published")

        retained = records(self.licence_filter("'Doe'"))
        expect(len(retained) == 1 and retained[0]["fields"]["family-name"] == "Doe",
               "the fault fixture had no retained present value")
        fault_root = retained[0]["rootId"]
        for fault in ("denied", "ambiguous", "disconnect"):
            self.control("set-person-fault", kind=fault)
            report = self.refresh("licence-holder-indexed", "holder")
            expect(report["unavailable"] > 0, f"{fault} was not reported by refresh")
            for literal in ("'Doe'", "null"):
                expect(self.licence_filter(literal)[0] == 503,
                       f"{fault} was treated as complete coverage")
            detail = self.view("licence-holder-indexed", "holder", fault_root)
            if detail[0] == 200:
                rows = records(detail)
                expect(detail[1]["status"] == "unavailable"
                       or (len(rows) == 1 and rows[0]["availability"] == "unavailable"),
                       f"{fault} did not withdraw the retained detail")
                expect(all(not row["fields"] for row in rows), f"{fault} disclosed retained fields")
            else:
                expect(detail[0] == 503, f"{fault} produced an unexpected detail response")
            self.control("set-person-fault", kind="none")
            expect(self.refresh("licence-holder-indexed", "holder")["published"] > 0,
                   "recovered Person refresh did not publish")
            recovered = records(self.licence_filter("'Doe'"))
            expect(len(recovered) == 1 and recovered[0]["rootId"] == fault_root,
                   "recovered Person coverage did not restore the retained value")


def records(response):
    status, document = response
    expect(status == 200 and isinstance(document, dict) and isinstance(document.get("records"), list),
           "a view did not return its records envelope")
    expect(isinstance(document.get("authority"), str), "a view did not identify the source authority")
    return document["records"]


def surname_from_label(holdings):
    person = next((row for row in holdings if row["fields"]["shareholder-type"] == "person"), {})
    company = next((row for row in holdings if row["fields"]["shareholder-type"] == "business"), {})
    expect(company.get("label") is None, "a company shareholder was interpreted as a Person")
    label = person.get("label")
    if not isinstance(label, dict):
        return None
    fields = label.get("fields", label)
    return fields.get("family-name")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--breg-origin", type=origin, required=True)
    parser.add_argument("--source-origin", type=origin, required=True)
    parser.add_argument("--officer-token-file", type=Path, required=True)
    parser.add_argument("--restricted-token-file", type=Path, required=True)
    parser.add_argument("--refresh-token-file", type=Path, required=True)
    parser.add_argument("--control-key-file", type=Path, required=True)
    parser.add_argument("--licence-root", type=UUID, required=True)
    parser.add_argument("--business-root", type=UUID, required=True)
    args = parser.parse_args()
    try:
        Journey(args).run()
    except (JourneyError, KeyError, TypeError, OSError) as error:
        detail = str(error) if isinstance(error, JourneyError) else "fixture result did not match its contract"
        parser.exit(1, f"External view journey failed: {detail}\n")
    print("External view journey passed")


if __name__ == "__main__":
    main()
