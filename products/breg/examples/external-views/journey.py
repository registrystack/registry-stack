#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check the projection journey against a fresh synthetic BReg deployment."""

import argparse
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


def poll_until(check, description, timeout=60, interval=1, clock=time.monotonic, sleep=time.sleep):
    """Return the first truthy result of check, failing visibly once timeout seconds have passed."""
    deadline = clock() + timeout
    while True:
        result = check()
        if result:
            return result
        if clock() >= deadline:
            raise JourneyError(f"timed out waiting for {description}")
        sleep(interval)


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
            "staff-refresh": {"Authorization": "Bearer " + fixture_credential(args.staff_token_file)},
            "local-facts": {"Authorization": "Bearer " + fixture_credential(args.restricted_token_file)},
        }
        self.control_auth = {"x-fixture-control-key": fixture_credential(args.control_key_file)}

    def view(self, view, link, root=None, profile="officer", query=None):
        path = f"/v1/external-views/{view}/{link}/records"
        if root is not None:
            path += f"/{root}"
        return request(self.args.breg_origin, path, self.auth[profile],
                       query={"accessProfile": profile, **(query or {})})

    def rows(self, response):
        """The records of a 200 response, or None while the view cannot answer yet."""
        return response[1].get("records") if response[0] == 200 and isinstance(response[1], dict) else None

    def request_refresh(self, view, link, root):
        # BReg runs the refresh in process; a staff application service client only queues it.
        # A root refresh answers 429 with Retry-After: 30 while the plan's queue is full, so wait it out.
        for attempt in range(3):
            status, _ = request(
                self.args.breg_origin, f"/v1/external-views/{view}/{link}/records/{root}/refresh",
                self.auth["staff-refresh"], method="POST", query={"accessProfile": "staff-refresh"},
            )
            if status != 429:
                break
            time.sleep(31)
        expect(status == 202, "a staff application root refresh was not accepted")

    def refresh_until(self, view, link, root, check, description):
        self.request_refresh(view, link, root)
        return poll_until(check, description, timeout=self.args.refresh_timeout)

    def wait_until(self, check, description):
        return poll_until(check, description, timeout=self.args.refresh_timeout)

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

    def licence_filter(self, surname_literal, **extra):
        return self.view("licence-holder-indexed", "holder",
                         query={"$filter": f"family-name eq {surname_literal}", "$count": "true", **extra})

    def business(self, live=False):
        return self.view("business-holdings-live" if live else "business-holdings-indexed",
                         "holdings", self.args.business_root)

    def licence_ready(self, literal, count):
        """The licence filter once it answers with exactly count rows, else None."""
        response = self.licence_filter(literal)
        rows = self.rows(response)
        return rows if rows is not None and len(rows) == count else None

    def related_label_acquired(self):
        rows = self.rows(self.business()) or []
        indirect = next((row for row in rows if row["fields"]["shareholder-key"] == "person-12"), {})
        return indirect.get("label", {}).get("fields", {}).get("family-name") == "Solano"

    def run(self):
        self.control("reset")

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

        live = records(self.view("licence-holder-live", "holder", self.args.licence_root))
        expect(len(live) == 1 and live[0]["fields"]["family-name"] == "Lee", "live Person lookup failed")
        live_holdings = records(self.business(live=True))
        expect({row["fields"]["shareholder-type"] for row in live_holdings} == {"person", "business"},
               "live list did not return both shareholder types")

        # The worker sweeps both plans on startup. Wait for both indexed views to fill.
        self.wait_until(lambda: self.licence_ready("'Lee'", 2), "the Person sweep to cover surname Lee")
        self.wait_until(lambda: len(self.rows(self.business()) or []) == 2, "the holdings sweep to publish")

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
        after_sweep = request(
            self.args.breg_origin, f"/v1/records/licences/{self.args.licence_root}",
            self.auth["local-facts"], query={"accessProfile": "local-facts"},
        )
        expect(after_sweep == restricted_root, "refresh changed the owned licence response")
        expect(self.source_calls() == reads_before, "indexed pages contacted the source")

        # Only a staff application's service client may queue a root refresh.
        for profile in ("officer", "local-facts"):
            status, _ = request(
                self.args.breg_origin,
                f"/v1/external-views/licence-holder-indexed/holder/records/{self.args.licence_root}/refresh",
                self.auth[profile], method="POST", query={"accessProfile": profile},
            )
            expect(status == 404, f"a {profile} caller was not refused the root refresh")
        expect(self.source_calls() == reads_before, "a refused root refresh contacted the source")

        original_holdings = records(self.business())
        expect(len(original_holdings) == 2 and surname_from_label(original_holdings) == "Lee",
               "the indexed holding did not reuse the Person projection")

        # A new holder reached only through a holding is labelled by the same refresh.
        self.control("add-label-only")
        self.refresh_until("business-holdings-indexed", "holdings", self.args.business_root,
                           self.related_label_acquired, "the related-only label to be acquired")
        expect(not records(self.licence_filter("'Solano'")),
               "a related label created a new local licence association")

        def person_refresh(check, description):
            return self.refresh_until("licence-holder-indexed", "holder", self.args.licence_root, check, description)

        # A refused no-store response withdraws coverage rather than keeping stale values.
        self.control("rename-holder")
        self.control("set-no-store", operation="person-batch", enabled=True)
        person_refresh(lambda: self.licence_filter("'Lee'")[0] == 503,
                       "a no-store refusal to withdraw Person coverage")
        current = self.view("licence-holder-indexed", "holder", self.args.licence_root)
        if current[0] == 200:
            expect(all(row.get("fields", {}).get("family-name") != "Ng" for row in records(current)),
                   "a no-store value entered the indexed view")
        else:
            expect(current[0] == 503, "no-store lookup returned an unexpected outcome")
        self.control("set-no-store", operation="person-batch", enabled=False)
        person_refresh(lambda: self.licence_ready("'Ng'", 2), "Person recovery to publish the renamed holder")
        expect(surname_from_label(records(self.business())) == "Ng", "one Person refresh did not update the holding label")
        # A withdrawn key does not end the projection scope, so a cursor stays valid; only a tampered one is refused.
        tampered = self.view("licence-holder-indexed", "holder", query={"$skiptoken": cursor[:-4] + "AAAA"})
        expect(tampered[0] == 400, f"a tampered cursor was not refused (status {tampered[0]})")

        self.control("restore-holder")
        person_refresh(lambda: self.licence_ready("'Lee'", 2), "the restored holder to publish")
        expect(not records(self.licence_filter("'Ng'")), "the older surname survived a newer Person publication")

        before_interruption = records(self.business())
        collections = self.source_calls().get("holdings-by-business", 0)
        self.control("interrupt-collection", enabled=True)
        self.request_refresh("business-holdings-indexed", "holdings", self.args.business_root)
        self.wait_until(lambda: self.source_calls().get("holdings-by-business", 0) > collections,
                        "the interrupted collection to reach the source")
        expect(records(self.business()) == before_interruption,
               "interruption displaced the last complete holdings snapshot")
        self.control("interrupt-collection", enabled=False)
        self.control("replace-holdings")

        def replaced():
            rows = self.rows(self.business())
            return rows is not None and len(rows) == 1 and rows[0]["fields"]["shareholder-type"] == "business"

        self.refresh_until("business-holdings-indexed", "holdings", self.args.business_root, replaced,
                           "a complete refresh to remove the old holding")
        self.control("empty-holdings")
        self.refresh_until("business-holdings-indexed", "holdings", self.args.business_root,
                           lambda: self.rows(self.business()) == [], "a complete empty snapshot to publish")

        retained = records(self.licence_filter("'Doe'"))
        expect(len(retained) == 1 and retained[0]["fields"]["family-name"] == "Doe",
               "the fault fixture had no retained present value")
        fault_root = retained[0]["rootId"]

        # A transient source fault is not a refusal: the last complete snapshot stays served until it expires.
        for fault in ("denied", "ambiguous", "disconnect"):
            calls = self.source_calls().get("person-batch", 0)
            self.control("set-person-fault", kind=fault)
            self.request_refresh("licence-holder-indexed", "holder", fault_root)
            self.wait_until(lambda: self.source_calls().get("person-batch", 0) > calls,
                            f"the {fault} refresh to reach the source")
            kept = records(self.licence_filter("'Doe'"))
            expect(len(kept) == 1 and kept[0]["fields"]["family-name"] == "Doe",
                   f"{fault} displaced the last complete Person snapshot")
            self.control("set-person-fault", kind="none")
            recovered = self.refresh_until("licence-holder-indexed", "holder", fault_root,
                                           lambda: self.licence_ready("'Doe'", 1), "recovered Person coverage")
            expect(recovered[0]["rootId"] == fault_root,
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
    parser.add_argument("--staff-token-file", type=Path, required=True)
    parser.add_argument("--control-key-file", type=Path, required=True)
    parser.add_argument("--licence-root", type=UUID, required=True)
    parser.add_argument("--business-root", type=UUID, required=True)
    parser.add_argument("--refresh-timeout", type=int, default=60,
                        help="seconds to wait for the worker to publish after each refresh request")
    args = parser.parse_args()
    try:
        Journey(args).run()
    except (JourneyError, KeyError, TypeError, OSError) as error:
        detail = str(error) if isinstance(error, JourneyError) else "fixture result did not match its contract"
        parser.exit(1, f"External view journey failed: {detail}\n")
    print("External view journey passed")


if __name__ == "__main__":
    main()
