#!/usr/bin/env python3
"""Generate the odk-central pack fixtures, deterministically.

Every value is synthetic: synthetic host, project 1, form
fixture-form.svc, obviously made-up answers, fixed timestamps. The
entity shape follows the documented Central OData page
(https://docs.getodk.org/central-api-odata-endpoints/): entities under
`value`, `__id` as the key, `meta` with `instanceID`, `__system` with
submitterId/submissionDate/updatedAt/reviewState, and the
`@odata.nextLink` carrying a synthetic `$skiptoken`. The repeat page
pins the sketch's hypothesized `__parent-id` (probe question 4 in the
pack README). Regenerate only with a pack change; the expected item
pages stay in lockstep with the recorded pages by construction.

The fixture files keep the stable AdapterFixture envelope and carry a
provisional job entry shape (jobRun.cursor / upstream / expected.page
or expected.problem): the maintained AdapterFixture artifact is
facade-shaped, and the job-mode fixture format lands with the engine
stream's job compiler.

The first three Submissions suites share one synthetic deployment
(172 submissions; the recorded order is the server's own and only the
skiptoken moves between pages). The empty suite is its own deployment
state (a form with no submissions yet).
"""

import yaml

PACK = "odk-central"
HOST = "https://central.example.invalid"
ENTITY_SET = "/v1/projects/1/forms/fixture-form.svc/Submissions"
PAGE_SIZE = 100

HEADER = """\
# yaml-language-server: $schema=https://id.registrystack.org/schemas/adapter/fixture/fixture.v1alpha1.schema.json
#
# Synthetic fixture (NOT captured, and NOT from a real ODK Central
# server): {title}. The upstream shape follows the documented Central
# OData page (https://docs.getodk.org/central-api-odata-endpoints/).
# Every value is a made-up stand-in. The entry shape is PROVISIONAL:
# the maintained AdapterFixture artifact is facade-shaped (a profile
# operation per entry), which a job route does not have, so this suite
# keeps the stable envelope and carries the job replay contract in a
# documented form until the engine stream's job compiler defines the
# job-mode fixture format.
"""

WORDS = ["One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten"]


def hexes(seed: int, length: int) -> str:
    return "".join("0123456789abcdef"[(seed * (41 + position)) % 16]
                   for position in range(length))


def uuid(seed: int) -> str:
    return (f"{hexes(seed, 8)}-{hexes(seed + 1, 4)}-{hexes(seed + 2, 4)}-"
            f"{hexes(seed + 3, 4)}-{hexes(seed + 4, 12)}")


def entity(number: int) -> dict:
    """One synthetic Submissions entity per the documented metadata
    shape, plus household-survey answers."""
    day = 5 + (number % 20)
    return {
        "__id": uuid(number),
        "meta": {"instanceID": f"uuid:{uuid(number)}"},
        "__system": {
            "submitterId": 7,
            "submissionDate": f"2026-08-{day:02d}T0{number % 10}:05:00.000Z",
            "updatedAt": f"2026-08-{day:02d}T0{number % 10}:05:00.000Z",
            "reviewState": None,
        },
        "respondent_name": f"Fixture {WORDS[number % 10]}",
        "household_size": 1 + (number % 8),
        "has_water": number % 3 != 0,
    }


def expected_item(number: int) -> dict:
    row = entity(number)
    return {
        "key": row["__id"],
        "revision": row["__system"]["updatedAt"],
        "value": row,
    }


def next_link(token: int) -> str:
    # The link as the source writes it: `$` is legal in a query, so
    # Central emits the names unencoded. The engine sends a pinned
    # link as written; only the pack's own query keys arrive
    # engine-encoded (%24).
    return f"{HOST}{ENTITY_SET}?$top=100&$skiptoken=fixture-skip-{token:04d}"


def page(start: int, size: int, count: int) -> dict:
    body = {
        "value": [entity(start + position) for position in range(size)],
    }
    if count is not None:
        body["@odata.count"] = count
    if size == PAGE_SIZE:
        body["@odata.nextLink"] = next_link(start + size)
    return body


def expected_page(start: int, size: int, count: int) -> dict:
    items = [expected_item(start + position) for position in range(size)]
    result = {"items": items}
    if size == PAGE_SIZE:
        result["next"] = {"nextLink": next_link(start + size)}
    return result


def submissions_suite(fixture_id: str, title: str, cursor: dict | None,
                      start: int, size: int, count: int,
                      request: dict) -> dict:
    entry = {"jobRun": {"cursor": cursor}}
    entry["upstream"] = [{
        "request": request,
        "response": {"status": 200, "body": page(start, size, count)},
    }]
    entry["expected"] = {"type": "page",
                         "page": expected_page(start, size, count)}
    return {
        "apiVersion": "id.registrystack.org/formats/adapter/fixture/v1alpha1",
        "kind": "AdapterFixture",
        "id": fixture_id,
        "pack": PACK,
        "upstreamVersion": "unverified",
        "provenance": {
            "type": "documented",
            "reference":
                "https://docs.getodk.org/central-api-odata-endpoints/",
        },
        "intercepts": [{"type": "endpoint", "endpoint": "odk-odata"}],
        "entries": [entry],
    }


def repeat_entity(number: int, parent: str, with_revision: bool) -> dict:
    row = {
        "__id": uuid(number + 10000),
        "__parent-id": parent,
        "child_name": f"Fixture Child {WORDS[number % 10]}",
        "child_age": number,
    }
    if with_revision:
        row["__system"] = {
            "updatedAt": f"2026-08-2{number % 9}T07:0{number % 10}:00.000Z",
        }
    return row


def repeats_suite() -> dict:
    parents = [uuid(31), uuid(32), uuid(33)]
    rows = [repeat_entity(index, parents[index], index != 1)
            for index in range(3)]
    body = {"value": rows, "@odata.count": 3}
    items = []
    for index, row in enumerate(rows):
        item = {"key": f"{row['__parent-id']}/{index}", "value": row}
        if "__system" in row:
            item["revision"] = row["__system"]["updatedAt"]
        items.append(item)
    entry = {
        "jobRun": {"cursor": None},
        "upstream": [{
            "request": {
                "endpoint": "odk-odata",
                "method": "GET",
                "path": "/",
                "query": "%24count=true&%24top=100",
            },
            "response": {"status": 200, "body": body},
        }],
        "expected": {"type": "page", "page": {"items": items}},
    }
    return {
        "apiVersion": "id.registrystack.org/formats/adapter/fixture/v1alpha1",
        "kind": "AdapterFixture",
        "id": "odk-central-repeats-page",
        "pack": PACK,
        "upstreamVersion": "unverified",
        "provenance": {
            "type": "documented",
            "reference":
                "https://docs.getodk.org/central-api-odata-endpoints/",
        },
        "intercepts": [{"type": "endpoint", "endpoint": "odk-odata"}],
        "entries": [entry],
    }


def unauthorized_suite() -> dict:
    entry = {
        "jobRun": {"cursor": None},
        "upstream": [{
            "request": {
                "endpoint": "odk-odata",
                "method": "GET",
                "path": "/",
                "query": "%24count=true&%24top=100",
            },
            "response": {
                "status": 401,
                "body": {"message": "Authentication failed.",
                         "code": 401.1},
            },
        }],
        "expected": {
            "type": "problem",
            "class": "credential.rejected",
            "code": "job.credential-rejected",
        },
    }
    return {
        "apiVersion": "id.registrystack.org/formats/adapter/fixture/v1alpha1",
        "kind": "AdapterFixture",
        "id": "odk-central-submissions-unauthorized",
        "pack": PACK,
        "upstreamVersion": "unverified",
        "provenance": {
            "type": "documented",
            "reference":
                "https://docs.getodk.org/central-api-authentication/",
        },
        "intercepts": [{"type": "endpoint", "endpoint": "odk-odata"}],
        "entries": [entry],
    }


OUT = "/Volumes/CodexWorktrees/adapter-components/products/adapter/packs/odk-central/fixtures"

FIRST_REQUEST = {
    "endpoint": "odk-odata",
    "method": "GET",
    "path": "/",
    "query": "%24count=true&%24top=100",
}
# The continuation send goes through the origin-pinned httpUri: the
# engine sends the pinned link's path and query exactly as the source
# wrote them.
NEXT_REQUEST = {
    "endpoint": "odk-odata",
    "method": "GET",
    "path": ENTITY_SET,
    "query": "$top=100&$skiptoken=fixture-skip-0100",
}


def dump(fixture_id: str, title: str, document: dict) -> None:
    body = yaml.safe_dump(document, sort_keys=False, allow_unicode=False,
                          width=100)
    with open(f"{OUT}/{fixture_id}.yaml", "w") as handle:
        handle.write(HEADER.format(title=title))
        handle.write(body)
    print(f"wrote {fixture_id}.yaml")


dump("odk-central-submissions-page-one",
     "first full page: first run, no cursor, the $top query, 100 of 172 submissions, nextLink back",
     submissions_suite("odk-central-submissions-page-one",
                       "first full page: first run, no cursor, the $top query, 100 of 172 submissions, nextLink back",
                       None, 0, PAGE_SIZE, 172, FIRST_REQUEST))
dump("odk-central-submissions-page-two",
     "second full page: cursor {nextLink}, sent through the origin-pinned link, 100 of 172 submissions, nextLink back",
     submissions_suite("odk-central-submissions-page-two",
                       "second full page: cursor {nextLink}, sent through the origin-pinned link, 100 of 172 submissions, nextLink back",
                       {"nextLink": next_link(100)}, 100, PAGE_SIZE, 172,
                       NEXT_REQUEST))
dump("odk-central-submissions-page-short",
     "short page: cursor {nextLink}, the last 22 of 172 submissions, no nextLink back",
     submissions_suite("odk-central-submissions-page-short",
                       "short page: cursor {nextLink}, the last 22 of 172 submissions, no nextLink back",
                       {"nextLink": next_link(100)}, 100, 22, 172,
                       NEXT_REQUEST))
dump("odk-central-submissions-empty",
     "empty page: first run over a form with no submissions yet, empty value, no nextLink back",
     submissions_suite("odk-central-submissions-empty",
                       "empty page: first run over a form with no submissions yet, empty value, no nextLink back",
                       None, 0, 0, 0, FIRST_REQUEST))
dump("odk-central-repeats-page",
     "repeat-table sketch: one short page of a repeat entity set, keys <parent>/<position>, revision optional",
     repeats_suite())
dump("odk-central-submissions-unauthorized",
     "refused credential: the entity set answers 401 without a WWW-Authenticate challenge, the engine raises credential.rejected before any route step",
     unauthorized_suite())
