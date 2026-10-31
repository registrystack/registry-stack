#!/usr/bin/env python3
"""Generate the kobotoolbox pack fixtures, deterministically.

Every value is synthetic: synthetic uid, synthetic host, obviously
made-up names ("Fixture One"), fixed timestamps. The submission shape
follows the documented Kobo data-endpoint metadata members; the
behavior is documentation-derived and unproved (see the pack README
probe questions). Regenerate only with a pack change; the expected
item pages stay in lockstep with the recorded pages by construction.

The fixture files keep the stable AdapterFixture envelope and carry a
provisional job entry shape (jobRun.cursor / upstream / expected.page
or expected.problem): the maintained AdapterFixture artifact is
facade-shaped, and the job-mode fixture format lands with the engine
stream's job compiler.

The first three suites share one synthetic deployment (260 submissions,
newest first, ids 260..1). The empty suite is its own deployment state:
a form whose total is a multiple of the page size (200), where the
second full page ends the data exactly and the next run reads offset
200 into an empty page, the exact-boundary case the fixed page size
can produce.
"""

import yaml

PACK = "kobotoolbox"
HOST = "https://kobo.example.invalid"
DATA_PATH = "/api/v2/assets/aFixtureUid0000000000000000000001/data"
PAGE_SIZE = 100

HEADER = """\
# yaml-language-server: $schema=https://id.registrystack.org/schemas/adapter/fixture/fixture.v1alpha1.schema.json
#
# Synthetic fixture (NOT captured, and NOT from a real KoboToolbox
# server): {title}. The upstream shape follows the documented v2 data
# endpoint ({{count, next, previous, results}} over
# GET /api/v2/assets/<uid>/data/ with format, limit, start;
# https://support.kobotoolbox.org/api.html and the kobotoolbox/docs
# source/migrating_api.md). Every value is a made-up stand-in; the
# reply's own `next` URL is synthetic and unread by the route. The
# entry shape is PROVISIONAL: the maintained AdapterFixture artifact is
# facade-shaped (a profile operation per entry), which a job route does
# not have, so this suite keeps the stable envelope and carries the
# job replay contract in a documented form until the engine stream's
# job compiler defines the job-mode fixture format.
"""

WORDS = ["One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten"]


def hexes(seed: int, length: int) -> str:
    return "".join("0123456789abcdef"[(seed * (37 + position)) % 16]
                   for position in range(length))


def uuid(seed: int) -> str:
    return (f"uuid:{hexes(seed, 8)}-{hexes(seed + 1, 4)}-"
            f"{hexes(seed + 2, 4)}-{hexes(seed + 3, 4)}-{hexes(seed + 4, 12)}")


def submission(number: int) -> dict:
    """One synthetic submission, documented metadata members plus
    household-survey answers, in the page order Kobo returns (newest
    first), so page one carries the highest ids."""
    day = 10 + (number % 18)
    return {
        "_id": number,
        "formhub/uuid": hexes(number + 500, 32),
        "_uuid": uuid(number),
        "_submission_time": f"2026-09-{day:02d}T0{number % 10}:15:30",
        "_tags": [],
        "_notes": [],
        "_version_": f"vX{hexes(number + 900, 12)}",
        "_status": "submitted_by_anonymous",
        "_submitted_by": None,
        "_geolocation": [],
        "meta/instanceID": uuid(number),
        "meta/rootUuid": uuid(number),
        "respondent_name": f"Fixture {WORDS[number % 10]}",
        "household_size": 1 + (number % 9),
        "has_water": number % 2 == 0,
    }


def expected_item(number: int) -> dict:
    return {
        "key": str(number),
        "revision": uuid(number),
        "value": submission(number),
    }


def kobo_page(start: int, size: int, count: int) -> list:
    """A results page in Kobo's newest-first order: the page at offset
    `start` carries ids count down to count-start-size+1."""
    top = count - start
    return [submission(top - position) for position in range(size)]


def expected_page(start: int, size: int, count: int) -> dict:
    top = count - start
    items = [expected_item(top - position) for position in range(size)]
    page = {"items": items}
    if size == PAGE_SIZE:
        page["next"] = {"offset": start + PAGE_SIZE}
    return page


def next_url(start: int) -> str:
    return f"{HOST}{DATA_PATH}?format=json&limit={PAGE_SIZE}&start={start + PAGE_SIZE}"


def suite(fixture_id: str, title: str, cursor: dict | None,
          start: int, size: int, count: int, note: str = "") -> dict:
    reply = {
        "count": count,
        "next": next_url(start) if size == PAGE_SIZE else None,
        "previous": None,
        "results": kobo_page(start, size, count),
    }
    page = expected_page(start, size, count)
    if fixture_id == "kobotoolbox-submissions-page-one":
        # One submission in the first page carries a _validation_status
        # object: the passthrough rule is that it may appear only
        # inside value, and no step reads it.
        reply["results"][3]["_validation_status"] = {
            "uid": "validation-status-fixture-1",
            "timestamp": 1759234530,
            "by_whom": "fixture-admin",
            "status": "approved",
        }
        page["items"][3]["value"]["_validation_status"] = (
            reply["results"][3]["_validation_status"]
        )
    if note:
        title = f"{title}. {note}"
    entry: dict = {"jobRun": {"cursor": cursor}}
    entry["upstream"] = [{
        "request": {
            "endpoint": "kobo-api",
            "method": "GET",
            "path": "/",
            "query": f"format=json&limit={PAGE_SIZE}&start={start}",
        },
        "response": {"status": 200, "body": reply},
    }]
    entry["expected"] = {"type": "page", "page": page}
    return {
        "apiVersion": "id.registrystack.org/formats/adapter/fixture/v1alpha1",
        "kind": "AdapterFixture",
        "id": fixture_id,
        "pack": PACK,
        "upstreamVersion": "unverified",
        "provenance": {
            "type": "documented",
            "reference": "https://support.kobotoolbox.org/api.html",
        },
        "intercepts": [{"type": "endpoint", "endpoint": "kobo-api"}],
        "entries": [entry],
    }


def unauthorized_suite() -> dict:
    entry = {
        "jobRun": {"cursor": None},
        "upstream": [{
            "request": {
                "endpoint": "kobo-api",
                "method": "GET",
                "path": "/",
                "query": "format=json&limit=100&start=0",
            },
            "response": {
                "status": 401,
                "body": {"detail": "Invalid username/password."},
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
        "id": "kobotoolbox-submissions-unauthorized",
        "pack": PACK,
        "upstreamVersion": "unverified",
        "provenance": {
            "type": "documented",
            "reference": "https://support.kobotoolbox.org/api.html",
        },
        "intercepts": [{"type": "endpoint", "endpoint": "kobo-api"}],
        "entries": [entry],
    }


SUITES = [
    ("kobotoolbox-submissions-page-one",
     "first full page: first run, no cursor, offset 0, 100 of 260 submissions, cursor {offset: 100} back",
     None, 0, PAGE_SIZE, 260),
    ("kobotoolbox-submissions-page-two",
     "second full page: cursor {offset: 100}, 100 of 260 submissions, cursor {offset: 200} back",
     {"offset": 100}, 100, PAGE_SIZE, 260),
    ("kobotoolbox-submissions-page-short",
     "short page: cursor {offset: 200}, the last 60 of 260 submissions, no cursor back",
     {"offset": 200}, 200, 60, 260),
    ("kobotoolbox-submissions-page-empty",
     "empty page: cursor {offset: 200} over a form whose total (200) is a multiple of the page size, empty results, no cursor back",
     {"offset": 200}, 200, 0, 200),
]

OUT = "/Volumes/CodexWorktrees/adapter-components/products/adapter/packs/kobotoolbox/fixtures"


def dump(fixture_id: str, title: str, document: dict) -> None:
    body = yaml.safe_dump(document, sort_keys=False, allow_unicode=False,
                          width=100)
    with open(f"{OUT}/{fixture_id}.yaml", "w") as handle:
        handle.write(HEADER.format(title=title))
        handle.write(body)
    print(f"wrote {fixture_id}.yaml")


for fixture_id, title, cursor, start, size, count in SUITES:
    dump(fixture_id, title,
         suite(fixture_id, title, cursor, start, size, count))
dump("kobotoolbox-submissions-unauthorized",
     "refused credential: the data endpoint answers 401, the engine raises credential.rejected before any route step",
     unauthorized_suite())
