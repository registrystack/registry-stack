#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Loopback source for the synthetic licensing projection journeys."""

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from threading import Condition

OPERATIONS = {
    "/people/exact": "person-exact",
    "/people/batch": "person-batch",
    "/holdings/by-business": "holdings-by-business",
}
PERSON_FIELDS = {"given-name", "family-name"}
HOLDING_FIELDS = {"share-class", "share-count", "shareholder-type", "shareholder-key", "person-key"}
ALLOWED_PEOPLE = {"person-7", "person-8", "person-9", "person-10", "person-12"}
ALLOWED_BUSINESSES = {"business-1", "business-2"}
MAX_BODY_BYTES = 16_384
PAGE_SIZE = 1


class FixtureFault(ValueError):
    def __init__(self, status, problem):
        super().__init__(problem)
        self.status = status
        self.problem = problem


def require(condition, problem="invalid fixture request", status=400):
    if not condition:
        raise FixtureFault(status, problem)


def digest(value):
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(canonical.encode("ascii")).hexdigest()


def holding(key, shareholder_type, shareholder_key, share_class, share_count):
    return {
        "holding": key,
        "business": "business-1",
        "properties": {
            "shareholder-type": shareholder_type,
            "shareholder-key": shareholder_key,
            "person-key": shareholder_key if shareholder_type == "person" else None,
            "share-class": share_class,
            "share-count": share_count,
        },
    }


class Fixture:
    def __init__(self):
        self._lock = Condition()
        self._operations = Counter()
        self._reset()

    def _reset(self):
        self._people = {
            "person-7": {"given-name": "Ari", "family-name": "Lee"},
            "person-8": {"given-name": "Sam", "family-name": "Rivera"},
            "person-10": {"given-name": "Pat", "family-name": "Doe"},
            "person-12": {"given-name": "Mika", "family-name": "Solano"},
        }
        self._holdings = [
            holding("holding-1", "person", "person-7", "common", 25),
            holding("holding-2", "business", "business-2", "preferred", 75),
        ]
        self._fault = "none"
        self._interrupt = False
        self._no_store = {"person-exact"}
        self._hold_next = None
        self._held = False

    def _one_person(self, key, fields):
        require(
            isinstance(key, str) and key in ALLOWED_PEOPLE,
            "selector outside the approved scope",
            403,
        )
        if key == "person-9":
            return {"subject": key, "state": "confirmed-absent"}
        if key == "person-10":
            if self._fault == "denied":
                raise FixtureFault(403, "protected subject")
            if self._fault == "disconnect":
                raise FixtureFault(0, "fixture transport interruption")
            if self._fault == "ambiguous":
                return {"subject": key, "state": "ambiguous"}
        record = self._people[key]
        return {
            "subject": key,
            "state": "found",
            "revision": digest(record),
            "properties": {field: record[field] for field in fields},
        }

    def _page(self, parent, cursor, fields):
        require(
            isinstance(parent, str) and parent in ALLOWED_BUSINESSES,
            "selector outside the approved scope",
            403,
        )
        rows = self._holdings if parent == "business-1" else []
        snapshot = digest([parent, rows])
        offset = 0
        if cursor is not None:
            require(isinstance(cursor, str) and len(cursor) <= 70 and ":" in cursor)
            requested_snapshot, offset_text = cursor.split(":", 1)
            require(compare_digest(requested_snapshot, snapshot), "snapshot changed", 409)
            require(offset_text.isascii() and offset_text.isdecimal() and len(offset_text) <= 3)
            offset = int(offset_text)
            require(0 < offset < len(rows))
            require(not self._interrupt, "collection interrupted", 503)
        items = [
            {
                "holding": row["holding"],
                "business": row["business"],
                "revision": digest(row["properties"]),
                "properties": {field: row["properties"][field] for field in fields},
            }
            for row in rows[offset : offset + PAGE_SIZE]
        ]
        next_offset = offset + len(items)
        finished = next_offset >= len(rows)
        return {
            "state": "snapshot",
            "business": parent,
            "snapshotId": snapshot,
            "finished": finished,
            "next": None if finished else f"{snapshot}:{next_offset}",
            "items": items,
        }

    def note_attempt(self, operation):
        with self._lock:
            self._operations[operation] += 1

    def acquire(self, operation, request):
        with self._lock:
            self._operations[operation] += 1
            require(isinstance(request, dict))
            fields = request.get("fields")
            permitted = HOLDING_FIELDS if operation == "holdings-by-business" else PERSON_FIELDS
            require(
                isinstance(fields, list) and fields
                and all(isinstance(field, str) and field in permitted for field in fields)
                and len(fields) == len(set(fields)),
                "field outside the approved scope",
                403,
            )
            if operation == "person-exact":
                require(set(request) == {"type", "key", "fields"} and request["type"] == "exact")
                result = self._one_person(request["key"], fields)
            elif operation == "person-batch":
                require(set(request) == {"type", "keys", "fields"} and request["type"] == "batch")
                keys = request["keys"]
                require(
                    isinstance(keys, list) and 1 <= len(keys) <= 64
                    and all(isinstance(key, str) for key in keys) and len(keys) == len(set(keys))
                )
                result = {"records": [self._one_person(key, fields) for key in keys]}
            elif operation == "holdings-by-business":
                require(
                    set(request) in ({"type", "parentKey", "fields"}, {"type", "parentKey", "fields", "cursor"})
                    and request["type"] == "by-parent"
                )
                result = self._page(request["parentKey"], request.get("cursor"), fields)
            else:
                raise FixtureFault(404, "unknown fixture operation")
            no_store = operation in self._no_store
            if self._hold_next == operation:
                self._hold_next = None
                self._held = True
                self._lock.notify_all()
                if not self._lock.wait_for(lambda: not self._held, timeout=4):
                    self._held = False
                    raise FixtureFault(503, "fixture hold expired")
            return result, no_store

    def wait_for_hold(self, timeout):
        with self._lock:
            return self._lock.wait_for(lambda: self._held, timeout=timeout)

    def status(self):
        with self._lock:
            return {"operations": dict(self._operations), "held": self._held}

    def control(self, body):
        with self._lock:
            require(isinstance(body, dict))
            action = body.get("action")
            if action in ("reset", "rename-holder", "restore-holder", "add-label-only", "replace-holdings",
                          "empty-holdings", "release"):
                require(set(body) == {"action"})
                if action == "reset":
                    self._reset()
                    self._operations.clear()
                elif action == "rename-holder":
                    self._people["person-7"] = {"given-name": "Ari", "family-name": "Ng"}
                elif action == "restore-holder":
                    self._people["person-7"] = {"given-name": "Ari", "family-name": "Lee"}
                elif action == "add-label-only":
                    if not any(row["holding"] == "holding-3" for row in self._holdings):
                        self._holdings.append(holding("holding-3", "person", "person-12", "common", 15))
                elif action == "replace-holdings":
                    self._holdings = [holding("holding-2", "business", "business-2", "preferred", 100)]
                elif action == "empty-holdings":
                    self._holdings = []
                else:
                    self._held = False
                self._lock.notify_all()
            elif action == "hold-next":
                require(set(body) == {"action", "operation"} and body["operation"] in OPERATIONS.values())
                require(self._hold_next is None and not self._held, "fixture hold already active", 409)
                self._hold_next = body["operation"]
            elif action == "set-person-fault":
                require(set(body) == {"action", "kind"} and body["kind"] in ("none", "ambiguous", "denied", "disconnect"))
                self._fault = body["kind"]
            elif action == "interrupt-collection":
                require(set(body) == {"action", "enabled"} and isinstance(body["enabled"], bool))
                self._interrupt = body["enabled"]
            elif action == "set-no-store":
                require(
                    set(body) == {"action", "operation", "enabled"}
                    and body["operation"] in OPERATIONS.values() and isinstance(body["enabled"], bool)
                )
                if body["enabled"]:
                    self._no_store.add(body["operation"])
                elif body["operation"] != "person-exact":
                    self._no_store.discard(body["operation"])
            else:
                raise FixtureFault(400, "unknown fixture control")
        return self.status()


def no_duplicate_members(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate fixture request member")
        result[name] = value
    return result


def handler(fixture, source_key, control_key):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(6)

        def log_message(self, *_):
            return None

        def _require_key(self, header, key):
            supplied = self.headers.get_all(header, [])
            require(
                key is not None and len(supplied) == 1 and supplied[0].isascii()
                and compare_digest(supplied[0], key),
                "fixture credential refused",
                403,
            )

        def _body(self):
            lengths = self.headers.get_all("Content-Length", [])
            require(len(lengths) == 1 and lengths[0].isascii() and lengths[0].isdecimal() and len(lengths[0]) <= 6)
            length = int(lengths[0])
            require(0 < length <= MAX_BODY_BYTES and not self.headers.get_all("Transfer-Encoding"))
            try:
                return json.loads(self.rfile.read(length), object_pairs_hook=no_duplicate_members)
            except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                raise FixtureFault(400, "invalid fixture JSON") from error

        def _reply(self, status, value, no_store=False):
            data = json.dumps(value, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            if no_store:
                self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

        def _handle(self, operation):
            try:
                operation()
            except FixtureFault as fault:
                if fault.status:
                    self._reply(fault.status, {"problem": fault.problem}, no_store=True)
                else:
                    self.close_connection = True

        def do_POST(self):
            def execute():
                if self.path == "/fixture/control":
                    self._require_key("x-fixture-control-key", control_key)
                    self._reply(200, fixture.control(self._body()), no_store=True)
                    return
                operation = OPERATIONS.get(self.path)
                require(operation is not None, "unknown fixture route", 404)
                try:
                    self._require_key("x-registry-service-key", source_key)
                    body = self._body()
                except FixtureFault:
                    fixture.note_attempt(operation)
                    raise
                result, no_store = fixture.acquire(operation, body)
                self._reply(200, result, no_store)
            self._handle(execute)

        def do_GET(self):
            def execute():
                require(self.path == "/fixture/status", "unknown fixture route", 404)
                self._require_key("x-fixture-control-key", control_key)
                self._reply(200, fixture.status(), no_store=True)
            self._handle(execute)

    return Handler


def source_key_from_file(path):
    with path.open("rb") as stream:
        value = stream.read(257).strip()
    require(8 <= len(value) <= 256 and all(33 <= byte <= 126 for byte in value),
            "fixture key file has an invalid shape")
    return value.decode("ascii")


def runtime_fragment(origin, key_file_name, grant_cutoff):
    pack = Path(__file__).resolve().parents[3] / "adapter/examples/external-projections/pack.yaml"
    pack_digest = "sha256:" + sha256(pack.read_bytes()).hexdigest()
    connection = {
        "id": "synthetic-licensing",
        "endpoints": [{
            "endpoint": "synthetic-registry", "baseUrl": origin,
            "credential": {"type": "static-api-key", "valueRef": f"secret:file/{key_file_name}"},
        }],
    }
    policy = [{
        "endpoint": "synthetic-registry", "baseUrl": origin, "clientIdentity": "forbidden",
        "authentication": {"type": "static-api-key"},
    }]
    bindings = []
    for binding, fields, selectors in (
        ("person-live", PERSON_FIELDS, ALLOWED_PEOPLE),
        ("person-indexed", PERSON_FIELDS, ALLOWED_PEOPLE),
        ("holdings-live", HOLDING_FIELDS - {"person-key"}, ALLOWED_BUSINESSES),
        ("holdings-indexed", HOLDING_FIELDS, ALLOWED_BUSINESSES),
    ):
        entry = {
            "id": binding, "packFile": str(pack), "packDigest": pack_digest,
            "connection": connection, "endpointPolicies": policy,
            "allowedFields": sorted(fields), "allowedSelectors": sorted(selectors),
            "grantValidUntil": grant_cutoff,
            "acquisition": {"maximumDataOperations": 8, "timeoutMilliseconds": 8000,
                            "maximumResponseBytes": 262144},
        }
        if binding.endswith("-indexed"):
            entry["retention"] = {"maximumRetentionSeconds": 300, "refreshIntervalSeconds": 60}
        bindings.append(entry)
    return {"externalSources": bindings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0, help="numeric loopback port, default ephemeral")
    parser.add_argument("--service-key-file", type=Path, required=True)
    parser.add_argument("--control-key-file", type=Path)
    parser.add_argument("--runtime-fragment-file", type=Path)
    options = parser.parse_args()
    source_key = source_key_from_file(options.service_key_file)
    control_key = source_key_from_file(options.control_key_file) if options.control_key_file else None
    if control_key is not None and compare_digest(source_key, control_key):
        parser.error("the read service and control identities must differ")
    with ThreadingHTTPServer(("127.0.0.1", options.port), handler(Fixture(), source_key, control_key)) as server:
        origin = f"http://127.0.0.1:{server.server_port}"
        if options.runtime_fragment_file:
            cutoff = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            fragment = runtime_fragment(origin, options.service_key_file.name, cutoff)
            fd = os.open(options.runtime_fragment_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(fragment, stream, indent=2)
                stream.write("\n")
        print(origin, flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
