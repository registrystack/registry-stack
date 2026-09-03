"""Small loopback Relay responder used by the native binding tests."""

from __future__ import annotations

import http.server
import json
import threading
from dataclasses import dataclass
from typing import Callable, Mapping

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
ETAG = f'"{"a" * 64}"'
REGISTRY_RECORD_CONTEXT = "https://id.registrystack.org/contexts/registry-record/v1"
RELAY_CONTEXT = "https://relay.example.test/v2/artifacts/context"


@dataclass(frozen=True)
class Request:
    method: str
    target: str
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class Response:
    status: int
    media_type: str = "application/json"
    body: bytes = b""
    headers: Mapping[str, str] | None = None


def json_response(value: object, *, headers: Mapping[str, str] | None = None) -> Response:
    return Response(200, body=json.dumps(value, separators=(",", ":")).encode(), headers=headers)


class RelayServer:
    def __init__(self, responder: Callable[[Request], Response]):
        self.requests: list[Request] = []
        self._responder = responder
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802
                self._handle()

            def do_POST(self) -> None:  # noqa: N802
                self._handle()

            def _handle(self) -> None:
                length = int(self.headers.get("content-length", "0"))
                request = Request(
                    self.command,
                    self.path,
                    {key.lower(): value for key, value in self.headers.items()},
                    self.rfile.read(length),
                )
                owner.requests.append(request)
                response = owner._responder(request)
                self.send_response(response.status)
                headers = dict(response.headers or {})
                headers.setdefault("traceparent", TRACEPARENT)
                if response.status != 304:
                    headers.setdefault("content-type", response.media_type)
                    headers.setdefault("content-length", str(len(response.body)))
                else:
                    headers.setdefault("content-length", "0")
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                if response.status != 304:
                    self.wfile.write(response.body)

            def log_message(self, _format: str, *_args: object) -> None:
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}/prefix"

    def __enter__(self) -> "RelayServer":
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def service_metadata() -> dict[str, object]:
    return {
        "registryIdentifier": "urn:example:registry",
        "name": "Example Registry",
        "authority": {"identifier": "urn:example:authority", "name": "Authority"},
        "operator": None,
        "authoritativeScope": "example",
        "product": {"name": "Registry Relay", "version": "0.19.0"},
        "apiBinding": {"name": "Registry Relay V2", "version": "2"},
        "alignmentTargets": [],
        "capabilities": [],
        "links": {"self": "/v2", "resources": "/v2/resources", "openapi": "/openapi.json"},
    }


def record_metadata() -> dict[str, object]:
    return {
        "registryIdentifier": "urn:example:registry",
        "datasetIdentifier": "people",
        "entityTypeIdentifier": "person",
        "operationIdentifier": "records",
        "accessProfile": "public",
        "family": "consultation",
        "pattern": "list",
        "disclosureProfile": "public",
        "contractRevision": "sha256:revision",
        "sourceRevision": {"profile": "snapshot", "status": "known", "value": "r1"},
        "selectedFields": [],
        "links": {
            "self": "/v2/resources/people/records",
            "context": RELAY_CONTEXT,
            "schema": "/v2/artifacts/schema",
            "semanticModel": "/v2/artifacts/model",
        },
    }


def record(identifier: str = "one", *, json_ld: bool = False) -> dict[str, object]:
    value = {
        "recordIdentifier": identifier,
        "revisionIdentifier": "r1",
        "lifecycleState": "active",
        "schemaReference": "/v2/artifacts/schema",
        "semanticModelReference": "/v2/artifacts/model",
        "authorityIdentifier": "urn:example:authority",
        "recordedAt": "2026-08-11T00:00:00Z",
        "domainData": {"label": "Example"},
    }
    if json_ld:
        value["@id"] = f"https://relay.example.test/v2/resources/people/records/{identifier}"
        value["@type"] = "urn:example:Person"
    return value


def record_collection(next_cursor: str | None, *, json_ld: bool = False) -> dict[str, object]:
    value = {
        "items": [record(json_ld=json_ld)],
        "pageInfo": {"nextCursor": next_cursor},
        "meta": record_metadata(),
    }
    if json_ld:
        value["@context"] = [REGISTRY_RECORD_CONTEXT, RELAY_CONTEXT]
    return value


def resource_document() -> dict[str, object]:
    return {
        "resourceIdentifier": "people",
        "title": "People",
        "description": "Example resource",
        "semanticClass": "urn:example:Person",
        "enumerationPosture": "public",
        "capabilities": [],
        "links": {"self": "/v2/resources/people"},
    }


def resource_collection(next_cursor: str | None) -> dict[str, object]:
    return {
        "items": [resource_document()],
        "pageInfo": {"nextCursor": next_cursor},
        "meta": {"registryIdentifier": "urn:example:registry"},
    }
