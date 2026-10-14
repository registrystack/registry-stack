import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

DEFAULT_BASE_URL = "https://r4.smarthealthit.org"
BASE_URL = os.environ.get("FHIR_TUTORIAL_TEST_BASE_URL", DEFAULT_BASE_URL)
if BASE_URL != DEFAULT_BASE_URL:
    parsed_origin = urlsplit(BASE_URL)
    if (
        parsed_origin.scheme != "http"
        or parsed_origin.hostname != "127.0.0.1"
        or parsed_origin.port is None
        or parsed_origin.username is not None
        or parsed_origin.password is not None
        or parsed_origin.path not in {"", "/"}
        or parsed_origin.query
        or parsed_origin.fragment
    ):
        raise RuntimeError("the tutorial test origin must be numeric loopback HTTP")
BASE_URL = BASE_URL.rstrip("/")
MAXIMUM_BYTES = 1_048_576
RESOURCE_PATH = re.compile(r"^/(Coverage|Organization)/([A-Za-z0-9.-]{1,64})$")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


OPENER = build_opener(ProxyHandler({}), NoRedirect)


class FhirReadThrough(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def send_body(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def fail(self, status):
        self.send_body(status, b'{"error":"FHIR read failed"}\n', "application/json")

    def do_GET(self):
        if self.path == "/healthz":
            self.send_body(200, b"ready\n", "text/plain")
            return

        match = RESOURCE_PATH.fullmatch(self.path)
        if match is None:
            self.fail(404)
            return
        resource_type, resource_id = match.groups()
        if resource_id in {".", ".."}:
            self.fail(404)
            return
        request = Request(
            f"{BASE_URL}/{resource_type}/{resource_id}",
            headers={"Accept": "application/fhir+json"},
        )
        try:
            with OPENER.open(request, timeout=20) as response:
                if response.status != 200 or response.headers.get_content_type() not in {
                    "application/fhir+json",
                    "application/json",
                }:
                    self.fail(502)
                    return
                body = response.read(MAXIMUM_BYTES + 1)
            if len(body) > MAXIMUM_BYTES:
                self.fail(502)
                return
            resource = json.loads(body)
            if (
                not isinstance(resource, dict)
                or resource.get("resourceType") != resource_type
                or resource.get("id") != resource_id
            ):
                self.fail(502)
                return
        except HTTPError as error:
            with error:
                self.fail(404 if error.code in {404, 410} else 502)
            return
        except (URLError, TimeoutError, ValueError):
            self.fail(502)
            return

        self.send_body(200, body, "application/json")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8000), FhirReadThrough)
    server.daemon_threads = True
    print("FHIR read-through adapter ready on 127.0.0.1:8000", flush=True)
    server.serve_forever()
