"""Serve an institution's public intake status."""

import calendar
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit


def status_payload(text):
    values = json.loads(text)
    if (
        not isinstance(values, dict) or set(values) != {"acceptingApplications", "nextReviewWeekday"}
        or type(values["acceptingApplications"]) is not bool
        or values["nextReviewWeekday"] not in calendar.day_name
    ):
        raise ValueError("Supply a public intake status and a weekday in status.json.")
    return (json.dumps(values, separators=(",", ":")) + "\n").encode()


def main():
    path = os.environ["PUBLIC_PATH"]
    port = int(os.environ["PORT"])
    body = status_payload(Path("/etc/registry-extension/status.json").read_text())

    class StatusHandler(BaseHTTPRequestHandler):
        timeout = 5

        def log_request(self, code="-", size="-"):
            self.log_message("intake status request returned %s", code)

        def do_GET(self):
            if urlsplit(self.path).path != path:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with HTTPServer(("0.0.0.0", port), StatusHandler) as server:
        print(f"Public intake status is listening on port {port}.")
        server.serve_forever()


if __name__ == "__main__":
    main()
