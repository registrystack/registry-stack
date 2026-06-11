#!/usr/bin/env python3
"""Serve the public Registry Lab homepage."""

from __future__ import annotations

import argparse
import html
import json
import os
import shlex
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from lab_homepage_scenarios import (
    run_alive_proof_step,
    run_scenario_step,
    scenario_nav_link,
    scenario_page_html,
    scenario_payload,
)


DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config/lab-homepage/public-demo-credentials.json"
DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / "config/lab-homepage/public-demo-credentials.env"
TOKEN_SUFFIXES = ("_RAW", "_TOKEN", "_BEARER")

FAVICON_CONTENT_TYPE = "image/svg+xml"

# Static assets (CSS/JS extracted from the page templates) live beside this script so they
# travel with it when the deploy copies scripts/ into the runtime image. Resolve relative to
# the script, never the CWD, so the path is correct regardless of where the server is launched.
STATIC_DIR = Path(__file__).resolve().parent / "lab_homepage_static"

# Strict allowlist: only these exact basenames may be served, each with a fixed content type.
# A request name is matched against this dict; anything else is a 404. We never build a
# filesystem path from a raw request path, which keeps traversal (../, %2e%2e) impossible.
STATIC_ASSETS: dict[str, str] = {
    "shared.css": "text/css; charset=utf-8",
    "homepage.css": "text/css; charset=utf-8",
    "scenarios.css": "text/css; charset=utf-8",
    "homepage.js": "application/javascript; charset=utf-8",
    "scenarios.js": "application/javascript; charset=utf-8",
}


def static_asset_bytes(name: str) -> bytes:
    """Read an allowlisted static asset by basename. Raises KeyError if not allowlisted."""
    if name not in STATIC_ASSETS:
        raise KeyError(name)
    # name is a known-good basename from STATIC_ASSETS, so this join cannot escape STATIC_DIR.
    return (STATIC_DIR / name).read_bytes()


def favicon_svg() -> bytes:
    # Minimal on-brand monogram: "RS" in the registry blue on a white square.
    return (
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">'
        b'<rect width="32" height="32" fill="#173b7a"/>'
        b'<text x="16" y="22" font-family="monospace" font-size="14" font-weight="700"'
        b' text-anchor="middle" fill="#ffffff">RS</text>'
        b"</svg>"
    )


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        try:
            values[key] = shlex.split(value, comments=False, posix=True)[0]
        except (IndexError, ValueError):
            values[key] = value.strip("'\"")
    return values


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def public_env(config: dict[str, Any]) -> dict[str, str]:
    names = {credential["env"] for credential in config.get("credentials", []) if credential.get("env")}
    env_values = dict(os.environ)
    return {name: env_values.get(name, "") for name in sorted(names)}


def apply_env_file(values: dict[str, str]) -> None:
    # Fill values that are absent or empty; a non-empty environment value wins.
    # Compose passes each token through as ${VAR:-}, so the key is present but empty
    # when nothing is set in the deploy environment, and setdefault would not fill it.
    for key, value in values.items():
        if not os.environ.get(key):
            os.environ[key] = value


def credential_lookup(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        credential["id"]: credential
        for credential in config.get("credentials", [])
        if credential.get("id")
    }


def auth_header_pair(credential: dict[str, Any], token: str) -> tuple[str, str]:
    """Return the (name, value) header used to present this credential's token.

    Notary api_key credentials authenticate via the X-Api-Key header; relays and
    bearer tokens use Authorization: Bearer (see auth.mode in the notary configs).
    """
    if credential.get("auth_scheme") == "api_key":
        return "X-Api-Key", token
    return "Authorization", f"Bearer {token}"


def group_credentials_by_service(
    services: list[dict[str, Any]], credentials: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Attach each credential to the service it calls, matched by URL.

    Services keep their order and gain a `credentials` list (empty when none apply).
    A credential whose service_url matches no service is surfaced under its own group
    so it is never silently dropped from the page.
    """
    by_url: dict[str, list[dict[str, Any]]] = {}
    for credential in credentials:
        by_url.setdefault(credential.get("service_url", ""), []).append(credential)

    grouped: list[dict[str, Any]] = []
    matched_urls: set[str] = set()
    for service in services:
        item = dict(service)
        url = item.get("url", "")
        item["credentials"] = by_url.get(url, [])
        matched_urls.add(url)
        grouped.append(item)

    for url, creds in by_url.items():
        if url not in matched_urls:
            grouped.append(
                {"id": creds[0].get("id", url), "label": url, "url": url, "purpose": "", "credentials": creds}
            )
    return grouped


def enrich_config(config: dict[str, Any]) -> dict[str, Any]:
    env_values = public_env(config)
    credentials = []
    for credential in config.get("credentials", []):
        item = dict(credential)
        token = env_values.get(item.get("env", ""), "")
        item["token"] = token
        item["configured"] = bool(token)
        if token:
            name, value = auth_header_pair(item, token)
            item["auth_header"] = f"{name}: {value}"
        else:
            item["auth_header"] = ""
        item["curl"] = curl_example(item, token)
        credentials.append(item)

    enriched = dict(config)
    enriched["services"] = group_credentials_by_service(config.get("services", []), credentials)
    enriched["credentials"] = credentials
    enriched["generated_at_unix_ms"] = int(time.time() * 1000)
    return enriched


def curl_example(credential: dict[str, Any], token: str) -> str:
    example = credential.get("example") or {}
    method = example.get("method", "GET")
    base_url = credential.get("service_url", "").rstrip("/")
    path = example.get("path", "/")
    url = f"{base_url}{path}"
    pieces = ["curl", "-fsS", "-X", method, shlex.quote(url)]
    if token:
        name, value = auth_header_pair(credential, token)
        pieces.extend(["-H", shlex.quote(f"{name}: {value}")])
    for header, value in (credential.get("required_headers") or {}).items():
        pieces.extend(["-H", shlex.quote(f"{header}: {value}")])
    return " ".join(pieces)


def base_url_browsable(url: str, timeout: float) -> bool:
    """Whether an unauthenticated browser would see a real page at the service root.

    The Open link points at this URL, so a 2xx/3xx (a page, or a redirect to one) means
    there is something to see; a 401/403/404/5xx or a transport error means there is not.
    """
    request = urllib.request.Request(url, headers={"User-Agent": "registry-lab-homepage/1.0"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 400
    except urllib.error.HTTPError as error:
        return 200 <= error.code < 400
    except Exception:  # noqa: BLE001
        return False


def status_checks(config: dict[str, Any], timeout: float) -> dict[str, Any]:
    credentials = credential_lookup(enrich_config(config))
    # Every credential in this lab is a token for a protected API, so a service that hands one
    # out is never browsable unauthenticated: skip its base-URL probe and treat it as such.
    credentialed_urls = {
        credential.get("service_url", "") for credential in config.get("credentials", []) if credential.get("service_url")
    }
    checks = []
    for service in config.get("services", []):
        start = time.monotonic()
        url = urljoin(service["url"].rstrip("/") + "/", service.get("status_path", "/").lstrip("/"))
        headers = {"User-Agent": "registry-lab-homepage/1.0"}
        credential_id = service.get("status_credential_id")
        token = ""
        if credential_id and credential_id in credentials:
            token = credentials[credential_id].get("token", "")
        if token:
            name, value = auth_header_pair(credentials[credential_id], token)
            headers[name] = value
        request = urllib.request.Request(url, headers=headers, method="GET")
        base_url = service.get("url", "")
        result: dict[str, Any] = {
            "id": service.get("id"),
            "label": service.get("label"),
            "url": base_url,
            "status_url": url,
            "auth_gated": False,
            "browsable": False if base_url in credentialed_urls else base_url_browsable(base_url, timeout),
        }
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                result["status_code"] = response.status
                result["ok"] = 200 <= response.status < 400
        except urllib.error.HTTPError as error:
            result["status_code"] = error.code
            # A 401/403 proves the service is reachable and enforcing auth: that is up, not down.
            result["auth_gated"] = error.code in (401, 403)
            result["ok"] = result["auth_gated"]
            if not result["ok"]:
                result["error"] = HTTPStatus(error.code).phrase if error.code in HTTPStatus._value2member_map_ else "HTTP error"
        except Exception as error:  # noqa: BLE001
            result["status_code"] = None
            result["ok"] = False
            result["error"] = error.__class__.__name__
        result["latency_ms"] = int((time.monotonic() - start) * 1000)
        checks.append(result)
    return {"generated_at_unix_ms": int(time.time() * 1000), "checks": checks}


def homepage_html(title: str) -> bytes:
    safe_title = html.escape(title)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{safe_title}</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="stylesheet" href="/static/shared.css">
  <link rel="stylesheet" href="/static/homepage.css">
</head>
<body>
  <header class="site-header">
    <a class="brand" href="/" aria-label="Registry Lab home">
      <span class="brand-mark" aria-hidden="true">RS</span>
      <span>Registry Lab</span>
    </a>
    <nav class="top-nav" aria-label="Lab navigation">
      {scenario_nav_link()}
      <a href="#services">Services &amp; credentials</a>
      <a href="#wallet">Wallet test</a>
      <a class="nav-emphasis" href="https://registrystack.org/">Registry Stack</a>
    </nav>
  </header>
  <main>
    <section class="hero" aria-labelledby="title">
      <div class="hero-inner">
        <div>
          <p class="eyebrow">Public demo lab</p>
          <h1 id="title">Registry Lab</h1>
          <p class="subtitle" id="subtitle"></p>
          <p class="hero-note">Everything here runs on synthetic demo data. The credentials below are public on purpose, and none of them reach a real or production system. Poke around freely.</p>
          <div class="hero-links">
            <a class="button primary" href="/scenarios">Try a scenario</a>
            <a class="button" href="#wallet">Try the wallet test</a>
            <a class="button" href="#services">See what is running</a>
          </div>
          <div class="badge-row">
            <span class="badge" id="domain"></span>
            <span class="badge" id="notice"></span>
          </div>
        </div>
        <aside class="status-summary">
          <h2>Status</h2>
          <p class="meta" id="status-time">Checking services</p>
          <div class="status-counts">
            <div class="count"><strong id="ok-count">0</strong><span class="meta">up</span></div>
            <div class="count"><strong id="bad-count">0</strong><span class="meta">down</span></div>
            <div class="count"><strong id="missing-count">0</strong><span class="meta">missing token</span></div>
          </div>
        </aside>
      </div>
    </section>
    <section class="band" id="services">
      <div class="band-inner">
        <div class="section-heading">
          <p class="eyebrow">What is running</p>
          <h2>The services in this lab, and how to call them.</h2>
          <p>Each card is a live Registry Stack service running on seeded demo data. The pill shows whether it is responding right now. Where a service needs a token, its public demo credentials and a ready-made curl command sit right here. They only reach seeded demo data, never a real or production system.</p>
        </div>
        <div class="grid" id="services-grid"></div>
      </div>
    </section>
    <section class="band band-muted" id="wallet">
      <div class="band-inner">
        <div class="section-heading">
          <p class="eyebrow">Wallet test</p>
          <h2>Issue a proof to the hosted wallet.</h2>
          <p>Start the citizen Notary flow, sign in as the demo citizen, then paste the generated credential offer into the hosted wallet. The wallet should receive a signed proof that the civil registry says the person is alive.</p>
        </div>
        <div class="wallet-grid" id="wallet-grid"></div>
      </div>
    </section>
  </main>
  <footer class="site-footer">
    <div>
      <a class="brand" href="https://registrystack.org/">
        <span class="brand-mark" aria-hidden="true">RS</span>
        <span>Registry Stack</span>
      </a>
      <p class="meta">Public demo environment for governed registry services.</p>
    </div>
  </footer>
  <script src="/static/homepage.js"></script>
</body>
</html>
""".encode("utf-8")




# Browser-hardening headers on every response (parity with the relay's
# restrictive CSP, registry-relay#87). The pages self-host all CSS/JS under
# /static/ and fetch only same-origin /api/ endpoints, so 'self' covers
# everything they need; anything else stays denied.
SECURITY_HEADERS = (
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'self'; script-src 'self'; "
        "img-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
)


class LabHomepageHandler(BaseHTTPRequestHandler):
    config: dict[str, Any] = {}
    status_timeout: float = 2.0
    lab_mode: str = "hosted"
    # Mask the BaseHTTP/Python banner; version details do not belong on a
    # public surface.
    server_version = "registry-lab"
    sys_version = ""

    def end_headers(self) -> None:
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        super().end_headers()

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self.send_bytes(homepage_html(self.config.get("title", "Registry Lab")), "text/html; charset=utf-8")
            return
        if path == "/favicon.svg":
            self.send_bytes(favicon_svg(), FAVICON_CONTENT_TYPE)
            return
        if path == "/favicon.ico":
            self.send_redirect("/favicon.svg")
            return
        if path.startswith("/static/"):
            # Match the requested name against the allowlist only. We never join the raw
            # request path onto the filesystem, so traversal attempts (../, %2e%2e) just
            # fail the allowlist check and fall through to a 404.
            name = path.removeprefix("/static/")
            content_type = STATIC_ASSETS.get(name)
            if content_type is not None:
                self.send_bytes(static_asset_bytes(name), content_type)
                return
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if path == "/scenarios":
            self.send_bytes(scenario_page_html(), "text/html; charset=utf-8")
            return
        if path.startswith("/scenarios/"):
            scenario_id = path.removeprefix("/scenarios/").strip("/")
            if scenario_id:
                self.send_bytes(
                    scenario_page_html(scenario_id=scenario_id),
                    "text/html; charset=utf-8",
                )
                return
        if path == "/healthz":
            self.send_json({"ok": True})
            return
        if path == "/api/lab.json":
            self.send_json(enrich_config(self.config))
            return
        if path == "/api/scenarios.json":
            self.send_json(scenario_payload(enrich_config(self.config), lab_mode=self.lab_mode))
            return
        if path.startswith("/api/scenarios/") and path.endswith(".json"):
            scenario_id = path.removeprefix("/api/scenarios/").removesuffix(".json")
            self.send_json(scenario_payload(enrich_config(self.config), scenario_id, lab_mode=self.lab_mode))
            return
        if path == "/api/status.json":
            self.send_json(status_checks(self.config, self.status_timeout))
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        prefix = "/api/scenarios/alive-proof/"
        if path.startswith(prefix):
            step_id = path.removeprefix(prefix)
            self.send_json(run_alive_proof_step(enrich_config(self.config), step_id, lab_mode=self.lab_mode))
            return
        scenario_prefix = "/api/scenarios/"
        if path.startswith(scenario_prefix):
            rest = path.removeprefix(scenario_prefix)
            scenario_id, sep, step_id = rest.partition("/")
            if sep and scenario_id and step_id:
                self.send_json(run_scenario_step(enrich_config(self.config), scenario_id, step_id, lab_mode=self.lab_mode))
                return
        self.send_error(HTTPStatus.NOT_FOUND)

    def send_json(self, value: Any) -> None:
        body = json.dumps(value, indent=2, sort_keys=True).encode("utf-8")
        self.send_bytes(body, "application/json; charset=utf-8")

    def send_bytes(self, body: bytes, content_type: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.MOVED_PERMANENTLY)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}", flush=True)


def verify_static_assets() -> None:
    """Fail loudly at startup if the static asset directory or any asset is missing.

    The pages link /static/*.css and /static/*.js; without those files the site renders
    unstyled and non-interactive. We refuse to start rather than serve broken pages.
    """
    if not STATIC_DIR.is_dir():
        raise SystemExit(
            f"static asset directory is missing: {STATIC_DIR}\n"
            "The homepage and scenario pages link /static/*.css and /static/*.js from this "
            "directory. It must sit beside lab-homepage-server.py (the deploy copies "
            "scripts/lab_homepage_static alongside the server). Aborting."
        )
    missing = [name for name in STATIC_ASSETS if not (STATIC_DIR / name).is_file()]
    if missing:
        raise SystemExit(
            f"static assets missing from {STATIC_DIR}: {', '.join(sorted(missing))}\n"
            "Aborting rather than serving broken pages."
        )


def main() -> int:
    verify_static_assets()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--env-file", type=Path, default=None)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--status-timeout", type=float, default=2.0)
    parser.add_argument(
        "--lab-mode",
        choices=("hosted", "local"),
        default=os.environ.get("LAB_HOMEPAGE_MODE", "hosted"),
    )
    args = parser.parse_args()

    env_file = args.env_file
    if env_file is None:
        # Default to the committed demo credentials file sitting beside the config file.
        candidate = args.config.with_name(DEFAULT_ENV_FILE.name)
        if candidate.exists():
            env_file = candidate
    if env_file is not None:
        apply_env_file(parse_env_file(env_file))

    config = load_config(args.config)
    LabHomepageHandler.config = config
    LabHomepageHandler.status_timeout = args.status_timeout
    LabHomepageHandler.lab_mode = args.lab_mode
    server = ThreadingHTTPServer((args.host, args.port), LabHomepageHandler)
    print(f"serving Registry Lab homepage on {args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
