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
  <style>
    :root {{
      color-scheme: light;
      --registry-blue: #173b7a;
      --registry-blue-dark: #102a56;
      --registry-teal: #0f766e;
      --registry-amber: #855b00;
      --registry-ink: #161616;
      --registry-body: #3a3a3a;
      --registry-muted: #6a6a6a;
      --registry-rule: #e5e5e5;
      --registry-sidebar: #fafafa;
      --registry-active: #eef3ff;
      --registry-code-bg: #f3f4f6;
      --registry-ok-bg: #edf7f2;
      --registry-bad-bg: #fff1f1;
      --registry-max: 1120px;
      --registry-font: "Public Sans", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --registry-mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }}
    * {{ box-sizing: border-box; letter-spacing: 0; }}
    html {{ background: #ffffff; color: var(--registry-body); font-family: var(--registry-font); scroll-behavior: smooth; }}
    body {{
      margin: 0;
      background: #ffffff;
      color: var(--registry-body);
      font: 14px/1.5 var(--registry-font);
    }}
    body, button, input, textarea {{ font: inherit; }}
    a {{ color: var(--registry-blue); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    :focus-visible {{ outline: 2px solid var(--registry-blue); outline-offset: 3px; }}
    .site-header {{
      align-items: center;
      background: rgba(255, 255, 255, 0.98);
      border-bottom: 1px solid var(--registry-rule);
      display: flex;
      gap: 24px;
      justify-content: space-between;
      padding: 14px clamp(16px, 4vw, 42px);
      position: sticky;
      top: 0;
      z-index: 10;
    }}
    .brand {{
      align-items: center;
      color: var(--registry-ink);
      display: inline-flex;
      font-size: 17px;
      font-weight: 700;
      gap: 12px;
      white-space: nowrap;
    }}
    .brand:hover {{ text-decoration: none; }}
    .brand-mark {{
      align-items: center;
      background: var(--registry-blue);
      color: #ffffff;
      display: inline-flex;
      font-family: var(--registry-mono);
      font-size: 13px;
      height: 34px;
      justify-content: center;
      width: 34px;
    }}
    .top-nav {{
      align-items: center;
      display: flex;
      flex-wrap: wrap;
      gap: clamp(12px, 2vw, 24px);
      justify-content: flex-end;
    }}
    .top-nav a {{
      align-items: center;
      color: var(--registry-muted);
      display: inline-flex;
      font-size: 14px;
      font-weight: 600;
      min-height: 36px;
    }}
    .top-nav .nav-emphasis {{ color: var(--registry-blue); }}
    .hero {{
      background: #ffffff;
      border-bottom: 1px solid var(--registry-rule);
    }}
    .hero-inner {{
      display: grid;
      gap: clamp(24px, 4vw, 44px);
      grid-template-columns: minmax(0, 1fr) minmax(260px, 340px);
      margin: 0 auto;
      max-width: var(--registry-max);
      padding: clamp(48px, 7vw, 86px) clamp(16px, 4vw, 42px) clamp(34px, 5vw, 58px);
    }}
    .eyebrow {{
      color: var(--registry-teal);
      font-family: var(--registry-mono);
      font-size: 12px;
      margin: 0 0 14px;
      text-transform: uppercase;
    }}
    h1, h2, h3, p {{ margin-top: 0; }}
    h1 {{
      color: var(--registry-ink);
      font-size: clamp(40px, 6vw, 70px);
      line-height: 1.02;
      margin: 0 0 22px;
      max-width: 820px;
    }}
    h2 {{
      color: var(--registry-ink);
      font-size: clamp(24px, 3vw, 36px);
      line-height: 1.05;
      margin: 0 0 18px;
    }}
    h3 {{
      color: var(--registry-ink);
      font-size: 18px;
      line-height: 1.2;
      margin: 0 0 10px;
    }}
    p {{ line-height: 1.58; margin: 0; }}
    .subtitle {{
      color: var(--registry-body);
      font-size: clamp(17px, 2vw, 22px);
      line-height: 1.42;
      max-width: 760px;
    }}
    .badge-row {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 28px; }}
    .badge {{
      border: 1px solid var(--registry-rule);
      color: var(--registry-ink);
      display: inline-flex;
      align-items: center;
      font-size: 14px;
      font-weight: 700;
      min-height: 38px;
      padding: 8px 10px;
      white-space: nowrap;
    }}
    .hero-note {{ color: var(--registry-body); font-size: 15px; margin-top: 18px; max-width: 620px; }}
    .hero-links {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 22px; }}
    .status-summary {{
      background: var(--registry-sidebar);
      border: 1px solid var(--registry-rule);
      min-width: 0;
      padding: 20px;
    }}
    .status-summary h2 {{ font-size: 22px; margin-bottom: 8px; }}
    .status-counts {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 0; margin-top: 18px; border: 1px solid var(--registry-rule); }}
    .count {{ background: #ffffff; border-left: 1px solid var(--registry-rule); padding: 12px 8px; text-align: center; }}
    .count:first-child {{ border-left: 0; }}
    .count strong {{ color: var(--registry-ink); display: block; font-size: 24px; line-height: 1; }}
    main {{ display: block; }}
    .band {{
      background: #ffffff;
      border-bottom: 1px solid var(--registry-rule);
    }}
    .band-muted {{ background: var(--registry-sidebar); }}
    .band-inner {{
      margin: 0 auto;
      max-width: var(--registry-max);
      padding: clamp(42px, 6vw, 70px) clamp(16px, 4vw, 42px);
    }}
    .section-heading {{
      margin-bottom: 28px;
      max-width: 800px;
    }}
    .section-heading p:not(.eyebrow) {{ color: var(--registry-body); font-size: 17px; max-width: 760px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
    .pill {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 88px;
      min-height: 32px;
      padding: 6px 9px;
      border: 1px solid var(--registry-rule);
      color: var(--registry-muted);
      background: #ffffff;
      font-family: var(--registry-mono);
      font-size: 12px;
    }}
    .pill.ok {{ color: var(--registry-teal); border-color: var(--registry-teal); background: var(--registry-ok-bg); }}
    .pill.bad {{ color: #a22d2d; border-color: #d9a1a1; background: var(--registry-bad-bg); }}
    .credential {{
      display: grid;
      gap: 14px;
      padding: 20px;
      border: 1px solid var(--registry-rule);
      background: #fff;
      min-width: 0;
    }}
    .credential h3::before {{
      background: var(--registry-blue);
      content: "";
      display: block;
      height: 3px;
      margin-bottom: 16px;
      width: 28px;
    }}
    .meta {{ color: var(--registry-muted); font-size: 13px; }}
    .token-box {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      align-items: center;
      min-width: 0;
    }}
    code, pre {{
      font-family: var(--registry-mono);
      font-size: 12px;
      letter-spacing: 0;
    }}
    code.token {{
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      border: 1px solid var(--registry-rule);
      color: var(--registry-ink);
      padding: 10px;
      background: var(--registry-code-bg);
    }}
    pre {{
      overflow: auto;
      margin: 0;
      border: 1px solid var(--registry-rule);
      color: var(--registry-ink);
      padding: 12px;
      background: var(--registry-code-bg);
      max-height: 140px;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    button, .button {{
      align-items: center;
      border: 1px solid var(--registry-blue);
      display: inline-flex;
      font-weight: 700;
      justify-content: center;
      min-height: 36px;
      padding: 7px 12px;
      background: #fff;
      color: var(--registry-blue);
      cursor: pointer;
      font: inherit;
      white-space: nowrap;
    }}
    button:hover, .button:hover {{ background: var(--registry-active); text-decoration: none; }}
    .primary {{ background: var(--registry-blue); border-color: var(--registry-blue); color: #fff; }}
    .primary:hover {{ background: var(--registry-blue-dark); }}
    .wallet-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }}
    .kv {{ display: grid; gap: 6px; padding: 18px; border: 1px solid var(--registry-rule); background: #ffffff; }}
    .kv span {{ color: var(--registry-teal); font-family: var(--registry-mono); font-size: 12px; text-transform: uppercase; letter-spacing: 0; }}
    .kv strong {{ color: var(--registry-ink); overflow-wrap: anywhere; }}
    .actions {{ display: flex; gap: 10px; flex-wrap: wrap; }}
    .step-list {{ display: grid; gap: 12px; grid-column: 1 / -1; }}
    .step-card {{
      align-items: start;
      background: #ffffff;
      border: 1px solid var(--registry-rule);
      display: grid;
      gap: 14px;
      grid-template-columns: 34px minmax(0, 1fr);
      padding: 18px;
    }}
    .step-number {{
      align-items: center;
      background: var(--registry-blue);
      color: #ffffff;
      display: inline-flex;
      font-family: var(--registry-mono);
      font-size: 13px;
      font-weight: 700;
      height: 34px;
      justify-content: center;
      width: 34px;
    }}
    .step-card p {{ color: var(--registry-muted); }}
    /* One service per row; its credentials tile inside so wide services use the space. */
    #services-grid {{ grid-template-columns: 1fr; }}
    .status-row {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
    .cred-list {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 18px;
      align-items: start;
      border-top: 1px solid var(--registry-rule);
      padding-top: 18px;
    }}
    .cred-block {{ display: grid; gap: 10px; min-width: 0; align-content: start; }}
    .cred-name {{ color: var(--registry-ink); font-weight: 700; }}
    .hidden {{ display: none; }}
    .site-footer {{
      align-items: start;
      display: flex;
      gap: 24px;
      justify-content: space-between;
      margin: 0 auto;
      max-width: var(--registry-max);
      padding: 32px clamp(16px, 4vw, 42px);
    }}
    @media (max-width: 760px) {{
      .site-header {{ align-items: flex-start; flex-direction: column; }}
      .top-nav {{ justify-content: flex-start; }}
      .hero-inner {{ grid-template-columns: 1fr; }}
      .token-box {{ grid-template-columns: 1fr; }}
    }}
  </style>
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
  <script>
    const text = (value) => value == null ? "" : String(value);
    const byId = (id) => document.getElementById(id);

    function escapeHtml(value) {{
      return text(value).replace(/[&<>"']/g, (char) => ({{
        "&": "&amp;", "<": "&lt;", ">": "&gt;", "\\"": "&quot;", "'": "&#39;"
      }}[char]));
    }}

    async function copyValue(value, button) {{
      await navigator.clipboard.writeText(value);
      const previous = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => button.textContent = previous, 1200);
    }}

    function renderWallet(wallet) {{
      const issuer = wallet.issuer || "";
      const credentialConfigurationId = wallet.credential_configuration_id || "";
      const offerStart = wallet.offer_start_url || (
        issuer && credentialConfigurationId
          ? `${{issuer.replace(/\\/$/, "")}}/oid4vci/offer/start?credential_configuration_id=${{encodeURIComponent(credentialConfigurationId)}}`
          : wallet.offer_url || ""
      );
      const walletUrl = wallet.wallet_url || "https://wallet.lab.registrystack.org/signup";
      const identity = wallet.demo_identity || {{}};
      const negative = wallet.negative_control || {{}};
      byId("wallet-grid").innerHTML = `
        <div class="step-list" aria-label="Wallet issuance steps">
          <div class="step-card"><span class="step-number">1</span><div><strong>Open the hosted wallet.</strong><p>Create or open a demo wallet, then use its scan or import-offer screen.</p><div class="actions"><a class="button" href="${{escapeHtml(walletUrl)}}" target="_blank" rel="noreferrer">Open wallet</a><button type="button" data-copy="${{escapeHtml(walletUrl)}}">Copy wallet URL</button></div></div></div>
          <div class="step-card"><span class="step-number">2</span><div><strong>Start credential issuance.</strong><p>The Notary will redirect to eSignet before it renders the wallet offer.</p><div class="actions"><a class="button primary" href="${{escapeHtml(offerStart)}}" target="_blank" rel="noreferrer">Start issuance</a><button type="button" data-copy="${{escapeHtml(offerStart)}}">Copy start URL</button></div></div></div>
          <div class="step-card"><span class="step-number">3</span><div><strong>Copy the generated offer into the wallet.</strong><p>After login, copy the <code>openid-credential-offer://</code> URI from the Notary page and paste it into the wallet scan/import screen within 300 seconds. The hosted demo no longer requires a separate issuer PIN.</p></div></div>
        </div>
        <div class="kv"><span>Sign in as</span><strong>${{escapeHtml(identity.name)}}</strong><div class="meta">Use ID ${{escapeHtml(identity.identifier)}}, OTP ${{escapeHtml(identity.generated_code)}}, and PIN ${{escapeHtml(identity.pin)}} if eSignet asks.</div></div>
        <div class="kv"><span>Your wallet should receive</span><strong>${{escapeHtml(wallet.credential_name || wallet.credential_configuration_id)}}</strong><div class="meta">${{escapeHtml(identity.expected_result || wallet.user_story || "")}}</div></div>
        <div class="kv"><span>Why this matters</span><strong>A service gets a yes/no proof, not the full civil record.</strong><div class="meta">${{escapeHtml(wallet.user_story || "")}}</div></div>
        <div class="kv"><span>Test a rejected case</span><strong>${{escapeHtml(negative.identifier)}}</strong><div class="meta">${{escapeHtml(negative.expected_result)}}</div></div>
        <div class="kv"><span>For developers</span><strong>Issuer and credential type</strong><div class="meta">${{escapeHtml(issuer)}} &middot; ${{escapeHtml(credentialConfigurationId)}}</div></div>
      `;
    }}

    function credentialBlock(credential) {{
      const scopes = (credential.scopes || []).join(", ");
      const token = credential.token || "";
      const curl = credential.curl || "";
      const headerRows = Object.entries(credential.required_headers || {{}})
        .map(([key, value]) => `<div class="meta">${{escapeHtml(key)}}: ${{escapeHtml(value)}}</div>`)
        .join("");
      return `
        <div class="cred-block">
          <div>
            <div class="cred-name">${{escapeHtml(credential.label)}}</div>
            <div class="meta">${{escapeHtml(scopes)}}</div>
            ${{headerRows}}
          </div>
          <div class="token-box">
            <code class="token" title="${{escapeHtml(token)}}">${{escapeHtml(token || "Missing env value")}}</code>
            <button type="button" data-copy="${{escapeHtml(token)}}" ${{token ? "" : "disabled"}}>Copy token</button>
          </div>
          <pre>${{escapeHtml(curl)}}</pre>
          <div class="actions">
            <button type="button" data-copy="${{escapeHtml(curl)}}">Copy curl</button>
          </div>
        </div>
      `;
    }}

    function renderServices(services) {{
      byId("services-grid").innerHTML = services.map((service) => {{
        const creds = (service.credentials || []).map(credentialBlock).join("");
        // The Open link starts hidden; loadStatus reveals it only when the service is
        // reachable and not auth-gated, so we never link to a 401 page or a dead host.
        return `
          <article class="credential">
            <div>
              <h3>${{escapeHtml(service.label)}}</h3>
              <div class="meta">${{escapeHtml(service.purpose || "")}}</div>
            </div>
            <div class="status-row">
              <span class="pill" data-status-for="${{escapeHtml(service.id)}}">checking</span>
              <a class="button hidden" data-open-for="${{escapeHtml(service.id)}}" href="${{escapeHtml(service.url)}}" target="_blank" rel="noreferrer">Open</a>
            </div>
            ${{creds ? `<div class="cred-list">${{creds}}</div>` : ""}}
          </article>
        `;
      }}).join("");
    }}

    function wireCopyButtons() {{
      document.querySelectorAll("[data-copy]").forEach((button) => {{
        if (button.dataset.copyWired === "true") return;
        button.dataset.copyWired = "true";
        button.addEventListener("click", () => copyValue(button.getAttribute("data-copy") || "", button));
      }});
    }}

    async function loadStatus() {{
      try {{
        const response = await fetch("/api/status.json", {{cache: "no-store"}});
        const status = await response.json();
        let ok = 0;
        let bad = 0;
        for (const check of status.checks || []) {{
          const node = document.querySelector(`[data-status-for="${{CSS.escape(check.id)}}"]`);
          const openNode = document.querySelector(`[data-open-for="${{CSS.escape(check.id)}}"]`);
          // Only offer the Open link when there is something to see: the service is up and its
          // base URL is browsable unauthenticated. A token-gated API or a down host shows nothing.
          if (openNode) openNode.classList.toggle("hidden", !(check.ok && check.browsable));
          if (check.ok) {{
            ok += 1;
            if (node) {{
              node.textContent = check.auth_gated ? "up - auth required" : `up - ${{check.status_code}}`;
              node.className = "pill ok";
            }}
          }} else {{
            bad += 1;
            if (node) {{
              node.textContent = check.status_code ? `down - ${{check.status_code}}` : `down`;
              node.className = "pill bad";
            }}
          }}
        }}
        byId("ok-count").textContent = ok;
        byId("bad-count").textContent = bad;
        byId("status-time").textContent = "Checked just now";
      }} catch (error) {{
        byId("status-time").textContent = "Status unavailable";
      }}
    }}

    async function start() {{
      const response = await fetch("/api/lab.json", {{cache: "no-store"}});
      const data = await response.json();
      byId("title").textContent = data.title || "Registry Lab";
      byId("subtitle").textContent = data.subtitle || "";
      byId("domain").textContent = data.environment?.domain || "";
      byId("notice").textContent = data.environment?.notice || "";
      byId("missing-count").textContent = (data.credentials || []).filter((credential) => !credential.configured).length;
      renderServices(data.services || []);
      renderWallet(data.wallet || {{}});
      wireCopyButtons();
      loadStatus();
    }}
    start();
  </script>
</body>
</html>
""".encode("utf-8")


class LabHomepageHandler(BaseHTTPRequestHandler):
    config: dict[str, Any] = {}
    status_timeout: float = 2.0

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self.send_bytes(homepage_html(self.config.get("title", "Registry Lab")), "text/html; charset=utf-8")
            return
        if path == "/scenarios":
            self.send_bytes(scenario_page_html("Registry Lab Scenarios"), "text/html; charset=utf-8")
            return
        if path.startswith("/scenarios/"):
            scenario_id = path.removeprefix("/scenarios/").strip("/")
            if scenario_id:
                self.send_bytes(
                    scenario_page_html("Registry Lab Scenarios", scenario_id),
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
            self.send_json(scenario_payload(enrich_config(self.config)))
            return
        if path.startswith("/api/scenarios/") and path.endswith(".json"):
            scenario_id = path.removeprefix("/api/scenarios/").removesuffix(".json")
            self.send_json(scenario_payload(enrich_config(self.config), scenario_id))
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
            self.send_json(run_alive_proof_step(enrich_config(self.config), step_id))
            return
        scenario_prefix = "/api/scenarios/"
        if path.startswith(scenario_prefix):
            rest = path.removeprefix(scenario_prefix)
            scenario_id, sep, step_id = rest.partition("/")
            if sep and scenario_id and step_id:
                self.send_json(run_scenario_step(enrich_config(self.config), scenario_id, step_id))
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

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--env-file", type=Path, default=None)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--status-timeout", type=float, default=2.0)
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
    server = ThreadingHTTPServer((args.host, args.port), LabHomepageHandler)
    print(f"serving Registry Lab homepage on {args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
