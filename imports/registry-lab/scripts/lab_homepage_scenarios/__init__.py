#!/usr/bin/env python3
"""Guided scenario surface for Registry Lab."""

from __future__ import annotations

import html
import json
from typing import Any

from . import agriculture_voucher, civil_alive, combined_support, dhis2_programme, social_aggregate, wallet_vc


SCENARIOS = [
    civil_alive,
    wallet_vc,
    dhis2_programme,
    social_aggregate,
    combined_support,
    agriculture_voucher,
]
STORY_BY_ID = {module.SCENARIO_ID: module for module in SCENARIOS}


def all_stories() -> list[dict[str, Any]]:
    return [module.story() for module in SCENARIOS]


def _is_runnable(story: dict[str, Any], lab_mode: str) -> bool:
    return story.get("availability", "hosted") == "hosted" or lab_mode == "local"


def scenario_payload(config: dict[str, Any], scenario_id: str | None = None, lab_mode: str = "hosted") -> dict[str, Any]:
    if scenario_id:
        module = STORY_BY_ID.get(scenario_id)
        if not module:
            return {"error": "unknown_scenario", "scenario_id": scenario_id}
        story = module.story()
        return {"story": story, "lab_mode": lab_mode, "runnable": _is_runnable(story, lab_mode)}
    return {
        "lab_mode": lab_mode,
        "default_scenario_id": civil_alive.SCENARIO_ID,
        "scenarios": [
            {
                "id": story["id"],
                "title": story["short_title"],
                "full_title": story["title"],
                "proves": story["proves"],
                "availability": story.get("availability", "hosted"),
                "availability_note": story.get("availability_note", ""),
                "steps": len(story.get("steps", [])),
                "runnable": _is_runnable(story, lab_mode),
            }
            for story in all_stories()
        ],
    }


_LOCAL_ONLY_NOTE = "Available when the story runs on the local lab profile."


def run_scenario_step(config: dict[str, Any], scenario_id: str, step_id: str, lab_mode: str = "hosted") -> dict[str, Any]:
    module = STORY_BY_ID.get(scenario_id)
    if not module:
        return {
            "step_id": step_id,
            "friendly": {
                "title": "Unknown scenario.",
                "message": "This scenario is not configured.",
                "status": "needs_attention",
                "facts": [{"label": "Scenario", "value": scenario_id}],
            },
            "request_source": {},
            "response_source": {},
        }
    story = module.story()
    if lab_mode == "hosted" and story.get("availability") == "local-only":
        short_title = story.get("short_title") or story.get("title", scenario_id)
        return {
            "step_id": step_id,
            "friendly": {
                "status": "local_only",
                "title": f"{short_title} runs on the local lab profile.",
                "message": (
                    "The hosted lab does not run the services this story needs, so this step cannot execute here. "
                    "Clone registry-lab and start the local profile to run it for real."
                ),
                "facts": [
                    {"label": "Availability", "value": "Local only"},
                    {"label": "Run it locally", "value": "https://github.com/jeremi/registry-lab"},
                ],
            },
            "request_source": {"note": _LOCAL_ONLY_NOTE},
            "response_source": {"note": _LOCAL_ONLY_NOTE},
        }
    return module.run_step(config, step_id)


def run_alive_proof_step(config: dict[str, Any], step_id: str, lab_mode: str = "hosted") -> dict[str, Any]:
    return run_scenario_step(config, civil_alive.SCENARIO_ID, step_id, lab_mode=lab_mode)


def scenario_nav_link() -> str:
    return '<a href="/scenarios">Scenario demos</a>'


def scenario_page_html(title: str = "Registry Lab Scenarios", scenario_id: str | None = None) -> bytes:
    safe_title = html.escape(title)
    active_scenario = json.dumps(scenario_id or "")
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
      --registry-warn-bg: #fff7e8;
      --registry-bad-bg: #fff1f1;
      --registry-max: 1080px;
      --registry-font: "Public Sans", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --registry-mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }}
    * {{ box-sizing: border-box; letter-spacing: 0; }}
    html {{ background: #ffffff; color: var(--registry-body); font-family: var(--registry-font); scroll-behavior: smooth; }}
    body {{ margin: 0; background: #ffffff; color: var(--registry-body); font: 14px/1.5 var(--registry-font); }}
    body, button {{ font: inherit; }}
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
    .brand {{ align-items: center; color: var(--registry-ink); display: inline-flex; font-size: 17px; font-weight: 700; gap: 12px; white-space: nowrap; }}
    .brand:hover {{ text-decoration: none; }}
    .brand-mark {{ align-items: center; background: var(--registry-blue); color: #ffffff; display: inline-flex; font-family: var(--registry-mono); font-size: 13px; height: 34px; justify-content: center; width: 34px; }}
    .top-nav {{ align-items: center; display: flex; flex-wrap: wrap; gap: clamp(12px, 2vw, 24px); justify-content: flex-end; }}
    .top-nav a {{ align-items: center; color: var(--registry-muted); display: inline-flex; font-size: 14px; font-weight: 600; min-height: 36px; }}
    .hero {{ background: #ffffff; border-bottom: 1px solid var(--registry-rule); }}
    .hero-inner {{ margin: 0 auto; max-width: var(--registry-max); padding: clamp(34px, 6vw, 62px) clamp(16px, 4vw, 42px); }}
    .eyebrow {{ color: var(--registry-teal); font-family: var(--registry-mono); font-size: 12px; margin: 0 0 14px; text-transform: uppercase; }}
    h1, h2, h3, h4, p {{ margin-top: 0; }}
    h1 {{ color: var(--registry-ink); font-size: clamp(34px, 5vw, 58px); line-height: 1.04; margin: 0 0 18px; max-width: 920px; }}
    h2 {{ color: var(--registry-ink); font-size: clamp(22px, 3vw, 32px); line-height: 1.1; margin: 0 0 14px; }}
    h3 {{ color: var(--registry-ink); font-size: 20px; line-height: 1.2; margin: 0; }}
    h4 {{ color: var(--registry-ink); font-size: 16px; margin: 0 0 6px; }}
    p {{ line-height: 1.58; margin: 0; }}
    .subtitle {{ color: var(--registry-body); font-size: clamp(17px, 2vw, 21px); line-height: 1.45; max-width: 820px; }}
    .band {{ background: var(--registry-sidebar); }}
    .band-inner {{ margin: 0 auto; max-width: var(--registry-max); padding: clamp(30px, 5vw, 52px) clamp(16px, 4vw, 42px); }}
    .chooser-grid {{ display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); }}
    .scenario-card, .story-setup, .step, .receipt {{ background: #ffffff; border: 1px solid var(--registry-rule); }}
    .scenario-card {{ display: grid; gap: 12px; padding: 18px; }}
    .scenario-card h2 {{ font-size: 20px; margin-bottom: 2px; }}
    .card-meta {{ color: var(--registry-muted); font-size: 13px; }}
    .availability {{ border: 1px solid var(--registry-rule); color: var(--registry-muted); display: inline-flex; font-family: var(--registry-mono); font-size: 12px; min-height: 30px; padding: 5px 8px; width: fit-content; }}
    .availability.hosted {{ background: var(--registry-ok-bg); border-color: #b7ddc9; color: var(--registry-teal); }}
    .availability.local-only {{ background: var(--registry-warn-bg); border-color: #e2b66c; color: var(--registry-amber); }}
    .story-setup {{ display: grid; gap: 14px; margin-bottom: 18px; padding: 18px; }}
    .local-run {{ border-top: 2px solid var(--registry-amber); }}
    .local-run .eyebrow {{ color: var(--registry-amber); }}
    .local-run pre {{ margin-top: 10px; }}
    .local-run .meta {{ margin-top: 8px; }}
    .setup-grid {{ display: grid; gap: 10px; grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .setup-item, .fact {{ border: 1px solid var(--registry-rule); display: grid; gap: 4px; padding: 12px; }}
    .setup-item span, .fact span {{ color: var(--registry-muted); font-family: var(--registry-mono); font-size: 12px; text-transform: uppercase; }}
    .setup-item strong, .fact strong {{ color: var(--registry-ink); overflow-wrap: anywhere; }}
    .step-list {{ display: grid; gap: 14px; }}
    .step.locked {{ opacity: .62; }}
    .step-head {{ align-items: start; border-bottom: 1px solid var(--registry-rule); display: grid; gap: 14px; grid-template-columns: 42px minmax(0, 1fr) auto; padding: 18px; }}
    .step-number {{ align-items: center; background: var(--registry-blue); color: #ffffff; display: inline-flex; font-family: var(--registry-mono); font-weight: 700; height: 36px; justify-content: center; width: 36px; }}
    .status-pill {{ border: 1px solid var(--registry-rule); color: var(--registry-muted); display: inline-flex; font-family: var(--registry-mono); font-size: 12px; min-height: 30px; padding: 5px 8px; white-space: nowrap; }}
    .status-pill.done, .status-pill.denied_as_expected {{ background: var(--registry-ok-bg); border-color: #b7ddc9; color: var(--registry-teal); }}
    .status-pill.running {{ background: var(--registry-warn-bg); border-color: #e2b66c; color: var(--registry-amber); }}
    @media (prefers-reduced-motion: no-preference) {{
      .status-pill.running::before {{ animation: pill-spin .7s linear infinite; border: 2px solid var(--registry-amber); border-top-color: transparent; border-radius: 50%; content: ""; display: inline-block; height: 10px; margin-right: 6px; width: 10px; }}
      @keyframes pill-spin {{ to {{ transform: rotate(360deg); }} }}
    }}
    .status-pill.local_only {{ background: var(--registry-warn-bg); border-color: #e2b66c; color: var(--registry-amber); }}
    .status-pill.needs_attention {{ background: var(--registry-bad-bg); border-color: #d9a1a1; color: #a22d2d; }}
    .step-body {{ display: grid; gap: 14px; padding: 18px; }}
    .request-text {{ background: var(--registry-code-bg); border: 1px solid var(--registry-rule); color: var(--registry-ink); padding: 12px; }}
    .reuse-box {{ background: #ffffff; border: 1px solid #b7c7dd; display: grid; gap: 10px; padding: 12px; }}
    .friendly-response {{ background: var(--registry-ok-bg); border: 1px solid #b7ddc9; display: none; gap: 12px; padding: 14px; }}
    .friendly-response.visible {{ display: grid; }}
    .friendly-response.needs_attention {{ background: var(--registry-bad-bg); border-color: #d9a1a1; }}
    .facts {{ display: grid; gap: 8px; grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .fact {{ background: #ffffff; border-color: rgba(0, 0, 0, .08); padding: 10px; }}
    .actions {{ display: flex; gap: 10px; flex-wrap: wrap; }}
    button, .button {{ align-items: center; background: #fff; border: 1px solid var(--registry-blue); color: var(--registry-blue); cursor: pointer; display: inline-flex; font-weight: 700; justify-content: center; min-height: 38px; padding: 8px 12px; white-space: nowrap; }}
    button:hover, .button:hover {{ background: var(--registry-active); text-decoration: none; }}
    button:disabled, button[aria-disabled="true"] {{ border-color: var(--registry-rule); color: var(--registry-muted); cursor: not-allowed; }}
    .primary {{ background: var(--registry-blue); border-color: var(--registry-blue); color: #fff; }}
    .primary:hover {{ background: var(--registry-blue-dark); }}
    details {{ border-top: 1px solid var(--registry-rule); }}
    summary {{ color: var(--registry-blue); cursor: pointer; font-weight: 700; padding: 12px 0 0; }}
    code, pre {{ font-family: var(--registry-mono); font-size: 12px; letter-spacing: 0; }}
    pre {{ background: var(--registry-code-bg); border: 1px solid var(--registry-rule); color: var(--registry-ink); margin: 10px 0 0; max-height: 300px; overflow: auto; padding: 12px; white-space: pre-wrap; word-break: break-word; }}
    .source-card {{ background: #ffffff; border: 1px solid var(--registry-rule); display: grid; gap: 12px; margin-top: 10px; padding: 12px; }}
    .source-line {{ background: var(--registry-code-bg); border: 1px solid var(--registry-rule); color: var(--registry-ink); font-family: var(--registry-mono); font-size: 12px; overflow-wrap: anywhere; padding: 10px; }}
    .source-section {{ display: grid; gap: 8px; }}
    .source-section h4 {{ color: var(--registry-muted); font-size: 12px; margin: 0; text-transform: uppercase; }}
    .source-table {{ border: 1px solid var(--registry-rule); display: grid; }}
    .source-row {{ display: grid; gap: 10px; grid-template-columns: minmax(118px, 180px) minmax(0, 1fr); padding: 9px 10px; }}
    .source-row + .source-row {{ border-top: 1px solid var(--registry-rule); }}
    .source-label, .source-value {{ font-family: var(--registry-mono); font-size: 12px; overflow-wrap: anywhere; }}
    .source-label {{ color: var(--registry-muted); }}
    .source-value {{ color: var(--registry-ink); }}
    .source-code {{ margin: 0; max-height: 360px; }}
    .source-note, .meta {{ color: var(--registry-muted); font-size: 13px; }}
    .source-toolbar {{ display: flex; justify-content: flex-end; }}
    .copy-curl {{ min-height: 32px; padding: 6px 10px; }}
    .receipt {{ display: none; gap: 14px; margin-top: 18px; padding: 18px; }}
    .receipt.visible {{ display: grid; }}
    .site-footer {{ margin: 0 auto; max-width: var(--registry-max); padding: 28px clamp(16px, 4vw, 42px); }}
    @media (max-width: 760px) {{
      .site-header {{ align-items: flex-start; flex-direction: column; }}
      .top-nav {{ justify-content: flex-start; }}
      .setup-grid, .facts {{ grid-template-columns: 1fr; }}
      .step-head {{ grid-template-columns: 42px minmax(0, 1fr); }}
      .status-pill {{ grid-column: 2; justify-self: start; }}
      .source-row {{ grid-template-columns: 1fr; }}
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
      <a href="/">Home</a>
      <a href="/scenarios">Scenario demos</a>
      <a href="/#services">Services &amp; credentials</a>
      <a href="/#wallet">Wallet test</a>
    </nav>
  </header>
  <main>
    <section class="hero" aria-labelledby="title">
      <div class="hero-inner">
        <p class="eyebrow" id="eyebrow">Guided demo</p>
        <h1 id="title">Choose a story to run step by step.</h1>
        <p class="subtitle" id="subtitle">Each story starts in plain language, runs requests one at a time, and keeps JSON hidden until you ask for the source.</p>
      </div>
    </section>
    <section class="band">
      <div class="band-inner">
        <div id="chooser"></div>
        <div id="story"></div>
      </div>
    </section>
  </main>
  <footer class="site-footer">
    <a class="brand" href="https://registrystack.org/">
      <span class="brand-mark" aria-hidden="true">RS</span>
      <span>Registry Stack</span>
    </a>
    <p class="meta">Public demo environment for governed registry services.</p>
  </footer>
  <script>
    const ACTIVE_SCENARIO = {active_scenario};
    const text = (value) => value == null ? "" : String(value);
    const byId = (id) => document.getElementById(id);
    const state = {{ completed: new Set(), story: null, runnable: true }};

    function escapeHtml(value) {{
      return text(value).replace(/[&<>"']/g, (char) => ({{
        "&": "&amp;", "<": "&lt;", ">": "&gt;", "\\"": "&quot;", "'": "&#39;"
      }}[char]));
    }}

    function prettyJson(value) {{
      if (typeof value === "string") return value;
      return JSON.stringify(value ?? {{}}, null, 2);
    }}

    function compactJson(value) {{
      if (typeof value === "string") return value;
      return JSON.stringify(value ?? {{}});
    }}

    function shellQuote(value) {{
      return "'" + text(value).replace(/'/g, "'\\"'\\"'") + "'";
    }}

    function curlCommand(value) {{
      const method = value.method || "GET";
      const parts = ["curl", "-X", shellQuote(method), shellQuote(value.url || "")];
      for (const [name, headerValue] of Object.entries(value.headers || {{}})) {{
        parts.push("-H", shellQuote(`${{name}}: ${{headerValue}}`));
      }}
      if (value.body != null) parts.push("--data", shellQuote(compactJson(value.body)));
      return parts.join(" ");
    }}

    function sourceRows(entries) {{
      const rows = Object.entries(entries || {{}});
      if (!rows.length) return `<div class="source-note">No values captured.</div>`;
      return `<div class="source-table">${{rows.map(([name, value]) => `
        <div class="source-row"><div class="source-label">${{escapeHtml(name)}}</div><div class="source-value">${{escapeHtml(value)}}</div></div>
      `).join("")}}</div>`;
    }}

    function sourceSection(title, content) {{
      if (!content) return "";
      return `<div class="source-section"><h4>${{escapeHtml(title)}}</h4>${{content}}</div>`;
    }}

    function renderRequestSource(value) {{
      const canCurl = value.method && value.method !== "SIMULATE" && value.url && !value.internal;
      return `<div class="source-card">
        ${{canCurl ? `<div class="source-toolbar"><button class="copy-curl" type="button" data-copy-curl="${{escapeHtml(curlCommand(value))}}">Copy as curl</button></div>` : ""}}
        ${{value.internal ? `<div class="source-note">Internal lab call. It authenticates with a runtime-only credential that is never published, so there is no runnable curl for it.</div>` : ""}}
        <div class="source-line">${{escapeHtml(value.method || "")}} ${{escapeHtml(value.url || "")}}</div>
        ${{sourceSection("Headers", sourceRows(value.headers || {{}}))}}
        ${{value.body == null ? "" : sourceSection("Body", `<pre class="source-code">${{escapeHtml(prettyJson(value.body))}}</pre>`)}}
      </div>`;
    }}

    function renderResponseSource(value, reused) {{
      const status = value.status == null ? "No HTTP status" : value.status;
      return `<div class="source-card">
        ${{reused ? sourceSection("Reused from discovery", sourceRows(reused)) : ""}}
        <div class="source-line">HTTP status ${{escapeHtml(status)}}</div>
        ${{sourceSection("Headers", sourceRows(value.headers || {{}}))}}
        ${{sourceSection("Body", `<pre class="source-code">${{escapeHtml(prettyJson(value.body))}}</pre>`)}}
        ${{value.error ? sourceSection("Client error", `<div class="source-note">${{escapeHtml(value.error)}}</div>`) : ""}}
      </div>`;
    }}

    function sourceBlock(value) {{
      const source = value || {{}};
      if (source.note) return `<div class="source-card"><div class="source-note">${{escapeHtml(source.note)}}</div></div>`;
      if (source.evaluation && source.render) {{
        return `
          <div class="source-section">
            <h4>Evaluation</h4>
            ${{sourceBlock(source.evaluation)}}
          </div>
          <div class="source-section">
            <h4>Render</h4>
            ${{sourceBlock(source.render)}}
          </div>
        `;
      }}
      if (source.method && source.url) return renderRequestSource(source);
      if (source.http) return renderResponseSource(source.http, source.reused_from_discovery);
      if ("status" in source || "headers" in source || "body" in source || "error" in source) return renderResponseSource(source);
      return `<pre class="source-code">${{escapeHtml(prettyJson(source))}}</pre>`;
    }}

    function renderFacts(facts) {{
      return (facts || []).map((fact) => `<div class="fact"><span>${{escapeHtml(fact.label)}}</span><strong>${{escapeHtml(fact.value)}}</strong></div>`).join("");
    }}

    function renderChooser(items) {{
      byId("chooser").innerHTML = `<section class="chooser-grid" aria-label="Scenario chooser">
        ${{items.map((item) => `<article class="scenario-card">
          <span class="availability ${{escapeHtml(item.availability)}}">${{escapeHtml(item.availability === "local-only" ? "Local only" : "Hosted")}}</span>
          <div><h2>${{escapeHtml(item.title)}}</h2><p>${{escapeHtml(item.proves)}}</p></div>
          ${{item.availability_note ? `<p class="card-meta">${{escapeHtml(item.availability_note)}}</p>` : ""}}
          <p class="card-meta">${{escapeHtml(item.steps)}} steps</p>
          <div class="actions"><a class="button primary" href="/scenarios/${{encodeURIComponent(item.id)}}">${{item.runnable ? "Open story" : "Read the walkthrough"}}</a></div>
        </article>`).join("")}}
      </section>`;
    }}

    function renderReuse(items) {{
      if (!items || !items.length) return "";
      return `<div class="reuse-box"><h4>Reuses from the previous step</h4><div class="facts">${{renderFacts(items)}}</div></div>`;
    }}

    function canRun(index) {{
      if (index === 0) return true;
      return state.completed.has(state.story.steps[index - 1].id);
    }}

    function statusLabel(status) {{
      if (status === "done") return "Done";
      if (status === "running") return "Running";
      if (status === "denied_as_expected") return "Denied as expected";
      if (status === "needs_attention") return "Needs attention";
      if (status === "local_only") return "Local only";
      return "Not run";
    }}

    function renderLocalOnlyBlock(story) {{
      return `
        <div class="story-setup local-run">
          <div>
            <p class="eyebrow">Run this story on your machine</p>
            <p>The hosted lab does not run the services this story needs. Clone the repository, start the local lab profile, then open this page from your local homepage.</p>
            <pre>git clone https://github.com/jeremi/registry-lab</pre>
            ${{story.availability_note ? `<p class="meta">${{escapeHtml(story.availability_note)}}</p>` : ""}}
          </div>
        </div>
      `;
    }}

    function renderStory(story, runnable) {{
      state.story = story;
      state.runnable = runnable !== false;
      byId("chooser").innerHTML = "";
      byId("eyebrow").textContent = story.availability === "local-only" ? "Guided demo · local only" : "Guided demo";
      byId("title").textContent = story.title;
      byId("subtitle").textContent = story.intro;
      byId("story").innerHTML = `
        <section class="story-setup">
          <div>
            <p class="eyebrow">User story</p>
            <h2>${{escapeHtml(story.short_title || story.title)}}</h2>
            <p>${{escapeHtml(story.proves)}}</p>
            ${{story.availability_note && state.runnable ? `<p class="meta">${{escapeHtml(story.availability_note)}}</p>` : ""}}
          </div>
          <div class="setup-grid">
            <div class="setup-item"><span>Actor</span><strong>${{escapeHtml(story.actor || "")}}</strong></div>
            <div class="setup-item"><span>Subject</span><strong>${{escapeHtml(story.subject.name)}} · ${{escapeHtml(story.subject.identifier)}}</strong></div>
            <div class="setup-item"><span>Allowed</span><strong>${{escapeHtml(story.boundary.allowed)}}</strong></div>
            <div class="setup-item"><span>Not allowed</span><strong>${{escapeHtml(story.boundary.not_allowed)}}</strong></div>
          </div>
        </section>
        ${{!state.runnable ? renderLocalOnlyBlock(story) : ""}}
        <section class="step-list">${{story.steps.map(renderStep).join("")}}</section>
        <section class="receipt" id="receipt"><div><p class="eyebrow">Final receipt</p><h2>What the demo proved</h2></div><div class="facts">${{renderFacts(story.receipt || [])}}</div></section>
      `;
    }}

    const LOCAL_ONLY_NOTE = "Available when the story runs on the local lab profile.";

    function renderStep(step, index) {{
      if (!state.runnable) {{
        return `<article class="step" id="step-${{escapeHtml(step.id)}}">
          <div class="step-head">
            <span class="step-number">${{index + 1}}</span>
            <div><h3>${{escapeHtml(step.label)}}</h3><p>${{escapeHtml(step.prompt)}}</p></div>
            <span class="status-pill local_only">Local only</span>
          </div>
          <div class="step-body">
            <div class="request-text"><strong>What this request will do:</strong> ${{escapeHtml(step.request_summary)}}</div>
            ${{renderReuse(step.reuses || [])}}
            <p class="meta">This step runs on the local lab profile.</p>
            <details><summary>Show technical request</summary><div data-request-source-for="${{escapeHtml(step.id)}}">${{sourceBlock({{ note: LOCAL_ONLY_NOTE }})}}</div></details>
            <details><summary>Show technical response</summary><div data-response-source-for="${{escapeHtml(step.id)}}">${{sourceBlock({{ note: LOCAL_ONLY_NOTE }})}}</div></details>
          </div>
        </article>`;
      }}
      const runnable = canRun(index);
      const ariaDisabled = runnable ? "" : `aria-disabled="true"`;
      const lockedHint = !runnable && index > 0 ? `<p class="meta" data-locked-hint-for="${{escapeHtml(step.id)}}">Locked until step ${{index}} completes.</p>` : "";
      return `<article class="step ${{runnable ? "" : "locked"}}" id="step-${{escapeHtml(step.id)}}">
        <div class="step-head">
          <span class="step-number">${{index + 1}}</span>
          <div><h3>${{escapeHtml(step.label)}}</h3><p>${{escapeHtml(step.prompt)}}</p></div>
          <span class="status-pill" role="status" data-status-for="${{escapeHtml(step.id)}}">Not run</span>
        </div>
        <div class="step-body">
          <div class="request-text"><strong>What this request will do:</strong> ${{escapeHtml(step.request_summary)}}</div>
          ${{renderReuse(step.reuses || [])}}
          ${{lockedHint}}
          <div class="actions"><button class="primary" type="button" data-run-step="${{escapeHtml(step.id)}}" data-run-label="${{escapeHtml(step.button)}}" ${{ariaDisabled}}>${{escapeHtml(step.button)}}</button></div>
          <div class="friendly-response" aria-live="polite" data-friendly-for="${{escapeHtml(step.id)}}"></div>
          <details><summary>Show technical request</summary><div data-request-source-for="${{escapeHtml(step.id)}}">${{sourceBlock({{ note: "Run this step to capture the request source." }})}}</div></details>
          <details><summary>Show technical response</summary><div data-response-source-for="${{escapeHtml(step.id)}}">${{sourceBlock({{ note: "Run this step to capture the response source." }})}}</div></details>
        </div>
      </article>`;
    }}

    function wireStepButtons() {{
      document.querySelectorAll("[data-run-step]").forEach((button) => {{
        button.addEventListener("click", () => {{
          if (button.getAttribute("aria-disabled") === "true") return;
          runStep(button.getAttribute("data-run-step") || "", button);
        }});
      }});
    }}

    async function copyText(value) {{
      if (navigator.clipboard?.writeText) {{
        try {{
          await navigator.clipboard.writeText(value);
          return;
        }} catch (_error) {{}}
      }}
      const textarea = document.createElement("textarea");
      textarea.value = value;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.left = "-9999px";
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      textarea.setSelectionRange(0, textarea.value.length);
      const copied = document.execCommand("copy");
      textarea.remove();
      if (!copied) throw new Error("Copy failed");
    }}

    function wireCurlCopyButtons() {{
      document.addEventListener("click", async (event) => {{
        const button = event.target instanceof Element ? event.target.closest("[data-copy-curl]") : null;
        if (!button) return;
        const label = button.textContent;
        try {{
          await copyText(button.getAttribute("data-copy-curl") || "");
          button.textContent = "Copied";
        }} catch (_error) {{
          button.textContent = "Copy failed";
        }}
        setTimeout(() => {{ button.textContent = label || "Copy as curl"; }}, 1200);
      }});
    }}

    function updateStatus(stepId, status) {{
      const node = document.querySelector(`[data-status-for="${{CSS.escape(stepId)}}"]`);
      if (!node) return;
      node.textContent = statusLabel(status);
      node.className = `status-pill ${{status || ""}}`;
    }}

    function renderFriendly(stepId, friendly) {{
      const node = document.querySelector(`[data-friendly-for="${{CSS.escape(stepId)}}"]`);
      if (!node) return;
      node.className = `friendly-response visible ${{friendly.status === "needs_attention" ? "needs_attention" : ""}}`;
      node.innerHTML = `<div><h4>${{escapeHtml(friendly.title)}}</h4><p>${{escapeHtml(friendly.message)}}</p></div><div class="facts">${{renderFacts(friendly.facts || [])}}</div>`;
    }}

    function setSource(stepId, kind, value) {{
      const node = document.querySelector(`[data-${{kind}}-source-for="${{CSS.escape(stepId)}}"]`);
      if (node) node.innerHTML = sourceBlock(value);
    }}

    function unlockNextSteps(completedStepId) {{
      const story = state.story;
      let firstUnlocked = null;
      for (const button of document.querySelectorAll("[data-run-step]")) {{
        const stepId = button.getAttribute("data-run-step") || "";
        const stepIndex = story.steps.findIndex((step) => step.id === stepId);
        const runnable = canRun(stepIndex);
        if (runnable) {{
          button.removeAttribute("aria-disabled");
          const hint = document.querySelector(`[data-locked-hint-for="${{CSS.escape(stepId)}}"]`);
          if (hint) hint.remove();
          if (!firstUnlocked && !state.completed.has(stepId)) firstUnlocked = button;
        }} else {{
          button.setAttribute("aria-disabled", "true");
        }}
        button.closest(".step")?.classList.toggle("locked", !runnable);
      }}
      const allDone = story.steps.every((step) => state.completed.has(step.id));
      if (allDone) {{
        const receipt = byId("receipt");
        receipt?.classList.add("visible");
        receipt?.scrollIntoView({{ block: "start" }});
      }} else if (firstUnlocked) {{
        firstUnlocked.focus({{ preventScroll: true }});
        firstUnlocked.closest(".step")?.scrollIntoView({{ block: "start" }});
      }}
    }}

    async function runStep(stepId, button) {{
      button.setAttribute("aria-disabled", "true");
      updateStatus(stepId, "running");
      const response = await fetch(`/api/scenarios/${{encodeURIComponent(state.story.id)}}/${{encodeURIComponent(stepId)}}`, {{method: "POST"}});
      const data = await response.json();
      renderFriendly(stepId, data.friendly || {{}});
      setSource(stepId, "request", data.request_source || {{}});
      setSource(stepId, "response", data.response_source || {{}});
      const status = data.friendly?.status || "done";
      updateStatus(stepId, status);
      if (status === "done" || status === "denied_as_expected") {{
        state.completed.add(stepId);
        setTimeout(() => unlockNextSteps(stepId), 80);
      }} else {{
        button.removeAttribute("aria-disabled");
        if (status === "needs_attention") button.textContent = "Try again";
      }}
    }}

    async function start() {{
      const catalogue = await (await fetch("/api/scenarios.json", {{cache: "no-store"}})).json();
      if (!ACTIVE_SCENARIO) {{
        renderChooser(catalogue.scenarios || []);
        wireCurlCopyButtons();
        return;
      }}
      const data = await (await fetch(`/api/scenarios/${{encodeURIComponent(ACTIVE_SCENARIO)}}.json`, {{cache: "no-store"}})).json();
      if (!data.story) {{
        byId("story").innerHTML = `<div class="story-setup"><h2>Scenario not found</h2><p>${{escapeHtml(ACTIVE_SCENARIO)}}</p></div>`;
        return;
      }}
      renderStory(data.story, data.runnable !== false);
      wireStepButtons();
      wireCurlCopyButtons();
    }}
    start();
  </script>
</body>
</html>
""".encode("utf-8")
