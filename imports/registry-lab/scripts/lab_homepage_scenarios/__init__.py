#!/usr/bin/env python3
"""Guided scenario surface for Registry Lab."""

from __future__ import annotations

import html
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


def _attach_previews(story: dict[str, Any], module: Any, config: dict[str, Any]) -> dict[str, Any]:
    steps = story.get("steps", [])
    enriched_steps = []
    for step in steps:
        step_copy = dict(step)
        step_copy["request_preview"] = module.preview_step(config, step["id"])
        enriched_steps.append(step_copy)
    return {**story, "steps": enriched_steps}


def scenario_payload(config: dict[str, Any], scenario_id: str | None = None, lab_mode: str = "hosted") -> dict[str, Any]:
    if scenario_id:
        module = STORY_BY_ID.get(scenario_id)
        if not module:
            return {"error": "unknown_scenario", "scenario_id": scenario_id}
        story = _attach_previews(module.story(), module, config)
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
                "domain": story.get("domain", ""),
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


def scenario_page_html(scenario_id: str | None = None) -> bytes:
    # The active scenario travels as a body data attribute (read by
    # scenarios.js) instead of an inline <script>, so the strict
    # script-src 'self' CSP holds.
    active_scenario = html.escape(scenario_id or "", quote=True)
    # Build page-level metadata: per-story when scenario_id is given, generic otherwise.
    if scenario_id and scenario_id in STORY_BY_ID:
        _story = STORY_BY_ID[scenario_id].story()
        _short_title = _story.get("short_title") or _story.get("title", "Registry Lab")
        _proves = _story.get("proves", "")
        _page_title = html.escape(f"{_short_title} · Registry Lab")
        _description = html.escape(_proves)
        _og_title = html.escape(_short_title)
        _head_extra = (
            f'  <meta name="description" content="{_description}">\n'
            f'  <meta property="og:title" content="{_og_title}">\n'
            f'  <meta property="og:description" content="{_description}">\n'
            f'  <meta property="og:type" content="website">\n'
        )
    else:
        _page_title = "Registry Lab Scenarios"
        _head_extra = '  <meta name="description" content="Step-by-step guided demos of governed registry services.">\n'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_page_title}</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
{_head_extra}  <link rel="stylesheet" href="/static/shared.css">
  <link rel="stylesheet" href="/static/scenarios.css">
</head>
<body data-active-scenario="{active_scenario}">
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
  <script src="/static/scenarios.js"></script>
</body>
</html>
""".encode("utf-8")
