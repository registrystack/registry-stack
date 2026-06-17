#!/usr/bin/env python3
"""Guided scenario surface for Registry Lab."""

from __future__ import annotations

import html
from typing import Any

from . import (
    agriculture_voucher,
    civil_alive,
    civil_birth_demographics,
    combined_support,
    dhis2_programme,
    social_aggregate,
    wallet_vc,
)
from .attestations import public_label_violations


SCENARIOS = [
    civil_alive,
    civil_birth_demographics,
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


def _with_runtime_availability(story: dict[str, Any], lab_mode: str) -> dict[str, Any]:
    item = dict(story)
    availability = item.get("availability", "hosted")
    runnable = _is_runnable(item, lab_mode)
    label = "Hosted" if availability == "hosted" else "Local only"
    item["availability_state"] = {
        **dict(item.get("availability_state") or {}),
        "state": availability,
        "label": label,
        "runnable": runnable,
        "lab_mode": lab_mode,
    }
    return item


def public_label_check(stories: list[dict[str, Any]] | None = None) -> list[str]:
    """Return first-level public-label violations for scenario story metadata."""
    return [
        violation
        for story in (stories or all_stories())
        for violation in public_label_violations(
            {
                "title": story.get("title", ""),
                "short_title": story.get("short_title", ""),
                "proves": story.get("proves", ""),
                "intro": story.get("intro", ""),
                "actor": story.get("actor", ""),
                "boundary": story.get("boundary", {}),
                "steps": [
                    {
                        "label": step.get("label", ""),
                        "prompt": step.get("prompt", ""),
                        "button": step.get("button", ""),
                        "request_summary": step.get("request_summary", ""),
                        "reuses": step.get("reuses", []),
                    }
                    for step in story.get("steps", [])
                ],
                "receipt": story.get("receipt", []),
                "requested_attestations": story.get("requested_attestations", []),
                "lookup_profile": story.get("lookup_profile", {}),
                "non_disclosure": story.get("non_disclosure", []),
                "proof_facts": story.get("proof_facts", []),
            },
            story.get("id", "$"),
        )
    ]


def scenario_payload(config: dict[str, Any], scenario_id: str | None = None, lab_mode: str = "hosted") -> dict[str, Any]:
    if scenario_id:
        module = STORY_BY_ID.get(scenario_id)
        if not module:
            return {"error": "unknown_scenario", "scenario_id": scenario_id}
        story = _with_runtime_availability(_attach_previews(module.story(), module, config), lab_mode)
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
                "availability_state": _with_runtime_availability(story, lab_mode)["availability_state"],
                "availability_note": story.get("availability_note", ""),
                "requested_attestations": story.get("requested_attestations", []),
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


def top_nav_html(active: str = "") -> str:
    """One nav for every lab page; `active` marks the current entry."""
    entries = (
        ("home", "/", "Home"),
        ("scenarios", "/scenarios", "Scenario demos"),
        ("registry-explorer", "/registry-explorer", "Registry Explorer"),
        ("claims-explorer", "/claims-explorer", "Claims Explorer"),
        ("wallet", "/#wallet", "Wallet test"),
        ("services", "/#services", "For developers"),
    )
    links = []
    for key, href, label in entries:
        current = ' aria-current="page"' if key == active else ""
        links.append(f'<a href="{href}"{current}>{label}</a>')
    links.append('<a class="nav-emphasis" href="https://registrystack.org/">Registry Stack</a>')
    return "\n      ".join(links)


def scenario_cards_html(lab_mode: str = "hosted") -> str:
    """Server-rendered chooser cards for the homepage.

    Mirrors renderChooser in scenarios.js: the default story leads, then the
    remaining hosted-runnable stories, then the local-only walkthroughs.
    """
    items = scenario_payload({}, lab_mode=lab_mode)["scenarios"]
    default_id = civil_alive.SCENARIO_ID
    ordered = (
        [item for item in items if item["id"] == default_id]
        + [item for item in items if item["id"] != default_id and item["runnable"]]
        + [item for item in items if item["id"] != default_id and not item["runnable"]]
    )
    cards = []
    for item in ordered:
        is_default = item["id"] == default_id
        card_class = "scenario-card scenario-card--default" if is_default else "scenario-card"
        availability_label = "Local only" if item["availability"] == "local-only" else "Hosted"
        note = html.escape(item["availability_note"])
        cards.append(
            f'<article class="{card_class}">'
            + ('<span class="start-here-badge">Start here</span>' if is_default else "")
            + f'<span class="availability {html.escape(item["availability"])}">{availability_label}</span>'
            + (f'<span class="domain-tag">{html.escape(item["domain"])}</span>' if item["domain"] else "")
            + f'<div><h3>{html.escape(item["title"])}</h3><p>{html.escape(item["proves"])}</p></div>'
            + (f'<p class="card-meta">{note}</p>' if note else "")
            + f'<p class="card-meta">{item["steps"]} steps</p>'
            + f'<div class="actions"><a class="button primary" href="/scenarios/{html.escape(item["id"], quote=True)}">'
            + ("Open story" if item["runnable"] else "Read the walkthrough")
            + "</a></div></article>"
        )
    return (
        '<p class="badge-explanation"><strong>Hosted</strong> stories run live in this lab from the browser. '
        "<strong>Local-only</strong> stories are read-only walkthroughs here and runnable via the GitHub repo locally.</p>\n"
        '        <div class="chooser-grid">' + "".join(cards) + "</div>"
    )


def scenario_page_html(scenario_id: str | None = None, analytics_html: str = "") -> bytes:
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
      {top_nav_html("scenarios")}
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
    <div class="site-footer-inner">
      <div>
        <strong>Registry Stack</strong>
        <p class="meta">Public demo environment for governed registry services.</p>
      </div>
      <nav aria-label="Footer links">
        <a href="https://registrystack.org/">Registry Stack</a>
        <a href="https://docs.registrystack.org/">Docs</a>
      </nav>
    </div>
  </footer>
{analytics_html}
  <script src="/static/scenarios.js"></script>
</body>
</html>
""".encode("utf-8")
