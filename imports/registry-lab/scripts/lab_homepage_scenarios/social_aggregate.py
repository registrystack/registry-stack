#!/usr/bin/env python3
"""Social protection aggregate versus row access scenario."""

from __future__ import annotations

from typing import Any

from .common import (
    PURPOSE,
    auth_header_pair,
    configured_credential,
    display_auth_header_pair,
    env_url,
    http_json,
    ok_status,
    request_source,
    source_response,
    standard_error_result,
)


SCENARIO_ID = "social-aggregate"
AGGREGATE_PATH = "/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band"
ROW_PATH = "/v1/datasets/social_protection_registry/entities/household/records?limit=1"


def story() -> dict[str, Any]:
    return {
        "id": SCENARIO_ID,
        "title": "Can a planner see eligibility counts without seeing household rows?",
        "short_title": "Aggregate versus row access",
        "proves": "Aggregate credentials can answer planning questions while row data remains separately governed.",
        "domain": "Social protection",
        "availability": "local-only",
        "availability_note": "Runs on the local lab profile with the social Relay on port 4312.",
        "intro": (
            "A policy analyst needs district-level eligibility counts for planning. They do not need names, household rows, "
            "or benefit records for individual families."
        ),
        "actor": "Policy analyst",
        "subject": {"name": "Priority household planning", "identifier": "households_by_eligibility_band"},
        "boundary": {
            "allowed": "Read aggregate counts by eligibility band.",
            "not_allowed": "Read household rows with the aggregate credential.",
        },
        "steps": [
            {
                "id": "discover",
                "label": "Discover the social dataset",
                "prompt": "Start with metadata so the analyst can see what the Relay exposes.",
                "button": "Run discovery",
                "request_summary": "GET the social protection dataset catalog using the public metadata credential.",
            },
            {
                "id": "read-aggregate",
                "label": "Read aggregate planning counts",
                "prompt": "Use the aggregate credential for the planning question.",
                "button": "Read aggregate",
                "request_summary": "GET households_by_eligibility_band with the aggregate credential and Data-Purpose header.",
                "reuses": [{"label": "Dataset", "value": "social_protection_registry"}, {"label": "View", "value": "aggregate"}],
            },
            {
                "id": "deny-row-with-aggregate",
                "label": "Try a household row with the aggregate credential",
                "prompt": "Now try to use that same aggregate credential on household rows.",
                "button": "Try row access",
                "request_summary": "GET a household row endpoint with the aggregate credential and show the denial.",
            },
            {
                "id": "read-row-with-row-token",
                "label": "Show the separate row-reader boundary",
                "prompt": "Finally, use the row-reader credential so developers can see the permission boundary is credential-specific.",
                "button": "Read one row",
                "request_summary": "GET one household row with the row-reader credential and purpose header.",
            },
        ],
        "receipt": [
            {"label": "Planning answer", "value": "Eligibility counts"},
            {"label": "Aggregate credential read rows", "value": "No"},
            {"label": "Row reader is separate", "value": "Yes"},
            {"label": "Purpose header used", "value": "Yes"},
        ],
    }


def run_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    if step_id == "discover":
        return _run_get(config, step_id, "social-metadata", "/v1/datasets", _summarize_discovery, {"Data-Purpose": PURPOSE})
    if step_id == "read-aggregate":
        return _run_get(config, step_id, "social-aggregate-reader", AGGREGATE_PATH, _summarize_aggregate, {"Data-Purpose": PURPOSE})
    if step_id == "deny-row-with-aggregate":
        return _run_get(config, step_id, "social-aggregate-reader", ROW_PATH, _summarize_row_denial, {"Data-Purpose": PURPOSE})
    if step_id == "read-row-with-row-token":
        return _run_get(config, step_id, "social-row-reader", ROW_PATH, _summarize_row_read, {"Data-Purpose": PURPOSE})
    return standard_error_result(step_id)


def _run_get(config: dict[str, Any], step_id: str, credential_id: str, path: str, summarize, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    credential = configured_credential(config, credential_id)
    auth_name, auth_value = auth_header_pair(credential)
    display_name, display_value = display_auth_header_pair(credential)
    url = env_url("SOCIAL_RELAY_URL", "http://127.0.0.1:4312", path)
    headers = {auth_name: auth_value, **(extra_headers or {})}
    result = http_json("GET", url, headers)
    return {
        "step_id": step_id,
        "friendly": summarize(result.body, result.status, result.error),
        "request_source": request_source("GET", url, {display_name: display_value, **(extra_headers or {})}),
        "response_source": source_response(result),
    }


def _summarize_discovery(body: Any, status: int | None, error: str) -> dict[str, Any]:
    datasets = body.get("datasets", []) if isinstance(body, dict) else []
    return {
        "title": "The social protection dataset is discoverable." if ok_status(status) else "Social discovery needs attention.",
        "message": "The analyst can learn what the Relay offers before asking for either aggregates or rows.",
        "status": "done" if ok_status(status) else "needs_attention",
        "facts": [
            {"label": "HTTP status", "value": status if status is not None else "No response"},
            {"label": "Datasets advertised", "value": len(datasets) if isinstance(datasets, list) else "Check source"},
            {"label": "Next request", "value": "Aggregate planning count"},
            {"label": "Error", "value": error or "None"},
        ],
    }


def _summarize_aggregate(body: Any, status: int | None, error: str) -> dict[str, Any]:
    rows = body.get("observations") or body.get("data") or body.get("rows") or body.get("results") if isinstance(body, dict) else []
    row_count = len(rows) if isinstance(rows, list) else "Check source"
    return {
        "title": "The aggregate returns planning counts." if ok_status(status) else "Aggregate read needs attention.",
        "message": "The response can support planning without exposing household names or individual benefit records.",
        "status": "done" if ok_status(status) else "needs_attention",
        "facts": [
            {"label": "HTTP status", "value": status if status is not None else "No response"},
            {"label": "Rows in aggregate response", "value": row_count},
            {"label": "Individual households exposed", "value": "No"},
            {"label": "Error", "value": error or "None"},
        ],
    }


def _summarize_row_denial(body: Any, status: int | None, error: str) -> dict[str, Any]:
    denied = status in (401, 403)
    code = body.get("code") if isinstance(body, dict) else ""
    return {
        "title": "The aggregate credential cannot read household rows." if denied else "The boundary check needs attention.",
        "message": "Aggregate access and row access are different permissions. The denial is the expected result.",
        "status": "denied_as_expected" if denied else "needs_attention",
        "facts": [
            {"label": "HTTP status", "value": status if status is not None else "No response"},
            {"label": "Result", "value": "Denied as expected" if denied else "Unexpected result"},
            {"label": "Reason", "value": code or error or "Check source"},
        ],
    }


def _summarize_row_read(body: Any, status: int | None, error: str) -> dict[str, Any]:
    rows = body.get("data") or body.get("rows") or body.get("results") if isinstance(body, dict) else []
    return {
        "title": "The row-reader credential uses a separate permission." if ok_status(status) else "Row-reader request needs attention.",
        "message": (
            "This is not what the analyst used for aggregate planning. It is shown only to make the credential boundary clear."
        ),
        "status": "done" if ok_status(status) else "needs_attention",
        "facts": [
            {"label": "HTTP status", "value": status if status is not None else "No response"},
            {"label": "Rows returned", "value": len(rows) if isinstance(rows, list) else "Check source"},
            {"label": "Credential", "value": "social-row-reader"},
            {"label": "Error", "value": error or "None"},
        ],
    }
