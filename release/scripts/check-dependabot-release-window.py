#!/usr/bin/env python3
"""Validate the routine Dependabot admission window used around releases."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / ".github" / "dependabot.yml"
EXPECTED_SLOTS = {
    "cargo": "04:00",
    "npm": "05:30",
    "github-actions": "07:00",
    "pip": "08:30",
    "docker": "10:00",
    "docker-compose": "11:30",
}
TIME = re.compile(r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")


def validate_config(data: Any) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    checked: list[dict[str, Any]] = []
    if not isinstance(data, dict) or data.get("version") != 2:
        return checked, ["dependabot config must be a version 2 object"]
    updates = data.get("updates")
    if not isinstance(updates, list):
        return checked, ["dependabot config must contain an updates list"]

    seen: set[str] = set()
    seen_times: set[str] = set()
    for index, update in enumerate(updates):
        context = f"updates[{index}]"
        if not isinstance(update, dict):
            errors.append(f"{context} must be an object")
            continue
        ecosystem = update.get("package-ecosystem")
        if ecosystem not in EXPECTED_SLOTS:
            errors.append(f"{context} has unexpected package ecosystem {ecosystem!r}")
            continue
        if ecosystem in seen:
            errors.append(f"package ecosystem {ecosystem} is configured more than once")
        seen.add(ecosystem)
        if "target-branch" in update:
            errors.append(f"{ecosystem} must not set target-branch")
        if update.get("open-pull-requests-limit") != 1:
            errors.append(
                f"{ecosystem} open-pull-requests-limit must be 1 for routine version updates"
            )
        schedule = update.get("schedule")
        if not isinstance(schedule, dict):
            errors.append(f"{ecosystem} schedule must be an object")
            continue
        interval = schedule.get("interval")
        day = schedule.get("day")
        time = schedule.get("time")
        timezone = schedule.get("timezone")
        if interval != "weekly":
            errors.append(f"{ecosystem} schedule interval must be weekly")
        if day != "wednesday":
            errors.append(f"{ecosystem} schedule day must be wednesday")
        if timezone != "Etc/UTC":
            errors.append(f"{ecosystem} schedule timezone must be Etc/UTC")
        if not isinstance(time, str) or TIME.fullmatch(time) is None:
            errors.append(f"{ecosystem} schedule time must be HH:MM")
        else:
            if time in seen_times:
                errors.append(f"Dependabot schedule time {time} is duplicated")
            seen_times.add(time)
            expected = EXPECTED_SLOTS[ecosystem]
            if time != expected:
                errors.append(
                    f"{ecosystem} schedule time must be {expected}, got {time}"
                )
        checked.append(
            {
                "ecosystem": ecosystem,
                "time": time,
                "directory": update.get("directory"),
                "directories": update.get("directories"),
            }
        )

    missing = sorted(set(EXPECTED_SLOTS) - seen)
    if missing:
        errors.append(f"missing package ecosystems: {', '.join(missing)}")
    return sorted(checked, key=lambda item: str(item["ecosystem"])), errors


def report(config: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(config.read_text(encoding="utf-8"))
        checked, errors = validate_config(data)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        checked, errors = [], [f"cannot load {config}: {exc}"]
    return {
        "schema_version": "registry-stack.dependabot-release-window.v1",
        "status": "passed" if not errors else "failed",
        "policy": {
            "day": "wednesday",
            "timezone": "Etc/UTC",
            "window_start": "04:00",
            "window_end": "12:00",
            "routine_version_pr_limit": 1,
        },
        "entries_checked": checked,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate staggered routine Dependabot scheduling around releases."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    result = report(args.config)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
