#!/usr/bin/env python3
"""Select CI from event commit endpoints, or request an explicit full sweep."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
from typing import Any

from ci_changes import LockChange, Workspace, classify, lock_change, write_github_outputs


@dataclass(frozen=True)
class EventSelection:
    paths: tuple[str, ...]
    full_sweep: bool
    archive_base_ref: str
    archive_comparison_required: bool
    reason: str
    # Review defers broad assurance to the merge queue, main and the nightly
    # sweep; every other event keeps it.
    pull_request: bool = False
    # Cargo.lock at the base and head commits when it changed; None marks a
    # side where it is absent or unreadable, which selects the complete matrix.
    lock_texts: tuple[str | None, str | None] | None = None


def commit_ref(repo: Path, ref: str) -> str:
    if not ref:
        return ""
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
        cwd=repo, capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def file_at(repo: Path, commit: str, path: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f"{commit}:{path}"], cwd=repo, capture_output=True, text=True,
    )
    return result.stdout if result.returncode == 0 else None


def select_event(
    repo: Path, event_name: str, event: dict[str, Any], head_sha: str
) -> EventSelection:
    if event_name == "schedule":
        # A periodic reconstruction validates current locked bytes. It has no
        # before/after comparison and must not pretend HEAD proves immutability.
        return EventSelection((), True, "", False, "scheduled full sweep")
    if event_name == "workflow_dispatch":
        base = "origin/main"
        head = head_sha
        full = event.get("inputs", {}).get("full", True)
        if full not in (True, False, "true", "false"):
            raise ValueError("workflow_dispatch full must be a boolean")
        full = full in (True, "true")
    elif event_name == "pull_request":
        base = event["pull_request"]["base"]["sha"]
        head = event["pull_request"]["head"]["sha"]
        full = False
    elif event_name == "push":
        base, head, full = event.get("before", ""), head_sha, False
    elif event_name == "merge_group":
        base = event["merge_group"]["base_sha"]
        head = event["merge_group"]["head_sha"]
        full = False
    else:
        raise ValueError(f"unsupported CI event: {event_name}")

    base_commit = commit_ref(repo, base)
    head_commit = commit_ref(repo, head)
    if not base_commit or not head_commit:
        # Run every gate, but leave the archive comparison visibly blocked if
        # its actual baseline is unavailable. Never substitute HEAD or HEAD^.
        return EventSelection((), True, base_commit, True, "unavailable event comparison")
    if full:
        return EventSelection((), True, base_commit, True, "manual full sweep")
    result = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", base_commit, head_commit],
        cwd=repo, capture_output=True, text=True,
    )
    if result.returncode != 0:
        return EventSelection((), True, base_commit, True, "failed event comparison")
    paths = tuple(path for path in result.stdout.split("\0") if path)
    lock_texts = (
        (file_at(repo, base_commit, "Cargo.lock"), file_at(repo, head_commit, "Cargo.lock"))
        if "Cargo.lock" in paths
        else None
    )
    return EventSelection(
        paths, False, base_commit, True, "affected event paths",
        pull_request=event_name == "pull_request", lock_texts=lock_texts,
    )


def selection_lock_change(
    workspace: Workspace, selection: EventSelection
) -> LockChange | None:
    if selection.lock_texts is None:
        return None
    return lock_change(*selection.lock_texts, workspace)


def selection_outputs(workspace: Workspace, selection: EventSelection) -> dict[str, Any]:
    outputs = classify(
        workspace, selection.paths, full_sweep=selection.full_sweep,
        pull_request=selection.pull_request,
        lock_change=selection_lock_change(workspace, selection),
    )
    outputs.update(
        archive_base_ref=selection.archive_base_ref,
        archive_comparison_required=selection.archive_comparison_required,
    )
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    selection = select_event(Path.cwd(), os.environ["GITHUB_EVENT_NAME"], event, os.environ["GITHUB_SHA"])
    workspace = Workspace(json.loads(args.metadata.read_text(encoding="utf-8")))
    outputs = selection_outputs(workspace, selection)
    write_github_outputs(args.github_output, outputs)
    print(f"CI selection: {selection.reason}; changed paths: {len(selection.paths)}")
    if (change := selection_lock_change(workspace, selection)) is not None:
        routed = "complete matrix" if change.members is None else "affected packages"
        print(f"Cargo.lock selection: {routed}; {change.reason}")
    print(json.dumps(outputs, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
