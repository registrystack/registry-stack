"""Collect linked release-note source material without inferring upgrade guidance."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


class NotesError(RuntimeError):
    """The requested draft could not be collected completely."""


def command(repo: Path, *args: str) -> str:
    try:
        result = subprocess.run(args, cwd=repo, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise NotesError(f"cannot run {args[0]}: {exc}") from exc
    if result.returncode:
        raise NotesError(f"{args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def commit(repo: Path, ref: str) -> str:
    sha = command(repo, "git", "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise NotesError(f"{ref!r} did not resolve to one exact commit")
    return sha


def markdown(text: str) -> str:
    # PR titles are data, including Markdown and HTML, rather than authored prose.
    text = " ".join(text.split())
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_{}\[\]()#!|])", r"\\\1", text)


def merged_prs(repo: Path, repository: str, sha: str, selected: set[str]) -> list[dict]:
    raw = command(
        repo, "gh", "api", "--paginate", "--slurp",
        f"repos/{repository}/commits/{sha}/pulls?per_page=100",
    )
    try:
        pages = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NotesError("GitHub returned invalid pull-request JSON") from exc
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise NotesError("GitHub returned malformed pull-request pages")
    matched = []
    for page in pages:
        for pr in page:
            if not isinstance(pr, dict):
                raise NotesError("GitHub returned a malformed pull request")
            if not pr.get("merged_at") or not isinstance(pr.get("merge_commit_sha"), str):
                continue
            if pr["merge_commit_sha"] not in selected:
                continue
            base = pr.get("base")
            base_repo = base.get("repo") if isinstance(base, dict) else None
            base_name = base_repo.get("full_name") if isinstance(base_repo, dict) else None
            if not isinstance(base_name, str) or base_name.casefold() != repository.casefold():
                continue
            if (
                not isinstance(pr.get("number"), int)
                or isinstance(pr["number"], bool)
                or pr["number"] < 1
                or not isinstance(pr.get("title"), str)
                or not pr["title"].strip()
            ):
                raise NotesError("GitHub returned a merged pull request without a number or title")
            matched.append(pr)
    return sorted(matched, key=lambda pr: pr["number"])


def build_draft(
    repo: Path, repository: str, version: str, release_id: str,
    baseline_tag: str, source_ref: str,
) -> str:
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", baseline_tag):
        raise NotesError("--from-tag must name an explicit release tag such as v0.28.0")
    baseline = commit(repo, f"refs/tags/{baseline_tag}")
    source = commit(repo, source_ref)
    ancestor = command(repo, "git", "merge-base", baseline, source).strip()
    if ancestor != baseline:
        raise NotesError(f"baseline {baseline_tag} is not an ancestor of the selected source")
    revision_range = f"{baseline}..{source}"
    selected = set(command(repo, "git", "rev-list", revision_range, "--").splitlines())
    history = command(
        repo, "git", "log", "--first-parent", "--reverse", "--format=%H%x00%s",
        revision_range, "--",
    )
    pull_requests: dict[int, dict] = {}
    direct_commits = []
    for line in history.splitlines():
        sha, title = line.split("\0", 1)
        associated = merged_prs(repo, repository, sha, selected)
        if associated:
            for pr in associated:
                pull_requests.setdefault(pr["number"], pr)
        else:
            direct_commits.append((sha, title))
    paths = command(repo, "git", "diff", "--no-renames", "--name-only", "-z", baseline, source, "--").split("\0")
    components: dict[str, int] = {}
    for path in filter(None, paths):
        parts = path.split("/")
        component = "/".join(parts[:2]) if parts[0] in {"crates", "products"} else parts[0]
        components[component] = components.get(component, 0) + 1
    url = f"https://github.com/{repository}"
    lines = [
        f"# Registry Stack v{version}", "",
        f"Registry Stack v{version} is the {release_id} release.", "",
        "DRAFT: mechanically collected source material. Review and replace the guidance",
        "below before publishing. PR titles and changed paths do not establish behavior,",
        "compatibility, release readiness, or migration requirements.", "",
        "## Compatibility and migration", "",
        "TODO (release author): describe compatibility changes and required upgrade steps",
        "after reviewing the linked changes, or explicitly state that none are required.", "",
        "## Change sources", "",
        f"Baseline: [{baseline_tag}]({url}/commit/{baseline}).",
        f"Source: [{source}]({url}/commit/{source}).",
        f"[Compare exact commits]({url}/compare/{baseline}...{source}).", "",
        "## Merged pull requests", "",
    ]
    for number, pr in pull_requests.items():
        lines.append(f"- {markdown(pr['title'])} ([#{number}]({url}/pull/{number})).")
    if not pull_requests:
        lines.append("No associated merged pull requests were found in this range.")
    lines.extend(["", "## Commits without an associated merged pull request", ""])
    for sha, title in direct_commits:
        lines.append(f"- {markdown(title)} ([{sha[:12]}]({url}/commit/{sha})).")
    if not direct_commits:
        lines.append("None.")
    lines.extend(["", "## Components with net file changes", ""])
    for component, count in sorted(components.items()):
        lines.append(f"- {markdown(component)}: {count} changed file{'s' if count != 1 else ''}.")
    if not components:
        lines.append("No net file changes.")
    lines.extend(["", "This remains a pre-1.0 Beta release for self-hosted institutional pilots.", ""])
    return "\n".join(lines)


def write_draft(body: str, output: Path | None) -> None:
    if output is None:
        print(body, end="")
        return
    try:
        # Exclusive creation also refuses dangling symlinks and closes the check/write race.
        with output.open("x", encoding="utf-8") as stream:
            stream.write(body)
    except FileExistsError as exc:
        raise NotesError(f"draft output already exists; choose a new path: {output}") from exc
