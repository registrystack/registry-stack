"""Prepare documentation in an isolated canonical build and return a reviewable patch."""

from __future__ import annotations

import datetime
import json
import re
import subprocess
import tempfile
import time
import tomllib
from pathlib import Path

DOCS_INPUTS = (
    "docs/site/src/data/docsets.yaml",
    "docs/site/src/data/repo-docs.yaml",
    "docs/site/src/data/archive-lock.yaml",
)


class PreparationError(Exception):
    pass


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def validate_inputs(repo: Path, version: str, release_id: str, date: str) -> str:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise PreparationError("PyYAML is required for documentation preparation") from exc
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise PreparationError("version must be MAJOR.MINOR.PATCH")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", release_id):
        raise PreparationError("invalid release ID")
    if datetime.date.fromisoformat(date).isoformat() != date:
        raise PreparationError("date must be YYYY-MM-DD")
    if git(repo, "status", "--porcelain", "--untracked-files=no"):
        raise PreparationError("commit the prepared source inputs before preparing documentation")
    manifest_name = f"release/manifests/registry-stack-{release_id}.yaml"
    prepared_inputs = (
        "Cargo.toml", manifest_name, f"release/notes/v{version}.md",
        "docs/site/src/data/cli-reference.yaml", *DOCS_INPUTS,
    )
    for name in prepared_inputs:
        if (repo / name).is_symlink() or not (repo / name).is_file():
            raise PreparationError(f"expected regular tracked input: {name}")
        git(repo, "ls-files", "--error-unmatch", name)
    workspace = tomllib.loads((repo / "Cargo.toml").read_text())
    if workspace["workspace"]["package"]["version"] != version:
        raise PreparationError("workspace version must match the selected release")
    try:
        manifest = yaml.safe_load(
            (repo / manifest_name).read_text()
        )
    except yaml.YAMLError as exc:
        raise PreparationError("release manifest is not valid YAML") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("stack"), dict):
        raise PreparationError("release manifest must contain a stack object")
    if manifest.get("stack", {}).get("version") != version or manifest["stack"].get("release") != release_id:
        raise PreparationError("manifest must match the selected version and release ID")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise PreparationError("release manifest must contain an artifacts object")
    if artifacts.get("registry-docs") != version:
        raise PreparationError("manifest must include the selected registry-docs version")
    return git(repo, "rev-parse", "HEAD")


def apply_patch(repo: Path, source_sha: str, patch: Path) -> None:
    if git(repo, "rev-parse", "HEAD") != source_sha:
        raise PreparationError("source HEAD changed during preparation; review the patch against the new source")
    # Check both staged and unstaged changes; never apply over concurrent edits.
    if git(repo, "status", "--porcelain", "--", *DOCS_INPUTS):
        raise PreparationError("documentation inputs changed during preparation; retain and review the patch")
    if not patch.read_bytes():
        return
    git(repo, "apply", "--check", str(patch))
    git(repo, "apply", str(patch))


def prepare_docs(
    repo: Path, version: str, release_id: str, date: str,
    output_dir: Path | None = None, apply: bool = False,
) -> dict:
    repo = repo.resolve()
    source_sha = validate_inputs(repo, version, release_id, date)
    if output_dir is None:
        output = Path(tempfile.mkdtemp(prefix="registry-docs-prepare-"))
    else:
        output = output_dir.absolute()
        output.mkdir(parents=True, exist_ok=False)
    report = {
        "operation": "prepare-docs", "version": version, "release_id": release_id,
        "date": date, "source_sha": source_sha, "status": "preparing",
        "output_dir": str(output), "applied": False,
        "editorial_review": "Existing review dates and CLI publication metadata are preserved. Review release notes and migration guidance separately.",
    }
    started = time.monotonic()
    report_path = output / "report.json"
    print(f"Preparing v{version} documentation; log and recovery files: {output}", flush=True)
    try:
        source = output / "source"
        git(repo, "clone", "--no-local", "--no-checkout", str(repo), str(source))
        git(source, "checkout", "--detach", source_sha)
        git(source, "remote", "set-url", "origin", git(repo, "remote", "get-url", "origin"))
        artifacts = output / "artifacts"
        artifacts.mkdir()
        command = [
            "docker", "run", "--rm", "--platform", "linux/amd64",
            "--mount", f"type=bind,src={source},dst=/input,readonly",
            "--mount", f"type=bind,src={artifacts},dst=/output",
            "--workdir", "/workspace",
            "--env", f"DOCS_VERSION={version}",
            "--env", f"DOCS_RELEASE_ID={release_id}",
            "--env", f"DOCS_DATE={date}",
            "--env", f"DOCS_SOURCE_SHA={source_sha}",
            "ubuntu:24.04", "bash", "/input/release/scripts/prepare-release-docs-container.sh",
        ]
        with (output / "prepare.log").open("w") as log:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
        patch = artifacts / "documentation.patch"
        # Only a patch of these owned inputs can be returned by the helper.
        changed = json.loads((artifacts / "changed-paths.json").read_text())
        if not isinstance(changed, list) or any(name not in DOCS_INPUTS for name in changed):
            raise PreparationError("preparation changed files outside its documentation inputs")
        if patch.read_bytes():
            git(repo, "apply", "--check", str(patch))
        report.update(status="ready", changed_paths=changed, patch=str(patch),
                      archive=str(artifacts / f"v{version}.tar.gz"))
        if apply:
            apply_patch(repo, source_sha, patch)
            report["applied"] = True
        return report
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, PreparationError) as exc:
        report.update(status="failed", error=str(exc))
        raise PreparationError(
            f"documentation preparation failed; inspect {output / 'prepare.log'} and {report_path}. "
            "No generated patch was applied. For stale CLI review metadata, run "
            "npm run cli-reference:digest in docs/site, review the changed reference, "
            "and commit its publication record before retrying."
        ) from exc
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report_path.write_text(json.dumps(report, indent=2) + "\n")


def run(repo: Path, version: str, release_id: str, date: str,
        output_dir: Path | None, apply: bool) -> int:
    try:
        report = prepare_docs(repo, version, release_id, date, output_dir, apply)
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, PreparationError) as exc:
        print(f"error: {exc}")
        return 1
