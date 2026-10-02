#!/usr/bin/env python3
"""Build and publish an opt-in nightly channel without replacing release bytes."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "registrystack/registry-stack"
SCHEMA = "registry-stack.nightly.v1"
CHANNEL = "nightly-channel"
TAG = re.compile(
    r"^v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-nightly\.([0-9]{8})\.([0-9a-f]{40})$"
)
INSTALLERS = {
    "breg": ("registry-breg", "BREG", ("breg", "bregctl")),
    "relay": ("registry-relay-v2", "RELAY", ("relay", "relayctl")),
    "evidencectl": (
        "registry-evidencectl",
        "EVIDENCECTL",
        ("evidence", "evidencectl", "evidence-oid4vci"),
    ),
    "casework": ("registry-casework", "CASEWORK", ("casework", "caseworkctl")),
    "scheduling": ("registry-scheduling", "SCHEDULING", ("schedulingctl",)),
}


class NightlyError(ValueError):
    """Refuse an invalid identity or incompatible public state."""


def run(*arguments: str, input: str | None = None) -> str:
    return subprocess.run(
        arguments, input=input, text=True, check=True, stdout=subprocess.PIPE
    ).stdout.strip()


def api(path: str, payload: dict | None = None) -> dict:
    arguments = ["gh", "api", path]
    if payload is not None:
        arguments += ["--method", "POST", "--input", "-"]
    return json.loads(
        run(*arguments, input=json.dumps(payload) if payload is not None else None)
    )


def optional_api(path: str) -> dict | None:
    # Only an explicit 404 means absence. Authentication and service failures
    # must never look like permission to create or replace public state.
    result = subprocess.run(
        ["gh", "api", "--include", path], text=True, capture_output=True
    )
    if result.returncode:
        if re.search(r"^HTTP/\S+ 404\b", result.stdout, re.MULTILINE):
            return None
        raise NightlyError(f"GitHub lookup failed: {path}")
    return json.loads(result.stdout.split("\n\n", 1)[1])


def identity(tag: str) -> tuple[str, str]:
    match = TAG.fullmatch(tag)
    if match is None:
        raise NightlyError(
            "nightly tag must be v<base>-nightly.<YYYYMMDD>.<full source SHA>"
        )
    try:
        dt.datetime.strptime(match[2], "%Y%m%d")
    except ValueError as error:
        raise NightlyError("nightly tag has an invalid calendar date") from error
    return match[1], match[3]


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def read_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text())
    base, sha = identity(manifest["tag"])
    if (
        manifest.get("schema_version"),
        manifest.get("base_version"),
        manifest.get("version"),
        manifest.get("source_sha"),
    ) != (SCHEMA, base, manifest["tag"][1:], sha):
        raise NightlyError("nightly manifest identity mismatch")
    assets = manifest.get("assets")
    if not isinstance(assets, list) or not assets:
        raise NightlyError("nightly manifest has no assets")
    names = set()
    for asset in assets:
        if not isinstance(asset, dict) or set(asset) != {"name", "sha256"}:
            raise NightlyError("invalid nightly asset record")
        name = asset["name"]
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)
            or name in names
            or not re.fullmatch(r"[0-9a-f]{64}", asset["sha256"])
        ):
            raise NightlyError("invalid or duplicate nightly asset")
        names.add(name)
    if not isinstance(manifest.get("images"), dict) or not manifest["images"]:
        raise NightlyError("nightly manifest has no images")
    expected_images = image_names(base)
    if set(manifest["images"]) != set(expected_images):
        raise NightlyError("nightly image roster mismatch")
    for name, reference in manifest["images"].items():
        if not re.fullmatch(
            rf"ghcr\.io/registrystack/{re.escape(name)}@sha256:[0-9a-f]{{64}}",
            reference,
        ):
            raise NightlyError("nightly image must be pinned to its public digest")
    return manifest


def image_names(version: str) -> list[str]:
    # The release roster remains the owner of image membership.
    import release_candidate

    return sorted(release_candidate._candidate_image_names(version))


def channel_metadata() -> tuple[dict | None, str | None]:
    ref = optional_api(f"repos/{REPOSITORY}/git/ref/heads/{CHANNEL}")
    if ref is None:
        return None, None
    head = ref["object"]["sha"]
    content = api(f"repos/{REPOSITORY}/contents/nightly.json?ref={head}")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "nightly.json"
        path.write_bytes(base64.b64decode(content["content"]))
        return read_manifest(path), head


def plan(output: Path) -> None:
    if (
        os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_EVENT_NAME") not in {"schedule", "workflow_dispatch"}
    ):
        raise NightlyError(
            "nightly builds run only from this repository's protected main"
        )
    sha = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or run("git", "rev-parse", "HEAD") != sha:
        raise NightlyError("checkout does not match the exact workflow source")
    if api(f"repos/{REPOSITORY}/branches/main")["commit"]["sha"] != sha:
        raise NightlyError(
            "main advanced before selection; dispatch again from current main"
        )
    with (ROOT / "Cargo.toml").open("rb") as handle:
        version = tomllib.load(handle)["workspace"]["package"]["version"]
    today = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")
    tag = f"v{version}-nightly.{today}.{sha}"
    identity(tag)
    previous, channel_head = channel_metadata()
    skip = previous is not None and previous["source_sha"] == sha
    plan_record = {
        "schema_version": SCHEMA,
        "tag": tag,
        "version": tag[1:],
        "base_version": version,
        "source_sha": sha,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "channel_head": channel_head,
        "skip": skip,
    }
    # Preserve the original metadata when reconciling an interrupted build.
    # Uploading nightly.json first makes that recovery identity discoverable.
    existing_release = (
        None if skip else optional_api(f"repos/{REPOSITORY}/releases/tags/{tag}")
    )
    if existing_release is not None and any(
        asset["name"] == "nightly.json" for asset in existing_release["assets"]
    ):
        with tempfile.TemporaryDirectory() as temporary:
            run(
                "gh",
                "release",
                "download",
                tag,
                "--repo",
                REPOSITORY,
                "--pattern",
                "nightly.json",
                "--dir",
                temporary,
            )
            original = read_manifest(Path(temporary) / "nightly.json")
        if original["tag"] != tag:
            raise NightlyError("existing nightly manifest names another build")
        plan_record["created_at"] = original["created_at"]
        plan_record["channel_head"] = original["channel_head"]
    # Require all release image destinations to be pre-provisioned. Actions
    # must not accidentally create public staging packages or private outputs.
    for name in [] if skip else image_names(version):
        for package, visibility in ((name, "public"), (f"{name}-candidate", "private")):
            metadata = api(f"orgs/registrystack/packages/container/{package}")
            if (
                metadata.get("name") != package
                or metadata.get("visibility") != visibility
            ):
                raise NightlyError(f"{package} must be provisioned as {visibility}")
    output.write_text(json.dumps(plan_record, indent=2) + "\n")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as handle:
        for key in ("tag", "version", "base_version", "source_sha"):
            handle.write(f"{key}={plan_record[key]}\n")
        handle.write(
            f"skip={str(skip).lower()}\nimage_names={' '.join(image_names(version))}\n"
        )


def check_scan(path: Path) -> None:
    report = json.loads(path.read_text())
    matches = report.get("matches")
    if not isinstance(matches, list):
        raise NightlyError("scanner did not return a complete matches array")
    database = report.get("descriptor", {}).get("db", {})
    built = database.get("built") or database.get("status", {}).get("built")
    if not isinstance(built, str):
        raise NightlyError("scanner did not identify its vulnerability database")
    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(
        built.replace("Z", "+00:00")
    )
    if not dt.timedelta(0) <= age <= dt.timedelta(days=3):
        raise NightlyError("scanner database must be current within three days")
    for match in matches:
        severity = match.get("vulnerability", {}).get("severity")
        if severity not in {"Negligible", "Low", "Medium", "High", "Critical"}:
            raise NightlyError(
                "scanner finding has an unknown severity and needs review"
            )
        if severity in {"High", "Critical"}:
            raise NightlyError(
                "nightly has a high or critical advisory; fix or review it before publication"
            )


def assemble(
    plan_path: Path, directories: list[Path], images: Path, output: Path
) -> None:
    record = json.loads(plan_path.read_text())
    base, sha = identity(record["tag"])
    if base != record["base_version"] or sha != record["source_sha"]:
        raise NightlyError("build plan identity mismatch")
    output.mkdir()
    for directory in directories:
        for asset in sorted(directory.iterdir()):
            if (
                not asset.is_file()
                or asset.is_symlink()
                or not re.fullmatch(
                    rf"[a-z][a-z0-9-]*-{re.escape(record['tag'])}-(?:linux-(?:amd64|arm64)|macos-arm64)(?:\.tar\.gz)?",
                    asset.name,
                )
            ):
                raise NightlyError(f"unexpected nightly payload: {asset.name}")
            if (output / asset.name).exists():
                raise NightlyError(f"duplicate nightly payload: {asset.name}")
            shutil.copy2(asset, output / asset.name)
    # Compare against the maintained release platform roster, changing only
    # the tag. A missing platform or binary cannot advance the channel.
    import release_candidate

    release_assets = release_candidate._relay_v2_payload_inventory(base)
    for name, kind in release_assets.items():
        if kind == "notice":
            notice = ROOT / name
            if not notice.is_file() or notice.is_symlink():
                raise NightlyError(f"release notice must be a regular file: {name}")
            shutil.copy2(notice, output / name)
    expected = {
        name.replace(f"v{base}", record["tag"])
        for name, kind in release_assets.items()
        if kind in {"binary", "notice"}
    }
    if {path.name for path in output.iterdir()} != expected:
        raise NightlyError(
            "nightly binary roster differs from the release platform roster"
        )
    # Actions artifact transport resets file modes. Restore executable modes
    # only after the complete maintained binary roster has been validated.
    for name, kind in release_assets.items():
        if kind == "binary" and not name.endswith(".tar.gz"):
            (output / name.replace(f"v{base}", record["tag"])).chmod(0o755)
    for product, (crate, _, _) in INSTALLERS.items():
        installer = (ROOT / "crates" / crate / "install.sh").read_text()
        if installer.count('default_version=""') != 1:
            raise NightlyError("installer pinning template changed")
        installer = installer.replace(
            'default_version=""', f'default_version="{record["tag"]}"'
        )
        for name in (f"{product}-{record['tag']}-install.sh", f"{product}-install.sh"):
            (output / name).write_text(installer)
            (output / name).chmod(0o755)
    image_references = {}
    for name in image_names(base):
        reference = (images / f"{name}.digest").read_text().strip()
        if not re.fullmatch(
            rf"ghcr\.io/registrystack/{re.escape(name)}-candidate@sha256:[0-9a-f]{{64}}",
            reference,
        ):
            raise NightlyError("nightly staging image digest is invalid")
        image_references[name] = reference.replace(f"/{name}-candidate@", f"/{name}@")
        for suffix in ("grype.json", "sbom.spdx.json"):
            shutil.copy2(images / f"{name}.{suffix}", output / f"{name}.{suffix}")
        check_scan(images / f"{name}.grype.json")
    assets = [
        {"name": path.name, "sha256": digest(path)} for path in sorted(output.iterdir())
    ]
    record.pop("skip", None)
    record["assets"] = assets
    record["images"] = image_references
    (output / "nightly.json").write_text(json.dumps(record, indent=2) + "\n")
    # Include the manifest itself in SHA256SUMS without a self-referential hash.
    (output / "SHA256SUMS").write_text(
        "".join(f"{digest(path)}  {path.name}\n" for path in sorted(output.iterdir()))
    )
    read_manifest(output / "nightly.json")


def smoke(directory: Path) -> None:
    manifest = read_manifest(directory / "nightly.json")
    for asset in manifest["assets"]:
        name = asset["name"]
        if not name.endswith(f"-{manifest['tag']}-linux-amd64"):
            continue
        binary = name.removesuffix(f"-{manifest['tag']}-linux-amd64")
        expected = f"{binary} {manifest['version']}"
        if binary == "registry-render":
            source = (ROOT / "crates/registry-render/src/lib.rs").read_text()
            match = re.search(
                r'^pub const TYPST_PIN: &str = "([^" ]+)";$', source, re.MULTILINE
            )
            if match is None:
                raise NightlyError("Registry Render's Typst version pin is missing")
            expected += f" (typst {match[1]})"
        if run(str((directory / name).resolve()), "--version") != expected:
            raise NightlyError(f"nightly {binary} reports another build identity")
    for product, (_, prefix, binaries) in INSTALLERS.items():
        with tempfile.TemporaryDirectory(prefix="nightly-install-") as temporary:
            destination = Path(temporary) / "bin"
            environment = os.environ | {
                f"{prefix}_ASSET_DIR": str(directory.resolve()),
                f"{prefix}_INSTALL_DIR": str(destination),
            }
            subprocess.run(
                ["bash", str(directory / f"{product}-{manifest['tag']}-install.sh")],
                env=environment,
                check=True,
            )
            for binary in binaries + (
                ("scheduling",) if product == "scheduling" else ()
            ):
                if (
                    run(str(destination / binary), "--version")
                    != f"{binary} {manifest['version']}"
                ):
                    raise NightlyError(f"installed {binary} reports another version")


def require_file_closure(directory: Path, manifest: dict) -> dict[str, str]:
    expected = {asset["name"]: asset["sha256"] for asset in manifest["assets"]}
    expected.update(
        {name: digest(directory / name) for name in ("nightly.json", "SHA256SUMS")}
    )
    if {path.name for path in directory.iterdir()} != set(expected):
        raise NightlyError("publication directory differs from the manifest")
    for name, checksum in expected.items():
        if (directory / name).is_symlink() or digest(directory / name) != checksum:
            raise NightlyError(f"publication checksum mismatch: {name}")
    checksums = "".join(
        f"{expected[name]}  {name}\n"
        for name in sorted(expected)
        if name != "SHA256SUMS"
    )
    if (directory / "SHA256SUMS").read_text() != checksums:
        raise NightlyError("SHA256SUMS differs from the manifest closure")
    return expected


def publish(directory: Path, layouts: Path) -> None:
    manifest = read_manifest(directory / "nightly.json")
    expected = require_file_closure(directory, manifest)
    tag, sha = manifest["tag"], manifest["source_sha"]
    if (
        os.environ.get("GITHUB_SHA") != sha
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or run("git", "rev-parse", "HEAD") != sha
    ):
        raise NightlyError(
            "publication must use the exact protected-main workflow source"
        )
    # Check all existing destinations before any mutation. Public bytes are
    # recoverable only by exact reconciliation, never --clobber or tag moves.
    ref = optional_api(f"repos/{REPOSITORY}/git/ref/tags/{tag}")
    if ref is not None and (ref["object"].get("sha"), ref["object"].get("type")) != (
        sha,
        "commit",
    ):
        raise NightlyError("nightly source tag already names a different object")
    release = optional_api(f"repos/{REPOSITORY}/releases/tags/{tag}")
    existing_assets = set()
    if release is not None:
        if release.get("tag_name") != tag or not release.get("prerelease"):
            raise NightlyError("nightly destination is not the matching prerelease")
        existing_assets = {asset["name"] for asset in release["assets"]}
        if len(existing_assets) != len(release["assets"]) or not existing_assets <= set(
            expected
        ):
            raise NightlyError("existing nightly has unexpected assets")
        with tempfile.TemporaryDirectory() as temporary:
            for name in sorted(existing_assets):
                run(
                    "gh",
                    "release",
                    "download",
                    tag,
                    "--repo",
                    REPOSITORY,
                    "--pattern",
                    name,
                    "--dir",
                    temporary,
                )
                if digest(Path(temporary) / name) != expected[name]:
                    raise NightlyError(
                        f"published nightly bytes differ: {name}; fix forward"
                    )
        if not release["draft"] and existing_assets != set(expected):
            raise NightlyError("public nightly asset roster is incomplete; fix forward")
    image_states = {}
    for name, reference in manifest["images"].items():
        metadata = api(f"orgs/registrystack/packages/container/{name}")
        if metadata.get("name") != name or metadata.get("visibility") != "public":
            raise NightlyError(
                f"{name} must remain a public pre-provisioned image package"
            )
        destination = f"ghcr.io/registrystack/{name}:{tag}"
        result = subprocess.run(
            ["crane", "digest", destination], text=True, capture_output=True
        )
        if result.returncode and not (
            "MANIFEST_UNKNOWN" in result.stderr or "NAME_UNKNOWN" in result.stderr
        ):
            raise NightlyError(f"could not establish image destination state: {name}")
        current = result.stdout.strip() if result.returncode == 0 else None
        if current is not None and current != reference.split("@", 1)[1]:
            raise NightlyError(f"nightly image tag differs: {name}; fix forward")
        image_states[name] = current
    for name, current in image_states.items():
        if current is None:
            run(
                "oras",
                "cp",
                "--from-oci-layout",
                f"{layouts / (name + '.oci')}@{manifest['images'][name].split('@', 1)[1]}",
                f"ghcr.io/registrystack/{name}:{tag}",
            )
        if (
            run("crane", "digest", f"ghcr.io/registrystack/{name}:{tag}")
            != manifest["images"][name].split("@", 1)[1]
        ):
            raise NightlyError(f"published image digest mismatch: {name}")
    if ref is None:
        api(f"repos/{REPOSITORY}/git/refs", {"ref": f"refs/tags/{tag}", "sha": sha})
    if release is None:
        release = api(
            f"repos/{REPOSITORY}/releases",
            {
                "tag_name": tag,
                "target_commitish": sha,
                "name": f"Nightly {manifest['version']}",
                "body": f"Opt-in development build from `{sha}`. See release/NIGHTLY.md for installation and verification. Native client registries and numbered release docs are unchanged.",
                "draft": True,
                "prerelease": True,
                "make_latest": "false",
            },
        )
    missing = set(expected) - existing_assets
    for name in sorted(missing, key=lambda name: (name != "nightly.json", name)):
        run("gh", "release", "upload", tag, str(directory / name), "--repo", REPOSITORY)
    if release["draft"]:
        run(
            "gh",
            "release",
            "edit",
            tag,
            "--repo",
            REPOSITORY,
            "--draft=false",
            "--prerelease",
            "--latest=false",
        )
    # Authenticate the downloaded public closure before advancing the channel.
    with tempfile.TemporaryDirectory() as temporary:
        run("gh", "release", "download", tag, "--repo", REPOSITORY, "--dir", temporary)
        if {path.name for path in Path(temporary).iterdir()} != set(expected):
            raise NightlyError("public nightly asset roster mismatch")
        for name, checksum in expected.items():
            if digest(Path(temporary) / name) != checksum:
                raise NightlyError(f"public checksum mismatch: {name}")
    advance_channel(manifest, (directory / "nightly.json").read_text())


def advance_channel(manifest: dict, content: str) -> None:
    previous, head = channel_metadata()
    if head != manifest.get("channel_head"):
        if previous == manifest:
            return
        raise NightlyError(
            "nightly channel advanced during this build; refusing to move it backwards"
        )
    if head is None:
        # Create a metadata-only branch, rather than carrying the source tree.
        tree = api(
            f"repos/{REPOSITORY}/git/trees",
            {
                "tree": [
                    {
                        "path": "nightly.json",
                        "mode": "100644",
                        "type": "blob",
                        "content": content,
                    }
                ]
            },
        )
        parents = []
    else:
        base_tree = api(f"repos/{REPOSITORY}/git/commits/{head}")["tree"]["sha"]
        tree = api(
            f"repos/{REPOSITORY}/git/trees",
            {
                "base_tree": base_tree,
                "tree": [
                    {
                        "path": "nightly.json",
                        "mode": "100644",
                        "type": "blob",
                        "content": content,
                    }
                ],
            },
        )
        parents = [head]
    commit = api(
        f"repos/{REPOSITORY}/git/commits",
        {
            "message": (
                f"chore(release): advance nightly channel to {manifest['tag']}\n\n"
                "Signed-off-by: github-actions[bot] "
                "<41898282+github-actions[bot]@users.noreply.github.com>"
            ),
            "tree": tree["sha"],
            "parents": parents,
        },
    )
    if head is None:
        api(
            f"repos/{REPOSITORY}/git/refs",
            {"ref": f"refs/heads/{CHANNEL}", "sha": commit["sha"]},
        )
    else:
        run(
            "gh",
            "api",
            f"repos/{REPOSITORY}/git/refs/heads/{CHANNEL}",
            "--method",
            "PATCH",
            "--input",
            "-",
            input=json.dumps({"sha": commit["sha"], "force": False}),
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan").add_argument("--output", required=True, type=Path)
    subparsers.add_parser("check-scan").add_argument("report", type=Path)
    assemble_parser = subparsers.add_parser("assemble")
    assemble_parser.add_argument("--plan", required=True, type=Path)
    assemble_parser.add_argument("--binaries", required=True, type=Path, nargs="+")
    assemble_parser.add_argument("--images", required=True, type=Path)
    assemble_parser.add_argument("--output", required=True, type=Path)
    subparsers.add_parser("smoke").add_argument("directory", type=Path)
    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument("directory", type=Path)
    publish_parser.add_argument("--layouts", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "plan":
            plan(args.output)
        elif args.command == "check-scan":
            check_scan(args.report)
        elif args.command == "assemble":
            assemble(args.plan, args.binaries, args.images, args.output)
        elif args.command == "smoke":
            smoke(args.directory)
        else:
            publish(args.directory, args.layouts)
    except (NightlyError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        print(f"nightly release refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
