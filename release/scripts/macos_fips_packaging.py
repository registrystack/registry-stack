#!/usr/bin/env python3
"""Relocate AWS-LC FIPS dylibs into self-contained macOS artifacts."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from collections import deque
from pathlib import Path
from typing import Sequence


FIPS_DYLIB = re.compile(r"^libaws_lc_fips_[A-Za-z0-9_]+\.dylib$")
SUPPORTED_SOURCE_PREFIX = "@rpath/"


class PackagingError(ValueError):
    """A macOS artifact cannot be made self-contained safely."""


def _regular_file(path: Path, description: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise PackagingError(f"missing {description}: {path}") from error
    if not stat.S_ISREG(mode):
        raise PackagingError(f"{description} must be a regular file: {path}")


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise PackagingError(f"cannot run {command[0]}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise PackagingError(f"{command[0]} failed for {command[-1]}: {detail}")
    return result.stdout


def _load_commands(path: Path) -> list[str]:
    output = _run(["otool", "-L", str(path)])
    commands: list[str] = []
    for line in output.splitlines()[1:]:
        entry = line.strip()
        if not entry:
            continue
        command, marker, _ = entry.partition(" (compatibility version ")
        if not marker or not command:
            raise PackagingError(f"cannot parse otool load command for {path}: {entry}")
        commands.append(command)
    return commands


def _fips_load_commands(path: Path, *, library: bool = False) -> dict[str, str]:
    commands: dict[str, str] = {}
    for command in _load_commands(path):
        name = Path(command).name
        if FIPS_DYLIB.fullmatch(name) is None:
            continue
        # A dylib reports its own install name in `otool -L`. It is identity,
        # not a dependency that needs to be relocated.
        if library and name == path.name:
            continue
        if not command.startswith(SUPPORTED_SOURCE_PREFIX):
            raise PackagingError(
                f"unsupported AWS-LC FIPS load command in {path}: {command}"
            )
        if command != f"{SUPPORTED_SOURCE_PREFIX}{name}":
            raise PackagingError(
                f"AWS-LC FIPS load command is not an exact basename in {path}: {command}"
            )
        previous = commands.setdefault(name, command)
        if previous != command:
            raise PackagingError(f"conflicting AWS-LC FIPS loads in {path}: {name}")
    return commands


def _resolve_library(name: str, roots: Sequence[Path]) -> Path:
    candidates: set[Path] = set()
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            raise PackagingError(f"library root must be a directory: {root}")
        direct = root / name
        if direct.exists() or direct.is_symlink():
            candidates.add(direct)
        for candidate in root.rglob(name):
            candidates.add(candidate)
    ordered = sorted(candidates)
    if not ordered:
        raise PackagingError(
            f"AWS-LC FIPS library {name} resolved to 0 files; expected at least one"
        )
    digests: set[str] = set()
    for candidate in ordered:
        _regular_file(candidate, "AWS-LC FIPS library")
        digest = hashlib.sha256()
        with candidate.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        digests.add(digest.hexdigest())
    if len(digests) != 1:
        raise PackagingError(
            f"AWS-LC FIPS library {name} resolved to {len(ordered)} nonidentical files"
        )
    return ordered[0]


def _loader_reference(consumer: Path, library_directory: Path, name: str) -> str:
    relative = os.path.relpath(library_directory, consumer.parent)
    if relative == ".":
        return f"@loader_path/{name}"
    return f"@loader_path/{Path(relative).as_posix()}/{name}"


def _replace_load(path: Path, old: str, new: str) -> None:
    _run(["install_name_tool", "-change", old, new, str(path)])


def _sign_and_verify(path: Path) -> None:
    _run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(path)])
    _run(["codesign", "--verify", "--strict", str(path)])


def bundle_macos_fips(
    consumers: Sequence[Path],
    library_roots: Sequence[Path],
    library_directory: Path,
) -> list[str]:
    """Bundle and relocate the complete FIPS dylib closure for consumers.

    Consumers are staged Mach-O files and are modified in place. Libraries are
    copied from the explicit build roots into ``library_directory``. Every
    AWS-LC FIPS load is changed from its build-time ``@rpath`` reference to the
    path relative to the referencing Mach-O file's ``@loader_path``.
    """

    if not consumers:
        raise PackagingError("at least one macOS consumer is required")
    if not library_roots:
        raise PackagingError("at least one AWS-LC FIPS library root is required")
    normalized_consumers = [Path(path) for path in consumers]
    if len(set(normalized_consumers)) != len(normalized_consumers):
        raise PackagingError("macOS consumers must be unique")
    for consumer in normalized_consumers:
        _regular_file(consumer, "macOS consumer")

    direct_loads: dict[Path, dict[str, str]] = {}
    pending: deque[str] = deque()
    for consumer in normalized_consumers:
        loads = _fips_load_commands(consumer)
        if not loads:
            raise PackagingError(f"macOS consumer has no AWS-LC FIPS dylib: {consumer}")
        direct_loads[consumer] = loads
        pending.extend(loads)

    resolved: dict[str, Path] = {}
    library_loads: dict[str, dict[str, str]] = {}
    while pending:
        name = pending.popleft()
        if name in resolved:
            continue
        source = _resolve_library(name, library_roots)
        if source.name != name:
            raise PackagingError(f"AWS-LC FIPS library basename changed: {source}")
        resolved[name] = source
        loads = _fips_load_commands(source, library=True)
        library_loads[name] = loads
        pending.extend(loads)

    if library_directory.exists():
        if not library_directory.is_dir() or library_directory.is_symlink():
            raise PackagingError(
                f"library destination must be a directory: {library_directory}"
            )
    else:
        library_directory.mkdir(parents=True)

    copied: dict[str, Path] = {}
    for name in sorted(resolved):
        destination = library_directory / name
        if destination.exists() or destination.is_symlink():
            raise PackagingError(f"library destination already exists: {destination}")
        shutil.copyfile(resolved[name], destination)
        destination.chmod(0o755)
        copied[name] = destination

    for consumer, loads in direct_loads.items():
        for name, old in sorted(loads.items()):
            _replace_load(
                consumer,
                old,
                _loader_reference(consumer, library_directory, name),
            )
    for name, loads in library_loads.items():
        library = copied[name]
        for dependency, old in sorted(loads.items()):
            _replace_load(library, old, f"@loader_path/{dependency}")

    for path in [*normalized_consumers, *(copied[name] for name in sorted(copied))]:
        _sign_and_verify(path)

    for consumer, expected in direct_loads.items():
        final = {
            Path(command).name: command
            for command in _load_commands(consumer)
            if FIPS_DYLIB.fullmatch(Path(command).name)
        }
        wanted = {
            name: _loader_reference(consumer, library_directory, name)
            for name in expected
        }
        if final != wanted:
            raise PackagingError(
                f"relocated AWS-LC FIPS loads do not match package layout for {consumer}"
            )
    for name, expected in library_loads.items():
        final = {
            Path(command).name: command
            for command in _load_commands(copied[name])
            if FIPS_DYLIB.fullmatch(Path(command).name) and Path(command).name != name
        }
        wanted = {dependency: f"@loader_path/{dependency}" for dependency in expected}
        if final != wanted:
            raise PackagingError(
                f"relocated AWS-LC FIPS library closure is incomplete for {name}"
            )
    return sorted(copied)


def _tar_info(path: Path, name: str, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = path.stat().st_size
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


def _write_deterministic_archive(
    output: Path, members: Sequence[tuple[Path, str, int]]
) -> None:
    if output.exists() or output.is_symlink():
        raise PackagingError(f"archive output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.parent / f".{output.name}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise PackagingError(f"temporary archive path already exists: {temporary}")
    try:
        with temporary.open("xb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT
                ) as archive:
                    for path, name, mode in members:
                        with path.open("rb") as source:
                            archive.addfile(_tar_info(path, name, mode), source)
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def archive_macos_fips_binary(
    *,
    binary: Path,
    asset_name: str,
    library_roots: Sequence[Path],
    notice: Path,
    output: Path,
) -> list[str]:
    """Create one deterministic, directly runnable macOS binary archive."""

    if Path(asset_name).name != asset_name or not asset_name:
        raise PackagingError(f"asset name must be one basename: {asset_name}")
    if not asset_name.endswith("-macos-arm64"):
        raise PackagingError(
            f"asset name is not a macOS arm64 release asset: {asset_name}"
        )
    _regular_file(binary, "macOS release binary")
    _regular_file(notice, "third-party notice")

    with tempfile.TemporaryDirectory(prefix="registry-macos-fips-") as temporary:
        staging = Path(temporary)
        staged_binary = staging / asset_name
        shutil.copyfile(binary, staged_binary)
        staged_binary.chmod(0o755)
        libraries = bundle_macos_fips([staged_binary], library_roots, staging)
        staged_notice = staging / "THIRD_PARTY_NOTICES"
        shutil.copyfile(notice, staged_notice)
        staged_notice.chmod(0o644)
        members = [
            (staged_binary, asset_name, 0o755),
            *((staging / name, name, 0o755) for name in libraries),
            (staged_notice, "THIRD_PARTY_NOTICES", 0o644),
        ]
        _write_deterministic_archive(output, members)
    return libraries


def extract_macos_binary_archive(
    archive: Path, destination: Path, expected_executable: str
) -> Path:
    """Strictly extract one self-contained Registry Stack macOS binary."""

    _regular_file(archive, "macOS binary archive")
    if Path(expected_executable).name != expected_executable or not expected_executable:
        raise PackagingError(
            f"expected executable must be one basename: {expected_executable}"
        )
    if destination.exists() or destination.is_symlink():
        raise PackagingError(f"archive destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
    )
    try:
        with tarfile.open(archive, mode="r:gz") as package:
            members = package.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                raise PackagingError("macOS binary archive repeats a member name")
            libraries = sorted(
                name for name in names if FIPS_DYLIB.fullmatch(name) is not None
            )
            expected = [expected_executable, *libraries, "THIRD_PARTY_NOTICES"]
            if not libraries or names != expected:
                raise PackagingError(
                    "macOS binary archive member roster is not canonical: "
                    f"expected {expected}, found {names}"
                )
            for member in members:
                if Path(member.name).name != member.name or not member.isfile():
                    raise PackagingError(
                        f"macOS binary archive member is not a flat regular file: {member.name}"
                    )
                expected_mode = 0o644 if member.name == "THIRD_PARTY_NOTICES" else 0o755
                if stat.S_IMODE(member.mode) != expected_mode:
                    raise PackagingError(
                        f"macOS binary archive member has wrong mode: {member.name}"
                    )
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname not in (None, "")
                    or member.gname not in (None, "")
                    or member.mtime != 0
                ):
                    raise PackagingError(
                        f"macOS binary archive member metadata is not canonical: {member.name}"
                    )
                source = package.extractfile(member)
                if source is None:
                    raise PackagingError(
                        f"cannot read macOS binary archive member: {member.name}"
                    )
                output = temporary / member.name
                with source, output.open("xb") as handle:
                    shutil.copyfileobj(source, handle)
                output.chmod(expected_mode)
        os.replace(temporary, destination)
    except tarfile.TarError as error:
        shutil.rmtree(temporary, ignore_errors=True)
        raise PackagingError(f"cannot read macOS binary archive: {error}") from error
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination / expected_executable


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    archive = subparsers.add_parser("archive")
    archive.add_argument("--binary", required=True, type=Path)
    archive.add_argument("--asset-name", required=True)
    archive.add_argument("--library-root", required=True, action="append", type=Path)
    archive.add_argument("--notice", required=True, type=Path)
    archive.add_argument("--output", required=True, type=Path)
    extract = subparsers.add_parser("extract")
    extract.add_argument("--archive", required=True, type=Path)
    extract.add_argument("--destination", required=True, type=Path)
    extract.add_argument("--expected-executable", required=True)
    args = parser.parse_args()
    try:
        if args.command == "archive":
            archive_macos_fips_binary(
                binary=args.binary,
                asset_name=args.asset_name,
                library_roots=args.library_root,
                notice=args.notice,
                output=args.output,
            )
        else:
            extract_macos_binary_archive(
                args.archive, args.destination, args.expected_executable
            )
    except (OSError, PackagingError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
