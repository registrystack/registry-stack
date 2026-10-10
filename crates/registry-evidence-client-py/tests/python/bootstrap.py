"""Builds the `registry_evidence_client` extension module via plain `cargo
build` (no maturin) and makes it importable, for the stdlib-only Python test
suite.

Every test file in this directory begins with the same few lines, inserting
this file's own directory onto `sys.path` before importing it. That is
deliberate: it works identically whether a test file is run directly, through
`python3 -m unittest discover`, or by dotted module name, without this
directory needing to be a real Python package (no `__init__.py`) or without
depending on how `unittest discover`'s top-level and start directories happen
to be set. See the crate's own README for the exact command this suite is
run with.
"""

from __future__ import annotations

import ctypes
import functools
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys

_CRATE_ROOT = pathlib.Path(__file__).resolve().parents[2]
_WORKSPACE_ROOT = _CRATE_ROOT.parents[1]
_MODULE_NAME = "registry_evidence_client"

_built = False


@functools.cache
def _target_debug() -> pathlib.Path:
    # Ask Cargo from the directory the build runs in, so CARGO_TARGET_DIR,
    # CARGO_BUILD_TARGET_DIR, a relative value and the `target` default all
    # resolve exactly as they did for that build.
    metadata = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
        cwd=_WORKSPACE_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    if metadata.returncode != 0:
        raise RuntimeError(
            "cargo metadata failed, so the Cargo target directory is unknown:\n"
            + metadata.stderr
        )
    return pathlib.Path(json.loads(metadata.stdout)["target_directory"]) / "debug"


def cargo_runtime_library() -> str | None:
    """The AWS-LC FIPS library the extension needs preloaded, or None.

    Only macOS with REGISTRY_CARGO_RUNTIME_LIBRARY_PATH set names one. A child
    interpreter that imports the extension must preload it as well: System
    Integrity Protection strips `DYLD_*` from protected executables, so the
    dynamic loader cannot be relied on to find it there.
    """
    if platform.system() != "Darwin":
        return None
    runtime_directory = os.environ.get("REGISTRY_CARGO_RUNTIME_LIBRARY_PATH")
    if runtime_directory is None:
        return None
    libraries = list(
        pathlib.Path(runtime_directory).glob("libaws_lc_fips*_crypto.dylib")
    )
    if len(libraries) != 1:
        raise RuntimeError(
            "expected one AWS-LC FIPS runtime library in "
            f"{runtime_directory}, found {len(libraries)}"
        )
    return str(libraries[0])


def _preload_cargo_runtime() -> None:
    library = cargo_runtime_library()
    if library is not None:
        ctypes.CDLL(library, mode=ctypes.RTLD_GLOBAL)


def _built_cdylib_path() -> pathlib.Path:
    system = platform.system()
    if system == "Darwin":
        name = f"lib{_MODULE_NAME}.dylib"
    elif system == "Linux":
        name = f"lib{_MODULE_NAME}.so"
    else:
        raise RuntimeError(
            f"the Python suite's cargo-build bootstrap does not know the "
            f"cdylib naming convention for {system!r}; macOS and Linux are "
            f"the only platforms this crate's local test bootstrap supports"
        )
    return _target_debug() / name


def ensure_built() -> None:
    """Build the extension module and put it on `sys.path`, once per process.

    This shells out to `cargo build` with this crate's own `extension-module`
    feature, exactly the command the crate's README documents for a manual
    build. It requires `python3` on `PATH` at build time: PyO3's own build
    script probes the interpreter it is building against. Short of maturin,
    which this crate's build/test approach deliberately keeps out of CI (see
    the README), there is no way around that requirement.
    """
    global _built
    if _built:
        return

    subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "registry-evidence-client-py",
            "--lib",
            "--features",
            "registry-evidence-client-py/extension-module",
        ],
        cwd=_WORKSPACE_ROOT,
        check=True,
    )

    built_path = _built_cdylib_path()
    if not built_path.is_file():
        raise RuntimeError(
            f"cargo build reported success but {built_path} does not exist; "
            f"the crate's `[lib] name` or this bootstrap's naming convention "
            f"has drifted"
        )

    _preload_cargo_runtime()
    import_dir = _target_debug() / "python_module"
    import_dir.mkdir(parents=True, exist_ok=True)
    # CPython's import machinery accepts a plain `.so` suffix for an
    # extension module on both macOS and Linux, with no ABI or version tag
    # needed: confirmed by importing a module built and renamed exactly this
    # way. The copy (not the original build artifact) is what every test
    # imports, so Cargo's shared debug output directory, which already holds
    # Cargo's own outputs for every crate, never gains a Python-import-shaped
    # file of its own.
    imported_path = import_dir / f"{_MODULE_NAME}.so"
    shutil.copyfile(built_path, imported_path)

    if str(import_dir) not in sys.path:
        sys.path.insert(0, str(import_dir))

    _built = True
