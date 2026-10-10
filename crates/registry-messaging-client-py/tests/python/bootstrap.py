"""Build and import the Messaging PyO3 module for stdlib-only tests."""

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
_MODULE_NAME = "registry_messaging_client"


@functools.cache
def _target_debug() -> pathlib.Path:
    # Ask Cargo from the directory the build runs in, so CARGO_TARGET_DIR,
    # CARGO_BUILD_TARGET_DIR, a relative value and the `target` default all
    # resolve exactly as they did for that build.
    metadata = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
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


def _preload_cargo_runtime() -> None:
    if platform.system() != "Darwin":
        return
    runtime_directory = os.environ.get("REGISTRY_CARGO_RUNTIME_LIBRARY_PATH")
    if runtime_directory is None:
        return
    libraries = list(
        pathlib.Path(runtime_directory).glob("libaws_lc_fips*_crypto.dylib")
    )
    if len(libraries) != 1:
        raise RuntimeError(
            "expected one AWS-LC FIPS runtime library in "
            f"{runtime_directory}, found {len(libraries)}"
        )
    ctypes.CDLL(str(libraries[0]), mode=ctypes.RTLD_GLOBAL)


def _library() -> pathlib.Path:
    suffix = {"Darwin": ".dylib", "Linux": ".so"}.get(platform.system())
    if suffix is None:
        raise RuntimeError("the Messaging Python tests support macOS and Linux")
    return _target_debug() / f"lib{_MODULE_NAME}{suffix}"


@functools.cache
def ensure_built() -> None:
    subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "registry-messaging-client-py",
            "--lib",
            "--features",
            "registry-messaging-client-py/extension-module",
        ],
        cwd=_WORKSPACE_ROOT,
        check=True,
    )
    source = _library()
    if not source.is_file():
        raise RuntimeError(f"cargo did not produce {source}")
    _preload_cargo_runtime()
    import_root = _target_debug() / "messaging_python_module"
    import_package = import_root / _MODULE_NAME
    import_package.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        _CRATE_ROOT / "python" / _MODULE_NAME / "__init__.py",
        import_package / "__init__.py",
    )
    shutil.copyfile(source, import_package / f"{_MODULE_NAME}.so")
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))
