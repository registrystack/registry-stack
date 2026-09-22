"""Build and import the Discovery PyO3 module for stdlib-only tests."""

from __future__ import annotations

import ctypes
import functools
import os
import pathlib
import platform
import shutil
import subprocess
import sys

_CRATE_ROOT = pathlib.Path(__file__).resolve().parents[2]
_WORKSPACE_ROOT = _CRATE_ROOT.parents[1]
_MODULE_NAME = "registry_discovery_client"
_TARGET_DEBUG = pathlib.Path(
    os.environ.get("CARGO_TARGET_DIR", _WORKSPACE_ROOT / "target")
) / "debug"
_IMPORT_DIR = _TARGET_DEBUG / "discovery_python_module"


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
        raise RuntimeError("the Discovery Python test bootstrap supports macOS and Linux")
    return _TARGET_DEBUG / f"lib{_MODULE_NAME}{suffix}"


@functools.cache
def ensure_built() -> None:
    subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "registry-discovery-client-py",
            "--lib",
            "--features",
            "registry-discovery-client-py/extension-module",
        ],
        cwd=_WORKSPACE_ROOT,
        check=True,
    )
    source = _library()
    if not source.is_file():
        raise RuntimeError(f"cargo did not produce {source}")
    _preload_cargo_runtime()
    _IMPORT_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, _IMPORT_DIR / f"{_MODULE_NAME}.so")
    if str(_IMPORT_DIR) not in sys.path:
        sys.path.insert(0, str(_IMPORT_DIR))
