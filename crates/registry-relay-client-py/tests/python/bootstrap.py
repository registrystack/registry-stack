"""Build and import the Relay PyO3 module for stdlib-only tests."""

from __future__ import annotations

import pathlib
import platform
import shutil
import subprocess
import sys

_CRATE_ROOT = pathlib.Path(__file__).resolve().parents[2]
_WORKSPACE_ROOT = _CRATE_ROOT.parents[1]
_MODULE_NAME = "registry_relay_client"
_TARGET_DEBUG = _WORKSPACE_ROOT / "target" / "debug"
_IMPORT_DIR = _TARGET_DEBUG / "relay_python_module"
_built = False


def _library() -> pathlib.Path:
    suffix = {"Darwin": ".dylib", "Linux": ".so"}.get(platform.system())
    if suffix is None:
        raise RuntimeError("the Relay Python test bootstrap supports macOS and Linux")
    return _TARGET_DEBUG / f"lib{_MODULE_NAME}{suffix}"


def ensure_built() -> None:
    global _built
    if _built:
        return
    subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "registry-relay-client-py",
            "--lib",
            "--features",
            "registry-relay-client-py/extension-module",
        ],
        cwd=_WORKSPACE_ROOT,
        check=True,
    )
    source = _library()
    if not source.is_file():
        raise RuntimeError(f"cargo did not produce {source}")
    _IMPORT_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, _IMPORT_DIR / f"{_MODULE_NAME}.so")
    if str(_IMPORT_DIR) not in sys.path:
        sys.path.insert(0, str(_IMPORT_DIR))
    _built = True
