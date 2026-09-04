"""Build and import the Base Registry PyO3 module for stdlib-only tests."""

from __future__ import annotations

import functools
import pathlib
import platform
import shutil
import subprocess
import sys

_CRATE_ROOT = pathlib.Path(__file__).resolve().parents[2]
_WORKSPACE_ROOT = _CRATE_ROOT.parents[1]
_MODULE_NAME = "registry_breg_client"
_TARGET_DEBUG = _WORKSPACE_ROOT / "target" / "debug"
_IMPORT_ROOT = _TARGET_DEBUG / "breg_python_module"
_IMPORT_PACKAGE = _IMPORT_ROOT / _MODULE_NAME


def _library() -> pathlib.Path:
    suffix = {"Darwin": ".dylib", "Linux": ".so"}.get(platform.system())
    if suffix is None:
        raise RuntimeError("the Base Registry Python tests support macOS and Linux")
    return _TARGET_DEBUG / f"lib{_MODULE_NAME}{suffix}"


@functools.cache
def ensure_built() -> None:
    subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "registry-breg-client-py",
            "--lib",
            "--features",
            "registry-breg-client-py/extension-module",
        ],
        cwd=_WORKSPACE_ROOT,
        check=True,
    )
    source = _library()
    if not source.is_file():
        raise RuntimeError(f"cargo did not produce {source}")
    _IMPORT_PACKAGE.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        _CRATE_ROOT / "python" / _MODULE_NAME / "__init__.py",
        _IMPORT_PACKAGE / "__init__.py",
    )
    shutil.copyfile(source, _IMPORT_PACKAGE / f"{_MODULE_NAME}.so")
    if str(_IMPORT_ROOT) not in sys.path:
        sys.path.insert(0, str(_IMPORT_ROOT))
