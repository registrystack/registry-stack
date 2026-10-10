"""Build and import the Messaging PyO3 module for stdlib-only tests."""

from __future__ import annotations

import functools
import json
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
