from __future__ import annotations

import importlib.util
import contextlib
import io
import sys
import types
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def _load_script(name: str, relative_path: str):
    if name == "run_scenario":
        sys.modules.setdefault("psutil", types.SimpleNamespace(Process=object))
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _Response:
    def __init__(self, status: int):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _ProbeHTTPError(urllib.error.HTTPError):
    def __init__(self, status: int):
        Exception.__init__(self, "probe failed")
        self.url = "http://127.0.0.1/probe"
        self.filename = self.url
        self.code = status
        self.msg = "probe failed"
        self.hdrs = None
        self.headers = None
        self.fp = None


def _http_error(status: int) -> urllib.error.HTTPError:
    return _ProbeHTTPError(status)


class ReadinessProbeTests(unittest.TestCase):
    def test_run_scenario_wait_for_requires_2xx(self) -> None:
        module = _load_script("run_scenario", "perf/scripts/run_scenario.py")
        with patch.object(module.time, "monotonic", side_effect=[0.0, 0.01, 1.0]):
            with patch.object(module.time, "sleep"):
                with patch.object(module.urllib.request, "urlopen", side_effect=_http_error(401)):
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertFalse(module._wait_for("http://127.0.0.1/probe", {}, 0.1))

        with patch.object(module.urllib.request, "urlopen", return_value=_Response(200)):
            self.assertTrue(module._wait_for("http://127.0.0.1/probe", {}, 0.1))

    def test_capture_baseline_wait_for_requires_2xx(self) -> None:
        module = _load_script("capture_baseline", "perf/scripts/capture_baseline.py")
        with patch.object(module.time, "monotonic", side_effect=[0.0, 0.01, 1.0]):
            with patch.object(module.time, "sleep"):
                with patch.object(module.urllib.request, "urlopen", side_effect=_http_error(404)):
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertFalse(module._wait_for("http://127.0.0.1/probe", {}, 0.1))

        with patch.object(module.urllib.request, "urlopen", return_value=_Response(204)):
            self.assertTrue(module._wait_for("http://127.0.0.1/probe", {}, 0.1))


if __name__ == "__main__":
    unittest.main()
