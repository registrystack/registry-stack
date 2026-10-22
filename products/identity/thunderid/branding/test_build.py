#!/usr/bin/env python3
"""Focused tests for the branding packager's asset base URL handling."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("build.py")


def load_module():
    spec = importlib.util.spec_from_file_location("branding_build", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AssetBaseTests(unittest.TestCase):
    def setUp(self):
        self.build = load_module()
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)

    def fresh_output(self) -> Path:
        return Path(tempfile.mkdtemp(dir=self.workspace.name)) / "branding"

    def refusal(self, asset_base: str) -> str:
        output = self.fresh_output()
        with self.assertRaises(ValueError) as refused:
            self.build.build(output, asset_base)
        self.assertFalse(output.exists(), asset_base)
        return str(refused.exception)

    def test_a_query_fragment_or_credential_is_refused(self):
        for asset_base in (
            "/identity-assets/registry-stack?v=1",
            "/identity-assets/registry-stack#top",
            "https://user:secret@assets.example.test/registry-stack",
        ):
            with self.subTest(asset_base=asset_base):
                self.assertEqual(
                    self.refusal(asset_base),
                    "asset base must not contain credentials, a query, or a fragment",
                )

    def test_a_bare_query_or_fragment_delimiter_is_refused(self):
        # urlsplit reports an empty query or fragment for a trailing delimiter,
        # yet the browser would still read everything after it as one.
        for asset_base in (
            "/identity-assets/registry-stack?",
            "/identity-assets/registry-stack#",
            "https://assets.example.test/registry-stack?",
        ):
            with self.subTest(asset_base=asset_base):
                self.assertEqual(
                    self.refusal(asset_base),
                    "asset base must not contain credentials, a query, or a fragment",
                )

    def test_a_root_relative_path_or_https_url_rewrites_the_font_url(self):
        for asset_base, expected in (
            ("/identity-assets/registry-stack/", "/identity-assets/registry-stack/fonts/"),
            ("https://assets.example.test/registry-stack", "https://assets.example.test/registry-stack/fonts/"),
        ):
            with self.subTest(asset_base=asset_base):
                output = self.fresh_output()
                with contextlib.redirect_stdout(io.StringIO()):
                    self.build.build(output, asset_base)
                stylesheet = (output / "registry-stack.css").read_text()
                self.assertIn(f"url(\"{expected}", stylesheet)
                self.assertNotIn(self.build.DEFAULT_ASSET_BASE, stylesheet)


if __name__ == "__main__":
    unittest.main()
