#!/usr/bin/env python3
"""Tests for the eSignet callback result page (capture-esignet-callback.py)."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent / "capture-esignet-callback.py"
_spec = importlib.util.spec_from_file_location("capture_esignet_callback", MODULE_PATH)
assert _spec and _spec.loader
callback = importlib.util.module_from_spec(_spec)
sys.modules["capture_esignet_callback"] = callback
_spec.loader.exec_module(callback)


class CallbackPageTest(unittest.TestCase):
    """The post-login page is small but wears the civic-print identity."""

    def test_page_escapes_title_and_next_step(self) -> None:
        page = callback.page_html("<script>x</script>", "detail", "<b>next</b>")
        self.assertNotIn("<script>x</script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("&lt;b&gt;next&lt;/b&gt;", page)

    def test_page_carries_the_civic_print_identity(self) -> None:
        page = callback.page_html("Authorization code captured", "Saved.", "Run: just citizen-code")
        self.assertIn('class="eyebrow"', page)
        self.assertIn("Registry Lab", page)
        for marker in ("#161616", "#173b7a", "Public Sans", "IBM Plex Mono"):
            self.assertIn(marker, page)
        self.assertIn("Run: just citizen-code", page)


if __name__ == "__main__":
    unittest.main()
