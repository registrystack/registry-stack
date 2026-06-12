#!/usr/bin/env python3
"""Tests for the live-service walkthrough report page (demo-live-stories.py)."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent / "demo-live-stories.py"
_spec = importlib.util.spec_from_file_location("demo_live_stories", MODULE_PATH)
assert _spec and _spec.loader
stories = importlib.util.module_from_spec(_spec)
# Register before exec: the module defines dataclasses, which resolve their
# namespace through sys.modules at class-creation time.
sys.modules["demo_live_stories"] = stories
_spec.loader.exec_module(stories)


def _render_report() -> str:
    """Render the report with empty fixtures; every artifact lookup tolerates absence."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        stories.write_interactive_story_html(
            out,
            {"case_summary": "Demo case summary.", "known_demo_shortcuts": []},
            {"entries": []},
        )
        return (out / "index.html").read_text(encoding="utf-8")


class WalkthroughCivicPrintTest(unittest.TestCase):
    """The walkthrough report follows the registrystack.org civic-print language."""

    def test_css_has_no_gradient_header_or_rounded_corners(self) -> None:
        self.assertNotIn("linear-gradient", stories.WALKTHROUGH_CSS)
        self.assertNotIn("border-radius", stories.WALKTHROUGH_CSS)

    def test_css_uses_the_civic_print_palette_and_type(self) -> None:
        for marker in ("#161616", "#173b7a", "#9d2c1d", "#d4af4e", "Public Sans", "IBM Plex Mono"):
            self.assertIn(marker, stories.WALKTHROUGH_CSS)
        # The old report palette must be gone.
        for vetoed in ("#1f6feb", "#102030", "#204b57", "Inter,"):
            self.assertNotIn(vetoed, stories.WALKTHROUGH_CSS)

    def test_report_opens_on_an_ink_band_with_brass_eyebrow(self) -> None:
        doc = _render_report()
        self.assertIn('class="eyebrow"', doc)
        self.assertIn("Demo case summary.", doc)
        self.assertNotIn("linear-gradient", doc)

    def test_step_jump_respects_reduced_motion(self) -> None:
        doc = _render_report()
        self.assertIn("prefers-reduced-motion", doc)


if __name__ == "__main__":
    unittest.main()
