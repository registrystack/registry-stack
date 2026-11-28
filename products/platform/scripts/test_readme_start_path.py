"""Check that each product's first development start uses rstack."""

from pathlib import Path
import re
import unittest


PRODUCTS = (
    "breg", "casework", "evidence", "messaging", "scheduling", "documents",
    "coordinator", "adapter", "render", "discovery",
)
ROOT = Path(__file__).resolve().parents[2]


class ReadmeStartPath(unittest.TestCase):
    def test_first_start_block_uses_rstack(self):
        for product in PRODUCTS:
            with self.subTest(product=product):
                readme = (ROOT / product / "README.md").read_text(encoding="utf-8")
                heading = re.search(r"^## Start a development run\s*$", readme, re.MULTILINE)
                self.assertIsNotNone(heading, f"{product} has no development start section")
                section = re.split(r"^## ", readme[heading.end():], maxsplit=1, flags=re.MULTILINE)[0]
                block = re.search(r"^```(?:sh|bash)\b[^\n]*\n(.*?)^```", section, re.MULTILINE | re.DOTALL)
                self.assertIsNotNone(block, f"{product} start section has no shell block")
                self.assertRegex(block[1], r"\brstack(?: --format json)? dev start\b")


if __name__ == "__main__":
    unittest.main()
