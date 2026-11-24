# /// script
# requires-python = ">=3.12"
# dependencies = ["pillow==12.3.0", "pypdfium2==5.15.2", "zxing-cpp==3.1.1"]
# ///
# SPDX-License-Identifier: Apache-2.0
"""Issue a test PDF, scan its rendered page, and follow the decoded URL to the issuer."""

import hashlib
import json
import os
import re
import select
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import ProxyHandler, build_opener

import pypdfium2 as pdfium
import zxingcpp

EXAMPLE = Path(__file__).resolve().parent
PUBLIC_ISSUED = (
    EXAMPLE.parents[3] / "docs/site/public/examples/population-extract/issued"
)
PUBLIC_LOOKUP = "https://docs.registrystack.org/dev/examples/population-extract/verify/"


class PrintedReferenceJourney(unittest.TestCase):
    def scan_printed_reference(self, path, reference):
        with pdfium.PdfDocument(path) as pdf:
            self.assertEqual(len(pdf), 1)
            page = pdf[0]
            text = " ".join(page.get_textpage().get_text_bounded().split())
            self.assertIn(reference, text)
            self.assertIn("FICTIONAL TEST SEAL", text)
            self.assertIn("not a valid official document.", text)
            codes = zxingcpp.read_barcodes(
                page.render(scale=2).to_pil(), formats=zxingcpp.BarcodeFormat.QRCode
            )
            self.assertEqual(len(codes), 1)
            return codes[0].text

    def test_published_pages_point_to_their_own_public_receipt(self):
        receipts = sorted(PUBLIC_ISSUED.glob("*/receipt.json"))
        self.assertTrue(receipts, "include at least one signed public specimen")
        for path in receipts:
            reference = path.parent.name
            with self.subTest(reference=reference):
                receipt = json.loads(path.read_bytes())
                pdf = path.with_name("document.pdf")
                self.assertEqual(receipt["reference"], reference)
                self.assertEqual(
                    receipt["signedFileDigest"],
                    "sha256:" + hashlib.sha256(pdf.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    self.scan_printed_reference(pdf, reference),
                    PUBLIC_LOOKUP + "?ref=" + reference,
                )

    def test_scan_reaches_the_receipt_for_this_pdf(self):
        with TemporaryDirectory(prefix="render-qr-journey-") as registry:
            server = subprocess.Popen(
                [
                    "node",
                    EXAMPLE / "serve.mjs",
                    "--registry",
                    registry,
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "0",
                ],
                text=True,
                stdout=subprocess.PIPE,
            )
            try:
                self.assertTrue(
                    select.select([server.stdout], [], [], 10)[0],
                    "verification server did not start",
                )
                ready = re.search(
                    r"http://127\.0\.0\.1:[0-9]+", server.stdout.readline()
                )
                self.assertIsNotNone(
                    ready, "verification server did not print its address"
                )
                issued = subprocess.run(
                    [
                        "node",
                        EXAMPLE / "issue.mjs",
                        "--registry",
                        registry,
                        "--origin",
                        ready.group(),
                        "--render",
                        os.environ.get("REGISTRY_RENDER_BIN", "registry-render"),
                    ],
                    check=False,
                    text=True,
                    capture_output=True,
                    timeout=60,
                )
                self.assertEqual(issued.returncode, 0, issued.stderr)
                specimen = json.loads(issued.stdout)
                decoded = self.scan_printed_reference(
                    specimen["pdf"], specimen["reference"]
                )
                self.assertEqual(decoded, specimen["url"])
                self.assertEqual(
                    decoded,
                    ready.group() + "/verify?ref=" + specimen["reference"],
                )
                opener = build_opener(ProxyHandler({}))
                with opener.open(decoded, timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    result = response.read().decode()
                self.assertIn(specimen["reference"], result)
                self.assertNotIn("NB-P-0001", result)
                self.assertNotIn("Ada Example", result)
            finally:
                server.terminate()
                server.wait(timeout=10)
                server.stdout.close()


if __name__ == "__main__":
    unittest.main()
