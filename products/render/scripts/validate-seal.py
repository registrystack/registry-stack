#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyhanko==0.38.1"]
# ///
# SPDX-License-Identifier: Apache-2.0
"""Validate a sealed Render PDF with an independent PAdES validator (pyHanko).

Checks, against operator-supplied trust roots and with no network access:

* the signature is intact and valid and chains to a trust root;
* the signature covers the entire file;
* it is a certification signature with DocMDP P=2;
* the SubFilter is ETSI.CAdES.detached;
* the signed attributes carry no signingTime;
* whether a signature timestamp is present and valid (level B-B or B-T);
* with --document-digest, the first revision (the file cut at the original
  %%EOF before the signature update) has the given digest, the answer's
  documentDigest (sha256:<hex>).

The report is JSON on stdout and names no certificate subjects. The exit code
is 0 only when every check passes.

    uv run --script validate-seal.py --pdf sealed.pdf --trust-root root.pem \\
        [--trust-root other.pem] [--document-digest sha256:<hex>]
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

EXPECTED_SUBFILTER = "/ETSI.CAdES.detached"
EXPECTED_DOCMDP_NAME = "FILL_FORMS"  # DocMDP P=2
EOF_MARKER = b"%%EOF"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def first_revision_end(pdf: bytes) -> int | None:
    """Offset just past the first revision's %%EOF marker.

    Render's first revision ends at the marker with no end-of-line; the
    signature update starts with its own. The signature update's trailer points back (/Prev) at the first
    revision's cross-reference section; the first %%EOF at or after that
    offset closes the first revision.
    """
    startxrefs = list(re.finditer(rb"startxref\s+(\d+)\s+%%EOF", pdf))
    if len(startxrefs) < 2:
        return None
    # The last startxref belongs to the update; read /Prev from its trailer.
    last = startxrefs[-1]
    update_xref = int(last.group(1))
    trailer = pdf[update_xref : last.start()]
    prev = re.search(rb"/Prev\s+(\d+)", trailer)
    if prev is None:
        return None
    eof = pdf.find(EOF_MARKER, int(prev.group(1)))
    if eof < 0:
        return None
    end = eof + len(EOF_MARKER)
    return end


def check(name: str, ok: bool, detail: Any = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"name": name, "ok": bool(ok)}
    if detail is not None:
        entry["detail"] = detail
    return entry


def first_revision_check(pdf: bytes, document_digest: str) -> dict[str, Any]:
    """Whether the first revision has the labelled digest `document_digest`."""
    end = first_revision_end(pdf)
    digest = (
        "sha256:" + hashlib.sha256(pdf[:end]).hexdigest() if end is not None else None
    )
    return check(
        "first-revision-digest",
        digest == document_digest,
        {"firstRevisionLength": end, "digest": digest},
    )


def labelled_digest(value: str) -> str:
    if DIGEST.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "expected sha256:<64 lowercase hex digits>, the answer's documentDigest"
        )
    return value


def validate(
    pdf: bytes, trust_roots: list[Path], document_digest: str | None
) -> dict[str, Any]:
    from pyhanko.keys import load_cert_from_pemder
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko.sign.validation.status import SignatureCoverageLevel
    from pyhanko_certvalidator import ValidationContext

    checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {"level": None, "checks": checks}

    reader = PdfFileReader(io.BytesIO(pdf))
    signatures = reader.embedded_signatures
    checks.append(
        check("one-signature", len(signatures) == 1, {"count": len(signatures)})
    )
    if len(signatures) != 1:
        return report
    sig = signatures[0]

    roots = [load_cert_from_pemder(str(path)) for path in trust_roots]
    context = ValidationContext(
        trust_roots=roots, allow_fetching=False, revocation_mode="soft-fail"
    )
    status = validate_pdf_signature(sig, signer_validation_context=context)

    checks.append(check("intact", status.intact))
    checks.append(check("valid", status.valid))
    checks.append(check("trusted", status.trusted))
    checks.append(check("not-revoked", not status.revoked))
    checks.append(
        check(
            "covers-entire-file",
            status.coverage == SignatureCoverageLevel.ENTIRE_FILE,
            {"coverage": status.coverage.name if status.coverage else None},
        )
    )

    docmdp = sig.docmdp_level
    checks.append(
        check(
            "certification-docmdp-p2",
            docmdp is not None and docmdp.name == EXPECTED_DOCMDP_NAME,
            {"docmdp": docmdp.name if docmdp is not None else None},
        )
    )
    checks.append(
        check(
            "docmdp-ok", status.docmdp_ok is not False, {"docmdp_ok": status.docmdp_ok}
        )
    )

    subfilter = str(sig.sig_object.get("/SubFilter"))
    checks.append(
        check(
            "subfilter-cades-detached",
            subfilter == EXPECTED_SUBFILTER,
            {"subFilter": subfilter},
        )
    )

    signer_info = sig.signer_info
    signed_types = [str(attr["type"].native) for attr in signer_info["signed_attrs"]]
    checks.append(
        check(
            "no-signing-time-attribute",
            "signing_time" not in signed_types,
            {"signedAttributes": signed_types},
        )
    )

    unsigned = signer_info["unsigned_attrs"]
    unsigned_types = (
        [str(attr["type"].native) for attr in unsigned] if unsigned.native else []
    )
    has_timestamp = "signature_time_stamp_token" in unsigned_types
    timestamp = status.timestamp_validity
    if has_timestamp:
        timestamp_ok = bool(
            timestamp is not None
            and timestamp.intact
            and timestamp.valid
            and timestamp.trusted
        )
        checks.append(check("signature-timestamp-valid", timestamp_ok))
        report["level"] = "B-T" if timestamp_ok else None
    else:
        report["level"] = "B-B"
    report["unsignedAttributes"] = unsigned_types

    if document_digest is not None:
        checks.append(first_revision_check(pdf, document_digest))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--pdf", type=Path, required=True, help="the sealed PDF")
    parser.add_argument(
        "--trust-root",
        type=Path,
        action="append",
        required=True,
        help="PEM trust root (repeatable)",
    )
    parser.add_argument(
        "--document-digest",
        type=labelled_digest,
        help="expected digest of the first revision, sha256:<hex> (the answer's documentDigest)",
    )
    args = parser.parse_args(argv)
    # pyHanko logs certificate subjects on failure; the JSON report is the output.
    logging.disable(logging.CRITICAL)

    try:
        report = validate(args.pdf.read_bytes(), args.trust_root, args.document_digest)
    except Exception as error:  # noqa: BLE001  a crash or unreadable input is a reported failure
        report = {
            "level": None,
            "checks": [
                check("validator-ran", False, f"{type(error).__name__}: {error}")
            ],
        }
    report["ok"] = (
        all(c["ok"] for c in report["checks"]) and report.get("level") is not None
    )
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
