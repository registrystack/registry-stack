"""Reloading the package after it has already been imported once.

`importlib.reload` re-executes a module's body against its existing
namespace, unlike a first import, which starts from an empty one. The
package's own `__init__.py` removes the submodule's bare name
(`registry_evidence_client`) from that namespace after `import *` runs; that
removal must stay safe to repeat, since a reload is exactly a repeat.
"""

from __future__ import annotations

import importlib
import pathlib
import sys
import unittest

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS_DIR))
sys.path.insert(0, str(_TESTS_DIR / "helpers"))

import bootstrap  # noqa: E402

bootstrap.ensure_built()

import registry_evidence_client as revc  # noqa: E402

# The thirteen names `__init__.pyi` declares: the four plain classes, the
# base exception, and its eight subclasses. Kept in lockstep with
# `test_drift.py`'s own `PLAIN_CLASS_NAMES` and `EXCEPTION_SUBCLASS_NAMES`.
PUBLIC_SURFACE_NAMES = {
    "EvidenceClient",
    "PreparedEvidenceRequest",
    "RawEvidenceResponse",
    "VerifiedEvidence",
    "EvidenceClientError",
    "ConfigurationError",
    "NonceError",
    "TokenError",
    "TransportError",
    "DeniedError",
    "NotAvailableError",
    "ProtocolError",
    "VerificationError",
}


class ReloadTest(unittest.TestCase):
    def test_the_public_surface_survives_a_reload(self):
        # The module-level import above already ran `__init__.py` once, which
        # already removed the submodule's bare name from this namespace. This
        # single `reload` call is already the second run of that removal, the
        # one a non-idempotent `del` would raise `NameError` on.
        importlib.reload(revc)
        live_names = {name for name in dir(revc) if not name.startswith("_")}
        self.assertEqual(live_names, PUBLIC_SURFACE_NAMES)


if __name__ == "__main__":
    unittest.main()
