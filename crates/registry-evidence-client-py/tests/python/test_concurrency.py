"""Every blocking `EvidenceClient` method releases the GIL for its I/O.

The client blocks on its own private tokio runtime from Rust (`py.detach`
around `self.runtime.block_on(...)` in `src/lib.rs`), specifically so a
long-running Evidence call does not stall every other Python thread for its
whole duration. This proves that by racing two clients against a
deliberately slow stub endpoint: if the GIL were held for the duration of the
blocking call, the two calls would serialize and the pair would take about
twice as long as either one alone.
"""

from __future__ import annotations

import pathlib
import sys
import threading
import time
import unittest

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS_DIR))
sys.path.insert(0, str(_TESTS_DIR / "helpers"))

import bootstrap  # noqa: E402

bootstrap.ensure_built()

import fixtures  # noqa: E402
import registry_evidence_client as revc  # noqa: E402
from stub_server import StubRoute, StubServer  # noqa: E402

JSON_MEDIA_TYPE = "application/json"
RESPONSE_DELAY_SECONDS = 0.4
JOIN_TIMEOUT_SECONDS = 5.0

DEFINITIONS_DOCUMENT_BODY = (
    b'{"schema": "registry.evidence-definitions/v1", "assuranceProfile": "local",'
    b' "configurationRevision": "r", "issuedBy": "i", "providedBy": "p",'
    b' "definitions": []}'
)


class ConcurrencyTest(unittest.TestCase):
    def test_two_concurrent_calls_overlap_instead_of_serializing(self):
        server = StubServer(
            {
                "GET /v1/evidence-definitions": StubRoute(
                    status=200,
                    headers={"Content-Type": JSON_MEDIA_TYPE},
                    body=DEFINITIONS_DOCUMENT_BODY,
                    delay_seconds=RESPONSE_DELAY_SECONDS,
                )
            }
        )
        self.addCleanup(server.close)

        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def call_discover() -> None:
            try:
                client = revc.EvidenceClient(
                    server.base_url, fixtures.VALID_JWKS, "test-token"
                )
                barrier.wait(timeout=JOIN_TIMEOUT_SECONDS)
                client.discover()
            except BaseException as error:  # noqa: BLE001 - captured, not swallowed
                errors.append(error)

        threads = [threading.Thread(target=call_discover) for _ in range(2)]
        started_at = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=JOIN_TIMEOUT_SECONDS)
        elapsed = time.monotonic() - started_at

        for thread in threads:
            self.assertFalse(
                thread.is_alive(),
                "a client thread did not finish within the bounded timeout",
            )
        self.assertEqual(errors, [])

        # Serialized, the pair would take roughly 2x the single-call delay;
        # overlapping, it takes roughly 1x. The threshold sits well below 2x
        # so ordinary scheduling jitter cannot make a passing run look like a
        # regression, while a genuinely serialized pair still fails it.
        self.assertLess(elapsed, RESPONSE_DELAY_SECONDS * 1.5)


class ConstructionGilReleaseTest(unittest.TestCase):
    """`EvidenceClient.__new__` also releases the GIL, for the same reason.

    Construction does no I/O (there is no server to race here at all: the
    base URL below is never contacted), but it does real work in Rust before
    returning: validating the configuration and building the TLS-capable HTTP
    client, which loads the platform's native trust store. That work is
    measurably slow enough, and this proves it overlaps across threads
    instead of serializing while the GIL is released for it.

    Unlike the async methods above, overlapping construction does not land
    close to the single-call cost: loading the native trust store twice at
    once still costs more than doing it once, so two overlapping
    constructions measure at roughly 1.5x the single-call cost on the
    machines this was calibrated against, not roughly 1x. The threshold
    below is set from that measured behavior, not copied from the roughly-1x
    async case.

    The budget is calibrated against this machine's own speed rather than a
    hard-coded duration, measured once at the start of this test run: a
    fixed millisecond budget would either be flaky on a slow machine or too
    loose on a fast one.
    """

    def test_two_concurrent_constructions_overlap_instead_of_serializing(self):
        # Construction only validates and builds a client; it never connects,
        # so this address does not need to be reachable.
        base_url = "http://127.0.0.1:1"

        def build_client() -> None:
            revc.EvidenceClient(base_url, fixtures.VALID_JWKS, "test-token")

        started_at = time.monotonic()
        build_client()
        baseline_elapsed = time.monotonic() - started_at

        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def build_at_barrier() -> None:
            try:
                barrier.wait(timeout=JOIN_TIMEOUT_SECONDS)
                build_client()
            except BaseException as error:  # noqa: BLE001 - captured, not swallowed
                errors.append(error)

        threads = [threading.Thread(target=build_at_barrier) for _ in range(2)]
        started_at = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=JOIN_TIMEOUT_SECONDS)
        concurrent_elapsed = time.monotonic() - started_at

        for thread in threads:
            self.assertFalse(
                thread.is_alive(),
                "a construction thread did not finish within the bounded timeout",
            )
        self.assertEqual(errors, [])

        # Serialized (GIL held for the whole constructor), the pair costs
        # roughly 2x the baseline. Overlapping (GIL released around the
        # trust-store load), it still costs more than 1x, since loading that
        # store twice at once genuinely costs more than doing it once, but
        # measurement across repeated runs put it consistently around 1.5x,
        # well clear of the roughly-2x serialized cost. 1.8x sits between the
        # two with headroom on both sides: comfortably above ordinary
        # overlapping jitter, and comfortably below what a regression to full
        # serialization would measure.
        self.assertLess(
            concurrent_elapsed,
            baseline_elapsed * 1.8,
            f"baseline={baseline_elapsed:.4f}s concurrent={concurrent_elapsed:.4f}s",
        )


if __name__ == "__main__":
    unittest.main()
