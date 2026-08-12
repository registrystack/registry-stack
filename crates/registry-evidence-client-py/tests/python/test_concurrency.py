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
    b' "audience": "urn:example:audience", "issuedBy": "i", "providedBy": "p",'
    b' "holderBoundBatchMaxSize": 1,'
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

        # Built on the main thread, before the timed region below, so the
        # elapsed time it measures is the two `discover()` calls themselves,
        # not construction plus those calls.
        clients = [
            revc.EvidenceClient(server.base_url, fixtures.VALID_JWKS, [], "test-token")
            for _ in range(2)
        ]

        def call_discover(client: revc.EvidenceClient) -> None:
            try:
                barrier.wait(timeout=JOIN_TIMEOUT_SECONDS)
                client.discover()
            except BaseException as error:  # noqa: BLE001 - captured, not swallowed
                errors.append(error)

        threads = [
            threading.Thread(target=call_discover, args=(client,)) for client in clients
        ]
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
    """`EvidenceClient.__new__` releases the GIL around its Rust-side work.

    Construction does no I/O (there is no server to race here at all: the
    base URL below is never contacted), but it does real work in Rust before
    returning: validating the configuration and building the TLS-capable HTTP
    client, which loads the platform's native trust store. This proves the
    GIL is available to other Python threads for the duration of that work,
    with a daemon thread that spins incrementing a counter in a plain Python
    loop until told to stop. The observer can only advance while it holds
    the GIL, so its tick count during a call is a direct measure of how much
    GIL time that call gave up: a constructor that keeps the GIL for its
    Rust work starves the observer, and one that releases it does not.
    Measuring it this way, rather than timing two overlapping constructions
    against each other, also means it cannot be confounded by both
    constructions instead serializing on a single CPU core.

    A control window, the observer running while the main thread sleeps
    (which releases the GIL), calibrates this machine's tick rate with
    nothing competing. The same observer, fresh, then runs across one
    construction on the main thread. Both windows are measured the same way:
    a tick snapshot taken immediately before and after the timed call, never
    the observer's count over its whole lifetime, so ticks from starting or
    stopping the observer thread never enter either number. The construction
    window's count is compared against the control count as a fraction, not
    against an absolute number, so the assertion holds regardless of how
    fast any given machine ticks.

    The switch interval is left at its default rather than raised. A
    construction call that runs for tens of milliseconds already leaves the
    observer waiting well past the default interval, so the interpreter
    hands it one timeslice at the boundary right after the call returns no
    matter the interval's size; that slice costs at most one interval's
    worth of ticks, small and roughly constant next to the construction
    time it is measured against, so it cannot make a held GIL look released.
    Raising the interval would not shrink that slice away, because the
    observer never yields the GIL voluntarily: whichever thread holds the
    GIL when the interval next elapses is the only one that can be made to
    give it up, so a bigger interval only makes that one unavoidable handoff
    bigger too. Leaving it at the default keeps that handoff small instead.
    """

    def test_construction_releases_the_gil(self):
        # Construction only validates and builds a client; it never connects,
        # so this address does not need to be reachable.
        base_url = "http://127.0.0.1:1"

        def build_client() -> None:
            revc.EvidenceClient(base_url, fixtures.VALID_JWKS, [], "test-token")

        def spin_observer(
            counter: list[int],
            stop_event: threading.Event,
            errors: list[BaseException],
        ) -> None:
            try:
                while not stop_event.is_set():
                    counter[0] += 1
            except BaseException as error:  # noqa: BLE001 - captured, not swallowed
                errors.append(error)

        def start_observer():
            counter = [0]
            stop_event = threading.Event()
            errors: list[BaseException] = []
            thread = threading.Thread(
                target=spin_observer, args=(counter, stop_event, errors), daemon=True
            )
            thread.start()
            return thread, counter, stop_event, errors

        def stop_observer(thread, stop_event, errors) -> None:
            stop_event.set()
            thread.join(timeout=JOIN_TIMEOUT_SECONDS)
            self.assertFalse(
                thread.is_alive(),
                "the GIL observer thread did not stop within the bounded timeout",
            )
            self.assertEqual(errors, [])

        def wait_until_ticking(thread, counter, errors) -> None:
            # `threading.Thread.start()` blocks on the new thread's startup
            # event, and waiting on an event releases the GIL, so the
            # observer can already be ticking before this is even called.
            # Waiting here for its first tick keeps that startup handoff
            # out of the measured window entirely, rather than measuring
            # from a snapshot that might land before the observer has run
            # at all for reasons that have nothing to do with the call
            # being timed.
            deadline = time.monotonic() + JOIN_TIMEOUT_SECONDS
            while counter[0] == 0:
                self.assertTrue(
                    thread.is_alive(),
                    f"the GIL observer thread exited before ticking: {errors}",
                )
                self.assertLessEqual(
                    time.monotonic(),
                    deadline,
                    "the GIL observer never ticked within the bounded settle timeout",
                )
                time.sleep(0)

        def measure_ticks(counter, run) -> int:
            # The snapshots go immediately around `run`, not over the
            # observer's whole lifetime, so ticks from starting or stopping
            # the observer thread never enter the delta: only ticks that
            # land while `run` itself is executing do.
            start_ticks = counter[0]
            run()
            return counter[0] - start_ticks

        # A throwaway construction times roughly how long the real
        # measurement below will take, so the control window spins the
        # observer for a comparable duration.
        started_at = time.monotonic()
        build_client()
        approximate_construction_seconds = time.monotonic() - started_at

        control_thread, control_counter, control_stop, control_errors = start_observer()
        try:
            wait_until_ticking(control_thread, control_counter, control_errors)
            control_ticks = measure_ticks(
                control_counter, lambda: time.sleep(approximate_construction_seconds)
            )
        finally:
            stop_observer(control_thread, control_stop, control_errors)

        (
            construction_thread,
            construction_counter,
            construction_stop,
            construction_errors,
        ) = start_observer()
        try:
            wait_until_ticking(
                construction_thread, construction_counter, construction_errors
            )
            construction_ticks = measure_ticks(construction_counter, build_client)
        finally:
            stop_observer(construction_thread, construction_stop, construction_errors)

        # A released GIL lets the observer tick at close to the control
        # rate. A held GIL keeps the observer from advancing for almost all
        # of the call's duration, since it can only advance while it holds
        # the GIL itself; the one unavoidable timeslice at the boundary
        # right after the call returns costs at most one switch interval's
        # worth of ticks, small next to a call that runs for tens of
        # milliseconds. A floor of half the control count sits with clear
        # room on both sides of that gap, so the assertion discriminates a
        # released GIL from a held one without depending on an exact
        # percentage.
        self.assertGreaterEqual(
            construction_ticks,
            control_ticks * 0.5,
            f"control_ticks={control_ticks} construction_ticks={construction_ticks}",
        )


if __name__ == "__main__":
    unittest.main()
