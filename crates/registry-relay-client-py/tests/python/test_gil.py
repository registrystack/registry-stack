from __future__ import annotations

import pathlib
import sys
import threading
import time
import unittest

TESTS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
import bootstrap  # noqa: E402
from relay_server import RelayServer, Request, json_response  # noqa: E402

bootstrap.ensure_built()
import registry_relay_client as relay  # noqa: E402


class GilTest(unittest.TestCase):
    def test_blocking_exchange_releases_the_gil_during_io(self):
        request_started = threading.Event()

        def respond(_request: Request):
            request_started.set()
            time.sleep(0.4)
            return json_response({"status": "ok"})

        with RelayServer(respond) as server:
            client = relay.RelayClient(server.base_url)
            result: list[dict[str, object]] = []
            worker = threading.Thread(target=lambda: result.append(client.health()))
            started = time.monotonic()
            worker.start()
            self.assertTrue(request_started.wait(timeout=1.0))
            observed = time.monotonic() - started
            # If the native method retained the GIL, this thread could not
            # return from Event.wait until the 400ms response had completed.
            self.assertLess(observed, 0.25)
            counter = 0
            deadline = time.monotonic() + 0.1
            while time.monotonic() < deadline:
                counter += 1
            self.assertGreater(counter, 0)
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result[0]["kind"], "complete")


if __name__ == "__main__":
    unittest.main()
