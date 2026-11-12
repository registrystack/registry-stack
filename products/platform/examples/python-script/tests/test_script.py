import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_script():
    client = types.ModuleType("registry_client")
    client.connect = lambda: None
    client.messaging = types.SimpleNamespace(MessagingClientError=MessagingClientError)
    previous = sys.modules.get("registry_client")
    sys.modules["registry_client"] = client
    spec = importlib.util.spec_from_file_location(
        "registry_python_script", ROOT / "script.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            del sys.modules["registry_client"]
        else:
            sys.modules["registry_client"] = previous
    return module


class BReg:
    def __init__(self):
        self.calls = []

    def list_records(self, route, **options):
        self.calls.append((route, options))
        return {
            "kind": "complete",
            "value": {
                "items": [{"data": {"reference": "application-001"}}],
                "meta": {},
                "pageInfo": {},
            },
            "trace_id": "breg-trace-canary",
            "etag": None,
            "continuation": None,
        }


class MessagingClientError(Exception):
    def __init__(self, *, outcome_unknown):
        super().__init__("synthetic Messaging failure")
        self.outcome_unknown = outcome_unknown


class Messaging:
    def __init__(self, submit_error=None):
        self.calls = []
        self.submit_error = submit_error

    def submit(self, key, request):
        self.calls.append(("submit", key, request))
        if self.submit_error is not None:
            raise self.submit_error
        return {
            "kind": "complete",
            "value": {"id": "message-from-receipt", "status": "queued"},
            "trace_id": "submit-trace-canary",
        }

    def message_receipt(self, key, request):
        self.calls.append(("message_receipt", key, request))
        return {
            "kind": "complete",
            "value": {"id": "message-from-receipt", "status": "queued"},
            "trace_id": "receipt-trace-canary",
        }


class Stack:
    def __init__(self):
        self.breg = BReg()
        self.messaging = Messaging()


class ScriptTests(unittest.TestCase):
    def test_run_uses_generated_defaults_and_reads_the_original_message_receipt(self):
        module = load_script()
        stack = Stack()
        connections = []
        module.connect = lambda: connections.append(True) or stack

        result = module.run()

        self.assertEqual(connections, [True])
        self.assertEqual(
            stack.breg.calls,
            [
                (
                    "applications",
                    {
                        "top": 1,
                        "select": ["reference", "profession"],
                        "access_profile": "applicant",
                    },
                )
            ],
        )
        self.assertEqual(
            [operation for operation, _, _ in stack.messaging.calls],
            ["submit", "message_receipt"],
        )
        submitted = stack.messaging.calls[0]
        recovered = stack.messaging.calls[1]
        self.assertEqual(submitted[1], "python-script-application-received")
        self.assertEqual(submitted[1:], recovered[1:])
        self.assertEqual(
            submitted[2],
            {
                "senderProfile": "licensing-email",
                "to": {"email": "applicant@example.test"},
                "template": {"id": "application-received", "version": "1"},
                "locale": "en",
                "data": {"reference": "application-001"},
                "correlationId": "python-script-application-001",
            },
        )
        self.assertEqual(
            result,
            {
                "applications": 1,
                "message": "message-from-receipt",
                "status": "queued",
            },
        )

    def test_main_prints_only_the_bounded_summary(self):
        module = load_script()
        module.run = lambda **_options: {
            "applications": 1,
            "message": "message-1",
            "status": "queued",
        }
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            module.main([])

        self.assertEqual(
            json.loads(output.getvalue()),
            {"applications": 1, "message": "message-1", "status": "queued"},
        )
        for canary in ("bearer", "connection", "trace", "token"):
            self.assertNotIn(canary, output.getvalue().lower())

    def test_unknown_submit_reads_the_same_original_receipt(self):
        module = load_script()
        stack = Stack()
        stack.messaging = Messaging(MessagingClientError(outcome_unknown=True))
        module.connect = lambda: stack

        result = module.run()

        self.assertEqual(
            [operation for operation, _, _ in stack.messaging.calls],
            ["submit", "message_receipt"],
        )
        self.assertEqual(stack.messaging.calls[0][1:], stack.messaging.calls[1][1:])
        self.assertEqual(result["message"], "message-from-receipt")

    def test_known_submit_refusal_is_not_treated_as_a_receipt_recovery(self):
        module = load_script()
        refusal = MessagingClientError(outcome_unknown=False)
        stack = Stack()
        stack.messaging = Messaging(refusal)
        module.connect = lambda: stack

        with self.assertRaises(MessagingClientError) as caught:
            module.run()

        self.assertIs(caught.exception, refusal)
        self.assertEqual(
            [operation for operation, _, _ in stack.messaging.calls], ["submit"]
        )

    def test_rotation_check_keeps_one_connection_and_repeats_the_protected_read(self):
        module = load_script()
        stack = Stack()
        connections = []
        waits = []
        module.connect = lambda: connections.append(True) or stack
        module.sleep = waits.append

        result = module.run(wait_for_rotation=True)

        self.assertEqual(connections, [True])
        self.assertEqual(waits, [65])
        self.assertEqual(len(stack.breg.calls), 2)
        self.assertEqual(result["applications"], 1)


if __name__ == "__main__":
    unittest.main()
