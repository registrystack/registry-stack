"""Machine admission selects one caller without changing workload authority."""

from dataclasses import dataclass
from pathlib import Path
import importlib
import sys
import types
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "python" / "registry_client"
PACKAGE = "_registry_client_machine_admission_test"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(SOURCE)]
sys.modules[PACKAGE] = package
machine = importlib.import_module(f"{PACKAGE}.machine")


@dataclass(frozen=True)
class Verified:
    kind: str = "access"
    issuer: str = "https://issuer.example.invalid/"
    audiences: tuple[str, ...] = ("urn:registry:python:test",)
    subject: str = "coordinator-service"
    client_id: str = "coordinator-client"
    scopes: tuple[str, ...] = ("python.invoke",)
    claims: dict[str, str] | None = None


class Verifier:
    def __init__(self, result: Verified | Exception):
        self.result = result
        self.tokens: list[str] = []

    def verify(self, token: str) -> Verified:
        self.tokens.append(token)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class VerificationFailure(Exception):
    kind = "verification"


class RuntimeFailure(Exception):
    kind = "runtime"


class MachineAdmissionTests(unittest.TestCase):
    def admission(self, result: Verified | Exception | None = None):
        verifier = Verifier(
            result or Verified(claims={"registry_actor_kind": "machine"})
        )
        admission = machine.MachineAdmission(
            verifier,
            issuer="https://issuer.example.invalid/",
            resource="urn:registry:python:test",
            client_id="coordinator-client",
            profile="coordinator-invoker",
            required_scopes=("python.invoke",),
            required_claims={"registry_actor_kind": "machine"},
        )
        return admission, verifier

    def test_exact_machine_bearer_is_admitted_without_browser_headers(self):
        admission, verifier = self.admission()
        context = admission.admit({"authorization": "Bearer synthetic-token"})
        self.assertEqual(verifier.tokens, ["synthetic-token"])
        self.assertEqual(context.client_id, "coordinator-client")
        self.assertEqual(context.issuer, "https://issuer.example.invalid/")
        self.assertEqual(context.resource, "urn:registry:python:test")
        self.assertEqual(context.profile, "coordinator-invoker")
        self.assertEqual(context.persona, "service")
        self.assertNotIn("synthetic-token", repr(context))

    def test_cookie_cannot_substitute_for_bearer_and_duplicates_refuse(self):
        admission, verifier = self.admission()
        for values in (
            {"cookie": "session=canary"},
            {"authorization": []},
            {"authorization": ["Bearer one", "Bearer two"]},
            {"authorization": "Basic canary"},
        ):
            with self.subTest(values=values), self.assertRaises(machine.AdmissionError):
                admission.admit(values)
        self.assertEqual(verifier.tokens, [])

    def test_verified_wrong_authority_never_becomes_a_machine_context(self):
        replacements = (
            {"kind": "id"},
            {"issuer": "https://other.example.invalid/"},
            {"audiences": ("urn:registry:breg:test",)},
            {"client_id": "another-client"},
            {"scopes": ()},
            {"scopes": None},
            {"claims": {"registry_actor_kind": "person"}},
            {"claims": None},
        )
        for replacement in replacements:
            with self.subTest(replacement=replacement):
                verified = Verified(claims={"registry_actor_kind": "machine"})
                verified = Verified(**{**vars(verified), **replacement})
                admission, _ = self.admission(verified)
                with self.assertRaises(machine.AdmissionError):
                    admission.admit({"authorization": "Bearer canary"})

    def test_verifier_refusal_is_value_free(self):
        admission, _ = self.admission(VerificationFailure("token-canary"))
        with self.assertRaises(machine.AdmissionError) as caught:
            admission.admit({"authorization": "Bearer bearer-canary"})
        self.assertNotIn("token-canary", str(caught.exception))
        self.assertNotIn("bearer-canary", str(caught.exception))

    def test_verifier_outage_is_distinct_and_value_free(self):
        admission, _ = self.admission(RuntimeFailure("jwks-canary"))
        with self.assertRaises(machine.AdmissionUnavailable) as caught:
            admission.admit({"authorization": "Bearer bearer-canary"})
        self.assertNotIn("jwks-canary", str(caught.exception))
        self.assertNotIn("bearer-canary", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
