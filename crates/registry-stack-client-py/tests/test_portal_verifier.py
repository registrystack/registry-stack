"""Native token projections gate the portal's complete personal grants."""

from dataclasses import dataclass
from pathlib import Path
import importlib
import sys
import types
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "python" / "registry_client"
PACKAGE = "_registry_client_portal_verifier_test"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(SOURCE)]
sys.modules[PACKAGE] = package
portal = importlib.import_module(f"{PACKAGE}.portal")


@dataclass(frozen=True)
class Projection:
    kind: str
    issuer: str
    audiences: tuple[str, ...]
    subject: str
    client_id: str
    scopes: tuple[str, ...]
    expires_at: int
    claims: dict[str, str]


class Verifier:
    def __init__(self, access: Projection, identity: Projection):
        self.access = access
        self.identity = identity
        self.calls = []

    def verify(self, token):
        self.calls.append(("access", token))
        return self.access

    def verify_id_token(self, token, nonce):
        self.calls.append(("id", token, nonce))
        return self.identity


class PortalVerifierTests(unittest.TestCase):
    def setUp(self):
        self.policy = portal.GrantPolicy(
            "breg",
            "https://breg.example.invalid/",
            ("registry.read",),
            "holder",
            {"registry_actor_kind": "human"},
        )
        self.access = Projection(
            "access",
            "https://issuer.example.invalid/",
            (self.policy.resource,),
            "person-1",
            "portal-client",
            ("registry.read",),
            300,
            {"registry_principal": "person-1", "registry_actor_kind": "human"},
        )
        self.identity = Projection(
            "id",
            "https://issuer.example.invalid/",
            ("portal-client",),
            "person-1",
            "portal-client",
            (),
            300,
            {},
        )

    def candidate(self, access=None, identity=None):
        module = importlib.import_module(f"{PACKAGE}.portal_verifier")
        verifier = Verifier(access or self.access, identity or self.identity)
        candidate = module.NativeGrantVerifier(
            issuer="https://issuer.example.invalid/",
            client_id="portal-client",
            persona="holder",
            grants={self.policy.name: self.policy},
            verifiers={self.policy.name: verifier},
        )
        return candidate, verifier

    def test_callback_requires_native_access_and_id_projection(self):
        candidate, verifier = self.candidate()
        grant = candidate(
            {
                "access_token": "access-canary",
                "refresh_token": "refresh-canary",
                "id_token": "id-canary",
            },
            "nonce-canary",
            self.policy,
            None,
        )
        self.assertEqual(grant.subject, "person-1")
        self.assertEqual(grant.principal, "person-1")
        self.assertEqual(grant.persona, "holder")
        self.assertEqual(grant.profile, "holder")
        self.assertEqual(grant.expires_at, 300)
        self.assertEqual(
            verifier.calls,
            [("access", "access-canary"), ("id", "id-canary", "nonce-canary")],
        )
        self.assertNotIn("access-canary", repr(grant))

    def test_callback_refuses_mismatched_identity_or_resource(self):
        for access, identity in (
            (self.access, Projection(**{**vars(self.identity), "subject": "person-2"})),
            (
                Projection(
                    **{**vars(self.access), "audiences": ("https://other.invalid/",)}
                ),
                self.identity,
            ),
            (
                Projection(
                    **{
                        **vars(self.access),
                        "claims": {
                            "registry_principal": "person-1",
                            "registry_actor_kind": "service",
                        },
                    }
                ),
                self.identity,
            ),
        ):
            with self.subTest(access=access, identity=identity):
                candidate, _ = self.candidate(access, identity)
                with self.assertRaises(portal.AdmissionError):
                    candidate(
                        {
                            "access_token": "access",
                            "refresh_token": "refresh",
                            "id_token": "id",
                        },
                        "nonce",
                        self.policy,
                        None,
                    )

    def test_explicit_forward_resource_accepts_only_exact_dual_audience(self):
        bridge = portal.GrantPolicy(
            "casework",
            "urn:example:casework",
            ("casework:review", "licensing:audit"),
            "reviewer",
            {"registry_actor_kind": "human"},
            forward_resource="urn:example:breg",
        )
        access = Projection(
            **{
                **vars(self.access),
                "audiences": (bridge.resource, bridge.forward_resource),
                "scopes": bridge.scopes,
            }
        )
        module = importlib.import_module(f"{PACKAGE}.portal_verifier")
        verifier = Verifier(access, self.identity)
        candidate = module.NativeGrantVerifier(
            issuer=self.access.issuer,
            client_id="portal-client",
            persona="staff",
            grants={bridge.name: bridge},
            verifiers={bridge.name: verifier},
        )
        response = {
            "access_token": "access",
            "refresh_token": "refresh",
            "id_token": "id",
        }
        self.assertEqual(
            candidate(response, "nonce", bridge, None).resource, bridge.resource
        )
        reversed_access = Projection(
            **{**vars(access), "audiences": tuple(reversed(access.audiences))}
        )
        candidate._verifiers[bridge.name] = Verifier(reversed_access, self.identity)
        self.assertEqual(
            candidate(response, "nonce", bridge, None).resource, bridge.resource
        )
        for audiences in (
            (bridge.resource,),
            (bridge.forward_resource,),
            (bridge.resource, bridge.forward_resource, "urn:other"),
        ):
            with (
                self.subTest(audiences=audiences),
                self.assertRaises(portal.AdmissionError),
            ):
                bad = Verifier(
                    Projection(**{**vars(access), "audiences": audiences}),
                    self.identity,
                )
                candidate._verifiers[bridge.name] = bad
                candidate(response, "nonce", bridge, None)

    def test_refresh_keeps_prior_id_token_and_refuses_identity_change(self):
        candidate, verifier = self.candidate()
        current = candidate(
            {
                "access_token": "old",
                "refresh_token": "old-refresh",
                "id_token": "old-id",
            },
            "nonce",
            self.policy,
            None,
        )
        verifier.calls.clear()
        refreshed = candidate(
            {"access_token": "new", "refresh_token": "new-refresh"},
            None,
            self.policy,
            current,
        )
        self.assertEqual(refreshed.id_token, "old-id")
        self.assertEqual(verifier.calls, [("access", "new")])
        changed = Projection(**{**vars(self.access), "subject": "person-2"})
        candidate, _ = self.candidate(changed)
        with self.assertRaises(portal.AdmissionError):
            candidate(
                {"access_token": "new", "refresh_token": "new-refresh"},
                None,
                self.policy,
                current,
            )


if __name__ == "__main__":
    unittest.main()
