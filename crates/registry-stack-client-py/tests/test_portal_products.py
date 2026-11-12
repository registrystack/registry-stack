"""Person product clients remain bound to the admitted resource grants."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import importlib
import sys
import types
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "python" / "registry_client"
PACKAGE = "_registry_client_portal_products_test"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(SOURCE)]
sys.modules[PACKAGE] = package


class BRegNative:
    def __init__(self, url, authorization):
        self.url = url
        self.authorization = authorization


class CaseworkNative:
    def __init__(self, url):
        self.url = url


breg = types.ModuleType(f"{PACKAGE}.breg")
breg.BaseRegistryClient = BRegNative
casework = types.ModuleType(f"{PACKAGE}.casework")
casework.CaseworkClient = CaseworkNative
sys.modules[breg.__name__] = breg
sys.modules[casework.__name__] = casework
portal = importlib.import_module(f"{PACKAGE}.portal")


class PortalProductTests(unittest.TestCase):
    def test_two_native_clients_get_only_their_resource_token(self):
        module = importlib.import_module(f"{PACKAGE}.portal_products")
        context = portal.PortalContext(
            "session",
            "person-one",
            "principal-one",
            "holder",
            {"breg": "breg-canary", "casework": "casework-canary"},
            "csrf",
            1000,
        )
        products = module.bind_person(
            context,
            persona="holder",
            breg_url="https://breg.example.invalid/",
            casework_url="https://casework.example.invalid/",
            casework_profile="holder",
        )
        self.assertEqual(products.breg._client.authorization, {"static": "breg-canary"})
        self.assertEqual(
            products.casework._HolderCaseworkWorkload__token, "casework-canary"
        )
        self.assertEqual(products.casework._HolderCaseworkWorkload__profile, "holder")
        self.assertEqual(type(products.casework).__name__, "HolderCaseworkWorkload")
        self.assertFalse(hasattr(products.casework, "review_tasks"))
        self.assertFalse(hasattr(products.casework, "claim_review_task"))
        with self.assertRaises(TypeError):
            products.casework.review_history("request-id", source_profile="auditor")
        self.assertEqual(products.principal, "principal-one")
        self.assertNotIn("breg-canary", repr(products))

    def test_wrong_persona_or_missing_grant_never_uses_workload_authority(self):
        module = importlib.import_module(f"{PACKAGE}.portal_products")
        context = portal.PortalContext(
            "session",
            "person-one",
            "principal-one",
            "holder",
            {"breg": "breg-canary"},
            "csrf",
            1000,
        )
        options = dict(
            breg_url="https://breg.example.invalid/",
            casework_url="https://casework.example.invalid/",
            casework_profile="holder",
        )
        with self.assertRaises(portal.ReauthenticationRequired):
            module.bind_person(context, persona="staff", **options)
        with self.assertRaises(portal.ReauthenticationRequired):
            module.bind_person(context, persona="holder", **options)

    def test_alternating_people_never_share_product_credentials(self):
        module = importlib.import_module(f"{PACKAGE}.portal_products")
        options = dict(
            persona="holder",
            breg_url="https://breg.example.invalid/",
            casework_url="https://casework.example.invalid/",
            casework_profile="applicant",
        )

        def bind(number):
            context = portal.PortalContext(
                f"session-{number}",
                f"person-{number}",
                f"principal-{number}",
                "holder",
                {
                    "breg": f"breg-token-{number}",
                    "casework": f"casework-token-{number}",
                },
                f"csrf-{number}",
                1000,
            )
            products = module.bind_person(context, **options)
            return (
                products.principal,
                products.breg._client.authorization["static"],
                products.casework._HolderCaseworkWorkload__token,
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(bind, range(64)))
        self.assertEqual(
            results,
            [
                (
                    f"principal-{number}",
                    f"breg-token-{number}",
                    f"casework-token-{number}",
                )
                for number in range(64)
            ],
        )


if __name__ == "__main__":
    unittest.main()
