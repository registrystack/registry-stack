import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from extension_endpoints import EndpointError, extension_values


class ExtensionEndpointTest(unittest.TestCase):
    def setUp(self):
        self.intent = {
            "extensions": {"endpoints": {"intake": {"path": "/extensions/intake"}}},
        }
        self.bindings = {
            "namespace": "registry-extensions",
            "publicHost": "service.example.test",
            "ingressClassName": "traefik",
            "ingressNamespace": "kube-system",
            "ingressPodLabels": {"app.kubernetes.io/name": "traefik"},
            "tlsSecretName": "service-tls",
            "endpoints": {"intake": {
                "image": "ghcr.io/example/intake@sha256:" + "a" * 64,
                "port": 8080,
                "credentialsSecretName": "intake-client",
            }},
        }

    def test_binds_only_the_reviewed_image_secret_and_public_route(self):
        values = extension_values(self.intent, self.bindings)
        self.assertEqual(values["tlsSecretName"], "service-tls")
        self.assertEqual(values["endpoints"]["intake"]["credentialsSecretName"], "intake-client")
        self.assertEqual(values["endpoints"]["intake"]["path"], "/extensions/intake")
        self.assertEqual(values["endpoints"]["intake"]["egress"], [])
        self.assertNotIn("path", self.bindings["endpoints"]["intake"])

    def test_requires_operator_pinned_image_and_named_route(self):
        invalid = copy.deepcopy(self.bindings)
        invalid["endpoints"]["intake"]["image"] = "example/intake:latest"
        with self.assertRaisesRegex(EndpointError, "digest-pinned"):
            extension_values(self.intent, invalid)
        self.intent["extensions"]["endpoints"]["intake"]["path"] = "/"
        with self.assertRaisesRegex(EndpointError, "route"):
            extension_values(self.intent, self.bindings)

    def test_workspace_cannot_set_privileges_or_an_environment(self):
        self.intent["extensions"]["endpoints"]["intake"]["privileged"] = True
        with self.assertRaisesRegex(EndpointError, "declares only the path"):
            extension_values(self.intent, self.bindings)

    def test_rejects_unrestricted_egress_rules(self):
        peers = ({}, {"podSelector": {}}, {"ipBlock": {"cidr": "0.0.0.0/0"}}, {"ipBlock": {"cidr": "::/0"}})
        for peer in peers:
            with self.subTest(peer=peer):
                self.bindings["endpoints"]["intake"]["egress"] = [{"to": peer, "ports": [{"port": 443}]}]
                with self.assertRaisesRegex(EndpointError, "explicit egress"):
                    extension_values(self.intent, self.bindings)

    def test_does_not_admit_an_operator_route_override(self):
        self.bindings["endpoints"]["intake"]["path"] = "/extensions/unpublished"
        with self.assertRaisesRegex(EndpointError, "Unknown"):
            extension_values(self.intent, self.bindings)


if __name__ == "__main__":
    unittest.main()
