import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local_volume import volume_documents


class LocalVolumeTest(unittest.TestCase):
    def test_binds_owned_claim_to_retained_node_local_storage(self):
        volume, claim = volume_documents("example", "audit", "node-a", "2Gi")
        self.assertEqual(volume["spec"]["persistentVolumeReclaimPolicy"], "Retain")
        self.assertEqual(volume["spec"]["local"]["path"], "/var/lib/registry-stack/storage/example/audit")
        self.assertEqual(volume["spec"]["claimRef"], {"namespace": "example", "name": "audit"})
        self.assertEqual(claim["spec"]["volumeName"], volume["metadata"]["name"])
        self.assertEqual(volume["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"][0]["values"], ["node-a"])

    def test_refuses_names_that_are_not_safe_directory_segments(self):
        for namespace, claim in (("../other", "audit"), ("example", "."), ("example", "foo/bar")):
            with self.subTest(namespace=namespace, claim=claim), self.assertRaises(ValueError):
                volume_documents(namespace, claim, "node-a", "2Gi")


if __name__ == "__main__":
    unittest.main()
