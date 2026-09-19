import copy
import unittest

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import BaseRegistryClient, BaseRegistryClientError  # noqa: E402


REQUEST_ID = "00000000-0000-4000-8000-000000000001"
APPLICATION_ID = "00000000-0000-4000-8000-000000000002"
TARGET_ID = "00000000-0000-4000-8000-000000000003"
DIGEST = "sha256:" + "0123456789abcdef" * 4


def request_record(result_links: list[dict[str, object]] | None = None) -> dict[str, object]:
    if result_links is None:
        result_links = [
            {
                "targetEntityId": "person",
                "targetRecordId": TARGET_ID,
                "targetRevision": 4,
            }
        ]
    return {
        "data": {
            "recordIdentifier": REQUEST_ID,
            "revisionIdentifier": "8",
            "domainData": {},
            "request": {
                "bregState": "applied",
                "proposalVersion": 2,
                "editable": False,
                "application": {
                    "applicationId": APPLICATION_ID,
                    "proposalVersion": 2,
                    "effectDigest": DIGEST,
                    "appliedAt": "2026-09-20T00:00:00Z",
                },
                "history": {
                    "proposals": [
                        {
                            "requestEntityId": "request",
                            "requestId": REQUEST_ID,
                            "proposalVersion": 2,
                            "bregState": "applied",
                            "current": True,
                            "contractFingerprint": DIGEST,
                            "detailErased": False,
                            "applicationId": APPLICATION_ID,
                            "resultLinkCount": len(result_links),
                            "resultLinks": result_links,
                        }
                    ],
                    "nextAfterProposalVersion": 2,
                },
            },
        },
        "meta": {
            "registryIdentifier": "registry",
            "datasetIdentifier": "dataset",
            "entityTypeIdentifier": "request",
        },
    }


class RequestHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = BaseRegistryClient("http://127.0.0.1:1")

    def test_projects_exact_inert_results_without_io(self) -> None:
        page = self.client.request_history(request_record())
        self.assertIsNotNone(page)
        assert page is not None
        self.assertEqual(page.next_after_proposal_version, 2)
        proposal = page.find_application(
            "request", REQUEST_ID, 2, APPLICATION_ID
        )
        self.assertIsNotNone(proposal)
        assert proposal is not None
        self.assertEqual(proposal.result_link_count, 1)
        reference = proposal.result_references[0]
        self.assertEqual(reference.target_entity_identifier, "person")
        self.assertEqual(reference.target_record_identifier, TARGET_ID)
        self.assertEqual(reference.target_revision, 4)
        self.assertEqual(repr(proposal), "BRegRetainedRequestProposal(<redacted>)")
        self.assertEqual(
            repr(reference), "BRegRequestResultReference(<redacted>)"
        )
        for secret in (REQUEST_ID, APPLICATION_ID, TARGET_ID, "person"):
            self.assertNotIn(secret, repr(page))
            self.assertNotIn(secret, repr(proposal))
            self.assertNotIn(secret, repr(reference))

    def test_distinguishes_absent_history_from_observed_empty_results(self) -> None:
        absent = request_record()
        del absent["data"]["request"]["history"]  # type: ignore[index]
        self.assertIsNone(self.client.request_history(absent))

        empty = self.client.request_history(request_record([]))
        assert empty is not None
        self.assertEqual(empty.proposals[0].result_link_count, 0)
        self.assertEqual(empty.proposals[0].result_references, [])

    def test_refuses_malformed_shapes(self) -> None:
        candidates = []
        for path, invalid in (
            (("resultLinkCount",), 2),
            (("applicationId",), None),
            (("resultLinks", 0, "targetRevision"), 0),
            (("resultLinks", 0, "targetRevision"), 9_007_199_254_740_992),
            (("unknown",), True),
        ):
            value = request_record()
            proposal = value["data"]["request"]["history"]["proposals"][0]  # type: ignore[index]
            target = proposal
            for member in path[:-1]:
                target = target[member]  # type: ignore[index]
            target[path[-1]] = invalid  # type: ignore[index]
            candidates.append(value)
        cursor = request_record()
        cursor["data"]["request"]["history"]["nextAfterProposalVersion"] = 1  # type: ignore[index]
        candidates.append(cursor)

        for value in candidates:
            with self.assertRaises(BaseRegistryClientError) as raised:
                self.client.request_history(copy.deepcopy(value))
            self.assertEqual(raised.exception.kind, "invalid_request")


if __name__ == "__main__":
    unittest.main()
