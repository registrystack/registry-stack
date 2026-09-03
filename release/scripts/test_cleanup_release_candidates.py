#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import unittest
from datetime import UTC, datetime
from pathlib import Path


SCRIPT = Path(__file__).with_name("cleanup-release-candidates.py")


def load_module():
    spec = importlib.util.spec_from_file_location("cleanup_release_candidates", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeClient:
    def __init__(self, versions, delete_errors=None):
        self.versions = versions
        self.listed = []
        self.deleted = []
        # Maps (package, version_id) to an exception delete_package_version
        # raises instead of recording the delete, so tests can simulate a
        # GitHub API failure on one specific version.
        self.delete_errors = delete_errors or {}

    def package_versions(self, package):
        self.listed.append(package)
        return list(self.versions.get(package, []))

    def delete_package_version(self, package, version_id):
        error = self.delete_errors.get((package, version_id))
        if error is not None:
            raise error
        self.deleted.append((package, version_id))


def version(version_id: int, updated_at: str, tags=None):
    return {
        "id": version_id,
        "updated_at": updated_at,
        "metadata": {"container": {"tags": tags or []}},
    }


class CleanupReleaseCandidatesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.now = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)

    def test_dry_run_uses_server_time_and_does_not_delete(self) -> None:
        client = FakeClient(
            {
                "relay-candidate": [
                    version(1, "2026-07-17T11:59:59Z", ["candidate-old"]),
                    version(2, "2026-07-17T12:00:00Z", ["candidate-boundary"]),
                ]
            }
        )
        result = self.module.cleanup(
            client,
            packages=["relay-candidate"],
            server_now=self.now,
            apply=False,
        )
        self.assertEqual([], client.deleted)
        self.assertEqual([1], [item["version_id"] for item in result["actions"]])
        self.assertEqual("would_delete", result["actions"][0]["action"])
        self.assertTrue(result["dry_run"])
        self.assertEqual(8, result["retention_days"])

    def test_apply_deletes_expired_versions_from_all_candidates(self) -> None:
        client = FakeClient(
            {
                "discovery-candidate": [version(6, "2026-07-03T00:00:00Z")],
                "evidence-candidate": [version(4, "2026-07-03T00:00:00Z")],
                "mint-candidate": [version(5, "2026-07-03T00:00:00Z")],
                "relay-candidate": [version(3, "2026-07-03T00:00:00Z")],
            }
        )
        result = self.module.cleanup(
            client,
            packages=list(self.module.CANDIDATE_PACKAGES),
            server_now=self.now,
            apply=True,
        )
        self.assertEqual(
            [
                ("discovery-candidate", 6),
                ("evidence-candidate", 4),
                ("mint-candidate", 5),
                ("relay-candidate", 3),
            ],
            client.deleted,
        )
        self.assertFalse(result["dry_run"])

    def test_undeletable_high_download_version_is_recorded_and_run_continues(
        self,
    ) -> None:
        detail = json.dumps(
            {
                "message": (
                    "Publicly visible package versions with more than 5000 "
                    "downloads cannot be deleted. Contact GitHub support for "
                    "further assistance."
                ),
                "documentation_url": (
                    "https://docs.github.com/rest/packages/packages"
                    "#delete-package-version-for-an-organization"
                ),
                "status": "400",
            }
        )
        stuck = self.module.GitHubApiError(
            "DELETE",
            "https://api.github.com/orgs/registrystack/packages/container/"
            "discovery-candidate/versions/1160334666",
            400,
            detail,
        )
        client = FakeClient(
            {
                "discovery-candidate": [
                    version(1160334666, "2026-07-01T00:00:00Z", ["stuck"]),
                    version(2, "2026-07-01T00:00:00Z", ["deletable"]),
                ],
                "relay-candidate": [
                    version(3, "2026-07-01T00:00:00Z", ["later-package"])
                ],
            },
            delete_errors={("discovery-candidate", 1160334666): stuck},
        )
        result = self.module.cleanup(
            client,
            packages=["discovery-candidate", "relay-candidate"],
            server_now=self.now,
            apply=True,
        )
        self.assertEqual(
            [("discovery-candidate", 2), ("relay-candidate", 3)], client.deleted
        )
        actions_by_id = {item["version_id"]: item for item in result["actions"]}
        self.assertEqual("undeletable", actions_by_id[1160334666]["action"])
        self.assertIn(
            "more than 5000 downloads", actions_by_id[1160334666]["reason"]
        )
        self.assertEqual("delete", actions_by_id[2]["action"])
        self.assertEqual("delete", actions_by_id[3]["action"])
        self.assertFalse(result["dry_run"])

    def test_delete_with_different_400_message_still_aborts(self) -> None:
        detail = json.dumps({"message": "Some other validation failure."})
        error = self.module.GitHubApiError(
            "DELETE",
            "https://api.github.com/orgs/registrystack/packages/container/"
            "relay-candidate/versions/9",
            400,
            detail,
        )
        client = FakeClient(
            {"relay-candidate": [version(9, "2026-07-01T00:00:00Z", ["old"])]},
            delete_errors={("relay-candidate", 9): error},
        )
        with self.assertRaisesRegex(self.module.CleanupError, "Some other validation"):
            self.module.cleanup(
                client,
                packages=["relay-candidate"],
                server_now=self.now,
                apply=True,
            )
        self.assertEqual([], client.deleted)

    def test_delete_with_non_400_status_still_aborts(self) -> None:
        for status in (403, 500):
            with self.subTest(status=status):
                error = self.module.GitHubApiError(
                    "DELETE",
                    "https://api.github.com/orgs/registrystack/packages/"
                    "container/relay-candidate/versions/9",
                    status,
                    json.dumps(
                        {
                            "message": (
                                "Publicly visible package versions with more "
                                "than 5000 downloads cannot be deleted."
                            )
                        }
                    ),
                )
                client = FakeClient(
                    {
                        "relay-candidate": [
                            version(9, "2026-07-01T00:00:00Z", ["old"])
                        ]
                    },
                    delete_errors={("relay-candidate", 9): error},
                )
                with self.assertRaises(self.module.CleanupError):
                    self.module.cleanup(
                        client,
                        packages=["relay-candidate"],
                        server_now=self.now,
                        apply=True,
                    )
                self.assertEqual([], client.deleted)

    def test_undeletable_high_download_reason_matches_only_documented_case(
        self,
    ) -> None:
        matching = self.module.GitHubApiError(
            "DELETE",
            "https://api.github.com/x",
            400,
            json.dumps(
                {
                    "message": (
                        "Publicly visible package versions with more than "
                        "5000 downloads cannot be deleted. Contact GitHub "
                        "support for further assistance."
                    )
                }
            ),
        )
        self.assertIsNotNone(
            self.module.undeletable_high_download_reason(matching)
        )

        wrong_status = self.module.GitHubApiError(
            "DELETE",
            "https://api.github.com/x",
            403,
            json.dumps(
                {
                    "message": (
                        "Publicly visible package versions with more than "
                        "5000 downloads cannot be deleted."
                    )
                }
            ),
        )
        self.assertIsNone(
            self.module.undeletable_high_download_reason(wrong_status)
        )

        wrong_message = self.module.GitHubApiError(
            "DELETE", "https://api.github.com/x", 400, json.dumps({"message": "Some other 400."})
        )
        self.assertIsNone(
            self.module.undeletable_high_download_reason(wrong_message)
        )

        non_json_detail = self.module.GitHubApiError(
            "DELETE", "https://api.github.com/x", 400, "not json"
        )
        self.assertIsNone(
            self.module.undeletable_high_download_reason(non_json_detail)
        )

    def test_public_and_unknown_packages_are_rejected_before_listing(self) -> None:
        for package in (
            "registry-notary",
            "registry-relay",
            "discovery",
            "evidence",
            "mint",
            "breg",
            "relay",
            "other-candidate",
        ):
            with self.subTest(package=package):
                client = FakeClient({})
                with self.assertRaises(self.module.CleanupError):
                    self.module.cleanup(
                        client,
                        packages=[package],
                        server_now=self.now,
                        apply=True,
                    )
                self.assertEqual([], client.listed)
                self.assertEqual([], client.deleted)

    def test_breg_candidate_is_not_yet_allowlisted(self) -> None:
        # breg-candidate joins CANDIDATE_PACKAGES only once v0.26.0 publishes
        # the first Base Registry Engine candidate; see release/OPERATIONS.md.
        self.assertNotIn("breg-candidate", self.module.CANDIDATE_PACKAGES)
        with self.assertRaises(self.module.CleanupError):
            self.module.assert_candidate_package("breg-candidate")

    def test_malformed_or_future_timestamp_fails_without_deleting(self) -> None:
        for timestamp in ("not-a-date", "2026-07-25T12:00:01Z"):
            with self.subTest(timestamp=timestamp):
                client = FakeClient(
                    {
                        "relay-candidate": [
                            version(2, "2026-07-01T00:00:00Z", ["valid-old"]),
                            version(3, timestamp, ["candidate"]),
                        ]
                    }
                )
                with self.assertRaises(self.module.CleanupError):
                    self.module.cleanup(
                        client,
                        packages=["relay-candidate"],
                        server_now=self.now,
                        apply=True,
                    )
                self.assertEqual([], client.deleted)

    def test_malformed_tag_metadata_fails_closed(self) -> None:
        malformed = version(1, "2026-07-01T00:00:00Z")
        malformed["metadata"]["container"]["tags"] = "not-a-list"
        client = FakeClient({"relay-candidate": [malformed]})
        with self.assertRaisesRegex(self.module.CleanupError, "malformed tag metadata"):
            self.module.cleanup(
                client,
                packages=["relay-candidate"],
                server_now=self.now,
                apply=True,
            )
        self.assertEqual([], client.deleted)

    def test_link_parser_selects_next_relation(self) -> None:
        value = (
            '<https://api.github.com/page/1>; rel="prev", '
            '<https://api.github.com/page/3>; rel="next"'
        )
        self.assertEqual("https://api.github.com/page/3", self.module.next_link(value))

    def test_server_now_comes_from_github_date_header(self) -> None:
        class ServerTimeClient(self.module.GitHubClient):
            def __init__(self):
                pass

            def request(self, path_or_url, *, method="GET"):
                self.assert_request = (path_or_url, method)
                return {}, {"date": "Sat, 25 Jul 2026 12:00:00 GMT"}

        client = ServerTimeClient()
        self.assertEqual(self.now, client.server_now())
        self.assertEqual(("/rate_limit", "GET"), client.assert_request)

    def test_package_versions_follows_pagination(self) -> None:
        class PaginatedClient(self.module.GitHubClient):
            def __init__(self):
                self.api_url = "https://api.github.com"
                self.calls = []

            def request(self, path_or_url, *, method="GET"):
                self.calls.append(path_or_url)
                if len(self.calls) == 1:
                    return [version(1, "2026-07-01T00:00:00Z")], {
                        "link": '<https://api.github.com/page/2>; rel="next"'
                    }
                return [version(2, "2026-07-02T00:00:00Z")], {}

        client = PaginatedClient()
        values = client.package_versions("relay-candidate")
        self.assertEqual([1, 2], [item["id"] for item in values])
        self.assertEqual(2, len(client.calls))

    def test_missing_allowlisted_candidate_package_fails_closed(self) -> None:
        class MissingClient(self.module.GitHubClient):
            def __init__(self):
                self.api_url = "https://api.github.com"
                self.calls = []

            def request(self, path_or_url, *, method="GET"):
                self.calls.append(path_or_url)
                raise self_module.GitHubApiError(
                    method,
                    f"{self.api_url}{path_or_url}",
                    404,
                    "package not found",
                )

        self_module = self.module
        client = MissingClient()
        with self.assertRaisesRegex(self.module.CleanupError, "failed with 404"):
            client.package_versions("relay-candidate")
        self.assertEqual(1, len(client.calls))

    def test_package_version_listing_fails_closed_for_other_errors(self) -> None:
        class FailingClient(self.module.GitHubClient):
            def __init__(self, status):
                self.api_url = "https://api.github.com"
                self.status = status
                self.calls = []

            def request(self, path_or_url, *, method="GET"):
                self.calls.append(path_or_url)
                raise self_module.GitHubApiError(
                    method,
                    f"{self.api_url}{path_or_url}",
                    self.status,
                    "listing failed",
                )

        self_module = self.module
        with self.assertRaisesRegex(self.module.CleanupError, "failed with 500"):
            FailingClient(500).package_versions("relay-candidate")

        client = FailingClient(404)
        with self.assertRaisesRegex(self.module.CleanupError, "exact candidate allowlist"):
            client.package_versions("other-candidate")
        self.assertEqual([], client.calls)

    def test_missing_pagination_page_is_not_treated_as_absent_package(self) -> None:
        class MissingSecondPageClient(self.module.GitHubClient):
            def __init__(self):
                self.api_url = "https://api.github.com"
                self.calls = []

            def request(self, path_or_url, *, method="GET"):
                self.calls.append(path_or_url)
                if len(self.calls) == 1:
                    return [version(1, "2026-07-01T00:00:00Z")], {
                        "link": '<https://api.github.com/page/2>; rel="next"'
                    }
                raise self_module.GitHubApiError(
                    method,
                    path_or_url,
                    404,
                    "page not found",
                )

        self_module = self.module
        with self.assertRaisesRegex(self.module.CleanupError, "failed with 404"):
            MissingSecondPageClient().package_versions("relay-candidate")

    def test_pagination_cannot_change_api_origin(self) -> None:
        class RedirectingClient(self.module.GitHubClient):
            def __init__(self):
                self.api_url = "https://api.github.com"

            def request(self, path_or_url, *, method="GET"):
                return [], {"link": '<https://example.test/page/2>; rel="next"'}

        with self.assertRaisesRegex(self.module.CleanupError, "changed API origin"):
            RedirectingClient().package_versions("relay-candidate")

    def test_pagination_cannot_repeat_a_page(self) -> None:
        class LoopingClient(self.module.GitHubClient):
            def __init__(self):
                self.api_url = "https://api.github.com"

            def request(self, path_or_url, *, method="GET"):
                return [], {
                    "link": (
                        "<https://api.github.com/orgs/registrystack/packages/"
                        "container/relay-candidate/versions?"
                        'per_page=100>; rel="next"'
                    )
                }

        with self.assertRaisesRegex(self.module.CleanupError, "repeated"):
            LoopingClient().package_versions("relay-candidate")


if __name__ == "__main__":
    unittest.main()
