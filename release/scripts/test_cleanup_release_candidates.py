#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
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
    def __init__(self, versions):
        self.versions = versions
        self.listed = []
        self.deleted = []

    def package_versions(self, package):
        self.listed.append(package)
        return list(self.versions.get(package, []))

    def delete_package_version(self, package, version_id):
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
                "registry-notary-candidate": [
                    version(1, "2026-07-18T11:59:59Z", ["candidate-old"]),
                    version(2, "2026-07-18T12:00:00Z", ["candidate-boundary"]),
                ]
            }
        )
        result = self.module.cleanup(
            client,
            packages=["registry-notary-candidate"],
            server_now=self.now,
            apply=False,
        )
        self.assertEqual([], client.deleted)
        self.assertEqual([1], [item["version_id"] for item in result["actions"]])
        self.assertEqual("would_delete", result["actions"][0]["action"])
        self.assertTrue(result["dry_run"])

    def test_apply_deletes_expired_versions_from_both_candidates(self) -> None:
        client = FakeClient(
            {
                "registry-notary-candidate": [version(1, "2026-07-01T00:00:00Z")],
                "registry-relay-candidate": [version(2, "2026-07-02T00:00:00Z")],
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
                ("registry-notary-candidate", 1),
                ("registry-relay-candidate", 2),
            ],
            client.deleted,
        )
        self.assertFalse(result["dry_run"])

    def test_public_and_unknown_packages_are_rejected_before_listing(self) -> None:
        for package in ("registry-notary", "registry-relay", "other-candidate"):
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

    def test_malformed_or_future_timestamp_fails_without_deleting(self) -> None:
        for timestamp in ("not-a-date", "2026-07-25T12:00:01Z"):
            with self.subTest(timestamp=timestamp):
                client = FakeClient(
                    {
                        "registry-relay-candidate": [
                            version(2, "2026-07-01T00:00:00Z", ["valid-old"]),
                            version(3, timestamp, ["candidate"]),
                        ]
                    }
                )
                with self.assertRaises(self.module.CleanupError):
                    self.module.cleanup(
                        client,
                        packages=["registry-relay-candidate"],
                        server_now=self.now,
                        apply=True,
                    )
                self.assertEqual([], client.deleted)

    def test_malformed_tag_metadata_fails_closed(self) -> None:
        malformed = version(1, "2026-07-01T00:00:00Z")
        malformed["metadata"]["container"]["tags"] = "not-a-list"
        client = FakeClient({"registry-notary-candidate": [malformed]})
        with self.assertRaisesRegex(self.module.CleanupError, "malformed tag metadata"):
            self.module.cleanup(
                client,
                packages=["registry-notary-candidate"],
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
        values = client.package_versions("registry-notary-candidate")
        self.assertEqual([1, 2], [item["id"] for item in values])
        self.assertEqual(2, len(client.calls))

    def test_pagination_cannot_change_api_origin(self) -> None:
        class RedirectingClient(self.module.GitHubClient):
            def __init__(self):
                self.api_url = "https://api.github.com"

            def request(self, path_or_url, *, method="GET"):
                return [], {"link": '<https://example.test/page/2>; rel="next"'}

        with self.assertRaisesRegex(self.module.CleanupError, "changed API origin"):
            RedirectingClient().package_versions("registry-relay-candidate")

    def test_pagination_cannot_repeat_a_page(self) -> None:
        class LoopingClient(self.module.GitHubClient):
            def __init__(self):
                self.api_url = "https://api.github.com"

            def request(self, path_or_url, *, method="GET"):
                return [], {
                    "link": (
                        "<https://api.github.com/orgs/registrystack/packages/"
                        "container/registry-relay-candidate/versions?"
                        'per_page=100>; rel="next"'
                    )
                }

        with self.assertRaisesRegex(self.module.CleanupError, "repeated"):
            LoopingClient().package_versions("registry-relay-candidate")


if __name__ == "__main__":
    unittest.main()
