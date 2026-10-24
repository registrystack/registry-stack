# SPDX-License-Identifier: Apache-2.0
"""Security and recovery boundaries of the invitation-booking reference."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / "products/coordinator/examples/invitation-booking"


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text())


class InvitationBookingExample(unittest.TestCase):
    def test_issuance_and_acceptance_are_separate_authorized_workflows(self):
        runtime = load_yaml(EXAMPLE / "runtime.yaml")
        packages = runtime["deployment"]["packages"]
        self.assertEqual(
            {Path(package["root"]).name for package in packages},
            {"issue-invitation", "accept-invitation"},
        )

        policies = runtime["deployment"]["authentication"]["policies"]
        self.assertEqual(policies["institution-issuer"]["workflows"], ["issue-invitation"])
        self.assertEqual(
            policies["authorized-acceptance-producer"]["workflows"],
            ["accept-invitation"],
        )
        self.assertNotEqual(
            policies["institution-issuer"]["requiredScopes"],
            policies["authorized-acceptance-producer"]["requiredScopes"],
        )

    def test_acceptance_claims_source_before_capacity_and_records_result_after(self):
        project = load_yaml(EXAMPLE / "accept-invitation/workflow.yaml")
        operations = project["operations"]
        self.assertEqual(
            operations["invitations-read-record"]["uses"], "breg.read-record/v1"
        )
        self.assertEqual(
            operations["invitations-claim"]["uses"], "breg.invoke-action/v1"
        )
        self.assertEqual(
            operations["book-appointment"]["uses"],
            "scheduling.create-appointment/v1",
        )
        self.assertEqual(
            operations["invitations-record-booking-result"]["uses"],
            "breg.invoke-action/v1",
        )

        steps = project["workflow"]["steps"]
        self.assertEqual(steps["claim"]["next"], "read-claimed-invitation")
        self.assertEqual(steps["book"]["next"], "record-result")
        self.assertEqual(steps["record-result"]["next"], "notify")
        self.assertEqual(steps["capacity"]["cases"]["unavailable"], "record-no-capacity")

        functions = (EXAMPLE / "accept-invitation/functions.rhai").read_text()
        self.assertIn("duplicateKey: invitation.acceptanceId", functions)
        self.assertIn(
            "if invitation.resourceRequired { invitation.resourceId }", functions
        )
        self.assertIn("durationMinutes: invitation.durationMinutes", functions)
        self.assertIn("resource: resource", functions)
        self.assertNotIn("token", functions.lower())

        readme = (EXAMPLE / "README.md").read_text()
        self.assertIn("Coordinator start idempotency key", readme)
        self.assertIn("same verified producer identity", readme)
        self.assertIn("does not authenticate", readme)

    def test_source_project_enforces_single_current_claim_and_server_date_expiry(self):
        registry = load_yaml(EXAMPLE / "source-registry/registry.yaml")
        invitation = registry["recordTypes"][0]
        self.assertIn(
            {
                "id": "invitation-acceptance-identity",
                "type": "unique",
                "fields": ["issuer", "acceptance-id"],
            },
            invitation["constraints"],
        )
        actions = {action["id"]: action for action in registry["actions"]}
        claim = actions["claim-invitation"]
        guards = claim["commitGuards"]["targets"]
        self.assertIn(
            {"input": "invitation", "field": "state", "equals": "issued"}, guards
        )
        self.assertIn(
            {"input": "invitation", "field": "acceptance-authorized", "equals": True},
            guards,
        )
        self.assertIn(
            {
                "input": "invitation",
                "field": "relationship-valid-through",
                "currentDate": "on-or-after",
            },
            guards,
        )
        self.assertIn(
            {
                "input": "invitation",
                "field": "expires-on",
                "currentDate": "on-or-after",
            },
            guards,
        )

        record_result = actions["record-booking-result"]
        result_guards = record_result["commitGuards"]["targets"]
        self.assertIn(
            {"input": "invitation", "field": "state", "equals": "accepting"},
            result_guards,
        )

        revoke = actions["revoke-invitation"]
        self.assertIn(
            {"input": "invitation", "field": "state", "equals": "issued"},
            revoke["commitGuards"]["targets"],
        )
        self.assertIn(
            {
                "input": "invitation",
                "field": "acceptance-id",
                "equalsFromInput": "acceptance-id",
            },
            result_guards,
        )

    def test_source_project_has_native_guard_and_replay_journey(self):
        clients = load_yaml(EXAMPLE / "source-registry/dev-clients.yaml")
        journeys = load_yaml(EXAMPLE / "source-registry/tests/journeys.yaml")
        client = next(
            item
            for item in clients["clients"]
            if item["id"] == "invitation-source-agent"
        )
        self.assertEqual(client["accessProfiles"], ["invitation-workflow"])
        steps = {
            step["id"]: step for step in journeys["journeys"][0]["steps"]
        }
        self.assertEqual(
            steps["retry-issued-response"]["request"]["idempotencyKey"],
            steps["issue-eligible"]["request"]["idempotencyKey"],
        )
        self.assertEqual(
            steps["second-claim-is-refused"]["expect"]["problemCode"],
            "precondition.failed",
        )
        for identifier in (
            "claim-expired-is-refused",
            "claim-revoked-is-refused",
            "claim-ineligible-is-refused",
        ):
            self.assertEqual(steps[identifier]["expect"]["outcome"], "refusal")
        self.assertEqual(
            steps["record-no-capacity"]["expect"]["outcome"], "success"
        )

    def test_urls_and_scenarios_keep_authority_out_of_the_invitation_reference(self):
        issue_functions = (EXAMPLE / "issue-invitation/functions.rhai").read_text()
        self.assertIn("invitationReference", issue_functions)
        self.assertNotIn("email=", issue_functions)
        self.assertNotIn("beneficiary", issue_functions.lower().split("?", 1)[-1])
        self.assertNotIn("token", issue_functions.lower())

        scenarios = load_yaml(EXAMPLE / "accept-invitation/scenarios.yaml")
        case_ids = {case["id"] for case in scenarios["cases"]}
        self.assertTrue(
            {
                "appointment-accepted",
                "assigned-resource-accepted",
                "no-current-capacity",
                "invitation-expired",
                "invitation-revoked",
                "invitation-ineligible",
                "simultaneous-acceptance-source-claim-refused",
                "booking-response-loss-reconciled",
                "source-result-response-loss-retried-same",
            }.issubset(case_ids)
        )
        assigned = next(
            case
            for case in scenarios["cases"]
            if case["id"] == "assigned-resource-accepted"
        )
        for step in ("read-invitation", "read-claimed-invitation"):
            invitation = assigned["replies"][step][0]["value"]["data"]["domainData"]
            self.assertEqual(invitation["durationMinutes"], 60)
            self.assertTrue(invitation["resourceRequired"])
            self.assertEqual(invitation["resourceId"], "professional-one")


if __name__ == "__main__":
    unittest.main()
