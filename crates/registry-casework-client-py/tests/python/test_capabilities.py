import unittest

from bootstrap import ensure_built

ensure_built()

from registry_casework_client import CaseworkClient  # noqa: E402


class CapabilityTests(unittest.TestCase):
    def test_all_canonical_operations_are_exported(self) -> None:
        methods = {
            "description",
            "create_or_recover_review_request", "review_request", "review_result",
            "review_results", "cancel_review_request", "review_policies", "review_policy",
            "review_tasks", "next_review_task", "review_task_holdings", "own_review_decisions", "supervisory_review_tasks", "review_task", "review_task_context", "claim_review_task", "release_review_task",
            "preview_review_task_templates", "list_review_task_grants",
            "approve_review_task_grant", "revoke_review_task_grant",
            "assign_review_task", "delegate_review_task", "review_task_draft",
            "save_review_task_draft", "delete_review_task_draft", "decide_review_task",
            "review_history", "add_review_note", "review_clocks", "review_accountability",



               "directory",
            "directory_targets",
            "bootstrap_directory",
            "update_directory_team",
            "absences", "create_absence", "update_absence", "delete_absence",
              "preview_caseload_move",
            "apply_caseload_move",
             "holiday_revision", "create_holiday_revision",
            "preview_clock_recompute", "apply_clock_recompute",
        }
        self.assertEqual({name for name in methods if not hasattr(CaseworkClient, name)}, set())
        for name in ("list_work_items", "get_draft", "recover_decision", "preview_task_templates"):
            self.assertFalse(hasattr(CaseworkClient, name), name)


if __name__ == "__main__":
    unittest.main()
