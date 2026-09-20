import unittest

from bootstrap import ensure_built

ensure_built()

from registry_casework_client import CaseworkClient  # noqa: E402


class CapabilityTests(unittest.TestCase):
    def test_all_canonical_operations_are_exported(self) -> None:
        methods = {
            "description",
            "create_or_recover_review_request", "review_request", "review_result",
            "review_results", "cancel_review_request", "review_kinds", "review_kind",
            "review_tasks", "review_task", "review_task_context", "claim_review_task", "release_review_task",
            "assign_review_task", "delegate_review_task", "review_task_draft",
            "save_review_task_draft", "delete_review_task_draft", "decide_review_task",
            "review_history", "add_review_note", "review_clocks", "review_accountability",
            "list_work_items", "next_work_item",
            "get_work_item", "claim_work_item", "release_work_item", "get_draft",
            "save_draft", "delete_draft", "decide_work_item", "recover_decision",
            "recover_decision_by_key", "work_item_history", "holdings", "directory",
            "directory_targets",
            "bootstrap_directory",
            "update_directory_team",
            "absences", "create_absence", "update_absence", "delete_absence",
            "assign_work_item", "delegate_work_item", "preview_caseload_move",
            "apply_caseload_move",
            "work_item_clocks", "holiday_revision", "create_holiday_revision",
            "preview_clock_recompute", "apply_clock_recompute",
        }
        self.assertEqual({name for name in methods if not hasattr(CaseworkClient, name)}, set())


if __name__ == "__main__":
    unittest.main()
