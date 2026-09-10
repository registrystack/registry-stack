import unittest

from bootstrap import ensure_built

ensure_built()

from registry_casework_client import CaseworkClient  # noqa: E402


class CapabilityTests(unittest.TestCase):
    def test_all_canonical_operations_are_exported(self) -> None:
        methods = {
            "description",
            "create_hosted_item", "get_hosted_item", "add_hosted_note",
            "requester_hosted_notes", "cancel_hosted_item", "hosted_terminal_items",
            "list_hosted_work_items", "get_hosted_work_item",
            "hosted_work_item_history", "hosted_accountability_record",
            "claim_hosted_work_item", "release_hosted_work_item",
            "decide_hosted_work_item", "list_work_items", "next_work_item",
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
