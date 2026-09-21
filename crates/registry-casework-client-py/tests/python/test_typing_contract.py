import ast
import unittest
from pathlib import Path


STUB = (
    Path(__file__).parents[2]
    / "python"
    / "registry_casework_client"
    / "__init__.pyi"
)


class TypingContractTests(unittest.TestCase):
    def test_review_parity_inventory_is_closed_and_bounded(self) -> None:
        module = ast.parse(STUB.read_text(encoding="utf-8"))
        classes = {
            node.name: node
            for node in module.body
            if isinstance(node, ast.ClassDef)
        }
        aliases = {
            node.target.id: node
            for node in module.body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
        }

        create_optional = classes["_ReviewCreateRequestOptional"]
        constraints = next(
            node.annotation
            for node in create_optional.body
            if isinstance(node, ast.AnnAssign)
            and node.target.id == "resultConstraints"
        )
        self.assertEqual(ast.unparse(constraints), "JsonObject | None")
        context_optional = classes["_ReviewTaskContextOptional"]
        context_constraints = next(
            node.annotation
            for node in context_optional.body
            if isinstance(node, ast.AnnAssign)
            and node.target.id == "resultConstraints"
        )
        self.assertEqual(ast.unparse(context_constraints), "JsonObject")
        result_optional = classes["_ReviewResultOptional"]
        result_payload = next(
            node.annotation
            for node in result_optional.body
            if isinstance(node, ast.AnnAssign) and node.target.id == "result"
        )
        self.assertEqual(ast.unparse(result_payload), "JsonObject")

        self.assertEqual(
            ast.unparse(aliases["ReviewResultOutcome"].value),
            "ReviewResultAvailable | ReviewResultPending | ReviewResultConcealedOrUnknown | ReviewResultExpired",
        )
        for name, kind, value_type in (
            ("ReviewResultAvailable", "available", "ReviewResult"),
            ("ReviewResultPending", "pending", "None"),
            ("ReviewResultConcealedOrUnknown", "concealed_or_unknown", "None"),
            ("ReviewResultExpired", "expired", "None"),
        ):
            fields = {
                node.target.id: ast.unparse(node.annotation)
                for node in classes[name].body
                if isinstance(node, ast.AnnAssign)
            }
            self.assertEqual(fields["kind"], f"Literal['{kind}']")
            self.assertEqual(fields["value"], value_type)
            self.assertEqual(fields["trace_id"], "str")

        self.assertEqual(
            ast.unparse(aliases["ReviewerTaskState"].value),
            "Literal['open', 'decided'] | ReviewHeldTaskState",
        )
        reviewer_task_fields = {
            node.target.id: ast.unparse(node.annotation)
            for node in classes["ReviewerTask"].body
            if isinstance(node, ast.AnnAssign)
        }
        self.assertEqual(reviewer_task_fields["state"], "ReviewerTaskState")
        self.assertEqual(reviewer_task_fields["stageIndex"], "SafeInteger")
        self.assertEqual(reviewer_task_fields["revision"], "SafeInteger")
        draft_fields = {
            node.target.id: ast.unparse(node.annotation)
            for node in classes["ReviewTaskDraft"].body
            if isinstance(node, ast.AnnAssign)
        }
        self.assertEqual(draft_fields["taskId"], "Uuid")
        self.assertEqual(draft_fields["revision"], "SafeInteger")

        for name in (
            "ReviewPageQuery",
            "_ReviewResultFeedPageOptional",
            "_ReviewTaskPageOptional",
            "_ReviewHistoryPageOptional",
        ):
            cursor = next(
                node.annotation
                for node in classes[name].body
                if isinstance(node, ast.AnnAssign)
                and node.target.id in {"cursor", "nextCursor"}
            )
            self.assertEqual(ast.unparse(cursor), "Uuid")

        methods = {
            node.name: node
            for node in classes["CaseworkClient"].body
            if isinstance(node, ast.FunctionDef)
        }
        cancellation = methods["cancel_review_request"]
        arguments = {
            argument.arg: ast.unparse(argument.annotation)
            for argument in cancellation.args.args
            if argument.annotation is not None
        }
        self.assertEqual(arguments["accepted"], "ReviewRequestAccepted")
        self.assertNotIn("request_id", arguments)
        for method_name in (
            "approve_review_task_grant",
            "claim_review_task",
            "release_review_task",
            "assign_review_task",
            "delegate_review_task",
            "save_review_task_draft",
            "delete_review_task_draft",
            "decide_review_task",
        ):
            method_arguments = {
                argument.arg: ast.unparse(argument.annotation)
                for argument in methods[method_name].args.args
                if argument.annotation is not None
            }
            self.assertEqual(method_arguments["task_id"], "Uuid")
            self.assertEqual(method_arguments["expected_revision"], "SafeInteger")

    def test_review_create_request_requires_wire_mandatory_fields(self) -> None:
        module = ast.parse(STUB.read_text(encoding="utf-8"))
        classes = {
            node.name: node
            for node in module.body
            if isinstance(node, ast.ClassDef)
        }
        optional = classes["_ReviewCreateRequestOptional"]
        request = classes["ReviewCreateRequest"]

        self.assertEqual(
            {node.target.id for node in optional.body if isinstance(node, ast.AnnAssign)},
            {"initiator", "resultConstraints"},
        )
        self.assertTrue(
            any(
                keyword.arg == "total" and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in optional.keywords
            )
        )
        self.assertEqual(
            {node.target.id for node in request.body if isinstance(node, ast.AnnAssign)},
            {"kind", "subject", "requesterReference", "context"},
        )
        self.assertEqual(
            [base.id for base in request.bases if isinstance(base, ast.Name)],
            ["_ReviewCreateRequestOptional"],
        )
        self.assertFalse(any(keyword.arg == "total" for keyword in request.keywords))

        context_alias = next(
            node
            for node in module.body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "ReviewContext"
        )
        self.assertEqual(
            ast.unparse(context_alias.value),
            "ReviewSubmittedCreateContext | ReviewSourceCreateContext",
        )
        context = next(
            node.annotation
            for node in request.body
            if isinstance(node, ast.AnnAssign) and node.target.id == "context"
        )
        self.assertEqual(ast.unparse(context), "ReviewContext")
        self.assertEqual(
            {
                node.target.id
                for node in classes["ReviewSubmittedCreateContext"].body
                if isinstance(node, ast.AnnAssign)
            },
            {"strategy", "snapshot"},
        )
        self.assertEqual(
            {
                node.target.id
                for node in classes["ReviewSourceCreateContext"].body
                if isinstance(node, ast.AnnAssign)
            },
            {"strategy", "binding"},
        )

    def test_review_request_view_keeps_only_active_stage_optional(self) -> None:
        module = ast.parse(STUB.read_text(encoding="utf-8"))
        classes = {
            node.name: node
            for node in module.body
            if isinstance(node, ast.ClassDef)
        }
        optional = classes["_ReviewRequestViewOptional"]
        view = classes["ReviewRequestView"]

        self.assertEqual(
            {node.target.id for node in optional.body if isinstance(node, ast.AnnAssign)},
            {"activeStage"},
        )
        self.assertTrue(
            any(
                keyword.arg == "total" and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in optional.keywords
            )
        )
        self.assertEqual(
            {node.target.id for node in view.body if isinstance(node, ast.AnnAssign)},
            {"requesterReference", "lifecycle", "createdAt", "updatedAt"},
        )
        self.assertEqual(
            [base.id for base in view.bases if isinstance(base, ast.Name)],
            ["ReviewRequestAccepted", "_ReviewRequestViewOptional"],
        )
        self.assertFalse(any(keyword.arg == "total" for keyword in view.keywords))

    def test_review_result_keeps_only_payload_fields_optional(self) -> None:
        module = ast.parse(STUB.read_text(encoding="utf-8"))
        classes = {
            node.name: node
            for node in module.body
            if isinstance(node, ast.ClassDef)
        }
        optional = classes["_ReviewResultOptional"]
        result = classes["ReviewResult"]

        self.assertEqual(
            {node.target.id for node in optional.body if isinstance(node, ast.AnnAssign)},
            {"outcome", "result"},
        )
        self.assertTrue(
            any(
                keyword.arg == "total" and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in optional.keywords
            )
        )
        self.assertEqual(
            {node.target.id for node in result.body if isinstance(node, ast.AnnAssign)},
            {"resultId", "status", "completedAt", "availableUntil"},
        )
        self.assertEqual(
            [base.id for base in result.bases if isinstance(base, ast.Name)],
            ["ReviewRequestAccepted", "_ReviewResultOptional"],
        )
        self.assertFalse(any(keyword.arg == "total" for keyword in result.keywords))

    def test_review_cancel_response_is_a_closed_tagged_union(self) -> None:
        module = ast.parse(STUB.read_text(encoding="utf-8"))
        classes = {
            node.name: node
            for node in module.body
            if isinstance(node, ast.ClassDef)
        }
        alias = next(
            node
            for node in module.body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "ReviewCancelResponse"
        )
        self.assertEqual(
            ast.unparse(alias.value),
            "ReviewCancelledResponse | ReviewAlreadyTerminalResponse",
        )
        for name in ("ReviewCancelledResponse", "ReviewAlreadyTerminalResponse"):
            self.assertEqual(
                {
                    node.target.id
                    for node in classes[name].body
                    if isinstance(node, ast.AnnAssign)
                },
                {"outcome", "result"},
            )

    def test_review_pages_history_and_decisions_match_required_wire_fields(self) -> None:
        module = ast.parse(STUB.read_text(encoding="utf-8"))
        classes = {
            node.name: node
            for node in module.body
            if isinstance(node, ast.ClassDef)
        }

        for page_name, optional_name in (
            ("ReviewResultFeedPage", "_ReviewResultFeedPageOptional"),
            ("ReviewTaskPage", "_ReviewTaskPageOptional"),
            ("ReviewHistoryPage", "_ReviewHistoryPageOptional"),
        ):
            with self.subTest(page=page_name):
                page = classes[page_name]
                optional = classes[optional_name]
                self.assertEqual(
                    {node.target.id for node in page.body if isinstance(node, ast.AnnAssign)},
                    {"items"},
                )
                self.assertEqual(
                    {node.target.id for node in optional.body if isinstance(node, ast.AnnAssign)},
                    {"nextCursor"},
                )
                self.assertFalse(any(keyword.arg == "total" for keyword in page.keywords))

        history = classes["ReviewHistoryEntry"]
        history_optional = classes["_ReviewHistoryEntryOptional"]
        self.assertEqual(
            {node.target.id for node in history.body if isinstance(node, ast.AnnAssign)},
            {"eventId", "requestId", "kind", "detail", "occurredAt"},
        )
        self.assertEqual(
            {node.target.id for node in history_optional.body if isinstance(node, ast.AnnAssign)},
            {"taskId", "actorRef"},
        )

        request = classes["ReviewTaskDecisionRequest"]
        self.assertEqual(
            {node.target.id for node in request.body if isinstance(node, ast.AnnAssign)},
            {"decision"},
        )
        for decision_name in (
            "ReviewApproveDecision",
            "ReviewRejectDecision",
            "ReviewChangesRequestedDecision",
            "ReviewAnswerDecision",
        ):
            self.assertIn(decision_name, classes)


if __name__ == "__main__":
    unittest.main()
