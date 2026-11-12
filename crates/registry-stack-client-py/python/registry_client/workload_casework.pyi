from typing import Never

from . import casework as casework

class CaseworkWorkload:
    def __init__(
        self, client: casework.CaseworkClient, token: str, profile: str
    ) -> None: ...
    def __setattr__(self, name: str, value: object) -> None: ...
    def __getattr__(self, operation: str) -> Never: ...
    def description(self) -> casework.Complete[casework.Description]: ...
    def review_policies(
        self,
    ) -> casework.Complete[list[casework.ReviewPolicyClosure]]: ...
    def review_policy(
        self, policy_id: str
    ) -> casework.Complete[casework.ReviewPolicyClosure]: ...
    def review_tasks(
        self,
        query: casework.ReviewStaffingQuery | None = None,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.ReviewTaskPage]: ...
    def review_task(
        self,
        task_id: casework.Uuid,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.ReviewTask]: ...
    def review_task_context(
        self,
        task_id: casework.Uuid,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.ReviewTaskContext]: ...
    def claim_review_task(
        self,
        task_id: casework.Uuid,
        expected_revision: casework.SafeInteger,
        idempotency_key: str,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.ReviewTask]: ...
    def release_review_task(
        self,
        task_id: casework.Uuid,
        expected_revision: casework.SafeInteger,
        idempotency_key: str,
    ) -> casework.Complete[casework.ReviewTask]: ...
    def decide_review_task(
        self,
        task_id: casework.Uuid,
        expected_revision: casework.SafeInteger,
        idempotency_key: str,
        decision: casework.ReviewTaskDecisionRequest,
        source_profile: str | None = None,
    ) -> casework.Complete[None]: ...
    def own_review_decisions(
        self,
        query: casework.OwnReviewDecisionQuery | None = None,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.OwnReviewDecisionPage]: ...
    def review_history(
        self,
        request_id: casework.Uuid,
        query: casework.ReviewPageQuery | None = None,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.ReviewHistoryPage]: ...

class HolderCaseworkWorkload:
    def __init__(
        self, client: casework.CaseworkClient, token: str, profile: str
    ) -> None: ...
    def __setattr__(self, name: str, value: object) -> None: ...
    def __getattr__(self, operation: str) -> Never: ...
    def review_history(
        self,
        request_id: casework.Uuid,
        query: casework.ReviewPageQuery | None = None,
    ) -> casework.Complete[casework.ReviewHistoryPage]: ...
