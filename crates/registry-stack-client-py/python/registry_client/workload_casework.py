"""Immutable, token-free access to the accepted staff Casework surface."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .connection import UnsupportedOperationError
from .workload import _require_sync

if TYPE_CHECKING:
    from . import casework


class CaseworkWorkload:
    """One Casework target with one immutable token and staff profile."""

    __slots__ = ("__client", "__token", "__profile")

    def __init__(
        self, client: casework.CaseworkClient, token: str, profile: str
    ) -> None:
        if not isinstance(token, str):
            raise TypeError("token must be a string")
        if not isinstance(profile, str):
            raise TypeError("profile must be a string")
        object.__setattr__(self, "_CaseworkWorkload__client", client)
        object.__setattr__(self, "_CaseworkWorkload__token", token)
        object.__setattr__(self, "_CaseworkWorkload__profile", profile)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("CaseworkWorkload is immutable")

    def __getattr__(self, operation: str):
        raise UnsupportedOperationError("casework", operation)

    def description(self) -> casework.Complete[casework.Description]:
        _require_sync()
        return self.__client.description(self.__token, self.__profile)

    def review_policies(
        self,
    ) -> casework.Complete[list[casework.ReviewPolicyClosure]]:
        _require_sync()
        return self.__client.review_policies(self.__token, self.__profile)

    def review_policy(
        self, policy_id: str
    ) -> casework.Complete[casework.ReviewPolicyClosure]:
        _require_sync()
        return self.__client.review_policy(self.__token, self.__profile, policy_id)

    def review_tasks(
        self,
        query: casework.ReviewStaffingQuery | None = None,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.ReviewTaskPage]:
        _require_sync()
        return self.__client.review_tasks(
            self.__token, self.__profile, query, source_profile
        )

    def review_task(
        self,
        task_id: casework.Uuid,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.ReviewTask]:
        _require_sync()
        return self.__client.review_task(
            self.__token, self.__profile, task_id, source_profile
        )

    def review_task_context(
        self,
        task_id: casework.Uuid,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.ReviewTaskContext]:
        _require_sync()
        return self.__client.review_task_context(
            self.__token, self.__profile, task_id, source_profile
        )

    def claim_review_task(
        self,
        task_id: casework.Uuid,
        expected_revision: casework.SafeInteger,
        idempotency_key: str,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.ReviewTask]:
        _require_sync()
        return self.__client.claim_review_task(
            self.__token,
            self.__profile,
            task_id,
            expected_revision,
            idempotency_key,
            source_profile,
        )

    def release_review_task(
        self,
        task_id: casework.Uuid,
        expected_revision: casework.SafeInteger,
        idempotency_key: str,
    ) -> casework.Complete[casework.ReviewTask]:
        _require_sync()
        return self.__client.release_review_task(
            self.__token,
            self.__profile,
            task_id,
            expected_revision,
            idempotency_key,
        )

    def decide_review_task(
        self,
        task_id: casework.Uuid,
        expected_revision: casework.SafeInteger,
        idempotency_key: str,
        decision: casework.ReviewTaskDecisionRequest,
        source_profile: str | None = None,
    ) -> casework.Complete[None]:
        _require_sync()
        return self.__client.decide_review_task(
            self.__token,
            self.__profile,
            task_id,
            expected_revision,
            idempotency_key,
            decision,
            source_profile,
        )

    def own_review_decisions(
        self,
        query: casework.OwnReviewDecisionQuery | None = None,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.OwnReviewDecisionPage]:
        _require_sync()
        return self.__client.own_review_decisions(
            self.__token, self.__profile, query, source_profile
        )

    def review_history(
        self,
        request_id: casework.Uuid,
        query: casework.ReviewPageQuery | None = None,
        source_profile: str | None = None,
    ) -> casework.Complete[casework.ReviewHistoryPage]:
        _require_sync()
        return self.__client.review_history(
            self.__token, self.__profile, request_id, query, source_profile
        )


class HolderCaseworkWorkload:
    """Holder authority exposes only personal review history."""

    __slots__ = ("__client", "__token", "__profile")

    def __init__(
        self, client: casework.CaseworkClient, token: str, profile: str
    ) -> None:
        if not isinstance(token, str) or not isinstance(profile, str):
            raise TypeError("token and profile must be strings")
        object.__setattr__(self, "_HolderCaseworkWorkload__client", client)
        object.__setattr__(self, "_HolderCaseworkWorkload__token", token)
        object.__setattr__(self, "_HolderCaseworkWorkload__profile", profile)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("HolderCaseworkWorkload is immutable")

    def __getattr__(self, operation: str):
        raise UnsupportedOperationError("casework", operation)

    def review_history(
        self,
        request_id: casework.Uuid,
        query: casework.ReviewPageQuery | None = None,
    ) -> casework.Complete[casework.ReviewHistoryPage]:
        _require_sync()
        return self.__client.review_history(
            self.__token, self.__profile, request_id, query, None
        )
