"""Typed, token-free access to the supported workload product methods."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
import math
import time
from typing import TYPE_CHECKING

from .connection import UnsupportedOperationError

if TYPE_CHECKING:
    from . import messaging
    from . import breg


_deadline: ContextVar[float | None] = ContextVar(
    "registry_client_deadline", default=None
)


class RequestBudgetExceeded(TimeoutError):
    """No new downstream work may begin within this request."""


@contextmanager
def request_budget(seconds: float):
    """Bound new work in this context; an inner budget cannot widen its parent."""
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("request budget must be finite and positive")
    deadline = time.monotonic() + seconds
    prior = _deadline.get()
    token = _deadline.set(min(prior, deadline) if prior is not None else deadline)
    try:
        yield
    finally:
        _deadline.reset(token)


def _require_sync() -> None:
    deadline = _deadline.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise RequestBudgetExceeded("request budget ended before a new downstream call")
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError(
        "Registry Stack native calls block the event-loop thread; use a synchronous "
        "handler or explicitly offload the call to a worker thread"
    )


class MessagingWorkload:
    """One Messaging target and one immutable workload token provider."""

    __slots__ = ("_client", "_provider")

    def __init__(self, client: messaging.MessagingClient, provider: breg.PrivateKeyJwt):
        self._client = client
        self._provider = provider

    def __getattr__(self, operation: str):
        raise UnsupportedOperationError("messaging", operation)

    def health(self) -> messaging.Complete[None]:
        _require_sync()
        return self._client.health()

    def ready(self) -> messaging.Complete[None]:
        _require_sync()
        return self._client.ready()

    def submit(
        self, idempotency_key: str, request: messaging.SubmitMessageRequest
    ) -> messaging.Complete[messaging.MessageReceipt]:
        _require_sync()
        return self._client.submit(
            self._provider.bearer_token(), idempotency_key, request
        )

    def message_receipt(
        self, idempotency_key: str, request: messaging.SubmitMessageRequest
    ) -> messaging.Complete[messaging.MessageReceipt]:
        _require_sync()
        return self._client.message_receipt(
            self._provider.bearer_token(), idempotency_key, request
        )

    def message(
        self, message_id: messaging.MessageId
    ) -> messaging.Complete[messaging.MessageView]:
        _require_sync()
        return self._client.message(self._provider.bearer_token(), message_id)

    def cancel(
        self, message_id: messaging.MessageId
    ) -> messaging.Complete[messaging.MessageView]:
        _require_sync()
        return self._client.cancel(self._provider.bearer_token(), message_id)

    def preview(
        self, template_id: str, version: str, request: messaging.TemplatePreviewRequest
    ) -> messaging.Complete[messaging.TemplatePreview]:
        _require_sync()
        return self._client.preview(
            self._provider.bearer_token(), template_id, version, request
        )
