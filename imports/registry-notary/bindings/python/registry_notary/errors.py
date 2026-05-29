"""Registry Notary Python exception hierarchy."""

from __future__ import annotations


class NotaryError(Exception):
    """Base class for all Registry Notary client exceptions."""

    def __init__(
        self,
        *,
        kind: str,
        title: str,
        status: int | None = None,
        code: str | None = None,
        retryable: bool = False,
        request_id: str | None = None,
        retry_after: float | str | None = None,
    ) -> None:
        super().__init__(title)
        self.kind = kind
        self.status = status
        self.code = code
        self.title = title
        self.retryable = retryable
        self.request_id = request_id
        self.retry_after = retry_after

    def __str__(self) -> str:
        parts = []
        if self.code:
            parts.append(f"code={self.code}")
        if self.status is not None:
            parts.append(f"status={self.status}")
        if self.request_id:
            parts.append(f"request_id={self.request_id}")
        return f"{self.title} ({', '.join(parts)})" if parts else self.title


class NotaryTransportError(NotaryError):
    """Raised when the client cannot complete the HTTP exchange."""

    def __init__(self, *, title: str = "Transport error") -> None:
        super().__init__(
            kind="transport",
            title=title,
            code="transport.failed",
            retryable=True,
        )


class NotaryProblemError(NotaryError):
    """Raised for safe Registry Notary problem envelopes and decode failures."""
