from collections.abc import Callable
from typing import Any

class RenderClientError(Exception):
    outcome_unknown: bool
    transport_kind: str | None
    kind: str
    status: int | None
    code: str | None
    trace_id: str | None

class RenderClient:
    def __init__(self, config: dict[str, Any]) -> None: ...
    def render(
        self,
        token: str | Callable[[], str] | Any,
        document_type: str,
        request: dict[str, Any],
    ) -> dict[str, Any]: ...

__version__: str
