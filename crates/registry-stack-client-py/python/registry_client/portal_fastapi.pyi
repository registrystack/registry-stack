from typing import Any, Callable

from .portal import PortalContext, PortalSessions

def install(
    app: Any,
    sessions: PortalSessions,
    *,
    origin: str,
    persona: str,
    person_factory: Callable[[PortalContext], Any],
    request_seconds: float,
    same_site: str = ...,
) -> None: ...
