"""FastAPI request translation for a configured Registry Stack service."""

from __future__ import annotations

import asyncio
from typing import Any

from .machine import AdmissionError, AdmissionUnavailable
from .web import is_public
from .workload import request_budget


def install(app: Any, stack: Any, *, request_seconds: float) -> None:
    """Protect every route unless its endpoint is explicitly decorated public."""
    from fastapi import Request
    from fastapi.responses import JSONResponse
    from starlette.routing import Match

    def route_is_public(scope: dict[str, Any]) -> bool:
        for route in app.router.routes:
            match, _ = route.matches(scope)
            if match == Match.FULL:
                return is_public(getattr(route, "endpoint", None))
        return False

    @app.middleware("http")
    async def admit_request(request: Request, call_next):
        with request_budget(request_seconds):
            if not route_is_public(request.scope):
                try:
                    request.state.registry_context = await asyncio.to_thread(
                        stack.admit,
                        {"authorization": request.headers.getlist("authorization")},
                    )
                except AdmissionError:
                    return JSONResponse(
                        {"code": AdmissionError.code},
                        status_code=401,
                        headers={"Cache-Control": "no-store"},
                    )
                except AdmissionUnavailable:
                    return JSONResponse(
                        {"code": AdmissionUnavailable.code},
                        status_code=503,
                        headers={"Cache-Control": "no-store"},
                    )
            return await call_next(request)
