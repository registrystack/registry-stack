"""FastAPI routes and host-only cookies for a holder or staff portal."""

import asyncio
from typing import Any, Callable, MutableMapping

from .portal import (
    AdmissionError,
    CSRFError,
    PortalContext,
    PortalSessions,
    ReauthenticationRequired,
    _PendingChainMismatch,
    _valid_chain_id,
)
from .web import form_csrf_token, is_public
from .workload import request_budget


def install(
    app: Any,
    sessions: PortalSessions,
    *,
    origin: str,
    persona: str,
    person_factory: Callable[[PortalContext], Any],
    request_seconds: float,
    same_site: str = "Lax",
) -> None:
    """Protect application routes and mount a complete multi-grant login flow."""
    from fastapi import Request
    from fastapi.responses import JSONResponse, RedirectResponse
    from starlette.routing import Match

    if persona not in ("holder", "staff") or same_site not in ("Lax", "Strict"):
        raise ValueError("portal persona and SameSite policy are unsupported")
    cookie_name = f"__Host-registry-{persona}"
    pending_cookie_name = f"__Host-registry-{persona}-pending"
    auth_paths = frozenset(
        ("/auth/login", "/auth/callback", "/auth/logout", "/auth/switch")
    )

    def error(code: str, status: int) -> JSONResponse:
        return JSONResponse(
            {"code": code},
            status_code=status,
            headers={"Cache-Control": "no-store"},
        )

    def route_is_public(scope: MutableMapping[str, Any]) -> bool:
        for route in app.router.routes:
            match, _ = route.matches(scope)
            if match == Match.FULL:
                return is_public(getattr(route, "endpoint", None))
        return False

    def request_origin(request: Request) -> str:
        return f"{request.url.scheme}://{request.headers.get('host', '')}"

    def clear_cookie(response: Any, name: str, *, pending: bool = False) -> None:
        response.set_cookie(
            name,
            "",
            max_age=0,
            expires=0,
            secure=True,
            httponly=True,
            samesite=("lax" if pending or same_site == "Lax" else "strict"),
            path="/",
        )

    async def cancel_pending(request: Request) -> None:
        chain_id = request.cookies.get(pending_cookie_name)
        if chain_id and _valid_chain_id(chain_id):
            await asyncio.to_thread(sessions.cancel, chain_id)

    async def authorized_mutation(request: Request) -> PortalContext:
        session_id = request.cookies.get(cookie_name)
        if not session_id:
            raise ReauthenticationRequired()
        csrf_token = request.headers.get("x-csrf-token", "")
        length_text = request.headers.get("content-length", "")
        if (
            not csrf_token
            and request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            == "application/x-www-form-urlencoded"
            and length_text.isascii()
            and length_text.isdecimal()
            and 1 <= int(length_text) <= 65_536
        ):
            csrf_token = form_csrf_token(
                content_type=request.headers["content-type"],
                content_length=int(length_text),
                body=await request.body(),
            )
        return await asyncio.to_thread(
            sessions.authorize_mutation,
            session_id,
            origin=request.headers.get("origin", ""),
            csrf_token=csrf_token,
        )

    @app.middleware("http")
    async def admit_request(request: Request, call_next: Callable):
        with request_budget(request_seconds):
            if request_origin(request) != origin:
                return error("authentication.origin-refused", 400)
            if request.url.path in auth_paths or route_is_public(request.scope):
                return await call_next(request)
            session_id = request.cookies.get(cookie_name)
            if not session_id:
                return error(ReauthenticationRequired.code, 401)
            try:
                if request.method in ("GET", "HEAD", "OPTIONS"):
                    context = await asyncio.to_thread(sessions.context, session_id)
                else:
                    context = await authorized_mutation(request)
                if context.persona != persona:
                    raise ReauthenticationRequired()
                request.state.registry_person = await asyncio.to_thread(
                    person_factory, context
                )
            except ReauthenticationRequired:
                return error(ReauthenticationRequired.code, 401)
            except CSRFError:
                return error(CSRFError.code, 403)
            return await call_next(request)

    @app.get("/auth/login")
    async def registry_login(request: Request):
        try:
            await cancel_pending(request)
            authorization = await asyncio.to_thread(
                sessions.start, request.query_params.get("return_to", "/")
            )
        except ValueError:
            return error(AdmissionError.code, 400)
        response = RedirectResponse(authorization.url, status_code=302)
        response.set_cookie(
            pending_cookie_name,
            authorization.chain_id,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/auth/callback")
    async def registry_callback(request: Request):
        chain_id = request.cookies.get(pending_cookie_name)
        if not chain_id:
            return error(AdmissionError.code, 401)
        if not _valid_chain_id(chain_id):
            response = error(AdmissionError.code, 401)
            clear_cookie(response, pending_cookie_name, pending=True)
            return response
        try:
            result = await asyncio.to_thread(
                sessions._callback_for_chain,
                str(request.url),
                state=request.query_params.get("state", ""),
                chain_id=chain_id,
            )
        except _PendingChainMismatch:
            return error(AdmissionError.code, 401)
        except AdmissionError:
            response = error(AdmissionError.code, 401)
            clear_cookie(response, pending_cookie_name, pending=True)
            return response
        if result.authorization is not None:
            response = RedirectResponse(result.authorization.url, status_code=302)
        else:
            if result.session_id is None or result.return_to is None:
                return error(AdmissionError.code, 401)
            response = RedirectResponse(result.return_to, status_code=302)
            response.set_cookie(
                cookie_name,
                result.session_id,
                secure=True,
                httponly=True,
                samesite="lax" if same_site == "Lax" else "strict",
                path="/",
            )
            clear_cookie(response, pending_cookie_name, pending=True)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/auth/logout")
    async def registry_logout(request: Request):
        try:
            await authorized_mutation(request)
        except ReauthenticationRequired:
            return error(ReauthenticationRequired.code, 401)
        except CSRFError:
            return error(CSRFError.code, 403)
        await cancel_pending(request)
        result = await asyncio.to_thread(sessions.logout, request.cookies[cookie_name])
        response = RedirectResponse(result.end_session_url or "/", status_code=302)
        clear_cookie(response, cookie_name)
        clear_cookie(response, pending_cookie_name, pending=True)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/auth/switch")
    async def registry_switch(request: Request):
        try:
            await authorized_mutation(request)
        except ReauthenticationRequired:
            return error(ReauthenticationRequired.code, 401)
        except CSRFError:
            return error(CSRFError.code, 403)
        await cancel_pending(request)
        result = await asyncio.to_thread(
            sessions.logout, request.cookies[cookie_name], switch=True
        )
        if result.end_session_url is not None:
            response = RedirectResponse(result.end_session_url, status_code=302)
        else:
            response = error("authentication.account-switch-unavailable", 409)
        clear_cookie(response, cookie_name)
        clear_cookie(response, pending_cookie_name, pending=True)
        response.headers["Cache-Control"] = "no-store"
        return response
