"""Flask routes and host-only cookies for a holder or staff portal."""

from __future__ import annotations

from typing import Any, Callable

from .portal import (
    AdmissionError,
    CSRFError,
    PortalContext,
    PortalSessions,
    ReauthenticationRequired,
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
    from flask import g, jsonify, make_response, redirect, request  # pyright: ignore[reportMissingImports]

    if persona not in ("holder", "staff") or same_site not in ("Lax", "Strict"):
        raise ValueError("portal persona and SameSite policy are unsupported")
    cookie_name = f"__Host-registry-{persona}"
    auth_paths = frozenset(
        ("/auth/login", "/auth/callback", "/auth/logout", "/auth/switch")
    )

    def error(code: str, status: int):
        response = jsonify({"code": code})
        response.status_code = status
        response.headers["Cache-Control"] = "no-store"
        return response

    def authorized_mutation():
        session_id = request.cookies.get(cookie_name)
        if not session_id:
            raise ReauthenticationRequired()
        csrf_token = request.headers.get("X-CSRF-Token", "")
        if not csrf_token and request.mimetype == "application/x-www-form-urlencoded":
            length = request.content_length
            if length is not None and 1 <= length <= 65_536:
                csrf_token = form_csrf_token(
                    content_type=request.content_type or "",
                    content_length=length,
                    body=request.get_data(cache=True),
                )
        return sessions.authorize_mutation(
            session_id,
            origin=request.headers.get("Origin", ""),
            csrf_token=csrf_token,
        )

    @app.before_request
    def admit_request():
        budget = request_budget(request_seconds)
        budget.__enter__()
        g._registry_portal_budget = budget
        if request.host_url.rstrip("/") != origin:
            return error("authentication.origin-refused", 400)
        if request.path in auth_paths or is_public(
            app.view_functions.get(request.endpoint)
        ):
            return None
        session_id = request.cookies.get(cookie_name)
        if not session_id:
            return error(ReauthenticationRequired.code, 401)
        try:
            if request.method in ("GET", "HEAD", "OPTIONS"):
                context = sessions.context(session_id)
            else:
                context = authorized_mutation()
            if context.persona != persona:
                raise ReauthenticationRequired()
            g.registry_person = person_factory(context)
        except ReauthenticationRequired:
            return error(ReauthenticationRequired.code, 401)
        except CSRFError:
            return error(CSRFError.code, 403)
        return None

    @app.teardown_request
    def finish_request(_error):
        budget = getattr(g, "_registry_portal_budget", None)
        if budget is not None:
            budget.__exit__(None, None, None)

    @app.get("/auth/login")
    def registry_login():
        try:
            authorization = sessions.start(request.args.get("return_to", "/"))
        except ValueError:
            return error(AdmissionError.code, 400)
        response = redirect(authorization.url)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/auth/callback")
    def registry_callback():
        try:
            result = sessions.callback(request.url, state=request.args.get("state", ""))
        except AdmissionError:
            return error(AdmissionError.code, 401)
        if result.authorization is not None:
            response = redirect(result.authorization.url)
        else:
            if result.session_id is None or result.return_to is None:
                return error(AdmissionError.code, 401)
            response = redirect(result.return_to)
            response.set_cookie(
                cookie_name,
                result.session_id,
                secure=True,
                httponly=True,
                samesite=same_site,
                path="/",
            )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/auth/logout")
    def registry_logout():
        try:
            authorized_mutation()
        except ReauthenticationRequired:
            return error(ReauthenticationRequired.code, 401)
        except CSRFError:
            return error(CSRFError.code, 403)
        result = sessions.logout(request.cookies[cookie_name])
        response = redirect(result.end_session_url or "/")
        response.delete_cookie(
            cookie_name, path="/", secure=True, httponly=True, samesite=same_site
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/auth/switch")
    def registry_switch():
        try:
            authorized_mutation()
        except ReauthenticationRequired:
            return error(ReauthenticationRequired.code, 401)
        except CSRFError:
            return error(CSRFError.code, 403)
        result = sessions.logout(request.cookies[cookie_name], switch=True)
        response = (
            redirect(result.end_session_url)
            if result.end_session_url is not None
            else make_response(
                jsonify({"code": "authentication.account-switch-unavailable"}), 409
            )
        )
        response.delete_cookie(
            cookie_name, path="/", secure=True, httponly=True, samesite=same_site
        )
        response.headers["Cache-Control"] = "no-store"
        return response
