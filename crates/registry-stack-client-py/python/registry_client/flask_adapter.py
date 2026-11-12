"""Flask request translation for a configured Registry Stack service."""

from __future__ import annotations

from typing import Any

from .machine import AdmissionError, AdmissionUnavailable
from .web import is_public
from .workload import request_budget


def install(app: Any, stack: Any, *, request_seconds: float) -> None:
    """Protect every route unless its view is explicitly decorated public."""
    from flask import g, jsonify, request

    @app.before_request
    def admit_request():
        budget = request_budget(request_seconds)
        budget.__enter__()
        g._registry_budget = budget
        view = app.view_functions.get(request.endpoint)
        if is_public(view):
            return None
        try:
            g.registry_context = stack.admit(
                {"authorization": request.headers.getlist("Authorization")}
            )
        except AdmissionError:
            response = jsonify({"code": AdmissionError.code})
            response.status_code = 401
            response.headers["Cache-Control"] = "no-store"
            return response
        except AdmissionUnavailable:
            response = jsonify({"code": AdmissionUnavailable.code})
            response.status_code = 503
            response.headers["Cache-Control"] = "no-store"
            return response
        return None

    @app.teardown_request
    def finish_request(_error):
        budget = getattr(g, "_registry_budget", None)
        if budget is not None:
            budget.__exit__(None, None, None)
