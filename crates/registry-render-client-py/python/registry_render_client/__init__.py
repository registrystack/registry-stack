"""Thin Registry Render facade over its canonical Rust client."""

import json

from .registry_render_client import __version__ as __version__
from .registry_render_client import _RenderClient, validate_render_request


class RenderClientError(Exception):
    def __init__(
        self,
        kind,
        *,
        status=None,
        code=None,
        trace_id=None,
        outcome_unknown=False,
        transport_kind=None,
    ):
        super().__init__(f"Registry Render client failed ({kind})")
        self.kind, self.status, self.code, self.trace_id = kind, status, code, trace_id
        self.outcome_unknown, self.transport_kind = outcome_unknown, transport_kind


def _mapped(error, fallback="invalid-request"):
    if isinstance(error, RenderClientError):
        return error
    try:
        envelope = json.loads(str(error))
        return RenderClientError(
            envelope["kind"],
            status=envelope.get("status"),
            code=envelope.get("code"),
            trace_id=envelope.get("traceId"),
            outcome_unknown=envelope["outcomeUnknown"],
            transport_kind=envelope.get("transportKind"),
        )
    except (ValueError, KeyError, TypeError):
        return RenderClientError(fallback, outcome_unknown=fallback == "protocol")


def _json(value):
    try:
        return json.dumps(value, allow_nan=False, ensure_ascii=False)
    except (ValueError, TypeError, OverflowError):
        raise RenderClientError("invalid-request") from None


class RenderClient:
    def __init__(self, config):
        try:
            self._native = _RenderClient(_json(config))
        except (ValueError, TypeError, RuntimeError, RenderClientError) as error:
            raise _mapped(error, "configuration") from None

    def render(self, token, document_type, request):
        """Render once; token is text, a callable, or a resource token provider."""
        try:
            request = _json(request)
            validate_render_request(document_type, request)
        except (ValueError, TypeError, RuntimeError, RenderClientError) as error:
            raise _mapped(error) from None
        if callable(token):
            token = token()
        elif not isinstance(token, str):
            token = token.bearer_token()
        if not isinstance(token, str):
            raise RenderClientError("invalid-request")
        try:
            return json.loads(self._native.render(token, document_type, request))
        except (ValueError, TypeError, RuntimeError, RenderClientError) as error:
            raise _mapped(error, "protocol") from None


__all__ = ["RenderClient", "RenderClientError"]
