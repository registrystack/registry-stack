"""Small shared web declarations; no framework is imported by the core."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar
from urllib.parse import parse_qs


_Function = TypeVar("_Function", bound=Callable)


def public(handler: _Function) -> _Function:
    """Declare one route callable public before installing a framework adapter."""
    setattr(handler, "__registry_public__", True)
    return handler


def is_public(handler: Callable | None) -> bool:
    return bool(handler is not None and getattr(handler, "__registry_public__", False))


def form_csrf_token(
    *, content_type: str, content_length: int | None, body: bytes
) -> str:
    """Read one bounded hidden CSRF field for a top-level browser form POST."""
    if (
        content_type.split(";", 1)[0].strip().lower()
        != "application/x-www-form-urlencoded"
        or content_length is None
        or not 1 <= content_length <= 65_536
        or len(body) != content_length
    ):
        return ""
    try:
        fields = parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=64,
            errors="strict",
        )
    except (UnicodeDecodeError, ValueError):
        return ""
    tokens = fields.get("csrf_token", ())
    return tokens[0] if len(tokens) == 1 else ""
