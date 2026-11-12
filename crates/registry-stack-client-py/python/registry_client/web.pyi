from collections.abc import Callable
from typing import ParamSpec, TypeVar

_P = ParamSpec("_P")
_R = TypeVar("_R")

def public(handler: Callable[_P, _R]) -> Callable[_P, _R]: ...
def is_public(handler: Callable | None) -> bool: ...
def form_csrf_token(
    *, content_type: str, content_length: int | None, body: bytes
) -> str: ...
