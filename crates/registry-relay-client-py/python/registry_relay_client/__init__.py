"""Synchronous Python binding for the Registry Relay V2 client."""

from .registry_relay_client import *  # noqa: F401,F403

globals().pop("registry_relay_client", None)


def _bind_public_module() -> None:
    for value in tuple(globals().values()):
        if isinstance(value, type) and value.__module__ == "registry_relay_client":
            value.__module__ = __name__


_bind_public_module()
del _bind_public_module
