"""Synchronous Python binding for the Registry Discovery client."""

from .registry_discovery_client import *  # noqa: F401,F403
from .registry_discovery_client import DiscoveryClientError as _DiscoveryClientError

globals().pop("registry_discovery_client", None)

# The native exception is implemented under an internal Rust type name and
# exported under this public name. Keep Python identity and lookup consistent.
_DiscoveryClientError.__name__ = "DiscoveryClientError"
_DiscoveryClientError.__qualname__ = "DiscoveryClientError"
del _DiscoveryClientError


def _bind_public_module() -> None:
    for value in tuple(globals().values()):
        if isinstance(value, type) and value.__module__ == "registry_discovery_client":
            value.__module__ = __name__


_bind_public_module()
del _bind_public_module
