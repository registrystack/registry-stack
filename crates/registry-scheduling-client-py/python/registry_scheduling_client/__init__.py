"""Internal Registry Scheduling binding bundled by registry-stack-client."""

from .registry_scheduling_client import *  # noqa: F401,F403
from .registry_scheduling_client import __version__ as __version__

globals().pop("registry_scheduling_client", None)


def _bind_public_module() -> None:
    for value in tuple(globals().values()):
        if isinstance(value, type) and value.__module__ == "registry_scheduling_client":
            value.__module__ = __name__


_bind_public_module()
del _bind_public_module
