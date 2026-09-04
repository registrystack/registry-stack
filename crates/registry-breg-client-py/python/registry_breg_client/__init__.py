"""Internal Base Registry Engine binding bundled by registry-stack-client."""

from .registry_breg_client import *  # noqa: F401,F403
from .registry_breg_client import __version__ as __version__

globals().pop("registry_breg_client", None)


def _bind_public_module() -> None:
    for value in tuple(globals().values()):
        if isinstance(value, type) and value.__module__ == "registry_breg_client":
            value.__module__ = __name__


_bind_public_module()
del _bind_public_module
