"""Synchronous Python binding for the Registry Discovery client."""

from .registry_discovery_client import *  # noqa: F401,F403

globals().pop("registry_discovery_client", None)
