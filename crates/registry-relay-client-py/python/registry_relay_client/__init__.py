"""Synchronous Python binding for the Registry Relay V2 client."""

from .registry_relay_client import *  # noqa: F401,F403

globals().pop("registry_relay_client", None)
