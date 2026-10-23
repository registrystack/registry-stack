"""Canonical OAuth providers, configured independently for each resource.

PrivateKeyJwt is the compatibility-identical native Rust provider. Create one
instance per resource and scope set; tokens do not grant cross-product authority.
"""
from .breg import PrivateKeyJwt

__all__ = ["PrivateKeyJwt"]
