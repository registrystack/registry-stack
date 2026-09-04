"""One versioned Python entry point for Registry Stack client APIs."""

import registry_client.breg as breg
import registry_client.discovery as discovery
import registry_client.evidence as evidence
import registry_client.relay as relay

__all__ = ["breg", "discovery", "evidence", "relay"]
__version__ = "0.26.1"
