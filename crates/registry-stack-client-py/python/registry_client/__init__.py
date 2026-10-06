"""One versioned Python entry point for Registry Stack client APIs."""

import registry_client.breg as breg
import registry_client.casework as casework
import registry_client.discovery as discovery
import registry_client.evidence as evidence
import registry_client.messaging as messaging

__all__ = ["breg", "casework", "discovery", "evidence", "messaging"]
__version__ = "0.40.0"
