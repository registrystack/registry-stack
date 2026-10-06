"""One versioned Python entry point for Registry Stack client APIs."""

import registry_client.breg as breg
import registry_client.casework as casework
import registry_client.discovery as discovery
import registry_client.evidence as evidence
import registry_client.messaging as messaging
import registry_client.scheduling as scheduling

__all__ = ["breg", "casework", "discovery", "evidence", "messaging", "scheduling"]
__version__ = "0.40.0"
