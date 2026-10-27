"""One versioned Python entry point for Registry Stack client APIs."""

import registry_client.auth as auth
import registry_client.breg as breg
import registry_client.casework as casework
import registry_client.discovery as discovery
import registry_client.evidence as evidence
import registry_client.messaging as messaging
import registry_client.scheduling as scheduling
import registry_client.render as render
import registry_client.coordinator as coordinator

__all__ = ["auth", "breg", "casework", "discovery", "evidence", "messaging", "scheduling", "render", "coordinator"]
__version__ = "0.45.0"
