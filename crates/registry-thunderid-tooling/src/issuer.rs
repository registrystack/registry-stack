//! What an owning CLI reads back about the issuer it now has.

use crate::description::IssuerDescription;

/// The public, non-secret projection of one running session's issuer: the
/// endpoints a client needs, the image pin that serves them, and the public
/// registration information for each client the description stated. No
/// private key, secret, or token is ever part of this structure.
#[derive(Debug, Clone)]
pub struct IssuerEndpoints {
    pub issuer: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub image: String,
    pub version: String,
    pub public_clients: Vec<PublicClient>,
}

#[derive(Debug, Clone)]
pub struct PublicClient {
    pub client_id: String,
    /// The RFC 8707 resource indicators this client may name, derived from
    /// the roles it was assigned. Informational for the owning CLI; the
    /// issuer and the resource servers enforce the real bounds.
    pub resources: Vec<String>,
}

impl IssuerEndpoints {
    /// Derive the endpoints from a validated description and the pin. The
    /// issuer URL is fixed for the session's life and never switches host
    /// spellings between restarts.
    pub fn from_description(
        description: &IssuerDescription,
        pin: &crate::version::ThunderIdPin,
    ) -> Result<Self, crate::ToolingError> {
        description.validate()?;
        let issuer = format!("http://127.0.0.1:{}", description.port);
        Ok(Self {
            token_endpoint: format!("{issuer}/oauth2/token"),
            jwks_uri: format!("{issuer}/oauth2/jwks"),
            issuer,
            image: pin.image.clone(),
            version: pin.version.clone(),
            public_clients: description
                .machine_clients
                .iter()
                .map(|client| PublicClient {
                    client_id: client.client_id.clone(),
                    resources: description
                        .roles
                        .iter()
                        .filter(|role| {
                            role.assigned_agents
                                .iter()
                                .any(|agent| agent == &client.agent_id)
                        })
                        .flat_map(|role| &role.permissions)
                        .filter_map(|(server_id, _)| {
                            description
                                .resource_servers
                                .iter()
                                .find(|server| &server.id == server_id)
                                .map(|server| server.identifier.clone())
                        })
                        .collect(),
                })
                .collect(),
        })
    }
}
