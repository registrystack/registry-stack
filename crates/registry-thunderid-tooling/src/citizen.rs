//! Closed native configuration for citizen authorization-code delegation.
//! Requires the reviewed native federation patch and rebuilt Gate frontend.
use crate::{
    description::{IssuerDescription, MachineClient},
    local::agent_id,
    render, ToolingError,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Public registration of one governed external identity provider.
#[derive(Debug, Clone)]
pub struct Federation {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_endpoint: String,
    /// Registered outbound OAuth client. The issuer's RS256 signing key authenticates it.
    pub client_id: String,
    pub redirect_uri: String,
    pub id_token_alg: String,
    pub userinfo_alg: String,
}

/// The complete downstream authority shown at each fresh consent prompt.
#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub name: String,
    pub public_jwks: String,
    pub redirect_uri: String,
    /// Exact RFC 8707 resource, copied from the destination's registration export.
    pub resource: String,
    pub purpose: String,
    pub scope_fields: BTreeMap<String, Vec<String>>,
    /// Optional governed eligibility constant. Never copied from citizen attributes.
    pub require_active_identity: bool,
}

fn invalid() -> ToolingError {
    ToolingError::InvalidDescription { reason: "citizen federation requires exact provider URLs, a distinct code-only client, public JWKS, and bounded resource, purpose and field policy" }
}
fn bounded(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && !s.contains(['\r', '\n'])
}
fn endpoint(s: &str) -> Result<url::Url, ToolingError> {
    let u = url::Url::parse(s).map_err(|_| invalid())?;
    if u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.query().is_some()
        || !(u.scheme() == "https"
            || u.scheme() == "http"
                && matches!(
                    u.host_str(),
                    Some("localhost" | "127.0.0.1" | "host.docker.internal")
                ))
    {
        return Err(invalid());
    }
    Ok(u)
}

/// Append one fixed federation, isolated human type, JIT authentication/consent
/// flow and code-only agent registration to a rendered fresh local session.
/// No arbitrary attributes, grant types, actor mappings or protocol claims are inputs.
pub fn render(
    description: &IssuerDescription,
    federation: &Federation,
    client: &Client,
) -> Result<(), ToolingError> {
    description.validate()?;
    let native_id = agent_id(&description.session.id, &client.client_id);
    let mut check = description.clone();
    check.machine_clients.push(MachineClient {
        agent_id: native_id.clone(),
        name: client.name.clone(),
        description: client.name.clone(),
        client_id: client.client_id.clone(),
        public_jwks: client.public_jwks.clone(),
        attributes: BTreeMap::new(),
        token_attributes: vec![],
        access_token_lifetime_seconds: 300,
        token_exchange: None,
    });
    check.validate()?;
    let issuer = endpoint(&federation.issuer)?;
    for address in [
        &federation.authorization_endpoint,
        &federation.token_endpoint,
        &federation.userinfo_endpoint,
        &federation.jwks_endpoint,
    ] {
        if endpoint(address)?.origin() != issuer.origin() {
            return Err(invalid());
        }
    }
    endpoint(&federation.redirect_uri)?;
    endpoint(&client.redirect_uri)?;
    if !bounded(&federation.name, 128)
        || !bounded(&federation.client_id, 128)
        || !bounded(&client.name, 128)
        || !bounded(&client.purpose, 1024)
        || !crate::description::valid_uuid(&federation.id)
        || description
            .exchange_issuers
            .iter()
            .any(|e| e.id == federation.id || e.issuer == federation.issuer)
        || !["RS256", "PS256", "ES256"].contains(&federation.id_token_alg.as_str())
        || !["RS256", "PS256", "ES256"].contains(&federation.userinfo_alg.as_str())
        || client.scope_fields.is_empty()
        || client.scope_fields.len() > 32
    {
        return Err(invalid());
    }
    let server = description
        .resource_servers
        .iter()
        .find(|s| s.identifier == client.resource)
        .ok_or_else(invalid)?;
    let mut scopes = BTreeSet::new();
    for resource in &server.resources {
        let mut names = vec![resource.handle.as_str()];
        let mut parent = resource.parent.as_deref();
        while let Some(handle) = parent {
            if names.contains(&handle) {
                return Err(invalid());
            }
            names.push(handle);
            parent = server
                .resources
                .iter()
                .find(|r| r.handle == handle)
                .ok_or_else(invalid)?
                .parent
                .as_deref();
        }
        names.reverse();
        for action in &resource.actions {
            scopes.insert(format!("{}:{}", names.join(":"), action.handle));
        }
    }
    for (scope, fields) in &client.scope_fields {
        if !scopes.contains(scope)
            || fields.is_empty()
            || fields.len() > 64
            || fields.iter().any(|f| !bounded(f, 256))
            || fields.iter().collect::<BTreeSet<_>>().len() != fields.len()
        {
            return Err(invalid());
        }
    }
    let jwks: Value = serde_json::from_str(&client.public_jwks).map_err(|_| invalid())?;
    for key in jwks["keys"].as_array().ok_or_else(invalid)? {
        if key.get("d").is_some()
            || key.get("k").is_some()
            || !matches!(key["kty"].as_str(), Some("RSA" | "EC"))
            || !key["kid"].as_str().is_some_and(|s| bounded(s, 128))
        {
            return Err(invalid());
        }
    }
    let type_id = agent_id(
        &description.session.id,
        &format!("citizen-type:{}", federation.id),
    );
    let type_name = format!("citizen-{}", &type_id[..8]);
    let flow_id = agent_id(
        &description.session.id,
        &format!("citizen-flow:{}", client.client_id),
    );
    let root = description.state_root.join(render::RESOURCES_DIR);
    let bootstrap = description.state_root.join(render::BOOTSTRAP_DIR);
    let connection = json!({"resource_type":"connection","id":federation.id,"name":federation.name,"type":"oidc","issuer":federation.issuer,"clientId":federation.client_id,"redirectUri":federation.redirect_uri,"authorizationEndpoint":federation.authorization_endpoint,"tokenEndpoint":federation.token_endpoint,"userInfoEndpoint":federation.userinfo_endpoint,"jwksEndpoint":federation.jwks_endpoint,"tokenEndpointAuthMethod":"private_key_jwt","idTokenSigningAlg":federation.id_token_alg,"userInfoSigningAlg":federation.userinfo_alg,"requiredClaims":["person_reference"],"scopes":["openid"],"prompt":"login","tokenExchangeEnabled":false,"idJagEnabled":false,"attributeConfiguration":{"user_type_resolution":{"default":type_name},"user_type_attribute_mappings":[{"user_type":type_name,"attributes":[{"external_attribute":"sub","local_attribute":"sub"},{"external_attribute":"person_reference","local_attribute":"person_reference"}]}]}});
    let user_type = json!({"resource_type":"user_type","id":type_id,"category":"user","name":type_name,"ouHandle":description.organization_unit.handle,"allowSelfRegistration":true,"schema":{"sub":{"type":"string","required":true},"registry_federation_issuer":{"type":"string","required":true},"person_reference":{"type":"string","required":true}}});
    let consent_input = json!({"ref":"consent_input","identifier":"consent_decisions","type":"CONSENT_INPUT","required":true});
    let flow = json!({"resource_type":"flow","id":flow_id,"name":format!("{} citizen consent",client.name),"handle":format!("citizen-{}",&flow_id[..8]),"flowType":"AUTHENTICATION","nodes":[
      {"id":"start","type":"START","onSuccess":"federation"},
      {"id":"federation","type":"TASK_EXECUTION","properties":{"idpId":federation.id,"allowAuthenticationWithoutLocalUser":true},"executor":{"name":"OIDCAuthExecutor"},"onSuccess":"provision"},
      {"id":"provision","type":"TASK_EXECUTION","condition":{"key":"{{ctx(userEligibleForProvisioning)}}","value":"true","onSkip":"consent"},"executor":{"name":"ProvisioningExecutor"},"onSuccess":"consent"},
      {"id":"consent","type":"TASK_EXECUTION","executor":{"name":"ConsentExecutor"},"onSuccess":"assert","onIncomplete":"prompt"},
      {"id":"prompt","type":"PROMPT","meta":{"components":[{"type":"TEXT","id":"heading","label":format!("{} requests your permission",client.name),"variant":"HEADING_1"},{"type":"BLOCK","id":"consent_block","components":[{"id":"consent_input","ref":"consent_decisions","type":"CONSENT_INPUT","required":true},{"type":"ACTION","id":"consent_action_deny","label":"Decline this request","variant":"SECONDARY","eventType":"SUBMIT"},{"type":"ACTION","id":"consent_action_allow","label":"Allow","variant":"PRIMARY","eventType":"SUBMIT"}]}]},"prompts":[{"inputs":[consent_input],"action":{"ref":"consent_action_allow","nextNode":"consent"}},{"inputs":[consent_input],"action":{"ref":"consent_action_deny","nextNode":"consent"}}]},
      {"id":"assert","type":"TASK_EXECUTION","executor":{"name":"AuthAssertExecutor"},"onSuccess":"end"},{"id":"end","type":"END"}]});
    let mut policy = json!({"purpose":client.purpose,"resource":client.resource,"scopeFields":client.scope_fields,"subjectAttribute":"person_reference"});
    if client.require_active_identity {
        policy["identityStatus"] = json!("active");
    }
    let agent = json!({"resource_type":"agent","id":native_id,"type":"default","ouHandle":description.organization_unit.handle,"name":client.name,"authFlowId":flow_id,"allowedUserTypes":[type_name],"assertion":{"validityPeriod":300,"userAttributes":["person_reference"]},"loginConsent":{"validityPeriod":300,"delegation":policy},"inboundAuthConfig":[{"type":"oauth2","config":{"clientId":client.client_id,"grantTypes":["authorization_code"],"responseTypes":["code"],"redirectUris":[client.redirect_uri],"pkceRequired":true,"publicClient":false,"tokenEndpointAuthMethod":"private_key_jwt","certificate":{"type":"JWKS","value":client.public_jwks},"token":{"accessToken":{"userConfig":{"validityPeriod":300,"attributes":["person_reference"]}}}}}]});
    for (path, doc) in [
        (
            root.join("connections")
                .join(format!("{}.yaml", federation.id)),
            connection,
        ),
        (
            bootstrap.join("user-types").join(format!("{type_id}.yaml")),
            user_type,
        ),
        (
            bootstrap.join("flows").join(format!("{flow_id}.yaml")),
            flow,
        ),
        (
            bootstrap.join("agents").join(format!("{native_id}.yaml")),
            agent,
        ),
    ] {
        render::write_owner_only(
            &path,
            serde_norway::to_string(&doc)
                .map_err(|_| invalid())?
                .as_bytes(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn citizen_configuration_rejects_authority_and_transport_expansion_before_writing() {
        let description = crate::testing::synthetic_description();
        let mut provider = Federation {
            id: "0197aaaa-0000-7000-8000-0000000000d9".into(),
            name: "Synthetic provider".into(),
            issuer: "https://provider.example".into(),
            authorization_endpoint: "https://provider.example/authorize".into(),
            token_endpoint: "https://provider.example/token".into(),
            userinfo_endpoint: "https://provider.example/userinfo".into(),
            jwks_endpoint: "https://provider.example/jwks".into(),
            client_id: "outbound".into(),
            redirect_uri: "http://127.0.0.1:8090/gate/signin".into(),
            id_token_alg: "PS256".into(),
            userinfo_alg: "PS256".into(),
        };
        let client = Client {
            client_id: "citizen".into(),
            name: "Citizen agent".into(),
            public_jwks: description.machine_clients[0].public_jwks.clone(),
            redirect_uri: "https://agent.example/callback".into(),
            resource: description.resource_servers[0].identifier.clone(),
            purpose: "Status lookup".into(),
            scope_fields: BTreeMap::from([("unregistered:scope".into(), vec!["status".into()])]),
            require_active_identity: true,
        };
        assert!(render(&description, &provider, &client).is_err());
        provider.token_endpoint = "https://other.example/token".into();
        assert!(render(&description, &provider, &client).is_err());
        provider.token_endpoint = "https://provider.example/token".into();
        provider.userinfo_alg = "none".into();
        assert!(render(&description, &provider, &client).is_err());
    }
}
