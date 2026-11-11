// SPDX-License-Identifier: Apache-2.0
//! Run-local bindings between BReg and Casework.
//!
//! The token endpoint exists only for one development run. It accepts the two
//! machine identities the plan explicitly binds, verifies their private-key
//! JWT assertions, and mints the same bounded product token a named test person
//! would receive. Keys, tokens, and assertion identifiers never enter reports
//! or logs.

use anyhow::{ensure, Context, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use registry_platform_crypto::{
    generate_private_jwk,
    jws::{parse_compact_jws, JwsLimits},
    parse_json_strict, GeneratedKeyAlgorithm, PrivateJwk, PublicJwk, SigningAlgorithm,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, TcpListener},
    path::Path,
    sync::{Arc, Mutex, Weak},
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

use super::{
    clock,
    issuer::Issuer,
    plan::{self, Plan, Product, TestPerson},
    write_private, RunInput,
};

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const FORM_LIMIT: usize = 16 * 1024;
const ASSERTION_LIMIT: usize = 12 * 1024;
const ASSERTION_LIFETIME_SECONDS: u64 = 300;
const TOKEN_LIFETIME_SECONDS: u64 = 300;
/// How long stop lets the token endpoint finish requests already in progress.
const TOKEN_SERVER_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const CLOCK_LEEWAY_SECONDS: u64 = 5;
const MAXIMUM_REPLAY_ENTRIES: usize = 256;

/// Run-local connections between BReg and Casework. Configuring either one requires both products, with BReg listed before Casework.
#[derive(Default, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Bindings {
    /// Connects BReg to Casework as a review authority. BReg authenticates to Casework as a machine identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) breg_review_authority: Option<BregReviewAuthority>,
    /// Connects Casework to BReg as a context provider. Casework authenticates to BReg as a machine identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) casework_context_provider: Option<CaseworkContextProvider>,
}

/// A BReg review authority that the run connects to Casework.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct BregReviewAuthority {
    /// Local identifier of the review authority.
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub(super) id: String,
    /// Local identifier of the review producer.
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub(super) producer: String,
    /// Name of the test person, in `people`, whose Casework grant BReg uses to authenticate. That grant needs at least one scope.
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub(super) identity: String,
}

/// A Casework context provider that the run connects to BReg.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct CaseworkContextProvider {
    /// Local identifier of the context provider.
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub(super) id: String,
    /// Name of the test person, in `people`, whose BReg grant Casework uses to authenticate. That grant needs at least one scope.
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub(super) identity: String,
    /// Local identifier of the BReg action that the provider pairs with.
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub(super) action: String,
}

impl Bindings {
    pub(super) fn validate(&self, plan: &Plan) -> plan::SemanticResult<()> {
        if self.breg_review_authority.is_none() && self.casework_context_provider.is_none() {
            return Ok(());
        }
        let breg = product_position(plan, Product::Breg);
        let casework = product_position(plan, Product::Casework);
        plan::require(
            breg.is_some() && casework.is_some(),
            "/bindings",
            "Run-local bindings require both BReg and Casework products.",
            "Add both products to products, or remove bindings.",
        )?;
        plan::require(
            breg < casework,
            "/products",
            "Products must place BReg before Casework when bindings are configured.",
            "Move the BReg product before the Casework product.",
        )?;

        if let Some(binding) = &self.breg_review_authority {
            plan::require(
                plan::identifier(&binding.id),
                "/bindings/bregReviewAuthority/id",
                "The BReg review authority ID must be a local identifier.",
                "Set id to a lowercase local identifier of at most 64 characters.",
            )?;
            plan::require(
                plan::identifier(&binding.producer),
                "/bindings/bregReviewAuthority/producer",
                "The BReg review producer must be a local identifier.",
                "Set producer to a lowercase local identifier of at most 64 characters.",
            )?;
            require_machine_person(
                plan,
                &binding.identity,
                Product::Casework,
                "/bindings/bregReviewAuthority/identity",
            )?;
        }
        if let Some(binding) = &self.casework_context_provider {
            plan::require(
                plan::identifier(&binding.id),
                "/bindings/caseworkContextProvider/id",
                "The Casework context provider ID must be a local identifier.",
                "Set id to a lowercase local identifier of at most 64 characters.",
            )?;
            plan::require(
                plan::identifier(&binding.action),
                "/bindings/caseworkContextProvider/action",
                "The Casework context provider action must be a local identifier.",
                "Set action to a lowercase local identifier of at most 64 characters.",
            )?;
            require_machine_person(
                plan,
                &binding.identity,
                Product::Breg,
                "/bindings/caseworkContextProvider/identity",
            )?;
        }
        Ok(())
    }
}

fn product_position(plan: &Plan, product: Product) -> Option<usize> {
    plan.products
        .iter()
        .position(|entry| entry.product == product)
}

fn require_machine_person<'a>(
    plan: &'a Plan,
    alias: &str,
    product: Product,
    field: &str,
) -> plan::SemanticResult<&'a TestPerson> {
    plan::require(
        plan::identifier(alias),
        field,
        "The binding identity must be a test person alias.",
        "Set identity to a lowercase local identifier naming a test person.",
    )?;
    plan::require(
        plan.people.contains_key(alias),
        field,
        "The binding identity does not name a test person.",
        "Set identity to the alias of a test person in people.",
    )?;
    let person = &plan.people[alias];
    plan::require(
        person.grants.contains_key(&product),
        field,
        format!(
            "The binding identity must name a person with a {} grant.",
            product.name()
        ),
        format!(
            "Add a {} grant to the named test person or choose another identity.",
            product.name()
        ),
    )?;
    Ok(person)
}

struct TokenServer {
    endpoint: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Drop for TokenServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

const BREG_REVIEW_CLIENT: &str = "breg-review-client";
const CASEWORK_CONTEXT_CLIENT: &str = "casework-context-client";

#[derive(Default)]
pub(super) struct RuntimeBindings {
    server: Option<TokenServer>,
    input: Option<Arc<RunInput>>,
    origins: BTreeMap<Product, String>,
    // Kept outside the server state so Issuer's Tokio runtime is dropped on
    // the supervisor thread, never from inside the token server's runtime.
    _issuer: Option<Arc<Issuer>>,
}

impl RuntimeBindings {
    pub(super) fn prepare(
        root: &Path,
        input: Arc<RunInput>,
        issuer: Arc<Issuer>,
        origins: &BTreeMap<Product, String>,
    ) -> Result<Self> {
        let bindings = &input.plan.bindings;
        if bindings.breg_review_authority.is_none() && bindings.casework_context_provider.is_none()
        {
            return Ok(Self::default());
        }
        bindings.validate(&input.plan)?;
        ensure!(
            origins.contains_key(&Product::Breg) && origins.contains_key(&Product::Casework),
            "run-local bindings require reserved BReg and Casework origins"
        );

        let mut clients = Vec::new();
        if let Some(binding) = &bindings.breg_review_authority {
            prepare_binding(
                root,
                &input,
                &binding.identity,
                Product::Casework,
                BREG_REVIEW_CLIENT,
                &mut clients,
            )?;
        }
        if let Some(binding) = &bindings.casework_context_provider {
            prepare_binding(
                root,
                &input,
                &binding.identity,
                Product::Breg,
                CASEWORK_CONTEXT_CLIENT,
                &mut clients,
            )?;
        }
        let server = start_token_server(input.clone(), issuer.clone(), clients)?;
        Ok(Self {
            server: Some(server),
            input: Some(input),
            origins: origins.clone(),
            _issuer: Some(issuer),
        })
    }

    pub(super) fn configure(&self, product: Product, config: &mut Value) {
        let Some(input) = self.input.as_ref() else {
            return;
        };
        let endpoint = &self
            .server
            .as_ref()
            .expect("prepared token server")
            .endpoint;
        render(&input.plan, product, &self.origins, endpoint, config);
    }
}

/// Writes the binding the plan configures for `product` into its runtime
/// configuration. Only the token endpoint and the product origins belong to
/// the run; every other value comes from the plan.
fn render(
    plan: &Plan,
    product: Product,
    origins: &BTreeMap<Product, String>,
    token_endpoint: &str,
    config: &mut Value,
) {
    match product {
        Product::Breg => {
            let Some(binding) = plan.bindings.breg_review_authority.as_ref() else {
                return;
            };
            let grant = &plan.people[&binding.identity].grants[&Product::Casework];
            let (client_id_ref, client_assertion_key_ref) = client_refs(BREG_REVIEW_CLIENT);
            config["reviewAuthorities"][binding.id.as_str()] = json!({
                "endpoint": origins[&Product::Casework],
                "profile": grant.profile,
                "privateKeyJwt": {
                    "tokenEndpoint": token_endpoint,
                    "clientIdRef": client_id_ref,
                    "clientAssertionKeyRef": client_assertion_key_ref,
                    "assertionAudience": plan.issuer,
                    "resource": plan.product(Product::Casework).audience,
                    "scopes": grant.scopes,
                },
                "producerId": binding.producer,
                "recoveryDays": 7,
            });
        }
        Product::Casework => {
            let Some(binding) = plan.bindings.casework_context_provider.as_ref() else {
                return;
            };
            let grant = &plan.people[&binding.identity].grants[&Product::Breg];
            let (client_id_ref, client_assertion_key_ref) = client_refs(CASEWORK_CONTEXT_CLIENT);
            config["contextProviders"][binding.id.as_str()] = json!({
                "baseUrl": origins[&Product::Breg],
                "statusProfile": grant.profile,
                "tokenEndpoint": token_endpoint,
                "clientAssertionAudience": plan.issuer,
                "resource": plan.product(Product::Breg).audience,
                "scopes": grant.scopes,
                "clientIdRef": client_id_ref,
                "clientAssertionKeyRef": client_assertion_key_ref,
            });
        }
    }
}

/// The secret references of the machine client `filename` names.
fn client_refs(filename: &str) -> (String, String) {
    (
        format!("secret:file/{filename}-id"),
        format!("secret:file/{filename}-key"),
    )
}

/// Origin and token endpoint `check` renders with. Nothing listens there: the
/// product readers refuse a binding's shape, not the address it names.
const CHECK_ORIGIN: &str = "http://127.0.0.1:1";
const CHECK_TOKEN_ENDPOINT: &str = "http://127.0.0.1:1/oauth2/token";

/// Renders each binding the plan configures exactly as `start` writes it and
/// lets the owning product's reader refuse what it would refuse at startup,
/// before anything is provisioned. A refusal names the plan field that
/// produced the value, not the generated fragment.
pub(super) fn check_with_product_readers(plan: &Plan) -> plan::SemanticResult<()> {
    let origins = BTreeMap::from([
        (Product::Breg, CHECK_ORIGIN.to_owned()),
        (Product::Casework, CHECK_ORIGIN.to_owned()),
    ]);
    if let Some(binding) = &plan.bindings.breg_review_authority {
        let mut config = json!({});
        render(
            plan,
            Product::Breg,
            &origins,
            CHECK_TOKEN_ENDPOINT,
            &mut config,
        );
        let grant = grant_field(&binding.identity, Product::Casework);
        let audience = audience_field(plan, Product::Casework);
        require_reader_accepts(
            "BReg",
            "/bindings/bregReviewAuthority",
            &config["reviewAuthorities"][binding.id.as_str()],
            &[
                Source::new(
                    "/profile",
                    &format!("{grant}/profile"),
                    json!("placeholder"),
                ),
                Source::new(
                    "/privateKeyJwt/assertionAudience",
                    "/issuer",
                    json!(STAND_IN_URI),
                ),
                Source::new("/privateKeyJwt/resource", &audience, json!(STAND_IN_URI)),
                Source::new(
                    "/privateKeyJwt/scopes",
                    &format!("{grant}/scopes"),
                    json!(["placeholder"]),
                ),
                Source::new(
                    "/producerId",
                    "/bindings/bregReviewAuthority/producer",
                    json!("placeholder"),
                ),
            ],
            |fragment| {
                registry_breg::runtime_config::check_review_authority(&binding.id, fragment)
                    .map_err(|error| error.to_string())
            },
        )?;
    }
    if let Some(binding) = &plan.bindings.casework_context_provider {
        let mut config = json!({});
        render(
            plan,
            Product::Casework,
            &origins,
            CHECK_TOKEN_ENDPOINT,
            &mut config,
        );
        let grant = grant_field(&binding.identity, Product::Breg);
        let audience = audience_field(plan, Product::Breg);
        require_reader_accepts(
            "Casework",
            "/bindings/caseworkContextProvider",
            &config["contextProviders"][binding.id.as_str()],
            &[
                Source::new(
                    "/statusProfile",
                    &format!("{grant}/profile"),
                    json!("placeholder"),
                ),
                Source::new("/clientAssertionAudience", "/issuer", json!(STAND_IN_URI)),
                Source::new("/resource", &audience, json!(STAND_IN_URI)),
                Source::new(
                    "/scopes",
                    &format!("{grant}/scopes"),
                    json!(["placeholder"]),
                ),
            ],
            |fragment| {
                serde_json::from_value::<registry_casework_breg::BregBinding>(fragment.clone())
                    .map_err(|_| {
                        "the configuration does not have the shape the reader expects".to_owned()
                    })?
                    .check_offline()
                    .map_err(|error| error.to_string())
            },
        )?;
    }
    Ok(())
}

const STAND_IN_URI: &str = "urn:example:stand-in";

/// One member of a rendered fragment and the plan field that produced it,
/// with a value every reader accepts for that member.
struct Source {
    member: &'static str,
    field: String,
    stand_in: Value,
}

impl Source {
    fn new(member: &'static str, field: &str, stand_in: Value) -> Self {
        Self {
            member,
            field: field.to_owned(),
            stand_in,
        }
    }
}

fn grant_field(alias: &str, product: Product) -> String {
    format!(
        "/people/{}/grants/{}",
        registry_platform_yaml::escape_pointer_segment(alias),
        product.name()
    )
}

fn audience_field(plan: &Plan, product: Product) -> String {
    let index = product_position(plan, product).expect("validated product");
    format!("/products/{index}/audience")
}

/// Refuses when `reader` refuses `fragment`. The readers state a rule without
/// saying which member broke it, so the refusal lands on the plan field of the
/// one member whose replacement by a stand-in makes the reader accept. When no
/// single member explains it, the refusal lands on the binding.
fn require_reader_accepts(
    product: &str,
    binding_field: &str,
    fragment: &Value,
    sources: &[Source],
    reader: impl Fn(&Value) -> Result<(), String>,
) -> plan::SemanticResult<()> {
    let Err(refusal) = reader(fragment) else {
        return Ok(());
    };
    let field = sources
        .iter()
        .find(|source| {
            let mut probe = fragment.clone();
            probe
                .pointer_mut(source.member)
                .map(|member| *member = source.stand_in.clone())
                .is_some()
                && reader(&probe).is_ok()
        })
        .map_or(binding_field, |source| source.field.as_str());
    plan::refuse(
        field,
        &format!("{product} refuses the binding configuration the run writes from this value: {refusal}."),
        "Correct the value so the product accepts the configuration the run writes for this binding.",
    )
}

fn prepare_binding(
    root: &Path,
    input: &RunInput,
    person_alias: &str,
    product: Product,
    filename: &str,
    clients: &mut Vec<MachineClient>,
) -> Result<()> {
    let person = require_machine_person(&input.plan, person_alias, product, "/bindings")?;
    let grant = &person.grants[&product];
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Es256)?;
    let public_key = key.public();
    let encoded = encode_private_jwk(&key)?;
    write_private(&root.join(format!("{filename}-key")), &encoded)?;
    write_private(
        &root.join(format!("{filename}-id")),
        person.client.as_bytes(),
    )?;
    clients.push(MachineClient {
        client_id: person.client.clone(),
        person: person_alias.to_owned(),
        product,
        public_key,
        resource: input.plan.product(product).audience.clone(),
        scope: grant.scopes.join(" "),
    });
    Ok(())
}

#[derive(Serialize)]
struct PrivateJwkDocument<'a> {
    kty: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crv: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    q: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dp: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dq: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qi: Option<&'a str>,
}

pub(super) fn encode_private_jwk(key: &PrivateJwk) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(serde_json::to_vec(&PrivateJwkDocument {
        kty: &key.kty,
        kid: key.kid.as_deref(),
        alg: key.alg.as_deref(),
        crv: key.crv.as_deref(),
        d: key.d.as_deref(),
        x: key.x.as_deref(),
        y: key.y.as_deref(),
        n: key.n.as_deref(),
        e: key.e.as_deref(),
        p: key.p.as_deref(),
        q: key.q.as_deref(),
        dp: key.dp.as_deref(),
        dq: key.dq.as_deref(),
        qi: key.qi.as_deref(),
    })?))
}

struct MachineClient {
    client_id: String,
    person: String,
    product: Product,
    public_key: PublicJwk,
    resource: String,
    scope: String,
}

struct TokenState {
    input: Arc<RunInput>,
    issuer: Weak<Issuer>,
    clients: Vec<MachineClient>,
    audience: String,
    replay: Mutex<BTreeMap<String, u64>>,
}

fn start_token_server(
    input: Arc<RunInput>,
    issuer: Arc<Issuer>,
    clients: Vec<MachineClient>,
) -> Result<TokenServer> {
    ensure!(!clients.is_empty(), "a binding token client is required");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .context("cannot bind the run-local token endpoint")?;
    listener.set_nonblocking(true)?;
    let origin = format!("http://{}", listener.local_addr()?);
    let endpoint = format!("{origin}/oauth2/token");
    let state = Arc::new(TokenState {
        audience: input.plan.issuer.clone(),
        input,
        issuer: Arc::downgrade(&issuer),
        clients,
        replay: Mutex::new(BTreeMap::new()),
    });
    let app = Router::new()
        .route("/oauth2/token", post(token))
        .layer(DefaultBodyLimit::max(FORM_LIMIT))
        .with_state(state);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server_thread = thread::Builder::new()
        .name("rstack-dev-token".to_owned())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
                    return;
                };
                let (drain_tx, drain_rx) = tokio::sync::oneshot::channel::<()>();
                let server = async move {
                    let _ = axum::serve(listener, app)
                        .with_graceful_shutdown(async move {
                            let _ = drain_rx.await;
                        })
                        .await;
                };
                tokio::pin!(server);
                tokio::select! {
                    () = &mut server => return,
                    _ = shutdown_rx => {}
                }
                let _ = drain_tx.send(());
                // A client that never finishes its request must not hold up
                // stop; whatever is still open after the grace is dropped.
                let _ = tokio::time::timeout(TOKEN_SERVER_SHUTDOWN_GRACE, server).await;
            });
            runtime.shutdown_timeout(TOKEN_SERVER_SHUTDOWN_GRACE);
        })?;
    Ok(TokenServer {
        endpoint,
        shutdown: Some(shutdown_tx),
        thread: Some(server_thread),
    })
}

async fn token(State(state): State<Arc<TokenState>>, headers: HeaderMap, body: Bytes) -> Response {
    match tokio::time::timeout(Duration::from_secs(5), issue_token(state, headers, body)).await {
        Ok(response) => response,
        Err(_) => oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    }
}

async fn issue_token(state: Arc<TokenState>, headers: HeaderMap, body: Bytes) -> Response {
    if !headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim() == "application/x-www-form-urlencoded")
        })
        || body.len() > FORM_LIMIT
        || !body.is_ascii()
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Some(form) = parse_form(&body) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if form.get("grant_type").map(String::as_str) != Some("client_credentials") {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    if form.get("client_assertion_type").map(String::as_str) != Some(ASSERTION_TYPE) {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let (Some(client_id), Some(assertion), Some(resource), Some(scope)) = (
        form.get("client_id"),
        form.get("client_assertion"),
        form.get("resource"),
        form.get("scope"),
    ) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if assertion.len() > ASSERTION_LIMIT {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }

    let limits = JwsLimits {
        max_compact_bytes: ASSERTION_LIMIT,
        max_header_bytes: 1024,
        max_payload_bytes: 2048,
    };
    let Ok(parsed) = parse_compact_jws(assertion, &limits) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let Some(kid) = parsed.header().get("kid").and_then(Value::as_str) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let Some(client) = state.clients.iter().find(|candidate| {
        candidate.client_id == client_id.as_str()
            && candidate.public_key.kid.as_deref() == Some(kid)
            && candidate.resource == resource.as_str()
            && candidate.scope == scope.as_str()
    }) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    if parsed.header().len() != 3
        || parsed.header().get("typ").and_then(Value::as_str) != Some("JWT")
        || parsed.header().get("alg").and_then(Value::as_str) != Some("ES256")
    {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let Ok(payload) = parsed.verify(&client.public_key, &[SigningAlgorithm::Es256]) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let Ok(payload) = parse_json_strict(payload) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let Ok(claims) = serde_json::from_value::<AssertionClaims>(payload) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let Ok(now) = clock() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    if claims.iss != client.client_id
        || claims.sub != client.client_id
        || claims.aud != state.audience
        || claims.jti.is_empty()
        || claims.jti.len() > 128
        || claims
            .jti
            .chars()
            .any(|value| value.is_control() || value.is_whitespace())
        || claims.iat > now.saturating_add(CLOCK_LEEWAY_SECONDS)
        || claims.exp <= now
        || !(1..=ASSERTION_LIFETIME_SECONDS).contains(&claims.exp.saturating_sub(claims.iat))
    {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    {
        let Ok(mut replay) = state.replay.lock() else {
            return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        };
        replay.retain(|_, expiry| *expiry > now);
        if replay.contains_key(&claims.jti) || replay.len() >= MAXIMUM_REPLAY_ENTRIES {
            return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
        }
        replay.insert(claims.jti, claims.exp);
    }
    let Some(person) = state.input.plan.people.get(&client.person) else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let Some(issuer) = state.issuer.upgrade() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let Ok(access_token) = issuer
        .sign(
            &state.input,
            person,
            client.product,
            now.saturating_add(TOKEN_LIFETIME_SECONDS),
        )
        .await
    else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({
            "access_token": &*access_token,
            "token_type": "Bearer",
            "expires_in": TOKEN_LIFETIME_SECONDS,
        })),
    )
        .into_response()
}

fn parse_form(body: &[u8]) -> Option<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    let allowed = BTreeSet::from([
        "grant_type",
        "client_id",
        "client_assertion_type",
        "client_assertion",
        "resource",
        "scope",
    ]);
    for (name, value) in url::form_urlencoded::parse(body) {
        if !allowed.contains(name.as_ref())
            || values
                .insert(name.into_owned(), value.into_owned())
                .is_some()
        {
            return None;
        }
    }
    (values.len() == allowed.len()).then_some(values)
}

fn oauth_error(status: StatusCode, error: &'static str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"error": error})),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
    jti: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_dev::{
        plan::{Grant, Journey, ProductPlan},
        BregAuthority,
    };
    use registry_platform_crypto::{jws::sign_compact_jws, LocalJwkSigner, PrivateJwk};
    use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider};
    use serde_json::{Map, Value};
    use std::{collections::BTreeMap, path::PathBuf};

    fn grant(profile: &str, scope: &str) -> Grant {
        Grant {
            profile: profile.to_owned(),
            scopes: vec![scope.to_owned()],
            claims: Map::new(),
        }
    }

    fn plan() -> Plan {
        Plan {
            issuer: "https://identity.example.test/realms/dev".to_owned(),
            products: vec![
                ProductPlan {
                    product: Product::Breg,
                    project: PathBuf::from("registry"),
                    audience: "urn:dev:breg".to_owned(),
                },
                ProductPlan {
                    product: Product::Casework,
                    project: PathBuf::from("casework"),
                    audience: "urn:dev:casework".to_owned(),
                },
            ],
            people: BTreeMap::from([
                (
                    "producer".to_owned(),
                    TestPerson {
                        subject: "review-producer".to_owned(),
                        client: "review-producer-client".to_owned(),
                        grants: BTreeMap::from([(
                            Product::Casework,
                            grant("producer", "casework:review:produce"),
                        )]),
                        casework_context: false,
                    },
                ),
                (
                    "context-reader".to_owned(),
                    TestPerson {
                        subject: "context-reader".to_owned(),
                        client: "context-reader-client".to_owned(),
                        grants: BTreeMap::from([(
                            Product::Breg,
                            grant("casework-review-status", "registry:proposal:review-status"),
                        )]),
                        casework_context: false,
                    },
                ),
            ]),
            bindings: Bindings {
                breg_review_authority: Some(BregReviewAuthority {
                    id: "casework".to_owned(),
                    producer: "registry".to_owned(),
                    identity: "producer".to_owned(),
                }),
                casework_context_provider: Some(CaseworkContextProvider {
                    id: "registry".to_owned(),
                    identity: "context-reader".to_owned(),
                    action: "reviewed-change".to_owned(),
                }),
            },
            journey: Journey {
                id: "binding".to_owned(),
                steps: Vec::new(),
            },
            schema_test_people: BTreeMap::new(),
        }
    }

    fn input(plan: Plan) -> RunInput {
        RunInput {
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
            project: PathBuf::from("/tmp/project"),
            plan,
            ttl_seconds: 300,
            schema_people: Vec::new(),
            breg_authority: Some(BregAuthority {
                principal: "sub".to_owned(),
                purpose: false,
                requires_postgis: false,
                named_clients: BTreeSet::new(),
            }),
            casework_principals: BTreeMap::from([("producer".to_owned(), "sub".to_owned())]),
            binaries: BTreeMap::new(),
        }
    }

    #[test]
    fn validation_refuses_missing_grants_and_wrong_product_order() {
        let mut value = plan();
        value.products.reverse();
        let error = value.bindings.validate(&value).unwrap_err().to_string();
        assert!(error.contains("/products"), "{error}");

        let mut value = plan();
        value.people.get_mut("producer").unwrap().grants.clear();
        let error = value.bindings.validate(&value).unwrap_err().to_string();
        assert!(
            error.contains("/bindings/bregReviewAuthority/identity"),
            "{error}"
        );
    }

    #[test]
    fn check_accepts_a_plan_both_product_readers_accept() {
        check_with_product_readers(&plan()).unwrap();
    }

    #[test]
    fn check_refuses_a_bound_audience_that_is_not_a_resource_uri() {
        let mut value = plan();
        value.products[1].audience = "review".to_owned();
        let error = check_with_product_readers(&value).unwrap_err().to_string();
        assert!(error.contains("/products/1/audience"), "{error}");
        assert!(error.contains("BReg refuses"), "{error}");

        let mut value = plan();
        value.products[0].audience = "registry".to_owned();
        let error = check_with_product_readers(&value).unwrap_err().to_string();
        assert!(error.contains("/products/0/audience"), "{error}");
        assert!(error.contains("Casework refuses"), "{error}");

        let mut value = plan();
        value.bindings.casework_context_provider = None;
        value.products[0].audience = "registry".to_owned();
        check_with_product_readers(&value).unwrap();
    }

    #[test]
    fn check_refuses_bound_scopes_the_products_would_not_request() {
        // Both products request a binding's scopes through the shared OAuth
        // client, which refuses this list before the run could start them.
        let too_long = (0..17)
            .map(|index| format!("{index:02}{}", "s".repeat(254)))
            .collect::<Vec<_>>();
        let mut value = plan();
        value
            .people
            .get_mut("producer")
            .unwrap()
            .grants
            .get_mut(&Product::Casework)
            .unwrap()
            .scopes
            .clone_from(&too_long);
        let error = check_with_product_readers(&value).unwrap_err().to_string();
        assert!(
            error.contains("/people/producer/grants/casework/scopes"),
            "{error}"
        );

        let mut value = plan();
        value
            .people
            .get_mut("context-reader")
            .unwrap()
            .grants
            .get_mut(&Product::Breg)
            .unwrap()
            .scopes = vec!["registry:\"quoted\"".to_owned()];
        let error = check_with_product_readers(&value).unwrap_err().to_string();
        assert!(
            error.contains("/people/context-reader/grants/breg/scopes"),
            "{error}"
        );

        // A person no binding names keeps the plan's own scope rule.
        let mut value = plan();
        value.bindings.casework_context_provider = None;
        value
            .people
            .get_mut("context-reader")
            .unwrap()
            .grants
            .get_mut(&Product::Breg)
            .unwrap()
            .scopes = too_long;
        value.bindings.validate(&value).unwrap();
        check_with_product_readers(&value).unwrap();
    }

    #[test]
    fn check_refuses_other_binding_values_at_the_plan_field_that_produced_them() {
        let mut value = plan();
        value.issuer = "not a uri".to_owned();
        let error = check_with_product_readers(&value).unwrap_err().to_string();
        assert!(error.contains("/issuer"), "{error}");

        // The profile grammar is a rule only the product readers state: the
        // runner restates nothing about it, so each product's reader catches
        // it and the refusal lands on the grant that produced the value.
        let mut value = plan();
        value
            .people
            .get_mut("context-reader")
            .unwrap()
            .grants
            .get_mut(&Product::Breg)
            .unwrap()
            .profile = "not a profile".to_owned();
        let error = check_with_product_readers(&value).unwrap_err().to_string();
        assert!(
            error.contains("/people/context-reader/grants/breg/profile"),
            "{error}"
        );

        let mut value = plan();
        value
            .people
            .get_mut("producer")
            .unwrap()
            .grants
            .get_mut(&Product::Casework)
            .unwrap()
            .profile = "not a profile".to_owned();
        let error = check_with_product_readers(&value).unwrap_err().to_string();
        assert!(
            error.contains("/people/producer/grants/casework/profile"),
            "{error}"
        );
    }

    #[test]
    fn stopping_the_token_server_does_not_wait_for_an_unfinished_request() {
        use std::io::Write;

        let root = tempfile::tempdir().unwrap();
        let issuer = Arc::new(Issuer::create(root.path()).unwrap());
        let origins = BTreeMap::from([
            (Product::Breg, "http://127.0.0.1:31001".to_owned()),
            (Product::Casework, "http://127.0.0.1:31002".to_owned()),
        ]);
        let runtime =
            RuntimeBindings::prepare(root.path(), Arc::new(input(plan())), issuer, &origins)
                .unwrap();
        let endpoint = runtime.server.as_ref().unwrap().endpoint.clone();
        let address = endpoint
            .trim_start_matches("http://")
            .trim_end_matches("/oauth2/token")
            .to_owned();
        let mut client = std::net::TcpStream::connect(address).unwrap();
        client
            .write_all(
                b"POST /oauth2/token HTTP/1.1\r\nHost: localhost\r\n\
                  Content-Type: application/x-www-form-urlencoded\r\n\
                  Content-Length: 100\r\n\r\ngrant_type=",
            )
            .unwrap();
        thread::sleep(Duration::from_millis(200));

        let (stopped, wait) = std::sync::mpsc::channel();
        thread::spawn(move || {
            drop(runtime);
            let _ = stopped.send(());
        });
        assert!(
            wait.recv_timeout(Duration::from_secs(10)).is_ok(),
            "the token server waited for a client that never finished its request"
        );
        drop(client);
    }

    async fn sign_assertion(
        key: &PrivateJwk,
        client: &str,
        audience: &str,
        issued_at: u64,
        jti: &str,
    ) -> String {
        let signer = LocalJwkSigner::new(key.clone()).unwrap();
        let claims = serde_json::to_vec(&json!({
            "iss": client, "sub": client, "aud": audience,
            "iat": issued_at, "exp": issued_at + 60, "jti": jti,
        }))
        .unwrap();
        sign_compact_jws(
            Map::from_iter([("typ".to_owned(), Value::String("JWT".to_owned()))]),
            &claims,
            &signer,
        )
        .await
        .unwrap()
    }

    #[test]
    fn endpoint_accepts_one_assertion_and_refuses_replay_tampering_and_wrong_resource() {
        let root = tempfile::tempdir().unwrap();
        let input = Arc::new(input(plan()));
        let issuer = Arc::new(Issuer::create(root.path()).unwrap());
        let origins = BTreeMap::from([
            (Product::Breg, "http://127.0.0.1:31001".to_owned()),
            (Product::Casework, "http://127.0.0.1:31002".to_owned()),
        ]);
        let runtime =
            RuntimeBindings::prepare(root.path(), input.clone(), issuer, &origins).unwrap();
        let endpoint = runtime.server.as_ref().unwrap().endpoint.clone();
        let encoded =
            Zeroizing::new(std::fs::read(root.path().join("casework-context-client-key")).unwrap());
        let key = PrivateJwk::parse(std::str::from_utf8(&encoded).unwrap()).unwrap();
        let now = clock().unwrap();
        let request_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let provider = PrivateKeyJwt::new(
            PrivateKeyJwtConfig::new(
                endpoint.parse().unwrap(),
                "context-reader-client",
                key.clone(),
            )
            .with_audience(input.plan.issuer.clone())
            .with_resource("urn:dev:breg")
            .with_scopes(vec!["registry:proposal:review-status".to_owned()]),
        )
        .unwrap();
        request_runtime
            .block_on(provider.bearer_token())
            .expect("the maintained private-key JWT client obtains a token");

        let assertion = request_runtime.block_on(sign_assertion(
            &key,
            "context-reader-client",
            &input.plan.issuer,
            now,
            "assertion-once",
        ));
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", "context-reader-client"),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", assertion.as_str()),
            ("resource", "urn:dev:breg"),
            ("scope", "registry:proposal:review-status"),
        ];
        let response = request_runtime
            .block_on(client.post(&endpoint).form(&form).send())
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let replay = request_runtime
            .block_on(client.post(&endpoint).form(&form).send())
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

        let mut tampered = assertion.clone().into_bytes();
        let last = tampered.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        let invalid = [
            ("grant_type", "client_credentials"),
            ("client_id", "context-reader-client"),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", tampered.as_str()),
            ("resource", "urn:dev:breg"),
            ("scope", "registry:proposal:review-status"),
        ];
        let response = request_runtime
            .block_on(client.post(&endpoint).form(&invalid).send())
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let second = request_runtime.block_on(sign_assertion(
            &key,
            "context-reader-client",
            &input.plan.issuer,
            now,
            "wrong-resource",
        ));
        let wrong = [
            ("grant_type", "client_credentials"),
            ("client_id", "context-reader-client"),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", second.as_str()),
            ("resource", "urn:dev:casework"),
            ("scope", "registry:proposal:review-status"),
        ];
        let response = request_runtime
            .block_on(client.post(&endpoint).form(&wrong).send())
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn configure_writes_native_product_bindings() {
        let root = tempfile::tempdir().unwrap();
        let input = Arc::new(input(plan()));
        let issuer = Arc::new(Issuer::create(root.path()).unwrap());
        let origins = BTreeMap::from([
            (Product::Breg, "http://127.0.0.1:31001".to_owned()),
            (Product::Casework, "http://127.0.0.1:31002".to_owned()),
        ]);
        let runtime = RuntimeBindings::prepare(root.path(), input, issuer, &origins).unwrap();
        let mut breg = json!({});
        runtime.configure(Product::Breg, &mut breg);
        assert_eq!(
            breg["reviewAuthorities"]["casework"]["endpoint"],
            "http://127.0.0.1:31002"
        );
        assert_eq!(
            breg["reviewAuthorities"]["casework"]["privateKeyJwt"]["resource"],
            "urn:dev:casework"
        );
        assert!(breg["reviewAuthorities"]["casework"]["tokenRef"].is_null());

        let mut casework = json!({});
        runtime.configure(Product::Casework, &mut casework);
        assert_eq!(
            casework["contextProviders"]["registry"]["baseUrl"],
            "http://127.0.0.1:31001"
        );
        assert_eq!(
            casework["contextProviders"]["registry"]["statusProfile"],
            "casework-review-status"
        );
    }
}
