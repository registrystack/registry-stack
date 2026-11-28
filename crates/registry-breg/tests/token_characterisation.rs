// SPDX-License-Identifier: Apache-2.0
//! Runs the token fixture corpus through BReg's real authentication path and
//! asserts each result against the `breg` column of `expected.yaml`.
//!
//! The access-token verifier profile and the authority claim mapping come from
//! a runtime file parsed by `parse_runtime_config`, as at startup. The key set
//! is the signer's static public key set. A token that authenticates is sent
//! through the authenticated router to a compiled access profile, so a profile
//! refusal is observed where a request meets it. A token the verifier refuses
//! is sent through the router too, and the check it failed is read from
//! `breg_request_refusals_total`, the counter an operator reads.

#![cfg(feature = "runtime")]

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use registry_breg::api::{
    authenticated_router, HeldReadResponse, HttpService, ReadRuntimeIdentity, ReadServiceError,
    ReadinessProbe, RecordReadRequest, RecordReadService, ServiceFuture,
};
use registry_breg::auth::{AuthenticationError, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::metrics::{metrics_app, Metrics};
use registry_breg::runtime_config::parse_runtime_config;
use registry_breg::{compile_project, parse_project_yaml, CompileProfile};
use registry_platform_oidc::{ActorKind, JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{
    Against, ClaimValue, Configuration, FixtureCase, Outcome, Stage, TokenCorpus, TokenFixture,
    TokenSigner,
};
use serde_json::{json, Value};
use tower::ServiceExt as _;
use zeroize::Zeroizing;

const ISSUER: &str = "https://issuer.example.test";
const AUDIENCE: &str = "urn:breg:test";
const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
/// The client a default configuration lists when the fixture names none, so a
/// token without a client claim meets a list that does not include it.
const LISTED_CLIENT: &str = "journey-app";
/// The scope a profile requires when the fixture carries none, outside a
/// declared-kind row.
const FALLBACK_SCOPE: &str = "records:get";

#[tokio::test]
async fn breg_token_characterisation() {
    let corpus = TokenCorpus::load().expect("the corpus loads");
    let signer = TokenSigner::new();
    let report = corpus
        .run_product_async("breg", &signer, ISSUER, AUDIENCE, observe)
        .await
        .expect("the corpus runs");
    assert!(
        report.rows.iter().any(|row| row.observed.is_some()),
        "no row ran, so the test proves nothing"
    );
    report.assert_matches();
}

/// What a configuration changes in the runtime file's `authentication.oidc`
/// block, derived from the fixture the way `expected.yaml` describes.
struct Shape {
    algorithm: &'static str,
    access_token_type: String,
    scope_claim: &'static str,
    /// Empty writes `allowedClients: unrestricted`.
    clients: Vec<String>,
    /// What the compiled access profile writes in `requiredScopes`.
    required_scopes: String,
    /// The kind the operator declares for a `recipe-declared-kind` row,
    /// written per client when the token names one.
    declared: Option<DeclaredKind>,
}

/// An actor kind the runtime file declares, and the client it is declared
/// for: `None` declares it for every token of the issuer.
struct DeclaredKind {
    client: Option<String>,
    kind: &'static str,
}

impl Shape {
    fn of(case: &FixtureCase) -> Self {
        let fixture = &case.fixture;
        let header = fixture.header.as_ref();
        let algorithm = match header.map(|header| header.alg.as_str()) {
            Some("ES256") => "ES256",
            Some("EdDSA") => "EdDSA",
            _ => "RS256",
        };
        let recipe = case.configuration == Configuration::Recipe;
        let access_token_type = match case.configuration {
            Configuration::Recipe => header
                .and_then(|header| header.typ.clone())
                .unwrap_or_else(|| "at+jwt".to_owned()),
            Configuration::JwtAccepted => "JWT".to_owned(),
            Configuration::Default => "at+jwt".to_owned(),
        };
        let scope_claim = if recipe && fixture.claims.contains_key("scp") {
            "scp"
        } else {
            "scope"
        };
        let client = literal_text(fixture, "client_id").or_else(|| literal_text(fixture, "azp"));
        let clients = match (&client, recipe) {
            (Some(client), _) => vec![client.clone()],
            (None, true) => Vec::new(),
            (None, false) => vec![LISTED_CLIENT.to_owned()],
        };
        // The profile requires the fixture's first scope. A scopeless token
        // meets a scope it lacks, except on a declared-kind row: the recipe
        // that declares a kind serves it on a profile that requires none.
        let required_scopes = match fixture.read_scope(scope_claim) {
            Some(scope) => format!("[{scope}]"),
            None if case.declared_kind.is_some() => "unrestricted".to_owned(),
            None => format!("[{FALLBACK_SCOPE}]"),
        };
        let declared = case.declared_kind.map(|kind| DeclaredKind {
            client: client.clone(),
            kind: match kind {
                ActorKind::Human => "human",
                ActorKind::Agent => "agent",
                ActorKind::Service => "service",
            },
        });
        Self {
            algorithm,
            access_token_type,
            scope_claim,
            clients,
            required_scopes,
            declared,
        }
    }

    /// The entry lines that declare the row's kind, if any.
    fn declared_kind_yaml(&self) -> String {
        match &self.declared {
            None => String::new(),
            Some(DeclaredKind {
                client: Some(client),
                kind,
            }) => format!(
                "        clientActorKinds:\n          {}: {kind}\n",
                json!(client)
            ),
            Some(DeclaredKind { client: None, kind }) => {
                format!("        actorKind: {kind}\n")
            }
        }
    }

    fn runtime_yaml(&self, case: &FixtureCase) -> String {
        let clients = if self.clients.is_empty() {
            "unrestricted".to_owned()
        } else {
            json!(self.clients).to_string()
        };
        format!(
            r#"
apiVersion: id.registrystack.org/formats/breg/runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:8080
identity:
  environment: production
  instanceId: registry-primary
  databaseId: registry-db
secretProviders:
  environment: {{}}
  file:
    root: /var/lib/breg/secrets
database:
  runtimeUrlRef: secret:env/BREG_DATABASE_URL
  migrationUrlRef: secret:env/BREG_MIGRATION_DATABASE_URL
  pool:
    maximumConnections: 4
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: /var/lib/breg/package
authentication:
  oidc:
    issuers:
      primary:
        issuer: {issuer}
        audience: {audience}
        allowedAlgorithm: {algorithm}
        accessTokenType: "{access_token_type}"
        scopeClaim: {scope_claim}
        scopeSeparator: " "
        allowedClients: {clients}
{declared}        maximumTokenLifetimeSeconds: 3600
        leewayMilliseconds: 60000
  authorityClaims:
    principal: sub
audit:
  hashKeyRef: secret:file/audit-key
  path: /var/lib/breg/audit/audit.jsonl
cursor:
  secretRef: secret:file/cursor-key
  maximumAgeSeconds: 300
destinations:
  hooks: {{}}
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#,
            issuer = case.issuer,
            audience = case.audience,
            algorithm = self.algorithm,
            access_token_type = self.access_token_type,
            scope_claim = self.scope_claim,
            declared = self.declared_kind_yaml(),
        )
    }

    /// A project with the one access profile the row is read against: a
    /// default profile for any actor, or a profile for people only. Each
    /// requires the scopes [`Shape::of`] chose and serves every client the
    /// issuer entry admits.
    fn project_yaml(&self, against: Against) -> String {
        let profile = match against {
            Against::PlainRead => format!(
                "  reader:\n    default: true\n    principalClaim: sub\n    requiredScopes: {}\n",
                self.required_scopes
            ),
            Against::HumanOnlyProfile => format!(
                "  people:\n    default: true\n    principalClaim: sub\n    actorKind: human\n    requiredScopes: {}\n",
                self.required_scopes
            ),
        };
        format!(
            r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {{id: token-characterisation, version: 0.1.0, defaultLanguage: en, canonicalBaseIri: https://authoring.example.test}}
recordTypes:
  case:
    primaryDataset: test-dataset
    route: cases
    mutationMode: mutable
    tombstone: false
    classification: public
    fields:
      - {{id: label, type: string, required: true, maximumLength: 100, classification: public}}
datasets:
  test-dataset: {{}}
accessProfiles:
{profile}    permissions:
      records:
        - {{recordType: case, operations: [get], readableFields: [label], rowBoundaries: unrestricted}}
"#
        )
    }
}

fn literal_text(fixture: &TokenFixture, claim: &str) -> Option<String> {
    match fixture.claims.get(claim) {
        Some(ClaimValue::Literal(Value::String(text))) => Some(text.clone()),
        _ => None,
    }
}

async fn observe(case: FixtureCase) -> Outcome {
    let shape = Shape::of(&case);
    let config = parse_runtime_config(
        &shape.runtime_yaml(&case),
        registry_platform_config::DeclaredPosture {
            posture: registry_platform_config::Posture::Production,
            source: registry_platform_config::PostureSource::Default,
        },
    )
    .expect("the runtime file for this row parses");
    let registry = Arc::new(
        compile_project(
            &parse_project_yaml(shape.project_yaml(case.against).as_bytes())
                .expect("project parses"),
            &[],
            CompileProfile::Authoring,
        )
        .expect("project compiles"),
    );
    let keys = Arc::new(JwksFetcher::new_static(
        serde_json::from_value(case.jwks.clone()).expect("the key set parses"),
        JwksFetcherConfig::defaults(),
    ));
    let issuers = config
        .authentication()
        .oidc()
        .issuers()
        .map(|entry| entry.authenticator_issuer(Arc::clone(&keys)))
        .collect();
    // The profiles name no requester clients, so every issuer entry the row
    // writes can serve them.
    let authenticator = Arc::new(
        RegistryAuthenticator::with_issuers(
            &registry,
            issuers,
            config.authentication().authority_claim_config(),
        )
        .unwrap_or_else(|error| {
            panic!("the authentication block is invalid for the project: {error}")
        }),
    );

    let token = case.token.expose();
    let claims = authenticator.authenticate(token).await;
    let claims = match claims {
        Ok(claims) => claims,
        Err(
            AuthenticationError::VerificationRefused | AuthenticationError::MalformedCredential,
        ) => {
            return refused_stage(&registry, &authenticator, token)
                .await
                .map_or(Outcome::Unknown, Outcome::Refused);
        }
        Err(AuthenticationError::InvalidClaims) => {
            return Outcome::Refused(Stage::Claims);
        }
    };
    let kind = actor_kind_of(&format!("{claims:?}"));

    let profile = match case.against {
        Against::PlainRead => "reader",
        Against::HumanOnlyProfile => "people",
    };
    let status = request_record(&registry, &authenticator, token, profile).await;
    if status == StatusCode::OK {
        Outcome::Admitted(Some(kind))
    } else {
        Outcome::Refused(Stage::Profile)
    }
}

/// The stage a refused token failed at: the check the request boundary counted
/// when the token was sent through the router, mapped onto the corpus's
/// stages. `None` when the boundary counted nothing or something else.
async fn refused_stage(
    registry: &Arc<registry_breg::CompiledRegistry>,
    authenticator: &Arc<RegistryAuthenticator>,
    token: &str,
) -> Option<Stage> {
    let before = refusal_counts().await;
    request_record(registry, authenticator, token, "reader").await;
    let after = refusal_counts().await;
    let counted: Vec<&str> = after
        .iter()
        .filter(|(check, count)| **count > before.get(*check).copied().unwrap_or(0))
        .map(|(check, _)| check.as_str())
        .collect();
    match counted.as_slice() {
        ["credential-malformed"] => Some(Stage::Header),
        ["token-algorithm"] => Some(Stage::Algorithm),
        ["token-type"] => Some(Stage::TokenType),
        ["token-key"] => Some(Stage::Key),
        ["token-signature"] => Some(Stage::Signature),
        ["token-issuer"] => Some(Stage::Issuer),
        ["token-audience"] => Some(Stage::Audience),
        ["token-time"] => Some(Stage::Time),
        ["token-client" | "token-assertion-issuer"] => Some(Stage::Client),
        ["actor-kind"] => Some(Stage::ActorKind),
        ["key-source-unavailable"] => Some(Stage::Unavailable),
        _ => None,
    }
}

/// The refusal counter as the metrics listener serves it.
async fn refusal_counts() -> std::collections::BTreeMap<String, u64> {
    let response = metrics_app(
        Arc::new(Metrics::without_pool_for_test()),
        registry_platform_config::Posture::Production,
    )
    .oneshot(
        Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .expect("scrape request"),
    )
    .await
    .expect("the metrics listener responds");
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("metrics body");
    String::from_utf8(bytes.to_vec())
        .expect("metrics are UTF-8")
        .lines()
        .filter_map(|line| line.strip_prefix("breg_request_refusals_total{check=\""))
        .map(|rest| {
            let (check, count) = rest.split_once("\"} ").expect("sample line");
            (check.to_owned(), count.parse().expect("counter value"))
        })
        .collect()
}

/// The actor kind in a `VerifiedRequestClaims` debug rendering, which prints
/// the kind and redacts every value: `unspecified` for a caller whose token
/// states no kind and has none declared.
fn actor_kind_of(rendered: &str) -> String {
    if rendered.contains("actor_kind: None") {
        return "unspecified".to_owned();
    }
    let after = rendered
        .split("actor_kind: Some(")
        .nth(1)
        .expect("an authenticated request renders its actor kind");
    after
        .split(')')
        .next()
        .expect("the actor kind is closed")
        .to_ascii_lowercase()
}

async fn request_record(
    registry: &Arc<registry_breg::CompiledRegistry>,
    authenticator: &Arc<RegistryAuthenticator>,
    token: &str,
    profile: &str,
) -> StatusCode {
    let service = Arc::new(HttpService::new(
        Arc::clone(registry),
        ReadRuntimeIdentity {
            package_revision: "package-token-test".to_owned(),
            schema_fingerprint: "schema-token-test".to_owned(),
        },
        Arc::new(OneRecord),
        Arc::new(Ready),
        Arc::new(
            CursorCodec::new(
                Zeroizing::new(vec![0x43; 32]),
                std::time::Duration::from_secs(300),
            )
            .expect("the cursor key is valid"),
        ),
    ));
    let app = authenticated_router(service, Arc::clone(authenticator));
    let request = Request::builder()
        .uri(format!(
            "/v1/records/cases/{RECORD_ID}?accessProfile={profile}"
        ))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    app.oneshot(request)
        .await
        .expect("the router responds")
        .status()
}

struct OneRecord;

impl RecordReadService for OneRecord {
    fn get(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        let fields: BTreeSet<String> = request.selected_fields;
        Box::pin(async move {
            let data: serde_json::Map<String, Value> = fields
                .into_iter()
                .map(|field| (field, json!("visible")))
                .collect();
            let record = json!({"id": RECORD_ID, "revision": 1, "data": data});
            Ok(Some(
                HeldReadResponse::from_json(&record).expect("the record serializes"),
            ))
        })
    }

    fn list(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        Box::pin(async {
            Ok(HeldReadResponse::from_json(&json!({"items": []})).expect("the list serializes"))
        })
    }

    fn lookup(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
    }
}

struct Ready;

impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
