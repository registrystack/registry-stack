// SPDX-License-Identifier: Apache-2.0

//! Durable, caller-driven ingestion runs behind the authenticated API.
//!
//! One run binds the active package revision, schema fingerprint, entity,
//! selected access profile, create-or-patch operation, input digest, chunking
//! algorithm, and announced counts at creation. The caller then submits
//! exactly the next chunk; every operation re-authorizes against the compiled
//! batch route the run drives, so possession of a run id grants nothing and
//! unknown or other-caller runs answer as not found. There is no server
//! worker: the protocol is synchronous and caller-driven, and the server
//! derives each chunk attempt key from the run binding, so no
//! `Idempotency-Key` is accepted on these routes.

use super::*;
use crate::postgres::{
    IngestionChunkSubmitInput, IngestionRunCreateInput, IngestionRunListQuery,
    IngestionServiceError,
};

/// The create-run document is a small fixed-shape binding, not a bulk input:
/// the source bytes stay with the caller and only digests travel.
const MAX_RUN_DOCUMENT_BYTES: usize = 4 * 1024;

/// One compiled batch route every run of an entity is bound to, layered as a
/// request extension exactly like the attachment routes bind their base.
#[derive(Clone)]
struct IngestionRoute {
    base: CompiledRoute,
}

/// Bind the ingestion-run routes of every batch-driven entity. The compiled
/// batch route is resolved through the same lookup the client-side import plan
/// uses, so a run and a direct batch submission of the same bytes authorize
/// against the same operation.
pub(super) fn routes(service: &HttpService) -> Router<Arc<HttpService>> {
    let mut app = Router::new();
    if service.mutations.is_none() {
        return app;
    }
    for entity in service.registry.entities().values() {
        if entity.batch.is_none() {
            continue;
        }
        // Every profile that grants the batch operation resolves the same
        // compiled route, so the first hit is the route the runs drive.
        let Some(base) = entity
            .access_profiles
            .keys()
            .filter_map(|profile_id| {
                crate::data::ingestion_batch_route(&service.registry, &entity.id, profile_id)
            })
            .next()
        else {
            continue;
        };
        let binding = IngestionRoute { base: base.clone() };
        let root = format!("/v1/records/{}/ingestion-runs", entity.route);
        app = app
            .route(
                &root,
                post(create_run)
                    .get(list_runs)
                    .layer(Extension(binding.clone())),
            )
            .route(
                &format!("{root}/{{run_id}}"),
                get(read_run).layer(Extension(binding.clone())),
            )
            .route(
                &format!("{root}/{{run_id}}/chunks"),
                post(submit_chunk).layer(Extension(binding.clone())),
            )
            .route(
                &format!("{root}/{{run_id}}/cancel"),
                post(cancel_run).layer(Extension(binding.clone())),
            )
            .route(
                &format!("{root}/{{run_id}}/chunks/{{chunk_index}}/receipt"),
                get(chunk_receipt).layer(Extension(binding)),
            );
    }
    app
}

#[allow(clippy::too_many_arguments)] // Axum extractors are the HTTP contract.
async fn create_run(
    State(service): State<Arc<HttpService>>,
    Extension(binding): Extension<IngestionRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &QueryOptions::default(),
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &binding.base, &claims, &options) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &options,
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    if headers.contains_key("idempotency-key") {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    }
    if !single_content_type(&headers, "application/json") {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            unsupported_media_type(),
            &correlation,
        )
        .await;
    }
    let Ok(body) = bounded_body_to(body, MAX_RUN_DOCUMENT_BYTES).await else {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    let Ok(input) = parse_create_run_body(&body, &binding.base.entity_id) else {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    match mutations
        .create_ingestion_run(&surface.context, &correlation, input)
        .await
    {
        Ok(run) => ingestion_response(StatusCode::CREATED, json!({ "run": run })),
        Err(error) => ingestion_problem(error),
    }
}

async fn list_runs(
    State(service): State<Arc<HttpService>>,
    Extension(binding): Extension<IngestionRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Ok(query) = parse_list_query(raw_query.as_deref()) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &QueryOptions::default(),
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &binding.base, &claims, &query.options) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &query.options,
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    match mutations
        .list_ingestion_runs(
            &surface.context,
            IngestionRunListQuery {
                entity_id: binding.base.entity_id.clone(),
                status: query.status,
                input_digest: query.input_digest,
                after_run_id: query.after_run_id,
                limit: query.limit,
            },
        )
        .await
    {
        Ok(page) => ingestion_response(StatusCode::OK, page),
        Err(error) => ingestion_problem(error),
    }
}

async fn read_run(
    State(service): State<Arc<HttpService>>,
    Extension(binding): Extension<IngestionRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    Path(path): Path<HashMap<String, String>>,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &QueryOptions::default(),
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &binding.base, &claims, &options) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &options,
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(run_id) = path_run_id(&path) else {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            concealed(),
            &correlation,
        )
        .await;
    };
    match mutations
        .read_ingestion_run(&surface.context, &binding.base.entity_id, run_id)
        .await
    {
        Ok(run) => ingestion_response(StatusCode::OK, json!({ "run": run })),
        Err(error) => ingestion_problem(error),
    }
}

#[allow(clippy::too_many_arguments)] // Axum extractors are the HTTP contract.
async fn cancel_run(
    State(service): State<Arc<HttpService>>,
    Extension(binding): Extension<IngestionRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    Path(path): Path<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &QueryOptions::default(),
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &binding.base, &claims, &options) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &options,
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    if headers.contains_key("idempotency-key") {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    }
    if headers.contains_key(CONTENT_TYPE) {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            unsupported_media_type(),
            &correlation,
        )
        .await;
    }
    if !body_is_empty(body).await {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    }
    let Some(run_id) = path_run_id(&path) else {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            concealed(),
            &correlation,
        )
        .await;
    };
    match mutations
        .cancel_ingestion_run(
            &surface.context,
            &correlation,
            &binding.base.entity_id,
            run_id,
        )
        .await
    {
        Ok(run) => ingestion_response(StatusCode::OK, json!({ "run": run })),
        Err(error) => ingestion_problem(error),
    }
}

#[allow(clippy::too_many_arguments)] // Axum extractors are the HTTP contract.
async fn submit_chunk(
    State(service): State<Arc<HttpService>>,
    Extension(binding): Extension<IngestionRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    Path(path): Path<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &QueryOptions::default(),
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &binding.base, &claims, &options) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &options,
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    // The chunk items are the batch items of the compiled route, so the
    // entity must carry a batch surface at all.
    if surface.entity.batch.is_none() {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    }
    if headers.contains_key("idempotency-key") {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    }
    if !single_content_type(&headers, "application/json") {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            unsupported_media_type(),
            &correlation,
        )
        .await;
    }
    // The body is bounded by the stable protocol ceilings, never the current
    // package's batch limits: an exact replay of a chunk a previous package
    // admitted must still reach the service, which enforces the run's own
    // stored bounds.
    let Ok(body) = bounded_body_to(body, crate::compiler::MAX_BATCH_BYTES as usize).await else {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    let Ok(parsed) = parse_chunk_body(&body, usize::from(crate::compiler::MAX_BATCH_ITEMS)) else {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    let Some(run_id) = path_run_id(&path) else {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            concealed(),
            &correlation,
        )
        .await;
    };
    match mutations
        .submit_ingestion_chunk(
            &surface.context,
            &correlation,
            IngestionChunkSubmitInput {
                run_id,
                entity_id: binding.base.entity_id.clone(),
                chunk_index: parsed.chunk_index,
                items: parsed.items,
                digest: parsed.digest,
                prefix_digest: parsed.prefix_digest,
            },
        )
        .await
    {
        Ok(answer) => ingestion_response(StatusCode::OK, answer),
        // A submission the run refuses after parsing owes the journal the
        // same durable refusal envelope pre-parse failures write, so an audit
        // outage gates the refusal instead of passing silently.
        Err(error) => {
            audited_mutation_refusal(
                mutations,
                &binding.base,
                &surface.context,
                None,
                ingestion_problem(error),
                &correlation,
            )
            .await
        }
    }
}

async fn chunk_receipt(
    State(service): State<Arc<HttpService>>,
    Extension(binding): Extension<IngestionRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    Path(path): Path<HashMap<String, String>>,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &QueryOptions::default(),
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &binding.base, &claims, &options) else {
        return audited_mutation_concealment(
            mutations,
            &binding.base,
            &options,
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(run_id) = path_run_id(&path) else {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            concealed(),
            &correlation,
        )
        .await;
    };
    let Some(chunk_index) = path_chunk_index(&path) else {
        return audited_mutation_refusal(
            mutations,
            &binding.base,
            &surface.context,
            None,
            concealed(),
            &correlation,
        )
        .await;
    };
    match mutations
        .ingestion_chunk_receipt(
            &surface.context,
            &correlation,
            &binding.base.entity_id,
            run_id,
            chunk_index,
        )
        .await
    {
        Ok(receipt) => ingestion_response(StatusCode::OK, receipt),
        Err(error) => ingestion_problem(error),
    }
}

/// One no-store JSON answer. Run state is caller-bound and perishable, so
/// nothing about it may be stored.
fn ingestion_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [
            (CONTENT_TYPE, "application/json"),
            (CACHE_CONTROL, "no-store"),
            (VARY, "authorization, accept"),
        ],
        Json(body),
    )
        .into_response()
}

/// Map the closed ingestion service vocabulary onto the registered problems.
/// Every mapping is the catalogue's own code, status, and published sentence;
/// nothing request-derived travels in a problem.
fn ingestion_problem(error: IngestionServiceError) -> Response {
    match error {
        IngestionServiceError::RequestInvalid => invalid_request(),
        IngestionServiceError::PreconditionFailed => precondition_failed(),
        IngestionServiceError::NotFound => concealed(),
        IngestionServiceError::ProfileMismatch => catalogue_problem(
            crate::problem::ProblemCode::IngestionProfileMismatch,
            StatusCode::FORBIDDEN,
        ),
        IngestionServiceError::RunNotOpen => catalogue_problem(
            crate::problem::ProblemCode::IngestionRunNotOpen,
            StatusCode::CONFLICT,
        ),
        IngestionServiceError::RunBlocked => catalogue_problem(
            crate::problem::ProblemCode::IngestionRunBlocked,
            StatusCode::CONFLICT,
        ),
        IngestionServiceError::ChunkMismatch => catalogue_problem(
            crate::problem::ProblemCode::IngestionChunkMismatch,
            StatusCode::CONFLICT,
        ),
        IngestionServiceError::ReceiptErased => catalogue_problem(
            crate::problem::ProblemCode::IngestionReceiptErased,
            StatusCode::GONE,
        ),
        IngestionServiceError::Unavailable => fixed_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "service.unavailable",
            "The Registry mutation service is unavailable.",
        ),
    }
}

/// The registered problem one ingestion code answers under: the catalogue's
/// own status, code, and published sentence, asserted to stay in lockstep.
fn catalogue_problem(code: crate::problem::ProblemCode, status: StatusCode) -> Response {
    debug_assert_eq!(
        code.status(),
        status.as_u16(),
        "the ingestion problem catalogue drifted from its registered status"
    );
    fixed_problem(status, code.code(), code.description())
}

/// The problem one ingestion refusal inside the ordinary batch path answers
/// under. The codes, statuses, and sentences are the catalogue's own.
pub(super) fn batch_refusal_problem(refusal: crate::mutation::IngestionRefusal) -> Response {
    match refusal {
        crate::mutation::IngestionRefusal::RunNotOpen => catalogue_problem(
            crate::problem::ProblemCode::IngestionRunNotOpen,
            StatusCode::CONFLICT,
        ),
        crate::mutation::IngestionRefusal::ChunkMismatch => catalogue_problem(
            crate::problem::ProblemCode::IngestionChunkMismatch,
            StatusCode::CONFLICT,
        ),
        crate::mutation::IngestionRefusal::BindingChanged => catalogue_problem(
            crate::problem::ProblemCode::IngestionRunBlocked,
            StatusCode::CONFLICT,
        ),
        crate::mutation::IngestionRefusal::ReceiptErased => catalogue_problem(
            crate::problem::ProblemCode::IngestionReceiptErased,
            StatusCode::GONE,
        ),
    }
}

/// The exact create-run document: the operation, the selected profile, the
/// binding the run announces, and the derived input counts. Every member is
/// required and no other member is admitted.
fn parse_create_run_body(body: &[u8], entity_id: &str) -> Result<IngestionRunCreateInput, ()> {
    const MEMBERS: [&str; 9] = [
        "operation",
        "profileId",
        "packageRevision",
        "schemaFingerprint",
        "inputDigest",
        "inputLength",
        "itemCount",
        "chunkCount",
        "chunkAlgorithmVersion",
    ];
    let value = parse_json_strict(body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    if object.len() != MEMBERS.len() || MEMBERS.iter().any(|member| !object.contains_key(*member)) {
        return Err(());
    }
    let text = |member: &str| {
        object
            .get(member)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or(())
    };
    let operation = text("operation")?;
    if !matches!(operation.as_str(), "create" | "patch") {
        return Err(());
    }
    let input_digest = text("inputDigest")?;
    if !valid_digest(&input_digest) {
        return Err(());
    }
    let chunk_algorithm_version = text("chunkAlgorithmVersion")?;
    if chunk_algorithm_version != crate::data::RUN_CHUNK_ALGORITHM_VERSION {
        return Err(());
    }
    let count = |member: &str| {
        i64::try_from(object.get(member).and_then(Value::as_u64).ok_or(())?).map_err(|_| ())
    };
    let (input_length, item_count, chunk_count) = (
        count("inputLength")?,
        count("itemCount")?,
        count("chunkCount")?,
    );
    if item_count <= 0 || chunk_count <= 0 {
        return Err(());
    }
    Ok(IngestionRunCreateInput {
        entity_id: entity_id.to_owned(),
        operation,
        profile_id: text("profileId")?,
        package_revision: text("packageRevision")?,
        schema_fingerprint: text("schemaFingerprint")?,
        input_digest,
        input_length,
        item_count,
        chunk_count,
        chunk_algorithm_version,
    })
}

struct ParsedChunkBody {
    chunk_index: i64,
    items: Vec<Value>,
    digest: String,
    prefix_digest: String,
}

/// The exact chunk-submission document: the chunk index, the bounded batch
/// items the compiled batch operation accepts, and the two digests that bind
/// the canonical chunk and the committed input prefix. Every member is
/// required and no other member is admitted.
fn parse_chunk_body(body: &[u8], maximum_items: usize) -> Result<ParsedChunkBody, ()> {
    let value = parse_json_strict(body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    if object.len() != 4
        || !object.contains_key("chunkIndex")
        || !object.contains_key("items")
        || !object.contains_key("digest")
        || !object.contains_key("prefixDigest")
    {
        return Err(());
    }
    let chunk_index = i64::try_from(object.get("chunkIndex").and_then(Value::as_u64).ok_or(())?)
        .map_err(|_| ())?;
    let digest = object
        .get("digest")
        .and_then(Value::as_str)
        .filter(|value| valid_digest(value))
        .ok_or(())?
        .to_owned();
    let prefix_digest = object
        .get("prefixDigest")
        .and_then(Value::as_str)
        .filter(|value| valid_digest(value))
        .ok_or(())?
        .to_owned();
    let announced = object.get("items").and_then(Value::as_array).ok_or(())?;
    if announced.is_empty() || announced.len() > maximum_items {
        return Err(());
    }
    let mut items = Vec::with_capacity(announced.len());
    for item in announced {
        if !item.is_object() {
            return Err(());
        }
        items.push(item.clone());
    }
    Ok(ParsedChunkBody {
        chunk_index,
        items,
        digest,
        prefix_digest,
    })
}

/// One sha256 digest as exactly 64 lowercase hex characters.
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// One run id from a path segment in canonical lowercase UUID form, so a
/// malformed id is an unknown run and never a parse side channel.
fn path_run_id(path: &HashMap<String, String>) -> Option<Uuid> {
    let value = path.get("run_id")?.as_str();
    Uuid::parse_str(value)
        .ok()
        .filter(|identifier| identifier.to_string() == value)
}

/// One chunk index from a path segment in canonical nonnegative decimal form.
fn path_chunk_index(path: &HashMap<String, String>) -> Option<i64> {
    let value = path.get("chunk_index")?.as_str();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let parsed = value.parse::<i64>().ok()?;
    (parsed >= 0 && parsed.to_string() == value).then_some(parsed)
}

struct IngestionListQuery {
    options: QueryOptions,
    status: Option<String>,
    input_digest: Option<String>,
    after_run_id: Option<Uuid>,
    limit: i64,
}

/// The query an ingestion listing admits: the access profile every ingestion
/// operation re-authorizes under, the bounded page size, the keyset cursor,
/// and the status and input-digest filters. Any other member is invalid,
/// exactly like the strict read query.
fn parse_list_query(raw: Option<&str>) -> Result<IngestionListQuery, QueryParseError> {
    let mut access_profile = None;
    let mut limit = crate::ingestion_store::DEFAULT_RUN_PAGE_SIZE;
    let mut limit_seen = false;
    let mut after_run_id = None;
    let mut status = None;
    let mut input_digest = None;
    if let Some(raw) = raw {
        if raw.is_empty() || raw.len() > MAX_RAW_QUERY_BYTES {
            return Err(QueryParseError::Invalid);
        }
        for pair in raw.split('&') {
            let (name, value) = pair.split_once('=').ok_or(QueryParseError::Invalid)?;
            let name = percent_decode(name)?;
            let value = percent_decode(value)?;
            match name.as_str() {
                "accessProfile" => {
                    if access_profile.replace(value).is_some() {
                        return Err(QueryParseError::Invalid);
                    }
                }
                "limit" => {
                    let parsed = parse_page_limit(&value)?;
                    if limit_seen {
                        return Err(QueryParseError::Invalid);
                    }
                    limit_seen = true;
                    limit = parsed;
                }
                "after" => {
                    if after_run_id.replace(parse_run_cursor(&value)?).is_some() {
                        return Err(QueryParseError::Invalid);
                    }
                }
                "status" => {
                    if crate::ingestion_store::IngestionRunStatus::parse(&value).is_none()
                        || status.replace(value).is_some()
                    {
                        return Err(QueryParseError::Invalid);
                    }
                }
                "inputDigest" => {
                    if !valid_digest(&value) || input_digest.replace(value).is_some() {
                        return Err(QueryParseError::Invalid);
                    }
                }
                _ => return Err(QueryParseError::Invalid),
            }
        }
    }
    Ok(IngestionListQuery {
        options: QueryOptions {
            parsed: strict_query::ParsedReadQuery {
                access_profile,
                as_of: None,
                mode: strict_query::ParsedReadQueryMode::Query(
                    strict_query::ReadQueryOptions::default(),
                ),
            },
            request_history_after_proposal_version: None,
            historical: None,
        },
        status,
        input_digest,
        after_run_id,
        limit,
    })
}

/// One page size in canonical decimal form within the store's fixed bounds.
fn parse_page_limit(value: &str) -> Result<i64, QueryParseError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(QueryParseError::Invalid);
    }
    let parsed = value
        .parse::<u64>()
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or(QueryParseError::Invalid)?;
    if parsed == 0 || parsed > crate::ingestion_store::MAX_RUN_PAGE_SIZE as u64 {
        return Err(QueryParseError::Invalid);
    }
    Ok(parsed as i64)
}

/// One keyset cursor in canonical lowercase UUID form, so a malformed cursor
/// is refused as input instead of silently matching nothing.
fn parse_run_cursor(value: &str) -> Result<Uuid, QueryParseError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|identifier| identifier.to_string() == value)
        .ok_or(QueryParseError::Invalid)
}

/// Advertise the ingestion routes of one selected profile. Like the attachment
/// operations, they are appended to the compiled-route document only for a
/// caller that holds the batch operation under the selected profile and
/// answers with a principal, and they never appear in `/v1/registry`.
pub(super) fn append_openapi(
    service: &HttpService,
    surfaces: &[AuthorizedSurface<'_>],
    paths: &mut Map<String, Value>,
    schemas: &mut Map<String, Value>,
) {
    if service.mutations.is_none() {
        return;
    }
    let mut advertised = false;
    for surface in surfaces.iter().filter(|surface| {
        surface.route.operation == Operation::Batch
            && surface.read_path.is_none()
            && surface.context.principal().is_some()
    }) {
        let Some(batch) = surface.entity.batch.as_ref() else {
            continue;
        };
        let root = format!("/v1/records/{}/ingestion-runs", surface.entity.route);
        let operation_id = |name: &str| format!("{}.ingestion.{name}", surface.entity.id);
        let methods = paths
            .entry(root.clone())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("compiled OpenAPI paths are objects");
        methods.insert(
            "post".to_owned(),
            json!({
                "operationId": operation_id("createRun"),
                "x-registry-entity": surface.entity.id,
                "x-registry-operation": "ingestionCreateRun",
                "security": [{"bearerAuth": []}],
                "x-registry-accessProfile": surface.context.selected_profile(),
                "parameters": [access_profile_parameter()],
                "requestBody": {
                    "required": true,
                    "content": {"application/json": {"schema": create_run_schema()}}
                },
                "responses": ingestion_responses(
                    "201",
                    create_run_answer(),
                    &[
                        crate::problem::ProblemCode::RequestInvalid,
                        crate::problem::ProblemCode::AuthenticationRefused,
                        crate::problem::ProblemCode::IngestionProfileMismatch,
                        crate::problem::ProblemCode::PreconditionFailed,
                        crate::problem::ProblemCode::UnsupportedMediaType,
                        crate::problem::ProblemCode::ServiceUnavailable,
                    ],
                ),
            }),
        );
        methods.insert(
            "get".to_owned(),
            json!({
                "operationId": operation_id("listRuns"),
                "x-registry-entity": surface.entity.id,
                "x-registry-operation": "ingestionListRuns",
                "security": [{"bearerAuth": []}],
                "x-registry-accessProfile": surface.context.selected_profile(),
                "parameters": [
                    access_profile_parameter(),
                    {
                        "name": "limit",
                        "in": "query",
                        "required": false,
                        "description": "The bounded page size. The default and maximum are the run store's own.",
                        "schema": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": crate::ingestion_store::MAX_RUN_PAGE_SIZE,
                            "default": crate::ingestion_store::DEFAULT_RUN_PAGE_SIZE
                        }
                    },
                    {
                        "name": "after",
                        "in": "query",
                        "required": false,
                        "description": "The keyset cursor: only runs ordered before this run id.",
                        "schema": {"type": "string", "format": "uuid"}
                    },
                    {
                        "name": "status",
                        "in": "query",
                        "required": false,
                        "description": "Only runs in one status.",
                        "schema": {
                            "type": "string",
                            "enum": ["open", "complete", "cancelled", "blocked"]
                        }
                    },
                    {
                        "name": "inputDigest",
                        "in": "query",
                        "required": false,
                        "description": "Only runs announced with this input digest.",
                        "schema": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                    }
                ],
                "responses": ingestion_responses(
                    "200",
                    list_runs_answer(),
                    &[
                        crate::problem::ProblemCode::RequestInvalid,
                        crate::problem::ProblemCode::AuthenticationRefused,
                        crate::problem::ProblemCode::ServiceUnavailable,
                    ],
                ),
            }),
        );
        let run_path = paths
            .entry(format!("{root}/{{run_id}}"))
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("compiled OpenAPI paths are objects");
        run_path.insert(
            "get".to_owned(),
            json!({
                "operationId": operation_id("readRun"),
                "x-registry-entity": surface.entity.id,
                "x-registry-operation": "ingestionReadRun",
                "security": [{"bearerAuth": []}],
                "x-registry-accessProfile": surface.context.selected_profile(),
                "parameters": [access_profile_parameter(), run_id_parameter()],
                "responses": ingestion_responses(
                    "200",
                    run_answer(),
                    &[
                        crate::problem::ProblemCode::RequestInvalid,
                        crate::problem::ProblemCode::AuthenticationRefused,
                        crate::problem::ProblemCode::ResourceNotFound,
                        crate::problem::ProblemCode::ServiceUnavailable,
                    ],
                ),
            }),
        );
        let chunks_path = paths
            .entry(format!("{root}/{{run_id}}/chunks"))
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("compiled OpenAPI paths are objects");
        chunks_path.insert(
            "post".to_owned(),
            json!({
                "operationId": operation_id("submitChunk"),
                "x-registry-entity": surface.entity.id,
                "x-registry-operation": "ingestionSubmitChunk",
                "security": [{"bearerAuth": []}],
                "x-registry-accessProfile": surface.context.selected_profile(),
                "x-registry-maximumItems": batch.maximum_items,
                "x-registry-maximumBytes": batch.maximum_bytes,
                "parameters": [access_profile_parameter(), run_id_parameter()],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": submit_chunk_schema(surface.entity, batch)
                        }
                    }
                },
                "responses": ingestion_responses(
                    "200",
                    json!({
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["run", "receipt"],
                        "properties": {
                            "run": {"$ref": "#/components/schemas/IngestionRun"},
                            "receipt": {
                                "$ref": "#/components/schemas/IngestionChunkReceipt"
                            }
                        }
                    }),
                    &[
                        crate::problem::ProblemCode::RequestInvalid,
                        crate::problem::ProblemCode::AuthenticationRefused,
                        crate::problem::ProblemCode::IngestionProfileMismatch,
                        crate::problem::ProblemCode::ResourceNotFound,
                        crate::problem::ProblemCode::IngestionRunNotOpen,
                        crate::problem::ProblemCode::IngestionRunBlocked,
                        crate::problem::ProblemCode::IngestionChunkMismatch,
                        crate::problem::ProblemCode::IngestionReceiptErased,
                        crate::problem::ProblemCode::PreconditionFailed,
                        crate::problem::ProblemCode::UnsupportedMediaType,
                        crate::problem::ProblemCode::ServiceUnavailable,
                    ],
                ),
            }),
        );
        let cancel_path = paths
            .entry(format!("{root}/{{run_id}}/cancel"))
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("compiled OpenAPI paths are objects");
        cancel_path.insert(
            "post".to_owned(),
            json!({
                "operationId": operation_id("cancelRun"),
                "x-registry-entity": surface.entity.id,
                "x-registry-operation": "ingestionCancelRun",
                "security": [{"bearerAuth": []}],
                "x-registry-accessProfile": surface.context.selected_profile(),
                "parameters": [access_profile_parameter(), run_id_parameter()],
                "responses": ingestion_responses(
                    "200",
                    run_answer(),
                    &[
                        crate::problem::ProblemCode::RequestInvalid,
                        crate::problem::ProblemCode::AuthenticationRefused,
                        crate::problem::ProblemCode::IngestionProfileMismatch,
                        crate::problem::ProblemCode::ResourceNotFound,
                        crate::problem::ProblemCode::IngestionRunNotOpen,
                        crate::problem::ProblemCode::UnsupportedMediaType,
                        crate::problem::ProblemCode::ServiceUnavailable,
                    ],
                ),
            }),
        );
        let receipt_path = paths
            .entry(format!("{root}/{{run_id}}/chunks/{{chunk_index}}/receipt"))
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("compiled OpenAPI paths are objects");
        receipt_path.insert(
            "get".to_owned(),
            json!({
                "operationId": operation_id("chunkReceipt"),
                "x-registry-entity": surface.entity.id,
                "x-registry-operation": "ingestionChunkReceipt",
                "security": [{"bearerAuth": []}],
                "x-registry-accessProfile": surface.context.selected_profile(),
                "parameters": [
                    access_profile_parameter(),
                    run_id_parameter(),
                    {
                        "name": "chunk_index",
                        "in": "path",
                        "required": true,
                        "schema": {"type": "integer", "minimum": 0}
                    }
                ],
                "responses": ingestion_responses(
                    "200",
                    json!({"$ref": "#/components/schemas/IngestionChunkReceipt"}),
                    &[
                        crate::problem::ProblemCode::RequestInvalid,
                        crate::problem::ProblemCode::AuthenticationRefused,
                        crate::problem::ProblemCode::ResourceNotFound,
                        crate::problem::ProblemCode::IngestionReceiptErased,
                        crate::problem::ProblemCode::ServiceUnavailable,
                    ],
                ),
            }),
        );
        advertised = true;
    }
    if advertised {
        schemas.insert("IngestionRun".to_owned(), ingestion_run_schema());
        schemas.insert(
            "IngestionChunkReceipt".to_owned(),
            ingestion_chunk_receipt_schema(),
        );
    }
}

fn access_profile_parameter() -> Value {
    json!({
        "name": "accessProfile",
        "in": "query",
        "required": false,
        "description": "The access profile every ingestion operation re-authorizes under.",
        "schema": {"type": "string"}
    })
}

fn run_id_parameter() -> Value {
    json!({
        "name": "run_id",
        "in": "path",
        "required": true,
        "description": "The ingestion run the operation drives.",
        "schema": {"type": "string", "format": "uuid"}
    })
}

/// The create-run answer: the stored run under its id.
fn create_run_answer() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["run"],
        "properties": {"run": {"$ref": "#/components/schemas/IngestionRun"}}
    })
}

/// The read-run answer: the stored run under its id.
fn run_answer() -> Value {
    create_run_answer()
}

/// The list answer: one bounded, creator-scoped page with the keyset cursor.
fn list_runs_answer() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["runs", "hasMore", "nextAfter"],
        "properties": {
            "runs": {
                "type": "array",
                "items": {"$ref": "#/components/schemas/IngestionRun"}
            },
            "hasMore": {"type": "boolean"},
            "nextAfter": {"type": ["string", "null"], "format": "uuid"}
        }
    })
}

/// The success and problem responses of one ingestion operation. Only the
/// statuses the operation's closed vocabulary names are documented, and every
/// answer is caller-bound, so no response may be stored.
fn ingestion_responses(
    success_status: &str,
    success_schema: Value,
    problems: &[crate::problem::ProblemCode],
) -> Value {
    let mut responses = Map::from_iter([(
        success_status.to_owned(),
        json!({
            "description": "The ingestion answer.",
            "headers": {
                "Cache-Control": {
                    "description": "Caller-dependent responses must not be stored.",
                    "schema": {"const": "no-store"}
                },
                "Vary": {
                    "description": "Responses vary by authorization and negotiated representation.",
                    "schema": {"type": "string"}
                }
            },
            "content": {"application/json": {"schema": success_schema}}
        }),
    )]);
    for status in [400u16, 401, 403, 404, 409, 410, 412, 415, 503] {
        let codes = problems
            .iter()
            .filter(|code| code.status() == status)
            .collect::<Vec<_>>();
        if codes.is_empty() {
            continue;
        }
        let examples = codes
            .iter()
            .map(|code| {
                (
                    code.code().to_owned(),
                    json!({"value": {
                        "type": crate::problem::type_uri(code.code()),
                        "title": code.title(),
                        "status": code.status(),
                        "detail": code.description(),
                        "code": code.code(),
                        "traceId": "11111111111111111111111111111111"
                    }}),
                )
            })
            .collect::<Map<_, _>>();
        responses.insert(
            status.to_string(),
            json!({
                "description": "Problem response",
                "headers": {
                    "traceparent": {
                        "description": "Trace context for this problem response.",
                        "schema": {"type": "string", "minLength": 55, "maxLength": 55}
                    },
                    "Cache-Control": {
                        "description": "Caller-dependent responses must not be stored.",
                        "schema": {"const": "no-store"}
                    }
                },
                "content": {
                    "application/problem+json": {
                        "schema": {"$ref": "#/components/schemas/Problem"},
                        "examples": examples
                    }
                }
            }),
        );
    }
    Value::Object(responses)
}

/// The create-run document the run is announced with.
fn create_run_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "operation", "profileId", "packageRevision", "schemaFingerprint", "inputDigest",
            "inputLength", "itemCount", "chunkCount", "chunkAlgorithmVersion"
        ],
        "properties": {
            "operation": {"type": "string", "enum": ["create", "patch"]},
            "profileId": {"type": "string", "minLength": 1},
            "packageRevision": {"type": "string", "minLength": 1},
            "schemaFingerprint": {"type": "string", "minLength": 1},
            "inputDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "inputLength": {"type": "integer", "minimum": 0},
            "itemCount": {"type": "integer", "minimum": 1},
            "chunkCount": {"type": "integer", "minimum": 1},
            "chunkAlgorithmVersion": {"const": crate::data::RUN_CHUNK_ALGORITHM_VERSION}
        }
    })
}

/// The chunk-submission document: the items of the compiled batch operation
/// and the digests that bind the chunk to the announced input. The item
/// count bound is the compiled batch maximum, the same ceiling the ordinary
/// batch route enforces.
fn submit_chunk_schema(entity: &CompiledEntity, batch: &crate::contract::BatchSource) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["chunkIndex", "items", "digest", "prefixDigest"],
        "properties": {
            "chunkIndex": {"type": "integer", "minimum": 0},
            "items": {
                "type": "array",
                "minItems": 1,
                "maxItems": batch.maximum_items,
                "items": {
                    "$ref": format!(
                        "#/components/schemas/{}/properties/items/items",
                        crate::artifacts::openapi_input_schema_id(&entity.id, Operation::Batch)
                    )
                }
            },
            "digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "prefixDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        }
    })
}

/// The operational, value-free view of one ingestion run.
fn ingestion_run_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "runId", "status", "blockedReason", "entityId", "operation", "profileId",
            "packageRevision", "schemaFingerprint", "inputDigest", "inputLength", "itemCount",
            "chunkCount", "chunkAlgorithmVersion", "maximumItems", "maximumBytes",
            "nextChunkIndex", "committedItems", "committedPrefixDigest", "lastAttempt",
            "createdAt", "updatedAt", "complete"
        ],
        "properties": {
            "runId": {"type": "string", "format": "uuid"},
            "status": {"type": "string", "enum": ["open", "complete", "cancelled", "blocked"]},
            "blockedReason": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "string", "enum": ["activePackageChanged"]}
                ]
            },
            "entityId": {"type": "string"},
            "operation": {"type": "string", "enum": ["create", "patch"]},
            "profileId": {"type": "string"},
            "packageRevision": {"type": "string"},
            "schemaFingerprint": {"type": "string"},
            "inputDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "inputLength": {"type": "integer", "minimum": 1},
            "itemCount": {"type": "integer", "minimum": 1},
            "chunkCount": {"type": "integer", "minimum": 1},
            "chunkAlgorithmVersion": {"const": crate::data::RUN_CHUNK_ALGORITHM_VERSION},
            "maximumItems": {"type": "integer", "minimum": 1},
            "maximumBytes": {"type": "integer", "minimum": 1},
            "nextChunkIndex": {"type": "integer", "minimum": 0},
            "committedItems": {"type": "integer", "minimum": 0},
            "committedPrefixDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "lastAttempt": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["outcome", "chunkIndex"],
                        "properties": {
                            "outcome": {
                                "type": "string",
                                "enum": [
                                    "committed", "replayed", "invalidItem", "refused",
                                    "bindingChanged", "chunkMismatch", "runNotOpen",
                                    "unavailable"
                                ]
                            },
                            "chunkIndex": {"type": ["integer", "null"], "minimum": 0}
                        }
                    }
                ]
            },
            "createdAt": {"type": "string", "format": "date-time"},
            "updatedAt": {"type": "string", "format": "date-time"},
            "complete": {"type": "boolean"}
        }
    })
}

/// The stored answer of one committed chunk, held until the record history it
/// describes is erased.
fn ingestion_chunk_receipt_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["chunkIndex", "digest", "replayed", "erased", "batch"],
        "properties": {
            "chunkIndex": {"type": "integer", "minimum": 0},
            "digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "replayed": {"type": "boolean"},
            "erased": {"const": false},
            "batch": {"type": "object"}
        }
    })
}
