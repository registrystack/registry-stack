use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use registry_breg_client::{
    BRegAsOfListRequest, BRegBoundingBox, BRegGeoJsonListRequest, BRegGeoJsonOptions,
    BRegListRequest, BRegRecordOptions, BRegRelationshipListRequest, BRegSnapshotListRequest,
    BaseRegistryClient, BaseRegistryClientConfig,
};
use registry_platform_httputil::client::{BearerToken, TokenError, TokenProvider};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use url::Url;

const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const LINK: &str = "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </prefix/v1/schemas/company>; rel=\"describedby\"";

#[derive(Debug)]
struct CountingToken(AtomicUsize);

#[async_trait]
impl TokenProvider for CountingToken {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BearerToken::new("token")
    }
}

#[derive(Clone)]
struct StateData(Arc<Mutex<Vec<String>>>);

async fn handler(State(state): State<StateData>, request: Request<Body>) -> Response<Body> {
    let uri = request.uri().to_string();
    let accept = request
        .headers()
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    state.0.lock().unwrap().push(format!("{accept} {uri}"));
    if accept == "application/geo+json" {
        let list = !uri.contains(RECORD_ID);
        let document = if list {
            json!({
                "type":"FeatureCollection",
                "features":[feature(Value::Null)],
                "numberReturned":1,
                "registry":{"pageInfo":{"nextCursor": if uri.contains("$skiptoken") { Value::Null } else { json!("geo-next") }}}
            })
        } else {
            feature(Value::Null)
        };
        return response("application/geo+json", document, false, false);
    }

    let collection = uri.contains(":current")
        || uri.contains(":as-of")
        || uri.contains(":snapshot")
        || uri.contains("/related");
    let mut document = if collection {
        json!({
            "items":[record()],
            "pageInfo":{"nextCursor": if uri.contains("$skiptoken") { Value::Null } else { json!("next") }},
            "meta":meta()
        })
    } else {
        json!({"data":record(),"meta":meta()})
    };
    if uri.contains(":snapshot") {
        document["snapshot"] = json!("breg1_00000000-0000-4000-8000-000000000002");
    }
    let etag = !collection && !uri.contains("/revisions/");
    response("application/json", document, true, etag)
}

fn feature(geometry: Value) -> Value {
    json!({
        "type":"Feature", "id":RECORD_ID, "geometry":geometry,
        "properties":{"label":"one"}, "registry":{"revision":1}
    })
}

fn record() -> Value {
    json!({"recordIdentifier":RECORD_ID,"revisionIdentifier":"1","domainData":{"label":"one"}})
}

fn meta() -> Value {
    json!({"registryIdentifier":"registry","datasetIdentifier":"dataset","entityTypeIdentifier":"company"})
}

fn response(media: &str, value: Value, link: bool, etag: bool) -> Response<Body> {
    let mut response = Response::new(Body::from(serde_json::to_vec(&value).unwrap()));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert("content-type", media.parse().unwrap());
    response
        .headers_mut()
        .insert("traceparent", TRACEPARENT.parse().unwrap());
    if link {
        response.headers_mut().insert("link", LINK.parse().unwrap());
    }
    if etag {
        response
            .headers_mut()
            .insert("etag", "\"breg-record\"".parse().unwrap());
    }
    response
}

async fn client(provider: Arc<CountingToken>) -> (BaseRegistryClient, Arc<Mutex<Vec<String>>>) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = StateData(captured.clone());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(handler)).with_state(state),
        )
        .await
        .unwrap();
    });
    let config =
        BaseRegistryClientConfig::new(Url::parse(&format!("http://{address}/prefix")).unwrap())
            .with_token_provider(provider);
    (BaseRegistryClient::new(config).unwrap(), captured)
}

#[tokio::test]
async fn invalid_operation_specific_inputs_fail_before_token_or_io() {
    let provider = Arc::new(CountingToken(AtomicUsize::new(0)));
    let (client, captured) = client(provider.clone()).await;
    let get_only = BRegRecordOptions::default()
        .request_history_after_proposal_version(1)
        .unwrap();
    assert!(client
        .list_records("companies", &BRegListRequest::default().options(get_only))
        .await
        .is_err());
    assert!(client
        .get_record_revision("companies", RECORD_ID, 0, &BRegRecordOptions::default())
        .await
        .is_err());
    assert!(client
        .list_relationship_records(
            "companies",
            RECORD_ID,
            "../related",
            &BRegRelationshipListRequest::default(),
        )
        .await
        .is_err());
    assert_eq!(provider.0.load(Ordering::SeqCst), 0);
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn read_routes_retain_operation_representation_and_snapshot_identity() {
    let provider = Arc::new(CountingToken(AtomicUsize::new(0)));
    let (client, captured) = client(provider).await;
    let bbox = BRegBoundingBox::new("100.1", "13.1", "100.2", "13.2").unwrap();
    let geo = BRegGeoJsonListRequest::default()
        .options(BRegGeoJsonOptions::default().access_profile("map").unwrap())
        .bbox(bbox)
        .top(1)
        .unwrap();
    let first = client
        .list_geojson_records("companies", &geo)
        .await
        .unwrap();
    assert!(first.value.value.features[0].geometry.is_none());
    assert!(first.metadata.etag().is_none());
    client
        .continue_geojson_list(first.value.continuation.as_ref().unwrap())
        .await
        .unwrap();

    let as_of = BRegAsOfListRequest::new("2026-09-10T00:00:00Z").unwrap();
    client
        .list_records_as_of("companies", &as_of)
        .await
        .unwrap();
    let relationship = BRegRelationshipListRequest::default().top(1).unwrap();
    client
        .list_relationship_records("companies", RECORD_ID, "related", &relationship)
        .await
        .unwrap();
    let snapshot = client
        .list_snapshot_records(
            "companies",
            &BRegSnapshotListRequest::default().top(1).unwrap(),
        )
        .await
        .unwrap();
    let token = snapshot.value.continuation.as_ref().unwrap();
    let second = client.continue_snapshot_list(token).await.unwrap();
    assert_eq!(second.value.snapshot, snapshot.value.snapshot);

    client
        .get_record_revision("companies", RECORD_ID, 1, &BRegRecordOptions::default())
        .await
        .unwrap();
    let get_options = BRegRecordOptions::default()
        .request_history_after_proposal_version(u32::MAX)
        .unwrap();
    client
        .get_record("companies", RECORD_ID, &get_options)
        .await
        .unwrap();

    let captured = captured.lock().unwrap();
    assert!(captured.iter().any(|value| value == "application/geo+json /prefix/v1/records/companies?accessProfile=map&$top=1&bbox=100.1%2C13.1%2C100.2%2C13.2"));
    assert!(captured.iter().any(|value| value == "application/geo+json /prefix/v1/records/companies?accessProfile=map&$skiptoken=geo-next"));
    assert!(captured
        .iter()
        .any(|value| value.contains("/companies:as-of?asOf=2026-09-10T00%3A00%3A00Z")));
    assert!(captured
        .iter()
        .any(|value| value.contains(&format!("/companies/{RECORD_ID}/related?$top=1"))));
    assert!(captured
        .iter()
        .any(|value| value.contains("/companies:snapshot?$skiptoken=next")));
    assert!(captured
        .iter()
        .any(|value| value.contains("requestHistoryAfterProposalVersion=4294967295")));
}
