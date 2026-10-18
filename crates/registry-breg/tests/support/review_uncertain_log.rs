// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn uncertain_submission_logs_one_bounded_value_free_transition() {
    async fn unavailable() -> Response {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "private-upstream-body-canary",
        )
            .into_response()
    }
    let authority = Authority::start(false, true).await;
    let fixture = fixture(&authority).await;
    let id = submitted(&fixture, "uncertain-log-canary").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/v1/review-requests", post(unavailable)),
        )
        .await
        .unwrap();
    });
    let remote = ReviewClient::new(ReviewClientConfig::new(endpoint.parse().unwrap())).unwrap();
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(logs.clone())
        .finish();
    let capture = tracing::subscriber::set_default(subscriber);
    let client = fixture.pool.get_for_test().await.unwrap();
    assert!(run_one_submission(
        &**client,
        AUTHORITY,
        &remote,
        "producer",
        &BearerToken::new(OUTGOING_TOKEN).unwrap(),
        30
    )
    .await
    .unwrap());
    drop(capture);
    server.abort();
    let delivered = job(&fixture, id).await;
    assert_eq!(delivered["state"], "uncertain");
    assert_eq!(delivered["error"], "remote-uncertain");
    assert!(delivered["lease"].is_null());
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let transitions = output
        .lines()
        .filter(|line| line.contains("uncertain") && line.contains("\"level\":\"WARN\""))
        .collect::<Vec<_>>();
    assert_eq!(
        transitions.len(),
        1,
        "one warning must describe the committed uncertain transition"
    );
    assert!(
        transitions[0].len() <= 2048,
        "transition logging stays bounded"
    );
    let event: Value = serde_json::from_str(transitions[0]).unwrap();
    assert!(event["fields"].is_object());
    for canary in [
        OUTGOING_TOKEN,
        INCOMING_TOKEN,
        RECIPIENT,
        "private-upstream-body-canary",
        "uncertain-log-canary",
        &id.to_string(),
        &endpoint,
        "After",
    ] {
        assert!(
            !output.contains(canary),
            "transition log must not contain source or transport values"
        );
    }
    assert_eq!(
        result_count(&fixture).await,
        0,
        "uncertainty does not manufacture review evidence"
    );
    drop(client);
    fixture.finish().await;
}
