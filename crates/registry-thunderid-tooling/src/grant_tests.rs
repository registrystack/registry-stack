use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;

fn key() -> PrivateJwk {
    let mut key = registry_platform_crypto::generate_private_jwk(
        registry_platform_crypto::GeneratedKeyAlgorithm::Es384,
    )
    .unwrap();
    key.kid = Some("synthetic-client".into());
    key
}
fn serve(responses: Vec<String>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        responses
            .into_iter()
            .map(|response| {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut byte = [0u8; 1];
                while !bytes.ends_with(b"\r\n\r\n") {
                    assert!(bytes.len() < 32 * 1024);
                    stream.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                }
                let head = String::from_utf8(bytes.clone()).unwrap();
                let length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(length < 32 * 1024);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                bytes.extend(body);
                stream.write_all(response.as_bytes()).unwrap();
                String::from_utf8(bytes).unwrap()
            })
            .collect()
    });
    (base, worker)
}
fn response(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
}
fn token_response(exchange: bool) -> String {
    let extra = if exchange {
        ",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\""
    } else {
        ""
    };
    response("200 OK", "Content-Type: application/json\r\n", &format!("{{\"access_token\":\"synthetic-token\",\"token_type\":\"Bearer\",\"expires_in\":300{extra}}}"))
}
fn connection(base: &str) -> GrantConnection {
    GrantConnection {
        casework_url: base.into(),
        token_endpoint: format!("{base}/oauth2/token"),
        client_assertion_audience: base.into(),
        bootstrap_resource: "urn:casework:test".into(),
        resource: "urn:breg:test".into(),
        scopes: vec!["records:get".into()],
    }
}
const GRANT: &str = "01970000-0000-7000-8000-000000000001";

#[tokio::test]
async fn wire_uses_only_agent_bootstrap_then_fixed_target_exchange() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let assertion = format!("{{\"assertion\":\"synthetic.assertion.signature\",\"expiresAt\":{},\"grantExpiresAt\":{}}}", now+60, now+900);
    let (base, worker) = serve(vec![
        token_response(false),
        response("200 OK", "Content-Type: application/json\r\n", &assertion),
        token_response(true),
    ]);
    let credential = acquire(&connection(&base), "task-agent", key(), GRANT)
        .await
        .unwrap();
    assert_eq!(credential.grant_expires_at, now + 900);
    let requests = worker.join().unwrap();
    assert!(requests[0].contains("grant_type=client_credentials"));
    assert!(requests[0].contains("resource=urn%3Acasework%3Atest"));
    assert!(requests[0].contains("scope=casework%3Agrants%3Aassert"));
    assert!(requests[1].starts_with(&format!("POST /v1/task-grants/{GRANT}/assertion ")));
    assert!(!requests[1].to_ascii_lowercase().contains("profile"));
    assert!(
        requests[2].contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt")
    );
    assert!(requests[2].contains("resource=urn%3Abreg%3Atest"));
    assert!(requests[2].contains("scope=records%3Aget"));
}

#[tokio::test]
async fn assertion_failures_are_redacted_and_never_reach_exchange() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expired = format!(
        "{{\"assertion\":\"sensitive-canary\",\"expiresAt\":{},\"grantExpiresAt\":{}}}",
        now - 1,
        now + 900
    );
    let cases = [
        response(
            "403 Forbidden",
            "Content-Type: application/json\r\n",
            "sensitive-canary",
        ),
        response(
            "302 Found",
            "Location: http://127.0.0.1:1/private\r\n",
            "sensitive-canary",
        ),
        response("200 OK", "Content-Type: text/html\r\n", "sensitive-canary"),
        response(
            "200 OK",
            "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
            "sensitive-canary",
        ),
        response("200 OK", "Content-Type: application/json\r\n", &expired),
        response(
            "200 OK",
            "Content-Type: application/json\r\n",
            "{\"assertion\":\"sensitive-canary\"}",
        ),
    ];
    for assertion in cases {
        let (base, worker) = serve(vec![token_response(false), assertion]);
        let result = acquire(&connection(&base), "task-agent", key(), GRANT).await;
        let Err(error) = result else {
            panic!("invalid assertion was accepted")
        };
        assert!(!error.to_string().contains("sensitive-canary"));
        assert_eq!(worker.join().unwrap().len(), 2);
    }
}
