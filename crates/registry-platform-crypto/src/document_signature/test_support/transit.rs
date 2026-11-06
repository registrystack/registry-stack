// SPDX-License-Identifier: Apache-2.0
//! A Transit signing proxy for tests.
//!
//! [`TestTransit::start`] answers the two requests a
//! [`TransitSigner`](crate::TransitSigner) sends over its Unix socket, the key
//! read and the prehashed ES256 sign call, for one ECDSA P-256 key version,
//! signing with a private JWK the test holds, such as a [`TestSeal`]'s. A
//! request for any other key, version or route is answered as a real proxy
//! would refuse it, so a client fault surfaces as a refusal rather than a
//! hang. Nothing here is fit for production signing.
//!
//! [`TestSeal`]: super::TestSeal

use std::io::{Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{EncodePublicKey as _, LineEnding};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::TestPkiError;
use crate::PrivateJwk;

/// The largest request the proxy reads, headers and body together.
const MAX_REQUEST_BYTES: usize = 128 * 1024;

/// A Transit signing proxy on a Unix socket, serving one key version until
/// it is dropped.
pub struct TestTransit {
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    signatures: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
}

/// What the proxy serves: the key's routes and what they answer.
struct TransitKey {
    metadata_path: String,
    sign_path: String,
    key_version: u32,
    metadata: Value,
    signing_key: SigningKey,
}

impl TestTransit {
    /// Serve key `key_name` version `key_version` of the `mount` Transit
    /// mount at `socket`, a path that must not exist yet, signing with `key`,
    /// a P-256 private JWK. The key read reports a non-exportable,
    /// non-derived `ecdsa-p256` signing key whose only signing version is
    /// `key_version`.
    pub fn start(
        socket: &Path,
        mount: &str,
        key_name: &str,
        key_version: u32,
        key: &PrivateJwk,
    ) -> Result<Self, TestPkiError> {
        Self::start_with(socket, mount, key_name, key_version, key, |_| {})
    }

    /// [`TestTransit::start`], with the key read document passed to
    /// `customise` before it is served, to make a key the signer must refuse.
    pub fn start_with(
        socket: &Path,
        mount: &str,
        key_name: &str,
        key_version: u32,
        key: &PrivateJwk,
        customise: impl FnOnce(&mut Value),
    ) -> Result<Self, TestPkiError> {
        if key.kty != "EC" || key.crv.as_deref() != Some("P-256") {
            return Err(TestPkiError::TransitKey);
        }
        let scalar = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(key.d.as_deref().ok_or(TestPkiError::TransitKey)?)
                .map_err(|_| TestPkiError::TransitKey)?,
        );
        let signing_key = SigningKey::from_slice(&scalar).map_err(|_| TestPkiError::TransitKey)?;
        let public_key = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|_| TestPkiError::TransitKey)?;
        let mut metadata = json!({
            "data": {
                "type": "ecdsa-p256",
                "derived": false,
                "exportable": false,
                "allow_plaintext_backup": false,
                "supports_signing": true,
                "latest_version": key_version,
                "min_encryption_version": key_version,
                "keys": {key_version.to_string(): {"public_key": public_key}}
            }
        });
        customise(&mut metadata);
        let served = TransitKey {
            metadata_path: format!("/v1/{mount}/keys/{key_name}"),
            sign_path: format!("/v1/{mount}/sign/{key_name}/sha2-256"),
            key_version,
            metadata,
            signing_key,
        };

        let listener = UnixListener::bind(socket)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let signatures = Arc::new(AtomicUsize::new(0));
        let worker_stop = Arc::clone(&stop);
        let worker_signatures = Arc::clone(&signatures);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if worker_stop.load(Ordering::Acquire) {
                            break;
                        }
                        served.answer(&mut stream, &worker_signatures);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("the test Transit proxy stopped accepting: {error}"),
                }
            }
        });
        Ok(Self {
            socket: socket.to_path_buf(),
            stop,
            signatures,
            worker: Some(worker),
        })
    }

    /// The socket the proxy listens on.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// How many sign calls the proxy has answered with a signature.
    #[must_use]
    pub fn signatures(&self) -> usize {
        self.signatures.load(Ordering::Acquire)
    }
}

impl Drop for TestTransit {
    /// Stop serving; the socket file stays, so a later connection is
    /// refused as it is when a proxy has gone away.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Wake the accept loop; it may already have stopped.
        let _ = UnixStream::connect(&self.socket);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() && !thread::panicking() {
                panic!("the test Transit proxy failed");
            }
        }
    }
}

impl TransitKey {
    /// Answer one connection. A request that cannot be read is answered
    /// 400; an unknown route 404.
    fn answer(&self, stream: &mut UnixStream, signatures: &AtomicUsize) {
        let (status, document) = match stream
            .set_nonblocking(false)
            .and_then(|()| stream.set_read_timeout(Some(Duration::from_secs(2))))
            .map_err(|_| ())
            .and_then(|()| read_request(stream))
        {
            Err(()) => (400, json!({"errors": ["the request could not be read"]})),
            Ok((method, path, body)) => {
                if method == "GET" && path == self.metadata_path {
                    (200, self.metadata.clone())
                } else if method == "POST" && path == self.sign_path {
                    match self.sign(&body) {
                        Some(document) => {
                            signatures.fetch_add(1, Ordering::AcqRel);
                            (200, document)
                        }
                        None => (400, json!({"errors": ["invalid sign request"]})),
                    }
                } else {
                    (404, json!({"errors": []}))
                }
            }
        };
        let bytes = document.to_string();
        let reason = if status == 200 { "OK" } else { "ERROR" };
        // The client sees a write failure as a refused call.
        let _ = write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{bytes}",
            bytes.len()
        );
    }

    /// The signature document for a prehashed ES256 sign request with the
    /// served version, or `None` for any other request.
    fn sign(&self, body: &[u8]) -> Option<Value> {
        let request: Value = serde_json::from_slice(body).ok()?;
        if request["key_version"].as_str() != Some(self.key_version.to_string().as_str())
            || request["marshaling_algorithm"] != "jws"
            || request["prehashed"] != true
        {
            return None;
        }
        let digest = STANDARD.decode(request["input"].as_str()?).ok()?;
        if digest.len() != 32 {
            return None;
        }
        let signature: Signature = self.signing_key.sign_prehash(&digest).ok()?;
        Some(json!({
            "data": {
                "signature": format!(
                    "vault:v{}:{}",
                    self.key_version,
                    URL_SAFE_NO_PAD.encode(signature.to_bytes())
                )
            }
        }))
    }
}

/// The method, path and body of one HTTP/1.1 request.
fn read_request(stream: &mut UnixStream) -> Result<(String, String, Vec<u8>), ()> {
    let mut request = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > MAX_REQUEST_BYTES {
            return Err(());
        }
        if let Some(position) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&request[..header_end]).map_err(|_| ())?;
    // A Transit proxy serves only requests that mark the proxy hop.
    if !headers
        .to_ascii_lowercase()
        .contains("x-vault-request: true")
    {
        return Err(());
    }
    let mut lines = headers.lines();
    let mut request_line = lines.next().ok_or(())?.split_whitespace();
    let method = request_line.next().ok_or(())?.to_owned();
    let path = request_line.next().ok_or(())?.to_owned();
    let content_length = match lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        Some((_, value)) => value.trim().parse::<usize>().map_err(|_| ())?,
        None => 0,
    };
    if header_end + content_length > MAX_REQUEST_BYTES {
        return Err(());
    }
    while request.len() < header_end + content_length {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        request.extend_from_slice(&chunk[..read]);
    }
    Ok((
        method,
        path,
        request[header_end..header_end + content_length].to_vec(),
    ))
}
