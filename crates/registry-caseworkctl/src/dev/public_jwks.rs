// SPDX-License-Identifier: Apache-2.0
//! Supervisor-owned public keys for the container's external-assertion verifier.
use super::private;
use anyhow::{Context, Result};
use registry_platform_crypto::PublicJwk;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicKeys {
    keys: Vec<PublicJwk>,
}

pub(super) fn probe(port: u16) -> Result<()> {
    TcpListener::bind(("0.0.0.0", port)).context("the explicit public JWKS port is occupied")?;
    Ok(())
}

pub(super) struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Server {
    pub fn start(port: u16, file: &Path) -> Result<Self> {
        // A typed round trip refuses private members before binding a socket.
        let keys: PublicKeys = serde_json::from_slice(&private::read(file, 64 * 1024)?)?;
        anyhow::ensure!(
            !keys.keys.is_empty() && keys.keys.len() <= 8,
            "public JWKS needs 1..8 keys"
        );
        let body = serde_json::to_vec(&keys)?;
        let listener = TcpListener::bind(("0.0.0.0", port))
            .context("cannot bind the explicit public JWKS listener")?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = respond(stream, &body);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn respond(mut stream: TcpStream, body: &[u8]) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut request = Vec::new();
    while request.len() < 4096 && Instant::now() < deadline {
        let mut buffer = [0u8; 512];
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(error.into()),
        }
    }
    let admitted = request.len() <= 4096
        && request.ends_with(b"\r\n\r\n")
        && request.split(|byte| *byte == b'\n').next()
            == Some(b"GET /oauth2/jwks HTTP/1.1\r".as_slice());
    let (status, body) = if admitted {
        ("200 OK", body)
    } else {
        ("404 Not Found", b"{}".as_slice())
    };
    write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len())?;
    stream.write_all(body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serves_only_public_keys_and_releases_its_listener() {
        let root = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let public = super::super::config::keypair(&root.path().join("key")).unwrap();
        let file = root.path().join("jwks.json");
        private::create(
            &file,
            &serde_json::to_vec(&serde_json::json!({"keys":[public]})).unwrap(),
        )
        .unwrap();
        let port = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let server = Server::start(port, &file).unwrap();
        for (method, path, expected) in [
            ("GET", "/oauth2/jwks", "200 OK"),
            ("POST", "/oauth2/jwks", "404 Not Found"),
            ("GET", "/assertion-key.jwk", "404 Not Found"),
        ] {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(
                socket,
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"
            )
            .unwrap();
            let mut response = String::new();
            socket.read_to_string(&mut response).unwrap();
            assert!(response.starts_with(&format!("HTTP/1.1 {expected}")));
            assert!(!response.contains("\"d\":"));
            if method == "GET" && path == "/oauth2/jwks" {
                assert!(response.contains("\"keys\":"));
            }
        }
        drop(server);
        probe(port).unwrap();
        private::replace(
            &file,
            b"{\"keys\":[{\"kty\":\"EC\",\"d\":\"private-canary\"}]}",
        )
        .unwrap();
        assert!(Server::start(port, &file).is_err());
        probe(port).unwrap();
    }
}
