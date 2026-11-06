// SPDX-License-Identifier: Apache-2.0

//! What the serve suites share to start the real `registry-render` binary on
//! a loopback port and to know that the listener answering there is the
//! child they started.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::FileExt as _;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

/// A loopback port no other fixture in this test binary has been given.
/// Port discovery releases the socket before the child binds it, so every
/// issued port is kept distinct and parallel fixtures cannot reach each
/// other's server. Another socket can still take the port meanwhile; the
/// server then exits with "Address already in use", and the caller retries
/// after [`move_to_fresh_port`].
pub fn free_port() -> u16 {
    static ISSUED_PORTS: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());
    let mut issued = ISSUED_PORTS.lock().expect("issued test ports");
    for _ in 0..1024 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind for port discovery");
        let port = listener.local_addr().expect("local addr").port();
        if issued.insert(port) {
            return port;
        }
    }
    panic!("could not allocate a distinct fixture port");
}

/// Point the runtime file's listener at a fresh [`free_port`].
pub fn move_to_fresh_port(runtime_path: &Path) {
    let text = std::fs::read_to_string(runtime_path).unwrap();
    let bind = text
        .lines()
        .find(|l| l.contains("bind:"))
        .expect("listener bind");
    let (address, _) = bind.rsplit_once(':').expect("bind port");
    let moved = text.replacen(bind, &format!("{address}:{}", free_port()), 1);
    std::fs::write(runtime_path, moved).unwrap();
}

/// Everything the server has written to `stderr`, its standard error file,
/// so far. The file is read with `read_exact_at`, which leaves untouched
/// the file offset the child writes at.
pub fn server_output(stderr: &File) -> String {
    let length = stderr.metadata().expect("server stderr metadata").len();
    let mut output = vec![0; usize::try_from(length).expect("server stderr length")];
    stderr
        .read_exact_at(&mut output, 0)
        .expect("read server stderr");
    String::from_utf8_lossy(&output).into_owned()
}

/// Whether the listener on `port` is a Render server: `/health` answers
/// 200 with the renderer version. A bare connect is not enough: `free_port`
/// releases its port before the server binds it, and another test's socket
/// (often a `free_port` probe given the same just-freed port) can hold it
/// meanwhile. The server then exits with "Address already in use", and a
/// request sent to the other socket is reset. Any failure here means "not
/// this server yet"; the caller checks for that exit and bounds the wait.
/// The answer may still come from another test's server given the same
/// port; [`logged_health_request`] settles which server answered.
pub fn answers_render_health(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .is_err()
        || stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .is_err()
    {
        return false;
    }
    let mut raw = Vec::new();
    if stream.read_to_end(&mut raw).is_err() {
        return false;
    }
    raw.starts_with(b"HTTP/1.1 200") && raw.windows(17).any(|w| w == b"\"rendererVersion\"")
}

/// Whether this server's own standard error records a `/health` request,
/// which shows the listener that answered [`answers_render_health`] is this
/// child.
pub fn logged_health_request(stderr: &File) -> bool {
    server_output(stderr)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .any(|line| {
            line["fields"]["message"] == "request completed" && line["fields"]["route"] == "/health"
        })
}
