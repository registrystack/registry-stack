// SPDX-License-Identifier: Apache-2.0

//! A loopback-only SSH/SFTP source for the operational CLI acceptance test.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use russh::server::{Auth, Server as _, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use tokio::sync::Mutex;

pub const CLIENT_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABDLGyfA39
J2FcJygtYqi5ISAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIN+Wjn4+4Fcvl2Jl
KpggT+wCRxpSvtqqpVrQrKN1/A22AAAAkOHDLnYZvYS6H9Q3S3Nk4ri3R2jAZlQlBbUos5
FkHpYgNw65KCWCTXtP7ye2czMC3zjn2r98pJLobsLYQgRiHIv/CUdAdsqbvMPECB+wl/UQ
e+JpiSq66Z6GIt0801skPh20jxOO3F52SoX1IeO5D5PXfZrfSZlw6S8c7bwyp2FHxDewRx
7/wNsnDM0T7nLv/Q==
-----END OPENSSH PRIVATE KEY-----";
pub const CLIENT_KEY_PASSPHRASE: &str = "blabla";

const P256_HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQ/i+HCsmZZPy0JhtT64vW7EmeA1DeA
M/VnPq3vAhu+xooJ7IMMK3lUHlBDosyvA2enNbCWyvNQc25dVt4oh9RhAAAAqHG7WMFxu1
jBAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD+L4cKyZlk/LQmG
1Pri9bsSZ4DUN4Az9Wc+re8CG77GignsgwwreVQeUEOizK8DZ6c1sJbK81Bzbl1W3iiH1G
EAAAAgLAmXR6IlN0SdiD6o8qr+vUr0mXLbajs/m0UlegElOmoAAAANcm9iZXJ0QGJic2Rl
dgECAw==
-----END OPENSSH PRIVATE KEY-----";

#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    directory_read: bool,
    auth_calls: AtomicUsize,
    writes: AtomicUsize,
}

pub struct SftpSourceServer {
    pub port: u16,
    pub host_key: String,
    state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}

impl SftpSourceServer {
    pub async fn start(bytes: &[u8]) -> Self {
        let state = Arc::new(Mutex::new(State {
            bytes: bytes.to_vec(),
            ..Default::default()
        }));
        let key = russh::keys::decode_secret_key(P256_HOST_KEY, None).expect("P-256 host key");
        let host_key = key.public_key().to_openssh().expect("OpenSSH host key");
        let listener = Box::leak(Box::new(
            tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("SFTP listener"),
        ));
        let port = listener.local_addr().expect("SFTP address").port();
        let config = Arc::new(russh::server::Config {
            auth_rejection_time: std::time::Duration::ZERO,
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            keys: vec![key],
            ..Default::default()
        });
        let server = Box::leak(Box::new(Server {
            state: state.clone(),
        }));
        let running = server.run_on_socket(config, listener);
        let task = tokio::spawn(async move {
            let _ = running.await;
        });
        Self {
            port,
            host_key,
            state,
            task,
        }
    }

    pub async fn replace(&self, bytes: &[u8]) {
        self.state.lock().await.bytes = bytes.to_vec();
    }

    pub async fn auth_calls(&self) -> usize {
        self.state.lock().await.auth_calls.load(Ordering::Relaxed)
    }

    pub async fn writes(&self) -> usize {
        self.state.lock().await.writes.load(Ordering::Relaxed)
    }
}

impl Drop for SftpSourceServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct Server {
    state: Arc<Mutex<State>>,
}

impl russh::server::Server for Server {
    type Handler = SshHandler;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        SshHandler {
            state: self.state.clone(),
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

struct SshHandler {
    state: Arc<Mutex<State>>,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<russh::server::Msg>>>>,
}

impl russh::server::Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        self.state
            .lock()
            .await
            .auth_calls
            .fetch_add(1, Ordering::Relaxed);
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        let channel = self
            .channels
            .lock()
            .await
            .remove(&channel_id)
            .expect("the SSH handler retained the SFTP channel");
        session.channel_success(channel_id)?;
        russh_sftp::server::run(
            channel.into_stream(),
            SftpHandler {
                state: self.state.clone(),
            },
        )
        .await;
        Ok(())
    }
}

struct SftpHandler {
    state: Arc<Mutex<State>>,
}

impl russh_sftp::server::Handler for SftpHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _: u32, _: HashMap<String, String>) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(Name {
            id,
            files: vec![File::dummy(path)],
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        if path != "/in" {
            return Err(StatusCode::PermissionDenied);
        }
        self.state.lock().await.directory_read = false;
        Ok(Handle { id, handle: path })
    }

    async fn readdir(&mut self, id: u32, _: String) -> Result<Name, Self::Error> {
        let mut state = self.state.lock().await;
        if state.directory_read {
            return Err(StatusCode::Eof);
        }
        state.directory_read = true;
        let mut attrs = FileAttributes {
            size: Some(state.bytes.len() as u64),
            mtime: Some(1),
            ..Default::default()
        };
        attrs.set_regular(true);
        Ok(Name {
            id,
            files: vec![File::new("submissions.csv", attrs)],
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        if path != "/in/submissions.csv" {
            return Err(StatusCode::PermissionDenied);
        }
        let state = self.state.lock().await;
        let mut attrs = FileAttributes {
            size: Some(state.bytes.len() as u64),
            mtime: Some(1),
            ..Default::default()
        };
        attrs.set_regular(true);
        Ok(Attrs { id, attrs })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        if filename != "/in/submissions.csv"
            || !flags.contains(OpenFlags::READ)
            || flags.intersects(
                OpenFlags::WRITE
                    | OpenFlags::APPEND
                    | OpenFlags::CREATE
                    | OpenFlags::TRUNCATE
                    | OpenFlags::EXCLUDE,
            )
        {
            self.state
                .lock()
                .await
                .writes
                .fetch_add(1, Ordering::Relaxed);
            return Err(StatusCode::PermissionDenied);
        }
        Ok(Handle {
            id,
            handle: filename,
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        self.lstat(id, handle).await
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        if handle != "/in/submissions.csv" {
            return Err(StatusCode::PermissionDenied);
        }
        let state = self.state.lock().await;
        let start = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
        if start >= state.bytes.len() {
            return Err(StatusCode::Eof);
        }
        let end = start.saturating_add(len as usize).min(state.bytes.len());
        Ok(Data {
            id,
            data: state.bytes[start..end].to_vec(),
        })
    }

    async fn close(&mut self, id: u32, _: String) -> Result<Status, Self::Error> {
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    async fn write(
        &mut self,
        _: u32,
        _: String,
        _: u64,
        _: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        self.state
            .lock()
            .await
            .writes
            .fetch_add(1, Ordering::Relaxed);
        Err(StatusCode::PermissionDenied)
    }
}
