// SPDX-License-Identifier: Apache-2.0

//! A scripted loopback SMTP relay for the provider's tests.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// What the stub does at one point of the session.
#[derive(Clone, Debug)]
pub(crate) enum Act {
    Reply(&'static str),
    /// Close the connection without replying.
    Drop,
    /// Never reply.
    Stall,
}

/// The session one stub plays. Each field is the stub's answer at that
/// point; `EHLO`, `AUTH`, `RSET`, `NOOP`, and `QUIT` always succeed.
#[derive(Clone)]
pub(crate) struct Script {
    pub greeting: Act,
    pub mail: Act,
    pub rcpt: Act,
    pub data: Act,
    pub end_of_data: Act,
    pub advertise_auth: bool,
    pub starttls: Option<Arc<ServerConfig>>,
    pub implicit_tls: Option<Arc<ServerConfig>>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            greeting: Act::Reply("220 stub.example.test ESMTP ready"),
            mail: Act::Reply("250 2.1.0 Ok"),
            rcpt: Act::Reply("250 2.1.5 Ok"),
            data: Act::Reply("354 End data with <CR><LF>.<CR><LF>"),
            end_of_data: Act::Reply("250 2.0.0 Ok: queued as 4BCD12345"),
            advertise_auth: false,
            starttls: None,
            implicit_tls: None,
        }
    }
}

/// What the stub saw.
#[derive(Clone, Debug, Default)]
pub(crate) struct Recorded {
    pub connections: usize,
    /// Every command line, in order, with its line ending removed.
    pub commands: Vec<String>,
    /// The content of the last `DATA`, dot-unstuffed, without the marker.
    pub content: Option<String>,
    /// Whether the session was encrypted when `MAIL FROM` arrived.
    pub mail_encrypted: Option<bool>,
}

pub(crate) struct Stub {
    pub address: SocketAddr,
    recorded: Arc<Mutex<Recorded>>,
}

impl Stub {
    pub(crate) async fn start(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub relay");
        let address = listener.local_addr().expect("stub address");
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let shared = Arc::clone(&recorded);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                shared.lock().expect("recorded lock").connections += 1;
                tokio::spawn(serve(stream, script.clone(), Arc::clone(&shared)));
            }
        });
        Self { address, recorded }
    }

    pub(crate) fn recorded(&self) -> Recorded {
        self.recorded.lock().expect("recorded lock").clone()
    }
}

enum Next<S> {
    Closed,
    Upgrade(S),
}

async fn serve(stream: TcpStream, script: Script, recorded: Arc<Mutex<Recorded>>) {
    if let Some(config) = &script.implicit_tls {
        let Ok(tls) = TlsAcceptor::from(Arc::clone(config)).accept(stream).await else {
            return;
        };
        let mut reader = BufReader::new(tls);
        if answer(&mut reader, &script.greeting).await {
            session(reader, &script, &recorded, true).await;
        }
        return;
    }
    let mut reader = BufReader::new(stream);
    if !answer(&mut reader, &script.greeting).await {
        return;
    }
    match session(reader, &script, &recorded, false).await {
        Next::Closed => {}
        Next::Upgrade(stream) => {
            let config = script.starttls.clone().expect("upgrade only when offered");
            let Ok(tls) = TlsAcceptor::from(config).accept(stream).await else {
                return;
            };
            session(BufReader::new(tls), &script, &recorded, true).await;
        }
    }
}

async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    mut reader: BufReader<S>,
    script: &Script,
    recorded: &Arc<Mutex<Recorded>>,
    encrypted: bool,
) -> Next<S> {
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return Next::Closed,
            Ok(_) => {}
        }
        let command = line.trim_end_matches(['\r', '\n']).to_owned();
        recorded
            .lock()
            .expect("recorded lock")
            .commands
            .push(command.clone());
        let verb = command
            .split([' ', ':'])
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let act = match verb.as_str() {
            "EHLO" | "HELO" => {
                let mut reply = String::from("250-stub.example.test\r\n250-8BITMIME\r\n");
                if script.starttls.is_some() && !encrypted {
                    reply.push_str("250-STARTTLS\r\n");
                }
                if script.advertise_auth {
                    reply.push_str("250-AUTH PLAIN LOGIN\r\n");
                }
                reply.push_str("250 SMTPUTF8\r\n");
                if write(&mut reader, &reply).await {
                    continue;
                }
                return Next::Closed;
            }
            "STARTTLS" if script.starttls.is_some() && !encrypted => {
                if write(&mut reader, "220 2.0.0 Ready to start TLS\r\n").await {
                    return Next::Upgrade(reader.into_inner());
                }
                return Next::Closed;
            }
            "AUTH" => Act::Reply("235 2.7.0 Authentication successful"),
            "MAIL" => {
                recorded.lock().expect("recorded lock").mail_encrypted = Some(encrypted);
                script.mail.clone()
            }
            "RCPT" => script.rcpt.clone(),
            "DATA" => {
                let act = script.data.clone();
                if !answer(&mut reader, &act).await {
                    return Next::Closed;
                }
                if !matches!(act, Act::Reply(reply) if reply.starts_with("354")) {
                    continue;
                }
                let Some(content) = read_content(&mut reader).await else {
                    return Next::Closed;
                };
                recorded.lock().expect("recorded lock").content = Some(content);
                script.end_of_data.clone()
            }
            "QUIT" => {
                write(&mut reader, "221 2.0.0 Bye\r\n").await;
                return Next::Closed;
            }
            "RSET" | "NOOP" => Act::Reply("250 2.0.0 Ok"),
            _ => Act::Reply("502 5.5.2 Command not recognized"),
        };
        if !answer(&mut reader, &act).await {
            return Next::Closed;
        }
    }
}

async fn read_content<S: AsyncRead + AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
) -> Option<String> {
    let mut content = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await.ok()? == 0 {
            return None;
        }
        if line == ".\r\n" {
            return Some(content);
        }
        content.push_str(line.strip_prefix('.').unwrap_or(&line));
    }
}

/// Play one act. False when the connection is over.
async fn answer<S: AsyncRead + AsyncWrite + Unpin>(reader: &mut BufReader<S>, act: &Act) -> bool {
    match act {
        Act::Reply(reply) => write(reader, &format!("{reply}\r\n")).await,
        Act::Drop => false,
        Act::Stall => std::future::pending().await,
    }
}

async fn write<S: AsyncRead + AsyncWrite + Unpin>(reader: &mut BufReader<S>, text: &str) -> bool {
    let stream = reader.get_mut();
    stream.write_all(text.as_bytes()).await.is_ok() && stream.flush().await.is_ok()
}
