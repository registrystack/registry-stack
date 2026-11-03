// SPDX-License-Identifier: Apache-2.0

//! Bounded, read-only SSH/SFTP host for governed-ingestion jobs.
//!
//! SFTP v3 has no portable atomic `open-beneath` or no-follow operation. The
//! client rejects observed symlinks and canonical paths outside the configured
//! tree as defense in depth, but those pathname checks cannot close a swap
//! between metadata and open. A supported deployment therefore gives this
//! dedicated read-only account server-side authority only inside the configured
//! source tree, using a chroot or equivalent server authorization policy.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use registry_adapter_engine::component::sftp::{
    validate_flat_name, SftpCompletion, SftpFile, SftpRead, SftpReadFault, SftpReadResult,
    SftpSource,
};
use registry_adapter_engine::job::JobProgram;
use registry_adapter_engine::job_sources::{SftpCredentialBinding, SftpSourceBinding};
use registry_platform_config::SecretResolver;
use russh::keys::ssh_key::{Algorithm, EcdsaCurve, PublicKey};
use russh::keys::PrivateKeyWithHashAlg;
use russh_sftp::client::{Config as SftpConfig, RawSftpSession, SftpSession};
use russh_sftp::protocol::StatusCode;
use tokio::io::AsyncReadExt as _;

/// The short modern algorithm set the client offers, in preference order.
/// It covers servers under a FIPS-style policy (NIST-curve key exchange,
/// AES-CTR with encrypt-then-MAC) as well as curve25519 and AES-GCM
/// servers, and nothing weaker: no SHA-1, CBC, 3DES, or finite-field
/// Diffie-Hellman. The AEAD ciphers carry their own integrity, so the
/// MACs apply to the CTR ciphers only.
const ACCEPTED_KEX: &[russh::kex::Name] = &[
    russh::kex::CURVE25519,
    russh::kex::ECDH_SHA2_NISTP256,
    russh::kex::ECDH_SHA2_NISTP384,
];
const ACCEPTED_CIPHERS: &[russh::cipher::Name] = &[
    russh::cipher::AES_256_GCM,
    russh::cipher::AES_128_GCM,
    russh::cipher::AES_256_CTR,
    russh::cipher::AES_128_CTR,
];
const ACCEPTED_MACS: &[russh::mac::Name] =
    &[russh::mac::HMAC_SHA256_ETM, russh::mac::HMAC_SHA512_ETM];

const SFTP_PACKET_BYTES: u32 = 256 * 1024;
const READ_CHUNK_BYTES: usize = 32 * 1024;

/// Validate every compiled SFTP host binding without opening a socket,
/// resolving a secret, or constructing an authentication client. The `check`
/// command and pass activation share this boundary.
pub fn validate_sftp_host_bindings(program: &JobProgram) -> Result<(), String> {
    for binding in program.sftp_source_bindings() {
        validate_host_binding(binding).map_err(|reason| {
            format!(
                "the SFTP source `{}` host binding was refused: {reason}",
                binding.endpoint
            )
        })?;
    }
    Ok(())
}

/// Build and register each selected SFTP source without connecting. Secret
/// resolution remains deferred until the server has proved the pinned key.
pub fn activate_sftp_sources(
    program: &mut JobProgram,
    resolver: Arc<SecretResolver>,
) -> Result<(), String> {
    validate_sftp_host_bindings(program)?;
    let bindings = program.sftp_source_bindings().cloned().collect::<Vec<_>>();
    for binding in bindings {
        let endpoint = binding.endpoint.clone();
        let source = Arc::new(RusshSftpSource::build(binding, resolver.clone())?);
        program
            .register_sftp_source(&endpoint, source)
            .map_err(|_| "the SFTP source client could not be registered".to_owned())?;
    }
    Ok(())
}

struct RusshSftpSource {
    binding: SftpSourceBinding,
    pinned_key: PublicKey,
    resolver: Arc<SecretResolver>,
    #[cfg(test)]
    disconnected: Arc<tokio::sync::Notify>,
}

impl fmt::Debug for RusshSftpSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RusshSftpSource")
            .field("endpoint", &self.binding.endpoint)
            .finish_non_exhaustive()
    }
}

impl RusshSftpSource {
    fn build(binding: SftpSourceBinding, resolver: Arc<SecretResolver>) -> Result<Self, String> {
        let pinned_key = validate_host_binding(&binding)?;
        Ok(Self {
            binding,
            pinned_key,
            resolver,
            #[cfg(test)]
            disconnected: Arc::new(tokio::sync::Notify::new()),
        })
    }

    async fn read_inner(&self, read: SftpRead) -> Result<SftpReadResult, SftpReadFault> {
        let config = russh::client::Config {
            inactivity_timeout: Some(remaining(read.deadline)?),
            nodelay: true,
            preferred: russh::Preferred {
                kex: Cow::Borrowed(ACCEPTED_KEX),
                key: Cow::Owned(vec![self.pinned_key.algorithm()]),
                host_key_certificates: Cow::Borrowed(&[]),
                cipher: Cow::Borrowed(ACCEPTED_CIPHERS),
                mac: Cow::Borrowed(ACCEPTED_MACS),
                compression: Cow::Owned(vec![russh::compression::NONE]),
            },
            ..Default::default()
        };
        // 0 means no key was presented, 1 a key was presented and refused,
        // 2 the exact pin matched. This keeps transport failures distinct from
        // pin failures without retaining any presented key.
        let verification = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let handler = PinnedHostKey {
            expected: self.pinned_key.clone(),
            verification: verification.clone(),
            #[cfg(test)]
            disconnected: self.disconnected.clone(),
        };
        let address = (self.binding.host.as_str(), self.binding.port);
        let mut ssh = tokio::time::timeout_at(
            read.deadline,
            russh::client::connect(Arc::new(config), address, handler),
        )
        .await
        .map_err(|_| SftpReadFault::Timeout)?
        .map_err(|error| {
            match (
                verification.load(std::sync::atomic::Ordering::Acquire),
                error,
            ) {
                (1, _) => SftpReadFault::HostKey,
                (_, russh::Error::NoCommonAlgo { .. }) => SftpReadFault::Negotiation,
                _ => SftpReadFault::Connection,
            }
        })?;

        // Deliberately after key verification: a wrong server receives no
        // credential lookup, password, signature, or public client key.
        let result =
            match authenticate(&mut ssh, &self.binding, &self.resolver, read.deadline).await {
                Ok(()) => match list_candidates(&ssh, &self.binding, read.deadline).await {
                    Ok(listed) => read_candidate(&ssh, listed, &read).await,
                    Err(fault) => Err(fault),
                },
                Err(fault) => Err(fault),
            };
        let disconnect = tokio::time::timeout_at(
            read.deadline,
            ssh.disconnect(russh::Disconnect::ByApplication, "", ""),
        )
        .await;
        keep_read_after_disconnect(result, matches!(disconnect, Ok(Ok(()))))
    }
}

fn validate_host_binding(binding: &SftpSourceBinding) -> Result<PublicKey, String> {
    let pinned_key = PublicKey::from_openssh(&binding.pinned_host_key)
        .map_err(|_| "the pinned host key is not one OpenSSH public key".to_owned())?;
    if !allowed_algorithm(pinned_key.algorithm()) {
        return Err("the pinned host key algorithm is not Ed25519 or P-256".to_owned());
    }
    if binding.maximum_listing_entries != binding.plan.maximum_listing_entries {
        return Err("the listing bounds disagree".to_owned());
    }
    Ok(pinned_key)
}

impl SftpSource for RusshSftpSource {
    fn read<'a>(
        &'a self,
        read: SftpRead,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<SftpReadResult, SftpReadFault>> + Send + 'a>,
    > {
        Box::pin(async move {
            match tokio::time::timeout_at(read.deadline, self.read_inner(read)).await {
                Ok(result) => result,
                Err(_) => Err(SftpReadFault::Timeout),
            }
        })
    }
}

#[derive(Clone)]
struct PinnedHostKey {
    expected: PublicKey,
    verification: Arc<std::sync::atomic::AtomicU8>,
    #[cfg(test)]
    disconnected: Arc<tokio::sync::Notify>,
}

impl russh::client::Handler for PinnedHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // OpenSSH comments are labels, not host-key identity. Pin the complete
        // decoded algorithm and key data while ignoring only that label.
        let presented = server_public_key.public_key();
        let matches = presented.algorithm() == self.expected.algorithm()
            && presented.key_data() == self.expected.key_data();
        self.verification.store(
            if matches { 2 } else { 1 },
            std::sync::atomic::Ordering::Release,
        );
        Ok(matches)
    }

    async fn disconnected(
        &mut self,
        reason: russh::client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        #[cfg(test)]
        self.disconnected.notify_one();
        match reason {
            russh::client::DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            russh::client::DisconnectReason::Error(error) => Err(error),
        }
    }
}

fn allowed_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::Ed25519
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            }
    )
}

fn remaining(deadline: tokio::time::Instant) -> Result<Duration, SftpReadFault> {
    let value = deadline.saturating_duration_since(tokio::time::Instant::now());
    if value.is_zero() {
        Err(SftpReadFault::Timeout)
    } else {
        Ok(value)
    }
}

async fn authenticate(
    ssh: &mut russh::client::Handle<PinnedHostKey>,
    binding: &SftpSourceBinding,
    resolver: &SecretResolver,
    deadline: tokio::time::Instant,
) -> Result<(), SftpReadFault> {
    let result = match &binding.credential {
        SftpCredentialBinding::Password { password_ref } => {
            let secret = resolver
                .resolve(password_ref.as_str())
                .map_err(|_| SftpReadFault::Credential)?;
            let password = std::str::from_utf8(secret.expose_secret())
                .map_err(|_| SftpReadFault::Credential)?;
            tokio::time::timeout_at(deadline, ssh.authenticate_password(&binding.user, password))
                .await
                .map_err(|_| SftpReadFault::Timeout)?
                .map_err(|_| SftpReadFault::Authentication)?
        }
        SftpCredentialBinding::PrivateKey {
            private_key_ref,
            passphrase_ref,
        } => {
            let key_secret = resolver
                .resolve(private_key_ref.as_str())
                .map_err(|_| SftpReadFault::Credential)?;
            let key_text = std::str::from_utf8(key_secret.expose_secret())
                .map_err(|_| SftpReadFault::Credential)?;
            let passphrase = passphrase_ref
                .as_ref()
                .map(|reference| resolver.resolve(reference.as_str()))
                .transpose()
                .map_err(|_| SftpReadFault::Credential)?;
            let passphrase = passphrase
                .as_ref()
                .map(|secret| std::str::from_utf8(secret.expose_secret()))
                .transpose()
                .map_err(|_| SftpReadFault::Credential)?;
            let key = russh::keys::decode_secret_key(key_text, passphrase)
                .map_err(|_| SftpReadFault::Credential)?;
            if !allowed_algorithm(key.algorithm()) {
                return Err(SftpReadFault::Credential);
            }
            tokio::time::timeout_at(
                deadline,
                ssh.authenticate_publickey(
                    &binding.user,
                    PrivateKeyWithHashAlg::new(Arc::new(key), None),
                ),
            )
            .await
            .map_err(|_| SftpReadFault::Timeout)?
            .map_err(|_| SftpReadFault::Authentication)?
        }
    };
    if result.success() {
        Ok(())
    } else {
        Err(SftpReadFault::Authentication)
    }
}

#[derive(Clone)]
struct Candidate {
    name: String,
    marker: Option<String>,
}

struct Listing {
    root: String,
    entries: u32,
    candidates: Vec<Candidate>,
}

fn sftp_config(deadline: tokio::time::Instant) -> Result<SftpConfig, SftpReadFault> {
    Ok(SftpConfig {
        max_packet_len: SFTP_PACKET_BYTES,
        max_concurrent_reads: 1,
        max_concurrent_writes: 1,
        max_write_packet_len: READ_CHUNK_BYTES as u32,
        request_timeout_secs: remaining(deadline)?.as_secs().max(1),
    })
}

async fn open_sftp_channel(
    ssh: &russh::client::Handle<PinnedHostKey>,
    deadline: tokio::time::Instant,
) -> Result<russh::ChannelStream<russh::client::Msg>, SftpReadFault> {
    let channel = tokio::time::timeout_at(deadline, ssh.channel_open_session())
        .await
        .map_err(|_| SftpReadFault::Timeout)?
        .map_err(|_| SftpReadFault::Connection)?;
    tokio::time::timeout_at(deadline, channel.request_subsystem(true, "sftp"))
        .await
        .map_err(|_| SftpReadFault::Timeout)?
        .map_err(|_| SftpReadFault::Connection)?;
    Ok(channel.into_stream())
}

async fn list_candidates(
    ssh: &russh::client::Handle<PinnedHostKey>,
    binding: &SftpSourceBinding,
    deadline: tokio::time::Instant,
) -> Result<Listing, SftpReadFault> {
    let raw = RawSftpSession::new_with_config(
        open_sftp_channel(ssh, deadline).await?,
        sftp_config(deadline)?,
    );
    tokio::time::timeout_at(deadline, raw.init())
        .await
        .map_err(|_| SftpReadFault::Timeout)?
        .map_err(|_| SftpReadFault::Listing)?;
    let canonical = tokio::time::timeout_at(deadline, raw.realpath(&binding.base_directory))
        .await
        .map_err(|_| SftpReadFault::Timeout)?
        .map_err(|_| SftpReadFault::Escape)?;
    let root = canonical
        .files
        .first()
        .map(|file| file.filename.clone())
        .filter(|path| path.starts_with('/') && !path.contains("/../"))
        .ok_or(SftpReadFault::Escape)?;
    let handle = tokio::time::timeout_at(deadline, raw.opendir(root.clone()))
        .await
        .map_err(|_| SftpReadFault::Timeout)?
        .map_err(|_| SftpReadFault::Listing)?;
    let mut entries = 0_u32;
    let mut files = Vec::new();
    let listing = async {
        loop {
            let page = tokio::time::timeout_at(deadline, raw.readdir(handle.handle.clone()))
                .await
                .map_err(|_| SftpReadFault::Timeout)?;
            let page = match page {
                Ok(page) => page,
                Err(russh_sftp::client::error::Error::Status(status))
                    if status.status_code == StatusCode::Eof =>
                {
                    break;
                }
                Err(_) => return Err(SftpReadFault::Listing),
            };
            select_listing_page(binding, page.files, deadline, &mut entries, &mut files)?;
        }
        Ok::<(), SftpReadFault>(())
    }
    .await;
    let close = tokio::time::timeout_at(deadline, raw.close(handle.handle)).await;
    let session_close = raw.close_session();
    listing?;
    close
        .map_err(|_| SftpReadFault::Timeout)?
        .map_err(|_| SftpReadFault::Close)?;
    session_close.map_err(|_| SftpReadFault::Close)?;
    let mut candidates = Vec::new();
    // One channel answers every done-file lookup of this listing.
    let mut marker_session = None;
    for (name, attrs) in files {
        if attrs.is_symlink() || !attrs.is_regular() {
            return Err(SftpReadFault::NotRegular);
        }
        let marker = if let SftpCompletion::DoneFile { pattern } = &binding.plan.completion {
            let marker_name = pattern.of(&name);
            validate_flat_name(&marker_name)?;
            let marker = joined(&root, &marker_name);
            if marker_session.is_none() {
                let session = RawSftpSession::new_with_config(
                    open_sftp_channel(ssh, deadline).await?,
                    sftp_config(deadline)?,
                );
                tokio::time::timeout_at(deadline, session.init())
                    .await
                    .map_err(|_| SftpReadFault::Timeout)?
                    .map_err(|_| SftpReadFault::Listing)?;
                marker_session = Some(session);
            }
            let attrs = marker_session.as_ref().ok_or(SftpReadFault::Listing)?;
            let ready = tokio::time::timeout_at(deadline, attrs.lstat(marker.clone())).await;
            match ready {
                Ok(Ok(value)) if value.attrs.is_regular() && !value.attrs.is_symlink() => {}
                Ok(Err(russh_sftp::client::error::Error::Status(status)))
                    if status.status_code == StatusCode::NoSuchFile =>
                {
                    continue
                }
                Ok(_) => return Err(SftpReadFault::Incomplete),
                Err(_) => return Err(SftpReadFault::Timeout),
            }
            Some(marker)
        } else {
            None
        };
        candidates.push(Candidate { name, marker });
    }
    if let Some(session) = marker_session {
        session.close_session().map_err(|_| SftpReadFault::Close)?;
    }
    candidates.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(Listing {
        root,
        entries,
        candidates,
    })
}

fn select_listing_page(
    binding: &SftpSourceBinding,
    page: Vec<russh_sftp::protocol::File>,
    deadline: tokio::time::Instant,
    entries: &mut u32,
    files: &mut Vec<(String, russh_sftp::protocol::FileAttributes)>,
) -> Result<(), SftpReadFault> {
    for file in page {
        if tokio::time::Instant::now() >= deadline {
            return Err(SftpReadFault::Timeout);
        }
        if matches!(file.filename.as_str(), "." | "..") {
            continue;
        }
        // A hidden name (a dotfile, an editor or transfer temp file) and a
        // subdirectory are never candidates, so they neither fail the read
        // nor count against the listing bound.
        if (file.filename.starts_with('.') && !file.filename.contains(['/', '\\']))
            || file.attrs.is_dir()
        {
            continue;
        }
        let included = binding
            .plan
            .include
            .as_ref()
            .is_none_or(|pattern| pattern.matches(&file.filename));
        let marker = match &binding.plan.completion {
            SftpCompletion::DoneFile { pattern } => pattern.is_done_file(&file.filename),
            SftpCompletion::CompletedName => false,
        };
        if !included || marker {
            continue;
        }
        // Only a name this read can open is validated and counted.
        validate_flat_name(&file.filename)?;
        *entries = entries
            .checked_add(1)
            .ok_or(SftpReadFault::ListingTooLarge)?;
        if *entries > binding.maximum_listing_entries {
            return Err(SftpReadFault::ListingTooLarge);
        }
        files.push((file.filename, file.attrs));
    }
    Ok(())
}

/// The read already finished and was verified by digest, so a server that
/// is slow to answer the disconnect costs nothing: keep the page and log
/// the close failure. A failed read keeps its own fault.
fn keep_read_after_disconnect(
    result: Result<SftpReadResult, SftpReadFault>,
    disconnected: bool,
) -> Result<SftpReadResult, SftpReadFault> {
    if !disconnected && result.is_ok() {
        tracing::warn!("an SFTP source session did not close cleanly after a complete read");
    }
    result
}

async fn read_candidate(
    ssh: &russh::client::Handle<PinnedHostKey>,
    listing: Listing,
    read: &SftpRead,
) -> Result<SftpReadResult, SftpReadFault> {
    let start = read
        .cursor
        .as_ref()
        .map_or("", |cursor| cursor.resume_after.as_str());
    validate_flat_name(start)
        .or_else(|fault| if start.is_empty() { Ok(()) } else { Err(fault) })?;
    let ready = listing
        .candidates
        .into_iter()
        .filter(|candidate| candidate.name.as_str() >= start)
        .collect::<Vec<_>>();
    for (index, candidate) in ready.iter().enumerate() {
        let session = SftpSession::new_with_config(
            open_sftp_channel(ssh, read.deadline).await?,
            sftp_config(read.deadline)?,
        )
        .await
        .map_err(|_| SftpReadFault::Connection)?;
        let path = joined(&listing.root, &candidate.name);
        let candidate_read = async {
            // These checks catch stable symlinks and ordinary escapes. They are
            // not an atomic jail: the server-side account confinement stated
            // in the module contract is what contains a pathname swap.
            let listed_type =
                tokio::time::timeout_at(read.deadline, session.symlink_metadata(path.clone()))
                    .await
                    .map_err(|_| SftpReadFault::Timeout)?
                    .map_err(|_| SftpReadFault::NotRegular)?;
            if listed_type.is_symlink() || !listed_type.is_regular() {
                return Err(SftpReadFault::NotRegular);
            }
            let canonical =
                tokio::time::timeout_at(read.deadline, session.canonicalize(path.clone()))
                    .await
                    .map_err(|_| SftpReadFault::Timeout)?
                    .map_err(|_| SftpReadFault::Escape)?;
            if canonical != path {
                return Err(SftpReadFault::Escape);
            }
            let mut file = tokio::time::timeout_at(read.deadline, session.open(path))
                .await
                .map_err(|_| SftpReadFault::Timeout)?
                .map_err(|_| SftpReadFault::NotRegular)?;
            let body = async {
                let before = tokio::time::timeout_at(read.deadline, file.metadata())
                    .await
                    .map_err(|_| SftpReadFault::Timeout)?
                    .map_err(|_| SftpReadFault::Listing)?;
                if before.is_symlink() || !before.is_regular() {
                    return Err(SftpReadFault::NotRegular);
                }
                if before
                    .size
                    .is_some_and(|size| size > read.maximum_file_bytes)
                {
                    return Err(SftpReadFault::TooLarge);
                }
                let mut bytes = Vec::with_capacity(
                    usize::try_from(before.size.unwrap_or(0).min(read.maximum_file_bytes))
                        .unwrap_or(0),
                );
                let mut buffer = [0_u8; READ_CHUNK_BYTES];
                loop {
                    let count = tokio::time::timeout_at(read.deadline, file.read(&mut buffer))
                        .await
                        .map_err(|_| SftpReadFault::Timeout)?
                        .map_err(|_| SftpReadFault::Connection)?;
                    if count == 0 {
                        break;
                    }
                    let total = bytes
                        .len()
                        .checked_add(count)
                        .ok_or(SftpReadFault::TooLarge)?;
                    if total as u64 > read.maximum_file_bytes {
                        return Err(SftpReadFault::TooLarge);
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                let after = tokio::time::timeout_at(read.deadline, file.metadata())
                    .await
                    .map_err(|_| SftpReadFault::Timeout)?
                    .map_err(|_| SftpReadFault::Listing)?;
                if before.size != after.size || before.mtime != after.mtime {
                    return Err(SftpReadFault::Incomplete);
                }
                Ok(bytes)
            }
            .await;
            let close = tokio::time::timeout_at(read.deadline, file.close())
                .await
                .map_err(|_| SftpReadFault::Timeout)?
                .map_err(|_| SftpReadFault::Close);
            let bytes = body?;
            close?;
            if let Some(marker) = &candidate.marker {
                let marker = tokio::time::timeout_at(
                    read.deadline,
                    session.symlink_metadata(marker.clone()),
                )
                .await
                .map_err(|_| SftpReadFault::Timeout)?
                .map_err(|_| SftpReadFault::Incomplete)?;
                if marker.is_symlink() || !marker.is_regular() {
                    return Err(SftpReadFault::Incomplete);
                }
            }
            Ok(bytes)
        }
        .await;
        tokio::time::timeout_at(read.deadline, session.close())
            .await
            .map_err(|_| SftpReadFault::Timeout)?
            .map_err(|_| SftpReadFault::Close)?;
        let bytes = candidate_read?;
        if let Some(cursor) = &read.cursor {
            let digest = registry_platform_config::sha256_uri(&bytes);
            if cursor.resume_after == candidate.name
                && cursor.digest == digest
                && cursor.position >= bytes.len() as u64
            {
                continue;
            }
        }
        return Ok(SftpReadResult {
            file: Some(SftpFile {
                name: candidate.name.clone(),
                bytes,
            }),
            more_candidates: index + 1 < ready.len(),
            listing_entries: listing.entries,
        });
    }
    Ok(SftpReadResult {
        file: None,
        more_candidates: false,
        listing_entries: listing.entries,
    })
}

fn joined(root: &str, name: &str) -> String {
    if root == "/" {
        format!("/{name}")
    } else {
        format!("{root}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use registry_adapter_engine::component::sftp::{SftpCursor, SftpPlan};
    use registry_adapter_engine::job_sources::DoneFileName;
    use registry_platform_config::SecretProvider;
    use registry_platform_yaml::SecretReference;
    use russh::server::{Auth, Server as _, Session};
    use russh::{Channel, ChannelId};
    use russh_sftp::protocol::{
        Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, Version,
    };
    use tokio::sync::Mutex;

    // Deterministic encrypted Ed25519 fixtures from russh's own key tests.
    const TEST_HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABDLGyfA39
J2FcJygtYqi5ISAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIN+Wjn4+4Fcvl2Jl
KpggT+wCRxpSvtqqpVrQrKN1/A22AAAAkOHDLnYZvYS6H9Q3S3Nk4ri3R2jAZlQlBbUos5
FkHpYgNw65KCWCTXtP7ye2czMC3zjn2r98pJLobsLYQgRiHIv/CUdAdsqbvMPECB+wl/UQ
e+JpiSq66Z6GIt0801skPh20jxOO3F52SoX1IeO5D5PXfZrfSZlw6S8c7bwyp2FHxDewRx
7/wNsnDM0T7nLv/Q==
-----END OPENSSH PRIVATE KEY-----";
    const WRONG_HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD1phlku5
A2G7Q9iP+DcOc9AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHeLC1lWiCYrXsf/
85O/pkbUFZ6OGIt49PX3nw8iRoXEAAAAkKRF0st5ZI7xxo9g6A4m4l6NarkQre3mycqNXQ
dP3jryYgvsCIBAA5jMWSjrmnOTXhidqcOy4xYCrAttzSnZ/cUadfBenL+DQq6neffw7j8r
0tbCxVGp6yCQlKrgSZf6c0Hy7dNEIU2bJFGxLe6/kWChcUAt/5Ll5rI7DVQPJdLgehLzvv
sJWR7W+cGvJ/vLsw==
-----END OPENSSH PRIVATE KEY-----";

    #[derive(Clone)]
    struct Entry {
        bytes: Vec<u8>,
        attrs: FileAttributes,
        stall: bool,
    }

    impl Entry {
        fn regular(bytes: &[u8]) -> Self {
            let mut attrs = FileAttributes {
                size: Some(bytes.len() as u64),
                mtime: Some(1),
                ..Default::default()
            };
            attrs.set_regular(true);
            Self {
                bytes: bytes.to_vec(),
                attrs,
                stall: false,
            }
        }
    }

    #[derive(Default)]
    struct TestState {
        listing: Vec<String>,
        entries: BTreeMap<String, Entry>,
        directory_read: bool,
        stall_after_listing_page: bool,
        off_root: bool,
        swap_outside_on_open: bool,
        scoped_authority: bool,
        remove_marker_on_read: bool,
        auth_calls: AtomicUsize,
        outside_open_attempts: AtomicUsize,
        outside_bytes_served: AtomicUsize,
        writes: AtomicUsize,
        closes: AtomicUsize,
    }

    #[derive(Clone)]
    struct TestServer {
        state: Arc<Mutex<TestState>>,
    }

    impl russh::server::Server for TestServer {
        type Handler = TestSsh;

        fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
            TestSsh {
                state: self.state.clone(),
                channels: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    struct TestSsh {
        state: Arc<Mutex<TestState>>,
        channels: Arc<Mutex<HashMap<ChannelId, Channel<russh::server::Msg>>>>,
    }

    impl russh::server::Handler for TestSsh {
        type Error = russh::Error;

        async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
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
                .expect("the test server retained the opened channel");
            session.channel_success(channel_id)?;
            russh_sftp::server::run(
                channel.into_stream(),
                TestSftp {
                    state: self.state.clone(),
                },
            )
            .await;
            Ok(())
        }
    }

    struct TestSftp {
        state: Arc<Mutex<TestState>>,
    }

    impl russh_sftp::server::Handler for TestSftp {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        async fn init(
            &mut self,
            _: u32,
            _: HashMap<String, String>,
        ) -> Result<Version, Self::Error> {
            Ok(Version::new())
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
                let stall = state.stall_after_listing_page;
                drop(state);
                if stall {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                return Err(StatusCode::Eof);
            }
            state.directory_read = true;
            let files = state
                .listing
                .iter()
                .map(|name| {
                    let attrs = state
                        .entries
                        .get(name)
                        .map_or_else(FileAttributes::default, |entry| entry.attrs.clone());
                    File::new(name, attrs)
                })
                .collect();
            Ok(Name { id, files })
        }

        async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
            let state = self.state.lock().await;
            let path = if state.off_root && path != "/in" {
                format!("/outside/{}", path.rsplit('/').next().unwrap_or("file"))
            } else {
                path
            };
            Ok(Name {
                id,
                files: vec![File::dummy(path)],
            })
        }

        async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
            let name = path.rsplit('/').next().ok_or(StatusCode::NoSuchFile)?;
            let state = self.state.lock().await;
            let entry = state.entries.get(name).ok_or(StatusCode::NoSuchFile)?;
            Ok(Attrs {
                id,
                attrs: entry.attrs.clone(),
            })
        }

        async fn open(
            &mut self,
            id: u32,
            filename: String,
            pflags: OpenFlags,
            _: FileAttributes,
        ) -> Result<Handle, Self::Error> {
            if !pflags.contains(OpenFlags::READ)
                || pflags.intersects(
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
            let state = self.state.lock().await;
            if state.swap_outside_on_open {
                state.outside_open_attempts.fetch_add(1, Ordering::Relaxed);
                // The name was regular and canonical while the client checked
                // it, then changed before open. A scoped account refuses the
                // now-off-root target instead of returning this outside handle.
                if state.scoped_authority {
                    return Err(StatusCode::PermissionDenied);
                }
                return Ok(Handle {
                    id,
                    handle: "outside-target".to_owned(),
                });
            }
            Ok(Handle {
                id,
                handle: filename,
            })
        }

        async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
            if handle == "outside-target" {
                let mut attrs = FileAttributes {
                    size: Some(b"outside-secret".len() as u64),
                    mtime: Some(1),
                    ..Default::default()
                };
                attrs.set_regular(true);
                return Ok(Attrs { id, attrs });
            }
            self.lstat(id, handle).await
        }

        async fn read(
            &mut self,
            id: u32,
            handle: String,
            offset: u64,
            len: u32,
        ) -> Result<Data, Self::Error> {
            if handle == "outside-target" {
                self.state
                    .lock()
                    .await
                    .outside_bytes_served
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(Data {
                    id,
                    data: b"outside-secret".to_vec(),
                });
            }
            let name = handle.rsplit('/').next().ok_or(StatusCode::NoSuchFile)?;
            let (bytes, stall) = {
                let mut state = self.state.lock().await;
                let entry = state.entries.get(name).ok_or(StatusCode::NoSuchFile)?;
                let result = (entry.bytes.clone(), entry.stall);
                if state.remove_marker_on_read && name == "people.csv" {
                    state.entries.remove("people.csv.done");
                    state.remove_marker_on_read = false;
                }
                result
            };
            if stall {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            let start = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
            if start >= bytes.len() {
                return Err(StatusCode::Eof);
            }
            let end = start.saturating_add(len as usize).min(bytes.len());
            Ok(Data {
                id,
                data: bytes[start..end].to_vec(),
            })
        }

        async fn close(&mut self, id: u32, _: String) -> Result<Status, Self::Error> {
            self.state
                .lock()
                .await
                .closes
                .fetch_add(1, Ordering::Relaxed);
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

    struct Harness {
        port: u16,
        host_key: String,
        state: Arc<Mutex<TestState>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn server(state: TestState) -> Harness {
        server_offering(state, russh::Preferred::DEFAULT).await
    }

    async fn server_offering(state: TestState, preferred: russh::Preferred) -> Harness {
        let state = Arc::new(Mutex::new(state));
        let key =
            russh::keys::decode_secret_key(TEST_HOST_KEY, Some("blabla")).expect("test host key");
        let host_key = key.public_key().to_openssh().expect("OpenSSH host key");
        let listener = Box::leak(Box::new(
            tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("test listener"),
        ));
        let port = listener.local_addr().expect("local address").port();
        let config = Arc::new(russh::server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![key],
            preferred,
            ..Default::default()
        });
        let server = Box::leak(Box::new(TestServer {
            state: state.clone(),
        }));
        let running = server.run_on_socket(config, listener);
        let task = tokio::spawn(async move {
            let _ = running.await;
        });
        Harness {
            port,
            host_key,
            state,
            task,
        }
    }

    fn test_source(harness: &Harness, host_key: String) -> RusshSftpSource {
        let binding = SftpSourceBinding {
            endpoint: "source".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: harness.port,
            user: "reader".to_owned(),
            base_directory: "/in".to_owned(),
            pinned_host_key: host_key,
            credential: SftpCredentialBinding::Password {
                password_ref: SecretReference::parse("secret:env/ADAPTER_SFTP_TEST_PASSWORD")
                    .expect("secret reference"),
            },
            maximum_listing_entries: 16,
            plan: SftpPlan {
                namespace: "people".to_owned(),
                include: Some(
                    registry_adapter_engine::job_sources::FlatGlob::compile("*.csv")
                        .expect("test include glob"),
                ),
                completion: SftpCompletion::DoneFile {
                    pattern: DoneFileName::Placeholder {
                        prefix: String::new(),
                        suffix: ".done".to_owned(),
                    },
                },
                maximum_listing_entries: 16,
            },
        };
        let resolver = Arc::new(
            SecretResolver::new([SecretProvider::Environment], "/").expect("environment resolver"),
        );
        RusshSftpSource::build(binding, resolver).expect("valid test source")
    }

    fn read(deadline: Duration, maximum_file_bytes: u64) -> SftpRead {
        SftpRead {
            cursor: None,
            maximum_file_bytes,
            deadline: tokio::time::Instant::now() + deadline,
        }
    }

    #[tokio::test]
    async fn done_file_gates_partial_file_and_completed_file_is_read_only() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        let mut state = TestState {
            listing: vec!["people.csv".to_owned()],
            ..Default::default()
        };
        state
            .entries
            .insert("people.csv".to_owned(), Entry::regular(b"id\n1\n"));
        let harness = server(state).await;
        let source = test_source(&harness, harness.host_key.clone());
        let partial = source
            .read(read(Duration::from_secs(2), 1024))
            .await
            .expect("partial listing is not a transport failure");
        assert!(partial.file.is_none());
        {
            let mut state = harness.state.lock().await;
            state.listing.push("people.csv.done".to_owned());
            state
                .entries
                .insert("people.csv.done".to_owned(), Entry::regular(b""));
        }
        let completed = source
            .read(read(Duration::from_secs(2), 1024))
            .await
            .expect("completed file");
        assert_eq!(completed.file.expect("ready file").bytes, b"id\n1\n");
        let state = harness.state.lock().await;
        assert_eq!(state.writes.load(Ordering::Relaxed), 0);
        assert!(state.closes.load(Ordering::Relaxed) >= 3);
    }

    #[tokio::test]
    async fn stalled_and_oversize_reads_are_bounded() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        let mut state = TestState {
            listing: vec!["people.csv".to_owned(), "people.csv.done".to_owned()],
            ..Default::default()
        };
        let mut entry = Entry::regular(b"0123456789");
        entry.stall = true;
        state.entries.insert("people.csv".to_owned(), entry);
        state
            .entries
            .insert("people.csv.done".to_owned(), Entry::regular(b""));
        let harness = server(state).await;
        let source = test_source(&harness, harness.host_key.clone());
        assert!(matches!(
            source.read(read(Duration::from_millis(100), 1024)).await,
            Err(SftpReadFault::Timeout)
        ));
        tokio::time::timeout(Duration::from_millis(500), source.disconnected.notified())
            .await
            .expect("the cancelled read terminates the independent russh session task");
        harness
            .state
            .lock()
            .await
            .entries
            .get_mut("people.csv")
            .expect("entry")
            .stall = false;
        assert!(matches!(
            source.read(read(Duration::from_secs(2), 4)).await,
            Err(SftpReadFault::TooLarge)
        ));
    }

    #[test]
    fn a_complete_read_survives_a_slow_disconnect() {
        let page = SftpReadResult {
            file: None,
            more_candidates: false,
            listing_entries: 0,
        };
        assert!(keep_read_after_disconnect(Ok(page), false).is_ok());
        assert!(matches!(
            keep_read_after_disconnect(Err(SftpReadFault::Authentication), false),
            Err(SftpReadFault::Authentication)
        ));
    }

    #[tokio::test]
    async fn done_file_removed_during_read_refuses_the_partial_handover() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        let mut state = TestState {
            listing: vec!["people.csv".to_owned(), "people.csv.done".to_owned()],
            remove_marker_on_read: true,
            ..Default::default()
        };
        state
            .entries
            .insert("people.csv".to_owned(), Entry::regular(b"data"));
        state
            .entries
            .insert("people.csv.done".to_owned(), Entry::regular(b""));
        let harness = server(state).await;
        let source = test_source(&harness, harness.host_key.clone());
        assert!(matches!(
            source.read(read(Duration::from_secs(2), 1024)).await,
            Err(SftpReadFault::Incomplete)
        ));
    }

    #[tokio::test]
    async fn replaced_same_name_is_not_skipped_by_the_old_digest() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        let mut state = TestState {
            listing: vec!["people.csv".to_owned(), "people.csv.done".to_owned()],
            ..Default::default()
        };
        state
            .entries
            .insert("people.csv".to_owned(), Entry::regular(b"old"));
        state
            .entries
            .insert("people.csv.done".to_owned(), Entry::regular(b""));
        let harness = server(state).await;
        let source = test_source(&harness, harness.host_key.clone());
        let first = source
            .read(read(Duration::from_secs(2), 1024))
            .await
            .expect("first read")
            .file
            .expect("first file");
        harness
            .state
            .lock()
            .await
            .entries
            .insert("people.csv".to_owned(), Entry::regular(b"replacement"));
        let replaced = source
            .read(SftpRead {
                cursor: Some(SftpCursor {
                    resume_after: "people.csv".to_owned(),
                    digest: registry_platform_config::sha256_uri(&first.bytes),
                    position: first.bytes.len() as u64,
                }),
                maximum_file_bytes: 1024,
                deadline: tokio::time::Instant::now() + Duration::from_secs(2),
            })
            .await
            .expect("replacement read")
            .file
            .expect("replacement file");
        assert_eq!(replaced.bytes, b"replacement");
    }

    #[tokio::test]
    async fn traversal_symlink_and_off_root_candidates_are_refused() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        let traversal = TestState {
            listing: vec!["../outside.csv".to_owned()],
            ..Default::default()
        };
        let harness = server(traversal).await;
        let source = test_source(&harness, harness.host_key.clone());
        assert!(matches!(
            source.read(read(Duration::from_secs(2), 1024)).await,
            Err(SftpReadFault::Traversal)
        ));

        let mut symlink = TestState {
            listing: vec!["people.csv".to_owned(), "people.csv.done".to_owned()],
            ..Default::default()
        };
        let mut link = Entry::regular(b"target");
        link.attrs.set_regular(false);
        link.attrs.set_symlink(true);
        symlink.entries.insert("people.csv".to_owned(), link);
        symlink
            .entries
            .insert("people.csv.done".to_owned(), Entry::regular(b""));
        let harness = server(symlink).await;
        let source = test_source(&harness, harness.host_key.clone());
        assert!(matches!(
            source.read(read(Duration::from_secs(2), 1024)).await,
            Err(SftpReadFault::NotRegular)
        ));

        let mut outside = TestState {
            listing: vec!["people.csv".to_owned(), "people.csv.done".to_owned()],
            off_root: true,
            ..Default::default()
        };
        outside
            .entries
            .insert("people.csv".to_owned(), Entry::regular(b"data"));
        outside
            .entries
            .insert("people.csv.done".to_owned(), Entry::regular(b""));
        let harness = server(outside).await;
        let source = test_source(&harness, harness.host_key.clone());
        assert!(matches!(
            source.read(read(Duration::from_secs(2), 1024)).await,
            Err(SftpReadFault::Escape)
        ));
    }

    #[tokio::test]
    async fn server_scoped_authority_refuses_a_symlink_swap_before_open() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        let mut state = TestState {
            listing: vec!["people.csv".to_owned(), "people.csv.done".to_owned()],
            swap_outside_on_open: true,
            scoped_authority: true,
            ..Default::default()
        };
        state
            .entries
            .insert("people.csv".to_owned(), Entry::regular(b"inside"));
        state
            .entries
            .insert("people.csv.done".to_owned(), Entry::regular(b""));
        let harness = server(state).await;
        let source = test_source(&harness, harness.host_key.clone());
        assert!(matches!(
            source.read(read(Duration::from_secs(2), 1024)).await,
            Err(SftpReadFault::NotRegular)
        ));
        let state = harness.state.lock().await;
        assert_eq!(state.outside_open_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(state.outside_bytes_served.load(Ordering::Relaxed), 0);
    }

    fn ready_state(listing: &[&str]) -> TestState {
        let mut state = TestState {
            listing: listing.iter().map(|name| (*name).to_owned()).collect(),
            ..Default::default()
        };
        for name in listing {
            state
                .entries
                .insert((*name).to_owned(), Entry::regular(b"id\n1\n"));
        }
        state
    }

    /// Hidden files and editor or transfer temp names beside the data are
    /// not candidates, so they cannot fail the read.
    #[tokio::test]
    async fn hidden_entries_beside_the_data_are_skipped() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        let harness = server(ready_state(&[
            ".DS_Store",
            ".people.csv.XyZ12",
            "people.csv",
            "people.csv.done",
        ]))
        .await;
        let source = test_source(&harness, harness.host_key.clone());
        let read = source
            .read(read(Duration::from_secs(2), 1024))
            .await
            .expect("hidden entries do not fail the read");
        assert_eq!(read.file.expect("the data file").name, "people.csv");
    }

    /// With no include glob a subdirectory is not a candidate and does not
    /// fail the read.
    #[tokio::test]
    async fn a_subdirectory_is_skipped_when_no_include_glob_is_declared() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        let mut state = ready_state(&["people.csv", "people.csv.done"]);
        let mut archive = Entry::regular(b"");
        archive.attrs.set_regular(false);
        archive.attrs.set_dir(true);
        state.listing.insert(0, "archive".to_owned());
        state.entries.insert("archive".to_owned(), archive);
        let harness = server(state).await;
        let mut source = test_source(&harness, harness.host_key.clone());
        source.binding.plan.include = None;
        let read = source
            .read(read(Duration::from_secs(2), 1024))
            .await
            .expect("a subdirectory does not fail the read");
        assert_eq!(read.file.expect("the data file").name, "people.csv");
    }

    /// The listing cap counts the entries a read can use, not every name in
    /// the directory.
    #[tokio::test]
    async fn the_listing_cap_counts_only_matching_entries() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        let mut names = (0..40)
            .map(|index| format!("old-{index}.tmp"))
            .collect::<Vec<_>>();
        names.extend(["people.csv".to_owned(), "people.csv.done".to_owned()]);
        let names = names.iter().map(String::as_str).collect::<Vec<_>>();
        let harness = server(ready_state(&names)).await;
        let source = test_source(&harness, harness.host_key.clone());
        let read = source
            .read(read(Duration::from_secs(2), 1024))
            .await
            .expect("unrelated names do not count against the cap");
        assert_eq!(read.file.expect("the data file").name, "people.csv");
        assert_eq!(read.listing_entries, 1);
    }

    fn offering(
        kex: russh::kex::Name,
        cipher: russh::cipher::Name,
        mac: russh::mac::Name,
    ) -> russh::Preferred {
        russh::Preferred {
            kex: Cow::Owned(vec![kex]),
            cipher: Cow::Owned(vec![cipher]),
            mac: Cow::Owned(vec![mac]),
            ..russh::Preferred::DEFAULT
        }
    }

    /// Institutional servers under a FIPS-style policy offer NIST-curve key
    /// exchange and AES-CTR with encrypt-then-MAC, not curve25519 and
    /// AES-GCM.
    #[tokio::test]
    async fn a_server_offering_only_nist_key_exchange_and_aes_ctr_is_readable() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        for (kex, cipher, mac) in [
            (
                russh::kex::ECDH_SHA2_NISTP256,
                russh::cipher::AES_256_CTR,
                russh::mac::HMAC_SHA256_ETM,
            ),
            (
                russh::kex::ECDH_SHA2_NISTP384,
                russh::cipher::AES_128_CTR,
                russh::mac::HMAC_SHA512_ETM,
            ),
            (
                russh::kex::CURVE25519,
                russh::cipher::AES_128_GCM,
                russh::mac::HMAC_SHA256_ETM,
            ),
        ] {
            let harness = server_offering(
                ready_state(&["people.csv", "people.csv.done"]),
                offering(kex, cipher, mac),
            )
            .await;
            let source = test_source(&harness, harness.host_key.clone());
            let read = source
                .read(read(Duration::from_secs(2), 1024))
                .await
                .unwrap_or_else(|fault| panic!("{kex:?} {cipher:?} {mac:?}: {fault:?}"));
            assert_eq!(read.file.expect("the data file").name, "people.csv");
        }
    }

    /// A server whose algorithms do not overlap is a negotiation failure
    /// with its own fault, not a generic connection failure.
    #[tokio::test]
    async fn a_server_with_no_shared_algorithm_is_a_negotiation_fault() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        let harness = server_offering(
            ready_state(&["people.csv", "people.csv.done"]),
            offering(
                russh::kex::DH_G14_SHA256,
                russh::cipher::AES_256_CTR,
                russh::mac::HMAC_SHA256_ETM,
            ),
        )
        .await;
        let source = test_source(&harness, harness.host_key.clone());
        assert!(matches!(
            source.read(read(Duration::from_secs(2), 1024)).await,
            Err(SftpReadFault::Negotiation)
        ));
    }

    #[tokio::test]
    async fn large_listing_remains_under_the_operation_deadline() {
        std::env::set_var("ADAPTER_SFTP_TEST_PASSWORD", "test-password");
        let state = TestState {
            listing: (0..1_500)
                .map(|index| format!("item-{index}.tmp"))
                .collect(),
            stall_after_listing_page: true,
            ..Default::default()
        };
        let harness = server(state).await;
        let mut source = test_source(&harness, harness.host_key.clone());
        source.binding.maximum_listing_entries = 2_000;
        source.binding.plan.maximum_listing_entries = 2_000;
        source.binding.plan.include = Some(
            registry_adapter_engine::job_sources::FlatGlob::compile(&format!(
                "{}*.csv",
                "é".repeat(500)
            ))
            .expect("bounded large include glob"),
        );
        let started = tokio::time::Instant::now();
        assert!(matches!(
            source.read(read(Duration::from_millis(100), 1024)).await,
            Err(SftpReadFault::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(harness.state.lock().await.directory_read);
    }

    #[tokio::test]
    async fn large_listing_cpu_loop_checks_the_deadline_it_owns() {
        let harness = server(TestState::default()).await;
        let mut source = test_source(&harness, harness.host_key.clone());
        source.binding.maximum_listing_entries = 2_000;
        source.binding.plan.maximum_listing_entries = 2_000;
        let page = (0..1_500)
            .map(|index| {
                russh_sftp::protocol::File::new(
                    format!("item-{index}.csv"),
                    FileAttributes::default(),
                )
            })
            .collect();
        let mut entries = 0;
        let mut selected = Vec::new();
        assert!(matches!(
            select_listing_page(
                &source.binding,
                page,
                tokio::time::Instant::now(),
                &mut entries,
                &mut selected,
            ),
            Err(SftpReadFault::Timeout)
        ));
        assert!(selected.is_empty());
    }

    #[tokio::test]
    async fn incorrect_host_key_does_not_reach_credential_resolution_or_authentication() {
        let harness = server(TestState::default()).await;
        let wrong = russh::keys::decode_secret_key(WRONG_HOST_KEY, Some("test"))
            .expect("wrong host key")
            .public_key()
            .to_openssh()
            .expect("OpenSSH wrong key");
        let mut source = test_source(&harness, wrong);
        source.resolver = Arc::new(SecretResolver::disabled());
        assert!(matches!(
            source.read(read(Duration::from_secs(2), 1024)).await,
            Err(SftpReadFault::HostKey)
        ));
        assert_eq!(
            harness
                .state
                .lock()
                .await
                .auth_calls
                .load(Ordering::Relaxed),
            0
        );
    }
}
