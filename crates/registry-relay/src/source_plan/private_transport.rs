// SPDX-License-Identifier: Apache-2.0
//! Restart-only loading of private CA and mTLS destination material.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use registry_platform_httputil::destination::{
    CredentialDestinationPolicy, DataDestinationPolicy, DestinationTlsMaterial,
    MAX_DESTINATION_CA_BUNDLE_BYTES, MAX_DESTINATION_CLIENT_IDENTITY_BYTES,
};
use thiserror::Error;
use zeroize::Zeroizing;

use super::artifact::DestinationDocument;

/// One hash-covered private transport reference.
///
/// It intentionally implements neither `Debug` nor serialization. Paths and
/// environment-variable names stay inside restart-only activation.
pub(super) struct CompiledDestinationTransport {
    ca: Option<CompiledCaReference>,
    mtls: Option<CompiledMtlsReference>,
}

struct CompiledCaReference {
    path: PathBuf,
    generation: u64,
}

struct CompiledMtlsReference {
    certificate_path: PathBuf,
    private_key_environment: Box<str>,
    generation: u64,
}

/// Value-free activation failures. No path, environment name, certificate,
/// or key material can reach diagnostics through this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum PrivateTransportActivationError {
    #[error("configured destination transport reference is invalid")]
    InvalidReference,
    #[error("configured destination transport file could not be loaded securely")]
    FileLoadFailed,
    #[error("configured destination transport secret could not be loaded")]
    SecretLoadFailed,
    #[error("configured destination TLS material is invalid")]
    InvalidTlsMaterial,
    #[error("configured destination TLS material could not be bound")]
    BindingFailed,
}

impl CompiledDestinationTransport {
    pub(super) fn from_document(destination: &DestinationDocument) -> Option<Self> {
        if destination.ca.is_none() && destination.mtls.is_none() {
            return None;
        }
        Some(Self {
            ca: destination.ca.as_ref().map(|ca| CompiledCaReference {
                path: ca.file.clone(),
                generation: ca.generation,
            }),
            mtls: destination.mtls.as_ref().map(|mtls| CompiledMtlsReference {
                certificate_path: mtls.certificate_file.clone(),
                private_key_environment: mtls.private_key.secret.as_str().into(),
                generation: mtls.generation,
            }),
        })
    }

    pub(super) fn activate_data(
        &self,
        destination: &mut DataDestinationPolicy,
    ) -> Result<(), PrivateTransportActivationError> {
        destination
            .install_configured_tls(self.load_material()?)
            .map_err(|_| PrivateTransportActivationError::BindingFailed)
    }

    pub(super) fn activate_credential(
        &self,
        destination: &mut CredentialDestinationPolicy,
    ) -> Result<(), PrivateTransportActivationError> {
        destination
            .install_configured_tls(self.load_material()?)
            .map_err(|_| PrivateTransportActivationError::BindingFailed)
    }

    fn load_material(&self) -> Result<DestinationTlsMaterial, PrivateTransportActivationError> {
        let ca = self
            .ca
            .as_ref()
            .map(|reference| {
                if reference.generation == 0 {
                    return Err(PrivateTransportActivationError::InvalidReference);
                }
                read_owner_only_regular_file(&reference.path, MAX_DESTINATION_CA_BUNDLE_BYTES)
            })
            .transpose()?;
        let identity = self
            .mtls
            .as_ref()
            .map(|reference| {
                if reference.generation == 0 {
                    return Err(PrivateTransportActivationError::InvalidReference);
                }
                let certificate = read_owner_only_regular_file(
                    &reference.certificate_path,
                    MAX_DESTINATION_CLIENT_IDENTITY_BYTES,
                )?;
                let private_key = read_secret_environment(&reference.private_key_environment)?;
                let capacity = certificate
                    .len()
                    .checked_add(1)
                    .and_then(|bytes| bytes.checked_add(private_key.len()))
                    .filter(|bytes| *bytes <= MAX_DESTINATION_CLIENT_IDENTITY_BYTES)
                    .ok_or(PrivateTransportActivationError::InvalidTlsMaterial)?;
                let mut identity = Zeroizing::new(Vec::with_capacity(capacity));
                identity.extend_from_slice(&certificate);
                if !certificate.ends_with(b"\n") {
                    identity.push(b'\n');
                }
                identity.extend_from_slice(&private_key);
                Ok(identity)
            })
            .transpose()?;
        DestinationTlsMaterial::from_pem(
            ca.as_deref(),
            identity.as_ref().map(|value| value.as_slice()),
        )
        .map_err(|_| PrivateTransportActivationError::InvalidTlsMaterial)
    }
}

fn read_owner_only_regular_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, PrivateTransportActivationError> {
    let mut file = open_read_only_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| PrivateTransportActivationError::FileLoadFailed)?;
    if !metadata.is_file() {
        return Err(PrivateTransportActivationError::FileLoadFailed);
    }
    validate_owner_only(&metadata)?;
    let max_bytes_u64 =
        u64::try_from(max_bytes).map_err(|_| PrivateTransportActivationError::FileLoadFailed)?;
    if metadata.len() > max_bytes_u64 {
        return Err(PrivateTransportActivationError::FileLoadFailed);
    }
    let read_cap = max_bytes_u64
        .checked_add(1)
        .ok_or(PrivateTransportActivationError::FileLoadFailed)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(read_cap)
        .read_to_end(&mut bytes)
        .map_err(|_| PrivateTransportActivationError::FileLoadFailed)?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(PrivateTransportActivationError::FileLoadFailed);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_read_only_no_follow(path: &Path) -> Result<File, PrivateTransportActivationError> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| PrivateTransportActivationError::FileLoadFailed)?;
    Ok(File::from(descriptor))
}

#[cfg(windows)]
fn open_read_only_no_follow(path: &Path) -> Result<File, PrivateTransportActivationError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| PrivateTransportActivationError::FileLoadFailed)
}

#[cfg(not(any(unix, windows)))]
fn open_read_only_no_follow(path: &Path) -> Result<File, PrivateTransportActivationError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PrivateTransportActivationError::FileLoadFailed)?;
    if metadata.file_type().is_symlink() {
        return Err(PrivateTransportActivationError::FileLoadFailed);
    }
    File::open(path).map_err(|_| PrivateTransportActivationError::FileLoadFailed)
}

#[cfg(unix)]
fn validate_owner_only(metadata: &fs::Metadata) -> Result<(), PrivateTransportActivationError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode();
    let owner = metadata.uid();
    let effective_user = rustix::process::geteuid().as_raw();
    // Trust roots and client certificates grant destination authority, while
    // the paired key is secret. Requiring the same 0400/0600 boundary for all
    // referenced files keeps deployment review and replacement semantics
    // simple and prevents a less privileged local user from changing either.
    if mode & 0o177 != 0 || mode & 0o400 == 0 || (owner != 0 && owner != effective_user) {
        return Err(PrivateTransportActivationError::FileLoadFailed);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only(_metadata: &fs::Metadata) -> Result<(), PrivateTransportActivationError> {
    Ok(())
}

fn read_secret_environment(
    name: &str,
) -> Result<Zeroizing<Vec<u8>>, PrivateTransportActivationError> {
    let value = std::env::var_os(name).ok_or(PrivateTransportActivationError::SecretLoadFailed)?;
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        value.as_os_str().as_bytes().to_vec()
    };
    #[cfg(not(unix))]
    let bytes = value
        .to_str()
        .ok_or(PrivateTransportActivationError::SecretLoadFailed)?
        .as_bytes()
        .to_vec();
    let bytes = Zeroizing::new(bytes);
    if bytes.is_empty() || bytes.len() > MAX_DESTINATION_CLIENT_IDENTITY_BYTES {
        return Err(PrivateTransportActivationError::SecretLoadFailed);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use registry_platform_httputil::destination::{DestinationProfile, DestinationTlsMaterial};
    use tempfile::TempDir;

    use super::*;

    fn environment_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write_owner_only(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write TLS fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("restrict TLS fixture");
        }
    }

    fn policy() -> DataDestinationPolicy {
        DataDestinationPolicy::new(
            "private-registry",
            "https://registry.example.test/",
            DestinationProfile::ProductionHttps,
            &[],
        )
        .expect("destination policy")
        .require_configured_tls()
    }

    fn pem(label: &str, der: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let encoded = STANDARD.encode(der);
        let body = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).expect("base64 is UTF-8"))
            .collect::<Vec<_>>()
            .join("\n");
        format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
    }

    #[test]
    fn guarded_loader_binds_private_ca_and_mtls_without_exposing_references() {
        let _lock = environment_lock();
        let directory = TempDir::new().expect("temporary TLS directory");
        let ca_path = directory.path().join("source-ca.pem");
        let certificate_path = directory.path().join("client.pem");
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["registry.example.test".to_owned()])
                .expect("generate TLS fixture");
        let certificate_pem = pem("CERTIFICATE", cert.der().as_ref());
        write_owner_only(&ca_path, certificate_pem.as_bytes());
        write_owner_only(&certificate_path, certificate_pem.as_bytes());
        let secret_name = "REGISTRY_RELAY_TEST_MTLS_KEY";
        std::env::set_var(secret_name, pem("PRIVATE KEY", &key_pair.serialize_der()));

        let transport = CompiledDestinationTransport {
            ca: Some(CompiledCaReference {
                path: ca_path.clone(),
                generation: 2,
            }),
            mtls: Some(CompiledMtlsReference {
                certificate_path: certificate_path.clone(),
                private_key_environment: secret_name.into(),
                generation: 3,
            }),
        };
        let mut destination = policy();
        transport
            .activate_data(&mut destination)
            .expect("private transport activates");
        let diagnostic = format!("{destination:?}");
        assert!(diagnostic.contains("tls: configured"));
        assert!(!diagnostic.contains(ca_path.to_string_lossy().as_ref()));
        assert!(!diagnostic.contains(certificate_path.to_string_lossy().as_ref()));
        assert!(!diagnostic.contains(secret_name));
        std::env::remove_var(secret_name);
    }

    #[test]
    fn guarded_loader_rejects_missing_material_and_invalid_tls_without_value_bearing_errors() {
        let _lock = environment_lock();
        let directory = TempDir::new().expect("temporary TLS directory");
        let missing = CompiledDestinationTransport {
            ca: Some(CompiledCaReference {
                path: directory.path().join("missing.pem"),
                generation: 1,
            }),
            mtls: None,
        };
        assert_eq!(
            missing.activate_data(&mut policy()),
            Err(PrivateTransportActivationError::FileLoadFailed)
        );

        let malformed_path = directory.path().join("malformed.pem");
        write_owner_only(&malformed_path, b"not a certificate");
        let malformed = CompiledDestinationTransport {
            ca: Some(CompiledCaReference {
                path: malformed_path,
                generation: 1,
            }),
            mtls: None,
        };
        let error = malformed.activate_data(&mut policy()).unwrap_err();
        assert_eq!(error, PrivateTransportActivationError::InvalidTlsMaterial);
        assert!(!format!("{error:?}").contains(directory.path().to_string_lossy().as_ref()));

        assert_eq!(
            DestinationTlsMaterial::from_pem(None, None).unwrap_err(),
            registry_platform_httputil::destination::DestinationTlsMaterialError::Empty
        );
    }

    #[cfg(unix)]
    #[test]
    fn guarded_loader_rejects_group_readable_files_and_symbolic_links() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = TempDir::new().expect("temporary TLS directory");
        let real = directory.path().join("real.pem");
        write_owner_only(&real, b"not parsed because permissions fail first");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o640))
            .expect("widen TLS fixture permissions");
        assert_eq!(
            read_owner_only_regular_file(&real, MAX_DESTINATION_CA_BUNDLE_BYTES),
            Err(PrivateTransportActivationError::FileLoadFailed)
        );

        fs::set_permissions(&real, fs::Permissions::from_mode(0o600))
            .expect("restore TLS fixture permissions");
        let link = directory.path().join("link.pem");
        symlink(&real, &link).expect("create TLS fixture symlink");
        assert_eq!(
            read_owner_only_regular_file(&link, MAX_DESTINATION_CA_BUNDLE_BYTES),
            Err(PrivateTransportActivationError::FileLoadFailed)
        );
    }
}
