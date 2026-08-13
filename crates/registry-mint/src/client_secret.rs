//! Provisioning for high-entropy client secrets.
//!
//! The raw credential is written once to an owner-only file. Only its
//! canonical SHA-256 fingerprint reaches standard output and the reloadable
//! client registry. A generated secret carries 256 bits of operating-system
//! randomness before printable base64url encoding.

use std::{
    fs::OpenOptions,
    io::{self, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_authcommon::fingerprint_api_key;
use thiserror::Error;
use zeroize::Zeroizing;

const CLIENT_SECRET_ENTROPY_BYTES: usize = 32;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Debug, Error)]
pub enum ClientSecretGenerationError {
    #[error("the operating system could not generate client-secret entropy")]
    Entropy,
    #[error("the client-secret output already exists")]
    Exists,
    #[error("the client-secret output could not be created")]
    Create,
    #[error("the client-secret output could not be written")]
    Write,
}

/// Generate one printable client secret and write it to a new owner-only file.
///
/// The return value is the non-secret fingerprint operators place in one
/// client registration. The function never replaces a file and never returns
/// or prints the raw credential.
pub fn generate(path: &Path) -> Result<String, ClientSecretGenerationError> {
    let mut entropy = Zeroizing::new([0_u8; CLIENT_SECRET_ENTROPY_BYTES]);
    getrandom::fill(entropy.as_mut_slice()).map_err(|_| ClientSecretGenerationError::Entropy)?;
    let secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(entropy.as_slice()));
    let fingerprint = fingerprint_api_key(&secret);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(PRIVATE_FILE_MODE);
    let mut file = options.open(path).map_err(|error| match error.kind() {
        io::ErrorKind::AlreadyExists => ClientSecretGenerationError::Exists,
        _ => ClientSecretGenerationError::Create,
    })?;
    file.write_all(secret.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| ClientSecretGenerationError::Write)?;
    Ok(fingerprint)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use registry_platform_authcommon::verify_api_key;

    use super::*;

    #[test]
    fn generation_writes_one_owner_only_secret_and_returns_only_its_fingerprint() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("qgis-client-secret");

        let fingerprint = generate(&path).expect("secret generates");
        let secret = fs::read_to_string(&path).expect("secret reads");
        let secret = secret.trim_end();

        assert_eq!(secret.len(), 43);
        assert!(secret
            .bytes()
            .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') }));
        assert_eq!(verify_api_key(secret, &fingerprint), Ok(true));
        assert!(!fingerprint.contains(secret));
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            PRIVATE_FILE_MODE
        );
    }

    #[test]
    fn generation_never_replaces_an_existing_file() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("qgis-client-secret");
        fs::write(&path, "existing").expect("fixture writes");

        assert!(matches!(
            generate(&path),
            Err(ClientSecretGenerationError::Exists)
        ));
        assert_eq!(fs::read_to_string(path).expect("fixture reads"), "existing");
    }

    #[test]
    fn independently_generated_credentials_do_not_repeat() {
        let directory = tempfile::tempdir().expect("temp dir");
        let first = generate(&directory.path().join("first")).expect("first generates");
        let second = generate(&directory.path().join("second")).expect("second generates");
        assert_ne!(first, second);
    }
}
