//! `registry-render keygen`: the PKCS #10 request a certificate authority
//! issues a seal certificate from, for a seal key in a key file or in
//! Transit.
//!
//! A key file is written owner-only as the private JWK a `local-jwk`
//! signer's `privateKeyRef` reads: generated here, or converted from an
//! unencrypted PKCS #8 PEM with `--from-pem`. A Transit key, the one a
//! `transit` signer names, stays in Transit: it signs the request through the
//! signing proxy, and only the request is written. The conversion, the
//! Transit signer and the request are `registry-platform-crypto`'s. No output
//! file may exist beforehand, and no key material is ever printed.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::Duration;

use registry_platform_crypto::{
    certificate_request, generate_seal_key, private_seal_key_json, seal_key_from_pkcs8_pem,
    CertificateRequest, CertificateRequestError, CertificateRequestSubject, LocalJwkSigner,
    SealKeyError, SigningAlgorithm, SigningProvider, TransitInitializationError, TransitSigner,
    TransitSignerConfig,
};
use zeroize::Zeroizing;

use crate::problem::{ProblemKind, RenderProblem};

/// A PEM private key is a few kilobytes; a larger `--from-pem` file is not
/// one.
const MAX_PEM_BYTES: u64 = 64 * 1024;

/// How long keygen waits for each Transit request. An operator runs keygen
/// by hand, once per key version, so a slow proxy is waited for.
const TRANSIT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// What `keygen` writes, and from what.
pub struct KeygenRequest<'a> {
    /// Where the seal key is held, and so whether a key file is written.
    pub key: SealKey<'a>,
    /// The PEM certificate request file to create.
    pub csr: &'a Path,
    pub subject: CertificateRequestSubject,
}

/// Where a seal key is held.
pub enum SealKey<'a> {
    /// A private JWK file keygen creates owner-only, for a `local-jwk`
    /// signer.
    File {
        path: &'a Path,
        /// The seal algorithm. Generation defaults to ES256; an imported key
        /// signs with the algorithm its curve fixes, or RS256 for RSA.
        algorithm: Option<SigningAlgorithm>,
        /// An unencrypted PKCS #8 PEM key to convert instead of generating
        /// one.
        from_pem: Option<&'a Path>,
    },
    /// An ECDSA P-256 key version held by Transit, named as a `transit`
    /// signer names it. It signs the request; no key file is written.
    Transit {
        unix_socket_path: &'a Path,
        mount: &'a str,
        key_name: &'a str,
        key_version: u32,
    },
}

/// Write the request, and the key file for a [`SealKey::File`], then print
/// where they are and what comes next. Every refusal happens before any
/// file is created, except a write that fails part way, which removes what
/// it created.
pub fn run(request: &KeygenRequest<'_>, out: &mut impl Write) -> Result<i32, RenderProblem> {
    match request.key {
        SealKey::File {
            path,
            algorithm,
            from_pem,
        } => run_with_key_file(request, path, algorithm, from_pem, out),
        SealKey::Transit {
            unix_socket_path,
            mount,
            key_name,
            key_version,
        } => run_with_transit_key(request, unix_socket_path, mount, key_name, key_version, out),
    }
}

fn run_with_key_file(
    request: &KeygenRequest<'_>,
    key: &Path,
    algorithm: Option<SigningAlgorithm>,
    from_pem: Option<&Path>,
    out: &mut impl Write,
) -> Result<i32, RenderProblem> {
    if same_file(key, request.csr) {
        return Err(invalid(
            "--key and --csr name the same file; give each its own path",
        ));
    }
    if let Some(pem) = from_pem {
        if same_file(pem, key) || same_file(pem, request.csr) {
            return Err(invalid(
                "--from-pem names an output file; keygen writes --key and --csr as new files",
            ));
        }
    }

    let jwk = match from_pem {
        Some(pem) => import(pem, algorithm)?,
        None => generate_seal_key(algorithm.unwrap_or(SigningAlgorithm::Es256))
            .map_err(|error| internal(&format!("the seal key could not be generated: {error}")))?,
    };
    let algorithm = jwk
        .alg
        .clone()
        .ok_or_else(|| internal("the seal key carries no algorithm"))?;
    let key_json = private_seal_key_json(&jwk)
        .map_err(|error| internal(&format!("the seal key could not be written: {error}")))?;
    let signer = LocalJwkSigner::new(jwk)
        .map_err(|error| internal(&format!("the seal key cannot sign: {error}")))?;

    let csr = signing_runtime()?.block_on(signed_request(&request.subject, &signer))?;

    write_pair(key, &key_json, request.csr, csr.to_pem().as_bytes())?;
    writeln!(
        out,
        "wrote the {algorithm} seal key to {} (owner-only; it is never printed)\n\
         wrote its certificate request to {}\n\
         Have a certificate authority issue a seal certificate from the request: a leaf with \
         basicConstraints CA:FALSE and the digitalSignature or nonRepudiation key usage. \
         Point signer.privateKeyRef at the key file and certificateChainFile at the issued \
         chain, the seal certificate first.",
        key.display(),
        request.csr.display(),
    )
    .map_err(|error| internal(&format!("the summary could not be printed: {error}")))?;
    Ok(0)
}

/// Read the Transit key's public half, check that Transit keeps the key and
/// signs with it, and have it sign the request.
fn run_with_transit_key(
    request: &KeygenRequest<'_>,
    unix_socket_path: &Path,
    mount: &str,
    key_name: &str,
    key_version: u32,
    out: &mut impl Write,
) -> Result<i32, RenderProblem> {
    let socket = std::path::absolute(unix_socket_path).map_err(|error| {
        invalid(&format!(
            "--transit-unix-socket-path {} cannot be read as a path: {error}",
            unix_socket_path.display()
        ))
    })?;
    let csr = signing_runtime()?.block_on(async {
        let config = TransitSignerConfig::discover(
            socket,
            mount,
            key_name,
            key_version,
            TRANSIT_ATTEMPT_TIMEOUT,
        )
        .await
        .map_err(transit_refusal)?;
        let signer = TransitSigner::initialize(config)
            .await
            .map_err(transit_refusal)?;
        signed_request(&request.subject, &signer).await
    })?;

    let mut file = create_new(request.csr, 0o644)?;
    let written = file
        .write_all(csr.to_pem().as_bytes())
        .and_then(|()| file.sync_all());
    if let Err(error) = written {
        drop(file);
        return Err(with_removed(
            invalid(&format!("the request could not be written: {error}")),
            &[request.csr],
        ));
    }
    writeln!(
        out,
        "wrote a certificate request for Transit key {mount}/{key_name} version {key_version} \
         to {}; the key stays in Transit\n\
         Have a certificate authority issue a seal certificate from the request: a leaf with \
         basicConstraints CA:FALSE and the digitalSignature or nonRepudiation key usage. \
         Point certificateChainFile at the issued chain, the seal certificate first, and sign \
         with signer.type: transit naming this key version, under trust: production.",
        request.csr.display(),
    )
    .map_err(|error| internal(&format!("the summary could not be printed: {error}")))?;
    Ok(0)
}

/// A runtime for one signing call; a Transit signer's requests need its
/// I/O and timers.
fn signing_runtime() -> Result<tokio::runtime::Runtime, RenderProblem> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| internal(&format!("the signing runtime could not start: {error}")))
}

async fn signed_request(
    subject: &CertificateRequestSubject,
    signer: &dyn SigningProvider,
) -> Result<CertificateRequest, RenderProblem> {
    certificate_request(subject, signer)
        .await
        .map_err(|error| match error {
            CertificateRequestError::Subject { .. } => invalid(&error.to_string()),
            other => internal(&format!(
                "the certificate request could not be signed: {other}"
            )),
        })
}

/// The Transit key cannot sign the request: the refusal names the cause,
/// which carries no path, provider answer or key material, and the flag
/// that fixes it.
fn transit_refusal(error: TransitInitializationError) -> RenderProblem {
    use TransitInitializationError as Fault;
    let fix = match error {
        Fault::Client | Fault::Unavailable => {
            "Start the Transit signing proxy listening on --transit-unix-socket-path, reachable \
             by this user."
        }
        Fault::Refused => {
            "Check --transit-mount and --transit-key-name, and give the proxy's token a policy \
             that reads that key and signs with it."
        }
        Fault::ProviderFailed => "Unseal Transit or restore its storage backend.",
        Fault::Custody => {
            "Name with --transit-key-name a Transit key of type ecdsa-p256 that is neither \
             derived nor exportable and allows no plaintext backup."
        }
        Fault::KeyVersionNotCreated | Fault::KeyVersionRetired | Fault::PublicKeyMismatch => {
            "Give --transit-key-version a version between the key's min_encryption_version and \
             latest_version."
        }
        Fault::SelfTest => {
            "Check that the proxy's token may sign with the key; its self-test signature did \
             not verify."
        }
        _ => {
            "Check that --transit-unix-socket-path is a Vault or OpenBao Transit signing proxy \
             and that --transit-mount, --transit-key-name and --transit-key-version name the \
             seal key."
        }
    };
    invalid(&format!(
        "the Transit key cannot sign the certificate request: {error}. {fix}"
    ))
}

/// Read and convert `--from-pem`, naming the `openssl` command that turns a
/// refused form into the one accepted.
fn import(
    pem: &Path,
    algorithm: Option<SigningAlgorithm>,
) -> Result<registry_platform_crypto::PrivateJwk, RenderProblem> {
    let mut file = File::open(pem).map_err(|error| {
        invalid(&format!(
            "--from-pem {} cannot be read: {error}",
            pem.display()
        ))
    })?;
    let mut text = Zeroizing::new(Vec::new());
    std::io::Read::by_ref(&mut file)
        .take(MAX_PEM_BYTES + 1)
        .read_to_end(&mut text)
        .map_err(|error| {
            invalid(&format!(
                "--from-pem {} cannot be read: {error}",
                pem.display()
            ))
        })?;
    if text.len() as u64 > MAX_PEM_BYTES {
        return Err(invalid(&format!(
            "--from-pem {} is larger than 64 KiB, which no PEM private key is",
            pem.display()
        )));
    }
    seal_key_from_pkcs8_pem(&text, algorithm).map_err(|error| {
        let path = shell_word(&pem.display().to_string());
        let conversion = match error {
            SealKeyError::EncryptedPkcs8 | SealKeyError::LegacyPem { .. } => {
                Some(format!("openssl pkey -in {path} -out seal-key.pem"))
            }
            SealKeyError::Pkcs12 => Some(format!(
                "openssl pkcs12 -in {path} -nocerts -nodes -out seal-key.pem"
            )),
            _ => None,
        };
        match conversion {
            Some(command) => invalid(&format!(
                "--from-pem {}: {error}. Run `{command}`, pass --from-pem seal-key.pem, and \
                 delete seal-key.pem once keygen has written the key file",
                pem.display()
            )),
            None => invalid(&format!("--from-pem {}: {error}", pem.display())),
        }
    })
}

/// Create both files new, or neither: a key without its request, or a request
/// for a key that was not kept, is never left behind.
fn write_pair(
    key: &Path,
    key_bytes: &[u8],
    csr: &Path,
    csr_bytes: &[u8],
) -> Result<(), RenderProblem> {
    let mut key_file = create_new(key, 0o600)?;
    let mut csr_file = match create_new(csr, 0o644) {
        Ok(file) => file,
        Err(problem) => {
            drop(key_file);
            return Err(with_removed(problem, &[key]));
        }
    };
    let written = key_file
        .write_all(key_bytes)
        .and_then(|()| key_file.sync_all())
        .and_then(|()| csr_file.write_all(csr_bytes))
        .and_then(|()| csr_file.sync_all());
    if let Err(error) = written {
        drop((key_file, csr_file));
        return Err(with_removed(
            invalid(&format!(
                "the key and request could not be written: {error}"
            )),
            &[key, csr],
        ));
    }
    Ok(())
}

fn create_new(path: &Path, mode: u32) -> Result<File, RenderProblem> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                invalid(&format!(
                    "{} already exists; keygen never overwrites a file, so name a new path",
                    path.display()
                ))
            } else {
                invalid(&format!("{} cannot be created: {error}", path.display()))
            }
        })
}

/// Remove the files this run created, saying so in `problem` if one cannot
/// be removed.
fn with_removed(mut problem: RenderProblem, created: &[&Path]) -> RenderProblem {
    for path in created {
        if let Err(error) = std::fs::remove_file(path) {
            problem.detail = format!(
                "{}; {} was created and could not be removed ({error}): delete it before \
                 running keygen again",
                problem.detail,
                path.display()
            );
        }
    }
    problem
}

/// Whether two paths name one file, compared as absolute paths since neither
/// output exists yet.
fn same_file(left: &Path, right: &Path) -> bool {
    match (std::path::absolute(left), std::path::absolute(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

/// `value` as one POSIX shell word, quoted only when it needs to be.
fn shell_word(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-+=:,@%".contains(&byte));
    if plain {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}

fn invalid(detail: &str) -> RenderProblem {
    RenderProblem::new(ProblemKind::InvalidArgument, detail)
}

fn internal(detail: &str) -> RenderProblem {
    RenderProblem::new(ProblemKind::Internal, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_printed_path_is_one_shell_word() {
        assert_eq!(shell_word("/srv/keys/seal.pem"), "/srv/keys/seal.pem");
        assert_eq!(shell_word("/Users/a b/seal.pem"), "'/Users/a b/seal.pem'");
        assert_eq!(shell_word("it's.pem"), r"'it'\''s.pem'");
        assert_eq!(shell_word("$HOME.pem"), "'$HOME.pem'");
    }

    #[test]
    fn two_spellings_of_one_path_are_one_file() {
        assert!(same_file(Path::new("seal.jwk"), Path::new("./seal.jwk")));
        assert!(!same_file(Path::new("seal.jwk"), Path::new("seal.csr")));
    }
}
