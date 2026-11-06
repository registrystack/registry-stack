//! `registry-render keygen`: a seal key, written owner-only as the private
//! JWK `signer.privateKeyRef` reads, and the PKCS #10 request a certificate
//! authority issues the seal certificate from.
//!
//! The key is generated here, or converted from an unencrypted PKCS #8 PEM
//! with `--from-pem`; the conversion and the request are
//! `registry-platform-crypto`'s. Neither output file may exist beforehand,
//! and no key material is ever printed.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use registry_platform_crypto::{
    certificate_request, generate_seal_key, private_seal_key_json, seal_key_from_pkcs8_pem,
    CertificateRequestError, CertificateRequestSubject, LocalJwkSigner, SealKeyError,
    SigningAlgorithm,
};
use zeroize::Zeroizing;

use crate::problem::{ProblemKind, RenderProblem};

/// A PEM private key is a few kilobytes; a larger `--from-pem` file is not
/// one.
const MAX_PEM_BYTES: u64 = 64 * 1024;

/// What `keygen` writes, and from what.
pub struct KeygenRequest<'a> {
    /// The private JWK file to create, owner-only.
    pub key: &'a Path,
    /// The PEM certificate request file to create.
    pub csr: &'a Path,
    pub subject: CertificateRequestSubject,
    /// The seal algorithm. Generation defaults to ES256; an imported key
    /// signs with the algorithm its curve fixes, or RS256 for RSA.
    pub algorithm: Option<SigningAlgorithm>,
    /// An unencrypted PKCS #8 PEM key to convert instead of generating one.
    pub from_pem: Option<&'a Path>,
}

/// Write the key and the request, then print where they are and what comes
/// next. Every refusal happens before either file is created, except a
/// write that fails part way, which removes what it created.
pub fn run(request: &KeygenRequest<'_>, out: &mut impl Write) -> Result<i32, RenderProblem> {
    if same_file(request.key, request.csr) {
        return Err(invalid(
            "--key and --csr name the same file; give each its own path",
        ));
    }
    if let Some(pem) = request.from_pem {
        if same_file(pem, request.key) || same_file(pem, request.csr) {
            return Err(invalid(
                "--from-pem names an output file; keygen writes --key and --csr as new files",
            ));
        }
    }

    let jwk = match request.from_pem {
        Some(pem) => import(pem, request.algorithm)?,
        None => generate_seal_key(request.algorithm.unwrap_or(SigningAlgorithm::Es256))
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

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|error| internal(&format!("the signing runtime could not start: {error}")))?;
    let csr = runtime
        .block_on(certificate_request(&request.subject, &signer))
        .map_err(|error| match error {
            CertificateRequestError::Subject { .. } => invalid(&error.to_string()),
            other => internal(&format!(
                "the certificate request could not be signed: {other}"
            )),
        })?;

    write_pair(request.key, &key_json, request.csr, csr.to_pem().as_bytes())?;
    writeln!(
        out,
        "wrote the {algorithm} seal key to {} (owner-only; it is never printed)\n\
         wrote its certificate request to {}\n\
         Have a certificate authority issue a seal certificate from the request: a leaf with \
         basicConstraints CA:FALSE and the digitalSignature or nonRepudiation key usage. \
         Point signer.privateKeyRef at the key file and certificateChainFile at the issued \
         chain, the seal certificate first.",
        request.key.display(),
        request.csr.display(),
    )
    .map_err(|error| internal(&format!("the summary could not be printed: {error}")))?;
    Ok(0)
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
