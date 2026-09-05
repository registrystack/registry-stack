//! Key material generation. Private material is written as owner-only files
//! and never reaches standard output.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Args, Subcommand, ValueEnum};
use p256::ecdsa::SigningKey;
use registry_platform_crypto::{GeneratedKeyAlgorithm, PrivateJwk, PublicJwk};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

#[derive(Debug, Subcommand)]
pub enum KeygenCommand {
    /// P-256 ES256 signing keypair as private and public JWK files.
    Signing(SigningArgs),
    /// One random raw secret file, 32 bytes (audit or subject-binding HMAC).
    ///
    /// This is HMAC key material, not a credential a source will accept: the
    /// bytes are arbitrary and an HTTP header value rejects most of them. Use
    /// `keygen token` for a bearer token.
    Secret(SecretArgs),
    /// One random bearer token file, printable and header-safe.
    Token(TokenArgs),
    /// P-256 ES256 holder keypair for SD-JWT VC confirmation binding.
    Holder(HolderArgs),
    /// Keypair a source's `clientAssertionKeyRef` points at, for a token
    /// endpoint that authenticates the client by signed assertion.
    ClientAssertion(ClientAssertionArgs),
}

#[derive(Debug, Args)]
pub struct SigningArgs {
    /// Secret directory receiving the private JWK file (created 0700).
    #[arg(long, alias = "out-dir")]
    pub output_dir: PathBuf,

    /// Public JWK output path; defaults to a file inside the secret directory.
    #[arg(long, alias = "public-out")]
    pub public_output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SecretArgs {
    /// Output file for the raw secret (written 0600).
    #[arg(long, alias = "out")]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct TokenArgs {
    /// Output file for the bearer token (written 0600).
    #[arg(long, alias = "out")]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct HolderArgs {
    /// Directory receiving the holder private JWK file (created 0700).
    #[arg(long, alias = "out-dir")]
    pub output_dir: PathBuf,

    /// Public JWK output path; defaults to a file inside the secret directory.
    #[arg(long, alias = "public-out")]
    pub public_output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ClientAssertionArgs {
    /// Secret directory receiving the private JWK file (created 0700).
    #[arg(long, alias = "out-dir")]
    pub output_dir: PathBuf,

    /// Public JWK output path; defaults to a file inside the secret directory.
    #[arg(long, alias = "public-out")]
    pub public_output: Option<PathBuf>,

    /// Name of the private JWK file, which is the `secret:file/NAME` a source's
    /// `clientAssertionKeyRef` points at; defaults to one naming the algorithm.
    /// The public half follows it as `NAME-public.jwk.json`.
    #[arg(long)]
    pub private_name: Option<String>,

    /// Signature algorithm the assertion is signed with.
    #[arg(long, value_enum, default_value_t = ClientAssertionAlgorithm::Es384)]
    pub algorithm: ClientAssertionAlgorithm,
}

/// The two algorithms a client authenticating by signed assertion has to be
/// able to offer.
///
/// SMART App Launch v2.2.0's `client-confidential-asymmetric` profile requires
/// a token endpoint to validate only one of ES384 and RS384, so which one an
/// adopter needs is the deployment's to say, not this tool's. ES384 is the
/// default because its key is far smaller and faster to generate; RS384 is
/// there because a conformant endpoint may accept nothing else.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ClientAssertionAlgorithm {
    /// ECDSA over P-384 with SHA-384.
    Es384,
    /// RSASSA-PKCS1-v1_5 with SHA-384 over a 2048-bit modulus.
    Rs384,
}

impl ClientAssertionAlgorithm {
    const fn generated(self) -> GeneratedKeyAlgorithm {
        match self {
            Self::Es384 => GeneratedKeyAlgorithm::Es384,
            Self::Rs384 => GeneratedKeyAlgorithm::Rs384,
        }
    }

    /// The filenames carry the algorithm, so a deployment that has to offer
    /// both keeps them side by side in one secret directory.
    const fn private_filename(self) -> &'static str {
        match self {
            Self::Es384 => CLIENT_ASSERTION_P384_PRIVATE_FILENAME,
            Self::Rs384 => CLIENT_ASSERTION_RSA_PRIVATE_FILENAME,
        }
    }

    const fn public_filename(self) -> &'static str {
        match self {
            Self::Es384 => CLIENT_ASSERTION_P384_PUBLIC_FILENAME,
            Self::Rs384 => CLIENT_ASSERTION_RSA_PUBLIC_FILENAME,
        }
    }
}

/// Filename for the private signing JWK, fixed to match the reference
/// deployment project's secret-mount layout.
const SIGNING_PRIVATE_FILENAME: &str = "signing-p256-private-jwk";
const SIGNING_PUBLIC_FILENAME: &str = "signing-p256-public.jwk.json";
const HOLDER_PRIVATE_FILENAME: &str = "holder-p256-private-jwk";
const HOLDER_PUBLIC_FILENAME: &str = "holder-p256-public.jwk.json";
const CLIENT_ASSERTION_P384_PRIVATE_FILENAME: &str = "client-assertion-p384-private-jwk";
const CLIENT_ASSERTION_P384_PUBLIC_FILENAME: &str = "client-assertion-p384-public.jwk.json";
const CLIENT_ASSERTION_RSA_PRIVATE_FILENAME: &str = "client-assertion-rsa2048-private-jwk";
const CLIENT_ASSERTION_RSA_PUBLIC_FILENAME: &str = "client-assertion-rsa2048-public.jwk.json";
const AUDIT_HMAC_FILENAME: &str = "audit-hmac-key";
const SUBJECT_BINDING_HMAC_FILENAME: &str = "subject-binding-hmac-key";

const PRIVATE_FILE_MODE: u32 = 0o600;
const PUBLIC_FILE_MODE: u32 = 0o644;
const PRIVATE_DIR_MODE: u32 = 0o700;

/// Exactly 32 raw bytes: one HMAC secret (audit or subject-binding).
const SECRET_FILE_BYTES: usize = 32;

/// How much randomness a generated bearer token carries, before encoding.
const TOKEN_ENTROPY_BYTES: usize = 32;

pub fn run(command: KeygenCommand) -> Result<ExitCode> {
    match command {
        KeygenCommand::Signing(args) => run_keypair(
            generate_p256_keypair()?,
            &args.output_dir,
            args.public_output.as_deref(),
            SIGNING_PRIVATE_FILENAME,
            SIGNING_PUBLIC_FILENAME,
        ),
        KeygenCommand::Secret(args) => run_secret(&args),
        KeygenCommand::Token(args) => run_token(&args),
        KeygenCommand::Holder(args) => run_keypair(
            generate_p256_keypair()?,
            &args.output_dir,
            args.public_output.as_deref(),
            HOLDER_PRIVATE_FILENAME,
            HOLDER_PUBLIC_FILENAME,
        ),
        KeygenCommand::ClientAssertion(args) => {
            // Before generating: an RSA keypair is expensive, and a name the
            // runtime could never resolve is worth refusing without it.
            let (private_filename, public_filename) = client_assertion_filenames(&args)?;
            run_keypair(
                generate_client_assertion_keypair(args.algorithm)?,
                &args.output_dir,
                args.public_output.as_deref(),
                &private_filename,
                &public_filename,
            )
        }
    }
}

/// Where one client assertion keypair is written.
///
/// The operator contract asks for one assertion key per authorization server,
/// and Evidence resolves every `secret:file/` reference inside one flat secret
/// root, so a deployment reaching two servers needs two names in one directory.
/// The default names the algorithm, which is right for the single-server
/// deployment and collides for any other.
///
/// A stated name is the private file's own name, because that is what the
/// bundle references. It has to satisfy the resolver's `secret:file/NAME`
/// grammar, or generation succeeds and produces key material no bundle can
/// point at.
fn client_assertion_filenames(args: &ClientAssertionArgs) -> Result<(String, String)> {
    let Some(name) = args.private_name.as_deref() else {
        return Ok((
            args.algorithm.private_filename().to_owned(),
            args.algorithm.public_filename().to_owned(),
        ));
    };
    if !is_secret_file_name(name) {
        bail!(
            "--private-name must be a name the runtime can resolve as \
             secret:file/NAME: a lowercase ASCII letter, then lowercase \
             letters, digits, '.', '_', or '-', at most 128 bytes"
        );
    }
    Ok((name.to_owned(), format!("{name}-public.jwk.json")))
}

/// The `secret:file/NAME` grammar, as `registry-platform-config` resolves it.
///
/// Restated here rather than shared: this tool delegates the runtime to the
/// `evidence` binary and does not link the config crate. The grammar admits no
/// path separator and no leading dot, so it also keeps the written file inside
/// the secret directory.
fn is_secret_file_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 128
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// Generate the four files needed during local Evidence authoring.
///
/// The caller supplies a newly staged, unpublished project. This function
/// never accepts force and never reports paths, so a collision fails closed
/// and no private material reaches standard output. Publication of the staged
/// project makes the complete batch visible at once.
pub(crate) fn generate_scaffold_key_material(out_dir: &Path) -> Result<()> {
    ensure_private_dir(out_dir)?;
    run_keypair_impl(
        generate_p256_keypair()?,
        out_dir,
        None,
        SIGNING_PRIVATE_FILENAME,
        SIGNING_PUBLIC_FILENAME,
        false,
        PUBLIC_FILE_MODE,
    )?;
    for filename in [AUDIT_HMAC_FILENAME, SUBJECT_BINDING_HMAC_FILENAME] {
        run_secret_impl(
            &SecretArgs {
                output: out_dir.join(filename),
            },
            false,
        )?;
    }
    Ok(())
}

/// Generate one private development keypair without reporting key material or
/// paths. Both halves remain owner-only because the pair lives in ephemeral
/// private supervisor state rather than in a public JWKS artifact.
pub(crate) fn generate_dev_keypair(
    out_dir: &Path,
    private_filename: &str,
    public_filename: &str,
) -> Result<(PathBuf, PathBuf)> {
    ensure_private_dir(out_dir)?;
    run_keypair_impl(
        generate_p256_keypair()?,
        out_dir,
        None,
        private_filename,
        public_filename,
        false,
        PRIVATE_FILE_MODE,
    )?;
    Ok((
        out_dir.join(private_filename),
        out_dir.join(public_filename),
    ))
}

/// Both halves of one generated keypair, rendered as the files a keypair
/// command writes.
struct KeypairFiles {
    private_json: Zeroizing<String>,
    public_json: String,
    kid: String,
}

/// Generate the P-256 ES256 pair the service signing key, the holder binding
/// key, and a scaffolded project's key material all use.
fn generate_p256_keypair() -> Result<KeypairFiles> {
    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed P-256 point has x"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed P-256 point has y"));
    let d = Zeroizing::new(URL_SAFE_NO_PAD.encode(signing_key.to_bytes()));
    let kid = default_kid(&x, &y)?;

    let private_json = Zeroizing::new(
        serde_json::to_string_pretty(&serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            // `json!` copies `d` into a `serde_json::Value::String` whose heap
            // buffer this crate does not zeroize, unlike every other copy of
            // the secret above. Accepted: serde_json owns the escaping here,
            // and the copy is short-lived, but it is not wiped.
            "d": d.as_str(),
            "x": x,
            "y": y,
            "alg": "ES256",
            "kid": kid,
        }))
        .context("failed to render the private JWK")?,
    );
    let public_json = serde_json::to_string_pretty(&serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "alg": "ES256",
        "kid": kid,
    }))
    .context("failed to render the public JWK")?;

    Ok(KeypairFiles {
        private_json,
        public_json,
        kid,
    })
}

/// Generate the pair a source signs its client assertion with.
///
/// Generation, and the `kid` that is the thumbprint of the public half, belong
/// to `registry-platform-crypto`: the key is produced by the same backend that
/// will sign with it, and validated by the crate that defines what a usable JWK
/// is.
fn generate_client_assertion_keypair(algorithm: ClientAssertionAlgorithm) -> Result<KeypairFiles> {
    let private = registry_platform_crypto::generate_private_jwk(algorithm.generated())
        .context("failed to generate the client-assertion key")?;
    let kid = private
        .kid
        .clone()
        .context("generated key carries no kid")?;
    let public_json = serde_json::to_string_pretty(&private.public())
        .context("failed to render the public JWK")?;

    Ok(KeypairFiles {
        private_json: render_private_jwk(&private)?,
        public_json,
        kid,
    })
}

/// Render a private JWK, secret members included, as the file the runtime
/// reads.
///
/// `PrivateJwk` serializes its public half only, deliberately, so the private
/// file is assembled here rather than through that impl.
fn render_private_jwk(jwk: &PrivateJwk) -> Result<Zeroizing<String>> {
    let mut members = Map::new();
    members.insert("kty".to_owned(), Value::String(jwk.kty.clone()));
    // Each secret member below is copied into a `serde_json::Value::String`
    // whose heap buffer this crate does not zeroize, unlike the `PrivateJwk` it
    // is copied from and the `Zeroizing` output. Accepted: serde_json owns the
    // escaping, and the copies are short-lived, but they are not wiped.
    for (name, value) in [
        ("crv", jwk.crv.as_deref()),
        ("n", jwk.n.as_deref()),
        ("e", jwk.e.as_deref()),
        ("d", jwk.d.as_deref()),
        ("x", jwk.x.as_deref()),
        ("y", jwk.y.as_deref()),
        ("p", jwk.p.as_deref()),
        ("q", jwk.q.as_deref()),
        ("dp", jwk.dp.as_deref()),
        ("dq", jwk.dq.as_deref()),
        ("qi", jwk.qi.as_deref()),
        ("alg", jwk.alg.as_deref()),
        ("kid", jwk.kid.as_deref()),
    ] {
        if let Some(value) = value {
            members.insert(name.to_owned(), Value::String(value.to_owned()));
        }
    }

    Ok(Zeroizing::new(
        serde_json::to_string_pretty(&Value::Object(members))
            .context("failed to render the private JWK")?,
    ))
}

fn run_keypair(
    keypair: KeypairFiles,
    out_dir: &Path,
    public_out: Option<&Path>,
    private_filename: &str,
    public_filename: &str,
) -> Result<ExitCode> {
    run_keypair_impl(
        keypair,
        out_dir,
        public_out,
        private_filename,
        public_filename,
        true,
        PUBLIC_FILE_MODE,
    )
}

fn run_keypair_impl(
    keypair: KeypairFiles,
    out_dir: &Path,
    public_out: Option<&Path>,
    private_filename: &str,
    public_filename: &str,
    report: bool,
    public_file_mode: u32,
) -> Result<ExitCode> {
    let private_path = out_dir.join(private_filename);
    let public_path = public_out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| out_dir.join(public_filename));

    // Every target path is known up front, so the whole batch can be checked
    // for collisions before anything is written.
    reject_existing(&[&private_path, &public_path])?;

    // Self-check: a key this tool cannot parse back is not fit to ship.
    PrivateJwk::parse(&keypair.private_json).context("generated private JWK failed validation")?;
    PublicJwk::parse(&keypair.public_json).context("generated public JWK failed validation")?;

    ensure_private_dir(out_dir)?;
    ensure_parent_dir(&public_path)?;
    write_owner_file(
        &private_path,
        keypair.private_json.as_bytes(),
        PRIVATE_FILE_MODE,
    )?;
    write_owner_file(
        &public_path,
        keypair.public_json.as_bytes(),
        public_file_mode,
    )?;

    if report {
        println!("wrote {}", private_path.display());
        println!("wrote {}", public_path.display());
        println!("kid: {}", keypair.kid);
    }

    Ok(ExitCode::SUCCESS)
}

fn run_secret(args: &SecretArgs) -> Result<ExitCode> {
    run_secret_impl(args, true)
}

fn run_secret_impl(args: &SecretArgs, report: bool) -> Result<ExitCode> {
    reject_existing(&[&args.output])?;

    let secret = generate_secret()?;

    if let Some(parent) = args
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_secret_parent_dir(parent)?;
    }
    write_owner_file(&args.output, secret.as_slice(), PRIVATE_FILE_MODE)?;

    if report {
        println!("wrote {}", args.output.display());
    }

    Ok(ExitCode::SUCCESS)
}

/// Write one bearer token, for a source that has no token of its own to issue.
///
/// A real source issues its own credential and this command has no business
/// inventing one. It exists for the stand-in source a project is stood up
/// against first, where the alternative is `keygen secret`: the obvious
/// neighbour, and the wrong tool, because its raw bytes reach an HTTP header
/// that rejects most of them.
fn run_token(args: &TokenArgs) -> Result<ExitCode> {
    reject_existing(&[&args.output])?;

    let mut entropy = Zeroizing::new([0_u8; TOKEN_ENTROPY_BYTES]);
    getrandom::fill(entropy.as_mut_slice()).context("failed to generate random key material")?;
    // base64url without padding: every character is unreserved in a header
    // value and never NUL, so no draw has to be rejected. Written without a
    // trailing newline, because the runtime reads the file whole and would
    // carry one into the header.
    let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(entropy.as_slice()));

    if let Some(parent) = args
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_secret_parent_dir(parent)?;
    }
    write_owner_file(&args.output, token.as_bytes(), PRIVATE_FILE_MODE)?;

    println!("wrote {}", args.output.display());

    Ok(ExitCode::SUCCESS)
}

/// Draws `SECRET_FILE_BYTES` uniformly at random, rejecting any draw that
/// contains a NUL byte.
///
/// The Evidence runtime refuses a file-provided secret containing NUL, which a
/// uniform 32-byte draw carries about 11.8% of the time. Rejection sampling
/// keeps the value uniform over the accepted set (255^32, or 255.8 bits) and
/// keeps a scaffolded project working the first time, instead of failing at
/// `evidence serve` long after `evidence check` passed.
fn generate_secret() -> Result<Zeroizing<[u8; SECRET_FILE_BYTES]>> {
    let mut secret = Zeroizing::new([0_u8; SECRET_FILE_BYTES]);
    loop {
        getrandom::fill(secret.as_mut_slice()).context("failed to generate random key material")?;
        if !secret.contains(&0) {
            return Ok(secret);
        }
    }
}

/// Default kid: the RFC 7638 thumbprint of the public key.
fn default_kid(x: &str, y: &str) -> Result<String> {
    let public = PublicJwk {
        kty: "EC".to_string(),
        kid: None,
        alg: None,
        crv: Some("P-256".to_string()),
        x: Some(x.to_string()),
        y: Some(y.to_string()),
        n: None,
        e: None,
    };
    public.jkt().context("failed to compute the JWK thumbprint")
}

/// Refuses to proceed if any target path already exists. Checked for every
/// path before any file is written so a batch either
/// completes in full or leaves nothing behind.
fn reject_existing(paths: &[&Path]) -> Result<()> {
    let mut existing = Vec::new();
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(_) => existing.push(path.display().to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
            }
        }
    }
    if existing.is_empty() {
        return Ok(());
    }
    bail!(
        "refusing to overwrite existing output: {}",
        existing.join(", ")
    );
}

/// Creates the parent directory of `path` if it does not already exist. Used
/// for public output paths, which carry no confidentiality requirement of
/// their own, so no particular mode is imposed.
fn ensure_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    if parent.exists() {
        return Ok(());
    }
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))
}

/// Creates `dir` as mode 0700 if missing, or normalizes its mode to 0700 if
/// it already exists. Used for `--out-dir`: the caller named `dir` itself as
/// the secret directory, so an existing directory found there is brought
/// under this tool's ownership either way.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    ensure_private_dir_impl(dir, true)
}

/// Creates `dir` as mode 0700 if missing; leaves its mode untouched if it
/// already exists. Used for `--out`'s parent directory, which is derived from
/// the output path rather than named by the caller as a secret directory, so
/// this tool does not re-chmod a directory it did not create.
fn ensure_secret_parent_dir(dir: &Path) -> Result<()> {
    ensure_private_dir_impl(dir, false)
}

/// Shared implementation: a symlink or non-directory at `dir` is always
/// rejected. A missing `dir` is always created at mode 0700. Whether an
/// already-existing `dir` has its mode normalized to 0700 is left to the
/// caller via `normalize_existing`.
fn ensure_private_dir_impl(dir: &Path, normalize_existing: bool) -> Result<()> {
    if dir.exists() {
        let metadata = fs::symlink_metadata(dir)
            .with_context(|| format!("failed to inspect {}", dir.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("{} exists and is not a plain directory", dir.display());
        }
        if !normalize_existing {
            return Ok(());
        }
    } else {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(PRIVATE_DIR_MODE);
        builder
            .create(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .with_context(|| format!("failed to set permissions on {}", dir.display()))
}

/// Writes `contents` to `path` with `mode`, set atomically at file creation
/// so there is no window where the file is readable with the wrong
/// permissions. Create-new semantics prevent replacement or symlink traversal.
fn write_owner_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).mode(mode).create_new(true);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to persist {}", path.display()))?;
    Ok(())
}
