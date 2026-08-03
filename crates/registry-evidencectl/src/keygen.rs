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
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;
use registry_platform_crypto::{PrivateJwk, PublicJwk};
use zeroize::Zeroizing;

#[derive(Debug, Subcommand)]
pub enum KeygenCommand {
    /// Ed25519 signing keypair as private and public JWK files.
    Signing(SigningArgs),
    /// One random raw secret file, 32 bytes (audit or subject-binding HMAC).
    ///
    /// This is HMAC key material, not a credential a source will accept: the
    /// bytes are arbitrary and an HTTP header value rejects most of them. Use
    /// `keygen token` for a bearer token.
    Secret(SecretArgs),
    /// One random bearer token file, printable and header-safe.
    Token(TokenArgs),
    /// Ed25519 holder keypair for SD-JWT VC confirmation binding.
    Holder(HolderArgs),
}

#[derive(Debug, Args)]
pub struct SigningArgs {
    /// Secret directory receiving the private JWK file (created 0700).
    #[arg(long)]
    pub out_dir: PathBuf,

    /// Key identifier; defaults to the RFC 7638 JWK thumbprint.
    #[arg(long)]
    pub kid: Option<String>,

    /// Public JWK output path; defaults to a file inside the secret directory.
    #[arg(long)]
    pub public_out: Option<PathBuf>,

    /// Overwrite existing output files.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct SecretArgs {
    /// Output file for the raw secret (written 0600).
    #[arg(long)]
    pub out: PathBuf,

    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct TokenArgs {
    /// Output file for the bearer token (written 0600).
    #[arg(long)]
    pub out: PathBuf,

    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct HolderArgs {
    /// Directory receiving the holder private JWK file (created 0700).
    #[arg(long)]
    pub out_dir: PathBuf,

    /// Key identifier; defaults to the RFC 7638 JWK thumbprint.
    #[arg(long)]
    pub kid: Option<String>,

    /// Public JWK output path; defaults to a file inside the secret directory.
    #[arg(long)]
    pub public_out: Option<PathBuf>,

    /// Overwrite existing output files.
    #[arg(long)]
    pub force: bool,
}

/// Filename for the private signing JWK, fixed to match the reference
/// deployment project's secret-mount layout.
const SIGNING_PRIVATE_FILENAME: &str = "signing-ed25519-private-jwk";
const SIGNING_PUBLIC_FILENAME: &str = "signing-ed25519-public.jwk.json";
const HOLDER_PRIVATE_FILENAME: &str = "holder-ed25519-private-jwk";
const HOLDER_PUBLIC_FILENAME: &str = "holder-ed25519-public.jwk.json";

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
            &args.out_dir,
            args.kid.as_deref(),
            args.public_out.as_deref(),
            args.force,
            SIGNING_PRIVATE_FILENAME,
            SIGNING_PUBLIC_FILENAME,
        ),
        KeygenCommand::Secret(args) => run_secret(&args),
        KeygenCommand::Token(args) => run_token(&args),
        KeygenCommand::Holder(args) => run_keypair(
            &args.out_dir,
            args.kid.as_deref(),
            args.public_out.as_deref(),
            args.force,
            HOLDER_PRIVATE_FILENAME,
            HOLDER_PUBLIC_FILENAME,
        ),
    }
}

fn run_keypair(
    out_dir: &Path,
    kid: Option<&str>,
    public_out: Option<&Path>,
    force: bool,
    private_filename: &str,
    public_filename: &str,
) -> Result<ExitCode> {
    if let Some(kid) = kid {
        if kid.trim().is_empty() {
            bail!("--kid must not be empty or whitespace-only");
        }
    }

    let private_path = out_dir.join(private_filename);
    let public_path = public_out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| out_dir.join(public_filename));

    // Every target path is known up front, so the whole batch can be checked
    // for collisions before anything is written.
    reject_existing(&[&private_path, &public_path], force)?;

    let mut secret = Zeroizing::new([0_u8; 32]);
    getrandom::fill(secret.as_mut_slice()).context("failed to generate random key material")?;
    let signing_key = SigningKey::from_bytes(&secret);
    let x = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());
    let d = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_slice()));

    let kid = match kid {
        Some(kid) => kid.to_string(),
        None => default_kid(&x)?,
    };

    let private_json = Zeroizing::new(
        serde_json::to_string_pretty(&serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            // `json!` copies `d` into a `serde_json::Value::String` whose heap
            // buffer this crate does not zeroize, unlike every other copy of
            // the secret above. Accepted: serde_json owns the escaping here,
            // and the copy is short-lived, but it is not wiped.
            "d": d.as_str(),
            "x": x,
            "alg": "EdDSA",
            "kid": kid,
        }))
        .context("failed to render the private JWK")?,
    );
    let public_json = serde_json::to_string_pretty(&serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "alg": "EdDSA",
        "kid": kid,
        "use": "sig",
    }))
    .context("failed to render the public JWK")?;

    // Self-check: a key this tool cannot parse back is not fit to ship.
    PrivateJwk::parse(&private_json).context("generated private JWK failed validation")?;
    PublicJwk::parse(&public_json).context("generated public JWK failed validation")?;

    ensure_private_dir(out_dir)?;
    ensure_parent_dir(&public_path)?;
    write_owner_file(
        &private_path,
        private_json.as_bytes(),
        PRIVATE_FILE_MODE,
        force,
    )?;
    write_owner_file(
        &public_path,
        public_json.as_bytes(),
        PUBLIC_FILE_MODE,
        force,
    )?;

    println!("wrote {}", private_path.display());
    println!("wrote {}", public_path.display());
    println!("kid: {kid}");

    Ok(ExitCode::SUCCESS)
}

fn run_secret(args: &SecretArgs) -> Result<ExitCode> {
    reject_existing(&[&args.out], args.force)?;

    let secret = generate_secret()?;

    if let Some(parent) = args
        .out
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_secret_parent_dir(parent)?;
    }
    write_owner_file(&args.out, secret.as_slice(), PRIVATE_FILE_MODE, args.force)?;

    println!("wrote {}", args.out.display());

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
    reject_existing(&[&args.out], args.force)?;

    let mut entropy = Zeroizing::new([0_u8; TOKEN_ENTROPY_BYTES]);
    getrandom::fill(entropy.as_mut_slice()).context("failed to generate random key material")?;
    // base64url without padding: every character is unreserved in a header
    // value and never NUL, so no draw has to be rejected. Written without a
    // trailing newline, because the runtime reads the file whole and would
    // carry one into the header.
    let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(entropy.as_slice()));

    if let Some(parent) = args
        .out
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_secret_parent_dir(parent)?;
    }
    write_owner_file(&args.out, token.as_bytes(), PRIVATE_FILE_MODE, args.force)?;

    println!("wrote {}", args.out.display());

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
fn default_kid(x: &str) -> Result<String> {
    let public = PublicJwk {
        kty: "OKP".to_string(),
        kid: None,
        alg: None,
        crv: Some("Ed25519".to_string()),
        x: Some(x.to_string()),
        y: None,
        n: None,
        e: None,
    };
    public.jkt().context("failed to compute the JWK thumbprint")
}

/// Refuses to proceed if any target path already exists, unless `force` is
/// set. Checked for every path before any file is written so a batch either
/// completes in full or leaves nothing behind.
fn reject_existing(paths: &[&Path], force: bool) -> Result<()> {
    if force {
        return Ok(());
    }
    let existing: Vec<String> = paths
        .iter()
        .filter(|path| path.exists())
        .map(|path| path.display().to_string())
        .collect();
    if existing.is_empty() {
        return Ok(());
    }
    bail!(
        "refusing to overwrite existing output without --force: {}",
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
/// permissions. A force overwrite first removes anything already at `path`,
/// including a symlink, so the create that follows always creates a fresh
/// file and `mode` is always the one `O_CREAT` applies, never a later chmod
/// that could instead land on whatever a symlink now points at.
fn write_owner_file(path: &Path, contents: &[u8], mode: u32, force: bool) -> Result<()> {
    if force {
        match fs::symlink_metadata(path) {
            Ok(_) => fs::remove_file(path)
                .with_context(|| format!("failed to remove existing {}", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
            }
        }
    }
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
