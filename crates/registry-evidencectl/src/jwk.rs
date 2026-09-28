//! Single public JWK conversion. `jwk from-pem` turns one PEM public key, such
//! as the one a Transit key export publishes, into the exact public JWK that
//! `jwks`, governance, and the runtime accept. Private keys are refused before
//! anything is decoded, and no error carries the input's contents.

use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Args, Subcommand, ValueEnum};
use pkcs8::{
    der::Decode as _,
    spki::{ObjectIdentifier, SubjectPublicKeyInfoRef},
};
use registry_platform_crypto::{PublicJwk, MAX_JWK_JSON_BYTES};
use serde_json::json;

use crate::OutputFormat;

#[derive(Debug, Subcommand)]
pub enum JwkCommand {
    /// Convert one PEM public key into a public JWK whose kid is its RFC 7638 thumbprint.
    ///
    /// Accepts a `PUBLIC KEY` (SubjectPublicKeyInfo) or `RSA PUBLIC KEY`
    /// (PKCS #1) block: EC P-256 becomes ES256, EC P-384 becomes ES384, and
    /// RSA takes the algorithm named by `--alg`. A private key is refused.
    FromPem(FromPemArgs),
}

#[derive(Debug, Args)]
pub struct FromPemArgs {
    /// PEM public key file, or `-` to read standard input.
    pub pem: PathBuf,

    /// JWS algorithm the key is published for; required for RSA keys.
    #[arg(long, value_enum)]
    pub alg: Option<JwkAlgorithm>,

    /// Write the JWK to this file instead of standard output.
    #[arg(long, conflicts_with = "output_dir")]
    pub output: Option<PathBuf>,

    /// Write the JWK into this existing directory as `<kid>.jwk.json`.
    #[arg(long)]
    pub output_dir: Option<PathBuf>,

    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,
}

/// The algorithms a converted public key may be published for: the ones the
/// platform JWK accepts for an EC or RSA key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum JwkAlgorithm {
    /// ECDSA over P-256 with SHA-256; the Evidence signing algorithm.
    Es256,
    /// ECDSA over P-384 with SHA-384.
    Es384,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    Rs384,
}

impl JwkAlgorithm {
    const fn jwa_name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
        }
    }
}

/// Upper bound on the PEM input: far above a 4096-bit RSA public key, far
/// below anything worth buffering.
const MAX_PEM_BYTES: usize = MAX_JWK_JSON_BYTES;

/// RFC 7518 section 3.3: an RSA key used with RS256 or RS384 has at least a
/// 2048-bit modulus.
const MIN_RSA_MODULUS_BITS: usize = 2048;

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

pub fn run(command: JwkCommand, format: OutputFormat) -> Result<ExitCode> {
    match command {
        JwkCommand::FromPem(args) => run_from_pem(&args, format),
    }
}

fn run_from_pem(args: &FromPemArgs, format: OutputFormat) -> Result<ExitCode> {
    let input = read_input(&args.pem)?;
    let jwk = public_jwk_from_pem(&input, args.alg)
        .with_context(|| format!("could not convert {}", describe(&args.pem)))?;
    let kid = jwk.kid.clone().context("converted JWK carries no kid")?;
    let alg = jwk.alg.clone().context("converted JWK carries no alg")?;
    let mut rendered =
        serde_json::to_string_pretty(&jwk).context("failed to render the public JWK")?;
    rendered.push('\n');

    let destination = match (&args.output, &args.output_dir) {
        (Some(path), _) => Some(path.clone()),
        (None, Some(dir)) => Some(dir.join(format!("{kid}.jwk.json"))),
        (None, None) => None,
    };
    let Some(path) = destination else {
        match format {
            OutputFormat::Human => print!("{rendered}"),
            OutputFormat::Json => crate::print_report(&crate::command_report(
                "jwk from-pem",
                json!({"kid": kid, "alg": alg, "jwk": jwk}),
            )),
        }
        return Ok(ExitCode::SUCCESS);
    };

    if path.exists() && !args.force {
        bail!(
            "refusing to overwrite existing output without --force: {}",
            path.display()
        );
    }
    crate::jwks::write_owner_file(&path, rendered.as_bytes(), args.force)?;
    match format {
        OutputFormat::Human => println!("wrote {} (kid {kid})", path.display()),
        OutputFormat::Json => crate::print_report(&crate::command_report(
            "jwk from-pem",
            json!({"kid": kid, "alg": alg, "files": [path.display().to_string()]}),
        )),
    }
    Ok(ExitCode::SUCCESS)
}

fn describe(path: &Path) -> String {
    if path == Path::new("-") {
        "standard input".to_owned()
    } else {
        path.display().to_string()
    }
}

fn read_input(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_PEM_BYTES).unwrap_or(u64::MAX) + 1;
    if path == Path::new("-") {
        std::io::stdin()
            .lock()
            .take(limit)
            .read_to_end(&mut bytes)
            .context("failed to read standard input")?;
    } else {
        fs::File::open(path)
            .with_context(|| format!("failed to read {}", path.display()))?
            .take(limit)
            .read_to_end(&mut bytes)
            .with_context(|| format!("failed to read {}", path.display()))?;
    }
    if bytes.len() > MAX_PEM_BYTES {
        bail!(
            "{} exceeds the {MAX_PEM_BYTES}-byte PEM limit",
            describe(path)
        );
    }
    String::from_utf8(bytes).map_err(|_| {
        anyhow::anyhow!(
            "{} is not a PEM public key: it is not UTF-8 text",
            describe(path)
        )
    })
}

/// Converts one PEM public key into a validated public JWK carrying `alg` and
/// its RFC 7638 thumbprint as `kid`.
///
/// Errors name what was found, never the bytes that were read.
pub(crate) fn public_jwk_from_pem(input: &str, alg: Option<JwkAlgorithm>) -> Result<PublicJwk> {
    let labels = pem_labels(input);
    if labels.iter().any(|label| label.ends_with("PRIVATE KEY")) {
        bail!(
            "the input holds a private key; jwk from-pem converts only a public key \
             (a `-----BEGIN PUBLIC KEY-----` block), so export the public half and \
             keep the private key where it is"
        );
    }
    let Some(label) = labels.first() else {
        bail!("the input is not a PEM public key: it has no `-----BEGIN PUBLIC KEY-----` line");
    };
    if labels.len() > 1 {
        bail!(
            "the input holds {} PEM blocks; convert one public key at a time",
            labels.len()
        );
    }
    let (decoded_label, der) = pkcs8::der::pem::decode_vec(input.trim().as_bytes())
        .map_err(|_| anyhow::anyhow!("the input is not a valid PEM `{label}` block"))?;

    let jwk = match decoded_label {
        "PUBLIC KEY" => from_spki(&der, alg)?,
        "RSA PUBLIC KEY" => {
            let key = pkcs1::RsaPublicKey::from_der(&der)
                .map_err(|_| anyhow::anyhow!("the `RSA PUBLIC KEY` block is not PKCS #1"))?;
            rsa_jwk(key, alg)?
        }
        other => bail!(
            "the input is a PEM `{other}` block; jwk from-pem accepts only `PUBLIC KEY` \
             or `RSA PUBLIC KEY`"
        ),
    };
    finish(jwk)
}

/// The label of every PEM pre-encapsulation boundary in `input`, in order.
fn pem_labels(input: &str) -> Vec<&str> {
    input
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("-----BEGIN ")?
                .strip_suffix("-----")
        })
        .collect()
}

fn from_spki(der: &[u8], alg: Option<JwkAlgorithm>) -> Result<PublicJwk> {
    let spki = SubjectPublicKeyInfoRef::from_der(der)
        .map_err(|_| anyhow::anyhow!("the `PUBLIC KEY` block is not a SubjectPublicKeyInfo"))?;
    let key = spki
        .subject_public_key
        .as_bytes()
        .context("the public key bit string is not whole bytes")?;
    match spki.algorithm.oid {
        EC_PUBLIC_KEY => {
            let curve = spki
                .algorithm
                .parameters_oid()
                .map_err(|_| anyhow::anyhow!("the EC key does not name its curve"))?;
            let (crv, width, implied) = match curve {
                PRIME256V1 => ("P-256", 32, JwkAlgorithm::Es256),
                SECP384R1 => ("P-384", 48, JwkAlgorithm::Es384),
                other => bail!(
                    "unsupported EC curve {other}; jwk from-pem converts EC P-256 and P-384 keys"
                ),
            };
            let alg = match alg {
                None => implied,
                Some(named) if named == implied => named,
                Some(named) => bail!(
                    "an EC {crv} key is published as {}, not {}; pass --alg {} or omit --alg",
                    implied.jwa_name(),
                    named.jwa_name(),
                    implied.jwa_name().to_ascii_lowercase()
                ),
            };
            let coordinates = match key.split_first() {
                Some((0x04, coordinates)) if coordinates.len() == 2 * width => coordinates,
                Some((0x02 | 0x03, _)) => {
                    bail!("the EC {crv} point is compressed; export the uncompressed public key")
                }
                _ => bail!("the input is not a valid EC {crv} public key"),
            };
            let (x, y) = coordinates.split_at(width);
            Ok(PublicJwk {
                kty: "EC".to_owned(),
                kid: None,
                alg: Some(alg.jwa_name().to_owned()),
                crv: Some(crv.to_owned()),
                x: Some(URL_SAFE_NO_PAD.encode(x)),
                y: Some(URL_SAFE_NO_PAD.encode(y)),
                n: None,
                e: None,
            })
            .and_then(|jwk| validate(jwk, &format!("EC {crv}")))
        }
        RSA_ENCRYPTION => {
            let key = pkcs1::RsaPublicKey::from_der(key)
                .map_err(|_| anyhow::anyhow!("the RSA public key is not PKCS #1"))?;
            rsa_jwk(key, alg)
        }
        other => bail!(
            "unsupported key type {other}; jwk from-pem converts EC P-256, EC P-384, and RSA keys"
        ),
    }
}

fn rsa_jwk(key: pkcs1::RsaPublicKey<'_>, alg: Option<JwkAlgorithm>) -> Result<PublicJwk> {
    let alg = match alg {
        Some(alg @ (JwkAlgorithm::Rs256 | JwkAlgorithm::Rs384)) => alg,
        Some(named) => bail!(
            "an RSA key cannot be published as {}; pass --alg rs256 or --alg rs384",
            named.jwa_name()
        ),
        None => bail!(
            "an RSA key does not imply its algorithm; pass --alg rs256 or --alg rs384 \
             for the verifier that will use it"
        ),
    };
    let modulus = key.modulus.as_bytes();
    let modulus_bits = modulus.len() * 8
        - modulus
            .first()
            .map_or(8, |top| top.leading_zeros() as usize);
    if modulus_bits < MIN_RSA_MODULUS_BITS {
        bail!(
            "the RSA modulus has {modulus_bits} bits; at least {MIN_RSA_MODULUS_BITS} are required"
        );
    }
    validate(
        PublicJwk {
            kty: "RSA".to_owned(),
            kid: None,
            alg: Some(alg.jwa_name().to_owned()),
            crv: None,
            x: None,
            y: None,
            n: Some(URL_SAFE_NO_PAD.encode(modulus)),
            e: Some(URL_SAFE_NO_PAD.encode(key.public_exponent.as_bytes())),
        },
        "RSA",
    )
}

/// Round-trips the JWK through the platform parser, the same one `jwks` and the
/// runtime use, so an off-curve point or empty member is refused here rather
/// than at startup.
fn validate(jwk: PublicJwk, kind: &str) -> Result<PublicJwk> {
    let json = serde_json::to_string(&jwk).context("failed to render the public JWK")?;
    PublicJwk::parse(&json)
        .map_err(|_| anyhow::anyhow!("the input is not a valid {kind} public key"))
}

fn finish(mut jwk: PublicJwk) -> Result<PublicJwk> {
    jwk.kid = Some(
        jwk.jkt()
            .context("failed to compute the RFC 7638 thumbprint")?,
    );
    Ok(jwk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_label_anywhere_refuses_the_input() {
        // The label is assembled at run time so the source carries no
        // key-shaped block for the secret scanner to report.
        let label = ["EC", "PRIVATE", "KEY"].join(" ");
        let input = format!(
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n\
             -----BEGIN {label}-----\nAAAA\n-----END {label}-----\n"
        );
        let error = public_jwk_from_pem(&input, None).unwrap_err().to_string();
        assert!(error.contains("private key"), "{error}");
    }

    #[test]
    fn labels_are_read_from_boundary_lines_only() {
        assert_eq!(
            pem_labels("x\n  -----BEGIN PUBLIC KEY-----  \nAAAA\n-----END PUBLIC KEY-----"),
            vec!["PUBLIC KEY"]
        );
        assert!(pem_labels("-----BEGIN PUBLIC KEY").is_empty());
    }

    #[test]
    fn two_public_blocks_are_refused() {
        let block = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
        let error = public_jwk_from_pem(&format!("{block}{block}"), None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("2 PEM blocks"), "{error}");
    }
}
