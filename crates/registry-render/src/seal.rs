//! Document seals in serve: the key-holding half of a PAdES seal.
//!
//! The render worker renders the first revision and answers with it alone.
//! Everything here runs in the serving parent, after the render slot is
//! released: hash the whole answer, append the signature field
//! ([`crate::pdf_signature::prepare`]), sign the byte ranges, timestamp the
//! signature for B-T, and splice the CMS in. Every byte after the first
//! revision is the parent's own.
//!
//! A seal is loaded once, at startup, from the runtime file's
//! `signing.seals`: its certificate chain is read and parsed, its signer is
//! made (a `local-jwk` key resolved through `secretProviders` into a
//! [`LocalJwkSigner`], or a `transit` key reached through its proxy as a
//! [`TransitSigner`] that has passed its sign-and-verify self-test), the
//! signer's key is matched to the certificate, the certificate must carry a
//! signing key usage, and the space the signature field reserves is computed
//! and must fit. A certificate outside its validity, or a Transit signer
//! that has stopped answering, does not refuse startup or stop plain
//! rendering; it makes that seal unavailable, which `/ready` reports and a
//! seal request answers with a 503 problem.
//!
//! Nothing here records or returns a certificate subject, a key, or a
//! timestamp token: the audit and the response carry the certificate's
//! SHA-256 fingerprint and the token's SHA-256.

use std::collections::BTreeMap;
use std::sync::Arc;

use registry_platform_config::SecretError;
use registry_platform_crypto::{
    accept_timestamp_response, add_signature_timestamp, random_timestamp_nonce, sign_detached,
    timestamp_request, CertificateChain, CertificateError, CertificateFingerprint, CmsError,
    KeyReadiness, LocalJwkSigner, PrivateJwk, SigningAlgorithm, SigningProvider, TimestampError,
    TransitInitializationError, TransitSigner, TransitSignerConfig, MAX_TIMESTAMP_RESPONSE_BYTES,
};
use registry_platform_yaml::{Diagnostic, Severity};
use time::OffsetDateTime;

use crate::bundle::{bundle_file_name, Bundle};
use crate::envelope::SigningPayload;
use crate::hash::{sha256_digest, sha256_label};
use crate::manifest::{Manifest, MANIFEST_FILE};
use crate::pdf_signature::{PdfSignatureError, SignatureField, MAX_CONTENTS_CAPACITY};
use crate::problem::{ProblemKind, RenderProblem};
use crate::runtime::{
    RenderRuntime, SealRuntime, SealSignerRuntime, TimestampAuthorityRuntime, RUNTIME_KIND,
};
use crate::worker::WorkerSeal;

/// The partial name, `/T`, of the one signature field a seal writes.
pub const SEAL_FIELD_NAME: &str = "RegistrySeal";

/// Room for the signature value: an RSA signature under a key of up to 8192
/// bits, which also covers DER ECDSA P-256 (at most 72 bytes) and P-384 (at
/// most 104 bytes).
pub const SIGNATURE_ALLOWANCE: usize = 1024;

/// Room for the CMS structure around the certificates and the signature:
/// content info, version, algorithm identifiers, the content-type and
/// message-digest attributes, the signing-certificate-v2 hash, and the
/// headers of every SEQUENCE and SET.
pub const STRUCTURE_ALLOWANCE: usize = 1024;

/// Room for the RFC 3161 timestamp token of a B-T seal. A token larger than
/// this does not fit the reserved space and fails the seal request as a
/// timestamp failure; it is never dropped to make a B-B seal.
pub const TIMESTAMP_TOKEN_ALLOWANCE: usize = 16 * 1024;

/// Room for the headers around the two copies of the seal certificate's
/// issuer and serial number: the `IssuerAndSerialNumber` sequence, and the
/// `IssuerSerial` sequence with its `GeneralNames` and directory-name tag.
pub const ISSUER_SERIAL_HEADER_ALLOWANCE: usize = 64;

/// The bytes a seal's signature field reserves for its CMS signature,
/// computed once at load and the same for every request:
///
/// ```text
/// chain DER + 2 x (seal certificate issuer DER + serial number DER)
///   + ISSUER_SERIAL_HEADER_ALLOWANCE + SIGNATURE_ALLOWANCE
///   + STRUCTURE_ALLOWANCE + (TIMESTAMP_TOKEN_ALLOWANCE when timestamped)
/// ```
///
/// The CMS carries the chain once in `certificates`, and names the seal
/// certificate by its issuer and serial number twice: in the signer
/// identifier and in the signing-certificate-v2 attribute.
pub fn contents_capacity(
    chain_der_len: usize,
    leaf_issuer_serial_der_len: usize,
    timestamped: bool,
) -> usize {
    chain_der_len
        + 2 * leaf_issuer_serial_der_len
        + ISSUER_SERIAL_HEADER_ALLOWANCE
        + SIGNATURE_ALLOWANCE
        + STRUCTURE_ALLOWANCE
        + if timestamped {
            TIMESTAMP_TOKEN_ALLOWANCE
        } else {
            0
        }
}

/// The PAdES baseline level a seal produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealLevel {
    /// Signed, without a timestamp: the named `withoutTimestamp` choice.
    BB,
    /// Signed and timestamped by the seal's timestamp authority.
    BT,
}

impl SealLevel {
    /// The level's name on the wire: the baseline level as ETSI EN 319 142-1
    /// writes it, so a caller compares it with a validator's report as is.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BB => "B-B",
            Self::BT => "B-T",
        }
    }
}

/// Why a seal cannot sign now, as `/ready` and the seal route name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    CertificateExpired,
    CertificateNotYetValid,
    SignerNotReady,
}

impl Unavailable {
    /// The value-free reason `/ready` reports.
    pub fn reason(self) -> &'static str {
        match self {
            Self::CertificateExpired => "certificate-expired",
            Self::CertificateNotYetValid => "certificate-not-yet-valid",
            Self::SignerNotReady => "signer-not-ready",
        }
    }

    /// The problem a seal request receives while the seal is unavailable.
    pub fn problem(self, seal_id: &str) -> RenderProblem {
        match self {
            Self::CertificateExpired => RenderProblem::new(
                ProblemKind::SealCertificateInvalid,
                format!("seal {seal_id}: the seal certificate has expired"),
            )
            .with_public_detail(
                "The seal certificate has expired; contact the operator. Plain rendering is \
                 unaffected.",
            ),
            Self::CertificateNotYetValid => RenderProblem::new(
                ProblemKind::SealCertificateInvalid,
                format!("seal {seal_id}: the seal certificate is not yet valid"),
            )
            .with_public_detail(
                "The seal certificate is not yet valid; contact the operator. Plain rendering is \
                 unaffected.",
            ),
            Self::SignerNotReady => RenderProblem::new(
                ProblemKind::SigningUnavailable,
                format!("seal {seal_id}: the seal's signer is not ready"),
            ),
        }
    }
}

/// One loaded seal.
pub struct Seal {
    id: String,
    chain: CertificateChain,
    signer: Arc<dyn SigningProvider>,
    fingerprint: CertificateFingerprint,
    contents_capacity: usize,
    signing: SigningPayload,
    timestamp: Option<TimestampAuthority>,
    allowed_clients: Vec<String>,
    /// Held while one caller probes a signer that is not ready, so a burst
    /// of requests sends the provider one probe.
    recovery_probe: tokio::sync::Mutex<()>,
}

/// What a recovery probe signs: never a document, so a probe signature
/// cannot stand in for a seal.
const SIGNER_PROBE_MESSAGE: &[u8] = b"registry-render-seal-signer-probe-v1";

impl std::fmt::Debug for Seal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seal")
            .field("id", &self.id)
            .field("fingerprint", &self.fingerprint.to_string())
            .field("contents_capacity", &self.contents_capacity)
            .finish_non_exhaustive()
    }
}

/// The loaded seals, by seal id.
pub type Seals = BTreeMap<String, Arc<Seal>>;

/// Load every seal the runtime file declares; an empty map when it declares
/// no signing block. Refuses as `runtime-invalid`, with a diagnostic at the
/// failing member whose message names the failing piece and repeats no
/// value; [`crate::runtime::RuntimePositions::place`] gives it its line.
pub async fn load(runtime: &RenderRuntime) -> Result<Seals, RenderProblem> {
    let mut seals = Seals::new();
    let Some(signing) = &runtime.signing else {
        return Ok(seals);
    };
    for (id, seal) in &signing.seals {
        let loaded = Seal::load(runtime, id.as_str(), seal).await?;
        seals.insert(id.as_str().to_owned(), Arc::new(loaded));
    }
    Ok(seals)
}

/// A seal that cannot load: the runtime file is refused, whichever piece
/// failed, so every startup refusal has the one exit code.
fn refusal(
    seal_id: &str,
    member: &str,
    code: &str,
    message: String,
    action: &str,
) -> RenderProblem {
    let mut diagnostic = Diagnostic::error(
        code,
        format!("/signing/seals/{seal_id}/{member}"),
        message,
        action,
    );
    diagnostic.artifact = Some(RUNTIME_KIND.to_owned());
    RenderProblem::new(
        ProblemKind::RuntimeInvalid,
        format!("seal {seal_id} cannot be loaded"),
    )
    .with_diagnostics(vec![diagnostic])
}

/// How long before a seal certificate expires `check` warns about it.
pub const EXPIRY_WARNING_DAYS: i64 = 30;

/// One finding about a seal's certificate chain file, decided without the
/// seal's key: the half of loading a seal that an offline check may repeat,
/// since the chain is public and the key is not read (CFG-CHECK-1). The
/// message names the failing piece and repeats no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFinding {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
    pub action: &'static str,
}

/// What [`check_chain`] found about one seal's chain, and the signature
/// space the seal reserves when the chain could be sized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCheck {
    pub findings: Vec<ChainFinding>,
    pub contents_capacity: Option<usize>,
}

fn chain_error(code: &'static str, message: String, action: &'static str) -> ChainFinding {
    ChainFinding {
        severity: Severity::Error,
        code,
        message,
        action,
    }
}

fn chain_warning(code: &'static str, message: String, action: &'static str) -> ChainFinding {
    ChainFinding {
        severity: Severity::Warning,
        code,
        message,
        action,
    }
}

/// Read and parse a seal's chain file.
fn read_chain(id: &str, seal: &SealRuntime) -> Result<CertificateChain, ChainFinding> {
    let pem = std::fs::read(&seal.certificate_chain_file).map_err(|_| {
        chain_error(
            "render.runtime.seal-chain-unreadable",
            format!("signing.seals.{id}.certificateChainFile cannot be read"),
            "Mount the PEM certificate chain file at the configured path, readable by serve.",
        )
    })?;
    CertificateChain::from_pem(&pem).map_err(|error| {
        let action = if matches!(error, CertificateError::LeafIsCertificateAuthority) {
            "Seal with a leaf certificate issued for the seal key, with basicConstraints \
             CA:FALSE, and list it first, then each issuer in turn. For a test seal, \
             `registry-render keygen` writes the key and its certificate request, and your own \
             test root issues the leaf."
        } else {
            "Write the seal certificate first, then each issuer in turn, as PEM CERTIFICATE \
             blocks."
        };
        chain_error(
            "render.runtime.seal-chain-invalid",
            format!(
                "signing.seals.{id}.certificateChainFile is not a usable certificate chain: {}",
                chain_error_text(&error)
            ),
            action,
        )
    })
}

fn usage_finding(id: &str) -> ChainFinding {
    chain_error(
        "render.runtime.seal-certificate-usage",
        format!(
            "signing.seals.{id}.certificateChainFile names a seal certificate with neither the \
             digitalSignature nor the nonRepudiation key usage"
        ),
        "Use a seal certificate issued with the digitalSignature or nonRepudiation key usage.",
    )
}

/// The seal's reserved signature space, refused when it exceeds what a field
/// may reserve.
fn reserved_space(
    id: &str,
    chain: &CertificateChain,
    seal: &SealRuntime,
) -> Result<usize, ChainFinding> {
    let capacity = contents_capacity(
        chain.der_len(),
        chain.leaf_issuer_serial_der_len(),
        seal.timestamp_authority.is_some(),
    );
    if capacity > MAX_CONTENTS_CAPACITY {
        return Err(chain_error(
            "render.runtime.seal-chain-too-large",
            format!(
                "signing.seals.{id}.certificateChainFile is too large for the signature space a \
                 seal may reserve ({MAX_CONTENTS_CAPACITY} bytes)"
            ),
            "List only the seal certificate and the issuers a validator needs to build the path \
             to the trust anchor.",
        ));
    }
    Ok(capacity)
}

/// What `check --environment` can say about one seal's chain at `now`
/// without its key: every refusal serve's load would make from the chain
/// alone, then a warning for a certificate outside its validity (serve
/// starts and the seal is unavailable) or within
/// [`EXPIRY_WARNING_DAYS`] of expiring. Whether the key matches the
/// certificate is only known to serve, which reads the key.
pub fn check_chain(id: &str, seal: &SealRuntime, now: OffsetDateTime) -> ChainCheck {
    let chain = match read_chain(id, seal) {
        Ok(chain) => chain,
        Err(finding) => {
            return ChainCheck {
                findings: vec![finding],
                contents_capacity: None,
            }
        }
    };
    let mut findings = Vec::new();
    if !chain.may_sign() {
        findings.push(usage_finding(id));
    }
    if !chain.allows_document_signing_purpose() {
        findings.push(chain_warning(
            "render.runtime.seal-certificate-purpose",
            format!(
                "signing.seals.{id}.certificateChainFile names a seal certificate whose extended \
                 key usage names no document-signing purpose; validators such as Acrobat flag \
                 its seals"
            ),
            "Use a seal certificate with no extended key usage, or one that lists document \
             signing, email protection or anyExtendedKeyUsage.",
        ));
    }
    let contents_capacity = match reserved_space(id, &chain, seal) {
        Ok(capacity) => Some(capacity),
        Err(finding) => {
            findings.push(finding);
            None
        }
    };
    let replace = "Replace the seal certificate and its chain before serving seals; plain \
                   rendering is unaffected.";
    if now < chain.not_before() {
        findings.push(chain_warning(
            "render.runtime.seal-certificate-not-yet-valid",
            format!(
                "signing.seals.{id}.certificateChainFile names a seal certificate that is not yet \
                 valid; the seal is unavailable until it is"
            ),
            "Wait for the certificate's validity to start, or install a certificate valid now.",
        ));
    } else if now > chain.not_after() {
        findings.push(chain_warning(
            "render.runtime.seal-certificate-expired",
            format!(
                "signing.seals.{id}.certificateChainFile names an expired seal certificate; the \
                 seal is unavailable"
            ),
            replace,
        ));
    } else if chain.not_after() - now < time::Duration::days(EXPIRY_WARNING_DAYS) {
        findings.push(chain_warning(
            "render.runtime.seal-certificate-expiring",
            format!(
                "signing.seals.{id}.certificateChainFile names a seal certificate that expires \
                 within {EXPIRY_WARNING_DAYS} days"
            ),
            replace,
        ));
    }
    ChainCheck {
        findings,
        contents_capacity,
    }
}

#[cfg(test)]
impl Seal {
    /// A B-B seal over a test PKI seal that signs with `signer`, allowing
    /// the client `records-service`, for unit tests.
    pub(crate) fn for_test(
        id: &str,
        seal: &registry_platform_crypto::document_signature::test_support::TestSeal,
        signer: Arc<dyn SigningProvider>,
    ) -> Self {
        let chain = seal.chain().expect("test seal chain");
        let contents_capacity =
            contents_capacity(chain.der_len(), chain.leaf_issuer_serial_der_len(), false);
        Self {
            id: id.to_owned(),
            fingerprint: chain.leaf_sha256_fingerprint(),
            signing: SigningPayload {
                signer_name: chain.display_name().map(str::to_owned),
                test_only: true,
            },
            chain,
            signer,
            contents_capacity,
            timestamp: None,
            allowed_clients: vec!["records-service".to_owned()],
            recovery_probe: tokio::sync::Mutex::new(()),
        }
    }
}

/// The code of a document type whose PDF standard cannot hold the
/// signature space its seal reserves.
pub const UNSEALABLE_CODE: &str = "render.bundle.seal-space-exceeds-standard";

/// A document type whose `pdfStandard` cannot hold the signature space its
/// seal reserves ([`crate::pdf_signature::sealable`]). Sealing it would
/// write a file that is not conformant, so it is refused before any render;
/// the signature is never truncated to fit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsealableDocument {
    /// The document type's position in the manifest's `documents`.
    pub index: usize,
    pub document_id: String,
    pub seal_id: String,
    pub contents_capacity: usize,
    pub reason: &'static str,
}

impl UnsealableDocument {
    /// The manifest member the finding is placed at: the document type's
    /// `seal`.
    pub fn pointer(&self) -> String {
        format!("/documents/{}/seal", self.index)
    }

    pub fn message(&self) -> String {
        format!(
            "document type {} is sealed by {}, which reserves {} bytes for its signature: {}",
            self.document_id, self.seal_id, self.contents_capacity, self.reason
        )
    }

    pub fn action(&self) -> &'static str {
        "List only the seal certificate and the issuers a validator needs in the seal's chain, \
         or choose a pdfStandard whose string limit holds the reserved space."
    }
}

/// Every document type in `manifest` whose seal reserves more signature
/// space than its `pdfStandard` allows. `capacity` answers a seal's
/// reserved space, or `None` when it is not known, as when `check` did not
/// read the chain; such a seal adds no finding.
pub fn unsealable_documents(
    manifest: &Manifest,
    capacity: impl Fn(&str) -> Option<usize>,
) -> Vec<UnsealableDocument> {
    let mut found = Vec::new();
    for (index, document) in manifest.documents.iter().enumerate() {
        let Some(seal_id) = &document.seal else {
            continue;
        };
        let Some(contents_capacity) = capacity(seal_id) else {
            continue;
        };
        if let Err(reason) =
            crate::pdf_signature::sealable(document.pdf_standard, contents_capacity)
        {
            found.push(UnsealableDocument {
                index,
                document_id: document.id.clone(),
                seal_id: seal_id.clone(),
                contents_capacity,
                reason,
            });
        }
    }
    found
}

/// Refuse to serve a package with a document type whose PDF standard cannot
/// hold the signature space its loaded seal reserves, each finding placed at
/// that document type's `seal` member in the package's manifest.
pub fn refuse_unsealable(bundle: &Bundle, seals: &Seals) -> Result<(), RenderProblem> {
    let diagnostics = crate::check::unsealable_at(
        &bundle_file_name(&bundle.root, MANIFEST_FILE),
        Some(&bundle.manifest_bytes),
        &bundle.manifest,
        |id| seals.get(id).map(|seal| seal.contents_capacity()),
    );
    if diagnostics.is_empty() {
        return Ok(());
    }
    Err(RenderProblem::new(
        ProblemKind::RuntimeInvalid,
        "a seal reserves more signature space than a document type's PDF standard allows",
    )
    .with_diagnostics(diagnostics))
}

/// The `local-jwk` signer of seal `id`: the private JWK the file-provider
/// secret `private_key_ref` holds.
fn local_jwk_signer(
    runtime: &RenderRuntime,
    id: &str,
    private_key_ref: &str,
) -> Result<LocalJwkSigner, RenderProblem> {
    let key = |code: &str, message: String, action: &str| {
        refusal(id, "signer/privateKeyRef", code, message, action)
    };
    // The resolver's buffer erases the JWK text, private members included,
    // when it drops after parsing.
    let secret =
        crate::runtime::resolve_protected_secret(runtime, private_key_ref).map_err(|error| {
            let action = if error == SecretError::UnsafeFile {
                "Make the key file a regular file owned by the serving user, with mode 0600 or \
                 0400 and one link."
            } else {
                "Provide the seal's private key under the secret provider the reference names."
            };
            key(
                "render.runtime.seal-key-unreadable",
                format!("signing.seals.{id}.signer.privateKeyRef cannot be resolved: {error}"),
                action,
            )
        })?;
    let not_a_key = || {
        key(
            "render.runtime.seal-key-invalid",
            format!("signing.seals.{id}.signer.privateKeyRef does not hold a private JWK"),
            "Store the seal's private key as one ES256, ES384, RS256 or RS384 private JWK; \
             `registry-render keygen --from-pem` converts an unencrypted PKCS #8 key.",
        )
    };
    let text = std::str::from_utf8(secret.expose_secret()).map_err(|_| not_a_key())?;
    let mut jwk = PrivateJwk::parse(text.trim()).map_err(|_| not_a_key())?;
    drop(secret);
    // The CMS names its signer by issuer and serial number, never by key id,
    // so a seal key needs none; the seal id stands in when it has none.
    if jwk.kid.as_deref().is_none_or(|kid| kid.trim().is_empty()) {
        jwk.kid = Some(id.to_owned());
    }
    LocalJwkSigner::new(jwk).map_err(|_| not_a_key())
}

/// Seal `id`'s Transit signer could not be made: the refusal names the
/// cause [`TransitInitializationError`] gives, which carries no path, name,
/// provider answer or key material, at the member that fixes it.
fn transit_refusal(id: &str, error: TransitInitializationError) -> RenderProblem {
    use TransitInitializationError as Fault;
    let (member, action) = match error {
        Fault::Client | Fault::Unavailable => (
            "signer/unixSocketPath",
            "Start the Transit signing proxy listening on signer.unixSocketPath, reachable by \
             the serving user, then start serve again.",
        ),
        Fault::Refused => (
            "signer",
            "Check signer.mount and signer.keyName, and give the proxy's token a policy that \
             reads that key and signs with it.",
        ),
        Fault::ProviderFailed => (
            "signer",
            "Unseal Transit or restore its storage backend, then start serve again.",
        ),
        Fault::Custody => (
            "signer/keyName",
            "Seal with a Transit key of type ecdsa-p256 that is neither derived nor exportable \
             and allows no plaintext backup.",
        ),
        Fault::KeyVersionNotCreated | Fault::KeyVersionRetired | Fault::PublicKeyMismatch => (
            "signer/keyVersion",
            "Pin signer.keyVersion to the Transit key version the seal certificate certifies, \
             one between the key's min_encryption_version and latest_version.",
        ),
        Fault::SelfTest => (
            "signer",
            "Check that the proxy's token may sign with the key; its self-test signature did \
             not verify.",
        ),
        _ => (
            "signer",
            "Check that signer.unixSocketPath is a Vault or OpenBao Transit signing proxy and \
             that the signer members name the seal's key.",
        ),
    };
    refusal(
        id,
        member,
        "render.runtime.seal-transit-unavailable",
        format!("signing.seals.{id}.signer cannot sign through Transit: {error}"),
        action,
    )
}

impl Seal {
    async fn load(
        runtime: &RenderRuntime,
        id: &str,
        seal: &SealRuntime,
    ) -> Result<Self, RenderProblem> {
        let certificate = |finding: ChainFinding| {
            refusal(
                id,
                "certificateChainFile",
                finding.code,
                finding.message,
                finding.action,
            )
        };
        let chain = read_chain(id, seal).map_err(certificate)?;
        let (signer, key_member): (Arc<dyn SigningProvider>, &str) = match &seal.signer {
            SealSignerRuntime::LocalJwk { private_key_ref } => (
                Arc::new(local_jwk_signer(runtime, id, private_key_ref)?),
                "signer/privateKeyRef",
            ),
            SealSignerRuntime::Transit {
                unix_socket_path,
                mount,
                key_name,
                key_version,
                attempt_timeout_milliseconds,
            } => {
                // The key Transit holds is the seal's only if the certificate
                // certifies it, which the check below decides before the seal
                // signs anything.
                let config = TransitSignerConfig::discover(
                    unix_socket_path,
                    mount.as_str(),
                    key_name.as_str(),
                    key_version.get(),
                    std::time::Duration::from_millis(attempt_timeout_milliseconds.get()),
                )
                .await
                .map_err(|error| transit_refusal(id, error))?;
                let signer = TransitSigner::initialize(config)
                    .await
                    .map_err(|error| transit_refusal(id, error))?;
                (Arc::new(signer), "signer/keyName")
            }
        };
        let key = |code: &str, message: String, action: &str| {
            refusal(id, key_member, code, message, action)
        };
        if signer.algorithm() == SigningAlgorithm::EdDsa {
            return Err(key(
                "render.runtime.seal-key-unsupported",
                format!(
                    "signing.seals.{id}.signer.privateKeyRef is an EdDSA key; PAdES seals use ES256, \
                     ES384, RS256 or RS384"
                ),
                "Issue the seal certificate for an ECDSA P-256, ECDSA P-384 or RSA key.",
            ));
        }
        // Validity is a per-request condition, not a load failure: check the
        // key and the key usage at an instant inside the validity, so only
        // they can refuse here.
        let inside_validity = chain
            .not_before()
            .max(OffsetDateTime::now_utc().min(chain.not_after()));
        match chain.check_for_signing(&signer.public_jwk(), inside_validity) {
            Ok(())
            | Err(CertificateError::Expired { .. } | CertificateError::NotYetValid { .. }) => {}
            Err(CertificateError::KeyMismatch { .. }) => {
                return Err(match &seal.signer {
                    SealSignerRuntime::LocalJwk { .. } => key(
                        "render.runtime.seal-key-mismatch",
                        format!(
                            "signing.seals.{id}.signer.privateKeyRef does not hold the key the \
                             seal certificate certifies"
                        ),
                        "Point signer.privateKeyRef at the private key of the seal certificate, \
                         or the chain file at the certificate issued for this key.",
                    ),
                    SealSignerRuntime::Transit { .. } => key(
                        "render.runtime.seal-key-mismatch",
                        format!(
                            "signing.seals.{id}.signer names a Transit key version that is not \
                             the key the seal certificate certifies"
                        ),
                        "Point signer.keyName and signer.keyVersion at the Transit key the seal \
                         certificate was issued for, or the chain file at a certificate issued \
                         from a request `registry-render keygen --transit-unix-socket-path` \
                         signed with this key. A Transit seal key is ECDSA P-256.",
                    ),
                })
            }
            Err(CertificateError::MissingSigningKeyUsage { .. }) => {
                return Err(certificate(usage_finding(id)))
            }
            Err(error) => {
                return Err(key(
                    "render.runtime.seal-key-unsupported",
                    format!(
                        "signing.seals.{id}: the seal key cannot sign under this certificate: {}",
                        chain_error_text(&error)
                    ),
                    "Issue the seal certificate for an ECDSA P-256, ECDSA P-384 or RSA key.",
                ))
            }
        }
        let contents_capacity = reserved_space(id, &chain, seal).map_err(certificate)?;
        let timestamp = match &seal.timestamp_authority {
            None => None,
            Some(authority) => Some(TimestampAuthority::load(runtime, id, authority)?),
        };
        Ok(Self {
            id: id.to_owned(),
            fingerprint: chain.leaf_sha256_fingerprint(),
            signing: SigningPayload {
                signer_name: chain.display_name().map(str::to_owned),
                test_only: seal.is_test_only(),
            },
            chain,
            signer,
            contents_capacity,
            timestamp,
            allowed_clients: seal.allowed_clients.as_slice().to_vec(),
            recovery_probe: tokio::sync::Mutex::new(()),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether the seal certificate's extended key usage, if any, names a
    /// document-signing purpose.
    pub fn allows_document_signing_purpose(&self) -> bool {
        self.chain.allows_document_signing_purpose()
    }

    /// Whether the runtime file declares the seal `trust: test-only`.
    pub fn is_test_only(&self) -> bool {
        self.signing.test_only
    }

    pub fn level(&self) -> SealLevel {
        if self.timestamp.is_some() {
            SealLevel::BT
        } else {
            SealLevel::BB
        }
    }

    pub fn contents_capacity(&self) -> usize {
        self.contents_capacity
    }

    /// The seal certificate's labelled SHA-256 digest, `sha256:<hex>` over
    /// its DER: its fingerprint, in the form every Render digest takes.
    pub fn certificate_digest(&self) -> String {
        sha256_label(&self.fingerprint.to_string())
    }

    /// Whether the seal's `allowedClients` names this verified client.
    pub fn allows_client(&self, client_id: &str) -> bool {
        self.allowed_clients
            .iter()
            .any(|client| client == client_id)
    }

    /// Give a signer that said it is not ready one chance to recover: one
    /// probe signature, which the signer verifies and records in its
    /// readiness. A Transit signer turns not ready when a call fails, and
    /// only a later call that succeeds turns it back, so the seal route and
    /// `/ready` probe before they ask [`Seal::availability`]. A ready signer
    /// is never called, and concurrent callers share one probe.
    pub async fn recover_signer(&self) {
        let Ok(_probe) = self.recovery_probe.try_lock() else {
            return;
        };
        // Read under the lock: a probe that just finished has set it.
        if self.signer.readiness() != KeyReadiness::NotReady {
            return;
        }
        if let Err(error) = self.signer.sign(SIGNER_PROBE_MESSAGE).await {
            tracing::warn!(
                target: "registry_render::seal",
                seal_id = %self.id,
                %error,
                "seal signer is still not ready"
            );
        }
    }

    /// Whether the seal can sign at `now`. Readiness asks this too; it never
    /// requests a timestamp.
    pub fn availability(&self, now: OffsetDateTime) -> Result<(), Unavailable> {
        if now < self.chain.not_before() {
            return Err(Unavailable::CertificateNotYetValid);
        }
        if now > self.chain.not_after() {
            return Err(Unavailable::CertificateExpired);
        }
        match self.signer.readiness() {
            KeyReadiness::NotReady => Err(Unavailable::SignerNotReady),
            _ => Ok(()),
        }
    }

    /// Whether a seal that can sign at `now` stops within
    /// [`EXPIRY_WARNING_DAYS`], the window `check --environment` warns in.
    pub fn expires_soon(&self, now: OffsetDateTime) -> bool {
        self.chain.not_after() - now < time::Duration::days(EXPIRY_WARNING_DAYS)
    }

    /// What the worker needs to render this seal's first revision: the
    /// template payload's `signing` member.
    pub fn worker_seal(&self) -> WorkerSeal {
        WorkerSeal {
            signing: self.signing.clone(),
        }
    }

    /// The signature field this seal writes at `signing_time`, the parent's
    /// clock truncated to whole seconds.
    pub(crate) fn signature_field(
        &self,
        signing_time: OffsetDateTime,
    ) -> Result<SignatureField, RenderProblem> {
        let signing_time = chrono::DateTime::from_timestamp(signing_time.unix_timestamp(), 0)
            .ok_or_else(|| {
                RenderProblem::new(
                    ProblemKind::Internal,
                    format!("seal {}: the signing time is out of range", self.id),
                )
            })?;
        Ok(SignatureField {
            signing_time,
            contents_capacity: self.contents_capacity,
            field_name: SEAL_FIELD_NAME.to_owned(),
        })
    }

    /// Seal the first revision a worker rendered, signed at `signing_time`:
    /// hash the whole of it as `documentDigest`, append this seal's
    /// signature field, then sign, timestamp and embed. The worker's answer
    /// must be a single-revision PDF; one that carries an update or bytes
    /// after its end marker is refused before anything is signed. Reading
    /// the PDF is blocking work, so it runs off the async workers; the
    /// caller bounds `first_revision` by the output limit. `in_flight` is
    /// the caller's place for this seal, held until the seal ends or, when
    /// this future is dropped first, until the blocking work does.
    pub async fn seal(
        &self,
        first_revision: Vec<u8>,
        signing_time: OffsetDateTime,
        in_flight: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<SealedDocument, RenderProblem> {
        let internal = |detail: String| RenderProblem::new(ProblemKind::Internal, detail);
        let field = self.signature_field(signing_time)?;
        // The place travels with the blocking work and back: if this future
        // is dropped, the work runs on and the place is released only when
        // it ends.
        let (_in_flight, prepared) = tokio::task::spawn_blocking(move || {
            let document_digest = sha256_digest(&first_revision);
            let prepared = crate::pdf_signature::prepare(&first_revision, &field)
                .map(|prepared| (document_digest, prepared));
            (in_flight, prepared)
        })
        .await
        .map_err(|error| {
            internal(format!(
                "seal {}: preparing the signature field stopped: {error}",
                self.id
            ))
        })?;
        let (document_digest, prepared) = prepared.map_err(|error| {
            internal(format!(
                "seal {}: the rendered document cannot be sealed: {error}",
                self.id
            ))
        })?;
        let signature = sign_detached(&prepared.signed_parts(), &self.chain, self.signer.as_ref())
            .await
            .map_err(|error| self.signing_problem(error))?;
        let (cms_der, timestamp) = match &self.timestamp {
            None => (signature.cms_der, None),
            Some(authority) => {
                let token = authority.stamp(&signature.signature_value).await?;
                let stamped = add_signature_timestamp(&signature.cms_der, &token.token_der)
                    .map_err(|_| {
                        authority.failure(TimestampFailure::InvalidToken, "token-not-embeddable")
                    })?;
                let gen_time = timestamped_at(token.gen_time).ok_or_else(|| {
                    authority.failure(TimestampFailure::InvalidToken, "gen-time-not-rfc3339")
                })?;
                let stamp = AppliedTimestamp {
                    timestamped_at: gen_time,
                    token_digest: sha256_digest(&token.token_der),
                };
                (stamped, Some(stamp))
            }
        };
        let pdf = prepared
            .embed(&cms_der)
            .map_err(|error| match (error, &self.timestamp) {
                (PdfSignatureError::SignatureTooLarge { .. }, Some(authority)) => {
                    authority.failure(TimestampFailure::TooLarge, "token-too-large")
                }
                (error, _) => internal(format!(
                    "seal {}: the signature could not be embedded: {error}",
                    self.id
                )),
            })?;
        Ok(SealedDocument {
            signed_file_digest: sha256_digest(&pdf),
            pdf,
            document_digest,
            level: self.level(),
            certificate_digest: self.certificate_digest(),
            timestamp,
        })
    }

    fn signing_problem(&self, error: CmsError) -> RenderProblem {
        match error {
            CmsError::Certificate(CertificateError::Expired { .. }) => {
                Unavailable::CertificateExpired.problem(&self.id)
            }
            CmsError::Certificate(CertificateError::NotYetValid { .. }) => {
                Unavailable::CertificateNotYetValid.problem(&self.id)
            }
            CmsError::Certificate(error) => RenderProblem::new(
                ProblemKind::SealCertificateInvalid,
                format!(
                    "seal {}: the seal certificate may not sign: {}",
                    self.id,
                    chain_error_text(&error)
                ),
            ),
            CmsError::Signing(_) => RenderProblem::new(
                ProblemKind::SigningUnavailable,
                format!("seal {}: the signing key provider failed", self.id),
            ),
            other => RenderProblem::new(
                ProblemKind::Internal,
                format!(
                    "seal {}: the signature could not be produced: {other}",
                    self.id
                ),
            ),
        }
    }
}

/// A certificate refusal in words that name the piece and carry no value:
/// no fingerprint, subject or position beyond the block number.
fn chain_error_text(error: &CertificateError) -> String {
    match error {
        CertificateError::Empty => "the file holds no PEM certificate".to_owned(),
        CertificateError::MalformedPem { position } => format!("PEM block {position} is malformed"),
        CertificateError::NotACertificate { position } => {
            format!("PEM block {position} is not a CERTIFICATE")
        }
        CertificateError::MalformedCertificate { position } => {
            format!("certificate {position} is not a DER X.509 certificate")
        }
        CertificateError::DuplicateCertificate { position } => {
            format!("certificate {position} appears earlier in the chain")
        }
        CertificateError::ChainOutOfOrder { position } => format!(
            "certificate {position} was not issued by the certificate after it; list the seal \
             certificate first, then each issuer in turn"
        ),
        CertificateError::LeafIsCertificateAuthority => "certificate 1 is a CA certificate \
             (basicConstraints CA:TRUE), and the first certificate in the file is taken as the \
             seal certificate: a CA certificate certifies other certificates, and validators \
             refuse it as the signer of a document"
            .to_owned(),
        CertificateError::KeyMismatch { .. } => {
            "the seal certificate does not hold the signing key's public key".to_owned()
        }
        CertificateError::MissingSigningKeyUsage { .. } => {
            "the seal certificate has neither the digitalSignature nor the nonRepudiation key usage"
                .to_owned()
        }
        CertificateError::NotYetValid { .. } => "the seal certificate is not yet valid".to_owned(),
        CertificateError::Expired { .. } => "the seal certificate has expired".to_owned(),
        CertificateError::UnsupportedKey { .. } => {
            "the seal key is not an ECDSA P-256, ECDSA P-384 or RSA key".to_owned()
        }
        _ => "the certificate chain was refused".to_owned(),
    }
}

/// A sealed file and the values the response and the audit record.
#[derive(Debug, Clone)]
pub struct SealedDocument {
    pub pdf: Vec<u8>,
    /// `sha256:<hex>` over the first revision: the whole of the worker's
    /// answer, computed by the parent before it appends the signature field.
    pub document_digest: String,
    /// `sha256:<hex>` over the whole signed file.
    pub signed_file_digest: String,
    pub level: SealLevel,
    /// `sha256:<hex>` over the seal certificate's DER.
    pub certificate_digest: String,
    /// Present for a B-T seal.
    pub timestamp: Option<AppliedTimestamp>,
}

/// A timestamp token's `genTime` as `timestampedAt` reports it: RFC 3339 in
/// UTC, at the precision the authority wrote, so fractional seconds appear
/// only when `genTime` has them. `None` for a time RFC 3339 cannot write.
fn timestamped_at(gen_time: OffsetDateTime) -> Option<String> {
    gen_time
        .to_offset(time::UtcOffset::UTC)
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// The timestamp a B-T seal carries.
#[derive(Debug, Clone)]
pub struct AppliedTimestamp {
    /// The token's `genTime`, RFC 3339 in UTC, at the precision the
    /// authority wrote it: fractional seconds only when `genTime` has them.
    pub timestamped_at: String,
    /// `sha256:<hex>` over the DER token.
    pub token_digest: String,
}

/// Which piece of the timestamp exchange failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampFailure {
    /// No answer within the attempt timeout, or the connection failed.
    Unreachable,
    /// The authority answered with an HTTP error or a status that grants no
    /// token.
    Refused,
    /// The answer is not a timestamp reply, or its token does not verify or
    /// does not cover this signature.
    InvalidToken,
    /// The answer exceeds what Render accepts, or its token does not fit the
    /// space the seal reserves.
    TooLarge,
}

impl TimestampFailure {
    fn operator_text(self) -> &'static str {
        match self {
            Self::Unreachable => "the timestamp authority could not be reached",
            Self::Refused => "the timestamp authority refused the request",
            Self::InvalidToken => "the timestamp authority returned an invalid timestamp token",
            Self::TooLarge => "the timestamp token is too large for the space the seal reserves",
        }
    }

    fn public_text(self) -> &'static str {
        match self {
            Self::Unreachable => {
                "The timestamp authority could not be reached within its attempt timeout; retry \
                 later."
            }
            Self::Refused => "The timestamp authority refused the request; contact the operator.",
            Self::InvalidToken => {
                "The timestamp authority returned an invalid timestamp token; contact the \
                 operator."
            }
            Self::TooLarge => {
                "The timestamp authority's answer is too large for the space the seal reserves; \
                 contact the operator."
            }
        }
    }
}

/// One seal's RFC 3161 timestamp authority: one attempt per seal request,
/// bounded by `attemptTimeoutMilliseconds`, never retried.
struct TimestampAuthority {
    seal_id: String,
    url: reqwest::Url,
    client: reqwest::Client,
}

const TIMESTAMP_QUERY: &str = "application/timestamp-query";
const TIMESTAMP_REPLY: &str = "application/timestamp-reply";

impl TimestampAuthority {
    /// The authority a seal declares, its CA bundle resolved when it names
    /// one.
    fn load(
        runtime: &RenderRuntime,
        seal_id: &str,
        authority: &TimestampAuthorityRuntime,
    ) -> Result<Self, RenderProblem> {
        let Some(reference) = authority.ca_bundle_ref.as_deref() else {
            return Self::new(seal_id, authority, None);
        };
        let bundle =
            crate::runtime::resolve_protected_secret(runtime, reference).map_err(|error| {
                refusal(
                    seal_id,
                    "timestampAuthority/caBundleRef",
                    "render.runtime.seal-timestamp-ca-bundle-unreadable",
                    format!(
                        "signing.seals.{seal_id}.timestampAuthority.caBundleRef cannot be \
                         resolved: {error}"
                    ),
                    "Provide the timestamp authority's PEM CA bundle under the secret provider \
                     the reference names.",
                )
            })?;
        Self::new(seal_id, authority, Some(bundle.expose_secret()))
    }

    fn new(
        seal_id: &str,
        authority: &TimestampAuthorityRuntime,
        trusted_root_certificates: Option<&[u8]>,
    ) -> Result<Self, RenderProblem> {
        let unusable = || {
            refusal(
                seal_id,
                "timestampAuthority",
                "render.runtime.seal-timestamp-client",
                format!("signing.seals.{seal_id}.timestampAuthority cannot be used"),
                "Check the timestamp authority URL and the host's trusted root certificates.",
            )
        };
        let url = reqwest::Url::parse(authority.url.to_url().as_str()).map_err(|_| unusable())?;
        let attempt_timeout = authority.attempt_timeout();
        let client = registry_platform_httputil::client::build_client(
            registry_platform_httputil::client::OutboundOptions {
                request_timeout: attempt_timeout,
                connect_timeout: attempt_timeout,
                user_agent: Some("registry-render"),
                trusted_root_certificates,
            },
        )
        .map_err(|reason| match trusted_root_certificates {
            None => unusable(),
            Some(_) => refusal(
                seal_id,
                "timestampAuthority/caBundleRef",
                "render.runtime.seal-timestamp-ca-bundle-invalid",
                format!("signing.seals.{seal_id}.timestampAuthority.caBundleRef: {reason}"),
                "Store the PEM certificates of the authorities that issue the timestamp \
                 authority's TLS certificate under the reference.",
            ),
        })?;
        Ok(Self {
            seal_id: seal_id.to_owned(),
            url,
            client,
        })
    }

    /// The problem for a failed exchange: `failure` names the piece for the
    /// caller, and `reason`, a value-free kebab-case name of the failing
    /// check, goes to the operator's log and the audit.
    fn failure(&self, failure: TimestampFailure, reason: &'static str) -> RenderProblem {
        RenderProblem::new(
            ProblemKind::TimestampFailed,
            format!(
                "seal {}: {} ({reason})",
                self.seal_id,
                failure.operator_text()
            ),
        )
        .with_public_detail(failure.public_text())
        .with_reason(reason)
    }

    async fn stamp(
        &self,
        signature_value: &[u8],
    ) -> Result<registry_platform_crypto::SignatureTimestamp, RenderProblem> {
        let internal = || {
            RenderProblem::new(
                ProblemKind::Internal,
                format!(
                    "seal {}: the timestamp request could not be built",
                    self.seal_id
                ),
            )
        };
        let nonce = random_timestamp_nonce().map_err(|_| internal())?;
        let query = timestamp_request(signature_value, nonce).map_err(|_| internal())?;
        let response = self
            .client
            .post(self.url.clone())
            .header(reqwest::header::CONTENT_TYPE, TIMESTAMP_QUERY)
            .header(reqwest::header::ACCEPT, TIMESTAMP_REPLY)
            .body(query)
            .send()
            .await
            .map_err(|error| {
                self.failure(TimestampFailure::Unreachable, transport_reason(&error))
            })?;
        if !response.status().is_success() {
            return Err(self.failure(TimestampFailure::Refused, "http-status"));
        }
        let is_reply = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|media| media.trim().eq_ignore_ascii_case(TIMESTAMP_REPLY));
        if !is_reply {
            return Err(self.failure(TimestampFailure::InvalidToken, "not-a-timestamp-reply"));
        }
        let reply =
            registry_platform_httputil::read_bounded(response, MAX_TIMESTAMP_RESPONSE_BYTES as u64)
                .await
                .map_err(|error| match error {
                    registry_platform_httputil::BoundedReadError::Transport(error) => {
                        self.failure(TimestampFailure::Unreachable, transport_reason(&error))
                    }
                    _ => self.failure(TimestampFailure::TooLarge, "response-too-large"),
                })?;
        accept_timestamp_response(&reply, signature_value, nonce).map_err(|error| {
            let (failure, reason) = response_failure(&error);
            self.failure(failure, reason)
        })
    }
}

/// The reason for a transport failure: the attempt timeout, or any other
/// connection failure.
fn transport_reason(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timed-out"
    } else {
        "connection-failed"
    }
}

/// The piece and the value-free reason for a refused timestamp response.
fn response_failure(error: &TimestampError) -> (TimestampFailure, &'static str) {
    use TimestampFailure::{InvalidToken, Refused, TooLarge};
    match error {
        TimestampError::NotGranted { .. } => (Refused, "not-granted"),
        TimestampError::ResponseTooLarge => (TooLarge, "response-too-large"),
        TimestampError::MalformedResponse => (InvalidToken, "malformed-response"),
        TimestampError::MissingToken => (InvalidToken, "missing-token"),
        TimestampError::NotTstInfo => (InvalidToken, "not-tst-info"),
        TimestampError::MalformedTstInfo => (InvalidToken, "malformed-tst-info"),
        TimestampError::MessageImprintMismatch => (InvalidToken, "message-imprint-mismatch"),
        TimestampError::NonceMismatch => (InvalidToken, "nonce-mismatch"),
        TimestampError::TokenSignature(_) => (InvalidToken, "token-signature-invalid"),
        TimestampError::TsaCertificateNotForTimestamping { .. } => {
            (InvalidToken, "tsa-certificate-not-for-timestamping")
        }
        TimestampError::TsaCertificateNotValidAtGenTime { .. } => {
            (InvalidToken, "tsa-certificate-not-valid-at-gen-time")
        }
        TimestampError::TsaCertificateNotNamedBySigningCertificate { .. } => {
            (InvalidToken, "tsa-certificate-not-named-by-token")
        }
        _ => (InvalidToken, "invalid-token"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use registry_platform_crypto::document_signature::test_support::TestPki;
    use registry_platform_crypto::{PublicJwk, SigningError};

    use crate::worker::seal_tests::sealed_receipt;

    /// A place for one seal in flight, from a service of one.
    fn place() -> tokio::sync::OwnedSemaphorePermit {
        Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .expect("a free place")
    }

    /// A client that disconnects drops its seal's future, but preparing the
    /// field is blocking work that runs on. The seal's place goes with that
    /// work and comes back only when it ends, so the drain, which waits for
    /// every place, waits for it too. With the one blocking thread busy, the
    /// preparation waits in the queue, holding the place, until it is free.
    #[test]
    fn a_dropped_seal_keeps_its_place_until_its_blocking_work_ends() {
        use std::future::Future as _;
        use std::task::{Context, Waker};

        let pki = TestPki::generate().expect("test PKI");
        let test_seal = pki.issue_seal(SigningAlgorithm::Es256).expect("test seal");
        let seal = Seal::for_test(
            "ministry",
            &test_seal,
            Arc::new(test_seal.signer().expect("test signer")),
        );
        let first_revision = sealed_receipt(seal.worker_seal());
        let places = Arc::new(tokio::sync::Semaphore::new(1));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let busy = tokio::task::spawn_blocking(move || wait.recv());
            let held = Arc::clone(&places).try_acquire_owned().expect("a place");
            let mut sealing = Box::pin(seal.seal(first_revision, OffsetDateTime::now_utc(), held));
            assert!(sealing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            drop(sealing);
            assert_eq!(
                places.available_permits(),
                0,
                "the queued preparation holds the place"
            );
            release.send(()).expect("the busy task waits");
            busy.await.expect("busy task").expect("released");
            let _place = places.acquire().await.expect("the place comes back");
        });
    }

    /// A signer that counts its signatures, so a test can show that a
    /// refused answer was never signed.
    struct CountingSigner {
        inner: LocalJwkSigner,
        signatures: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SigningProvider for CountingSigner {
        fn algorithm(&self) -> SigningAlgorithm {
            self.inner.algorithm()
        }

        fn key_id(&self) -> &str {
            self.inner.key_id()
        }

        fn public_jwk(&self) -> PublicJwk {
            self.inner.public_jwk()
        }

        async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
            self.signatures.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(payload).await
        }
    }

    /// S1: a worker answers with the first revision only and the parent
    /// writes everything after it, so `documentDigest` covers every byte a
    /// worker chose. The review's proof of concept put a content stream and
    /// a second signature dictionary, its name escaped past a byte scan,
    /// between the first revision and the parent's signature dictionary,
    /// and kept the digest equal to an honest render. Here the same bytes
    /// after the end marker, and an update of the worker's own, are refused
    /// before anything is signed; an honest answer seals into the answer
    /// followed by exactly the update the parent writes for it.
    #[tokio::test]
    async fn a_worker_cannot_put_signed_bytes_outside_the_document_digest() {
        let pki = TestPki::generate().expect("test PKI");
        let test_seal = pki.issue_seal(SigningAlgorithm::Es256).expect("test seal");
        let signer = Arc::new(CountingSigner {
            inner: test_seal.signer().expect("test signer"),
            signatures: AtomicUsize::new(0),
        });
        let seal = Seal::for_test("ministry", &test_seal, Arc::clone(&signer) as _);
        let now = OffsetDateTime::now_utc();
        let honest = sealed_receipt(seal.worker_seal());

        let mut smuggled = honest.clone();
        smuggled.extend_from_slice(
            b"90 0 obj\n<</Length 21>>\nstream\nBT (SMUGGLED TEXT) ET\nendstream\nendobj\n\
              91 0 obj\n<</Type/Sig/Byte#52ange[0 0 0 0]/Contents<00>>>\nendobj\n",
        );
        let field = seal.signature_field(now).expect("a field");
        let own_update = crate::pdf_signature::prepare(&honest, &field)
            .expect("an update")
            .bytes()
            .to_vec();
        for (label, answer) in [
            ("bytes after the end marker", smuggled),
            ("an update of the worker's own", own_update),
        ] {
            let Err(problem) = seal.seal(answer, now, place()).await else {
                panic!("{label}: sealed");
            };
            assert_eq!(problem.kind, ProblemKind::Internal, "{label}");
        }
        assert_eq!(
            signer.signatures.load(Ordering::SeqCst),
            0,
            "nothing signed"
        );

        let sealed = seal
            .seal(honest.clone(), now, place())
            .await
            .expect("seals");
        assert_eq!(signer.signatures.load(Ordering::SeqCst), 1);
        assert_eq!(sealed.document_digest, sha256_digest(&honest));
        let expected = crate::pdf_signature::prepare(&honest, &field).expect("the parent's update");
        let [_, gap_start, gap_end, _] = expected.byte_range();
        let mut unsigned = sealed.pdf.clone();
        unsigned[gap_start + 1..gap_end - 1].fill(b'0');
        assert!(
            unsigned == expected.bytes(),
            "the sealed file is the answer and the parent's update"
        );
    }

    #[test]
    fn timestamped_at_keeps_the_precision_the_authority_wrote() {
        let whole = time::macros::datetime!(2026-11-06 10:00:00 UTC);
        assert_eq!(timestamped_at(whole).unwrap(), "2026-11-06T10:00:00Z");
        let fraction = time::macros::datetime!(2026-11-06 10:00:00.25 UTC);
        assert_eq!(timestamped_at(fraction).unwrap(), "2026-11-06T10:00:00.25Z");
        let micros = time::macros::datetime!(2026-11-06 10:00:00.000123 UTC);
        assert_eq!(
            timestamped_at(micros).unwrap(),
            "2026-11-06T10:00:00.000123Z"
        );
    }

    /// What a seal sends the worker is the signing payload alone; none of
    /// the seal key's private members, for an elliptic curve key or an RSA
    /// key.
    #[test]
    fn the_seal_key_never_crosses_into_the_worker() {
        use std::collections::BTreeSet;

        use crate::worker::seal_tests::receipt_request;

        let pki = TestPki::generate().expect("test PKI");
        for algorithm in [SigningAlgorithm::Es256, SigningAlgorithm::Rs256] {
            let test_seal = pki.issue_seal(algorithm).expect("test seal");
            let signer = Arc::new(test_seal.signer().expect("test signer"));
            let seal = Seal::for_test("ministry", &test_seal, signer);
            let request = receipt_request(Some(seal.worker_seal()));
            let sent = serde_json::to_value(&request).expect("worker request");
            let members: BTreeSet<&str> = sent["seal"]
                .as_object()
                .expect("the seal member")
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(members, BTreeSet::from(["signing"]), "{algorithm:?}");
            let jwk = test_seal.private_jwk();
            let private: Vec<&str> = [&jwk.d, &jwk.p, &jwk.q, &jwk.dp, &jwk.dq, &jwk.qi]
                .into_iter()
                .flatten()
                .map(String::as_str)
                .collect();
            let expected = match algorithm {
                SigningAlgorithm::Rs256 => 6,
                _ => 1,
            };
            assert_eq!(private.len(), expected, "{algorithm:?} private members");
            let sent = sent.to_string();
            for value in private {
                assert!(
                    !sent.contains(value),
                    "{algorithm:?}: a private key member reached the worker request"
                );
            }
        }
    }

    /// The CMS carries the chain once and names the seal certificate by its
    /// issuer and serial number twice, so a seal certificate with larger
    /// extensions grows the reserved space by its own growth once, and the
    /// space still holds the signature a seal makes with it.
    #[tokio::test]
    async fn the_reserved_space_counts_the_seal_certificate_once() {
        let pki = TestPki::generate().expect("test PKI");
        let small = pki.issue_seal(SigningAlgorithm::Es256).expect("seal");
        let large = pki
            .issue_seal_with(SigningAlgorithm::Es256, |params| {
                params
                    .custom_extensions
                    .push(rcgen::CustomExtension::from_oid_content(
                        &[1, 3, 6, 1, 4, 1, 55555, 1],
                        vec![0x5a; 8 * 1024],
                    ));
            })
            .expect("seal with a large extension");
        let seal_of =
            |test_seal: &registry_platform_crypto::document_signature::test_support::TestSeal| {
                Seal::for_test(
                    "ministry",
                    test_seal,
                    Arc::new(test_seal.signer().expect("test signer")),
                )
            };
        let (small_seal, large_seal) = (seal_of(&small), seal_of(&large));
        let growth = large.chain().unwrap().der_len() - small.chain().unwrap().der_len();
        assert!(growth > 8 * 1024);
        assert_eq!(
            large_seal.contents_capacity() - small_seal.contents_capacity(),
            growth
        );

        let first_revision = sealed_receipt(large_seal.worker_seal());
        large_seal
            .seal(first_revision, OffsetDateTime::now_utc(), place())
            .await
            .expect("the signature fits the reserved space");
    }

    #[test]
    fn the_reserved_space_follows_the_documented_formula() {
        assert_eq!(
            contents_capacity(1200, 150, false),
            1200 + 300 + 64 + 1024 + 1024
        );
        assert_eq!(
            contents_capacity(1200, 150, true),
            1200 + 300 + 64 + 1024 + 1024 + 16 * 1024
        );
        assert!(
            contents_capacity(0, 0, true) < MAX_CONTENTS_CAPACITY,
            "the fixed allowances leave room for a chain"
        );
    }

    /// A signer whose readiness follows its last signature, as a Transit
    /// signer's does, and whose signatures succeed while `healthy` is set.
    struct ProbedSigner {
        inner: LocalJwkSigner,
        healthy: std::sync::atomic::AtomicBool,
        ready: std::sync::atomic::AtomicBool,
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SigningProvider for ProbedSigner {
        fn algorithm(&self) -> SigningAlgorithm {
            self.inner.algorithm()
        }

        fn key_id(&self) -> &str {
            self.inner.key_id()
        }

        fn public_jwk(&self) -> PublicJwk {
            self.inner.public_jwk()
        }

        fn readiness(&self) -> KeyReadiness {
            if self.ready.load(Ordering::SeqCst) {
                KeyReadiness::Ready
            } else {
                KeyReadiness::NotReady
            }
        }

        async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let healthy = self.healthy.load(Ordering::SeqCst);
            self.ready.store(healthy, Ordering::SeqCst);
            if healthy {
                self.inner.sign(payload).await
            } else {
                Err(SigningError::external("the provider is away"))
            }
        }
    }

    /// A signer that turned not ready gets one probe per recovery, shared by
    /// concurrent callers, and the seal is available again once the probe
    /// signs; a ready signer is never probed.
    #[tokio::test]
    async fn a_signer_that_turned_not_ready_is_probed_once_and_recovers() {
        let pki = TestPki::generate().expect("test PKI");
        let test_seal = pki.issue_seal(SigningAlgorithm::Es256).expect("test seal");
        let signer = Arc::new(ProbedSigner {
            inner: test_seal.signer().expect("test signer"),
            healthy: std::sync::atomic::AtomicBool::new(false),
            ready: std::sync::atomic::AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        });
        let seal = Seal::for_test("ministry", &test_seal, Arc::clone(&signer) as _);
        let now = OffsetDateTime::now_utc();

        tokio::join!(seal.recover_signer(), seal.recover_signer());
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1, "one shared probe");
        assert_eq!(seal.availability(now), Err(Unavailable::SignerNotReady));

        signer.healthy.store(true, Ordering::SeqCst);
        seal.recover_signer().await;
        assert_eq!(signer.calls.load(Ordering::SeqCst), 2);
        assert_eq!(seal.availability(now), Ok(()));

        seal.recover_signer().await;
        assert_eq!(
            signer.calls.load(Ordering::SeqCst),
            2,
            "a ready signer is not probed"
        );
    }

    #[test]
    fn levels_and_reasons_have_stable_names() {
        assert_eq!(SealLevel::BT.as_str(), "B-T");
        assert_eq!(SealLevel::BB.as_str(), "B-B");
        for (reason, name, kind) in [
            (
                Unavailable::CertificateExpired,
                "certificate-expired",
                ProblemKind::SealCertificateInvalid,
            ),
            (
                Unavailable::CertificateNotYetValid,
                "certificate-not-yet-valid",
                ProblemKind::SealCertificateInvalid,
            ),
            (
                Unavailable::SignerNotReady,
                "signer-not-ready",
                ProblemKind::SigningUnavailable,
            ),
        ] {
            assert_eq!(reason.reason(), name);
            assert_eq!(reason.problem("ministry").kind, kind);
        }
    }

    #[test]
    fn a_document_type_is_unsealable_when_its_standard_cannot_hold_the_reserved_space() {
        let manifest = crate::manifest::Manifest::parse(
            concat!(
                "apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1\n",
                "kind: RenderBundle\n",
                "bundleVersion: 1\n",
                "documents:\n",
                "  - {id: plain, version: 1, entryFile: templates/plain.typ, seal: ministry}\n",
                "  - {id: archive2, version: 1, entryFile: templates/archive2.typ, pdfStandard: a-2b, seal: ministry}\n",
                "  - {id: archive1, version: 1, entryFile: templates/archive1.typ, pdfStandard: a-1b, seal: ministry}\n",
                "  - {id: other, version: 1, entryFile: templates/other.typ, pdfStandard: a-2b, seal: regional}\n",
                "  - {id: unsealed, version: 1, entryFile: templates/unsealed.typ, pdfStandard: a-2b}\n",
            )
            .as_bytes(),
        )
        .unwrap();
        let reserving =
            |capacity: usize| move |seal: &str| (seal == "ministry").then_some(capacity);

        assert!(unsealable_documents(&manifest, reserving(32_767)).is_empty());

        let found = unsealable_documents(&manifest, reserving(40_000));
        assert_eq!(found.len(), 1, "{found:?}");
        let archive2 = &found[0];
        assert_eq!(archive2.pointer(), "/documents/1/seal");
        assert_eq!(archive2.document_id, "archive2");
        assert_eq!(archive2.seal_id, "ministry");
        assert!(
            archive2.message().contains("40000 bytes"),
            "{}",
            archive2.message()
        );
        assert!(
            archive2
                .message()
                .contains("PDF/A-2 and PDF/A-3 limit a string to 32767 bytes"),
            "{}",
            archive2.message()
        );

        let found = unsealable_documents(&manifest, reserving(70_000));
        let pointers: Vec<_> = found.iter().map(UnsealableDocument::pointer).collect();
        assert_eq!(pointers, ["/documents/1/seal", "/documents/2/seal"]);
    }
}
