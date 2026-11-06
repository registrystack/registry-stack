//! Document seals in serve: the key-holding half of a PAdES seal.
//!
//! The render worker renders the first revision and appends a signature
//! field the parent fixed ([`crate::pdf_signature::prepare`]). Everything
//! here runs in the serving parent, after the render slot is released: check
//! the prepared file's fixed shape, hash the first revision, sign the byte
//! ranges, timestamp the signature for B-T, and splice the CMS in.
//!
//! A seal is loaded once, at startup, from the runtime file's
//! `signing.seals`: its certificate chain is read and parsed, its private key
//! resolved through `secretProviders` into a [`LocalJwkSigner`], the key is
//! matched to the certificate, the certificate must carry a signing key
//! usage, and the space the signature field reserves is computed and must fit.
//! A certificate outside its validity does not refuse startup; it makes that
//! seal unavailable, which `/ready` reports and a seal request answers with a
//! 503 problem.
//!
//! Nothing here records or returns a certificate subject, a key, or a
//! timestamp token: the audit and the response carry the certificate's
//! SHA-256 fingerprint and the token's SHA-256.

use std::collections::BTreeMap;
use std::sync::Arc;

use registry_platform_crypto::{
    accept_timestamp_response, add_signature_timestamp, random_timestamp_nonce, sign_detached,
    timestamp_request, CertificateChain, CertificateError, CertificateFingerprint, CmsError,
    KeyReadiness, LocalJwkSigner, PrivateJwk, SigningAlgorithm, SigningProvider, TimestampError,
    MAX_TIMESTAMP_RESPONSE_BYTES,
};
use registry_platform_yaml::{Diagnostic, Severity};
use time::OffsetDateTime;

use crate::envelope::SigningPayload;
use crate::hash::sha256_hex;
use crate::manifest::{Manifest, MANIFEST_KIND};
use crate::pdf_signature::{PdfSignatureError, MAX_CONTENTS_CAPACITY};
use crate::problem::{ProblemKind, RenderProblem};
use crate::runtime::{RenderRuntime, SealRuntime, RUNTIME_KIND};
use crate::worker::{WorkerPrepared, WorkerSeal};

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
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BB => "b-b",
            Self::BT => "b-t",
        }
    }
}

/// Why a seal cannot sign now, as `/ready` and the seal route name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    CertificateExpired,
    CertificateNotYetValid,
    ProviderNotReady,
}

impl Unavailable {
    /// The value-free reason `/ready` reports.
    pub fn reason(self) -> &'static str {
        match self {
            Self::CertificateExpired => "certificate-expired",
            Self::CertificateNotYetValid => "certificate-not-yet-valid",
            Self::ProviderNotReady => "provider-not-ready",
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
            Self::ProviderNotReady => RenderProblem::new(
                ProblemKind::SigningUnavailable,
                format!("seal {seal_id}: the signing key provider is not ready"),
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
}

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
/// no signing block. Refuses with a problem positioned at the failing member,
/// whose message names the failing piece and repeats no value.
pub fn load(runtime: &RenderRuntime) -> Result<Seals, RenderProblem> {
    let mut seals = Seals::new();
    let Some(signing) = &runtime.signing else {
        return Ok(seals);
    };
    for (id, seal) in &signing.seals {
        let loaded = Seal::load(runtime, id.as_str(), seal)?;
        seals.insert(id.as_str().to_owned(), Arc::new(loaded));
    }
    Ok(seals)
}

fn refusal(
    kind: ProblemKind,
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
    RenderProblem::new(kind, format!("seal {seal_id} cannot be loaded"))
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
        chain_error(
            "render.runtime.seal-chain-invalid",
            format!(
                "signing.seals.{id}.certificateChainFile is not a usable certificate chain: {}",
                chain_error_text(&error)
            ),
            "Write the seal certificate first, then each issuer in turn, as PEM CERTIFICATE \
             blocks.",
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
/// that document type's `seal` member.
pub fn refuse_unsealable(manifest: &Manifest, seals: &Seals) -> Result<(), RenderProblem> {
    let found = unsealable_documents(manifest, |id| {
        seals.get(id).map(|seal| seal.contents_capacity())
    });
    if found.is_empty() {
        return Ok(());
    }
    let diagnostics = found
        .iter()
        .map(|document| {
            let mut diagnostic = Diagnostic::error(
                UNSEALABLE_CODE,
                document.pointer(),
                document.message(),
                document.action(),
            );
            diagnostic.artifact = Some(MANIFEST_KIND.to_owned());
            diagnostic
        })
        .collect();
    Err(RenderProblem::new(
        ProblemKind::RuntimeInvalid,
        "a seal reserves more signature space than a document type's PDF standard allows",
    )
    .with_diagnostics(diagnostics))
}

impl Seal {
    fn load(runtime: &RenderRuntime, id: &str, seal: &SealRuntime) -> Result<Self, RenderProblem> {
        let certificate = |finding: ChainFinding| {
            refusal(
                ProblemKind::SealCertificateInvalid,
                id,
                "certificateChainFile",
                finding.code,
                finding.message,
                finding.action,
            )
        };
        let key = |kind: ProblemKind, code: &str, message: String, action: &str| {
            refusal(kind, id, "privateKeyRef", code, message, action)
        };
        let chain = read_chain(id, seal).map_err(certificate)?;
        let secret =
            crate::runtime::resolve_secret(runtime, &seal.private_key_ref).map_err(|_| {
                key(
                    ProblemKind::RuntimeInvalid,
                    "render.runtime.seal-key-unreadable",
                    format!("signing.seals.{id}.privateKeyRef cannot be resolved"),
                    "Provide the seal's private key under the secret provider the reference names.",
                )
            })?;
        let not_a_key = || {
            key(
                ProblemKind::RuntimeInvalid,
                "render.runtime.seal-key-invalid",
                format!("signing.seals.{id}.privateKeyRef does not hold a private JWK"),
                "Store the seal's private key as one ES256, ES384, RS256 or RS384 private JWK.",
            )
        };
        let text = std::str::from_utf8(&secret).map_err(|_| not_a_key())?;
        let mut jwk = PrivateJwk::parse(text.trim()).map_err(|_| not_a_key())?;
        drop(secret);
        // The CMS names its signer by issuer and serial number, never by key
        // id, so a seal key needs none; the seal id stands in when it has
        // none.
        if jwk.kid.as_deref().is_none_or(|kid| kid.trim().is_empty()) {
            jwk.kid = Some(id.to_owned());
        }
        let signer = LocalJwkSigner::new(jwk).map_err(|_| not_a_key())?;
        if signer.algorithm() == SigningAlgorithm::EdDsa {
            return Err(key(
                ProblemKind::SealCertificateInvalid,
                "render.runtime.seal-key-unsupported",
                format!(
                    "signing.seals.{id}.privateKeyRef is an EdDSA key; PAdES seals use ES256, \
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
                return Err(key(
                    ProblemKind::SealCertificateInvalid,
                    "render.runtime.seal-key-mismatch",
                    format!(
                        "signing.seals.{id}.privateKeyRef does not hold the key the seal \
                         certificate certifies"
                    ),
                    "Point privateKeyRef at the private key of the seal certificate, or the \
                     chain file at the certificate issued for this key.",
                ))
            }
            Err(CertificateError::MissingSigningKeyUsage { .. }) => {
                return Err(certificate(usage_finding(id)))
            }
            Err(error) => {
                return Err(key(
                    ProblemKind::SealCertificateInvalid,
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
            Some(authority) => Some(TimestampAuthority::new(
                id,
                authority.url.to_url().as_str(),
                authority.attempt_timeout(),
            )?),
        };
        Ok(Self {
            id: id.to_owned(),
            fingerprint: chain.leaf_sha256_fingerprint(),
            signing: SigningPayload {
                signer_name: chain.display_name().map(str::to_owned),
                test_only: seal.is_test_only(),
            },
            chain,
            signer: Arc::new(signer),
            contents_capacity,
            timestamp,
            allowed_clients: seal.allowed_clients.as_slice().to_vec(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
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

    /// The seal certificate's SHA-256 fingerprint, lowercase hex.
    pub fn certificate_fingerprint(&self) -> String {
        self.fingerprint.to_string()
    }

    /// Whether the seal's `allowedClients` names this verified client.
    pub fn allows_client(&self, client_id: &str) -> bool {
        self.allowed_clients
            .iter()
            .any(|client| client == client_id)
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
            KeyReadiness::NotReady => Err(Unavailable::ProviderNotReady),
            _ => Ok(()),
        }
    }

    /// Whether a seal that can sign at `now` stops within
    /// [`EXPIRY_WARNING_DAYS`], the window `check --environment` warns in.
    pub fn expires_soon(&self, now: OffsetDateTime) -> bool {
        self.chain.not_after() - now < time::Duration::days(EXPIRY_WARNING_DAYS)
    }

    /// What the worker needs to prepare this seal's field at `signing_time`,
    /// the parent's clock truncated to whole seconds.
    pub fn worker_seal(&self, signing_time: OffsetDateTime) -> WorkerSeal {
        let signing_time = signing_time.replace_nanosecond(0).unwrap_or(signing_time);
        let signing_time = chrono::DateTime::from_timestamp(signing_time.unix_timestamp(), 0)
            .unwrap_or_default()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        WorkerSeal {
            signing: self.signing.clone(),
            signing_time,
            contents_capacity: self.contents_capacity,
            field_name: SEAL_FIELD_NAME.to_owned(),
        }
    }

    /// Check, sign, timestamp and embed what the worker prepared from the
    /// package serve verified, whose hash is `bundle_hash`. An answer from
    /// any other package is refused before anything is signed.
    pub async fn seal(
        &self,
        prepared: WorkerPrepared,
        bundle_hash: &str,
    ) -> Result<SealedDocument, RenderProblem> {
        if prepared.bundle_hash != bundle_hash {
            return Err(RenderProblem::new(
                ProblemKind::BundleTampered,
                "the package changed under serve; refusing the render from a drifted package",
            ));
        }
        let internal = |detail: String| RenderProblem::new(ProblemKind::Internal, detail);
        let first_revision_len = prepared.first_revision_len;
        let checked = prepared
            .prepared
            .check(first_revision_len)
            .map_err(|error| {
                internal(format!(
                    "seal {}: the worker's prepared file was refused: {error}",
                    self.id
                ))
            })?;
        if checked.contents_capacity() != self.contents_capacity {
            return Err(internal(format!(
                "seal {}: the worker reserved another signature space than requested",
                self.id
            )));
        }
        // The check placed the signature dictionary after the first
        // revision, so the first signed range starts with all of it.
        let [first_part, _] = checked.signed_parts();
        let document_sha256 = sha256_hex(&first_part[..first_revision_len]);
        let signature = sign_detached(&checked.signed_parts(), &self.chain, self.signer.as_ref())
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
                let gen_time = token
                    .gen_time
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|_| {
                        authority.failure(TimestampFailure::InvalidToken, "gen-time-not-rfc3339")
                    })?;
                let stamp = AppliedTimestamp {
                    time: gen_time,
                    token_sha256: sha256_hex(&token.token_der),
                };
                (stamped, Some(stamp))
            }
        };
        let pdf = checked
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
            signed_file_sha256: sha256_hex(&pdf),
            pdf,
            document_sha256,
            level: self.level(),
            certificate_fingerprint: self.certificate_fingerprint(),
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
    /// SHA-256 over the first revision, Render's own document.
    pub document_sha256: String,
    /// SHA-256 over the whole signed file.
    pub signed_file_sha256: String,
    pub level: SealLevel,
    pub certificate_fingerprint: String,
    /// Present for a B-T seal.
    pub timestamp: Option<AppliedTimestamp>,
}

/// The timestamp a B-T seal carries.
#[derive(Debug, Clone)]
pub struct AppliedTimestamp {
    /// The token's `genTime`, RFC 3339.
    pub time: String,
    /// SHA-256 over the DER token.
    pub token_sha256: String,
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
    fn new(
        seal_id: &str,
        url: &str,
        attempt_timeout: std::time::Duration,
    ) -> Result<Self, RenderProblem> {
        let unusable = || {
            refusal(
                ProblemKind::RuntimeInvalid,
                seal_id,
                "timestampAuthority",
                "render.runtime.seal-timestamp-client",
                format!("signing.seals.{seal_id}.timestampAuthority cannot be used"),
                "Check the timestamp authority URL and the host's trusted root certificates.",
            )
        };
        let url = reqwest::Url::parse(url).map_err(|_| unusable())?;
        let client = registry_platform_httputil::client::build_client(
            registry_platform_httputil::client::OutboundOptions {
                request_timeout: attempt_timeout,
                connect_timeout: attempt_timeout,
                user_agent: Some("registry-render"),
                trusted_root_certificates: None,
            },
        )
        .map_err(|_| unusable())?;
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

    use crate::worker::seal_tests::prepared_receipt;

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

    /// A worker answer rendered from another package than the one serve
    /// verified is refused as tampered before anything is signed; the same
    /// answer under the served package hash seals.
    #[tokio::test]
    async fn a_worker_answer_from_another_package_is_refused_before_signing() {
        let pki = TestPki::generate().expect("test PKI");
        let test_seal = pki.issue_seal(SigningAlgorithm::Es256).expect("test seal");
        let signer = Arc::new(CountingSigner {
            inner: test_seal.signer().expect("test signer"),
            signatures: AtomicUsize::new(0),
        });
        let seal = Seal::for_test("ministry", &test_seal, Arc::clone(&signer) as _);
        let prepared = prepared_receipt(seal.worker_seal(OffsetDateTime::now_utc()));
        let served_hash = prepared.bundle_hash.clone();
        let mut drifted = prepared.clone();
        drifted.bundle_hash = "0".repeat(64);
        assert_ne!(drifted.bundle_hash, served_hash);

        let Err(problem) = seal.seal(drifted, &served_hash).await else {
            panic!("an answer from another package was sealed");
        };
        assert_eq!(problem.kind, ProblemKind::BundleTampered);
        assert_eq!(
            signer.signatures.load(Ordering::SeqCst),
            0,
            "nothing signed"
        );

        let sealed = seal
            .seal(prepared, &served_hash)
            .await
            .expect("an answer from the served package");
        assert_eq!(signer.signatures.load(Ordering::SeqCst), 1);
        assert!(sealed.pdf.starts_with(b"%PDF-"));
    }

    /// What a seal sends the worker is the signing payload, the signing
    /// time, the reserved space and the field name; none of the seal key's
    /// private members, for an elliptic curve key or an RSA key.
    #[test]
    fn the_seal_key_never_crosses_into_the_worker() {
        use std::collections::BTreeSet;

        use crate::worker::seal_tests::receipt_request;

        let pki = TestPki::generate().expect("test PKI");
        for algorithm in [SigningAlgorithm::Es256, SigningAlgorithm::Rs256] {
            let test_seal = pki.issue_seal(algorithm).expect("test seal");
            let signer = Arc::new(test_seal.signer().expect("test signer"));
            let seal = Seal::for_test("ministry", &test_seal, signer);
            let request = receipt_request(Some(seal.worker_seal(OffsetDateTime::now_utc())));
            let sent = serde_json::to_value(&request).expect("worker request");
            let members: BTreeSet<&str> = sent["seal"]
                .as_object()
                .expect("the seal member")
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                members,
                BTreeSet::from(["contentsCapacity", "fieldName", "signing", "signingTime"]),
                "{algorithm:?}"
            );
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

        let prepared = prepared_receipt(large_seal.worker_seal(OffsetDateTime::now_utc()));
        let bundle_hash = prepared.bundle_hash.clone();
        large_seal
            .seal(prepared, &bundle_hash)
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

    #[test]
    fn levels_and_reasons_have_stable_names() {
        assert_eq!(SealLevel::BT.as_str(), "b-t");
        assert_eq!(SealLevel::BB.as_str(), "b-b");
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
                Unavailable::ProviderNotReady,
                "provider-not-ready",
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
