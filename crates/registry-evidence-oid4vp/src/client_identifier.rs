//! The verifier's identity toward a wallet: a client identifier, the key that
//! signs request objects, and for the Ed25519 identifiers the public key
//! material a wallet resolves it from.
//!
//! Resolution reads secret material, so it runs at startup, not in the offline
//! check. A deployment whose certificate does not name its public host, whose
//! signing key is not the leaf's key (or not an Ed25519 key where one is
//! required), or whose certificate has expired does not start: every wallet
//! would refuse its requests, and a wallet's refusal gives the operator
//! nothing to act on.
//!
//! Four client identifier types exist. The two X.509 types sign ES256 with a
//! certificate chain in the `x5c` header. The `decentralized_identifier` type
//! (`did:web`) and the `pre-registered` type sign EdDSA without a certificate;
//! the wallet finds the public key in the DID document or in the JWKS this
//! service serves, selecting by the request object's `kid`.

use std::sync::Arc;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use der::Decode as _;
use registry_platform_config::SecretResolver;
use registry_platform_crypto::{
    LocalJwkSigner, PrivateJwk, PublicJwk, SigningAlgorithm, SigningProvider,
};
use registry_platform_x509::{CertifiedSigner, X509Error, X5cChain};
use serde_json::{json, Value};
use x509_cert::{
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

use crate::config::{
    ClientIdentifierConfig, ClientIdentifierKind, DidMaterial, PreRegisteredMaterial,
};

/// The object identifier of the subject alternative name extension (RFC 5280
/// section 4.2.1.6).
const SUBJECT_ALT_NAME: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17");

/// The multicodec prefix of an Ed25519 public key (varint `0xed`).
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// The base58btc alphabet (the Bitcoin alphabet), as the Multibase `z` prefix
/// names.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Why the verifier identity could not be built. Each carries a stable code and
/// never any secret material.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdentityError {
    #[error("the certificate chain secret could not be read")]
    ChainUnavailable,
    #[error("the signing key secret could not be read")]
    KeyUnavailable,
    #[error("the certificate chain is not a PEM bundle of certificates")]
    ChainInvalid,
    #[error("the signing key is not a usable private JWK")]
    KeyInvalid,
    #[error("the signing key is not an Ed25519 key")]
    KeyNotEd25519,
    #[error("the signing key is not the leaf certificate's key")]
    KeyMismatch,
    #[error("the leaf certificate has no DNS subject alternative name for the public host")]
    SanMissingHost,
    #[error("a certificate in the chain has expired")]
    CertificateExpired,
    #[error("a certificate in the chain is not yet valid")]
    CertificateNotYetValid,
    #[error("another client identifier presents the same client id")]
    DuplicateClientId,
}

impl IdentityError {
    /// The diagnostic code for this refusal.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ChainUnavailable | Self::KeyUnavailable => "evidence.oid4vp.secret-unavailable",
            Self::ChainInvalid => "evidence.oid4vp.certificate-chain-invalid",
            Self::KeyInvalid => "evidence.oid4vp.signing-key-invalid",
            Self::KeyNotEd25519 => "evidence.oid4vp.signing-key-not-ed25519",
            Self::KeyMismatch => "evidence.oid4vp.signing-key-mismatch",
            Self::SanMissingHost => "evidence.oid4vp.certificate-san-host",
            Self::CertificateExpired => "evidence.oid4vp.certificate-expired",
            Self::CertificateNotYetValid => "evidence.oid4vp.certificate-not-yet-valid",
            Self::DuplicateClientId => "evidence.oid4vp.duplicate-client-identifier",
        }
    }

    /// The refusal as a positioned diagnostic for the client identifier at
    /// `index` in `clientIdentifiers`, naming what to change.
    #[must_use]
    pub fn diagnostic(&self, index: usize) -> registry_platform_yaml::Diagnostic {
        let (member, action) = match self {
            Self::ChainUnavailable | Self::ChainInvalid => (
                "certificateChainRef",
                "Provide the PEM certificate chain, leaf first, at the referenced secret.",
            ),
            Self::KeyUnavailable | Self::KeyInvalid => (
                "signingKeyRef",
                "Provide the private JWK of the signing key at the referenced secret.",
            ),
            Self::KeyNotEd25519 => (
                "signingKeyRef",
                "Provide a private Ed25519 JWK (kty OKP, crv Ed25519, alg EdDSA) at the referenced secret.",
            ),
            Self::KeyMismatch => (
                "signingKeyRef",
                "Reference the private key that belongs to the leaf certificate.",
            ),
            Self::SanMissingHost => (
                "certificateChainRef",
                "Issue a certificate whose DNS subject alternative name is the host of publicBaseUrl, or use the x509-hash client identifier.",
            ),
            Self::CertificateExpired | Self::CertificateNotYetValid => (
                "certificateChainRef",
                "Replace the certificate chain with one that is valid now.",
            ),
            Self::DuplicateClientId => (
                "id",
                "Remove the client identifier, or change what it presents so no two identifiers share a client id.",
            ),
        };
        registry_platform_yaml::Diagnostic::error(
            self.code(),
            format!("/clientIdentifiers/{index}/{member}"),
            self.to_string(),
            action,
        )
    }
}

/// How a request object is signed under an identity.
enum Signing {
    /// ES256 with the certificate chain in the `x5c` header.
    Certified {
        signer: CertifiedSigner,
        expires_at: u64,
    },
    /// EdDSA with a `kid` a wallet resolves the public key by.
    Ed25519 {
        signer: LocalJwkSigner,
        /// The DID document, for a `did:web` identifier.
        did_document: Option<Value>,
    },
}

/// The resolved identity that signs request objects.
#[derive(Clone)]
pub struct RequestIdentity(Arc<Resolved>);

struct Resolved {
    id: String,
    client_id: String,
    signing: Signing,
}

impl std::fmt::Debug for RequestIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestIdentity")
            .field("client_id", &self.0.client_id)
            .finish_non_exhaustive()
    }
}

impl RequestIdentity {
    /// Resolve the secrets `config` names and check them against the public
    /// host and the clock.
    pub fn resolve(
        config: &ClientIdentifierConfig,
        public_host: &str,
        resolver: &SecretResolver,
        now: u64,
    ) -> Result<Self, IdentityError> {
        let secret = |reference| {
            resolver
                .resolve_binary_reference(reference)
                .map_err(|_| IdentityError::KeyUnavailable)
        };
        match &config.kind {
            ClientIdentifierKind::X509SanDns(material)
            | ClientIdentifierKind::X509Hash(material) => {
                let chain = resolver
                    .resolve_binary_reference(&material.certificate_chain_ref)
                    .map_err(|_| IdentityError::ChainUnavailable)?;
                let key = secret(&material.signing_key_ref)?;
                Self::from_x509_material(
                    config,
                    public_host,
                    chain.expose_secret(),
                    key.expose_secret(),
                    now,
                )
            }
            ClientIdentifierKind::DecentralizedIdentifier(DidMaterial {
                did,
                signing_key_ref,
            }) => {
                let key = secret(signing_key_ref)?;
                Self::from_ed25519_material(
                    &config.id,
                    &format!("decentralized_identifier:{did}"),
                    Some(did),
                    key.expose_secret(),
                )
            }
            ClientIdentifierKind::PreRegistered(PreRegisteredMaterial {
                client_id,
                signing_key_ref,
            }) => {
                let key = secret(signing_key_ref)?;
                Self::from_ed25519_material(&config.id, client_id, None, key.expose_secret())
            }
        }
    }

    /// Build an X.509 identity from the chain PEM and the private JWK bytes.
    /// `config` must be an X.509 identifier.
    pub fn from_x509_material(
        config: &ClientIdentifierConfig,
        public_host: &str,
        chain_pem: &[u8],
        signing_jwk: &[u8],
        now: u64,
    ) -> Result<Self, IdentityError> {
        let chain = X5cChain::from_pem(chain_pem).map_err(|_| IdentityError::ChainInvalid)?;
        let certificates = chain
            .to_x5c()
            .iter()
            .map(|entry| {
                STANDARD
                    .decode(entry)
                    .map_err(|_| IdentityError::ChainInvalid)
                    .and_then(|der| {
                        Certificate::from_der(&der).map_err(|_| IdentityError::ChainInvalid)
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let Some(leaf) = certificates.first() else {
            return Err(IdentityError::ChainInvalid);
        };

        for certificate in &certificates {
            let validity = certificate.tbs_certificate().validity();
            if now >= validity.not_after.to_unix_duration().as_secs() {
                return Err(IdentityError::CertificateExpired);
            }
            if now < validity.not_before.to_unix_duration().as_secs() {
                return Err(IdentityError::CertificateNotYetValid);
            }
        }
        let expires_at = certificates
            .iter()
            .map(|certificate| {
                certificate
                    .tbs_certificate()
                    .validity()
                    .not_after
                    .to_unix_duration()
                    .as_secs()
            })
            .min()
            .unwrap_or(0);

        let jwk = std::str::from_utf8(signing_jwk)
            .map_err(|_| IdentityError::KeyInvalid)
            .and_then(|json| PrivateJwk::parse(json).map_err(|_| IdentityError::KeyInvalid))?;
        let local = LocalJwkSigner::new(jwk).map_err(|_| IdentityError::KeyInvalid)?;
        let signer = CertifiedSigner::new(Arc::new(local), chain).map_err(|error| match error {
            X509Error::SignerKeyMismatch => IdentityError::KeyMismatch,
            _ => IdentityError::ChainInvalid,
        })?;

        let client_id = match config.kind {
            ClientIdentifierKind::X509SanDns(_) => {
                if !san_dns_names(leaf)
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(public_host))
                {
                    return Err(IdentityError::SanMissingHost);
                }
                format!("x509_san_dns:{public_host}")
            }
            _ => format!("x509_hash:{}", signer.x509_hash()),
        };
        Ok(Self(Arc::new(Resolved {
            id: config.id.clone(),
            client_id,
            signing: Signing::Certified { signer, expires_at },
        })))
    }

    /// Build an EdDSA identity from the private JWK bytes. With `did` set, the
    /// request's `kid` names a verification method of that DID and the DID
    /// document is built; without it the `kid` is the key's RFC 7638
    /// thumbprint.
    pub fn from_ed25519_material(
        id: &str,
        client_id: &str,
        did: Option<&str>,
        signing_jwk: &[u8],
    ) -> Result<Self, IdentityError> {
        let mut jwk = std::str::from_utf8(signing_jwk)
            .map_err(|_| IdentityError::KeyInvalid)
            .and_then(|json| PrivateJwk::parse(json).map_err(|_| IdentityError::KeyInvalid))?;
        if jwk.algorithm().ok() != Some(SigningAlgorithm::EdDsa)
            || jwk.kty != "OKP"
            || jwk.crv.as_deref() != Some("Ed25519")
        {
            return Err(IdentityError::KeyNotEd25519);
        }
        let public = jwk.public();
        let thumbprint = public.jkt().map_err(|_| IdentityError::KeyInvalid)?;
        let kid = did.map_or_else(|| thumbprint.clone(), |did| format!("{did}#{thumbprint}"));
        jwk.alg = Some(SigningAlgorithm::EdDsa.jwa_name().to_owned());
        jwk.kid = Some(kid.clone());
        let did_document = did
            .map(|did| did_document(did, &kid, &public))
            .transpose()?;
        let signer = LocalJwkSigner::new(jwk).map_err(|_| IdentityError::KeyInvalid)?;
        Ok(Self(Arc::new(Resolved {
            id: id.to_owned(),
            client_id: client_id.to_owned(),
            signing: Signing::Ed25519 {
                signer,
                did_document,
            },
        })))
    }

    /// The local id of the client identifier this identity was built from.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.0.id
    }

    /// The prefixed `client_id` the request object carries.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.0.client_id
    }

    /// The signer of request objects.
    #[must_use]
    pub fn signer(&self) -> &dyn SigningProvider {
        match &self.0.signing {
            Signing::Certified { signer, .. } => signer.signer().as_ref(),
            Signing::Ed25519 { signer, .. } => signer,
        }
    }

    /// The certificate chain for the `x5c` header, leaf first. Absent for an
    /// identifier a wallet resolves the key of by `kid`.
    #[must_use]
    pub fn x5c(&self) -> Option<Vec<String>> {
        match &self.0.signing {
            Signing::Certified { signer, .. } => Some(signer.x5c()),
            Signing::Ed25519 { .. } => None,
        }
    }

    /// The earliest `notAfter` in the certificate chain, as Unix seconds.
    /// Absent for an Ed25519 identifier, which has no certificate.
    #[must_use]
    pub fn expires_at(&self) -> Option<u64> {
        match &self.0.signing {
            Signing::Certified { expires_at, .. } => Some(*expires_at),
            Signing::Ed25519 { .. } => None,
        }
    }

    /// The public key as a JWKS entry, whose `kid` is the `kid` of the request
    /// objects it verifies. Absent for an X.509 identifier, whose key travels
    /// in the `x5c` header.
    #[must_use]
    pub fn jwks_entry(&self) -> Option<Value> {
        match &self.0.signing {
            Signing::Certified { .. } => None,
            Signing::Ed25519 { signer, .. } => {
                let public = signer.public_jwk();
                Some(json!({
                    "kty": public.kty,
                    "crv": public.crv,
                    "x": public.x,
                    "kid": signer.key_id(),
                    "use": "sig",
                    "alg": SigningAlgorithm::EdDsa.jwa_name(),
                }))
            }
        }
    }

    /// The DID document of a `did:web` identifier.
    #[must_use]
    pub fn did_document(&self) -> Option<&Value> {
        match &self.0.signing {
            Signing::Ed25519 { did_document, .. } => did_document.as_ref(),
            Signing::Certified { .. } => None,
        }
    }
}

/// The DID document a wallet resolves `did` to (`did:web`): one
/// `Ed25519VerificationKey2020` method whose id is `method_id`, listed for
/// authentication and assertion. The key is the one member the resolver reads,
/// as `publicKeyMultibase`.
fn did_document(did: &str, method_id: &str, public: &PublicJwk) -> Result<Value, IdentityError> {
    let key = public
        .x
        .as_deref()
        .ok_or(IdentityError::KeyInvalid)
        .and_then(|x| {
            URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|_| IdentityError::KeyInvalid)
        })?;
    let mut multicodec = ED25519_MULTICODEC.to_vec();
    multicodec.extend_from_slice(&key);
    Ok(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "verificationMethod": [{
            "id": method_id,
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": format!("z{}", base58btc(&multicodec)),
        }],
        "authentication": [method_id],
        "assertionMethod": [method_id],
    }))
}

/// `bytes` in base58btc, each leading zero byte as a leading `1`.
fn base58btc(bytes: &[u8]) -> String {
    let leading_zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    // Digits, least significant first.
    let mut digits: Vec<u8> = Vec::new();
    for byte in bytes {
        let mut carry = u32::from(*byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    std::iter::repeat_n('1', leading_zeros)
        .chain(
            digits
                .iter()
                .rev()
                .map(|digit| char::from(BASE58_ALPHABET[usize::from(*digit)])),
        )
        .collect()
}

fn san_dns_names(certificate: &Certificate) -> Vec<String> {
    let Some(extensions) = certificate.tbs_certificate().extensions() else {
        return Vec::new();
    };
    extensions
        .iter()
        .filter(|extension| extension.extn_id == SUBJECT_ALT_NAME)
        .filter_map(|extension| SubjectAltName::from_der(extension.extn_value.as_bytes()).ok())
        .flat_map(|names| names.0)
        .filter_map(|name| match name {
            GeneralName::DnsName(name) => Some(name.as_str().to_owned()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58btc_matches_the_published_vectors() {
        for (bytes, expected) in [
            (&b""[..], ""),
            (b"a", "2g"),
            (b"bbb", "a3gV"),
            (b"ccc", "aPEr"),
            (b"Hello World!", "2NEpo7TZRRrLZSi2U"),
            (b"simply a long string", "2cFupjhnEsSn59qHXstmK2ffpLv2"),
            (&[0, 0, 0], "111"),
            (&[0, 0, 40, 127, 180, 205], "11233QC4"),
        ] {
            assert_eq!(base58btc(bytes), expected, "{bytes:?}");
        }
    }
}
