// SPDX-License-Identifier: Apache-2.0
//! A signing provider bound to the certificate chain that certifies its key.

use registry_platform_crypto::SigningProvider;
use std::sync::Arc;

use crate::input::{parse_certificate, X5cChain};
use crate::verify::{leaf_public_jwk, x509_hash};
use crate::X509Error;

/// A [`SigningProvider`] together with the certificate chain whose leaf certifies its public
/// key. It is how a service signs a request object or credential under a certificate-backed
/// identity: the chain goes in the `x5c` header, and the leaf's `x509_hash` names the identity.
///
/// Construction checks that the leaf key is the signer's key. It does not validate the chain;
/// relying parties do that against their own trust anchors.
#[derive(Clone)]
pub struct CertifiedSigner {
    signer: Arc<dyn SigningProvider>,
    chain: X5cChain,
    x509_hash: String,
}

impl CertifiedSigner {
    /// Refuses a chain whose leaf public key differs from the signer's public key.
    pub fn new(signer: Arc<dyn SigningProvider>, chain: X5cChain) -> Result<Self, X509Error> {
        let leaf = parse_certificate(chain.leaf_der())?;
        let (leaf_jwk, _) = leaf_public_jwk(&leaf)?;
        let key = signer.public_jwk();
        let same_key = leaf_jwk.kty == key.kty
            && leaf_jwk.crv == key.crv
            && leaf_jwk.x == key.x
            && leaf_jwk.y == key.y;
        if !same_key {
            return Err(X509Error::SignerKeyMismatch);
        }
        let x509_hash = x509_hash(chain.leaf_der());
        Ok(Self {
            signer,
            chain,
            x509_hash,
        })
    }

    /// The signing provider.
    #[must_use]
    pub fn signer(&self) -> &Arc<dyn SigningProvider> {
        &self.signer
    }

    /// The `x5c` header value, leaf first.
    #[must_use]
    pub fn x5c(&self) -> Vec<String> {
        self.chain.to_x5c()
    }

    /// The `x509_hash` client identifier value of the leaf.
    #[must_use]
    pub fn x509_hash(&self) -> &str {
        &self.x509_hash
    }
}

impl std::fmt::Debug for CertifiedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertifiedSigner")
            .field("alg", &self.signer.algorithm())
            .field("kid", &self.signer.key_id())
            .field("certificates", &self.chain.len())
            .field("x509_hash", &self.x509_hash)
            .finish()
    }
}
