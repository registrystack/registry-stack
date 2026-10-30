// SPDX-License-Identifier: Apache-2.0

//! The orthogonal outbound TLS of one endpoint binding
//! (`products/adapter/CONCEPT.md` section 10.2): the trust profile's
//! CA bundle and the mTLS client identity, resolved from the binding's
//! secret references into zeroizing buffers, and rebuilt into platform
//! destination material for each client the engine builds.
//!
//! TLS is orthogonal to the credential kinds: any kind may send under a
//! private root, under a client identity, or both, and the material is
//! installed on the endpoint's data policy and its token policy alike,
//! which is why [`EndpointTls::material`] builds fresh material per
//! call instead of holding one platform value.

use crate::auth::token::{resolve_binary, resolve_protected};
use crate::auth::{AuthError, ProtectedText};
use registry_adapter_core::EndpointBinding;
use registry_platform_config::SecretResolver;
use registry_platform_httputil::destination::DestinationTlsMaterial;
use std::fmt;

/// Why a binding's outbound TLS material could not be resolved or
/// built. Every rendering is fixed text; none carries a reference name
/// or file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFault {
    /// The CA bundle reference did not resolve to usable text.
    CaBundle,
    /// The client identity's certificate or key reference did not
    /// resolve.
    ClientIdentity,
    /// The resolved material is not PEM the platform accepts: a bundle
    /// without a usable certificate, or an identity without exactly one
    /// certificate chain and one private key.
    Material,
}

impl fmt::Display for TlsFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaBundle => formatter.write_str("the endpoint's CA bundle could not be resolved"),
            Self::ClientIdentity => {
                formatter.write_str("the endpoint's mTLS client identity could not be resolved")
            }
            Self::Material => {
                formatter.write_str("the endpoint's outbound TLS material is not usable")
            }
        }
    }
}

/// One endpoint's resolved outbound TLS material.
#[derive(Debug, Default)]
pub struct EndpointTls {
    ca: Option<ProtectedText>,
    identity: Option<ProtectedText>,
}

impl EndpointTls {
    /// No trust material beyond the system roots and no client
    /// identity.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            ca: None,
            identity: None,
        }
    }

    /// Resolve a binding's TLS material from its secret references: the
    /// CA bundle as text, the client identity as the certificate chain
    /// followed by exactly one private key, concatenated into one
    /// zeroizing buffer.
    pub fn resolve(
        binding: &EndpointBinding,
        resolver: &SecretResolver,
    ) -> Result<Self, AuthError> {
        let ca = match &binding.ca_bundle_ref {
            Some(reference) => Some(
                resolve_protected(resolver, reference)
                    .map_err(|_| AuthError::Tls(TlsFault::CaBundle))?,
            ),
            None => None,
        };
        let identity = match &binding.mtls_identity {
            Some(identity) => {
                let certificate = resolve_binary(resolver, &identity.certificate_ref)
                    .map_err(|_| AuthError::Tls(TlsFault::ClientIdentity))?;
                let key = resolve_binary(resolver, &identity.key_ref)
                    .map_err(|_| AuthError::Tls(TlsFault::ClientIdentity))?;
                let mut joined = Vec::with_capacity(certificate.len() + 1 + key.len());
                joined.extend_from_slice(certificate.as_bytes());
                joined.push(b'\n');
                joined.extend_from_slice(key.as_bytes());
                Some(ProtectedText::from_owned(joined))
            }
            None => None,
        };
        Ok(Self { ca, identity })
    }

    /// Whether any trust material is configured.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.ca.is_some() || self.identity.is_some()
    }

    /// Platform TLS material for one client build; fresh on each call
    /// so the endpoint's data policy and token policy install the same
    /// material without sharing one platform value.
    pub fn material(&self) -> Result<Option<DestinationTlsMaterial>, AuthError> {
        if !self.is_configured() {
            return Ok(None);
        }
        let material = DestinationTlsMaterial::from_pem(
            self.ca.as_ref().map(|bundle| bundle.as_bytes()),
            self.identity.as_ref().map(|identity| identity.as_bytes()),
        )
        .map_err(|_| AuthError::Tls(TlsFault::Material))?;
        Ok(Some(material))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_adapter_core::{MtlsIdentity, RuntimeCredential};
    use registry_platform_yaml::{ExternalId, SecretReference, Url};

    /// Throwaway self-signed fixtures generated for these tests only;
    /// no deployment has ever trusted them.
    const ROOT_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBnzCCAUWgAwIBAgIUGSkZVSD93tTafMYk9zXkW+9N+VcwCgYIKoZIzj0EAwIw\nJTEjMCEGA1UEAwwaUmVnaXN0cnkgQWRhcHRlciBUZXN0IFJvb3QwHhcNMjYxMDMw\nMDQ1NDIwWhcNMzYxMDI3MDQ1NDIwWjAlMSMwIQYDVQQDDBpSZWdpc3RyeSBBZGFw\ndGVyIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIDV7zIjqChx\n97aw2DaQUGi02tuThFuNl5IKP4RFr+5lxRclqsvlNfhU0Y4JnNLDuxdToqXgVKz6\nDnA2hpkMqZyjUzBRMB0GA1UdDgQWBBSPV2C1/cYwPYf/YYcSqJMvbWT8OjAfBgNV\nHSMEGDAWgBSPV2C1/cYwPYf/YYcSqJMvbWT8OjAPBgNVHRMBAf8EBTADAQH/MAoG\nCCqGSM49BAMCA0gAMEUCIQDE6ceiEQLBfR3wcAbPoXkClwMWZCs+QRHpi9asKR6w\nGwIgG/WsmuvsVVNeDynYVj92+B5SNtyVRK2+p3eo97VtmF0=\n-----END CERTIFICATE-----\n";
    const CLIENT_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBojCCAUmgAwIBAgIUBz6xzkGZHFIeP5fMAc8V6F6xm8UwCgYIKoZIzj0EAwIw\nNzElMCMGA1UEAwwcUmVnaXN0cnkgQWRhcHRlciBUZXN0IENsaWVudDAeFw0yNjEw\nMzAwNDU0MjBaFw0zNjEwMjcwNDU0MjBaMCcxJTAjBgNVBAMMHFJlZ2lzdHJ5IEFk\nYXB0ZXIgVGVzdCBDbGllbnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASF0oBX\nS/LsU8FsocRWwJ/N8VazeqamiXcJ3wiCQlR8HOmO6RnJ1wDbrQcfYcEnFPyNxi+C\ndnIYPRU8Cg9FZo+ko1MwUTAdBgNVHQ4EFgQUWRGGtHle4QQaNtLdD34RuXhTBmww\nHwYDVR0jBBgwFoAUWRGGtHle4QQaNtLdD34RuXhTBmwwDwYDVR0TAQH/BAUwAwEB\n/zAKBggqhkjOPQQDAgNHADBEAiBW+k+uqrpHbZPdMoz4JEYuDDkC7W4zCWhzUWN9\nTl43DwIgMkjYqsF9WAV8L5NMl5em/u8Y4wcnr+vtvqyt4HSQJYM=\n-----END CERTIFICATE-----\n";
    const CLIENT_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcu64hV3YOzpMTbrA\nS7rf1eo4blksHD/fMmlOLZi06MmhRANCAASF0oBXS/LsU8FsocRWwJ/N8Vazeqam\niXcJ3wiCQlR8HOmO6RnJ1wDbrQcfYcEnFPyNxi+CdnIYPRU8Cg9FZo+k\n-----END PRIVATE KEY-----\n";

    fn secret(name: &str) -> SecretReference {
        SecretReference::new(format!("secret:env/{name}")).expect("secret reference")
    }

    fn resolver() -> SecretResolver {
        SecretResolver::new([registry_platform_yaml::SecretProvider::Environment], "")
            .expect("resolver")
    }

    fn binding(
        ca_bundle_ref: Option<SecretReference>,
        mtls_identity: Option<MtlsIdentity>,
    ) -> EndpointBinding {
        EndpointBinding {
            endpoint: ExternalId::new("case-api").expect("id"),
            base_url: Url::new("https://cases.example.invalid").expect("url"),
            credential: Some(RuntimeCredential::None {}),
            ca_bundle_ref,
            mtls_identity,
        }
    }

    fn identity_refs(certificate: &str, key: &str) -> MtlsIdentity {
        MtlsIdentity {
            certificate_ref: secret(certificate),
            key_ref: secret(key),
        }
    }

    /// A binding without TLS references resolves to nothing, and no
    /// material is demanded of the platform.
    #[test]
    fn an_unconfigured_binding_resolves_nothing() {
        let tls = EndpointTls::resolve(&binding(None, None), &resolver())
            .expect("an unconfigured binding resolves");
        assert!(!tls.is_configured());
        assert!(tls.material().expect("no material").is_none());
        assert!(EndpointTls::none()
            .material()
            .expect("no material")
            .is_none());
    }

    /// A CA bundle resolves through the resolver and builds platform
    /// material; the debug rendering never carries the PEM.
    #[test]
    fn trust_material_resolves_through_the_resolver() {
        std::env::set_var("ADAPTER_TEST_CA", ROOT_CERTIFICATE_PEM);
        let tls =
            EndpointTls::resolve(&binding(Some(secret("ADAPTER_TEST_CA")), None), &resolver())
                .expect("the bundle resolves");
        assert!(tls.is_configured());
        let material = tls.material().expect("valid bundle material");
        assert!(material.is_some(), "a bundle alone configures TLS");
        let rendered = format!("{tls:?}");
        assert!(!rendered.contains("BEGIN CERTIFICATE"), "{rendered}");
    }

    /// The mTLS identity resolves as the certificate chain followed by
    /// one private key, and builds platform material.
    #[test]
    fn mtls_identities_resolve_and_build() {
        std::env::set_var("ADAPTER_TEST_CA", ROOT_CERTIFICATE_PEM);
        std::env::set_var("ADAPTER_TEST_CLIENT_CERT", CLIENT_CERTIFICATE_PEM);
        std::env::set_var("ADAPTER_TEST_CLIENT_KEY", CLIENT_PRIVATE_KEY_PEM);
        let tls = EndpointTls::resolve(
            &binding(
                Some(secret("ADAPTER_TEST_CA")),
                Some(identity_refs(
                    "ADAPTER_TEST_CLIENT_CERT",
                    "ADAPTER_TEST_CLIENT_KEY",
                )),
            ),
            &resolver(),
        )
        .expect("the identity resolves");
        assert!(tls.is_configured());
        assert!(tls.material().expect("valid identity material").is_some());
    }

    /// Resolved but unusable material refuses value-free: a bundle that
    /// is not PEM, an identity whose certificate is not PEM.
    #[test]
    fn garbage_material_refuses() {
        std::env::set_var("ADAPTER_TEST_BAD_CA", "not a pem bundle");
        let tls = EndpointTls::resolve(
            &binding(Some(secret("ADAPTER_TEST_BAD_CA")), None),
            &resolver(),
        )
        .expect("any text resolves");
        assert_eq!(
            tls.material().unwrap_err(),
            AuthError::Tls(TlsFault::Material),
            "a non-PEM bundle is unusable"
        );

        std::env::set_var("ADAPTER_TEST_BAD_CERT", "not a certificate");
        std::env::set_var("ADAPTER_TEST_CLIENT_KEY", CLIENT_PRIVATE_KEY_PEM);
        let tls = EndpointTls::resolve(
            &binding(
                None,
                Some(identity_refs(
                    "ADAPTER_TEST_BAD_CERT",
                    "ADAPTER_TEST_CLIENT_KEY",
                )),
            ),
            &resolver(),
        )
        .expect("any bytes resolve");
        assert_eq!(
            tls.material().unwrap_err(),
            AuthError::Tls(TlsFault::Material),
            "a non-PEM identity is unusable"
        );
    }

    /// Unavailable and oversized references refuse value-free: the
    /// rendering names neither the variable nor the content.
    #[test]
    fn unusable_references_refuse_value_free() {
        let fault = EndpointTls::resolve(
            &binding(Some(secret("ADAPTER_TEST_NEVER_SET")), None),
            &resolver(),
        )
        .unwrap_err();
        assert_eq!(fault, AuthError::Tls(TlsFault::CaBundle));
        assert!(
            !fault.to_string().contains("ADAPTER_TEST_NEVER_SET"),
            "{fault}"
        );

        let fault = EndpointTls::resolve(
            &binding(
                None,
                Some(identity_refs(
                    "ADAPTER_TEST_NEVER_SET",
                    "ADAPTER_TEST_NEVER_SET",
                )),
            ),
            &resolver(),
        )
        .unwrap_err();
        assert_eq!(fault, AuthError::Tls(TlsFault::ClientIdentity));

        std::env::set_var("ADAPTER_TEST_HUGE_CA", "p".repeat(65 * 1024));
        let fault = EndpointTls::resolve(
            &binding(Some(secret("ADAPTER_TEST_HUGE_CA")), None),
            &resolver(),
        )
        .unwrap_err();
        assert_eq!(fault, AuthError::Tls(TlsFault::CaBundle));
    }
}
