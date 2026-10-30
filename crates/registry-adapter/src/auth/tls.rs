// SPDX-License-Identifier: Apache-2.0

//! The orthogonal outbound TLS of one endpoint binding
//! (`products/adapter/CONCEPT.md` section 10.2): the trust profile's
//! CA bundle, read from the profile's process-local file, and the mTLS
//! client identity, resolved from the binding's secret references into
//! zeroizing buffers, and rebuilt into platform destination material for
//! each client the engine builds.
//!
//! TLS is orthogonal to the credential kinds: any kind may send under a
//! private root, under a client identity, or both, and the material is
//! installed on the endpoint's data policy and its token policy alike,
//! which is why [`EndpointTls::material`] builds fresh material per
//! call instead of holding one platform value.

use crate::auth::token::resolve_binary;
use crate::auth::{AuthError, ProtectedText};
use registry_adapter_core::{AdapterRuntimeConfig, EndpointBinding};
use registry_platform_config::SecretResolver;
use registry_platform_httputil::destination::{
    DestinationTlsMaterial, MAX_DESTINATION_CA_BUNDLE_BYTES,
};
use std::fmt;

/// Why a binding's outbound TLS material could not be resolved or
/// built. Every rendering is fixed text; none carries a reference name,
/// a profile name, a path, or file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFault {
    /// The binding's trust profile named no profile the runtime config
    /// declares, or the profile's CA bundle file could not be read within
    /// the bundle bound.
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

    /// Resolve a binding's TLS material: the CA bundle of the trust
    /// profile the binding names, read from that profile's process-local
    /// file, and the client identity resolved from its secret references
    /// as the certificate chain followed by exactly one private key,
    /// concatenated into one zeroizing buffer.
    pub fn resolve(
        binding: &EndpointBinding,
        runtime: &AdapterRuntimeConfig,
        resolver: &SecretResolver,
    ) -> Result<Self, AuthError> {
        let ca = match &binding.tls_trust_profile {
            Some(profile) => Some(resolve_ca_bundle(runtime, profile.as_str())?),
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

/// Read the CA bundle of one named trust profile. Every failure is the
/// one [`TlsFault::CaBundle`]: an undeclared profile, an unreadable,
/// non-regular, or oversized file all refuse value-free, without naming
/// the profile, the path, or the file's content.
///
/// The path is required to be a regular file before it is opened (a
/// FIFO with no writer would block inside `open(2)` before any check on
/// the handle could run) and required again on the opened handle (the
/// path may have been swapped between the two), then read through the
/// platform bound plus one byte: the bound bounds the read even when
/// the file's own size lies.
fn resolve_ca_bundle(
    runtime: &AdapterRuntimeConfig,
    profile: &str,
) -> Result<ProtectedText, AuthError> {
    use std::io::Read;
    let refuse = || AuthError::Tls(TlsFault::CaBundle);
    let path = runtime
        .outbound_tls
        .as_ref()
        .and_then(|tls| tls.trust_profiles.get(profile))
        .map(|declared| declared.ca_bundle_file.as_str())
        .ok_or_else(refuse)?;
    if !std::fs::metadata(path).map_err(|_| refuse())?.is_file() {
        return Err(refuse());
    }
    let file = std::fs::File::open(path).map_err(|_| refuse())?;
    if !file.metadata().map_err(|_| refuse())?.is_file() {
        return Err(refuse());
    }
    let mut bytes = Vec::new();
    file.take((MAX_DESTINATION_CA_BUNDLE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    if bytes.len() > MAX_DESTINATION_CA_BUNDLE_BYTES {
        return Err(refuse());
    }
    Ok(ProtectedText::from_owned(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_adapter_core::{MtlsIdentity, RuntimeCredential};
    use registry_platform_yaml::{ExternalId, LocalId, SecretReference, Url};

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
        tls_trust_profile: Option<LocalId>,
        mtls_identity: Option<MtlsIdentity>,
    ) -> EndpointBinding {
        EndpointBinding {
            endpoint: ExternalId::new("case-api").expect("id"),
            base_url: Url::new("https://cases.example.invalid").expect("url"),
            credential: Some(RuntimeCredential::None {}),
            tls_trust_profile,
            mtls_identity,
        }
    }

    /// A unique scratch path for one test's CA bundle file: the tests
    /// write and remove their own files.
    fn bundle_path(name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("registry-adapter-tls-{name}-{unique}.pem"))
    }

    /// A runtime config declaring the one trust profile `private-ca` whose
    /// bundle file is `ca_bundle_file`; `None` declares no profiles.
    fn runtime_config(ca_bundle_file: Option<&str>) -> AdapterRuntimeConfig {
        let trust_profiles = ca_bundle_file.map_or_else(
            || r#"{ "trustProfiles": {} }"#.to_owned(),
            |file| {
                format!(
                    r#"{{ "trustProfiles": {{ "private-ca": {{ "caBundleFile": "{file}" }} }} }}"#
                )
            },
        );
        serde_json::from_str(&format!(
            r#"{{
                "id": "case-deployment",
                "endpoints": [],
                "outboundTls": {trust_profiles},
                "allowedPrivateCidrs": ["10.0.0.0/8"],
                "listener": {{ "bind": "127.0.0.1:8080" }},
                "database": {{
                    "runtimeUrlRef": "secret:env/DB_RUNTIME",
                    "migrationUrlRef": "secret:env/DB_MIGRATION"
                }},
                "oidc": {{
                    "issuer": "https://issuer.example.invalid",
                    "audience": "case-api"
                }},
                "audit": {{ "retentionDays": 90 }}
            }}"#
        ))
        .expect("runtime config")
    }

    fn private_ca() -> LocalId {
        LocalId::new("private-ca").expect("id")
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
        let tls = EndpointTls::resolve(&binding(None, None), &runtime_config(None), &resolver())
            .expect("an unconfigured binding resolves");
        assert!(!tls.is_configured());
        assert!(tls.material().expect("no material").is_none());
        assert!(EndpointTls::none()
            .material()
            .expect("no material")
            .is_none());
    }

    /// A declared trust profile's CA bundle file resolves and builds
    /// platform material; the debug rendering never carries the PEM.
    #[test]
    fn a_declared_trust_profile_resolves_its_bundle_file() {
        let path = bundle_path("root");
        std::fs::write(&path, ROOT_CERTIFICATE_PEM).expect("write bundle");
        let runtime = runtime_config(Some(path.to_str().expect("utf-8 path")));
        let tls = EndpointTls::resolve(&binding(Some(private_ca()), None), &runtime, &resolver())
            .expect("the bundle resolves");
        std::fs::remove_file(&path).expect("remove bundle");
        assert!(tls.is_configured());
        let material = tls.material().expect("valid bundle material");
        assert!(material.is_some(), "a bundle alone configures TLS");
        let rendered = format!("{tls:?}");
        assert!(!rendered.contains("BEGIN CERTIFICATE"), "{rendered}");
    }

    /// The mTLS identity resolves as the certificate chain followed by
    /// one private key, beside a trust profile's bundle, and builds
    /// platform material.
    #[test]
    fn mtls_identities_resolve_and_build() {
        let path = bundle_path("mtls-root");
        std::fs::write(&path, ROOT_CERTIFICATE_PEM).expect("write bundle");
        let runtime = runtime_config(Some(path.to_str().expect("utf-8 path")));
        std::env::set_var("ADAPTER_TEST_CLIENT_CERT", CLIENT_CERTIFICATE_PEM);
        std::env::set_var("ADAPTER_TEST_CLIENT_KEY", CLIENT_PRIVATE_KEY_PEM);
        let tls = EndpointTls::resolve(
            &binding(
                Some(private_ca()),
                Some(identity_refs(
                    "ADAPTER_TEST_CLIENT_CERT",
                    "ADAPTER_TEST_CLIENT_KEY",
                )),
            ),
            &runtime,
            &resolver(),
        )
        .expect("the identity resolves");
        std::fs::remove_file(&path).expect("remove bundle");
        assert!(tls.is_configured());
        assert!(tls.material().expect("valid identity material").is_some());
    }

    /// Resolved but unusable material refuses value-free: a bundle that
    /// is not PEM, an identity whose certificate is not PEM.
    #[test]
    fn garbage_material_refuses() {
        let path = bundle_path("garbage");
        std::fs::write(&path, "not a pem bundle").expect("write bundle");
        let runtime = runtime_config(Some(path.to_str().expect("utf-8 path")));
        let tls = EndpointTls::resolve(&binding(Some(private_ca()), None), &runtime, &resolver())
            .expect("any file content resolves");
        std::fs::remove_file(&path).expect("remove bundle");
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
            &runtime_config(None),
            &resolver(),
        )
        .expect("any bytes resolve");
        assert_eq!(
            tls.material().unwrap_err(),
            AuthError::Tls(TlsFault::Material),
            "a non-PEM identity is unusable"
        );
    }

    /// Undeclared profiles and unreadable, non-regular, or oversized
    /// bundle paths refuse value-free: the rendering names neither the
    /// profile, the path, nor the content.
    #[test]
    fn unusable_profiles_refuse_value_free() {
        let fault = EndpointTls::resolve(
            &binding(Some(private_ca()), None),
            &runtime_config(None),
            &resolver(),
        )
        .unwrap_err();
        assert_eq!(fault, AuthError::Tls(TlsFault::CaBundle));
        assert!(!fault.to_string().contains("private-ca"), "{fault}");

        let missing = bundle_path("missing");
        let runtime = runtime_config(Some(missing.to_str().expect("utf-8 path")));
        let fault = EndpointTls::resolve(&binding(Some(private_ca()), None), &runtime, &resolver())
            .unwrap_err();
        assert_eq!(fault, AuthError::Tls(TlsFault::CaBundle));
        assert!(!fault.to_string().contains("missing"), "{fault}");

        let oversized = bundle_path("oversized");
        std::fs::write(&oversized, vec![b'p'; MAX_DESTINATION_CA_BUNDLE_BYTES + 1])
            .expect("write bundle");
        let runtime = runtime_config(Some(oversized.to_str().expect("utf-8 path")));
        let fault = EndpointTls::resolve(&binding(Some(private_ca()), None), &runtime, &resolver())
            .unwrap_err();
        std::fs::remove_file(&oversized).expect("remove bundle");
        assert_eq!(fault, AuthError::Tls(TlsFault::CaBundle));

        let fault = EndpointTls::resolve(
            &binding(
                None,
                Some(identity_refs(
                    "ADAPTER_TEST_NEVER_SET",
                    "ADAPTER_TEST_NEVER_SET",
                )),
            ),
            &runtime_config(None),
            &resolver(),
        )
        .unwrap_err();
        assert_eq!(fault, AuthError::Tls(TlsFault::ClientIdentity));
    }

    /// A bundle path that is not a regular file refuses: a directory (or
    /// any device or FIFO an operator mistyped) cannot block startup.
    #[test]
    fn a_non_regular_bundle_path_refuses() {
        let directory = std::env::temp_dir().join(format!(
            "registry-adapter-tls-dir-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&directory).expect("create directory");
        let runtime = runtime_config(Some(directory.to_str().expect("utf-8 path")));
        let fault = EndpointTls::resolve(&binding(Some(private_ca()), None), &runtime, &resolver())
            .unwrap_err();
        std::fs::remove_dir(&directory).expect("remove directory");
        assert_eq!(fault, AuthError::Tls(TlsFault::CaBundle));
        assert!(
            !fault.to_string().contains("registry-adapter-tls-dir"),
            "{fault}"
        );
    }

    /// On Unix, a bundle path that is a FIFO with no writer refuses
    /// instead of blocking: the regular-file check runs before
    /// `open(2)`, which would otherwise wait for a writer forever. The
    /// resolve runs on a thread and the test waits bounded, so a
    /// regression fails by timeout rather than hanging the suite.
    #[cfg(unix)]
    #[test]
    fn a_fifo_bundle_path_refuses_without_blocking() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let fifo = std::env::temp_dir().join(format!("registry-adapter-tls-fifo-{unique}"));
        let created = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(created.success(), "mkfifo created the fifo");
        let runtime = runtime_config(Some(fifo.to_str().expect("utf-8 path")));
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let resolved =
                EndpointTls::resolve(&binding(Some(private_ca()), None), &runtime, &resolver());
            let _ = sender.send(resolved);
        });
        let outcome = receiver.recv_timeout(std::time::Duration::from_secs(10));
        std::fs::remove_file(&fifo).expect("remove fifo");
        let resolved = outcome.expect("the fifo path refused instead of blocking on open(2)");
        assert_eq!(resolved.unwrap_err(), AuthError::Tls(TlsFault::CaBundle));
    }
}
