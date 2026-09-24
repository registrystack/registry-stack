// SPDX-License-Identifier: Apache-2.0

//! The operator-authored settings of one SMTP provider and their checks.

use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Certificate, TlsParameters};
use registry_platform_config::{SecretReference, SecretResolver};
use registry_platform_httputil::destination::{
    DestinationPolicyError, ProductionAddressPolicy, MAX_DESTINATION_PRIVATE_CIDRS,
};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{Network, SmtpProvider, Transport};
use crate::config::describe_secret_failure;

/// The attempt timeout a provider gets when none is configured.
pub const DEFAULT_SMTP_ATTEMPT_TIMEOUT_SECONDS: u64 = 30;

/// The longest attempt timeout a provider may configure. One attempt covers
/// resolution, connection, TLS, authentication, and the whole transaction.
pub const MAXIMUM_SMTP_ATTEMPT_TIMEOUT_SECONDS: u64 = 60;

/// The submission port, which requires STARTTLS.
pub const SMTP_SUBMISSION_PORT: u16 = 587;

/// The implicit-TLS submission port.
pub const SMTP_IMPLICIT_TLS_PORT: u16 = 465;

/// Whether this build accepts `tls: development-loopback`. Like
/// `database.testOnlyPlaintext`, plaintext SMTP is a test-build affordance:
/// only a build carrying the `postgres-test` or `smtp-test` feature, or a unit
/// test build, accepts it, so a release binary refuses it at startup and in
/// `messagingctl check`.
const DEVELOPMENT_LOOPBACK_PERMITTED: bool =
    cfg!(any(test, feature = "postgres-test", feature = "smtp-test"));

/// The longest host name a provider may configure (RFC 1035).
const MAXIMUM_HOST_BYTES: usize = 253;

/// How the connection to the relay is protected.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SmtpTlsMode {
    /// Connect in plaintext and upgrade with `STARTTLS` before anything else
    /// is sent. The relay must offer it. Defaults to port 587.
    Starttls,
    /// TLS from the first byte. Defaults to port 465.
    Implicit,
    /// Plaintext to a loopback relay, for a local development server only.
    /// The host must be a loopback literal or `localhost`, every resolved
    /// address must be loopback, and the port must be explicit. Only a test
    /// build accepts it.
    DevelopmentLoopback,
}

/// The credential pair the relay authenticates, as `secret:` references.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SmtpAuthentication {
    pub username_ref: String,
    pub password_ref: String,
}

impl std::fmt::Debug for SmtpAuthentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmtpAuthentication")
            .field("username_ref", &"<redacted>")
            .field("password_ref", &"<redacted>")
            .finish()
    }
}

/// One SMTP provider's runtime settings, as the operator writes them.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SmtpProviderSettings {
    /// The relay's DNS name or IP literal. It is resolved once per attempt and
    /// is the name TLS verifies the relay's certificate against.
    pub host: String,
    /// Defaults to 587 for `starttls` and 465 for `implicit`; required for
    /// `development-loopback`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub tls: SmtpTlsMode,
    /// A PEM root certificate trusted in addition to the public web roots,
    /// for a relay behind a private certificate authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_root_certificate_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<SmtpAuthentication>,
    #[serde(default = "default_attempt_timeout_seconds")]
    pub attempt_timeout_seconds: u64,
    /// Exact RFC 1918, CGNAT, or unique-local networks the relay may resolve
    /// into. Every other non-public address is refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_private_cidrs: Vec<String>,
}

const fn default_attempt_timeout_seconds() -> u64 {
    DEFAULT_SMTP_ATTEMPT_TIMEOUT_SECONDS
}

impl std::fmt::Debug for SmtpProviderSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmtpProviderSettings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field(
                "trusted_root_certificate_ref",
                &self
                    .trusted_root_certificate_ref
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("authentication", &self.authentication)
            .field("attempt_timeout_seconds", &self.attempt_timeout_seconds)
            .field("allowed_private_cidrs", &self.allowed_private_cidrs)
            .finish()
    }
}

/// Why SMTP settings cannot be used. Every message names the field and never
/// a secret value.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SmtpSettingsError {
    #[error("host must be a DNS name or an IP literal of at most {MAXIMUM_HOST_BYTES} bytes")]
    InvalidHost,
    #[error("port must not be zero")]
    PortZero,
    #[error("port 587 requires tls starttls")]
    SubmissionPortRequiresStarttls,
    #[error("port 465 requires tls implicit")]
    ImplicitPortRequiresImplicitTls,
    #[error("tls development-loopback is accepted only by a test build")]
    DevelopmentNotPermitted,
    #[error("tls development-loopback requires a loopback IP literal or localhost as host")]
    DevelopmentRequiresLoopbackHost,
    #[error("tls development-loopback requires an explicit port other than 465 and 587")]
    DevelopmentRequiresExplicitPort,
    #[error("tls development-loopback cannot declare trustedRootCertificateRef")]
    DevelopmentTrustedRootDenied,
    #[error("tls development-loopback cannot declare allowedPrivateCidrs")]
    DevelopmentPrivateCidrsDenied,
    #[error(
        "attemptTimeoutSeconds must be from 1 to {MAXIMUM_SMTP_ATTEMPT_TIMEOUT_SECONDS} seconds"
    )]
    AttemptTimeoutOutOfRange,
    #[error("allowedPrivateCidrs accepts at most {MAX_DESTINATION_PRIVATE_CIDRS} networks")]
    TooManyPrivateCidrs,
    #[error("allowedPrivateCidrs entry {index} is not a CIDR network")]
    InvalidPrivateCidr { index: usize },
    #[error(
        "allowedPrivateCidrs may name only exact RFC 1918, CGNAT, or unique-local networks, \
         and never a cloud metadata address"
    )]
    PrivateCidrDenied,
    #[error("{field} is not an exact secret:env/NAME or secret:file/name reference")]
    InvalidSecretReference { field: &'static str },
    #[error("{0}")]
    Secret(String),
    #[error("{field} must resolve to UTF-8 text")]
    SecretNotText { field: &'static str },
    #[error("trustedRootCertificateRef must resolve to at least one PEM certificate")]
    InvalidTrustedRootCertificate,
    #[error("the TLS client for this provider could not be built")]
    TlsClient,
}

impl SmtpProviderSettings {
    /// Check the settings without resolving anything.
    pub fn check(&self) -> Result<(), SmtpSettingsError> {
        self.checked().map(|_| ())
    }

    /// Every secret reference these settings name, with the field that names
    /// it, so a runtime can check its providers are enabled.
    #[must_use]
    pub fn secret_references(&self) -> Vec<(&'static str, &str)> {
        let mut references = Vec::new();
        if let Some(reference) = &self.trusted_root_certificate_ref {
            references.push(("trustedRootCertificateRef", reference.as_str()));
        }
        if let Some(authentication) = &self.authentication {
            references.push((
                "authentication.usernameRef",
                authentication.username_ref.as_str(),
            ));
            references.push((
                "authentication.passwordRef",
                authentication.password_ref.as_str(),
            ));
        }
        references
    }

    /// Check the settings, resolve their secrets, and build the provider.
    pub fn activate(&self, secrets: &SecretResolver) -> Result<SmtpProvider, SmtpSettingsError> {
        let checked = self.checked()?;
        let transport = match self.tls {
            SmtpTlsMode::DevelopmentLoopback => Transport::DevelopmentLoopback,
            SmtpTlsMode::Starttls => Transport::Starttls(self.tls_parameters(secrets)?),
            SmtpTlsMode::Implicit => Transport::Implicit(self.tls_parameters(secrets)?),
        };
        let credentials = match &self.authentication {
            None => None,
            Some(authentication) => Some(Credentials::new(
                resolve_text(
                    secrets,
                    "authentication.usernameRef",
                    &authentication.username_ref,
                )?,
                resolve_text(
                    secrets,
                    "authentication.passwordRef",
                    &authentication.password_ref,
                )?,
            )),
        };
        Ok(SmtpProvider {
            host: self.host.clone(),
            port: checked.port,
            transport,
            credentials,
            attempt_timeout: checked.attempt_timeout,
            policy: checked.policy,
            network: Network::System,
        })
    }

    fn tls_parameters(&self, secrets: &SecretResolver) -> Result<TlsParameters, SmtpSettingsError> {
        let mut builder = TlsParameters::builder(self.host.clone());
        if let Some(reference) = &self.trusted_root_certificate_ref {
            let pem = secrets.resolve(reference).map_err(|error| {
                SmtpSettingsError::Secret(describe_secret_failure(
                    "trustedRootCertificateRef",
                    reference,
                    &error,
                ))
            })?;
            let certificates = CertificateDer::pem_slice_iter(pem.expose_secret())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| SmtpSettingsError::InvalidTrustedRootCertificate)?;
            if certificates.is_empty() {
                return Err(SmtpSettingsError::InvalidTrustedRootCertificate);
            }
            for der in certificates {
                let certificate = Certificate::from_der(der.to_vec())
                    .map_err(|_| SmtpSettingsError::InvalidTrustedRootCertificate)?;
                builder = builder.add_root_certificate(certificate);
            }
        }
        builder
            .build_rustls()
            .map_err(|_| SmtpSettingsError::TlsClient)
    }

    fn checked(&self) -> Result<Checked, SmtpSettingsError> {
        self.checked_with(DEVELOPMENT_LOOPBACK_PERMITTED)
    }

    fn checked_with(&self, development_permitted: bool) -> Result<Checked, SmtpSettingsError> {
        let host_literal = check_host(&self.host)?;
        if !(1..=MAXIMUM_SMTP_ATTEMPT_TIMEOUT_SECONDS).contains(&self.attempt_timeout_seconds) {
            return Err(SmtpSettingsError::AttemptTimeoutOutOfRange);
        }
        if self.port == Some(0) {
            return Err(SmtpSettingsError::PortZero);
        }
        for (field, reference) in self.secret_references() {
            SecretReference::parse(reference)
                .map_err(|_| SmtpSettingsError::InvalidSecretReference { field })?;
        }
        let port = match self.tls {
            SmtpTlsMode::DevelopmentLoopback => {
                if !development_permitted {
                    return Err(SmtpSettingsError::DevelopmentNotPermitted);
                }
                let loopback = match host_literal {
                    Some(ip) => ip.to_canonical().is_loopback(),
                    None => self.host.eq_ignore_ascii_case("localhost"),
                };
                if !loopback {
                    return Err(SmtpSettingsError::DevelopmentRequiresLoopbackHost);
                }
                if self.trusted_root_certificate_ref.is_some() {
                    return Err(SmtpSettingsError::DevelopmentTrustedRootDenied);
                }
                if !self.allowed_private_cidrs.is_empty() {
                    return Err(SmtpSettingsError::DevelopmentPrivateCidrsDenied);
                }
                match self.port {
                    Some(port)
                        if port != SMTP_SUBMISSION_PORT && port != SMTP_IMPLICIT_TLS_PORT =>
                    {
                        port
                    }
                    _ => return Err(SmtpSettingsError::DevelopmentRequiresExplicitPort),
                }
            }
            SmtpTlsMode::Starttls => match self.port {
                Some(SMTP_IMPLICIT_TLS_PORT) => {
                    return Err(SmtpSettingsError::ImplicitPortRequiresImplicitTls)
                }
                Some(port) => port,
                None => SMTP_SUBMISSION_PORT,
            },
            SmtpTlsMode::Implicit => match self.port {
                Some(SMTP_SUBMISSION_PORT) => {
                    return Err(SmtpSettingsError::SubmissionPortRequiresStarttls)
                }
                Some(port) => port,
                None => SMTP_IMPLICIT_TLS_PORT,
            },
        };
        if self.allowed_private_cidrs.len() > MAX_DESTINATION_PRIVATE_CIDRS {
            return Err(SmtpSettingsError::TooManyPrivateCidrs);
        }
        let cidrs = self
            .allowed_private_cidrs
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                raw.parse::<IpNet>()
                    .map_err(|_| SmtpSettingsError::InvalidPrivateCidr { index })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let policy = ProductionAddressPolicy::new(&cidrs).map_err(|error| match error {
            DestinationPolicyError::TooManyPrivateCidrs => SmtpSettingsError::TooManyPrivateCidrs,
            _ => SmtpSettingsError::PrivateCidrDenied,
        })?;
        Ok(Checked {
            port,
            attempt_timeout: Duration::from_secs(self.attempt_timeout_seconds),
            policy,
        })
    }
}

struct Checked {
    port: u16,
    attempt_timeout: Duration,
    policy: ProductionAddressPolicy,
}

/// Accept an IP literal or a DNS name of ASCII letters, digits, and hyphens,
/// and return the literal when it is one.
fn check_host(host: &str) -> Result<Option<IpAddr>, SmtpSettingsError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Some(ip));
    }
    let valid = !host.is_empty()
        && host.len() <= MAXIMUM_HOST_BYTES
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        // A name whose last label is numeric would read as a malformed IPv4
        // literal, so it is refused rather than resolved.
        && !host
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()));
    if valid {
        Ok(None)
    } else {
        Err(SmtpSettingsError::InvalidHost)
    }
}

fn resolve_text(
    secrets: &SecretResolver,
    field: &'static str,
    reference: &str,
) -> Result<String, SmtpSettingsError> {
    let secret = secrets.resolve(reference).map_err(|error| {
        SmtpSettingsError::Secret(describe_secret_failure(field, reference, &error))
    })?;
    std::str::from_utf8(secret.expose_secret())
        .map(str::to_owned)
        .map_err(|_| SmtpSettingsError::SecretNotText { field })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn settings(yaml: &str) -> Result<SmtpProviderSettings, serde_norway::Error> {
        serde_norway::from_str(yaml)
    }

    fn starttls() -> SmtpProviderSettings {
        settings("host: smtp.example.org\ntls: starttls\n").expect("minimal settings parse")
    }

    #[test]
    fn minimal_starttls_settings_default_to_the_submission_port_and_thirty_seconds() {
        let settings = starttls();
        let checked = settings.checked().expect("settings check");
        assert_eq!(checked.port, 587);
        assert_eq!(checked.attempt_timeout, Duration::from_secs(30));
    }

    #[test]
    fn implicit_tls_defaults_to_port_465() {
        let settings = settings("host: smtp.example.org\ntls: implicit\n").expect("parse");
        assert_eq!(settings.checked().expect("check").port, 465);
    }

    #[test]
    fn unknown_keys_are_refused_at_every_level() {
        for yaml in [
            "host: smtp.example.org\ntls: starttls\nverifyCertificates: false\n",
            "host: smtp.example.org\ntls: starttls\nauthentication:\n  usernameRef: secret:env/U\n  passwordRef: secret:env/P\n  mechanism: plain\n",
            "host: smtp.example.org\ntls: none\n",
        ] {
            assert!(settings(yaml).is_err(), "accepted: {yaml}");
        }
    }

    #[test]
    fn the_attempt_timeout_is_bounded_to_sixty_seconds() {
        let mut settings = starttls();
        settings.attempt_timeout_seconds = 60;
        assert!(settings.check().is_ok());
        for refused in [0, 61, 3600] {
            settings.attempt_timeout_seconds = refused;
            assert_eq!(
                settings.check(),
                Err(SmtpSettingsError::AttemptTimeoutOutOfRange)
            );
        }
    }

    #[test]
    fn the_well_known_ports_require_their_tls_mode() {
        let mut settings = starttls();
        settings.port = Some(465);
        assert_eq!(
            settings.check(),
            Err(SmtpSettingsError::ImplicitPortRequiresImplicitTls)
        );
        settings.tls = SmtpTlsMode::Implicit;
        settings.port = Some(587);
        assert_eq!(
            settings.check(),
            Err(SmtpSettingsError::SubmissionPortRequiresStarttls)
        );
        settings.port = Some(0);
        assert_eq!(settings.check(), Err(SmtpSettingsError::PortZero));
        settings.tls = SmtpTlsMode::Starttls;
        settings.port = Some(2525);
        assert!(settings.check().is_ok());
    }

    #[test]
    fn plaintext_is_refused_for_a_host_that_is_not_loopback() {
        for host in [
            "smtp.example.org",
            "10.0.0.5",
            "0.0.0.0",
            "::",
            "localhost.example.org",
        ] {
            let settings = SmtpProviderSettings {
                host: host.to_owned(),
                port: Some(1025),
                ..development("127.0.0.1")
            };
            assert_eq!(
                settings.check(),
                Err(SmtpSettingsError::DevelopmentRequiresLoopbackHost),
                "{host}"
            );
        }
        for host in [
            "127.0.0.1",
            "127.3.2.1",
            "::1",
            "localhost",
            "LOCALHOST",
            "::ffff:127.0.0.1",
        ] {
            assert!(development(host).check().is_ok(), "{host}");
        }
    }

    #[test]
    fn plaintext_is_refused_by_a_build_without_a_test_feature() {
        assert_eq!(
            development("127.0.0.1").checked_with(false).map(|_| ()),
            Err(SmtpSettingsError::DevelopmentNotPermitted)
        );
        assert!(development("127.0.0.1").checked_with(true).is_ok());
        let production = SmtpProviderSettings {
            host: "smtp.example.org".to_owned(),
            port: None,
            tls: SmtpTlsMode::Starttls,
            ..development("127.0.0.1")
        };
        assert!(production.checked_with(false).is_ok());
    }

    #[test]
    fn plaintext_needs_an_explicit_port_that_is_not_a_tls_port() {
        let mut settings = development("127.0.0.1");
        for port in [None, Some(465), Some(587)] {
            settings.port = port;
            assert_eq!(
                settings.check(),
                Err(SmtpSettingsError::DevelopmentRequiresExplicitPort)
            );
        }
    }

    #[test]
    fn plaintext_refuses_tls_material_and_private_networks() {
        let mut settings = development("127.0.0.1");
        settings.trusted_root_certificate_ref = Some("secret:env/ROOT".to_owned());
        assert_eq!(
            settings.check(),
            Err(SmtpSettingsError::DevelopmentTrustedRootDenied)
        );
        let mut settings = development("127.0.0.1");
        settings.allowed_private_cidrs = vec!["10.0.0.0/8".to_owned()];
        assert_eq!(
            settings.check(),
            Err(SmtpSettingsError::DevelopmentPrivateCidrsDenied)
        );
    }

    #[test]
    fn hosts_must_be_a_dns_name_or_an_ip_literal() {
        for host in [
            "",
            "smtp example.org",
            "smtp.example.org.",
            "-smtp.example.org",
            "smtp_relay.example.org",
            "smtp.example.org:25",
            "user@smtp.example.org",
            "exämple.org",
            "999.1.1.1",
            "1.2.3",
            &"a".repeat(64),
        ] {
            let mut settings = starttls();
            settings.host = host.to_owned();
            assert_eq!(
                settings.check(),
                Err(SmtpSettingsError::InvalidHost),
                "{host}"
            );
        }
        for host in [
            "smtp.example.org",
            "relay-1.mail.example",
            "203.0.113.7",
            "2001:db8::1",
        ] {
            let mut settings = starttls();
            settings.host = host.to_owned();
            assert!(settings.check().is_ok(), "{host}");
        }
    }

    #[test]
    fn private_networks_are_checked_like_a_production_destination() {
        let mut settings = starttls();
        settings.allowed_private_cidrs = vec!["10.20.0.0/16".to_owned(), "fd00:1::/64".to_owned()];
        assert!(settings.check().is_ok());
        for (cidrs, expected) in [
            (vec!["10.20.0.1/16"], SmtpSettingsError::PrivateCidrDenied),
            (vec!["8.8.8.0/24"], SmtpSettingsError::PrivateCidrDenied),
            (vec!["127.0.0.0/8"], SmtpSettingsError::PrivateCidrDenied),
            (
                vec!["169.254.169.254/32"],
                SmtpSettingsError::PrivateCidrDenied,
            ),
            (
                vec!["10.0.0.0/8", "not-a-cidr"],
                SmtpSettingsError::InvalidPrivateCidr { index: 1 },
            ),
        ] {
            settings.allowed_private_cidrs = cidrs.iter().map(|cidr| (*cidr).to_owned()).collect();
            assert_eq!(settings.check(), Err(expected), "{cidrs:?}");
        }
        settings.allowed_private_cidrs =
            (0..17).map(|index| format!("10.{index}.0.0/16")).collect();
        assert_eq!(
            settings.check(),
            Err(SmtpSettingsError::TooManyPrivateCidrs)
        );
    }

    #[test]
    fn secret_references_must_be_exact_references() {
        let mut settings = starttls();
        settings.authentication = Some(SmtpAuthentication {
            username_ref: "secret:env/SMTP_USER".to_owned(),
            password_ref: "hunter2".to_owned(),
        });
        let error = settings.check().expect_err("literal password refused");
        assert_eq!(
            error,
            SmtpSettingsError::InvalidSecretReference {
                field: "authentication.passwordRef"
            }
        );
        assert!(!error.to_string().contains("hunter2"));
        assert_eq!(
            settings.secret_references(),
            vec![
                ("authentication.usernameRef", "secret:env/SMTP_USER"),
                ("authentication.passwordRef", "hunter2"),
            ]
        );
    }

    #[test]
    fn debug_output_names_no_secret_reference() {
        let mut settings = starttls();
        settings.trusted_root_certificate_ref = Some("secret:file/relay-root".to_owned());
        settings.authentication = Some(SmtpAuthentication {
            username_ref: "secret:file/relay-user".to_owned(),
            password_ref: "secret:file/relay-password".to_owned(),
        });
        let debug = format!("{settings:?}");
        assert!(!debug.contains("relay-"), "{debug}");
        assert!(debug.contains("smtp.example.org"));
    }

    #[test]
    fn activation_resolves_credentials_and_the_trusted_root() {
        let directory = tempfile::tempdir().expect("secret directory");
        let root = directory.path().canonicalize().expect("canonical root");
        write_secret(&root, "relay-user", b"mailer");
        write_secret(&root, "relay-password", b"correct horse");
        write_secret(&root, "relay-root", b"not a certificate");
        let secrets = SecretResolver::new([registry_platform_config::SecretProvider::File], &root)
            .expect("resolver");
        let mut settings = starttls();
        settings.authentication = Some(SmtpAuthentication {
            username_ref: "secret:file/relay-user".to_owned(),
            password_ref: "secret:file/relay-password".to_owned(),
        });
        let provider = settings.activate(&secrets).expect("activation");
        assert!(provider.credentials.is_some());
        let debug = format!("{provider:?}");
        assert!(
            !debug.contains("mailer") && !debug.contains("horse"),
            "{debug}"
        );

        settings.trusted_root_certificate_ref = Some("secret:file/relay-root".to_owned());
        assert_eq!(
            settings.activate(&secrets).map(|_| ()),
            Err(SmtpSettingsError::InvalidTrustedRootCertificate)
        );
        settings.trusted_root_certificate_ref = Some("secret:file/absent".to_owned());
        let error = settings.activate(&secrets).map(|_| ()).expect_err("absent");
        assert!(matches!(error, SmtpSettingsError::Secret(_)), "{error:?}");
    }

    pub(crate) fn development(host: &str) -> SmtpProviderSettings {
        SmtpProviderSettings {
            host: host.to_owned(),
            port: Some(1025),
            tls: SmtpTlsMode::DevelopmentLoopback,
            trusted_root_certificate_ref: None,
            authentication: None,
            attempt_timeout_seconds: DEFAULT_SMTP_ATTEMPT_TIMEOUT_SECONDS,
            allowed_private_cidrs: Vec::new(),
        }
    }

    pub(crate) fn write_secret(root: &std::path::Path, name: &str, value: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;
        let path = root.join(name);
        std::fs::write(&path, value).expect("write secret");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secret mode");
    }
}
