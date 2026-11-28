// SPDX-License-Identifier: Apache-2.0
//! The `tokio-postgres` side of the shared database transport check.
//!
//! `registry-platform-config` checks the database hosts and returns the
//! numeric addresses each was checked as. This crate builds the
//! `tokio_postgres::Config` that dials only those addresses, so the
//! configuration crate stays free of a PostgreSQL client.

use std::net::IpAddr;
#[cfg(unix)]
use std::path::PathBuf;

use registry_platform_config::{
    check_database_hosts, CheckedHost, DatabaseConfig, DatabaseHost, DatabaseTransport,
    DatabaseTransportError, DevelopmentWitness, HostResolver, PermittedTransport,
};
use tokio_postgres::config::Host;
use tokio_postgres::Config;

/// The port the driver uses for a host when the configuration names none.
const DEFAULT_PORT: u16 = 5432;

/// Check every host and `hostaddr` of a parsed PostgreSQL configuration, as
/// [`DatabaseConfig::permitted_transport`] does, with the host names looked
/// up by `resolve`, and return the transport with the configuration the pool
/// hands to the driver. A runtime passes
/// [`registry_platform_config::resolve_database_host`] as `resolve`.
///
/// Under a plaintext transport every TCP host becomes one entry for each
/// numeric address it was checked as, each with the host's port, so the
/// driver never resolves a name again. An authored `hostaddr` is dialled as
/// written, Unix socket hosts are kept as they are, and every other setting
/// is carried over. Under `verified-tls` the configuration is returned
/// unchanged: certificate verification needs the name.
pub fn postgres_connection(
    config: &DatabaseConfig,
    postgres: Config,
    witness: Option<&DevelopmentWitness>,
    resolve: &HostResolver,
) -> Result<(DatabaseTransport, Config), DatabaseTransportError> {
    let permitted =
        config.permitted_transport_with_resolver(&database_hosts(&postgres), witness, resolve)?;
    let pinned = pinned(&permitted, postgres)?;
    Ok((permitted.transport, pinned))
}

/// Check a parsed PostgreSQL configuration under `loopback-plaintext` and
/// return the configuration that dials only the checked loopback addresses,
/// as [`postgres_connection`] does. For a constructor that holds no runtime
/// database block and allows plaintext only to an explicit local host.
pub fn loopback_postgres_connection(
    postgres: Config,
    resolve: &HostResolver,
) -> Result<Config, DatabaseTransportError> {
    let permitted = check_database_hosts(
        DatabaseTransport::LoopbackPlaintext,
        &database_hosts(&postgres),
        resolve,
    )?;
    pinned(&permitted, postgres)
}

/// Every host and `hostaddr` of `postgres`, in that order. The driver dials a
/// `hostaddr` in preference to the host at the same position, so both lists
/// are checked.
fn database_hosts(postgres: &Config) -> Vec<DatabaseHost> {
    postgres
        .get_hosts()
        .iter()
        .map(|host| match host {
            Host::Tcp(name) => DatabaseHost::Tcp(name.clone()),
            #[cfg(unix)]
            Host::Unix(_) => DatabaseHost::Unix,
        })
        .chain(
            postgres
                .get_hostaddrs()
                .iter()
                .map(|address| DatabaseHost::Tcp(address.to_string())),
        )
        .collect()
}

/// `postgres` rewritten to dial what `permitted` checked, or unchanged when
/// nothing was checked.
fn pinned(
    permitted: &PermittedTransport,
    postgres: Config,
) -> Result<Config, DatabaseTransportError> {
    let Some(checked) = &permitted.checked else {
        return Ok(postgres);
    };
    match targets(&postgres, checked) {
        Layout::Targets(targets) => Ok(pin(&postgres, targets)),
        Layout::RefusedByDriver => Ok(postgres),
        Layout::Bracketed(address) => Err(DatabaseTransportError::BracketedHost(address)),
        Layout::Unmatched => Err(DatabaseTransportError::HostMismatch(permitted.transport)),
    }
}

/// One connection target the driver tries, in order.
enum Target {
    Address(IpAddr, u16),
    #[cfg(unix)]
    Socket(PathBuf, u16),
}

enum Layout {
    /// Every target the driver tries, in its order.
    Targets(Vec<Target>),
    /// A host, `hostaddr` and port layout the driver refuses before it
    /// dials anything, so the configuration is handed on for the driver to
    /// refuse.
    RefusedByDriver,
    /// Every host the driver dials is an IP literal in brackets. The URL
    /// parser strips the brackets of an authority, the keyword parser keeps
    /// them, and the driver then looks the bracketed text up as a name,
    /// which fails, and moves on to the next host. The first such literal
    /// is named.
    Bracketed(IpAddr),
    /// The checked entries do not match the hosts they were checked for.
    Unmatched,
}

/// The targets of `postgres` with every TCP host replaced by its checked
/// addresses. `checked` holds one entry for each host followed by one for
/// each `hostaddr`, as the check received them. The driver tries position
/// `i` at the `hostaddr` there when there is one, else at the host there, on
/// the port there, the only port, or 5432.
fn targets(postgres: &Config, checked: &[CheckedHost]) -> Layout {
    let hosts = postgres.get_hosts();
    let addresses = postgres.get_hostaddrs();
    let ports = postgres.get_ports();
    if !hosts.is_empty() && !addresses.is_empty() && hosts.len() != addresses.len() {
        return Layout::RefusedByDriver;
    }
    let count = hosts.len().max(addresses.len());
    if ports.len() > 1 && ports.len() != count {
        return Layout::RefusedByDriver;
    }
    if checked.len() != hosts.len() + addresses.len() {
        return Layout::Unmatched;
    }
    let mut targets = Vec::new();
    let mut bracketed = None;
    for position in 0..count {
        let port = ports
            .get(position)
            .or_else(|| ports.first())
            .copied()
            .unwrap_or(DEFAULT_PORT);
        if addresses.is_empty() {
            if let Some(Host::Tcp(name)) = hosts.get(position) {
                // The driver fails this entry and tries the next, so the
                // entry is dropped and the others keep their order and ports.
                if let Some(address) = bracketed_ip(name) {
                    bracketed.get_or_insert(address);
                    continue;
                }
            }
        }
        let dialled = if addresses.is_empty() {
            (&checked[position], hosts.get(position))
        } else {
            (&checked[hosts.len() + position], None)
        };
        match dialled {
            (CheckedHost::Tcp(checked_addresses), _) => targets.extend(
                checked_addresses
                    .iter()
                    .map(|address| Target::Address(*address, port)),
            ),
            #[cfg(unix)]
            (CheckedHost::Unix, Some(Host::Unix(path))) => {
                targets.push(Target::Socket(path.clone(), port));
            }
            (CheckedHost::Unix, _) => return Layout::Unmatched,
        }
    }
    match bracketed {
        Some(address) if targets.is_empty() => Layout::Bracketed(address),
        _ => Layout::Targets(targets),
    }
}

/// The IP address in a host written as `[address]`.
fn bracketed_ip(host: &str) -> Option<IpAddr> {
    host.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

/// A copy of `postgres` that dials `targets` alone.
fn pin(postgres: &Config, targets: Vec<Target>) -> Config {
    let mut pinned = without_hosts(postgres);
    #[cfg(unix)]
    let with_socket = targets
        .iter()
        .any(|target| matches!(target, Target::Socket(..)));
    #[cfg(not(unix))]
    let with_socket = false;
    for target in targets {
        match target {
            // The driver pairs each `hostaddr` with the host at the same
            // position, so beside a socket an address is written as a numeric
            // host, which the driver parses without a lookup.
            Target::Address(address, port) if with_socket => {
                pinned.host(address.to_string()).port(port);
            }
            Target::Address(address, port) => {
                pinned.hostaddr(address).port(port);
            }
            #[cfg(unix)]
            Target::Socket(path, port) => {
                pinned.host_path(path).port(port);
            }
        }
    }
    pinned
}

/// A copy of `postgres` with no host, `hostaddr` or port.
fn without_hosts(postgres: &Config) -> Config {
    let mut copy = Config::new();
    if let Some(user) = postgres.get_user() {
        copy.user(user);
    }
    if let Some(password) = postgres.get_password() {
        copy.password(password);
    }
    if let Some(dbname) = postgres.get_dbname() {
        copy.dbname(dbname);
    }
    if let Some(options) = postgres.get_options() {
        copy.options(options);
    }
    if let Some(application_name) = postgres.get_application_name() {
        copy.application_name(application_name);
    }
    if let Some(timeout) = postgres.get_connect_timeout() {
        copy.connect_timeout(*timeout);
    }
    if let Some(timeout) = postgres.get_tcp_user_timeout() {
        copy.tcp_user_timeout(*timeout);
    }
    if let Some(interval) = postgres.get_keepalives_interval() {
        copy.keepalives_interval(interval);
    }
    if let Some(retries) = postgres.get_keepalives_retries() {
        copy.keepalives_retries(retries);
    }
    copy.ssl_mode(postgres.get_ssl_mode())
        .ssl_negotiation(postgres.get_ssl_negotiation())
        .keepalives(postgres.get_keepalives())
        .keepalives_idle(postgres.get_keepalives_idle())
        .target_session_attrs(postgres.get_target_session_attrs())
        .channel_binding(postgres.get_channel_binding())
        .load_balance_hosts(postgres.get_load_balance_hosts());
    copy
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use tokio_postgres::config::Host;
    use tokio_postgres::Config;

    use registry_platform_config::{
        DatabaseConfig, DatabaseTransport, DatabaseTransportError, DeclaredPosture,
        DevelopmentWitness, LoadedRuntimeConfig, Posture, PostureSource, RuntimeConfigLoader,
        RuntimeEnvelope,
    };

    use super::postgres_connection;

    const ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
        api_version: "registry.registrystack.org/example-runtime/v1alpha1",
        kind: "ExampleRuntimeConfig",
    };

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Example {
        database: DatabaseConfig,
    }

    /// A runtime file holding only a database block, loaded by a process
    /// that declared development.
    fn load(transport: Option<&str>) -> LoadedRuntimeConfig<Example> {
        let mut text = String::from(
            "apiVersion: registry.registrystack.org/example-runtime/v1alpha1\n\
             kind: ExampleRuntimeConfig\n\
             database:\n  runtimeUrlRef: secret:env/DB_RUNTIME\n  \
             migrationUrlRef: secret:env/DB_MIGRATION\n",
        );
        if let Some(transport) = transport {
            text.push_str(&format!("  transport: {transport}\n"));
        }
        let declared = DeclaredPosture {
            posture: Posture::Development,
            source: PostureSource::Flag,
        };
        RuntimeConfigLoader::new(ENVELOPE, declared)
            .parse_str(&text, |_| None)
            .unwrap()
    }

    /// The witness a configuration that declares development receives.
    fn development_witness() -> DevelopmentWitness {
        load(None)
            .development
            .expect("a development declaration yields a witness")
    }

    fn database(transport: Option<&str>) -> DatabaseConfig {
        load(transport).config.database
    }

    fn resolve(name: &str) -> std::io::Result<Vec<IpAddr>> {
        match name {
            "localhost" => Ok(vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ]),
            _ => Err(std::io::Error::other("no such name")),
        }
    }

    fn loopback(url: &str) -> (DatabaseTransport, Config) {
        postgres_connection(
            &database(Some("loopback-plaintext")),
            Config::from_str(url).unwrap(),
            None,
            &resolve,
        )
        .unwrap()
    }

    #[test]
    fn a_loopback_name_becomes_one_numeric_hostaddr_per_checked_address() {
        let (transport, pinned) = loopback("postgresql://app@localhost:5433/registry");
        assert_eq!(transport, DatabaseTransport::LoopbackPlaintext);
        assert_eq!(pinned.get_hosts(), &[] as &[Host]);
        assert_eq!(
            pinned.get_hostaddrs(),
            &[
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ]
        );
        assert_eq!(pinned.get_ports(), &[5433, 5433]);
    }

    #[test]
    fn every_other_setting_survives_the_pin() {
        let settings = "user=app password=secret dbname=registry options='-c search_path=app' \
             application_name=registry connect_timeout=7 tcp_user_timeout=9 keepalives=0 \
             keepalives_idle=30 keepalives_interval=11 keepalives_retries=4 \
             target_session_attrs=read-write channel_binding=require load_balance_hosts=random \
             sslmode=disable";
        let (_, pinned) = loopback(&format!("host=localhost port=5433 {settings}"));
        let expected =
            Config::from_str(&format!("hostaddr=127.0.0.1,::1 port=5433,5433 {settings}")).unwrap();
        assert_eq!(pinned, expected);
    }

    // `Host::Unix` exists on Unix targets only.
    #[cfg(unix)]
    #[test]
    fn a_socket_beside_a_name_keeps_its_place_and_its_port() {
        let (_, pinned) = loopback(
            "host=/run/postgresql,localhost,127.0.0.2 port=5432,5433,5434 user=app dbname=registry",
        );
        assert_eq!(
            pinned.get_hosts(),
            &[
                Host::Unix("/run/postgresql".into()),
                Host::Tcp("127.0.0.1".to_owned()),
                Host::Tcp("::1".to_owned()),
                Host::Tcp("127.0.0.2".to_owned()),
            ]
        );
        assert_eq!(pinned.get_hostaddrs(), &[] as &[IpAddr]);
        assert_eq!(pinned.get_ports(), &[5432, 5433, 5433, 5434]);
    }

    #[test]
    fn an_authored_hostaddr_is_dialled_as_checked_and_its_name_is_not_expanded() {
        let (_, pinned) = loopback("host=localhost hostaddr=127.0.0.3 user=app dbname=registry");
        assert_eq!(pinned.get_hosts(), &[] as &[Host]);
        assert_eq!(
            pinned.get_hostaddrs(),
            &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))]
        );
        assert_eq!(pinned.get_ports(), &[5432]);
    }

    #[test]
    fn an_authored_non_loopback_hostaddr_is_refused() {
        let answer = postgres_connection(
            &database(Some("loopback-plaintext")),
            Config::from_str("host=localhost hostaddr=10.0.0.5 user=app dbname=registry").unwrap(),
            None,
            &resolve,
        );
        assert_eq!(
            answer.map(|(transport, _)| transport),
            Err(DatabaseTransportError::HostMismatch(
                DatabaseTransport::LoopbackPlaintext
            ))
        );
    }

    #[test]
    fn a_bracketed_keyword_host_the_driver_would_dial_is_refused_by_name() {
        let error = postgres_connection(
            &database(Some("loopback-plaintext")),
            Config::from_str("host=[::1] port=5433 user=app dbname=registry").unwrap(),
            None,
            &resolve,
        )
        .unwrap_err();
        assert_eq!(error.code(), "platform.database.bracketed-host");
        assert!(error.to_string().contains("[::1]"), "{error}");
        assert!(
            error.suggested_action().contains("without brackets"),
            "{}",
            error.suggested_action()
        );
    }

    #[test]
    fn a_bracketed_keyword_host_is_skipped_and_the_hosts_beside_it_keep_their_ports() {
        // The driver fails the bracketed entry and tries the next one, so
        // the pin drops that entry and keeps the others in order.
        for url in [
            "host=[::1],127.0.0.1 port=5433,5432 user=app dbname=registry",
            "host=127.0.0.1,[::1] port=5432,5433 user=app dbname=registry",
        ] {
            let (_, pinned) = loopback(url);
            assert_eq!(pinned.get_hosts(), &[] as &[Host], "{url}");
            assert_eq!(
                pinned.get_hostaddrs(),
                &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
                "{url}"
            );
            assert_eq!(pinned.get_ports(), &[5432], "{url}");
        }
        let error = postgres_connection(
            &database(Some("loopback-plaintext")),
            Config::from_str("host=[::1],[::1] port=5433,5434 user=app dbname=registry").unwrap(),
            None,
            &resolve,
        )
        .unwrap_err();
        assert_eq!(error.code(), "platform.database.bracketed-host");
        assert!(error.to_string().contains("[::1]"), "{error}");
    }

    #[test]
    fn a_bracketed_ipv4_keyword_host_is_skipped_like_a_bracketed_ipv6_host() {
        let witness = development_witness();
        let private = |url: &str| {
            postgres_connection(
                &database(Some("private-network-plaintext")),
                Config::from_str(url).unwrap(),
                Some(&witness),
                &resolve,
            )
        };
        let error = private("host=[127.0.0.1] port=5433 user=app dbname=registry").unwrap_err();
        assert_eq!(error.code(), "platform.database.bracketed-host");
        assert!(error.to_string().contains("[127.0.0.1]"), "{error}");
        let (_, pinned) =
            private("host=[10.0.0.4],127.0.0.1 port=5433,5432 user=app dbname=registry").unwrap();
        assert_eq!(pinned.get_hosts(), &[] as &[Host]);
        assert_eq!(pinned.get_hostaddrs(), &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert_eq!(pinned.get_ports(), &[5432]);
        // The driver dials the authored hostaddr, never the host beside it.
        let (_, pinned) =
            private("host=[127.0.0.1] hostaddr=10.0.0.2 port=5433 user=app dbname=registry")
                .unwrap();
        assert_eq!(
            pinned.get_hostaddrs(),
            &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]
        );
        // Loopback plaintext already refuses the bracketed IPv4 spelling.
        let error = postgres_connection(
            &database(Some("loopback-plaintext")),
            Config::from_str("host=[127.0.0.1] port=5433 user=app dbname=registry").unwrap(),
            None,
            &resolve,
        )
        .unwrap_err();
        assert_eq!(error.code(), "platform.database.transport-host-mismatch");
    }

    #[test]
    fn a_bracketed_url_authority_and_a_bracketed_host_beside_a_hostaddr_still_connect() {
        // The URL parser strips the brackets of an IPv6 authority.
        let (_, pinned) = loopback("postgresql://app@[::1]:5433/registry");
        assert_eq!(pinned.get_hosts(), &[] as &[Host]);
        assert_eq!(pinned.get_hostaddrs(), &[IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        assert_eq!(pinned.get_ports(), &[5433]);
        // The driver dials the authored hostaddr, never the host beside it.
        let (_, pinned) =
            loopback("host=[::1] hostaddr=127.0.0.3 port=5433 user=app dbname=registry");
        assert_eq!(pinned.get_hosts(), &[] as &[Host]);
        assert_eq!(
            pinned.get_hostaddrs(),
            &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))]
        );
    }

    #[test]
    fn the_loopback_helper_pins_a_loopback_name_and_refuses_any_other_host() {
        let pinned = super::loopback_postgres_connection(
            Config::from_str("postgresql://app@localhost:5433/registry").unwrap(),
            &resolve,
        )
        .unwrap();
        assert_eq!(pinned.get_hosts(), &[] as &[Host]);
        assert_eq!(
            pinned.get_hostaddrs(),
            &[
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ]
        );
        for url in [
            "postgresql://app@10.0.0.5/registry",
            "host=localhost hostaddr=10.0.0.5 user=app dbname=registry",
        ] {
            assert_eq!(
                super::loopback_postgres_connection(Config::from_str(url).unwrap(), &resolve),
                Err(DatabaseTransportError::HostMismatch(
                    DatabaseTransport::LoopbackPlaintext
                )),
                "{url}"
            );
        }
    }

    #[test]
    fn a_layout_the_driver_refuses_is_left_for_the_driver_to_refuse() {
        // Two hosts and one hostaddr: the driver refuses this before it dials
        // anything, so the configuration is handed on as written.
        let url = "host=localhost,127.0.0.1 hostaddr=127.0.0.1 user=app dbname=registry";
        let (_, pinned) = loopback(url);
        assert_eq!(pinned, Config::from_str(url).unwrap());
    }

    #[test]
    fn verified_tls_keeps_the_name_and_resolves_nothing() {
        let never = |name: &str| -> std::io::Result<Vec<IpAddr>> {
            panic!("verified-tls looked up {name}");
        };
        let url = "postgresql://app@db.example.com:5433/registry?sslmode=require";
        let (transport, config) = postgres_connection(
            &database(None),
            Config::from_str(url).unwrap(),
            None,
            &never,
        )
        .unwrap();
        assert_eq!(transport, DatabaseTransport::VerifiedTls);
        assert_eq!(config, Config::from_str(url).unwrap());
    }
}
