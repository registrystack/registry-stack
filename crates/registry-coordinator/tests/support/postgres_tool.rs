// SPDX-License-Identifier: Apache-2.0
//! Runs a PostgreSQL client tool against a disposable database URL without
//! placing the URL or its password on the command line.

pub fn command(program: &str, url: &str) -> std::process::Command {
    let config: tokio_postgres::Config = url.parse().expect("disposable PostgreSQL URL");
    let mut command = std::process::Command::new(program);
    let host = match config.get_hosts().first().expect("explicit local host") {
        tokio_postgres::config::Host::Tcp(host) => std::ffi::OsString::from(host),
        #[cfg(unix)]
        tokio_postgres::config::Host::Unix(path) => path.as_os_str().to_owned(),
    };
    command
        .env("PGHOST", host)
        .env(
            "PGPORT",
            config
                .get_ports()
                .first()
                .copied()
                .unwrap_or(5432)
                .to_string(),
        )
        .env(
            "PGDATABASE",
            config.get_dbname().expect("explicit disposable database"),
        )
        .env("PGUSER", config.get_user().expect("explicit test role"))
        .env("PGCONNECT_TIMEOUT", "5");
    if let Some(password) = config.get_password() {
        command.env(
            "PGPASSWORD",
            std::str::from_utf8(password).expect("UTF-8 test password"),
        );
    }
    command
}
