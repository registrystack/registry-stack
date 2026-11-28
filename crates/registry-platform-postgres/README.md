# Registry Platform Postgres

`registry-platform-postgres` builds the `tokio_postgres::Config` a runtime's pool hands to the driver, from the host check in `registry-platform-config`. It keeps the PostgreSQL client out of the configuration crate, so a crate that reads configuration does not link `tokio-postgres`.

- `postgres_connection` checks every host and `hostaddr` of a parsed connection string under the runtime's `database.transport`. Under a plaintext transport it returns a configuration that dials only the numeric addresses each host was checked as, so the driver never resolves a name again. Under `verified-tls` the configuration is returned unchanged.
- `loopback_postgres_connection` does the same under `loopback-plaintext`, for a constructor that holds no runtime database block.
- Both take the host resolver as an argument. A runtime passes `registry_platform_config::resolve_database_host`; tests pass a fixed answer.
- A keyword host written as an IP address in brackets, such as `host=[::1]`, is dropped from the list, as the driver itself fails that entry. When no other host is left, the connection is refused with `platform.database.bracketed-host`.
