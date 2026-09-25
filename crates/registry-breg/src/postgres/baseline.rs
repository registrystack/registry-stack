// SPDX-License-Identifier: Apache-2.0

//! Value-free advisories about the PostgreSQL server a Registry runs on.
//!
//! The inspection is one read of settings and catalog rows every role may
//! read, so it needs no grant beyond the runtime role's own. It never refuses
//! startup: a setting it cannot read becomes an advisory saying so. Each
//! advisory carries a stable code, a fixed sentence, and the observed numbers
//! it was decided from; none carries a connection, role, or data value.

use tokio_postgres::{Client, Row};

/// One read of every input the advisories are decided from. The settings are
/// read with `missing_ok`, so a server without one reports it as absent
/// instead of failing the whole read. `CREATE EXTENSION pg_stat_statements`
/// succeeds whether or not the module is in `shared_preload_libraries`, but
/// its `_PG_init` defines the extension's custom settings only when it runs
/// from there, so a `pg_settings` row for `pg_stat_statements.max` tells the
/// two cases apart without the superuser-only `shared_preload_libraries`
/// setting itself. `current_setting` cannot: a configured value for a module
/// that never loaded is kept as a placeholder it still returns, while
/// `pg_settings` lists only defined settings.
const BASELINE_QUERY: &str = "SELECT
    pg_catalog.current_setting('max_connections', true),
    pg_catalog.current_setting('superuser_reserved_connections', true),
    pg_catalog.current_setting('reserved_connections', true),
    pg_catalog.current_setting('autovacuum', true),
    pg_catalog.current_setting('track_counts', true),
    EXISTS (
        SELECT FROM pg_catalog.pg_extension WHERE extname = 'pg_stat_statements'
    ),
    EXISTS (
        SELECT FROM pg_catalog.pg_settings WHERE name = 'pg_stat_statements.max'
    )";

/// Whether an advisory names something an operator should change or only
/// something worth knowing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdvisorySeverity {
    Warning,
    Information,
}

impl AdvisorySeverity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Information => "information",
        }
    }
}

/// One advisory about the PostgreSQL server, decided at startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaselineAdvisory {
    code: &'static str,
    severity: AdvisorySeverity,
    message: &'static str,
    observed: Vec<(&'static str, i64)>,
}

impl BaselineAdvisory {
    const fn new(code: &'static str, severity: AdvisorySeverity, message: &'static str) -> Self {
        Self {
            code,
            severity,
            message,
            observed: Vec::new(),
        }
    }

    fn observing(mut self, observed: Vec<(&'static str, i64)>) -> Self {
        self.observed = observed;
        self
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn severity(&self) -> AdvisorySeverity {
        self.severity
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// The numbers the advisory was decided from, as camel-case name and value
    /// pairs in a fixed order.
    #[must_use]
    pub fn observed(&self) -> &[(&'static str, i64)] {
        &self.observed
    }
}

/// The raw settings one inspection read. `None` means the value could not be
/// read, which the advisories report instead of guessing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BaselineSettings {
    pub max_connections: Option<String>,
    pub superuser_reserved_connections: Option<String>,
    pub reserved_connections: Option<String>,
    pub autovacuum: Option<String>,
    pub track_counts: Option<String>,
    pub pg_stat_statements_installed: Option<bool>,
    pub pg_stat_statements_loaded: Option<bool>,
}

/// Inspect the server behind `client` and advise on it for a runtime pool of
/// `pool_max_size` connections. A failed read is reported as one advisory,
/// never as an error.
pub async fn inspect_baseline(client: &Client, pool_max_size: usize) -> Vec<BaselineAdvisory> {
    match client.query_one(BASELINE_QUERY, &[]).await {
        Ok(row) => advise(&settings_from_row(&row), pool_max_size),
        Err(_) => vec![BaselineAdvisory::new(
            "postgres.baseline.not_inspected",
            AdvisorySeverity::Information,
            "could not inspect the PostgreSQL server settings, so no baseline advisory was checked",
        )],
    }
}

fn settings_from_row(row: &Row) -> BaselineSettings {
    let text = |index: usize| row.try_get::<_, Option<String>>(index).ok().flatten();
    BaselineSettings {
        max_connections: text(0),
        superuser_reserved_connections: text(1),
        reserved_connections: text(2),
        autovacuum: text(3),
        track_counts: text(4),
        pg_stat_statements_installed: row.try_get::<_, Option<bool>>(5).ok().flatten(),
        pg_stat_statements_loaded: row.try_get::<_, Option<bool>>(6).ok().flatten(),
    }
}

/// Decide the advisories for `settings` and a runtime pool of `pool_max_size`
/// connections, in a fixed order: connections, vacuum, then statements.
#[must_use]
pub fn advise(settings: &BaselineSettings, pool_max_size: usize) -> Vec<BaselineAdvisory> {
    let mut advisories = vec![connection_budget(settings, pool_max_size)];
    advisories.extend(switch(
        settings.autovacuum.as_deref(),
        BaselineAdvisory::new(
            "postgres.autovacuum.off",
            AdvisorySeverity::Warning,
            "autovacuum is off, so dead rows left by updates and deletes accumulate and planner statistics go stale until an operator vacuums",
        ),
        BaselineAdvisory::new(
            "postgres.autovacuum.not_inspected",
            AdvisorySeverity::Information,
            "could not inspect whether autovacuum is on",
        ),
    ));
    advisories.extend(switch(
        settings.track_counts.as_deref(),
        BaselineAdvisory::new(
            "postgres.track_counts.off",
            AdvisorySeverity::Warning,
            "track_counts is off, so autovacuum cannot tell which tables need vacuuming or analyzing",
        ),
        BaselineAdvisory::new(
            "postgres.track_counts.not_inspected",
            AdvisorySeverity::Information,
            "could not inspect whether track_counts is on",
        ),
    ));
    // `CREATE EXTENSION pg_stat_statements` succeeds without
    // `shared_preload_libraries`, but its view then refuses every query, so
    // installed and loaded are inspected and advised on separately.
    match (
        settings.pg_stat_statements_installed,
        settings.pg_stat_statements_loaded,
    ) {
        (Some(true), Some(true)) => {}
        (Some(false), Some(_)) => advisories.push(BaselineAdvisory::new(
            "postgres.pg_stat_statements.unavailable",
            AdvisorySeverity::Information,
            "pg_stat_statements is not installed in this database, so per-statement timings are unavailable when diagnosing load",
        )),
        (Some(true), Some(false)) => advisories.push(BaselineAdvisory::new(
            "postgres.pg_stat_statements.unavailable",
            AdvisorySeverity::Information,
            "pg_stat_statements is installed but not loaded through shared_preload_libraries, so per-statement timings are unavailable when diagnosing load",
        )),
        (_, _) => advisories.push(BaselineAdvisory::new(
            "postgres.pg_stat_statements.not_inspected",
            AdvisorySeverity::Information,
            "could not inspect whether pg_stat_statements is installed in this database",
        )),
    }
    advisories
}

/// Compare one replica's runtime pool with the connections PostgreSQL leaves
/// for roles that are not superusers. The numbers are always reported; the
/// advisory warns when the pool alone may take more than half of them, leaving
/// too little for other replicas, operator tooling, and maintenance.
fn connection_budget(settings: &BaselineSettings, pool_max_size: usize) -> BaselineAdvisory {
    let pool = i64::try_from(pool_max_size).unwrap_or(i64::MAX);
    let number = |value: &Option<String>| value.as_deref().and_then(|v| v.parse::<i64>().ok());
    let (Some(max), Some(superuser_reserved), Some(reserved)) = (
        number(&settings.max_connections),
        number(&settings.superuser_reserved_connections),
        number(&settings.reserved_connections),
    ) else {
        return BaselineAdvisory::new(
            "postgres.connections.not_inspected",
            AdvisorySeverity::Information,
            "could not inspect how many connections the PostgreSQL server allows",
        )
        .observing(vec![("poolMaxSize", pool)]);
    };
    let usable = max
        .saturating_sub(superuser_reserved)
        .saturating_sub(reserved);
    let observed = vec![
        ("poolMaxSize", pool),
        ("maxConnections", max),
        ("superuserReservedConnections", superuser_reserved),
        ("reservedConnections", reserved),
        ("usableConnections", usable),
    ];
    if pool.saturating_mul(2) > usable {
        BaselineAdvisory::new(
            "postgres.connections.pool_over_half",
            AdvisorySeverity::Warning,
            "one replica's runtime pool may take more than half of the connections PostgreSQL leaves for ordinary roles, leaving too few for other replicas, operator tooling, and maintenance",
        )
        .observing(observed)
    } else {
        BaselineAdvisory::new(
            "postgres.connections.budget",
            AdvisorySeverity::Information,
            "one replica's runtime pool takes at most half of the connections PostgreSQL leaves for ordinary roles",
        )
        .observing(observed)
    }
}

/// Advise on a boolean setting: nothing when it is on, `off` when it is off,
/// and `not_inspected` when it could not be read as either.
fn switch(
    value: Option<&str>,
    off: BaselineAdvisory,
    not_inspected: BaselineAdvisory,
) -> Option<BaselineAdvisory> {
    match value {
        Some("on") => None,
        Some("off") => Some(off),
        _ => Some(not_inspected),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> BaselineSettings {
        BaselineSettings {
            max_connections: Some("100".to_owned()),
            superuser_reserved_connections: Some("3".to_owned()),
            reserved_connections: Some("0".to_owned()),
            autovacuum: Some("on".to_owned()),
            track_counts: Some("on".to_owned()),
            pg_stat_statements_installed: Some(true),
            pg_stat_statements_loaded: Some(true),
        }
    }

    fn codes(advisories: &[BaselineAdvisory]) -> Vec<&'static str> {
        advisories.iter().map(BaselineAdvisory::code).collect()
    }

    #[test]
    fn a_healthy_server_reports_only_the_connection_numbers() {
        let advisories = advise(&healthy(), 16);
        assert_eq!(codes(&advisories), ["postgres.connections.budget"]);
        assert_eq!(advisories[0].severity(), AdvisorySeverity::Information);
        assert_eq!(
            advisories[0].observed(),
            [
                ("poolMaxSize", 16),
                ("maxConnections", 100),
                ("superuserReservedConnections", 3),
                ("reservedConnections", 0),
                ("usableConnections", 97),
            ]
        );
    }

    #[test]
    fn a_pool_over_half_of_usable_connections_warns_and_half_does_not() {
        let mut settings = healthy();
        settings.reserved_connections = Some("2".to_owned());
        // 100 - 3 - 2 leaves 95 usable connections: 47 fits, 48 does not.
        let fits = advise(&settings, 47);
        assert_eq!(fits[0].code(), "postgres.connections.budget");
        let over = advise(&settings, 48);
        assert_eq!(over[0].code(), "postgres.connections.pool_over_half");
        assert_eq!(over[0].severity(), AdvisorySeverity::Warning);
        assert_eq!(over[0].observed()[4], ("usableConnections", 95));
    }

    #[test]
    fn vacuum_settings_that_are_off_warn() {
        let mut settings = healthy();
        settings.autovacuum = Some("off".to_owned());
        settings.track_counts = Some("off".to_owned());
        let advisories = advise(&settings, 4);
        assert_eq!(
            codes(&advisories),
            [
                "postgres.connections.budget",
                "postgres.autovacuum.off",
                "postgres.track_counts.off",
            ]
        );
        assert!(advisories[1..]
            .iter()
            .all(|advisory| advisory.severity() == AdvisorySeverity::Warning));
    }

    #[test]
    fn an_installed_and_loaded_pg_stat_statements_reports_no_advisory() {
        let advisories = advise(&healthy(), 4);
        assert_eq!(codes(&advisories), ["postgres.connections.budget"]);
    }

    #[test]
    fn a_not_installed_pg_stat_statements_is_information_only() {
        let mut settings = healthy();
        settings.pg_stat_statements_installed = Some(false);
        settings.pg_stat_statements_loaded = Some(false);
        let advisories = advise(&settings, 4);
        assert_eq!(
            advisories[1].code(),
            "postgres.pg_stat_statements.unavailable"
        );
        assert_eq!(advisories[1].severity(), AdvisorySeverity::Information);
        assert!(advisories[1].message().contains("not installed"));
    }

    #[test]
    fn an_installed_but_not_loaded_pg_stat_statements_is_information_only() {
        let mut settings = healthy();
        settings.pg_stat_statements_loaded = Some(false);
        let advisories = advise(&settings, 4);
        assert_eq!(
            advisories[1].code(),
            "postgres.pg_stat_statements.unavailable"
        );
        assert_eq!(advisories[1].severity(), AdvisorySeverity::Information);
        assert!(advisories[1].message().contains("shared_preload_libraries"));
    }

    #[test]
    fn settings_that_could_not_be_read_are_reported_not_guessed() {
        let advisories = advise(&BaselineSettings::default(), 4);
        assert_eq!(
            codes(&advisories),
            [
                "postgres.connections.not_inspected",
                "postgres.autovacuum.not_inspected",
                "postgres.track_counts.not_inspected",
                "postgres.pg_stat_statements.not_inspected",
            ]
        );
        assert_eq!(advisories[0].observed(), [("poolMaxSize", 4)]);
        let mut unparsable = healthy();
        unparsable.max_connections = Some("many".to_owned());
        assert_eq!(
            advise(&unparsable, 4)[0].code(),
            "postgres.connections.not_inspected"
        );
    }

    #[test]
    fn pg_stat_statements_is_not_inspected_when_either_value_is_unreadable() {
        let mut installed_unknown = healthy();
        installed_unknown.pg_stat_statements_installed = None;
        assert_eq!(
            advise(&installed_unknown, 4)[1].code(),
            "postgres.pg_stat_statements.not_inspected"
        );

        let mut loaded_unknown = healthy();
        loaded_unknown.pg_stat_statements_loaded = None;
        assert_eq!(
            advise(&loaded_unknown, 4)[1].code(),
            "postgres.pg_stat_statements.not_inspected"
        );
    }
}
