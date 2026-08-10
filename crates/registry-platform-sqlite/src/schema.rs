use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::statement::{confirm_connection_still_bound, database_uri};
use crate::{DatabaseProfile, ErrorKind, SqliteError};

const ENGINE_LIMIT: i32 = 8 * 1_024 * 1_024;
const STEP_INTERVAL: u64 = 1_000;
const MAXIMUM_SCHEMA_OBJECTS: usize = 16_384;
const MAXIMUM_SCHEMA_COLUMNS: usize = 65_536;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InspectionLimits {
    pub maximum_objects: usize,
    pub maximum_sql_bytes: usize,
    pub maximum_statement_steps: u64,
    pub timeout: Duration,
}

impl InspectionLimits {
    pub(crate) fn validate(&self) -> Result<(), SqliteError> {
        if self.maximum_objects == 0
            || self.maximum_sql_bytes == 0
            || self.maximum_statement_steps == 0
            || self.timeout.is_zero()
            || Instant::now().checked_add(self.timeout).is_none()
            || self.maximum_objects > MAXIMUM_SCHEMA_OBJECTS
            || self.maximum_sql_bytes > usize::try_from(ENGINE_LIMIT).unwrap_or(usize::MAX)
        {
            return Err(SqliteError::new(ErrorKind::InvalidPlan));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SchemaObjectKind {
    Table,
    Index,
    View,
    Trigger,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaObject {
    pub kind: SchemaObjectKind,
    pub name: String,
    pub table_name: String,
    pub sql: Option<String>,
    /// Columns in SQLite `cid` order. Indexes and triggers have no columns.
    pub columns: Vec<SchemaColumn>,
}

/// Schema-only column metadata. No stored value is sampled to construct it.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaColumn {
    pub name: String,
    pub declared_type: String,
    pub nullable: bool,
    pub primary_key: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaCatalog {
    pub fingerprint: String,
    pub objects: Vec<SchemaObject>,
}

/// Inspect only `main.sqlite_schema`. No table or view row is sampled.
pub fn inspect_schema(
    profile: &DatabaseProfile,
    limits: &InspectionLimits,
) -> Result<SchemaCatalog, SqliteError> {
    limits.validate()?;
    profile_confirm(profile)?;
    let connection = open_for_schema(profile)?;
    // Establish one read snapshot. The only SQL below is fixed schema-catalog
    // inspection; no caller SQL or raw connection crosses this boundary.
    connection
        .execute_batch("BEGIN")
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    let outcome = collect_schema(&connection, limits);
    profile_confirm(profile)?;
    confirm_connection_still_bound(&connection)?;
    drop(connection);
    let objects = outcome?;
    let fingerprint = fingerprint_objects(&objects);
    Ok(SchemaCatalog {
        fingerprint,
        objects,
    })
}

pub fn schema_fingerprint(
    profile: &DatabaseProfile,
    limits: &InspectionLimits,
) -> Result<String, SqliteError> {
    inspect_schema(profile, limits).map(|catalog| catalog.fingerprint)
}

fn profile_confirm(profile: &DatabaseProfile) -> Result<(), SqliteError> {
    match profile {
        DatabaseProfile::Snapshot(value) => value.confirm_still_bound(),
        DatabaseProfile::LiveReadOnly(value) => value.confirm_still_bound(),
    }
}

fn profile_path(profile: &DatabaseProfile) -> &Path {
    match profile {
        DatabaseProfile::Snapshot(value) => value.path(),
        DatabaseProfile::LiveReadOnly(value) => value.path(),
    }
}

fn open_for_schema(profile: &DatabaseProfile) -> Result<Connection, SqliteError> {
    let immutable = matches!(profile, DatabaseProfile::Snapshot(_));
    let uri = database_uri(profile_path(profile), immutable)
        .ok_or_else(|| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(uri, flags)
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_LENGTH, ENGINE_LIMIT)
        .map_err(|_| SqliteError::new(ErrorKind::DatabaseUnavailable))?;
    confirm_connection_still_bound(&connection)?;
    Ok(connection)
}

fn collect_schema(
    connection: &Connection,
    limits: &InspectionLimits,
) -> Result<Vec<SchemaObject>, SqliteError> {
    const WITHIN: u8 = 0;
    const STEPS: u8 = 1;
    const TIME: u8 = 2;
    let outcome = Arc::new(AtomicU8::new(WITHIN));
    let observed = Arc::clone(&outcome);
    let interval = limits.maximum_statement_steps.clamp(1, STEP_INTERVAL);
    let budget = limits.maximum_statement_steps;
    let deadline = Instant::now()
        .checked_add(limits.timeout)
        .ok_or_else(|| SqliteError::new(ErrorKind::InvalidPlan))?;
    let mut consumed = 0_u64;
    connection
        .progress_handler(
            i32::try_from(interval).unwrap_or(i32::MAX),
            Some(move || {
                consumed = consumed.saturating_add(interval);
                if consumed >= budget {
                    observed.store(STEPS, Ordering::Relaxed);
                    true
                } else if Instant::now() >= deadline {
                    observed.store(TIME, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }),
        )
        .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?;

    collect_schema_with_installed_budget(connection, limits).map_err(|error| {
        if error.kind() == ErrorKind::SchemaMalformed
            && matches!(outcome.load(Ordering::Relaxed), STEPS | TIME)
        {
            SqliteError::new(ErrorKind::SchemaBudgetExceeded)
        } else {
            error
        }
    })
}

/// Read the schema while a caller-owned progress handler and transaction are
/// already active. Statement execution uses this so live fingerprint checking
/// and the data query share one time/step budget and one read snapshot.
pub(crate) fn collect_schema_with_installed_budget(
    connection: &Connection,
    limits: &InspectionLimits,
) -> Result<Vec<SchemaObject>, SqliteError> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM main.sqlite_schema \
         WHERE type IN ('table','index','view','trigger') \
         ORDER BY type, name, tbl_name, coalesce(sql, '')",
        )
        .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?;
    let mut rows = statement.raw_query();
    let mut objects = Vec::new();
    let mut column_count = 0_usize;
    let mut sql_bytes = 0_usize;
    loop {
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(_) => return Err(SqliteError::new(ErrorKind::SchemaMalformed)),
        };
        if objects.len() >= limits.maximum_objects {
            return Err(SqliteError::new(ErrorKind::SchemaBudgetExceeded));
        }
        let kind = match read_text(
            row.get_ref(0)
                .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?,
        )?
        .as_str()
        {
            "table" => SchemaObjectKind::Table,
            "index" => SchemaObjectKind::Index,
            "view" => SchemaObjectKind::View,
            "trigger" => SchemaObjectKind::Trigger,
            _ => return Err(SqliteError::new(ErrorKind::SchemaMalformed)),
        };
        let name = read_text(
            row.get_ref(1)
                .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?,
        )?;
        let table_name = read_text(
            row.get_ref(2)
                .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?,
        )?;
        let sql = match row
            .get_ref(3)
            .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?
        {
            ValueRef::Null => None,
            value => Some(read_text(value)?),
        };
        sql_bytes = sql_bytes
            .saturating_add(name.len())
            .saturating_add(table_name.len())
            .saturating_add(sql.as_ref().map_or(0, String::len));
        if sql_bytes > limits.maximum_sql_bytes {
            return Err(SqliteError::new(ErrorKind::SchemaBudgetExceeded));
        }
        let columns = if matches!(kind, SchemaObjectKind::Table | SchemaObjectKind::View) {
            read_columns(connection, &name, limits, &mut sql_bytes, &mut column_count)?
        } else {
            Vec::new()
        };
        objects.push(SchemaObject {
            kind,
            name,
            table_name,
            sql,
            columns,
        });
    }
    Ok(objects)
}

fn read_columns(
    connection: &Connection,
    object_name: &str,
    limits: &InspectionLimits,
    catalog_bytes: &mut usize,
    catalog_columns: &mut usize,
) -> Result<Vec<SchemaColumn>, SqliteError> {
    // The table-valued PRAGMA accepts the object name as a bound value. The
    // fixed query cannot sample rows from that object and never interpolates an
    // identifier supplied by the database schema.
    let mut statement = connection
        .prepare(
            "SELECT name, type, \"notnull\", pk FROM pragma_table_xinfo(?1, 'main') \
             ORDER BY cid",
        )
        .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?;
    let mut rows = statement
        .query([object_name])
        .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?;
    let mut columns = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?
    {
        // SQLite bounds columns per table. The platform adds one global catalog
        // ceiling so many wide tables cannot multiply into an unbounded result.
        if *catalog_columns >= MAXIMUM_SCHEMA_COLUMNS {
            return Err(SqliteError::new(ErrorKind::SchemaBudgetExceeded));
        }
        let name = read_text(
            row.get_ref(0)
                .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?,
        )?;
        let declared_type = read_text(
            row.get_ref(1)
                .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?,
        )?;
        let not_null = read_flag(
            row.get_ref(2)
                .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?,
        )?;
        let primary_key = read_nonnegative_integer(
            row.get_ref(3)
                .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))?,
        )? > 0;
        *catalog_bytes = catalog_bytes
            .saturating_add(name.len())
            .saturating_add(declared_type.len());
        if *catalog_bytes > limits.maximum_sql_bytes {
            return Err(SqliteError::new(ErrorKind::SchemaBudgetExceeded));
        }
        columns.push(SchemaColumn {
            name,
            declared_type,
            nullable: !not_null,
            primary_key,
        });
        *catalog_columns += 1;
    }
    Ok(columns)
}

fn read_text(value: ValueRef<'_>) -> Result<String, SqliteError> {
    let ValueRef::Text(bytes) = value else {
        return Err(SqliteError::new(ErrorKind::SchemaMalformed));
    };
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| SqliteError::new(ErrorKind::SchemaMalformed))
}

fn read_flag(value: ValueRef<'_>) -> Result<bool, SqliteError> {
    match value {
        ValueRef::Integer(0) => Ok(false),
        ValueRef::Integer(1) => Ok(true),
        _ => Err(SqliteError::new(ErrorKind::SchemaMalformed)),
    }
}

fn read_nonnegative_integer(value: ValueRef<'_>) -> Result<i64, SqliteError> {
    match value {
        ValueRef::Integer(value) if value >= 0 => Ok(value),
        _ => Err(SqliteError::new(ErrorKind::SchemaMalformed)),
    }
}

pub(crate) fn fingerprint_objects(objects: &[SchemaObject]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-platform-sqlite-schema-v1\0");
    for object in objects {
        put_field(
            &mut hasher,
            match object.kind {
                SchemaObjectKind::Table => b"table",
                SchemaObjectKind::Index => b"index",
                SchemaObjectKind::View => b"view",
                SchemaObjectKind::Trigger => b"trigger",
            },
        );
        put_field(&mut hasher, object.name.as_bytes());
        put_field(&mut hasher, object.table_name.as_bytes());
        match &object.sql {
            Some(sql) => {
                hasher.update([1]);
                put_field(&mut hasher, sql.as_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.update(
            u64::try_from(object.columns.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for column in &object.columns {
            put_field(&mut hasher, column.name.as_bytes());
            put_field(&mut hasher, column.declared_type.as_bytes());
            hasher.update([u8::from(column.nullable), u8::from(column.primary_key)]);
        }
    }
    let digest = hasher.finalize();
    let mut label = String::with_capacity(71);
    label.push_str("sha256:");
    for byte in digest.as_slice() {
        use std::fmt::Write as _;
        write!(&mut label, "{byte:02x}").expect("writing to a string cannot fail");
    }
    label
}

fn put_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}
