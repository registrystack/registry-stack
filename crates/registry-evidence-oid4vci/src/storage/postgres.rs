//! The PostgreSQL backend: the same state as the memory backend, shared by
//! every replica that opens the same schema with the same keys.
//!
//! It keeps the three properties [`crate::store`] states for the memory
//! backend, and the ones a shared database adds.
//!
//! 1. **Nothing is keyed by the secret it stands for.** Offers, transaction
//!    code ledgers and access tokens are keyed by the same HMAC tags the memory
//!    backend uses, under tagging keys the caller supplies. The database never
//!    sees a pre-authorized code, a transaction code or an access token.
//! 2. **Saturation fails closed, deployment-wide.** Capacity is a count of the
//!    live rows every replica wrote, taken in the same transaction as the
//!    insert and under a transaction advisory lock, so two replicas cannot
//!    both take the last place. A full store refuses; nothing is evicted.
//!    Every transaction runs at READ COMMITTED whatever the server, role or
//!    database default, so the count sees what the previous lock holder
//!    committed.
//! 3. **A transaction code lockout outlives the request it refused, across
//!    replicas.** Attempts are counted by a conditional
//!    `UPDATE ... WHERE state = 'open' ... RETURNING`, so concurrent attempts
//!    from any replica increment one counter and the attempt that reaches the
//!    ceiling is the one that locks the offer.
//!
//! And the ones a database adds:
//!
//! - **Single use is a conditional update.** Redemption moves the ledger from
//!   `open` to `redeemed` with a conditional `UPDATE ... RETURNING`; exactly
//!   one transaction sees its row come back. A claim deletes the token row and
//!   reads it back in one statement.
//! - **Prepared requests are sealed at rest.** A prepared request is stored only
//!   as `XChaCha20Poly1305` ciphertext under a versioned sealing key the caller
//!   supplies, with a fresh random nonce, and associated data binding it to the
//!   row's tag, both key versions and the catalog generation. A ciphertext
//!   moved onto another row does not open. The row is deleted when the request
//!   is handed back and by the purge once it expires.
//! - **Expired rows are never served.** Every read filters on expiry; the purge
//!   deletes what has expired.
//! - **Every exchange is bound to its catalog generation.** A redemption or
//!   claim under another generation is refused as unknown and spends nothing.
//! - **No replica waits on another past its request timeout.** Every
//!   transaction limits its lock waits to a quarter of the service's request
//!   timeout and each statement, and each pause between statements, to half
//!   of it. A replica that hangs while holding a lock is cut off by the
//!   server, and the requests waiting on it refuse in time, spending nothing.
//!
//! Database failures refuse with [`StoreError::Unavailable`] and are logged by
//! operation and SQLSTATE only, never with a value. A connection the pool
//! cannot give is logged by its cause (a timeout, a closed pool or a failed
//! connection) and the server's SQLSTATE, never with the server's message.
//!
//! The caller builds the pool, so the connection's TLS and credentials are the
//! caller's decision. [`PostgresStore::migrate`] creates the schema and applies
//! the embedded migrations once, serialized on a transaction advisory lock.
//! Migration runs before the service answers requests, so it does not take
//! the request-derived bounds: a replica waits for another's migration to
//! finish.
//!
//! # Known limits
//!
//! These hold today and are left to the deployment or to later work.
//!
//! - **Length.** A sealed prepared request is not padded, so its ciphertext
//!   length follows the request body's length and can hint at the kind of
//!   identifier the request selects by.
//! - **Erasure.** A deleted row survives in the write-ahead log, base backups,
//!   replicas and dead tuples until vacuum, and stays openable while its
//!   sealing key is current or previous, so erasing a prepared request means
//!   retiring its sealing key through two rotations and destroying it, with
//!   backup retention sized to match.
//! - **Restore and failover.** Restoring a backup, failing over to a lagging
//!   asynchronous replica, or running with `synchronous_commit = off` can bring
//!   back offers and access tokens already spent for the rest of their
//!   lifetime, so after a restore or failover the deployment must change the
//!   catalog generation or rotate the tagging key with no previous key, unless
//!   replication is synchronous.
//! - **Clocks.** Expiry is judged against each replica's own clock, so replica
//!   clocks must be kept in step: a slow clock serves entries past their expiry
//!   by its skew, and a fast one's purge deletes entries the others still
//!   treat as live.
//! - **Work on the request path.** Offer creation and token redemption count
//!   the live key-space under a deployment-wide lock, so near the largest
//!   capacity every replica queues behind those counts. A credential request
//!   starts a background key-space count after its claim and does not wait for
//!   it; expired rows are swept by the periodic cleanup.
//! - **Linkable rows.** A database reader can link an offer to the access token
//!   it was redeemed for, because the ledger update and the token insert
//!   commit in one transaction and expire together, though neither row carries
//!   an identifier.
//! - **Per-statement bounds.** The waits are bounded per statement, not per
//!   transaction, so a transaction of several slow statements can outlast the
//!   request, which then times out and is answered as spent once it has asked
//!   to spend.
//! - **A lost commit reply.** A commit that lands but whose reply is lost to a
//!   broken connection is answered as unavailable (503), so the wallet's retry
//!   meets a spent offer or token and is refused.
//! - **Not yet selectable.** The current `oid4vci-profile` contract and this
//!   crate's `AGENTS.md` still forbid a database and more than one replica, so
//!   selecting this backend needs the reviewed v2 profile and those rules to
//!   change with it.

use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::{HookError, Object, Pool, PoolError, TimeoutType, Transaction};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio_postgres::IsolationLevel;
use zeroize::Zeroizing;

use super::sealing::{self, Binding, Purpose, SealError, Sealed};
use super::{
    refuse_shared_keys, tag, transaction_code_tag, CatalogGeneration, KeyRing, Store, VersionedKey,
};
use crate::config::StoreConfig;
use crate::store::{PreparedRequest, StoreError, ACCESS_TOKEN_DOMAIN, OFFER_DOMAIN};

/// The schema a deployment uses unless it names another.
pub const DEFAULT_SCHEMA: &str = "evidence_oid4vci";

const MIGRATIONS: [(i64, &str); 1] = [(1, include_str!("migrations/0001_store.sql"))];

/// The first half of every advisory lock this store takes. The second half is
/// a hash of the schema and what is being serialized.
const LOCK_NAMESPACE: i32 = 0x4f49_4434;

const LOG_TARGET: &str = "registry_evidence_oid4vci::storage";

#[derive(Debug, Error)]
pub enum PostgresSetupError {
    #[error(
        "the store schema name must be 1 to 63 lowercase ASCII letters, digits or underscores, \
         must not start with a digit or with pg_, and must not be public or information_schema"
    )]
    SchemaName,
    #[error("the store schema carries migration {0}, which this build does not know")]
    SchemaVersion(i64),
    #[error("the store schema holds a migration table this store did not make")]
    MigrationTable,
    #[error("the tagging and sealing key rings must not share a key")]
    SharedKey,
    #[error("the store database could not be reached")]
    Unreachable,
    #[error("the store database refused the migration (SQLSTATE {0})")]
    Refused(String),
}

/// The offer state of every replica that opens the same schema.
pub struct PostgresStore {
    pool: Pool,
    schema: String,
    capacity: i64,
    offer_lifetime_seconds: i64,
    access_token_lifetime_seconds: i64,
    maximum_transaction_code_attempts: i32,
    waits: String,
    tag_keys: KeyRing,
    sealing_keys: KeyRing,
}

impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresStore")
            .field("schema", &self.schema)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

/// What a redemption decided, and whether the writes it made must stand.
///
/// A refused transaction code has counted an attempt, and that count is the
/// lockout, so it is committed. Every other refusal changed nothing.
struct Refusal {
    error: StoreError,
    keep_writes: bool,
}

impl From<StoreError> for Refusal {
    fn from(error: StoreError) -> Self {
        Self {
            error,
            keep_writes: false,
        }
    }
}

/// The offer and its ledger as one read.
struct OfferRow {
    offer_tag: String,
    state: String,
    offer: Option<HeldOffer>,
}

struct HeldOffer {
    transaction_code_tag: Option<String>,
    catalog_generation: String,
    sealing_key_version: u32,
}

impl PostgresStore {
    /// A store over `schema`, reached through `pool`, bounded like the memory
    /// backend and tagging and sealing under the supplied keys.
    ///
    /// `request_timeout` is the timeout of the service the store answers for.
    /// Every transaction bounds how long it waits for a lock or a statement
    /// to a fraction of it, so a replica that hangs while holding a lock
    /// refuses the others' requests rather than outlasting them.
    ///
    /// The tagging and sealing rings must share no key, under any version:
    /// see [`refuse_shared_keys`].
    ///
    /// Nothing is read or written until [`Self::migrate`] or the first call.
    pub fn new(
        pool: Pool,
        schema: &str,
        bounds: &StoreConfig,
        request_timeout: Duration,
        tag_keys: KeyRing,
        sealing_keys: KeyRing,
    ) -> Result<Self, PostgresSetupError> {
        if !valid_schema_name(schema) {
            return Err(PostgresSetupError::SchemaName);
        }
        if refuse_shared_keys(&[&tag_keys, &sealing_keys]).is_err() {
            return Err(PostgresSetupError::SharedKey);
        }
        Ok(Self {
            pool,
            schema: schema.to_owned(),
            capacity: i64::try_from(bounds.maximum_offers).unwrap_or(i64::MAX),
            offer_lifetime_seconds: i64::try_from(bounds.offer_lifetime_seconds)
                .unwrap_or(i64::MAX),
            access_token_lifetime_seconds: i64::try_from(bounds.access_token_lifetime_seconds)
                .unwrap_or(i64::MAX),
            maximum_transaction_code_attempts: i32::try_from(
                bounds.maximum_transaction_code_attempts,
            )
            .unwrap_or(i32::MAX),
            waits: transaction_waits(request_timeout),
            tag_keys,
            sealing_keys,
        })
    }

    /// Create the schema if it is missing and apply every embedded migration it
    /// has not seen, in one transaction. Replicas that migrate at once wait for
    /// each other on an advisory lock, and each version is applied once.
    pub async fn migrate(&self) -> Result<(), PostgresSetupError> {
        let mut client = self.pool.get().await.map_err(|error| {
            log_unreachable(&error);
            PostgresSetupError::Unreachable
        })?;
        let refused = |error: tokio_postgres::Error| {
            let code = sqlstate(&error);
            tracing::error!(target: LOG_TARGET, sqlstate = code, "the store migration was refused");
            PostgresSetupError::Refused(code.to_owned())
        };
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(refused)?;
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock($1, hashtext($2))",
                &[&LOCK_NAMESPACE, &format!("{}.migrations", self.schema)],
            )
            .await
            .map_err(refused)?;
        transaction
            .batch_execute(&format!(
                "CREATE SCHEMA IF NOT EXISTS {schema}; \
                 SET LOCAL search_path TO {schema}; \
                 CREATE TABLE IF NOT EXISTS oid4vci_schema_migrations (\
                 version bigint PRIMARY KEY CHECK (version > 0), \
                 applied_at timestamptz NOT NULL DEFAULT now());",
                schema = self.schema
            ))
            .await
            .map_err(refused)?;
        let applied = transaction
            .query(
                "SELECT version FROM oid4vci_schema_migrations ORDER BY version",
                &[],
            )
            .await
            .map_err(refused)?
            .iter()
            .map(|row| row.try_get::<_, i64>(0))
            .collect::<Result<Vec<i64>, _>>()
            .map_err(|_| {
                tracing::error!(
                    target: LOG_TARGET,
                    operation = "read the applied migrations",
                    "the store schema holds a migration table this store did not make"
                );
                PostgresSetupError::MigrationTable
            })?;
        if let Some(unknown) = applied
            .iter()
            .find(|version| !MIGRATIONS.iter().any(|(known, _)| known == *version))
        {
            tracing::error!(
                target: LOG_TARGET,
                operation = "check the applied migrations",
                version = *unknown,
                "the store schema carries a migration this build does not know"
            );
            return Err(PostgresSetupError::SchemaVersion(*unknown));
        }
        for (version, migration) in MIGRATIONS {
            if applied.contains(&version) {
                continue;
            }
            transaction
                .batch_execute(migration)
                .await
                .map_err(refused)?;
            transaction
                .execute(
                    "INSERT INTO oid4vci_schema_migrations (version) VALUES ($1)",
                    &[&version],
                )
                .await
                .map_err(refused)?;
        }
        transaction.commit().await.map_err(refused)
    }

    fn table(&self, name: &str) -> String {
        format!("{}.{name}", self.schema)
    }

    async fn client(&self) -> Result<Object, StoreError> {
        self.pool.get().await.map_err(|error| {
            log_unreachable(&error);
            StoreError::Unavailable
        })
    }

    /// Begin a transaction at READ COMMITTED, whatever the server, role or
    /// database default is. A count taken after an advisory lock is granted
    /// must see what the previous holder committed; under REPEATABLE READ or
    /// SERIALIZABLE the snapshot would date from before the lock wait.
    ///
    /// The transaction then bounds its own waits below the request timeout. A
    /// wait that runs out is refused like any other database failure.
    async fn begin<'c>(
        &self,
        client: &'c mut Object,
        operation: &'static str,
    ) -> Result<Transaction<'c>, StoreError> {
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(failed(operation))?;
        transaction
            .batch_execute(&self.waits)
            .await
            .map_err(failed(operation))?;
        Ok(transaction)
    }

    /// Serialize every writer of one key-space across replicas until the
    /// transaction ends.
    async fn lock_keyspace(
        &self,
        transaction: &Transaction<'_>,
        keyspace: &str,
    ) -> Result<(), StoreError> {
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock($1, hashtext($2))",
                &[&LOCK_NAMESPACE, &self.table(keyspace)],
            )
            .await
            .map_err(failed("lock a key-space"))?;
        Ok(())
    }

    /// The tag `secret` would carry under every accepted key, current first.
    fn candidate_tags<'k>(
        &'k self,
        domain: &str,
        secret: &str,
    ) -> Vec<(&'k VersionedKey, Zeroizing<String>)> {
        self.tag_keys
            .accepted()
            .map(|key| (key, tag(key, domain, secret)))
            .collect()
    }

    /// The live offer under the first of `tags` that holds one. The tags come
    /// current key first, so if a code was drawn twice during a rotation, the
    /// ledger under the current key is the one read.
    async fn read_offer(
        &self,
        transaction: &Transaction<'_>,
        tags: &[&str],
        now: i64,
    ) -> Result<Option<OfferRow>, StoreError> {
        let row = transaction
            .query_opt(
                &format!(
                    "SELECT l.offer_tag, l.state, o.offer_tag IS NOT NULL, \
                            o.transaction_code_tag, o.catalog_generation, o.sealing_key_version \
                     FROM {ledgers} l \
                     LEFT JOIN {offers} o ON o.offer_tag = l.offer_tag AND o.expires_at > $2 \
                     WHERE l.offer_tag = ANY($1) AND l.expires_at > $2 \
                     ORDER BY array_position($1, l.offer_tag) \
                     LIMIT 1",
                    ledgers = self.table("offer_ledgers"),
                    offers = self.table("offers"),
                ),
                &[&tags, &now],
            )
            .await
            .map_err(failed("read an offer"))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let held: bool = row.get(2);
        let offer = if held {
            Some(HeldOffer {
                transaction_code_tag: row.get(3),
                catalog_generation: row.get(4),
                sealing_key_version: key_version(row.get(5))?,
            })
        } else {
            None
        };
        Ok(Some(OfferRow {
            offer_tag: row.get(0),
            state: row.get(1),
            offer,
        }))
    }

    /// Why an offer whose ledger did not move cannot be redeemed now.
    async fn ledger_refusal(
        &self,
        transaction: &Transaction<'_>,
        offer_tag: &str,
        now: i64,
    ) -> Result<StoreError, StoreError> {
        let state: Option<String> = transaction
            .query_opt(
                &format!(
                    "SELECT state FROM {} WHERE offer_tag = $1 AND expires_at > $2",
                    self.table("offer_ledgers")
                ),
                &[&offer_tag, &now],
            )
            .await
            .map_err(failed("read a ledger"))?
            .map(|row| row.get(0));
        Ok(state.as_deref().map_or(StoreError::Unknown, state_refusal))
    }

    /// Redeem inside `transaction`, which the caller commits.
    async fn redeem_in(
        &self,
        transaction: &Transaction<'_>,
        code: &str,
        transaction_code: Option<&str>,
        generation: &CatalogGeneration,
        now: i64,
    ) -> Result<PreparedRequest, Refusal> {
        let candidates = self.candidate_tags(OFFER_DOMAIN, code);
        let tags: Vec<&str> = candidates.iter().map(|(_, tag)| tag.as_str()).collect();
        let Some(row) = self.read_offer(transaction, &tags, now).await? else {
            return Err(StoreError::Unknown.into());
        };
        if row.state != "open" {
            return Err(state_refusal(&row.state).into());
        }
        let Some(offer) = row.offer else {
            return Err(StoreError::Unknown.into());
        };
        // A request prepared against another catalog is not handed back, and
        // the refusal neither spends the offer nor counts as an attempt.
        if offer.catalog_generation != generation.as_str() {
            return Err(StoreError::Unknown.into());
        }
        // A request sealed under a retired key can never be opened again.
        if self
            .sealing_keys
            .accepted_version(offer.sealing_key_version)
            .is_none()
        {
            return Err(StoreError::Unknown.into());
        }
        let Some((key, _)) = candidates
            .iter()
            .find(|(_, candidate)| candidate.as_str() == row.offer_tag)
        else {
            return Err(StoreError::Unknown.into());
        };
        // The transaction code was tagged for this offer, under the key the
        // offer was.
        let presented =
            transaction_code.map(|value| transaction_code_tag(key, &row.offer_tag, value));
        if !codes_match(
            offer.transaction_code_tag.as_deref(),
            presented.as_ref().map(|tag| tag.as_str()),
        ) {
            return Err(self.count_failure(transaction, &row.offer_tag, now).await?);
        }

        let moved = transaction
            .query_opt(
                &format!(
                    "UPDATE {} SET state = 'redeemed' \
                     WHERE offer_tag = $1 AND state = 'open' AND expires_at > $2 \
                     RETURNING offer_tag",
                    self.table("offer_ledgers")
                ),
                &[&row.offer_tag, &now],
            )
            .await
            .map_err(failed("redeem an offer"))?;
        if moved.is_none() {
            return Err(self
                .ledger_refusal(transaction, &row.offer_tag, now)
                .await?
                .into());
        }
        let Some(sealed) = transaction
            .query_opt(
                &format!(
                    "DELETE FROM {} WHERE offer_tag = $1 AND expires_at > $2 \
                     RETURNING tag_key_version, sealing_key_version, prepared_nonce, \
                               prepared_ciphertext",
                    self.table("offers")
                ),
                &[&row.offer_tag, &now],
            )
            .await
            .map_err(failed("take an offer"))?
        else {
            return Err(StoreError::Unknown.into());
        };
        let binding = Binding {
            purpose: Purpose::Offer,
            tag: &row.offer_tag,
            tag_key_version: key_version(sealed.get(0))?,
            generation,
        };
        let sealed = Sealed {
            key_version: key_version(sealed.get(1))?,
            nonce: sealed.get(2),
            ciphertext: sealed.get(3),
        };
        Ok(self.open(&binding, &sealed)?)
    }

    /// Count a refused transaction code against the offer, locking it out at
    /// the ceiling. Concurrent attempts from any replica serialize on the
    /// ledger row, and each sees the count the one before it left.
    async fn count_failure(
        &self,
        transaction: &Transaction<'_>,
        offer_tag: &str,
        now: i64,
    ) -> Result<Refusal, StoreError> {
        let counted = transaction
            .query_opt(
                &format!(
                    "UPDATE {} SET failures = failures + 1, \
                         state = CASE WHEN failures + 1 >= $3 THEN 'locked_out' ELSE state END \
                     WHERE offer_tag = $1 AND state = 'open' AND expires_at > $2 \
                     RETURNING state",
                    self.table("offer_ledgers")
                ),
                &[&offer_tag, &now, &self.maximum_transaction_code_attempts],
            )
            .await
            .map_err(failed("count a transaction code attempt"))?;
        let Some(counted) = counted else {
            return Ok(self
                .ledger_refusal(transaction, offer_tag, now)
                .await?
                .into());
        };
        let state: String = counted.get(0);
        if state == "locked_out" {
            // An offer nobody can open is not worth keeping: the sealed
            // request goes, and the ledger keeps the lockout standing.
            transaction
                .execute(
                    &format!("DELETE FROM {} WHERE offer_tag = $1", self.table("offers")),
                    &[&offer_tag],
                )
                .await
                .map_err(failed("drop a locked-out offer"))?;
        }
        Ok(Refusal {
            error: StoreError::TransactionCodeRefused,
            keep_writes: true,
        })
    }

    /// Refuse an access token that is live already or would not fit.
    async fn reserve_token_room(
        &self,
        transaction: &Transaction<'_>,
        access_token: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let candidates = self.candidate_tags(ACCESS_TOKEN_DOMAIN, access_token);
        let tags: Vec<&str> = candidates.iter().map(|(_, tag)| tag.as_str()).collect();
        let row = transaction
            .query_one(
                &format!(
                    "SELECT count(*) FILTER (WHERE token_tag = ANY($1)), count(*) \
                     FROM {} WHERE expires_at > $2",
                    self.table("access_tokens")
                ),
                &[&tags, &now],
            )
            .await
            .map_err(failed("size the token key-space"))?;
        let (held, live): (i64, i64) = (row.get(0), row.get(1));
        if held > 0 {
            return Err(StoreError::AlreadyRedeemed);
        }
        if live >= self.capacity {
            return Err(StoreError::Saturated);
        }
        Ok(())
    }

    async fn bind_in(
        &self,
        transaction: &Transaction<'_>,
        access_token: &str,
        generation: &CatalogGeneration,
        prepared: &PreparedRequest,
        now: i64,
    ) -> Result<(), StoreError> {
        let key = self.tag_keys.current();
        let token_tag = tag(key, ACCESS_TOKEN_DOMAIN, access_token);
        let sealed = self.seal(
            &Binding {
                purpose: Purpose::AccessToken,
                tag: &token_tag,
                tag_key_version: key.version(),
                generation,
            },
            prepared,
        )?;
        let table = self.table("access_tokens");
        transaction
            .execute(
                &format!("DELETE FROM {table} WHERE token_tag = $1 AND expires_at <= $2"),
                &[&token_tag.as_str(), &now],
            )
            .await
            .map_err(failed("clear an expired access token"))?;
        transaction
            .execute(
                &format!(
                    "INSERT INTO {table} (token_tag, tag_key_version, catalog_generation, \
                         sealing_key_version, prepared_nonce, prepared_ciphertext, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)"
                ),
                &[
                    &token_tag.as_str(),
                    &i64::from(key.version()),
                    &generation.as_str(),
                    &i64::from(sealed.key_version),
                    &sealed.nonce,
                    &sealed.ciphertext,
                    &now.saturating_add(self.access_token_lifetime_seconds),
                ],
            )
            .await
            .map_err(failed("bind an access token"))?;
        Ok(())
    }

    fn seal(
        &self,
        binding: &Binding<'_>,
        prepared: &PreparedRequest,
    ) -> Result<Sealed, StoreError> {
        sealing::seal(&self.sealing_keys, binding, prepared).map_err(|_| {
            tracing::error!(target: LOG_TARGET, "a prepared request could not be sealed");
            StoreError::Unavailable
        })
    }

    fn open(&self, binding: &Binding<'_>, sealed: &Sealed) -> Result<PreparedRequest, StoreError> {
        sealing::open(&self.sealing_keys, binding, sealed).map_err(|error| match error {
            SealError::RetiredKey => StoreError::Unknown,
            SealError::Refused => {
                tracing::error!(
                    target: LOG_TARGET,
                    "a sealed prepared request did not open for the row that holds it"
                );
                StoreError::Unavailable
            }
        })
    }

    /// Commit what a redemption decided, or drop it.
    async fn settle<T>(
        transaction: Transaction<'_>,
        outcome: Result<T, Refusal>,
    ) -> Result<T, StoreError> {
        match outcome {
            Ok(value) => {
                transaction
                    .commit()
                    .await
                    .map_err(failed("commit a redemption"))?;
                Ok(value)
            }
            Err(refusal) if refusal.keep_writes => {
                transaction
                    .commit()
                    .await
                    .map_err(failed("commit a refused attempt"))?;
                Err(refusal.error)
            }
            Err(refusal) => {
                transaction
                    .rollback()
                    .await
                    .map_err(failed("roll back a refusal"))?;
                Err(refusal.error)
            }
        }
    }

    async fn count(&self, statement: &str) -> Result<i64, StoreError> {
        let mut client = self.client().await?;
        let transaction = self.begin(&mut client, "begin a count").await?;
        let row = transaction
            .query_one(statement, &[])
            .await
            .map_err(failed("count held entries"))?;
        transaction.commit().await.map_err(failed("end a count"))?;
        Ok(row.get(0))
    }
}

#[async_trait]
impl Store for PostgresStore {
    async fn remember_offer(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        generation: &CatalogGeneration,
        prepared: PreparedRequest,
        now: i64,
    ) -> Result<(), StoreError> {
        let key = self.tag_keys.current();
        let offer_tag = tag(key, OFFER_DOMAIN, code);
        let transaction_code_tag =
            transaction_code.map(|value| transaction_code_tag(key, &offer_tag, value));
        let candidates = self.candidate_tags(OFFER_DOMAIN, code);
        let tags: Vec<&str> = candidates.iter().map(|(_, tag)| tag.as_str()).collect();
        let sealed = self.seal(
            &Binding {
                purpose: Purpose::Offer,
                tag: &offer_tag,
                tag_key_version: key.version(),
                generation,
            },
            &prepared,
        )?;
        let ledgers = self.table("offer_ledgers");

        let mut client = self.client().await?;
        let transaction = self
            .begin(&mut client, "begin remembering an offer")
            .await?;
        self.lock_keyspace(&transaction, "offers").await?;
        let row = transaction
            .query_one(
                &format!(
                    "SELECT count(*) FILTER (WHERE offer_tag = ANY($1)), count(*) \
                     FROM {ledgers} WHERE expires_at > $2"
                ),
                &[&tags, &now],
            )
            .await
            .map_err(failed("size the offer key-space"))?;
        let (held, live): (i64, i64) = (row.get(0), row.get(1));
        let refusal = if held > 0 {
            Some(StoreError::AlreadyRedeemed)
        } else if live >= self.capacity {
            Some(StoreError::Saturated)
        } else {
            None
        };
        if let Some(refusal) = refusal {
            transaction
                .rollback()
                .await
                .map_err(failed("roll back a refused offer"))?;
            return Err(refusal);
        }
        let expires_at = now.saturating_add(self.offer_lifetime_seconds);
        // An expired ledger under the same tag would collide with the new
        // one. Deleting it cascades to its offer.
        transaction
            .execute(
                &format!("DELETE FROM {ledgers} WHERE offer_tag = $1 AND expires_at <= $2"),
                &[&offer_tag.as_str(), &now],
            )
            .await
            .map_err(failed("clear an expired offer"))?;
        transaction
            .execute(
                &format!(
                    "INSERT INTO {ledgers} (offer_tag, state, failures, expires_at) \
                     VALUES ($1, 'open', 0, $2)"
                ),
                &[&offer_tag.as_str(), &expires_at],
            )
            .await
            .map_err(failed("open an offer ledger"))?;
        transaction
            .execute(
                &format!(
                    "INSERT INTO {} (offer_tag, tag_key_version, transaction_code_tag, \
                         catalog_generation, sealing_key_version, prepared_nonce, \
                         prepared_ciphertext, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    self.table("offers")
                ),
                &[
                    &offer_tag.as_str(),
                    &i64::from(key.version()),
                    &transaction_code_tag.as_ref().map(|tag| tag.as_str()),
                    &generation.as_str(),
                    &i64::from(sealed.key_version),
                    &sealed.nonce,
                    &sealed.ciphertext,
                    &expires_at,
                ],
            )
            .await
            .map_err(failed("remember an offer"))?;
        transaction
            .commit()
            .await
            .map_err(failed("commit an offer"))
    }

    async fn redeem_offer(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        generation: &CatalogGeneration,
        now: i64,
    ) -> Result<PreparedRequest, StoreError> {
        let mut client = self.client().await?;
        let transaction = self.begin(&mut client, "begin a redemption").await?;
        let outcome = self
            .redeem_in(&transaction, code, transaction_code, generation, now)
            .await;
        Self::settle(transaction, outcome).await
    }

    async fn redeem_offer_for_access_token(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        access_token: &str,
        generation: &CatalogGeneration,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        let transaction = self.begin(&mut client, "begin a redemption").await?;
        // The token key-space is sized before the offer is spent, and stays
        // locked until the token is bound, so a saturated store refuses
        // having changed nothing.
        self.lock_keyspace(&transaction, "access_tokens").await?;
        self.reserve_token_room(&transaction, access_token, now)
            .await?;
        let outcome = match self
            .redeem_in(&transaction, code, transaction_code, generation, now)
            .await
        {
            Ok(prepared) => self
                .bind_in(&transaction, access_token, generation, &prepared, now)
                .await
                .map_err(Refusal::from),
            Err(refusal) => Err(refusal),
        };
        Self::settle(transaction, outcome).await
    }

    async fn bind_access_token(
        &self,
        access_token: &str,
        generation: &CatalogGeneration,
        prepared: PreparedRequest,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        let transaction = self
            .begin(&mut client, "begin binding an access token")
            .await?;
        self.lock_keyspace(&transaction, "access_tokens").await?;
        self.reserve_token_room(&transaction, access_token, now)
            .await?;
        self.bind_in(&transaction, access_token, generation, &prepared, now)
            .await?;
        transaction
            .commit()
            .await
            .map_err(failed("commit an access token"))
    }

    async fn claim_access_token(
        &self,
        access_token: &str,
        generation: &CatalogGeneration,
        now: i64,
    ) -> Result<PreparedRequest, StoreError> {
        let candidates = self.candidate_tags(ACCESS_TOKEN_DOMAIN, access_token);
        let tags: Vec<&str> = candidates.iter().map(|(_, tag)| tag.as_str()).collect();
        let mut client = self.client().await?;
        let transaction = self.begin(&mut client, "begin a claim").await?;
        // Deleting is claiming: of two claims of one token, one deletes the
        // row and the other finds nothing to delete. Claiming under another
        // catalog generation deletes nothing.
        let row = transaction
            .query_opt(
                &format!(
                    "DELETE FROM {} \
                     WHERE token_tag = ANY($1) AND expires_at > $2 AND catalog_generation = $3 \
                     RETURNING token_tag, tag_key_version, sealing_key_version, prepared_nonce, \
                               prepared_ciphertext",
                    self.table("access_tokens")
                ),
                &[&tags, &now, &generation.as_str()],
            )
            .await
            .map_err(failed("claim an access token"))?;
        let Some(row) = row else {
            return Self::settle(transaction, Err(StoreError::Unknown.into())).await;
        };
        let token_tag: String = row.get(0);
        let outcome = (|| {
            let binding = Binding {
                purpose: Purpose::AccessToken,
                tag: &token_tag,
                tag_key_version: key_version(row.get(1))?,
                generation,
            };
            let sealed = Sealed {
                key_version: key_version(row.get(2))?,
                nonce: row.get(3),
                ciphertext: row.get(4),
            };
            self.open(&binding, &sealed)
        })()
        .map_err(Refusal::from);
        Self::settle(transaction, outcome).await
    }

    async fn sweep(&self, now: i64) -> usize {
        // The purge runs again on its next tick; what it could not delete is
        // never served meanwhile, because every read filters on expiry.
        let Ok(mut client) = self.client().await else {
            return 0;
        };
        let Ok(transaction) = self.begin(&mut client, "begin a purge").await else {
            return 0;
        };
        let mut expired: u64 = 0;
        for table in ["offers", "offer_ledgers", "access_tokens"] {
            match transaction
                .execute(
                    &format!("DELETE FROM {} WHERE expires_at <= $1", self.table(table)),
                    &[&now],
                )
                .await
            {
                Ok(deleted) => expired = expired.saturating_add(deleted),
                Err(error) => {
                    failed("purge expired entries")(error);
                    return 0;
                }
            }
        }
        match transaction.commit().await {
            Ok(()) => usize::try_from(expired).unwrap_or(usize::MAX),
            Err(error) => {
                failed("commit a purge")(error);
                0
            }
        }
    }

    async fn len(&self) -> usize {
        let statement = format!(
            "SELECT (SELECT count(*) FROM {}) + (SELECT count(*) FROM {}) \
                  + (SELECT count(*) FROM {})",
            self.table("offers"),
            self.table("offer_ledgers"),
            self.table("access_tokens"),
        );
        self.count(&statement)
            .await
            .ok()
            .and_then(|held| usize::try_from(held).ok())
            .unwrap_or(0)
    }

    async fn maximum_keyspace_len(&self) -> Option<usize> {
        let statement = format!(
            "SELECT GREATEST((SELECT count(*) FROM {}), (SELECT count(*) FROM {}), \
                             (SELECT count(*) FROM {}))",
            self.table("offers"),
            self.table("offer_ledgers"),
            self.table("access_tokens"),
        );
        self.count(&statement)
            .await
            .ok()
            .and_then(|held| usize::try_from(held).ok())
    }
}

/// The waits a transaction allows itself, derived from the service's request
/// timeout: a lock is waited for a quarter of it, and a statement, or a pause
/// between statements, may take half. A replica that hangs while it holds a
/// lock is cut off by the server after that half, which releases the lock.
fn transaction_waits(request_timeout: Duration) -> String {
    let share = |divisor: u128| {
        i32::try_from((request_timeout.as_millis() / divisor).max(1)).unwrap_or(i32::MAX)
    };
    let (lock, statement) = (share(4), share(2));
    format!(
        "SET LOCAL lock_timeout = '{lock}ms'; \
         SET LOCAL statement_timeout = '{statement}ms'; \
         SET LOCAL idle_in_transaction_session_timeout = '{statement}ms';"
    )
}

/// A schema name this store can interpolate into SQL without quoting, and
/// one it can own: `public` is shared with whatever else uses the database,
/// and `information_schema` and the `pg_` prefix belong to PostgreSQL.
fn valid_schema_name(schema: &str) -> bool {
    let mut bytes = schema.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    schema.len() <= 63
        && (first.is_ascii_lowercase() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !matches!(schema, "public" | "information_schema")
        && !schema.starts_with("pg_")
}

fn state_refusal(state: &str) -> StoreError {
    match state {
        "redeemed" => StoreError::AlreadyRedeemed,
        "locked_out" => StoreError::LockedOut,
        _ => StoreError::Unknown,
    }
}

/// Compare the transaction code an offer carries with the one presented, as
/// the memory backend does: constant time over the tags, and an offer that
/// carries no code refuses one.
fn codes_match(expected: Option<&str>, presented: Option<&str>) -> bool {
    match (expected, presented) {
        (None, None) => true,
        (Some(expected), Some(presented)) => expected.as_bytes().ct_eq(presented.as_bytes()).into(),
        _ => false,
    }
}

fn key_version(stored: i64) -> Result<u32, StoreError> {
    u32::try_from(stored).map_err(|_| {
        tracing::error!(target: LOG_TARGET, "a stored key version is out of range");
        StoreError::Unavailable
    })
}

fn sqlstate(error: &tokio_postgres::Error) -> &str {
    error.code().map_or("none", |code| code.code())
}

/// Why the pool gave no connection, coarse enough to log: the kind of failure
/// and the server's SQLSTATE when the server answered. The message is left
/// out, because it can name the host, the database or the user.
fn pool_failure(error: &PoolError) -> (&'static str, &str) {
    match error {
        PoolError::Timeout(TimeoutType::Wait) => ("wait timeout", "none"),
        PoolError::Timeout(TimeoutType::Create) => ("connect timeout", "none"),
        PoolError::Timeout(TimeoutType::Recycle) => ("recycle timeout", "none"),
        PoolError::Backend(error) => ("connect", sqlstate(error)),
        PoolError::Closed => ("closed", "none"),
        PoolError::NoRuntimeSpecified => ("no runtime", "none"),
        PoolError::PostCreateHook(HookError::Backend(error)) => {
            ("post-create hook", sqlstate(error))
        }
        PoolError::PostCreateHook(HookError::Message(_)) => ("post-create hook", "none"),
    }
}

/// Log that the pool gave no connection, by cause and SQLSTATE only.
fn log_unreachable(error: &PoolError) {
    let (cause, sqlstate) = pool_failure(error);
    tracing::error!(
        target: LOG_TARGET,
        cause,
        sqlstate,
        "the store database is unreachable"
    );
}

/// Log a database failure by operation and SQLSTATE, and refuse.
fn failed(operation: &'static str) -> impl Fn(tokio_postgres::Error) -> StoreError {
    move |error| {
        tracing::error!(
            target: LOG_TARGET,
            operation,
            sqlstate = sqlstate(&error),
            "the store database refused an operation"
        );
        StoreError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_plain_lowercase_identifier_is_a_schema_name() {
        for accepted in [DEFAULT_SCHEMA, "_store", "store_2", &"s".repeat(63)] {
            assert!(valid_schema_name(accepted), "{accepted}");
        }
        for refused in [
            "",
            "2store",
            "Store",
            "store-1",
            "store.offers",
            "store;drop",
            "store \"x\"",
            &"s".repeat(64),
            // Shared with other tools, or reserved by PostgreSQL.
            "public",
            "information_schema",
            "pg_catalog",
            "pg_store",
        ] {
            assert!(!valid_schema_name(refused), "{refused}");
        }
    }

    #[test]
    fn transaction_waits_stay_below_the_request_timeout() {
        assert_eq!(
            transaction_waits(Duration::from_millis(5_000)),
            "SET LOCAL lock_timeout = '1250ms'; \
             SET LOCAL statement_timeout = '2500ms'; \
             SET LOCAL idle_in_transaction_session_timeout = '2500ms';"
        );
        // Zero would mean no bound at all, so the shortest wait is one
        // millisecond.
        assert_eq!(
            transaction_waits(Duration::from_millis(1)),
            "SET LOCAL lock_timeout = '1ms'; \
             SET LOCAL statement_timeout = '1ms'; \
             SET LOCAL idle_in_transaction_session_timeout = '1ms';"
        );
        assert!(transaction_waits(Duration::MAX).contains(&format!("'{}ms'", i32::MAX)));
    }

    #[test]
    fn tagging_and_sealing_under_one_key_is_refused() {
        let open = |tag_byte: u8, sealing_byte: u8| {
            let pool = Pool::builder(deadpool_postgres::Manager::new(
                tokio_postgres::Config::new(),
                tokio_postgres::NoTls,
            ))
            .build()
            .expect("a pool that has not connected");
            let ring = |version, byte| {
                KeyRing::single(VersionedKey::new(version, &[byte; 32]).expect("a key"))
            };
            PostgresStore::new(
                pool,
                DEFAULT_SCHEMA,
                &StoreConfig::default(),
                Duration::from_secs(5),
                ring(1, tag_byte),
                ring(2, sealing_byte),
            )
        };
        let shared = open(0x11, 0x11);
        assert!(
            matches!(shared, Err(PostgresSetupError::SharedKey)),
            "{shared:?}"
        );
        assert!(open(0x11, 0x22).is_ok());
    }

    #[test]
    fn a_pool_failure_is_named_by_its_cause_without_its_message() {
        for (error, cause) in [
            (PoolError::Timeout(TimeoutType::Wait), "wait timeout"),
            (PoolError::Timeout(TimeoutType::Create), "connect timeout"),
            (PoolError::Timeout(TimeoutType::Recycle), "recycle timeout"),
            (PoolError::Closed, "closed"),
            (PoolError::NoRuntimeSpecified, "no runtime"),
            (
                PoolError::PostCreateHook(HookError::Message("names the host".into())),
                "post-create hook",
            ),
        ] {
            assert_eq!(pool_failure(&error), (cause, "none"), "{error:?}");
        }
    }

    #[test]
    fn transaction_codes_compare_as_the_memory_backend_compares_them() {
        assert!(codes_match(None, None));
        assert!(codes_match(Some("tag"), Some("tag")));
        assert!(!codes_match(Some("tag"), Some("other")));
        assert!(!codes_match(Some("tag"), None));
        assert!(!codes_match(None, Some("tag")));
    }

    #[test]
    fn a_ledger_state_maps_to_the_refusal_the_memory_backend_gives() {
        assert_eq!(state_refusal("redeemed"), StoreError::AlreadyRedeemed);
        assert_eq!(state_refusal("locked_out"), StoreError::LockedOut);
        assert_eq!(state_refusal("open"), StoreError::Unknown);
    }
}
