//! The storage contract, written once and run against every backend.
//!
//! Each case below is a plain function over a [`Kind`]. The `contract!` macro
//! turns every case into one test per backend, so the memory backend and the
//! PostgreSQL backend answer the same questions with the same assertions. The
//! PostgreSQL half needs the `postgres-test` feature and a disposable server
//! named by `EVIDENCE_OID4VCI_TEST_DATABASE_URL`.
//!
//! The PostgreSQL-only cases at the end cover what a single process cannot
//! show: two replicas contending for one offer, one lockout counter and one
//! capacity shared between them, what the database holds at rest, and how a
//! real database failure is logged and answered.

mod store_support;

use registry_evidence_oid4vci::config::StoreConfig;
use registry_evidence_oid4vci::store::StoreError;
use store_support::{
    assert_prepared, bounds, generation, prepared, Deployment, Keys, Kind, Ring, LIFETIME, NOW,
    TAG_ONE, TAG_THREE, TAG_TWO,
};

macro_rules! contract {
    ($($case:ident),+ $(,)?) => {
        mod memory {
            $(
                #[tokio::test]
                async fn $case() {
                    super::$case(super::Kind::Memory).await;
                }
            )+
        }

        #[cfg(feature = "postgres-test")]
        mod postgres {
            $(
                #[tokio::test]
                async fn $case() {
                    super::$case(super::Kind::Postgres).await;
                }
            )+
        }
    };
}

contract!(
    an_offer_is_created_once_and_redeemed_once,
    a_redeemed_offer_carries_its_request_to_one_access_token_claim,
    a_bound_access_token_is_claimed_exactly_once,
    wrong_transaction_codes_count_toward_a_lockout_that_persists,
    expired_entries_are_never_served,
    a_purge_drops_only_what_has_expired,
    saturation_fails_closed_and_spends_nothing,
    rotation_accepts_current_and_previous_keys_and_refuses_a_retired_one,
    a_catalog_generation_mismatch_is_refused_without_spending_anything,
);

async fn an_offer_is_created_once_and_redeemed_once(kind: Kind) {
    let (_deployment, store) = Deployment::open(kind, bounds(), Keys::default()).await;
    let catalog = generation("catalog-1");

    store
        .remember_offer("code-1", None, &catalog, prepared(), NOW)
        .await
        .expect("the offer is remembered");
    assert_eq!(
        store
            .remember_offer("code-1", None, &catalog, prepared(), NOW)
            .await,
        Err(StoreError::AlreadyRedeemed),
        "a live code is never remembered twice"
    );

    let redeemed = store
        .redeem_offer("code-1", None, &catalog, NOW)
        .await
        .expect("the offer redeems once");
    assert_prepared(&redeemed);
    assert_eq!(
        store
            .redeem_offer("code-1", None, &catalog, NOW)
            .await
            .err(),
        Some(StoreError::AlreadyRedeemed)
    );
    assert_eq!(
        store
            .redeem_offer("never-issued", None, &catalog, NOW)
            .await
            .err(),
        Some(StoreError::Unknown)
    );
}

async fn a_redeemed_offer_carries_its_request_to_one_access_token_claim(kind: Kind) {
    let (_deployment, store) = Deployment::open(kind, bounds(), Keys::default()).await;
    let catalog = generation("catalog-1");
    store
        .remember_offer("code-1", Some("4711"), &catalog, prepared(), NOW)
        .await
        .expect("the offer is remembered");

    store
        .redeem_offer_for_access_token("code-1", Some("4711"), "token-1", &catalog, NOW)
        .await
        .expect("the offer redeems for an access token");
    assert_eq!(
        store
            .redeem_offer_for_access_token("code-1", Some("4711"), "token-2", &catalog, NOW)
            .await,
        Err(StoreError::AlreadyRedeemed)
    );

    let claimed = store
        .claim_access_token("token-1", &catalog, NOW)
        .await
        .expect("the token claims once");
    assert_prepared(&claimed);
    for token in ["token-1", "token-2"] {
        assert_eq!(
            store.claim_access_token(token, &catalog, NOW).await.err(),
            Some(StoreError::Unknown),
            "{token}"
        );
    }
}

async fn a_bound_access_token_is_claimed_exactly_once(kind: Kind) {
    let (_deployment, store) = Deployment::open(kind, bounds(), Keys::default()).await;
    let catalog = generation("catalog-1");

    store
        .bind_access_token("token-1", &catalog, prepared(), NOW)
        .await
        .expect("the token is bound");
    assert_eq!(
        store
            .bind_access_token("token-1", &catalog, prepared(), NOW)
            .await,
        Err(StoreError::AlreadyRedeemed),
        "a live token is never bound twice"
    );
    let claimed = store
        .claim_access_token("token-1", &catalog, NOW)
        .await
        .expect("the token claims once");
    assert_prepared(&claimed);
    assert_eq!(
        store
            .claim_access_token("token-1", &catalog, NOW)
            .await
            .err(),
        Some(StoreError::Unknown)
    );
}

async fn wrong_transaction_codes_count_toward_a_lockout_that_persists(kind: Kind) {
    let (deployment, first) = Deployment::open(kind, bounds(), Keys::default()).await;
    let catalog = generation("catalog-1");
    first
        .remember_offer("code-1", Some("4711"), &catalog, prepared(), NOW)
        .await
        .expect("the offer is remembered");

    assert_eq!(
        first
            .redeem_offer("code-1", Some("0000"), &catalog, NOW)
            .await
            .err(),
        Some(StoreError::TransactionCodeRefused)
    );
    assert_eq!(
        first
            .redeem_offer("code-1", None, &catalog, NOW)
            .await
            .err(),
        Some(StoreError::TransactionCodeRefused),
        "a missing code counts like a wrong one"
    );
    // A second handle on the same state continues the same count.
    let second = deployment.reopen(Keys::default()).await;
    assert_eq!(
        second
            .redeem_offer("code-1", Some("1111"), &catalog, NOW)
            .await
            .err(),
        Some(StoreError::TransactionCodeRefused),
        "the third wrong code reaches the ceiling"
    );

    for store in [&first, &second] {
        assert_eq!(
            store
                .redeem_offer("code-1", Some("4711"), &catalog, NOW)
                .await
                .err(),
            Some(StoreError::LockedOut),
            "the right code no longer opens a locked-out offer"
        );
        assert_eq!(
            store
                .redeem_offer_for_access_token("code-1", Some("4711"), "token-1", &catalog, NOW)
                .await,
            Err(StoreError::LockedOut)
        );
    }
    assert_eq!(
        first
            .claim_access_token("token-1", &catalog, NOW)
            .await
            .err(),
        Some(StoreError::Unknown)
    );

    // An offer created without a code refuses one, and counts it.
    first
        .remember_offer("code-2", None, &catalog, prepared(), NOW)
        .await
        .expect("the offer is remembered");
    assert_eq!(
        first
            .redeem_offer("code-2", Some("4711"), &catalog, NOW)
            .await
            .err(),
        Some(StoreError::TransactionCodeRefused)
    );
    first
        .redeem_offer("code-2", None, &catalog, NOW)
        .await
        .expect("the offer still redeems without a code");
}

async fn expired_entries_are_never_served(kind: Kind) {
    let (_deployment, store) = Deployment::open(kind, bounds(), Keys::default()).await;
    let catalog = generation("catalog-1");
    for code in ["code-1", "code-2", "code-3"] {
        store
            .remember_offer(code, None, &catalog, prepared(), NOW)
            .await
            .expect("the offer is remembered");
    }
    store
        .bind_access_token("token-1", &catalog, prepared(), NOW)
        .await
        .expect("the token is bound");

    let expiry = NOW + LIFETIME;
    // Time only moves forward here: a write prunes what has expired by its
    // reading of the clock, so the last live second is checked first.
    let redeemed = store
        .redeem_offer("code-3", None, &catalog, expiry - 1)
        .await
        .expect("an offer is served until its last second");
    assert_prepared(&redeemed);
    assert_eq!(
        store
            .redeem_offer("code-1", None, &catalog, expiry)
            .await
            .err(),
        Some(StoreError::Unknown)
    );
    assert_eq!(
        store
            .redeem_offer_for_access_token("code-2", None, "token-2", &catalog, expiry)
            .await,
        Err(StoreError::Unknown)
    );
    assert_eq!(
        store
            .claim_access_token("token-1", &catalog, expiry)
            .await
            .err(),
        Some(StoreError::Unknown)
    );
}

async fn a_purge_drops_only_what_has_expired(kind: Kind) {
    let (_deployment, store) = Deployment::open(kind, bounds(), Keys::default()).await;
    let catalog = generation("catalog-1");
    let earlier = NOW - LIFETIME;
    let later = NOW - 10;
    store
        .remember_offer("old-code", None, &catalog, prepared(), earlier)
        .await
        .expect("the old offer is remembered");
    store
        .bind_access_token("old-token", &catalog, prepared(), earlier)
        .await
        .expect("the old token is bound");
    store
        .remember_offer("live-code", None, &catalog, prepared(), later)
        .await
        .expect("the live offer is remembered");
    store
        .bind_access_token("live-token", &catalog, prepared(), later)
        .await
        .expect("the live token is bound");

    assert_eq!(
        store.sweep(NOW).await,
        3,
        "the old offer, its ledger and the old token"
    );
    assert_eq!(store.len().await, 3);
    assert_eq!(store.maximum_keyspace_len().await, Some(1));

    store
        .redeem_offer("live-code", None, &catalog, NOW)
        .await
        .expect("the live offer survives the purge");
    store
        .claim_access_token("live-token", &catalog, NOW)
        .await
        .expect("the live token survives the purge");
    assert_eq!(store.sweep(NOW).await, 0);
    assert_eq!(store.len().await, 1, "the redeemed offer's ledger remains");
    assert_eq!(store.sweep(later + LIFETIME).await, 1);
    assert!(store.is_empty().await);
}

async fn saturation_fails_closed_and_spends_nothing(kind: Kind) {
    let bounds = StoreConfig {
        maximum_offers: 2,
        ..bounds()
    };
    let (_deployment, store) = Deployment::open(kind, bounds, Keys::default()).await;
    let catalog = generation("catalog-1");
    for code in ["code-1", "code-2"] {
        store
            .remember_offer(code, None, &catalog, prepared(), NOW)
            .await
            .expect("the offer is remembered");
    }
    assert_eq!(
        store
            .remember_offer("code-3", None, &catalog, prepared(), NOW)
            .await,
        Err(StoreError::Saturated)
    );
    store
        .redeem_offer("code-1", None, &catalog, NOW)
        .await
        .expect("the refusal cost no live offer");
    assert_eq!(
        store
            .redeem_offer("code-3", None, &catalog, NOW)
            .await
            .err(),
        Some(StoreError::Unknown)
    );
    assert_eq!(
        store
            .remember_offer("code-4", None, &catalog, prepared(), NOW)
            .await,
        Err(StoreError::Saturated),
        "a redeemed offer's ledger still counts until it expires"
    );

    for token in ["token-1", "token-2"] {
        store
            .bind_access_token(token, &catalog, prepared(), NOW)
            .await
            .expect("the token is bound");
    }
    assert_eq!(
        store
            .bind_access_token("token-3", &catalog, prepared(), NOW)
            .await,
        Err(StoreError::Saturated)
    );
    assert_eq!(
        store
            .redeem_offer_for_access_token("code-2", None, "token-4", &catalog, NOW)
            .await,
        Err(StoreError::Saturated)
    );
    store
        .claim_access_token("token-1", &catalog, NOW)
        .await
        .expect("a live token is still claimable");
    store
        .redeem_offer_for_access_token("code-2", None, "token-4", &catalog, NOW)
        .await
        .expect("the saturated refusal did not spend the offer");
}

async fn rotation_accepts_current_and_previous_keys_and_refuses_a_retired_one(kind: Kind) {
    let (deployment, first) =
        Deployment::open(kind, bounds(), Keys::tagged(Ring::of(TAG_ONE))).await;
    let catalog = generation("catalog-1");
    for code in ["code-a", "code-b"] {
        first
            .remember_offer(code, Some("4711"), &catalog, prepared(), NOW)
            .await
            .expect("the offer is remembered under the first key");
    }
    first
        .bind_access_token("token-a", &catalog, prepared(), NOW)
        .await
        .expect("the token is bound under the first key");

    let rotated = deployment
        .reopen(Keys::tagged(Ring::rotated(TAG_TWO, TAG_ONE)))
        .await;
    let redeemed = rotated
        .redeem_offer("code-a", Some("4711"), &catalog, NOW)
        .await
        .expect("an offer tagged under the previous key still redeems");
    assert_prepared(&redeemed);
    rotated
        .claim_access_token("token-a", &catalog, NOW)
        .await
        .expect("a token tagged under the previous key still claims");
    rotated
        .remember_offer("code-c", Some("4711"), &catalog, prepared(), NOW)
        .await
        .expect("the offer is remembered under the current key");
    rotated
        .bind_access_token("token-c", &catalog, prepared(), NOW)
        .await
        .expect("the token is bound under the current key");

    let retired = deployment
        .reopen(Keys::tagged(Ring::rotated(TAG_THREE, TAG_TWO)))
        .await;
    assert_eq!(
        retired
            .redeem_offer("code-b", Some("4711"), &catalog, NOW)
            .await
            .err(),
        Some(StoreError::Unknown),
        "an offer tagged under a retired key is unreachable"
    );
    retired
        .redeem_offer("code-c", Some("4711"), &catalog, NOW)
        .await
        .expect("an offer tagged under the previous key still redeems");
    retired
        .claim_access_token("token-c", &catalog, NOW)
        .await
        .expect("a token tagged under the previous key still claims");
}

async fn a_catalog_generation_mismatch_is_refused_without_spending_anything(kind: Kind) {
    let (_deployment, store) = Deployment::open(kind, bounds(), Keys::default()).await;
    let prepared_under = generation("catalog-1");
    let changed = generation("catalog-2");
    store
        .remember_offer("code-1", Some("4711"), &prepared_under, prepared(), NOW)
        .await
        .expect("the offer is remembered");

    for presented in ["4711", "0000", "1111", "2222"] {
        assert_eq!(
            store
                .redeem_offer("code-1", Some(presented), &changed, NOW)
                .await
                .err(),
            Some(StoreError::Unknown),
            "a request prepared under another catalog is never handed back"
        );
    }
    assert_eq!(
        store
            .redeem_offer_for_access_token("code-1", Some("4711"), "token-1", &changed, NOW)
            .await,
        Err(StoreError::Unknown)
    );

    store
        .redeem_offer_for_access_token("code-1", Some("4711"), "token-1", &prepared_under, NOW)
        .await
        .expect("refusals under another generation neither spent nor locked the offer");
    assert_eq!(
        store
            .claim_access_token("token-1", &changed, NOW)
            .await
            .err(),
        Some(StoreError::Unknown)
    );
    let claimed = store
        .claim_access_token("token-1", &prepared_under, NOW)
        .await
        .expect("the token claims under the generation it was bound under");
    assert_prepared(&claimed);
}

#[cfg(feature = "postgres-test")]
mod postgres_only {
    //! What only a shared database can show.

    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use registry_evidence_client::{EvidenceDefinitionsDocument, HolderBoundRequestSpec};
    use registry_evidence_oid4vci::audit::DeliveryAudit;
    use registry_evidence_oid4vci::authorizer::{
        AuthorizationError, AuthorizedOffer, OfferAuthorizer,
    };
    use registry_evidence_oid4vci::config::{DeliveryConfig, StoreConfig};
    use registry_evidence_oid4vci::issuer::{CredentialIssuer, IssuanceError};
    use registry_evidence_oid4vci::metadata::CredentialCatalog;
    use registry_evidence_oid4vci::service::{
        build_app, DeliveryService, CREDENTIAL_PATH, OFFERS_PATH, TOKEN_PATH,
    };
    use registry_evidence_oid4vci::storage::postgres::PostgresSetupError;
    use registry_evidence_oid4vci::storage::Store;
    use registry_evidence_oid4vci::store::{PreparedRequest, StoreError};
    use registry_evidence_oid4vci::PRE_AUTHORIZED_CODE_GRANT_TYPE;
    use registry_platform_audit::AuditWriter;
    use serde_json::{json, Value};
    use tokio::sync::Barrier;

    use super::store_support::postgres::{
        admin, count, dump, isolated_schema_name, open_over, pool, pool_with_options,
        pool_with_password, unmigrated, LOCK_NAMESPACE, REQUEST_TIMEOUT,
    };
    use super::store_support::{
        assert_prepared, bounds, generation, prepared, Deployment, Keys, Kind, Logs, Ring,
        LIFETIME, NOW, SEAL_ONE, SEAL_THREE, SEAL_TWO, TAG_ONE,
    };

    const CONTENDERS: usize = 24;

    async fn two_replicas(bounds: StoreConfig) -> (Deployment, Arc<dyn Store>, Arc<dyn Store>) {
        let (deployment, first) = Deployment::open(Kind::Postgres, bounds, Keys::default()).await;
        let second = deployment.reopen(Keys::default()).await;
        (deployment, first, second)
    }

    fn replica<'a>(
        index: usize,
        first: &'a Arc<dyn Store>,
        second: &'a Arc<dyn Store>,
    ) -> Arc<dyn Store> {
        Arc::clone(if index.is_multiple_of(2) {
            first
        } else {
            second
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_replicas_redeem_one_offer_exactly_once() {
        let (_deployment, first, second) = two_replicas(bounds()).await;
        let catalog = generation("catalog-1");
        first
            .remember_offer("contended", None, &catalog, prepared(), NOW)
            .await
            .expect("the offer is remembered");

        let mut contenders = Vec::new();
        for index in 0..CONTENDERS {
            let store = replica(index, &first, &second);
            let catalog = catalog.clone();
            contenders.push(tokio::spawn(async move {
                store
                    .redeem_offer("contended", None, &catalog, NOW)
                    .await
                    .map(|_| ())
            }));
        }
        let outcomes = join(contenders).await;
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert!(outcomes
            .iter()
            .filter_map(|outcome| outcome.as_ref().err())
            .all(|error| *error == StoreError::AlreadyRedeemed));

        second
            .remember_offer("contended-token", None, &catalog, prepared(), NOW)
            .await
            .expect("the offer is remembered");
        let mut contenders = Vec::new();
        for index in 0..CONTENDERS {
            let store = replica(index, &first, &second);
            let catalog = catalog.clone();
            contenders.push(tokio::spawn(async move {
                store
                    .redeem_offer_for_access_token(
                        "contended-token",
                        None,
                        &format!("token-{index}"),
                        &catalog,
                        NOW,
                    )
                    .await
            }));
        }
        let outcomes = join(contenders).await;
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert!(outcomes
            .iter()
            .filter_map(|outcome| outcome.as_ref().err())
            .all(|error| *error == StoreError::AlreadyRedeemed));
        let mut claimed = 0;
        for index in 0..CONTENDERS {
            if replica(index, &first, &second)
                .claim_access_token(&format!("token-{index}"), &catalog, NOW)
                .await
                .is_ok()
            {
                claimed += 1;
            }
        }
        assert_eq!(claimed, 1, "exactly one access token carries the request");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_replicas_share_one_lockout_counter() {
        let (_deployment, first, second) = two_replicas(bounds()).await;
        let catalog = generation("catalog-1");
        first
            .remember_offer("guessed", Some("4711"), &catalog, prepared(), NOW)
            .await
            .expect("the offer is remembered");

        let mut contenders = Vec::new();
        for index in 0..CONTENDERS {
            let store = replica(index, &first, &second);
            let catalog = catalog.clone();
            contenders.push(tokio::spawn(async move {
                store
                    .redeem_offer("guessed", Some(&format!("{index:04}")), &catalog, NOW)
                    .await
                    .map(|_| ())
            }));
        }
        let outcomes = join(contenders).await;
        let refused = outcomes
            .iter()
            .filter(|outcome| **outcome == Err(StoreError::TransactionCodeRefused))
            .count();
        let locked = outcomes
            .iter()
            .filter(|outcome| **outcome == Err(StoreError::LockedOut))
            .count();
        assert_eq!(refused, 3, "three wrong codes across both replicas");
        assert_eq!(
            locked,
            CONTENDERS - 3,
            "every later attempt meets the lockout"
        );

        for store in [&first, &second] {
            assert_eq!(
                store
                    .redeem_offer("guessed", Some("4711"), &catalog, NOW)
                    .await
                    .err(),
                Some(StoreError::LockedOut)
            );
        }
    }

    fn four_places() -> StoreConfig {
        StoreConfig {
            maximum_offers: 4,
            ..bounds()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_replicas_count_capacity_together() {
        let (_deployment, first, second) = two_replicas(four_places()).await;
        count_capacity_together(&first, &second).await;
    }

    /// A role or database whose sessions default to REPEATABLE READ, as some
    /// hardening baselines set, takes each transaction's snapshot at its first
    /// statement, before the advisory lock is granted. A count taken under
    /// that snapshot misses the offer the previous lock holder committed, so
    /// the store has to choose its own isolation rather than inherit one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn capacity_holds_when_sessions_default_to_repeatable_read() {
        const REPEATABLE_READ: &str = "-c default_transaction_isolation=repeatable\\ read";
        let (deployment, _store) =
            Deployment::open(Kind::Postgres, four_places(), Keys::default()).await;
        let session = pool_with_options(REPEATABLE_READ);
        let default: String = session
            .get()
            .await
            .expect("a session under the repeatable read default")
            .query_one("SHOW default_transaction_isolation", &[])
            .await
            .expect("read the session default")
            .get(0);
        assert_eq!(default, "repeatable read", "the session default took hold");

        let first = open_over(
            session,
            deployment.schema(),
            &four_places(),
            Keys::default(),
        )
        .await;
        let second = open_over(
            pool_with_options(REPEATABLE_READ),
            deployment.schema(),
            &four_places(),
            Keys::default(),
        )
        .await;
        count_capacity_together(&first, &second).await;
    }

    async fn count_capacity_together(first: &Arc<dyn Store>, second: &Arc<dyn Store>) {
        let catalog = generation("catalog-1");

        let mut contenders = Vec::new();
        for index in 0..CONTENDERS {
            let store = replica(index, first, second);
            let catalog = catalog.clone();
            contenders.push(tokio::spawn(async move {
                store
                    .remember_offer(&format!("code-{index}"), None, &catalog, prepared(), NOW)
                    .await
            }));
        }
        let outcomes = join(contenders).await;
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 4);
        assert!(outcomes
            .iter()
            .filter_map(|outcome| outcome.as_ref().err())
            .all(|error| *error == StoreError::Saturated));

        let mut contenders = Vec::new();
        for index in 0..CONTENDERS {
            let store = replica(index, first, second);
            let catalog = catalog.clone();
            contenders.push(tokio::spawn(async move {
                store
                    .bind_access_token(&format!("token-{index}"), &catalog, prepared(), NOW)
                    .await
            }));
        }
        let outcomes = join(contenders).await;
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 4);
        assert!(outcomes
            .iter()
            .filter_map(|outcome| outcome.as_ref().err())
            .all(|error| *error == StoreError::Saturated));
        assert_eq!(first.maximum_keyspace_len().await, Some(4));
        assert_eq!(second.maximum_keyspace_len().await, Some(4));
    }

    /// A replica that hangs while it holds a key-space lock must not hold
    /// every other replica's requests past their timeout. Each transaction
    /// bounds its own waits from the service's request timeout, so a writer
    /// that meets a held lock gives up inside that timeout, answers as any
    /// database failure does, and leaves nothing spent.
    #[tokio::test]
    async fn a_held_keyspace_lock_refuses_within_the_bound_and_spends_nothing() {
        const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
        let (deployment, _store) =
            Deployment::open(Kind::Postgres, bounds(), Keys::default()).await;
        let schema = deployment.schema().to_owned();
        let store = unmigrated(pool(), &schema, &bounds(), Keys::default(), REQUEST_TIMEOUT);
        let catalog = generation("catalog-1");
        store
            .remember_offer("waiting", None, &catalog, prepared(), NOW)
            .await
            .expect("an offer to redeem once the lock is free");
        let held = at_rest(&schema).await;

        let holder = admin().await;
        for keyspace in ["offers", "access_tokens"] {
            holder
                .execute(
                    "SELECT pg_advisory_lock($1, hashtext($2))",
                    &[&LOCK_NAMESPACE, &format!("{schema}.{keyspace}")],
                )
                .await
                .expect("hold a key-space lock as a hung replica would");
        }

        let (logs, _guard) = Logs::capture();
        let started = Instant::now();
        let created =
            within_the_test_bound(store.remember_offer("blocked", None, &catalog, prepared(), NOW))
                .await;
        assert_eq!(created, Err(StoreError::Unavailable));
        assert!(
            started.elapsed() < REQUEST_TIMEOUT,
            "offer creation gave up after {:?}",
            started.elapsed()
        );
        let started = Instant::now();
        let redeemed = within_the_test_bound(
            store.redeem_offer_for_access_token("waiting", None, "token", &catalog, NOW),
        )
        .await;
        assert_eq!(redeemed, Err(StoreError::Unavailable));
        assert!(
            started.elapsed() < REQUEST_TIMEOUT,
            "redemption gave up after {:?}",
            started.elapsed()
        );
        assert_eq!(at_rest(&schema).await, held, "nothing was written or spent");

        let rendered = logs.rendered();
        assert_eq!(
            rendered
                .matches(r#"operation="lock a key-space" sqlstate="55P03""#)
                .count(),
            2,
            "{rendered}"
        );
        for value in ["blocked", "waiting", "token", schema.as_str()] {
            assert!(
                !rendered.contains(value),
                "the log names {value}: {rendered}"
            );
        }

        holder
            .execute("SELECT pg_advisory_unlock_all()", &[])
            .await
            .expect("release the key-space locks");
        store
            .remember_offer("blocked", None, &catalog, prepared(), NOW)
            .await
            .expect("the refused offer can be created once the lock is free");
        store
            .redeem_offer_for_access_token("waiting", None, "token", &catalog, NOW)
            .await
            .expect("the refused redemption spent nothing");
    }

    /// A database error's message and detail carry values: a check violation
    /// prints the row it refused. The store logs the operation and SQLSTATE
    /// and nothing the server said, and the refusal spends nothing.
    #[tokio::test]
    async fn a_database_refusal_is_logged_by_operation_and_sqlstate_only() {
        let (deployment, store) = Deployment::open(Kind::Postgres, bounds(), Keys::default()).await;
        let schema = deployment.schema().to_owned();
        let catalog = generation("catalog-1");
        store
            .remember_offer("refused-code", None, &catalog, prepared(), NOW)
            .await
            .expect("the offer is remembered");
        let admin = admin().await;
        let offer_tag: String = admin
            .query_one(
                &format!("SELECT offer_tag FROM {schema}.offer_ledgers"),
                &[],
            )
            .await
            .expect("read the offer's tag")
            .get(0);
        // A constraint the store does not expect makes the server refuse the
        // redemption's update and name the failing row in the error.
        admin
            .batch_execute(&format!(
                "ALTER TABLE {schema}.offer_ledgers \
                 ADD CONSTRAINT refuse_every_redemption CHECK (state <> 'redeemed') NOT VALID"
            ))
            .await
            .expect("add a constraint the redemption violates");

        let (logs, _guard) = Logs::capture();
        assert_eq!(
            store
                .redeem_offer("refused-code", None, &catalog, NOW)
                .await
                .err(),
            Some(StoreError::Unavailable)
        );
        let rendered = logs.rendered();
        assert!(
            rendered.contains(r#"operation="redeem an offer" sqlstate="23514""#),
            "{rendered}"
        );
        for value in [
            offer_tag.as_str(),
            "refused-code",
            "refuse_every_redemption",
            "Failing row",
            "offer_ledgers",
            schema.as_str(),
        ] {
            assert!(
                !rendered.contains(value),
                "the log names {value}: {rendered}"
            );
        }

        admin
            .batch_execute(&format!(
                "ALTER TABLE {schema}.offer_ledgers DROP CONSTRAINT refuse_every_redemption"
            ))
            .await
            .expect("drop the constraint");
        assert_prepared(
            &store
                .redeem_offer("refused-code", None, &catalog, NOW)
                .await
                .expect("the refused redemption spent nothing"),
        );
    }

    /// A store whose tables are missing meets a real PostgreSQL error at
    /// every step, and the service answers each one with the retryable 503
    /// every store fault gets, going no further.
    #[tokio::test]
    async fn a_database_error_is_answered_as_temporarily_unavailable() {
        let store = unmigrated(
            pool(),
            &isolated_schema_name(),
            &bounds(),
            Keys::default(),
            REQUEST_TIMEOUT,
        );
        let issuer = Arc::new(CountingIssuer::new());
        let server = service_over(Arc::new(store), Arc::clone(&issuer));

        let (logs, _guard) = Logs::capture();
        let created = server
            .post(OFFERS_PATH)
            .add_header("authorization", "Bearer offer-token")
            .json(&json!({
                "credentialConfigurationId": CONFIGURATION_ID,
                "subjects": [{"role": "primary", "selectorValues": {"identifier": "subject"}}],
                "transactionCode": false,
            }))
            .await;
        let granted = server
            .post(TOKEN_PATH)
            .form(&[
                ("grant_type", PRE_AUTHORIZED_CODE_GRANT_TYPE),
                ("pre-authorized_code", "any-code"),
            ])
            .await;
        let claimed = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", "Bearer any-token")
            .json(&json!({"credential_configuration_id": CONFIGURATION_ID}))
            .await;
        for response in [&created, &granted, &claimed] {
            assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                response.json::<Value>()["error"],
                json!("temporarily_unavailable")
            );
        }
        assert_eq!(issuer.issued.load(Ordering::SeqCst), 0);
        let rendered = logs.rendered();
        for operation in [
            "size the offer key-space",
            "size the token key-space",
            "claim an access token",
        ] {
            assert!(
                rendered.contains(&format!(r#"operation="{operation}" sqlstate="42P01""#)),
                "{rendered}"
            );
        }
    }

    const CONFIGURATION_ID: &str = "urn:example:requirement:holder-bound";

    const SERVICE_CONFIG: &str = r#"
apiVersion: id.registrystack.org/formats/evidence/oid4vci-runtime/v1alpha1
kind: EvidenceOid4vciRuntimeConfig
credentialIssuer: https://wallet.example.org
listener: {bind: "127.0.0.1:8090"}
secretProviders:
  file:
    root: /run/secrets/evidence-oid4vci
audit:
  destination: stdout
  hashKeyRef: secret:file/unused-audit-hash-key
evidence:
  baseUrl: https://evidence.example.org
tokenClient:
  tokenEndpoint: https://mint.example.org/token
  clientId: evidence-oid4vci
  privateKeyRef: secret:file/unused-delivery-client.jwk.json
offers:
  issuer: https://mint.example.org
  jwksUri: https://mint.example.org/.well-known/jwks.json
  audiences: ["https://wallet.example.org"]
  algorithms: [EdDSA]
  authorizedClients: [adopter-front-end]
  requiredScopes: unrestricted
  maximumTokenLifetimeSeconds: 900
store:
  maximumOffers: 4096
  offerLifetimeSeconds: 300
  accessTokenLifetimeSeconds: 300
  nonceLifetimeSeconds: 120
  maximumTransactionCodeAttempts: 3
"#;

    const DEFINITIONS: &str = r#"{
  "schema": "registry.evidence-definitions/v1",
  "assuranceProfile": "local",
  "audience": "https://wallet.example.org",
  "issuedBy": "https://registry.example.org",
  "providedBy": "https://provider.example.org",
  "maximumHolderBoundBatchSize": 4,
  "definitions": [{
    "handle": "holder-bound",
    "requirement": "urn:example:requirement:holder-bound",
    "configurationRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "kind": "criterion",
    "subjectBindingMode": "holder-bound",
    "evidenceType": "urn:example:evidence-type:holder-bound",
    "purpose": "urn:example:purpose:demonstration",
    "responseFormats": ["sd-jwt-vc", "sd-jwt-vc-batch"],
    "referenceFrameworks": ["urn:example:framework:synthetic"],
    "subjects": [{
      "role": "primary",
      "cardinality": "one",
      "selector": {
        "profile": "synthetic-identifier-v1",
        "valueOrigin": "request",
        "fields": [{
          "type": "string",
          "name": "identifier",
          "minimumBytes": 1,
          "maximumBytes": 64
        }]
      }
    }],
    "concepts": [{"handle": "outcome", "concept": "urn:example:concept:outcome", "required": true, "form": {"type": "boolean"}}]
  }]
}"#;

    /// Lets every offer request through as the one authorized client.
    struct AnyClient;

    #[async_trait]
    impl OfferAuthorizer for AnyClient {
        async fn authorize(
            &self,
            _credential: &str,
        ) -> Result<AuthorizedOffer, AuthorizationError> {
            Ok(AuthorizedOffer {
                client: Some("adopter-front-end".to_owned()),
                subject: None,
            })
        }
    }

    /// Serves the test catalog and counts every request that reaches
    /// issuance.
    struct CountingIssuer {
        catalog: Arc<CredentialCatalog>,
        issued: AtomicUsize,
    }

    impl CountingIssuer {
        fn new() -> Self {
            let document: EvidenceDefinitionsDocument =
                serde_json::from_str(DEFINITIONS).expect("the test definitions parse");
            Self {
                catalog: Arc::new(
                    CredentialCatalog::derive(&document).expect("the catalog is valid"),
                ),
                issued: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl CredentialIssuer for CountingIssuer {
        async fn catalog(&self) -> Result<Arc<CredentialCatalog>, IssuanceError> {
            Ok(Arc::clone(&self.catalog))
        }

        async fn issue(&self, _spec: HolderBoundRequestSpec) -> Result<Vec<String>, IssuanceError> {
            self.issued.fetch_add(1, Ordering::SeqCst);
            Err(IssuanceError::Unavailable)
        }
    }

    /// The service, holding its offers in `store`.
    fn service_over(store: Arc<dyn Store>, issuer: Arc<CountingIssuer>) -> TestServer {
        // The configuration reader refuses a path through a symbolic link,
        // and the system temporary directory is one on some hosts.
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory resolves");
        let directory = tempfile::tempdir_in(base).expect("a temporary deployment directory");
        let path = directory.path().join("oid4vci.yaml");
        std::fs::write(&path, SERVICE_CONFIG).expect("write the test deployment");
        let config = DeliveryConfig::load(&path).expect("the test deployment loads");
        let audit = DeliveryAudit::with_writer(
            AuditWriter::from_line_sink(Box::new(io::sink())),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .expect("the test audit profile is valid");
        let service =
            DeliveryService::with_halves(config, Arc::new(AnyClient), issuer, Arc::new(audit))
                .with_store(store, generation("catalog-1"));
        TestServer::new(build_app(Arc::new(service)))
    }

    /// Two wrong transaction codes leave an offer one attempt from its
    /// lockout. The right code and a third wrong one then arrive together at
    /// two replicas, and exactly one of them decides the offer: either it
    /// redeems and the wrong code finds it spent, or the lockout lands and
    /// the right code finds it locked. The right code takes the token
    /// endpoint's path. The wrong one takes it too in even rounds, where the
    /// token key-space lock orders the two, and in odd rounds goes without
    /// that lock, so only the ledger row orders them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_right_code_and_the_locking_wrong_code_reach_one_outcome() {
        const ROUNDS: usize = 24;
        let (_deployment, first, second) = two_replicas(StoreConfig {
            maximum_offers: 64,
            ..bounds()
        })
        .await;
        let catalog = generation("catalog-1");
        for round in 0..ROUNDS {
            let code = format!("racing-{round}");
            first
                .remember_offer(&code, Some("4711"), &catalog, prepared(), NOW)
                .await
                .expect("the offer is remembered");
            for wrong in ["0001", "0002"] {
                assert_eq!(
                    second
                        .redeem_offer(&code, Some(wrong), &catalog, NOW)
                        .await
                        .err(),
                    Some(StoreError::TransactionCodeRefused)
                );
            }

            let start = Arc::new(Barrier::new(2));
            let right = {
                let (store, code, catalog, start) = (
                    replica(round, &first, &second),
                    code.clone(),
                    catalog.clone(),
                    Arc::clone(&start),
                );
                tokio::spawn(async move {
                    start.wait().await;
                    store
                        .redeem_offer_for_access_token(
                            &code,
                            Some("4711"),
                            &format!("right-{round}"),
                            &catalog,
                            NOW,
                        )
                        .await
                })
            };
            let wrong = {
                let (store, code, catalog, start) = (
                    replica(round + 1, &first, &second),
                    code.clone(),
                    catalog.clone(),
                    Arc::clone(&start),
                );
                tokio::spawn(async move {
                    start.wait().await;
                    if round.is_multiple_of(2) {
                        store
                            .redeem_offer_for_access_token(
                                &code,
                                Some("0003"),
                                &format!("wrong-{round}"),
                                &catalog,
                                NOW,
                            )
                            .await
                    } else {
                        store
                            .redeem_offer(&code, Some("0003"), &catalog, NOW)
                            .await
                            .map(|_| ())
                    }
                })
            };
            let right = right.await.expect("the right code's task joins");
            let wrong = wrong.await.expect("the wrong code's task joins");

            let claimed = first
                .claim_access_token(&format!("right-{round}"), &catalog, NOW)
                .await;
            match (right, wrong) {
                (Ok(()), Err(StoreError::AlreadyRedeemed)) => {
                    assert_prepared(&claimed.expect("the redeemed offer's request is bound"));
                }
                (Err(StoreError::LockedOut), Err(StoreError::TransactionCodeRefused)) => {
                    assert_eq!(claimed.err(), Some(StoreError::Unknown));
                    assert_eq!(
                        second
                            .redeem_offer(&code, Some("4711"), &catalog, NOW)
                            .await
                            .err(),
                        Some(StoreError::LockedOut)
                    );
                }
                (right, wrong) => {
                    panic!("round {round}: the right code got {right:?}, the wrong one {wrong:?}")
                }
            }
            assert_eq!(
                second
                    .claim_access_token(&format!("wrong-{round}"), &catalog, NOW)
                    .await
                    .err(),
                Some(StoreError::Unknown),
                "a wrong code never binds a token"
            );
        }
    }

    /// Every row in `schema`, in a stable order.
    async fn at_rest(schema: &str) -> Vec<(String, String)> {
        let mut rows = dump(schema).await;
        rows.sort();
        rows
    }

    /// Await `operation`, failing the test rather than hanging it when the
    /// store waits without bound.
    async fn within_the_test_bound<T>(operation: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), operation)
            .await
            .expect("the store answers rather than waiting on a held lock")
    }

    const SELECTOR: &str = "canary-selector-7f3a9c";
    const SECOND_SELECTOR: &str = "canary-birthdate-1984-02-29";
    const EXCHANGE: &str = "canary-exchange-77aa";
    const KIND: &str = "urn:canary:kind-4b1d";
    const CODE: &str = "canary-offer-secret-51be";
    const TRANSACTION_CODE: &str = "canary-tx-8812";
    const TOKEN: &str = "canary-access-token-c0de";
    const LOCKED_CODE: &str = "canary-locked-offer-93e1";

    fn canaries() -> [&'static str; 8] {
        [
            SELECTOR,
            SECOND_SELECTOR,
            EXCHANGE,
            KIND,
            CODE,
            TRANSACTION_CODE,
            TOKEN,
            LOCKED_CODE,
        ]
    }

    fn canary_request() -> PreparedRequest {
        PreparedRequest::new(
            EXCHANGE,
            KIND,
            &format!(
                r#"{{"selector":{{"nationalId":"{SELECTOR}","birthDate":"{SECOND_SELECTOR}"}}}}"#
            ),
            2,
        )
    }

    fn hex(value: &str) -> String {
        value.bytes().map(|byte| format!("{byte:02x}")).collect()
    }

    async fn assert_no_canary_at_rest(schema: &str, moment: &str) {
        let rows = dump(schema).await;
        for (table, row) in &rows {
            for canary in canaries() {
                assert!(
                    !row.contains(canary),
                    "{moment}: {table} holds {canary} in plaintext"
                );
                assert!(
                    !row.contains(&hex(canary)),
                    "{moment}: {table} holds {canary} as plaintext bytes"
                );
            }
        }
    }

    #[tokio::test]
    async fn prepared_requests_are_sealed_at_rest_and_gone_after_claim_lockout_and_expiry() {
        let (deployment, store) = Deployment::open(Kind::Postgres, bounds(), Keys::default()).await;
        let schema = deployment.schema().to_owned();
        let catalog = generation("catalog-1");

        store
            .remember_offer(
                CODE,
                Some(TRANSACTION_CODE),
                &catalog,
                canary_request(),
                NOW,
            )
            .await
            .expect("the offer is remembered");
        assert_eq!(count(&schema, "offers").await, 1);
        assert_no_canary_at_rest(&schema, "after the offer is created").await;

        store
            .redeem_offer_for_access_token(CODE, Some(TRANSACTION_CODE), TOKEN, &catalog, NOW)
            .await
            .expect("the offer redeems for an access token");
        assert_eq!(
            count(&schema, "offers").await,
            0,
            "the redeemed offer row is gone"
        );
        assert_eq!(count(&schema, "access_tokens").await, 1);
        assert_no_canary_at_rest(&schema, "after the offer is redeemed").await;

        let claimed = store
            .claim_access_token(TOKEN, &catalog, NOW)
            .await
            .expect("the token claims once");
        assert_eq!(claimed.exchange_id(), EXCHANGE);
        assert_eq!(claimed.kind(), KIND);
        assert!(claimed.body().contains(SELECTOR));
        assert_eq!(
            count(&schema, "access_tokens").await,
            0,
            "the claimed token row is gone"
        );
        assert_no_canary_at_rest(&schema, "after the token is claimed").await;

        // An offer locked out by wrong transaction codes can never be opened,
        // so its sealed request goes with the attempt that locks it, and only
        // the ledger stays to keep refusing the right code.
        store
            .remember_offer(
                LOCKED_CODE,
                Some(TRANSACTION_CODE),
                &catalog,
                canary_request(),
                NOW,
            )
            .await
            .expect("the offer is remembered");
        assert_eq!(count(&schema, "offers").await, 1);
        for wrong in ["wrong-1", "wrong-2", "wrong-3"] {
            assert_eq!(
                store
                    .redeem_offer(LOCKED_CODE, Some(wrong), &catalog, NOW)
                    .await
                    .err(),
                Some(StoreError::TransactionCodeRefused)
            );
        }
        assert_eq!(
            count(&schema, "offers").await,
            0,
            "the locked-out offer's sealed request is gone"
        );
        assert_eq!(
            store
                .redeem_offer(LOCKED_CODE, Some(TRANSACTION_CODE), &catalog, NOW)
                .await
                .err(),
            Some(StoreError::LockedOut),
            "the ledger keeps the lockout standing"
        );
        assert_no_canary_at_rest(&schema, "after the offer is locked out").await;

        store
            .remember_offer(
                "expiring-code",
                Some(TRANSACTION_CODE),
                &catalog,
                canary_request(),
                NOW,
            )
            .await
            .expect("the offer is remembered");
        store
            .bind_access_token("expiring-token", &catalog, canary_request(), NOW)
            .await
            .expect("the token is bound");
        assert_no_canary_at_rest(&schema, "before the purge").await;
        assert_eq!(
            store.sweep(NOW + LIFETIME).await,
            5,
            "three offers' ledgers, one offer, one token"
        );
        for table in ["offers", "offer_ledgers", "access_tokens"] {
            assert_eq!(count(&schema, table).await, 0, "{table} after expiry");
        }
    }

    /// A transaction code is tagged together with the offer it guards, so
    /// two offers that carry the same code hold different tags, and a reader
    /// of the table cannot tell which offers share a code.
    #[tokio::test]
    async fn one_transaction_code_tags_differently_on_every_offer() {
        let (deployment, store) = Deployment::open(Kind::Postgres, bounds(), Keys::default()).await;
        let schema = deployment.schema().to_owned();
        let catalog = generation("catalog-1");
        for code in ["first-offer", "second-offer"] {
            store
                .remember_offer(code, Some("4711"), &catalog, prepared(), NOW)
                .await
                .expect("the offer is remembered");
        }
        let tags: Vec<String> = admin()
            .await
            .query(
                &format!("SELECT transaction_code_tag FROM {schema}.offers"),
                &[],
            )
            .await
            .expect("read the transaction code tags")
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(tags.len(), 2);
        assert_ne!(tags[0], tags[1], "two offers share a transaction code tag");
        for code in ["first-offer", "second-offer"] {
            assert_prepared(
                &store
                    .redeem_offer(code, Some("4711"), &catalog, NOW)
                    .await
                    .expect("the right code still opens each offer"),
            );
        }
    }

    #[tokio::test]
    async fn a_sealed_request_moved_to_another_row_is_refused() {
        let (deployment, store) = Deployment::open(Kind::Postgres, bounds(), Keys::default()).await;
        let schema = deployment.schema().to_owned();
        let catalog = generation("catalog-1");
        store
            .remember_offer("donor", None, &catalog, canary_request(), NOW)
            .await
            .expect("the donor offer is remembered");
        store
            .remember_offer("target", None, &catalog, prepared(), NOW)
            .await
            .expect("the target offer is remembered");

        // Someone with write access to the database copies one offer's sealed
        // request onto the other offer's row. Which row receives it depends on
        // how the tags sort, so the assertions below accept either. The seal is
        // bound to the tag of the row it was made for, so the receiving row
        // refuses to open it rather than serving another offer's request.
        let moved = admin()
            .await
            .execute(
                &format!(
                    "UPDATE {schema}.offers AS target \
                     SET prepared_nonce = donor.prepared_nonce, \
                         prepared_ciphertext = donor.prepared_ciphertext \
                     FROM {schema}.offers AS donor \
                     WHERE target.offer_tag <> donor.offer_tag \
                       AND target.offer_tag = (SELECT min(offer_tag) FROM {schema}.offers)"
                ),
                &[],
            )
            .await
            .expect("move a sealed request");
        assert_eq!(moved, 1);

        let mut refused = 0;
        for code in ["donor", "target"] {
            match store.redeem_offer(code, None, &catalog, NOW).await {
                Ok(request) if request.exchange_id() == EXCHANGE => {
                    assert_ne!(code, "target", "the target served the donor's request");
                }
                Ok(request) => assert_prepared(&request),
                Err(error) => {
                    assert_eq!(error, StoreError::Unavailable);
                    refused += 1;
                }
            }
        }
        assert_eq!(refused, 1, "exactly the row carrying a moved seal refuses");
    }

    #[tokio::test]
    async fn sealing_keys_rotate_like_tagging_keys() {
        let sealed_under = |sealing: Ring| Keys {
            tags: Ring::of(TAG_ONE),
            sealing,
        };
        let (deployment, first) =
            Deployment::open(Kind::Postgres, bounds(), sealed_under(Ring::of(SEAL_ONE))).await;
        let catalog = generation("catalog-1");
        for code in ["code-a", "code-b"] {
            first
                .remember_offer(code, None, &catalog, prepared(), NOW)
                .await
                .expect("the offer is sealed under the first key");
        }

        let rotated = deployment
            .reopen(sealed_under(Ring::rotated(SEAL_TWO, SEAL_ONE)))
            .await;
        assert_prepared(
            &rotated
                .redeem_offer("code-a", None, &catalog, NOW)
                .await
                .expect("a request sealed under the previous key opens"),
        );
        rotated
            .remember_offer("code-c", None, &catalog, prepared(), NOW)
            .await
            .expect("the offer is sealed under the current key");

        let retired = deployment
            .reopen(sealed_under(Ring::rotated(SEAL_THREE, SEAL_TWO)))
            .await;
        assert_eq!(
            retired
                .redeem_offer("code-b", None, &catalog, NOW)
                .await
                .err(),
            Some(StoreError::Unknown),
            "a request sealed under a retired key is unreachable"
        );
        assert_prepared(
            &retired
                .redeem_offer("code-c", None, &catalog, NOW)
                .await
                .expect("a request sealed under the previous key opens"),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn migrating_again_or_concurrently_applies_nothing_twice() {
        let (deployment, _first) =
            Deployment::open(Kind::Postgres, bounds(), Keys::default()).await;
        // Each reopen migrates over a pool of its own, so these four race at
        // the database rather than taking turns in this task.
        tokio::join!(
            deployment.reopen(Keys::default()),
            deployment.reopen(Keys::default()),
            deployment.reopen(Keys::default()),
            deployment.reopen(Keys::default()),
        );
        assert_eq!(
            count(deployment.schema(), "oid4vci_schema_migrations").await,
            1
        );
    }

    /// Replicas installed together all find an empty database. Their first
    /// migrations race to create the same schema and tables, which only the
    /// migration lock keeps from colliding. Several fresh schemas are raced,
    /// each from four replicas whose connections are open before the start.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn first_migrations_of_a_fresh_schema_serialize() {
        const REPLICAS: usize = 4;
        for _ in 0..8 {
            let schema = isolated_schema_name();
            let start = Arc::new(Barrier::new(REPLICAS));
            let mut replicas = Vec::new();
            for _ in 0..REPLICAS {
                let pool = pool();
                drop(pool.get().await.expect("open a replica's connection"));
                let store = unmigrated(pool, &schema, &bounds(), Keys::default(), REQUEST_TIMEOUT);
                let start = Arc::clone(&start);
                replicas.push(tokio::spawn(async move {
                    start.wait().await;
                    store.migrate().await
                }));
            }
            let outcomes = join(replicas).await;
            assert!(
                outcomes.iter().all(Result::is_ok),
                "every first migration succeeds: {outcomes:?}"
            );
            assert_eq!(count(&schema, "oid4vci_schema_migrations").await, 1);
        }
    }

    /// A schema a later build migrated is refused rather than served by a
    /// build that does not know its shape, and the refusal is logged with the
    /// version it found and nothing else.
    #[tokio::test]
    async fn a_schema_carrying_an_unknown_migration_is_refused() {
        let (deployment, _store) =
            Deployment::open(Kind::Postgres, bounds(), Keys::default()).await;
        let schema = deployment.schema().to_owned();
        admin()
            .await
            .execute(
                &format!("INSERT INTO {schema}.oid4vci_schema_migrations (version) VALUES (999)"),
                &[],
            )
            .await
            .expect("record a migration from a later build");

        let (logs, _guard) = Logs::capture();
        let refused = unmigrated(pool(), &schema, &bounds(), Keys::default(), REQUEST_TIMEOUT)
            .migrate()
            .await;
        assert!(
            matches!(refused, Err(PostgresSetupError::SchemaVersion(999))),
            "{refused:?}"
        );
        let rendered = logs.rendered();
        assert!(
            rendered.contains(r#"operation="check the applied migrations" version=999"#),
            "{rendered}"
        );
        assert!(!rendered.contains(&schema), "{rendered}");
    }

    /// A migration table of the store's name that another tool made, with
    /// versions this build cannot read, is refused rather than read.
    #[tokio::test]
    async fn a_migration_table_this_store_did_not_make_is_refused() {
        let schema = isolated_schema_name();
        admin()
            .await
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; \
                 CREATE TABLE {schema}.oid4vci_schema_migrations (version varchar PRIMARY KEY); \
                 INSERT INTO {schema}.oid4vci_schema_migrations VALUES ('20240101000000');"
            ))
            .await
            .expect("leave another tool's migration table in the schema");

        let (logs, _guard) = Logs::capture();
        let refused = unmigrated(pool(), &schema, &bounds(), Keys::default(), REQUEST_TIMEOUT)
            .migrate()
            .await;
        assert!(
            matches!(refused, Err(PostgresSetupError::MigrationTable)),
            "{refused:?}"
        );
        let rendered = logs.rendered();
        assert!(
            rendered.contains(r#"operation="read the applied migrations""#),
            "{rendered}"
        );
        assert!(!rendered.contains("20240101000000"), "{rendered}");
    }

    /// A pool that cannot sign in, or that has been closed, refuses as
    /// unavailable. The log names the cause and the server's SQLSTATE, so an
    /// operator can tell a rejected password from a timeout, and never what
    /// the server said.
    #[tokio::test]
    async fn a_connection_failure_is_logged_by_its_cause_only() {
        let catalog = generation("catalog-1");
        let rejected = unmigrated(
            pool_with_password("not-the-server-secret"),
            &isolated_schema_name(),
            &bounds(),
            Keys::default(),
            REQUEST_TIMEOUT,
        );
        let closed_pool = pool();
        closed_pool.close();
        let closed = unmigrated(
            closed_pool,
            &isolated_schema_name(),
            &bounds(),
            Keys::default(),
            REQUEST_TIMEOUT,
        );

        let (logs, _guard) = Logs::capture();
        let migration = rejected.migrate().await;
        assert!(
            matches!(migration, Err(PostgresSetupError::Unreachable)),
            "{migration:?}"
        );
        assert_eq!(
            rejected
                .redeem_offer("any-code", None, &catalog, NOW)
                .await
                .err(),
            Some(StoreError::Unavailable)
        );
        assert_eq!(
            closed
                .redeem_offer("any-code", None, &catalog, NOW)
                .await
                .err(),
            Some(StoreError::Unavailable)
        );
        let rendered = logs.rendered();
        assert_eq!(
            rendered
                .matches(r#"cause="connect" sqlstate="28P01""#)
                .count(),
            2,
            "{rendered}"
        );
        assert!(
            rendered.contains(r#"cause="closed" sqlstate="none""#),
            "{rendered}"
        );
        for value in [
            "not-the-server-secret",
            "password",
            "authentication",
            "user",
        ] {
            assert!(
                !rendered.contains(value),
                "the log names {value}: {rendered}"
            );
        }
    }

    async fn join<T: Send + 'static>(handles: Vec<tokio::task::JoinHandle<T>>) -> Vec<T> {
        let mut outcomes = Vec::with_capacity(handles.len());
        for handle in handles {
            outcomes.push(handle.await.expect("a contender task joins"));
        }
        outcomes
    }
}
