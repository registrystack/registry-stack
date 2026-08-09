//! The bounded, in-memory state a delivery flow needs between its steps.
//!
//! An offer is created, redeemed for an access token, and the token is claimed
//! for a credential. Each step happens in a separate request, so something has
//! to carry the prepared request forward. That something is this store, and it
//! is deliberately the smallest thing that works: one process, one mutex, three
//! key-spaces, everything bounded and everything expiring in minutes.
//!
//! Three properties are load-bearing.
//!
//! 1. **Nothing is keyed by the secret it stands for.** Every key is an HMAC tag
//!    under a random per-process key, so what the store holds identifies an
//!    entry without being usable as the credential that reaches it. Tags from
//!    one process mean nothing in another.
//! 2. **Saturation fails closed.** A full store refuses a new offer rather than
//!    evicting a live one. Evicting would turn a load spike into a silent denial
//!    for whoever was already holding an offer, which is the harder failure to
//!    see and the one a caller cannot retry out of.
//! 3. **A transaction code lockout outlives the request it refused.** The
//!    failure count lives as long as the offer does, in its own key-space, so a
//!    caller cannot reset it by abandoning a request.
//!
//! `c_nonce` is deliberately absent. It is minted as an HMAC over its own
//! expiry and verified by recomputation, so a wallet's nonce costs the process
//! no memory and cannot be exhausted by asking for more. See [`NonceMinter`].
//!
//! The consequences of holding all of this in one process are real and are
//! accepted rather than engineered around: a restart invalidates every
//! outstanding offer, and single use is enforced per process, so a second
//! replica would not see the first one's spent codes. A single replica is the
//! deployment this service supports.

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
};

use registry_evidence_verifier::redacted_debug;
use registry_platform_crypto::hmac_sha256_base64url_no_pad;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::StoreConfig;

/// Domain labels, so a value that is a valid key in one key-space cannot be
/// replayed as a key in another.
const OFFER_DOMAIN: &str = "oid4vci.offer";
const TRANSACTION_CODE_DOMAIN: &str = "oid4vci.transaction-code";
const ACCESS_TOKEN_DOMAIN: &str = "oid4vci.access-token";
const NONCE_DOMAIN: &str = "oid4vci.nonce";

#[derive(Debug, Error, Eq, PartialEq)]
pub enum StoreError {
    #[error("the store lock is poisoned")]
    Poisoned,
    #[error("the store is full")]
    Saturated,
    #[error("no live entry")]
    Unknown,
    #[error("the entry was already redeemed")]
    AlreadyRedeemed,
    #[error("the transaction code was refused")]
    TransactionCodeRefused,
    #[error("too many transaction code attempts")]
    LockedOut,
}

/// The Evidence request an offer was created for.
///
/// Prepared once, when the adopter creates the offer, and carried unchanged to
/// the moment Evidence is called. Nothing between those two points may alter
/// it: the wallet's contribution to the exchange is a proof of key possession,
/// never a say in what is being requested.
#[derive(Zeroize, ZeroizeOnDrop)]
// Equality exists for the tests that assert on a whole redemption result. It is
// deliberately not part of the shipped surface: nothing in the service compares
// two prepared requests, and a derived comparison over held values is not one
// this type should invite.
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct PreparedRequest {
    kind: String,
    body: String,
}

redacted_debug!(PreparedRequest);

impl PreparedRequest {
    #[must_use]
    pub fn new(kind: &str, body: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            body: body.to_owned(),
        }
    }

    /// The Evidence assertion kind this offer will request.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The request body Evidence will receive, exactly as it was prepared.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }
}

/// What the store keeps about an offer that has not been redeemed yet.
struct OfferEntry {
    prepared: PreparedRequest,
    /// The tag of the transaction code the offer was created with, if any.
    /// The code itself is never held.
    transaction_code_tag: Option<Zeroizing<String>>,
    expires_at: i64,
}

/// What the store keeps about an offer for the whole of its life, whether or not
/// the offer itself is still redeemable.
///
/// Separate from [`OfferEntry`] on purpose. A failure count that lived inside
/// the offer would be forgotten the moment the offer was dropped, and dropping
/// the offer is exactly what a lockout does. Keeping the ledger to the offer's
/// original expiry is what makes "three wrong codes" mean three for this offer
/// rather than three per attempt at guessing.
struct OfferLedger {
    failures: u32,
    redeemed: bool,
    locked_out: bool,
    expires_at: i64,
}

/// What the store keeps between a redeemed offer and the credential request.
struct TokenEntry {
    prepared: PreparedRequest,
    expires_at: i64,
}

#[derive(Default)]
struct StoreState {
    offers: HashMap<String, OfferEntry>,
    ledgers: HashMap<String, OfferLedger>,
    tokens: HashMap<String, TokenEntry>,
}

impl StoreState {
    fn prune(&mut self, now: i64) {
        self.offers.retain(|_, entry| entry.expires_at > now);
        self.ledgers.retain(|_, ledger| ledger.expires_at > now);
        self.tokens.retain(|_, entry| entry.expires_at > now);
    }
}

/// The whole of the service's memory.
pub struct OfferStore {
    capacity: usize,
    offer_lifetime_seconds: i64,
    access_token_lifetime_seconds: i64,
    maximum_transaction_code_attempts: u32,
    /// The per-process tagging key. Random, never persisted, wiped on drop.
    key: Zeroizing<[u8; 32]>,
    state: Mutex<StoreState>,
}

impl std::fmt::Debug for OfferStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held = self.state.lock().map(|state| state.offers.len()).ok();
        formatter
            .debug_struct("OfferStore")
            .field("capacity", &self.capacity)
            .field("offers", &held)
            .finish_non_exhaustive()
    }
}

impl OfferStore {
    /// Build a store over the configured bounds, with a fresh tagging key.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG is unavailable. On the supported targets that
    /// happens only in catastrophic conditions, and a delivery service that
    /// tagged its state with a predictable key would be worse than one that
    /// refused to start.
    #[must_use]
    pub fn new(config: &StoreConfig) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut_slice()).expect("the OS CSPRNG must be available at startup");
        Self {
            capacity: config.maximum_offers,
            offer_lifetime_seconds: config.offer_lifetime_seconds as i64,
            access_token_lifetime_seconds: config.access_token_lifetime_seconds as i64,
            maximum_transaction_code_attempts: config.maximum_transaction_code_attempts,
            key,
            state: Mutex::new(StoreState::default()),
        }
    }

    /// Tag a secret for one key-space. The result identifies an entry and is
    /// useless as the secret it stands for.
    fn tag(&self, domain: &str, secret: &str) -> Zeroizing<String> {
        let mut input = Zeroizing::new(String::with_capacity(domain.len() + secret.len() + 1));
        input.push_str(domain);
        input.push('\u{0}');
        input.push_str(secret);
        Zeroizing::new(hmac_sha256_base64url_no_pad(
            self.key.as_ref(),
            input.as_bytes(),
        ))
    }

    /// Remember a prepared request against a fresh pre-authorized code.
    ///
    /// Both key-spaces are sized before either is written, so a store that
    /// cannot hold the ledger never holds a half-created offer.
    pub fn remember_offer(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        prepared: PreparedRequest,
        now: i64,
    ) -> Result<(), StoreError> {
        let offer_tag = self.tag(OFFER_DOMAIN, code);
        let transaction_code_tag =
            transaction_code.map(|value| self.tag(TRANSACTION_CODE_DOMAIN, value));
        let expires_at = now.saturating_add(self.offer_lifetime_seconds);

        let mut state = self.lock()?;
        state.prune(now);
        if state.offers.contains_key(offer_tag.as_str())
            || state.ledgers.contains_key(offer_tag.as_str())
        {
            return Err(StoreError::AlreadyRedeemed);
        }
        if state.offers.len() >= self.capacity || state.ledgers.len() >= self.capacity {
            return Err(StoreError::Saturated);
        }
        state.offers.insert(
            offer_tag.to_string(),
            OfferEntry {
                prepared,
                transaction_code_tag,
                expires_at,
            },
        );
        state.ledgers.insert(
            offer_tag.to_string(),
            OfferLedger {
                failures: 0,
                redeemed: false,
                locked_out: false,
                expires_at,
            },
        );
        Ok(())
    }

    /// Redeem a pre-authorized code once, handing back the request it was
    /// created for.
    ///
    /// The store's copy is removed, and zeroized, before this returns. A wrong
    /// transaction code is counted against the offer's own ceiling; exhausting
    /// it drops the prepared request and leaves the refusal standing for the
    /// rest of the offer's life.
    pub fn redeem_offer(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        now: i64,
    ) -> Result<PreparedRequest, StoreError> {
        let mut state = self.lock()?;
        self.redeem_locked(&mut state, code, transaction_code, now)
    }

    fn redeem_locked(
        &self,
        state: &mut StoreState,
        code: &str,
        transaction_code: Option<&str>,
        now: i64,
    ) -> Result<PreparedRequest, StoreError> {
        let offer_tag = self.tag(OFFER_DOMAIN, code);
        let presented_tag = transaction_code.map(|value| self.tag(TRANSACTION_CODE_DOMAIN, value));

        let Some(ledger) = state.ledgers.get(offer_tag.as_str()) else {
            return Err(StoreError::Unknown);
        };
        if ledger.expires_at <= now {
            return Err(StoreError::Unknown);
        }
        if ledger.redeemed {
            return Err(StoreError::AlreadyRedeemed);
        }
        if ledger.locked_out {
            return Err(StoreError::LockedOut);
        }

        let Some(entry) = state.offers.get(offer_tag.as_str()) else {
            return Err(StoreError::Unknown);
        };
        if entry.expires_at <= now {
            return Err(StoreError::Unknown);
        }

        if !transaction_code_matches(
            entry.transaction_code_tag.as_deref(),
            presented_tag.as_deref(),
        ) {
            // Counted against the offer, then dropped whole once the ceiling is
            // reached: an offer nobody can open is not worth keeping open.
            let ledger = state
                .ledgers
                .get_mut(offer_tag.as_str())
                .ok_or(StoreError::Unknown)?;
            ledger.failures = ledger.failures.saturating_add(1);
            if ledger.failures >= self.maximum_transaction_code_attempts {
                ledger.locked_out = true;
                state.offers.remove(offer_tag.as_str());
            }
            return Err(StoreError::TransactionCodeRefused);
        }

        let entry = state
            .offers
            .remove(offer_tag.as_str())
            .ok_or(StoreError::Unknown)?;
        let ledger = state
            .ledgers
            .get_mut(offer_tag.as_str())
            .ok_or(StoreError::Unknown)?;
        ledger.redeemed = true;
        Ok(entry.prepared)
    }

    /// Redeem a pre-authorized code and carry its request forward under the
    /// access token it was exchanged for, as one step.
    ///
    /// One lock and one decision, because the two halves cannot be undone
    /// independently: a redeemed offer is gone, so a bind that failed after one
    /// would leave a caller holding a code it can never redeem again and a
    /// refusal that invites it to try. The token key-space is sized before the
    /// offer is spent, so a saturated store refuses having changed nothing.
    pub fn redeem_offer_for_access_token(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        access_token: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut state = self.lock()?;
        self.reserve_token_room(&mut state, access_token, now)?;
        let prepared = self.redeem_locked(&mut state, code, transaction_code, now)?;
        self.bind_locked(&mut state, access_token, prepared, now)
    }

    /// Carry a redeemed offer's request forward under the access token that was
    /// issued for it.
    pub fn bind_access_token(
        &self,
        access_token: &str,
        prepared: PreparedRequest,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut state = self.lock()?;
        self.bind_locked(&mut state, access_token, prepared, now)
    }

    /// Answer whether the token key-space can take this token, without writing
    /// anything to it.
    fn reserve_token_room(
        &self,
        state: &mut StoreState,
        access_token: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let token_tag = self.tag(ACCESS_TOKEN_DOMAIN, access_token);
        state.prune(now);
        if state.tokens.contains_key(token_tag.as_str()) {
            return Err(StoreError::AlreadyRedeemed);
        }
        if state.tokens.len() >= self.capacity {
            return Err(StoreError::Saturated);
        }
        Ok(())
    }

    fn bind_locked(
        &self,
        state: &mut StoreState,
        access_token: &str,
        prepared: PreparedRequest,
        now: i64,
    ) -> Result<(), StoreError> {
        let token_tag = self.tag(ACCESS_TOKEN_DOMAIN, access_token);
        let expires_at = now.saturating_add(self.access_token_lifetime_seconds);

        self.reserve_token_room(state, access_token, now)?;
        state.tokens.insert(
            token_tag.to_string(),
            TokenEntry {
                prepared,
                expires_at,
            },
        );
        Ok(())
    }

    /// Claim an access token once, handing back the request it carries.
    ///
    /// The store's copy is removed, and zeroized, before this returns, so a
    /// replayed token finds nothing to claim.
    pub fn claim_access_token(
        &self,
        access_token: &str,
        now: i64,
    ) -> Result<PreparedRequest, StoreError> {
        let token_tag = self.tag(ACCESS_TOKEN_DOMAIN, access_token);

        let mut state = self.lock()?;
        let Some(entry) = state.tokens.get(token_tag.as_str()) else {
            return Err(StoreError::Unknown);
        };
        if entry.expires_at <= now {
            return Err(StoreError::Unknown);
        }
        let entry = state
            .tokens
            .remove(token_tag.as_str())
            .ok_or(StoreError::Unknown)?;
        Ok(entry.prepared)
    }

    /// Drop everything that has expired.
    ///
    /// Writes prune as they go, so this exists for the quiet deployment: one
    /// that stops receiving requests must not keep the last minutes of state in
    /// memory indefinitely.
    pub fn sweep(&self, now: i64) {
        // A poisoned lock means a panic already happened while state was being
        // changed. There is nothing safe to prune and nothing to report to, so
        // the sweep skips this round; every read and write still fails loudly.
        if let Ok(mut state) = self.state.lock() {
            state.prune(now);
        }
    }

    /// How many entries the store holds, across every key-space.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.offers.len() + state.ledgers.len() + state.tokens.len())
            .unwrap_or(0)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, StoreState>, StoreError> {
        self.state.lock().map_err(|_: PoisonError<_>| {
            // A panic while the state was being changed leaves the store's
            // single-use guarantees unproven. Refusing every later call is the
            // only answer that cannot issue twice.
            StoreError::Poisoned
        })
    }

    /// Every key the store currently holds, for tests that prove those keys are
    /// tags rather than the secrets they stand for.
    #[cfg(test)]
    fn held_key_material(&self) -> Vec<String> {
        let state = self.state.lock().expect("the store lock is not poisoned");
        let mut held: Vec<String> = state
            .offers
            .iter()
            .map(|(tag, entry)| {
                format!(
                    "{tag}{}",
                    entry
                        .transaction_code_tag
                        .as_deref()
                        .cloned()
                        .unwrap_or_default()
                )
            })
            .chain(state.ledgers.keys().cloned())
            .chain(state.tokens.keys().cloned())
            .collect();
        held.sort();
        held
    }
}

/// Compare the transaction code an offer carries with the one presented.
///
/// Constant time over the tags, and an offer that carries no code refuses one:
/// accepting a code nobody asked for would let a caller learn which offers are
/// protected by watching which refusals it gets.
fn transaction_code_matches(expected: Option<&String>, presented: Option<&String>) -> bool {
    match (expected, presented) {
        (None, None) => true,
        (Some(expected), Some(presented)) => expected.as_bytes().ct_eq(presented.as_bytes()).into(),
        _ => false,
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum NonceError {
    #[error("the nonce is not a nonce this process minted")]
    Refused,
    #[error("the nonce has expired")]
    Expired,
}

/// The `c_nonce` a wallet must echo inside its proof of key possession.
///
/// Nothing is stored. A nonce is its own expiry plus an HMAC over that expiry,
/// so verification is a recomputation and a comparison. That is the whole
/// reason to do it this way: an endpoint that hands out nonces on request is an
/// endpoint an unauthenticated caller can use to fill memory, and a nonce
/// nobody remembers cannot be exhausted.
///
/// It is a freshness challenge and nothing more. OpenID4VCI 1.0 Final gives the
/// nonce endpoint no authorization, so a nonce is minted for a caller this
/// process cannot name and can be bound to no credential of one. What bounds
/// replay is the access token behind the proof: it is claimed once, and each
/// proof binds the wallet's own key, so a nonce presented a second time returns
/// the same holder the same credential and reaches nothing else.
pub struct NonceMinter {
    lifetime_seconds: i64,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for NonceMinter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NonceMinter")
            .field("lifetimeSeconds", &self.lifetime_seconds)
            .finish_non_exhaustive()
    }
}

impl NonceMinter {
    /// # Panics
    ///
    /// Panics if the OS CSPRNG is unavailable, for the same reason
    /// [`OfferStore::new`] does.
    #[must_use]
    pub fn new(lifetime_seconds: u64) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut_slice()).expect("the OS CSPRNG must be available at startup");
        Self {
            lifetime_seconds: lifetime_seconds as i64,
            key,
        }
    }

    #[must_use]
    pub fn mint(&self, now: i64) -> String {
        let expires_at = now.saturating_add(self.lifetime_seconds);
        let tag = self.tag(expires_at);
        format!("{expires_at}.{tag}")
    }

    /// Verify a nonce by recomputing it. Never reads a stored value, because
    /// there is none.
    pub fn verify(&self, nonce: &str, now: i64) -> Result<(), NonceError> {
        let (expiry, presented) = nonce.split_once('.').ok_or(NonceError::Refused)?;
        let expires_at: i64 = expiry.parse().map_err(|_| NonceError::Refused)?;
        let expected = self.tag(expires_at);
        // The MAC is checked before the expiry, so a caller cannot learn
        // anything about a nonce it did not receive by reading the refusal.
        let matches: bool = expected.as_bytes().ct_eq(presented.as_bytes()).into();
        if !matches {
            return Err(NonceError::Refused);
        }
        if expires_at <= now {
            return Err(NonceError::Expired);
        }
        Ok(())
    }

    fn tag(&self, expires_at: i64) -> String {
        let input = format!("{NONCE_DOMAIN}\u{0}{expires_at}");
        hmac_sha256_base64url_no_pad(self.key.as_ref(), input.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::StoreConfig;

    const NOW: i64 = 1_700_000_000;

    fn bounds() -> StoreConfig {
        StoreConfig::default()
    }

    fn prepared() -> PreparedRequest {
        PreparedRequest::new("urn:example:kind", r#"{"selector":"held-by-the-adopter"}"#)
    }

    fn store() -> OfferStore {
        OfferStore::new(&bounds())
    }

    #[test]
    fn a_redeemed_pre_authorized_code_is_refused_on_reuse() {
        let store = store();
        store
            .remember_offer("code-1", None, prepared(), NOW)
            .expect("the offer is remembered");

        let claimed = store
            .redeem_offer("code-1", None, NOW)
            .expect("the offer redeems once");
        assert_eq!(claimed.kind(), "urn:example:kind");

        assert_eq!(
            store.redeem_offer("code-1", None, NOW),
            Err(StoreError::AlreadyRedeemed)
        );
    }

    #[test]
    fn a_claimed_access_token_is_refused_on_reuse() {
        let store = store();
        store
            .bind_access_token("token-1", prepared(), NOW)
            .expect("the token is bound");

        store
            .claim_access_token("token-1", NOW)
            .expect("the token claims once");
        assert_eq!(
            store.claim_access_token("token-1", NOW),
            Err(StoreError::Unknown)
        );
    }

    #[test]
    fn saturation_fails_closed_instead_of_evicting_a_live_offer() {
        let mut bounds = bounds();
        bounds.maximum_offers = 256;
        let store = OfferStore::new(&bounds);
        for index in 0..256 {
            store
                .remember_offer(&format!("code-{index}"), None, prepared(), NOW)
                .expect("the offer is remembered");
        }

        assert_eq!(
            store.remember_offer("code-256", None, prepared(), NOW),
            Err(StoreError::Saturated)
        );
        // The refusal must not have cost an offer somebody is still holding.
        store
            .redeem_offer("code-0", None, NOW)
            .expect("the first offer is still live");
        assert_eq!(
            store.redeem_offer("code-256", None, NOW),
            Err(StoreError::Unknown)
        );
    }

    #[test]
    fn saturation_fails_closed_for_access_tokens_too() {
        let mut bounds = bounds();
        bounds.maximum_offers = 256;
        let store = OfferStore::new(&bounds);
        for index in 0..256 {
            store
                .bind_access_token(&format!("token-{index}"), prepared(), NOW)
                .expect("the token is bound");
        }

        assert_eq!(
            store.bind_access_token("token-256", prepared(), NOW),
            Err(StoreError::Saturated)
        );
        store
            .claim_access_token("token-0", NOW)
            .expect("the first token is still live");
    }

    /// A saturated token key-space must not cost the caller its offer.
    ///
    /// Redeeming and binding are one step because the refusal a full store
    /// answers with is retryable, and a retry needs the pre-authorized code to
    /// still be redeemable. A store that spent the offer first would answer
    /// "try again" to a caller that can never succeed again.
    #[test]
    fn a_saturated_token_key_space_refuses_without_spending_the_offer() {
        let mut bounds = bounds();
        bounds.maximum_offers = 256;
        let store = OfferStore::new(&bounds);
        store
            .remember_offer("code-1", None, prepared(), NOW)
            .expect("the offer is remembered");
        for index in 0..256 {
            store
                .bind_access_token(&format!("token-{index}"), prepared(), NOW)
                .expect("the token is bound");
        }

        assert_eq!(
            store.redeem_offer_for_access_token("code-1", None, "token-256", NOW),
            Err(StoreError::Saturated)
        );

        store
            .claim_access_token("token-0", NOW)
            .expect("a claimed token leaves room for another");
        store
            .redeem_offer_for_access_token("code-1", None, "token-256", NOW)
            .expect("the offer survived the refusal and still redeems");
        assert_eq!(
            store
                .claim_access_token("token-256", NOW)
                .expect("the bound token carries the offer's request"),
            prepared()
        );
    }

    #[test]
    fn an_expired_offer_is_refused_and_pruned_by_the_next_write() {
        let store = store();
        store
            .remember_offer("code-1", None, prepared(), NOW)
            .expect("the offer is remembered");
        let expired = NOW + bounds().offer_lifetime_seconds as i64 + 1;

        assert_eq!(
            store.redeem_offer("code-1", None, expired),
            Err(StoreError::Unknown)
        );
        assert_eq!(store.len(), 2, "reading must not prune on its own");

        store
            .remember_offer("code-2", None, prepared(), expired)
            .expect("the offer is remembered");
        assert_eq!(store.len(), 2, "the write pruned what had expired");
    }

    #[test]
    fn an_expired_access_token_is_refused() {
        let store = store();
        store
            .bind_access_token("token-1", prepared(), NOW)
            .expect("the token is bound");
        let expired = NOW + bounds().access_token_lifetime_seconds as i64 + 1;

        assert_eq!(
            store.claim_access_token("token-1", expired),
            Err(StoreError::Unknown)
        );
    }

    #[test]
    fn a_sweep_drops_only_what_has_expired() {
        let store = store();
        store
            .remember_offer("code-1", None, prepared(), NOW)
            .expect("the offer is remembered");
        let later = NOW + 60;
        store
            .remember_offer("code-2", None, prepared(), later)
            .expect("the offer is remembered");

        store.sweep(NOW + bounds().offer_lifetime_seconds as i64 + 1);
        assert_eq!(
            store.redeem_offer("code-1", None, later),
            Err(StoreError::Unknown)
        );
        store
            .redeem_offer("code-2", None, later)
            .expect("the later offer survived the sweep");
    }

    #[test]
    fn a_transaction_code_is_required_and_compared_before_anything_is_handed_back() {
        let store = store();
        store
            .remember_offer("code-1", Some("4711"), prepared(), NOW)
            .expect("the offer is remembered");

        assert_eq!(
            store.redeem_offer("code-1", None, NOW),
            Err(StoreError::TransactionCodeRefused)
        );
        assert_eq!(
            store.redeem_offer("code-1", Some("0000"), NOW),
            Err(StoreError::TransactionCodeRefused)
        );
        store
            .redeem_offer("code-1", Some("4711"), NOW)
            .expect("the right transaction code redeems the offer");
    }

    #[test]
    fn an_offer_carrying_no_transaction_code_refuses_one() {
        let store = store();
        store
            .remember_offer("code-1", None, prepared(), NOW)
            .expect("the offer is remembered");

        assert_eq!(
            store.redeem_offer("code-1", Some("4711"), NOW),
            Err(StoreError::TransactionCodeRefused)
        );
    }

    #[test]
    fn failed_transaction_codes_lock_the_offer_out_for_the_rest_of_its_life() {
        let mut bounds = bounds();
        bounds.maximum_transaction_code_attempts = 3;
        let store = OfferStore::new(&bounds);
        store
            .remember_offer("code-1", Some("4711"), prepared(), NOW)
            .expect("the offer is remembered");

        for attempt in 1..=3 {
            assert_eq!(
                store.redeem_offer("code-1", Some("0000"), NOW),
                Err(StoreError::TransactionCodeRefused),
                "attempt {attempt}"
            );
        }

        // Locked out, and the right code does not reopen it. The lockout has to
        // outlive the prepared request it protects, right to the offer's
        // expiry, or an attacker just waits for the counter to be forgotten.
        assert_eq!(
            store.redeem_offer("code-1", Some("4711"), NOW),
            Err(StoreError::LockedOut)
        );
        let nearly_expired = NOW + bounds.offer_lifetime_seconds as i64 - 1;
        assert_eq!(
            store.redeem_offer("code-1", Some("4711"), nearly_expired),
            Err(StoreError::LockedOut)
        );
    }

    #[test]
    fn a_locked_out_offer_no_longer_holds_the_request_it_was_protecting() {
        let mut bounds = bounds();
        bounds.maximum_transaction_code_attempts = 1;
        let store = OfferStore::new(&bounds);
        store
            .remember_offer("code-1", Some("4711"), prepared(), NOW)
            .expect("the offer is remembered");
        assert_eq!(store.len(), 2);

        assert_eq!(
            store.redeem_offer("code-1", Some("0000"), NOW),
            Err(StoreError::TransactionCodeRefused)
        );
        // The ledger stays, so the lockout stands. The prepared request is gone,
        // because nothing can ever redeem it now.
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn nothing_the_store_holds_is_the_secret_it_stands_for() {
        let store = store();
        store
            .remember_offer("code-1", Some("4711"), prepared(), NOW)
            .expect("the offer is remembered");
        store
            .bind_access_token("token-1", prepared(), NOW)
            .expect("the token is bound");

        for held in store.held_key_material() {
            for secret in ["code-1", "4711", "token-1"] {
                assert!(
                    !held.contains(secret),
                    "the store held {secret} rather than a tag"
                );
            }
        }
    }

    #[test]
    fn debug_output_renders_neither_a_request_nor_a_tag() {
        let store = store();
        store
            .remember_offer("code-1", Some("4711"), prepared(), NOW)
            .expect("the offer is remembered");

        let rendered = format!("{store:?} {:?}", prepared());
        for secret in ["code-1", "4711", "held-by-the-adopter", "urn:example:kind"] {
            assert!(!rendered.contains(secret), "rendered: {rendered}");
        }
    }

    #[test]
    fn two_stores_tag_the_same_secret_differently() {
        // The tagging key is per process and random, so a tag observed in one
        // process says nothing in another, and nothing about the secret.
        let first = store();
        let second = store();
        first
            .remember_offer("code-1", None, prepared(), NOW)
            .expect("the offer is remembered");
        second
            .remember_offer("code-1", None, prepared(), NOW)
            .expect("the offer is remembered");

        assert_ne!(first.held_key_material(), second.held_key_material());
    }

    /// A nonce is a freshness challenge, so what it must survive is the window
    /// it states and nothing else. It carries no caller, because the endpoint
    /// that mints it is given none.
    #[test]
    fn a_minted_nonce_verifies_for_the_window_it_states() {
        let minter = NonceMinter::new(120);
        let nonce = minter.mint(NOW);

        minter.verify(&nonce, NOW).expect("a fresh nonce verifies");
        minter
            .verify(&nonce, NOW + 119)
            .expect("the nonce verifies up to its expiry");
    }

    #[test]
    fn an_expired_or_tampered_nonce_is_refused() {
        let minter = NonceMinter::new(120);
        let nonce = minter.mint(NOW);

        assert_eq!(minter.verify(&nonce, NOW + 121), Err(NonceError::Expired));

        let (expiry, tag) = nonce.split_once('.').expect("the nonce carries its expiry");
        for tampered in [
            format!("{}.{tag}", expiry.parse::<i64>().expect("an expiry") + 600),
            format!("{expiry}.{}", &tag[1..]),
            format!("{expiry}."),
            "not-a-nonce".to_owned(),
            String::new(),
        ] {
            assert!(
                minter.verify(&tampered, NOW).is_err(),
                "the minter accepted {tampered}"
            );
        }
    }

    #[test]
    fn a_nonce_from_another_process_is_refused() {
        let first = NonceMinter::new(120);
        let second = NonceMinter::new(120);
        let nonce = first.mint(NOW);

        assert_eq!(second.verify(&nonce, NOW), Err(NonceError::Refused));
    }

    #[test]
    fn a_nonce_never_renders_its_minting_key() {
        let minter = NonceMinter::new(120);
        let rendered = format!("{minter:?}");
        assert!(!rendered.contains("key"), "rendered: {rendered}");
    }
}
