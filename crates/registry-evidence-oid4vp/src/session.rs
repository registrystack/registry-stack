//! Presentation sessions, held in memory only.
//!
//! A session carries the per-session secrets of one OpenID4VP exchange: the
//! nonce, the `state`, and the response-encryption key. None of it is ever
//! persisted. A restart ends every session; a portal creates a new one.
//!
//! The store is bounded and honest about its bound. A full store refuses a new
//! session, it never forgets a live one to make room. Expiry is enforced on
//! every read from the clock, so a session past its lifetime is invisible even
//! when the cleanup task has not yet run.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::Duration,
};

use registry_platform_crypto::{jwe::EcdhEsP256Key, random_base64url, RandomTokenError};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Random bytes behind a session reference, request id, nonce, and `state`.
const SECRET_BYTES: usize = 32;
/// Random bytes behind the response-encryption key identifier.
const KEY_ID_BYTES: usize = 16;

/// A source of the current Unix time in seconds. Injected so tests control
/// expiry.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The wall clock.
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    })
}

/// The authenticated caller that created a session. Only this principal may
/// read the session's status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    pub issuer: String,
    pub subject: Option<String>,
    pub client: Option<String>,
}

impl Principal {
    /// A stable, bounded key for rate limiting, which reveals none of the
    /// principal's identifiers.
    #[must_use]
    pub fn rate_key(&self) -> String {
        let mut hasher = Sha256::new();
        for part in [
            Some(self.issuer.as_str()),
            self.subject.as_deref(),
            self.client.as_deref(),
        ] {
            // Length-prefixed so adjacent parts cannot run together.
            let part = part.unwrap_or_default();
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        hex(&hasher.finalize())
    }
}

/// Where a session is in its life.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    /// The request object is available and no wallet response has arrived.
    Pending,
    /// The wallet's presentation was accepted and awaits a read.
    Received,
    /// The wallet reported an error.
    Failed,
}

impl SessionStatus {
    /// The status name a portal reads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Received => "received",
            Self::Failed => "failed",
        }
    }
}

/// The presentation bytes the store holds across all sessions, against a
/// limit. A session charges its presentation when it reserves a response and
/// the charge is returned when the session's settlement is dropped or its
/// result is consumed: the reservation is released, the session is discarded,
/// Evidence reads the result, or the result expires and the sweep removes it.
#[derive(Debug)]
struct HeldBudget {
    limit: u64,
    used: AtomicU64,
}

impl HeldBudget {
    /// Charge `bytes`, or `None` when that would pass the limit.
    fn charge(self: &Arc<Self>, bytes: u64) -> Option<Charge> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.limit)
            })
            .ok()
            .map(|_| Charge {
                budget: Arc::clone(self),
                bytes,
            })
    }
}

/// Bytes charged to a [`HeldBudget`], returned on drop.
#[derive(Debug)]
struct Charge {
    budget: Arc<HeldBudget>,
    bytes: u64,
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

/// The presentations a wallet returned, keyed by DCQL credential query
/// `id`. Held in memory only; each string is zeroized when the session drops.
pub struct Presentation(BTreeMap<String, Vec<Zeroizing<String>>>);

impl Presentation {
    #[must_use]
    pub const fn new(entries: BTreeMap<String, Vec<Zeroizing<String>>>) -> Self {
        Self(entries)
    }

    /// The bytes of every held presentation string.
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.0
            .values()
            .flatten()
            .map(|value| value.len() as u64)
            .sum()
    }

    /// The `vp_token` object (OpenID4VP 1.0 section 8.1). The returned value
    /// is an unzeroized copy for the one response that releases it.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.0
                .iter()
                .map(|(id, values)| {
                    (
                        id.clone(),
                        serde_json::Value::Array(
                            values
                                .iter()
                                .map(|value| serde_json::Value::String(value.as_str().to_owned()))
                                .collect(),
                        ),
                    )
                })
                .collect(),
        )
    }
}

impl fmt::Debug for Presentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Presentation(<redacted>)")
    }
}

/// Why a wallet reported an error. A closed set, so no wallet text reaches a
/// log, an audit record, or an Evidence caller (OpenID4VP 1.0 section 8.5
/// error codes; anything else is `Other`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureCategory {
    AccessDenied,
    InvalidRequest,
    InvalidClient,
    VpFormatsNotSupported,
    WalletUnavailable,
    Other,
}

impl FailureCategory {
    /// The category for a wallet's `error` code.
    #[must_use]
    pub fn from_error_code(code: &str) -> Self {
        match code {
            "access_denied" => Self::AccessDenied,
            "invalid_request" => Self::InvalidRequest,
            "invalid_client" => Self::InvalidClient,
            "vp_formats_not_supported" => Self::VpFormatsNotSupported,
            "wallet_unavailable" => Self::WalletUnavailable,
            _ => Self::Other,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessDenied => "access_denied",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::VpFormatsNotSupported => "vp_formats_not_supported",
            Self::WalletUnavailable => "wallet_unavailable",
            Self::Other => "other",
        }
    }
}

/// What the wallet's one accepted response held.
#[derive(Debug)]
pub enum Held {
    Presentation(Presentation),
    WalletError(FailureCategory),
}

/// Where a confirmed result is in being read by Evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Consumption {
    /// No read has taken the result.
    Open,
    /// A read has taken the result and its audit record is being written. The
    /// result is held until the read is finished or abandoned.
    Claimed,
    /// A read delivered the result; the presentation is no longer held.
    Consumed,
}

/// The wallet response a session took, with the digest of the bytes that
/// carried it. Until `confirmed`, the session reads as pending: the response
/// is reserved while its audit record is written, and released if the record
/// is refused.
#[derive(Debug)]
struct Settlement {
    digest: Digest32,
    held: Held,
    received_at: u64,
    confirmed: bool,
    consumption: Consumption,
    /// The held presentation bytes, charged to the store's budget.
    charge: Option<Charge>,
}

/// What a read finds when it claims a session's result.
#[derive(Debug)]
pub enum Claim {
    /// The wallet has not presented, or its response is not yet recorded.
    Pending,
    /// There is no result to deliver: it was consumed or is being delivered.
    Gone,
    /// The `vp_token` the wallet presented, and when it was accepted.
    Presentation {
        vp_token: serde_json::Value,
        received_at: u64,
    },
    /// The wallet reported an error.
    Failed(FailureCategory),
}

/// What reserving a session for a response came to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reserve {
    /// The response is reserved.
    Reserved,
    /// The session already took a response.
    AlreadyTaken,
    /// Holding the presentation would pass the store's byte budget.
    OverBudget,
}

/// How a response relates to the one a session already took.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Prior {
    /// The session has taken no response.
    None,
    /// The identical response was accepted.
    Same,
    /// The identical response is being recorded and is not yet accepted.
    InFlight,
    /// A different response was accepted or is being recorded.
    Different,
}

/// What a read of a session finds.
#[derive(Debug)]
pub enum Outcome<'a> {
    Pending,
    Received {
        presentation: &'a Presentation,
        received_at: u64,
    },
    Failed(FailureCategory),
}

/// One presentation exchange.
pub struct Session {
    /// The policy the session was created under.
    pub policy_id: String,
    /// The caller that created it.
    pub principal: Principal,
    /// The random identifier the wallet uses to fetch the request object. It
    /// is not the session reference, so a wallet never learns the reference.
    pub request_id: String,
    /// Bound into the request object and echoed back in the key binding.
    pub nonce: String,
    /// Bound into the request object and echoed back in the response.
    pub state: String,
    /// The key the wallet encrypts its response to. Discarded with the
    /// session.
    pub encryption_key: EcdhEsP256Key,
    /// Where the wallet posts its response.
    pub response_uri: String,
    pub created_at: u64,
    /// The end of the exchange window: the request object is not served, and
    /// no response is accepted, from this instant.
    pub expires_at: u64,
    /// The end of the store's hold on the session. Equal to `expires_at`
    /// while pending.
    pub retain_until: u64,
    /// A digest of the session reference, the only handle audit records
    /// carry. The reference is 256 random bits, so the digest identifies the
    /// session without disclosing it.
    pub audit_ref: String,
    settlement: Option<Settlement>,
    budget: Arc<HeldBudget>,
}

impl Session {
    /// The session's status.
    #[must_use]
    pub fn status(&self) -> SessionStatus {
        match self.outcome() {
            Outcome::Pending => SessionStatus::Pending,
            Outcome::Received { .. } => SessionStatus::Received,
            Outcome::Failed(_) => SessionStatus::Failed,
        }
    }

    /// What the wallet's response, if accepted, held.
    #[must_use]
    pub fn outcome(&self) -> Outcome<'_> {
        match &self.settlement {
            Some(Settlement {
                held: Held::Presentation(presentation),
                received_at,
                confirmed: true,
                ..
            }) => Outcome::Received {
                presentation,
                received_at: *received_at,
            },
            Some(Settlement {
                held: Held::WalletError(category),
                confirmed: true,
                ..
            }) => Outcome::Failed(*category),
            _ => Outcome::Pending,
        }
    }

    /// How a response with this digest relates to the one already taken. The
    /// digests are compared in constant time.
    #[must_use]
    pub fn prior(&self, digest: &Digest32) -> Prior {
        match &self.settlement {
            None => Prior::None,
            Some(settlement) => {
                if !registry_platform_crypto::constant_time_eq(&settlement.digest, digest) {
                    Prior::Different
                } else if settlement.confirmed {
                    Prior::Same
                } else {
                    Prior::InFlight
                }
            }
        }
    }

    /// Reserve the session for a response, charging a presentation's bytes to
    /// the store's budget. A refused reservation leaves the session as it was
    /// and drops `held`.
    pub fn reserve(&mut self, digest: Digest32, held: Held, now: u64) -> Reserve {
        if self.settlement.is_some() {
            return Reserve::AlreadyTaken;
        }
        let charge = match &held {
            Held::Presentation(presentation) => {
                let Some(charge) = self.budget.charge(presentation.byte_len()) else {
                    return Reserve::OverBudget;
                };
                Some(charge)
            }
            Held::WalletError(_) => None,
        };
        self.settlement = Some(Settlement {
            digest,
            held,
            received_at: now,
            confirmed: false,
            consumption: Consumption::Open,
            charge,
        });
        Reserve::Reserved
    }

    /// Make the reserved response the session's result and hold it for
    /// `result_ttl_seconds`. Returns `false` when the reservation is not this
    /// digest's.
    pub fn confirm(&mut self, digest: &Digest32, now: u64, result_ttl_seconds: u64) -> bool {
        match &mut self.settlement {
            Some(settlement) if !settlement.confirmed && settlement.digest == *digest => {
                settlement.confirmed = true;
                settlement.received_at = now;
                self.retain_until = now.saturating_add(result_ttl_seconds);
                true
            }
            _ => false,
        }
    }

    /// Take the confirmed result for delivery to Evidence. Exactly one claim
    /// succeeds until it is [`Self::unclaim`]ed; every later one finds the
    /// result [`Claim::Gone`]. Nothing is released until [`Self::consume`].
    pub fn claim(&mut self) -> Claim {
        let Some(settlement) = &mut self.settlement else {
            return Claim::Pending;
        };
        if !settlement.confirmed {
            return Claim::Pending;
        }
        if settlement.consumption != Consumption::Open {
            return Claim::Gone;
        }
        settlement.consumption = Consumption::Claimed;
        match &settlement.held {
            Held::Presentation(presentation) => Claim::Presentation {
                vp_token: presentation.to_json(),
                received_at: settlement.received_at,
            },
            Held::WalletError(category) => Claim::Failed(*category),
        }
    }

    /// Give a claimed result back, because its delivery did not happen.
    pub fn unclaim(&mut self) {
        if let Some(settlement) = &mut self.settlement {
            if settlement.consumption == Consumption::Claimed {
                settlement.consumption = Consumption::Open;
            }
        }
    }

    /// Finish delivery of a claimed result: the presentation and its byte
    /// charge are released. The session keeps its status and its digest, so
    /// the wallet's identical retry is still answered.
    pub fn consume(&mut self) {
        if let Some(settlement) = &mut self.settlement {
            if settlement.consumption == Consumption::Claimed {
                settlement.consumption = Consumption::Consumed;
                if let Held::Presentation(held) = &mut settlement.held {
                    *held = Presentation::new(BTreeMap::new());
                }
                settlement.charge = None;
            }
        }
    }

    /// Drop an unconfirmed reservation, leaving the session pending.
    pub fn release(&mut self, digest: &Digest32) {
        if self
            .settlement
            .as_ref()
            .is_some_and(|settlement| !settlement.confirmed && settlement.digest == *digest)
        {
            self.settlement = None;
        }
    }

    fn is_live(&self, now: u64) -> bool {
        now < self.retain_until
    }

    /// Whether a response is reserved and awaiting its confirmation or
    /// release. The reservation was made inside the exchange window, so it
    /// outlives it.
    fn holds_reservation(&self) -> bool {
        self.settlement
            .as_ref()
            .is_some_and(|settlement| !settlement.confirmed)
    }
}

impl fmt::Debug for Session {
    // Nonce, state, key, and identifiers are secrets or correlators; none is
    // printed.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("policy_id", &self.policy_id)
            .field("status", &self.status())
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// What a newly created session needs from its creator.
pub struct NewSession<'a> {
    pub policy_id: &'a str,
    pub principal: Principal,
    pub response_uri_for: &'a dyn Fn(&str) -> String,
    pub ttl_seconds: u64,
}

/// The two secrets a portal and a wallet each hold of a new session.
#[derive(Debug)]
pub struct Created {
    /// The reference the portal reads status with.
    pub reference: String,
    /// The request id the wallet fetches the request object with.
    pub request_id: String,
    pub expires_at: u64,
    pub audit_ref: String,
}

/// Why the store refused to create a session.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum StoreError {
    #[error("the session store is full")]
    Full,
    #[error("session secrets could not be generated")]
    Entropy,
}

impl From<RandomTokenError> for StoreError {
    fn from(_: RandomTokenError) -> Self {
        Self::Entropy
    }
}

impl From<registry_platform_crypto::CryptoError> for StoreError {
    fn from(_: registry_platform_crypto::CryptoError) -> Self {
        Self::Entropy
    }
}

/// A SHA-256 digest.
pub type Digest32 = [u8; 32];

#[derive(Default)]
struct Inner {
    by_reference: HashMap<Digest32, Session>,
    reference_by_request: HashMap<Digest32, Digest32>,
}

impl Inner {
    fn purge_expired(&mut self, now: u64) -> usize {
        let before = self.by_reference.len();
        let expired: Vec<Digest32> = self
            .by_reference
            .iter()
            .filter(|(_, session)| !session.is_live(now) && !session.holds_reservation())
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.remove(&key);
        }
        before - self.by_reference.len()
    }

    fn remove(&mut self, reference: &Digest32) {
        if let Some(session) = self.by_reference.remove(reference) {
            self.reference_by_request
                .remove(&digest(&session.request_id));
        }
    }
}

/// The in-memory session store. Keys are digests of the secrets, so a heap
/// dump of the index does not yield a usable reference or request id.
pub struct SessionStore {
    inner: Mutex<Inner>,
    capacity: usize,
    budget: Arc<HeldBudget>,
    clock: Clock,
}

impl fmt::Debug for SessionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionStore")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl SessionStore {
    /// A store of at most `capacity` sessions that holds at most
    /// `maximum_held_presentation_bytes` of presentations.
    #[must_use]
    pub fn new(capacity: usize, maximum_held_presentation_bytes: u64, clock: Clock) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            capacity,
            budget: Arc::new(HeldBudget {
                limit: maximum_held_presentation_bytes,
                used: AtomicU64::new(0),
            }),
            clock,
        }
    }

    /// The presentation bytes held now, expired results not yet swept
    /// included.
    #[must_use]
    pub fn held_presentation_bytes(&self) -> u64 {
        self.budget.used.load(Ordering::SeqCst)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding the lock cannot leave the maps inconsistent
        // across an await point, because the lock is never held across one.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The current time as the store sees it.
    #[must_use]
    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    /// How many sessions the store holds, expired but not yet cleaned up
    /// included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().by_reference.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Create a session, or refuse when the store is full of live sessions.
    pub fn create(&self, new: &NewSession<'_>) -> Result<Created, StoreError> {
        let reference = random_base64url(SECRET_BYTES)?;
        let request_id = random_base64url(SECRET_BYTES)?;
        let nonce = random_base64url(SECRET_BYTES)?;
        let state = random_base64url(SECRET_BYTES)?;
        let encryption_key = EcdhEsP256Key::generate(&random_base64url(KEY_ID_BYTES)?)?;
        let now = self.now();
        let expires_at = now.saturating_add(new.ttl_seconds);
        let audit_ref = audit_ref(&reference);
        let session = Session {
            policy_id: new.policy_id.to_owned(),
            principal: new.principal.clone(),
            response_uri: (new.response_uri_for)(&request_id),
            request_id: request_id.clone(),
            nonce,
            state,
            encryption_key,
            created_at: now,
            expires_at,
            retain_until: expires_at,
            audit_ref: audit_ref.clone(),
            settlement: None,
            budget: Arc::clone(&self.budget),
        };

        let mut inner = self.lock();
        if inner.by_reference.len() >= self.capacity {
            // Only dead sessions are reclaimed. A live session is never
            // dropped to admit another.
            inner.purge_expired(now);
        }
        if inner.by_reference.len() >= self.capacity {
            return Err(StoreError::Full);
        }
        let key = digest(&reference);
        inner.reference_by_request.insert(digest(&request_id), key);
        inner.by_reference.insert(key, session);
        Ok(Created {
            reference,
            request_id,
            expires_at,
            audit_ref,
        })
    }

    /// Run `read` on the live session with this reference. An unknown,
    /// expired, or cleaned-up reference is `None`, with no way to tell which.
    pub fn with_by_reference<R>(
        &self,
        reference: &str,
        read: impl FnOnce(&Session) -> R,
    ) -> Option<R> {
        let now = self.now();
        let inner = self.lock();
        inner
            .by_reference
            .get(&digest(reference))
            .filter(|session| session.is_live(now))
            .map(read)
    }

    /// Run `read` on the session a wallet's request id names, while the
    /// exchange window is open.
    pub fn with_by_request_id<R>(
        &self,
        request_id: &str,
        read: impl FnOnce(&Session) -> R,
    ) -> Option<R> {
        let now = self.now();
        let inner = self.lock();
        let reference = inner.reference_by_request.get(&digest(request_id))?;
        inner
            .by_reference
            .get(reference)
            .filter(|session| session.is_live(now) && now < session.expires_at)
            .map(read)
    }

    /// Run `update` on the session a wallet's request id names, while the
    /// exchange window is open, under the store lock.
    pub fn with_by_request_id_mut<R>(
        &self,
        request_id: &str,
        update: impl FnOnce(&mut Session) -> R,
    ) -> Option<R> {
        let now = self.now();
        let mut inner = self.lock();
        let reference = *inner.reference_by_request.get(&digest(request_id))?;
        inner
            .by_reference
            .get_mut(&reference)
            .filter(|session| session.is_live(now) && now < session.expires_at)
            .map(update)
    }

    /// Run `update` on the session a wallet's request id names, whether or not
    /// the exchange window is still open. A response reserved inside the window
    /// is confirmed or released through this, because the audit write between
    /// the two can outlast the window and the sweep keeps a reserved session.
    pub fn with_reserved_mut<R>(
        &self,
        request_id: &str,
        update: impl FnOnce(&mut Session) -> R,
    ) -> Option<R> {
        let mut inner = self.lock();
        let reference = *inner.reference_by_request.get(&digest(request_id))?;
        inner
            .by_reference
            .get_mut(&reference)
            .filter(|session| session.holds_reservation())
            .map(update)
    }

    /// Run `update` on the live session with this reference.
    pub fn with_by_reference_mut<R>(
        &self,
        reference: &str,
        update: impl FnOnce(&mut Session) -> R,
    ) -> Option<R> {
        let now = self.now();
        let mut inner = self.lock();
        inner
            .by_reference
            .get_mut(&digest(reference))
            .filter(|session| session.is_live(now))
            .map(update)
    }

    /// Remove the session with this reference, live or not.
    pub fn discard(&self, reference: &str) {
        self.lock().remove(&digest(reference));
    }

    /// Drop every session past its hold. Returns how many were dropped.
    pub fn cleanup(&self) -> usize {
        let now = self.now();
        self.lock().purge_expired(now)
    }
}

/// Run [`SessionStore::cleanup`] every `interval` until the store is dropped.
///
/// The task holds the store weakly, so it never keeps a store alive, and each
/// pass is one bounded sweep under the store lock. Correctness does not depend
/// on it: reads enforce expiry themselves.
pub fn spawn_cleanup(store: &Arc<SessionStore>, interval: Duration) -> tokio::task::JoinHandle<()> {
    let store: Weak<SessionStore> = Arc::downgrade(store);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Some(store) = store.upgrade() else {
                return;
            };
            let dropped = store.cleanup();
            if dropped > 0 {
                tracing::debug!(dropped, "expired presentation sessions dropped");
            }
        }
    })
}

/// The audit handle of a session reference.
#[must_use]
pub fn audit_ref(reference: &str) -> String {
    format!("sha256:{}", hex(&digest(reference)))
}

fn digest(secret: &str) -> Digest32 {
    Sha256::digest(secret.as_bytes()).into()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    fn principal(subject: &str) -> Principal {
        Principal {
            issuer: "https://issuer.example".to_owned(),
            subject: Some(subject.to_owned()),
            client: Some("portal".to_owned()),
        }
    }

    fn store(capacity: usize) -> (SessionStore, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(1_000));
        let clock = {
            let time = Arc::clone(&time);
            Arc::new(move || time.load(Ordering::SeqCst)) as Clock
        };
        (SessionStore::new(capacity, 1 << 20, clock), time)
    }

    fn create(store: &SessionStore, subject: &str) -> Result<Created, StoreError> {
        store.create(&NewSession {
            policy_id: "policy",
            principal: principal(subject),
            response_uri_for: &|id| format!("https://v.example/v1/responses/{id}"),
            ttl_seconds: 300,
        })
    }

    #[test]
    fn a_session_carries_fresh_independent_secrets() {
        let (store, _) = store(8);
        let first = create(&store, "a").unwrap();
        let second = create(&store, "a").unwrap();
        assert_ne!(first.reference, second.reference);
        assert_ne!(first.reference, first.request_id);
        let (nonce_a, state_a, key_a) = store
            .with_by_reference(&first.reference, |s| {
                (
                    s.nonce.clone(),
                    s.state.clone(),
                    s.encryption_key.public_jwk(),
                )
            })
            .unwrap();
        let (nonce_b, state_b, key_b) = store
            .with_by_reference(&second.reference, |s| {
                (
                    s.nonce.clone(),
                    s.state.clone(),
                    s.encryption_key.public_jwk(),
                )
            })
            .unwrap();
        assert_ne!(nonce_a, nonce_b);
        assert_ne!(state_a, state_b);
        assert_ne!(nonce_a, state_a);
        assert_ne!(key_a, key_b);
        // 32 random bytes in unpadded base64url.
        assert_eq!(first.reference.len(), 43);
        assert_eq!(nonce_a.len(), 43);
        assert_eq!(state_a.len(), 43);
    }

    #[test]
    fn a_full_store_refuses_rather_than_evicts() {
        let (store, _) = store(2);
        let first = create(&store, "a").unwrap();
        let second = create(&store, "b").unwrap();
        assert_eq!(create(&store, "c").unwrap_err(), StoreError::Full);
        assert!(store.with_by_reference(&first.reference, |_| ()).is_some());
        assert!(store.with_by_reference(&second.reference, |_| ()).is_some());
    }

    #[test]
    fn a_full_store_reclaims_only_expired_sessions() {
        let (store, time) = store(1);
        let old = create(&store, "a").unwrap();
        time.store(1_000 + 300, Ordering::SeqCst);
        let fresh = create(&store, "b").unwrap();
        assert!(store.with_by_reference(&old.reference, |_| ()).is_none());
        assert!(store.with_by_reference(&fresh.reference, |_| ()).is_some());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn expiry_is_enforced_on_read_without_cleanup() {
        let (store, time) = store(8);
        let created = create(&store, "a").unwrap();
        time.store(1_000 + 299, Ordering::SeqCst);
        assert!(store
            .with_by_reference(&created.reference, |_| ())
            .is_some());
        assert!(store
            .with_by_request_id(&created.request_id, |_| ())
            .is_some());
        time.store(1_000 + 300, Ordering::SeqCst);
        assert_eq!(store.len(), 1, "no cleanup has run");
        assert!(store
            .with_by_reference(&created.reference, |_| ())
            .is_none());
        assert!(store
            .with_by_request_id(&created.request_id, |_| ())
            .is_none());
        assert_eq!(store.cleanup(), 1);
        assert!(store.is_empty());
    }

    #[test]
    fn the_request_id_does_not_open_the_session_by_reference() {
        let (store, _) = store(8);
        let created = create(&store, "a").unwrap();
        assert!(store
            .with_by_reference(&created.request_id, |_| ())
            .is_none());
        assert!(store
            .with_by_request_id(&created.reference, |_| ())
            .is_none());
    }

    #[test]
    fn debug_prints_no_secret_and_no_key() {
        let (store, _) = store(8);
        let created = create(&store, "a").unwrap();
        let printed = store
            .with_by_reference(&created.reference, |session| {
                (
                    format!("{session:?}"),
                    session.nonce.clone(),
                    session.state.clone(),
                    session.request_id.clone(),
                )
            })
            .unwrap();
        let (text, nonce, state, request_id) = printed;
        for secret in [&nonce, &state, &request_id, &created.reference] {
            assert!(!text.contains(secret.as_str()), "{text}");
        }
        assert!(!text.contains("encryption_key"), "{text}");
        assert!(!format!("{store:?}").contains(&created.reference));
    }

    #[test]
    fn a_discarded_session_is_gone_by_reference_and_request_id() {
        let (store, _) = store(8);
        let created = create(&store, "a").unwrap();
        store.discard(&created.reference);
        assert!(store.is_empty());
        assert!(store
            .with_by_reference(&created.reference, |_| ())
            .is_none());
        assert!(store
            .with_by_request_id(&created.request_id, |_| ())
            .is_none());
    }

    #[test]
    fn the_audit_handle_is_a_digest_not_the_reference() {
        let (store, _) = store(8);
        let created = create(&store, "a").unwrap();
        assert_eq!(created.audit_ref, audit_ref(&created.reference));
        assert!(created.audit_ref.starts_with("sha256:"));
        assert!(!created.audit_ref.contains(&created.reference));
    }

    #[test]
    fn the_rate_key_distinguishes_principals_and_reveals_none() {
        let a = principal("alice").rate_key();
        assert_eq!(a, principal("alice").rate_key());
        assert_ne!(a, principal("bob").rate_key());
        assert!(!a.contains("alice"));
        assert!(a.len() <= 256);
    }

    fn held() -> Held {
        Held::Presentation(Presentation::new(BTreeMap::from([(
            "id".to_owned(),
            vec![Zeroizing::new("presentation-secret".to_owned())],
        )])))
    }

    #[test]
    fn a_reservation_reads_as_pending_until_confirmed() {
        let (store, time) = store(8);
        let created = create(&store, "a").unwrap();
        let first = [1u8; 32];
        let other = [2u8; 32];
        let status = |store: &SessionStore| {
            store
                .with_by_reference(&created.reference, |s| (s.status(), s.prior(&first)))
                .unwrap()
        };
        let reserved = store
            .with_by_request_id_mut(&created.request_id, |s| s.reserve(first, held(), 1_000))
            .unwrap();
        assert_eq!(reserved, Reserve::Reserved);
        assert_eq!(status(&store), (SessionStatus::Pending, Prior::InFlight));
        // A second reservation, and a different digest, are refused.
        let again = store
            .with_by_request_id_mut(&created.request_id, |s| {
                (s.reserve(other, held(), 1_000), s.prior(&other))
            })
            .unwrap();
        assert_eq!(again, (Reserve::AlreadyTaken, Prior::Different));

        time.store(1_010, Ordering::SeqCst);
        let confirmed = store
            .with_by_request_id_mut(&created.request_id, |s| {
                (
                    s.confirm(&other, 1_010, 1_800),
                    s.confirm(&first, 1_010, 1_800),
                )
            })
            .unwrap();
        assert_eq!(confirmed, (false, true));
        assert_eq!(status(&store), (SessionStatus::Received, Prior::Same));
        // The result is held for its own lifetime, past the exchange window.
        time.store(1_000 + 300 + 1, Ordering::SeqCst);
        assert!(store
            .with_by_reference(&created.reference, |_| ())
            .is_some());
        time.store(1_010 + 1_800, Ordering::SeqCst);
        assert!(store
            .with_by_reference(&created.reference, |_| ())
            .is_none());
    }

    #[test]
    fn a_released_reservation_leaves_the_session_open_and_a_confirmed_one_stays() {
        let (store, _) = store(8);
        let created = create(&store, "a").unwrap();
        let digest = [1u8; 32];
        store
            .with_by_request_id_mut(&created.request_id, |s| {
                s.reserve(digest, held(), 1_000);
                s.release(&[9u8; 32]);
                assert_eq!(
                    s.prior(&digest),
                    Prior::InFlight,
                    "another digest cannot release"
                );
                s.release(&digest);
                assert_eq!(s.prior(&digest), Prior::None);
                s.reserve(digest, held(), 1_000);
                s.confirm(&digest, 1_000, 60);
                s.release(&digest);
                assert_eq!(
                    s.prior(&digest),
                    Prior::Same,
                    "a confirmed response is not released"
                );
            })
            .unwrap();
    }

    #[test]
    fn a_held_presentation_is_never_printed() {
        let (store, _) = store(8);
        let created = create(&store, "a").unwrap();
        let text = store
            .with_by_request_id_mut(&created.request_id, |s| {
                s.reserve([1u8; 32], held(), 1_000);
                s.confirm(&[1u8; 32], 1_000, 60);
                format!("{s:?} {:?}", s.outcome())
            })
            .unwrap();
        assert!(!text.contains("presentation-secret"), "{text}");
    }

    fn held_of(bytes: usize) -> Held {
        Held::Presentation(Presentation::new(BTreeMap::from([(
            "id".to_owned(),
            vec![Zeroizing::new("x".repeat(bytes))],
        )])))
    }

    fn store_with_budget(limit: u64) -> (SessionStore, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(1_000));
        let clock = {
            let time = Arc::clone(&time);
            Arc::new(move || time.load(Ordering::SeqCst)) as Clock
        };
        (SessionStore::new(8, limit, clock), time)
    }

    #[test]
    fn a_reservation_is_charged_and_refused_past_the_budget() {
        let (store, _) = store_with_budget(100);
        let first = create(&store, "a").unwrap();
        let second = create(&store, "b").unwrap();
        let reserve = |created: &Created, bytes| {
            store
                .with_by_request_id_mut(&created.request_id, |s| {
                    s.reserve([1u8; 32], held_of(bytes), 1_000)
                })
                .unwrap()
        };
        assert_eq!(reserve(&first, 60), Reserve::Reserved);
        assert_eq!(store.held_presentation_bytes(), 60);
        // 60 + 41 passes the limit; 60 + 40 reaches it.
        assert_eq!(reserve(&second, 41), Reserve::OverBudget);
        assert_eq!(store.held_presentation_bytes(), 60);
        assert_eq!(reserve(&second, 40), Reserve::Reserved);
        assert_eq!(store.held_presentation_bytes(), 100);
    }

    #[test]
    fn held_bytes_return_on_release_discard_and_sweep() {
        let (store, time) = store_with_budget(1_000);
        let released = create(&store, "a").unwrap();
        let discarded = create(&store, "b").unwrap();
        let expiring = create(&store, "c").unwrap();
        for created in [&released, &discarded, &expiring] {
            let digest = [3u8; 32];
            store
                .with_by_request_id_mut(&created.request_id, |s| {
                    assert_eq!(s.reserve(digest, held_of(100), 1_000), Reserve::Reserved);
                })
                .unwrap();
        }
        store
            .with_by_request_id_mut(&expiring.request_id, |s| {
                s.confirm(&[3u8; 32], 1_000, 60);
            })
            .unwrap();
        assert_eq!(store.held_presentation_bytes(), 300);

        store
            .with_by_request_id_mut(&released.request_id, |s| s.release(&[3u8; 32]))
            .unwrap();
        assert_eq!(store.held_presentation_bytes(), 200);

        store.discard(&discarded.reference);
        assert_eq!(store.held_presentation_bytes(), 100);

        // The unconfirmed reservation of `released` was dropped; `expiring`
        // holds its result until its hold ends and the sweep removes it.
        time.store(1_000 + 60, Ordering::SeqCst);
        assert_eq!(store.held_presentation_bytes(), 100);
        assert!(store.cleanup() >= 1);
        assert_eq!(store.held_presentation_bytes(), 0);
    }

    #[test]
    fn a_wallet_error_is_not_charged() {
        let (store, _) = store_with_budget(10);
        let created = create(&store, "a").unwrap();
        let reserved = store
            .with_by_request_id_mut(&created.request_id, |s| {
                s.reserve([1u8; 32], Held::WalletError(FailureCategory::Other), 1_000)
            })
            .unwrap();
        assert_eq!(reserved, Reserve::Reserved);
        assert_eq!(store.held_presentation_bytes(), 0);
    }

    #[test]
    fn one_claim_wins_and_consume_releases_the_bytes() {
        let (store, _) = store_with_budget(1_000);
        let created = create(&store, "a").unwrap();
        let digest = [4u8; 32];
        let claim_twice = || {
            store
                .with_by_reference_mut(&created.reference, |s| (s.claim(), s.claim()))
                .unwrap()
        };
        store
            .with_by_request_id_mut(&created.request_id, |s| {
                s.reserve(digest, held_of(100), 1_000);
                assert!(matches!(s.claim(), Claim::Pending), "unconfirmed");
                s.confirm(&digest, 1_000, 60);
            })
            .unwrap();
        let (first, second) = claim_twice();
        assert!(matches!(first, Claim::Presentation { .. }));
        assert!(matches!(second, Claim::Gone));
        // Claimed, not yet consumed: still charged, and a refused delivery
        // gives it back.
        assert_eq!(store.held_presentation_bytes(), 100);
        store.with_by_reference_mut(&created.reference, Session::unclaim);
        store
            .with_by_reference_mut(&created.reference, |s| {
                assert!(matches!(s.claim(), Claim::Presentation { .. }));
                s.consume();
                assert!(matches!(s.claim(), Claim::Gone));
                assert_eq!(s.status(), SessionStatus::Received);
                assert_eq!(s.prior(&digest), Prior::Same);
            })
            .unwrap();
        assert_eq!(store.held_presentation_bytes(), 0);
    }

    #[test]
    fn a_reserved_session_is_confirmed_after_its_window_and_never_swept() {
        let (store, time) = store(8);
        let created = create(&store, "a").unwrap();
        let digest = [6u8; 32];
        store
            .with_by_request_id_mut(&created.request_id, |s| s.reserve(digest, held(), 1_000))
            .unwrap();
        time.store(1_000 + 10_000, Ordering::SeqCst);
        assert_eq!(store.cleanup(), 0, "a reserved session is not swept");
        assert!(store
            .with_by_request_id_mut(&created.request_id, |_| ())
            .is_none());
        let confirmed = store
            .with_reserved_mut(&created.request_id, |s| s.confirm(&digest, 11_000, 60))
            .unwrap();
        assert!(confirmed);
        assert!(store
            .with_by_reference(&created.reference, |_| ())
            .is_some());
        // Once confirmed it is no longer reserved, so it is swept with its hold.
        time.store(11_000 + 60, Ordering::SeqCst);
        assert_eq!(store.cleanup(), 1);
        assert!(store
            .with_reserved_mut(&created.request_id, |_| ())
            .is_none());
    }

    #[tokio::test]
    async fn the_cleanup_task_drops_expired_sessions_and_stops_with_the_store() {
        let (store, time) = store(8);
        let store = Arc::new(store);
        create(&store, "a").unwrap();
        time.store(5_000, Ordering::SeqCst);
        let task = spawn_cleanup(&store, Duration::from_millis(10));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !store.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cleanup removes the expired session");
        drop(store);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the task ends once the store is gone")
            .unwrap();
    }
}
