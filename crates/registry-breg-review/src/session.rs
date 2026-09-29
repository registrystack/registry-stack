// SPDX-License-Identifier: Apache-2.0

//! Bounded in-memory sessions and pending sign-ins.
//!
//! Nothing here survives a restart, so a restart signs everyone out. A cookie
//! carries only a random 256-bit identifier; the store is keyed by its
//! SHA-256 digest, so the store never holds a value a browser presents. The
//! person's access token lives only in the session's registry client.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_breg_client::{BRegLifecycleAction, BaseRegistryClient};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::registry::RecordRevision;

/// The length of a base64url encoding of 32 random bytes.
pub(crate) const TOKEN_LENGTH: usize = 43;

/// How many rendered views one session remembers. A person with more open
/// tabs than this re-confirms the oldest one.
const MAXIMUM_VIEWS: usize = 16;

/// How many sessions one citizen holds at once: enough for a phone and a
/// computer and a spare, few enough that one person signing in again and
/// again cannot fill the store. A sign-in past this share ends that
/// citizen's oldest session.
pub(crate) const MAXIMUM_SESSIONS_PER_CITIZEN: usize = 3;

/// A fresh base64url encoding of 32 bytes from the operating system.
pub(crate) fn random_token() -> Result<String, getrandom::Error> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
}

/// Whether `value` has the shape of a token this page issues.
pub(crate) fn well_formed_token(value: &str) -> bool {
    value.len() == TOKEN_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Compare two tokens without an early exit on the first differing byte.
pub(crate) fn tokens_match(presented: &str, expected: &str) -> bool {
    presented.len() == expected.len() && bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
}

fn digest(cookie: &str) -> [u8; 32] {
    Sha256::digest(cookie.as_bytes()).into()
}

/// A sign-in the page started and the provider has not yet returned.
pub(crate) struct PendingSignIn {
    pub request_id: String,
    pub state: Zeroizing<String>,
    pub nonce: Zeroizing<String>,
    pub verifier: Zeroizing<String>,
    expires_at: Instant,
}

impl PendingSignIn {
    pub(crate) fn new(
        request_id: String,
        state: String,
        nonce: String,
        verifier: String,
        lifetime: Duration,
    ) -> Self {
        Self {
            request_id,
            state: Zeroizing::new(state),
            nonce: Zeroizing::new(nonce),
            verifier: Zeroizing::new(verifier),
            expires_at: Instant::now() + lifetime,
        }
    }
}

/// One rendered review: the exact submit action the person saw, the target
/// revision whose values they saw beside it, and the idempotency key every
/// submit of that view reuses.
#[derive(Clone)]
pub(crate) struct View {
    pub id: String,
    pub request_id: String,
    pub action: BRegLifecycleAction,
    pub target: RecordRevision,
    pub idempotency_key: String,
}

pub(crate) struct Session {
    pub citizen: String,
    pub registry: Arc<BaseRegistryClient>,
    pub csrf: String,
    pub expires_at: Instant,
    views: VecDeque<View>,
    /// The order the store admitted this session in, so a citizen's oldest
    /// session is the one with the smallest value.
    admitted: u64,
}

impl Session {
    pub(crate) fn new(
        citizen: String,
        registry: Arc<BaseRegistryClient>,
        csrf: String,
        expires_at: Instant,
    ) -> Self {
        Self {
            citizen,
            registry,
            csrf,
            expires_at,
            views: VecDeque::new(),
            admitted: 0,
        }
    }
}

/// What a request handler needs from a live session.
#[derive(Clone)]
pub(crate) struct Current {
    pub citizen: String,
    pub registry: Arc<BaseRegistryClient>,
    pub csrf: String,
}

/// The store refused to hold another entry.
#[derive(Debug)]
pub(crate) struct Exhausted;

/// The citizen's sessions an insert ended to keep their share, held so a
/// sign-in that fails afterwards can put them back.
#[must_use]
pub(crate) struct Replaced(Vec<([u8; 32], Session)>);

pub(crate) struct Store {
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    pending: Mutex<HashMap<[u8; 32], PendingSignIn>>,
    maximum_sessions: usize,
    maximum_pending: usize,
    /// How many sessions the store has admitted, which orders them.
    admitted: AtomicU64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock leaves plain data behind, never a
    // half-applied invariant, so the entries stay usable.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Store {
    pub(crate) fn new(maximum_sessions: usize, maximum_pending: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            maximum_sessions,
            maximum_pending,
            admitted: AtomicU64::new(0),
        }
    }

    pub(crate) fn begin_sign_in(
        &self,
        cookie: &str,
        pending: PendingSignIn,
    ) -> Result<(), Exhausted> {
        let mut entries = lock(&self.pending);
        if entries.len() >= self.maximum_pending {
            let now = Instant::now();
            entries.retain(|_, entry| entry.expires_at > now);
        }
        if entries.len() >= self.maximum_pending {
            return Err(Exhausted);
        }
        entries.insert(digest(cookie), pending);
        Ok(())
    }

    /// Remove and return the pending sign-in behind `cookie`. A sign-in
    /// cookie is good for one callback, whatever that callback carries.
    pub(crate) fn finish_sign_in(&self, cookie: &str) -> Option<PendingSignIn> {
        let pending = lock(&self.pending).remove(&digest(cookie))?;
        (pending.expires_at > Instant::now()).then_some(pending)
    }

    /// Admit `session` under `cookie`. The citizen's own share is made first:
    /// their expired sessions go, and at [`MAXIMUM_SESSIONS_PER_CITIZEN`] their
    /// oldest one ends, views and all. Only then is the store's own bound
    /// checked, so a citizen signing in again never takes another slot. A
    /// refused insert changes nothing; an admitted one returns the sessions
    /// it ended, for [`Store::restore`].
    pub(crate) fn insert(&self, cookie: &str, mut session: Session) -> Result<Replaced, Exhausted> {
        let mut sessions = lock(&self.sessions);
        let now = Instant::now();
        sessions.retain(|_, held| held.citizen != session.citizen || held.expires_at > now);
        let mut held: Vec<(u64, [u8; 32])> = sessions
            .iter()
            .filter(|(_, held)| held.citizen == session.citizen)
            .map(|(key, held)| (held.admitted, *key))
            .collect();
        held.sort_unstable();
        let excess = (held.len() + 1).saturating_sub(MAXIMUM_SESSIONS_PER_CITIZEN);
        if sessions.len() - excess >= self.maximum_sessions {
            sessions.retain(|_, session| session.expires_at > now);
        }
        if sessions.len() - excess >= self.maximum_sessions {
            return Err(Exhausted);
        }
        let replaced = held
            .into_iter()
            .take(excess)
            .filter_map(|(_, key)| sessions.remove_entry(&key))
            .collect();
        session.admitted = self.admitted.fetch_add(1, Ordering::Relaxed);
        sessions.insert(digest(cookie), session);
        Ok(Replaced(replaced))
    }

    /// Put back the sessions an insert replaced, once the session that
    /// replaced them has been removed.
    pub(crate) fn restore(&self, replaced: Replaced) {
        lock(&self.sessions).extend(replaced.0);
    }

    /// The live session behind `cookie`. An expired session is removed: a
    /// session never outlives the access token it holds.
    pub(crate) fn current(&self, cookie: &str) -> Option<Current> {
        let key = digest(cookie);
        let mut sessions = lock(&self.sessions);
        let session = sessions.get(&key)?;
        if session.expires_at <= Instant::now() {
            sessions.remove(&key);
            return None;
        }
        Some(Current {
            citizen: session.citizen.clone(),
            registry: session.registry.clone(),
            csrf: session.csrf.clone(),
        })
    }

    pub(crate) fn remove(&self, cookie: &str) {
        lock(&self.sessions).remove(&digest(cookie));
    }

    /// Remember a rendered view. Returns `false` when the session ended
    /// meanwhile.
    pub(crate) fn remember_view(&self, cookie: &str, view: View) -> bool {
        let mut sessions = lock(&self.sessions);
        let Some(session) = sessions.get_mut(&digest(cookie)) else {
            return false;
        };
        if session.views.len() >= MAXIMUM_VIEWS {
            session.views.pop_front();
        }
        session.views.push_back(view);
        true
    }

    /// The view `view_id` this session rendered for `request_id`, if any.
    pub(crate) fn view(&self, cookie: &str, request_id: &str, view_id: &str) -> Option<View> {
        let sessions = lock(&self.sessions);
        let session = sessions.get(&digest(cookie))?;
        session
            .views
            .iter()
            .find(|view| view.request_id == request_id && tokens_match(view_id, &view.id))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_256_bit_base64url() {
        let token = random_token().expect("random");
        assert!(well_formed_token(&token));
        assert_ne!(token, random_token().expect("random"));
        assert!(!well_formed_token(&format!("{}=", &token[..42])));
        assert!(!well_formed_token(&token[..42]));
    }

    #[test]
    fn a_pending_sign_in_is_single_use_and_bounded() {
        let store = Store::new(1, 1);
        let pending = || {
            PendingSignIn::new(
                "id".to_owned(),
                "state".to_owned(),
                "nonce".to_owned(),
                "verifier".to_owned(),
                Duration::from_secs(60),
            )
        };
        store.begin_sign_in("a", pending()).expect("room");
        assert!(store.begin_sign_in("b", pending()).is_err());
        assert!(store.finish_sign_in("a").is_some());
        assert!(store.finish_sign_in("a").is_none());
        store.begin_sign_in("b", pending()).expect("room again");
    }

    #[test]
    fn an_expired_pending_sign_in_is_refused_and_evicted() {
        let store = Store::new(1, 1);
        let expired = PendingSignIn::new(
            "id".to_owned(),
            "state".to_owned(),
            "nonce".to_owned(),
            "verifier".to_owned(),
            Duration::ZERO,
        );
        store.begin_sign_in("a", expired).expect("room");
        assert!(store.finish_sign_in("a").is_none());
    }

    fn session(citizen: &str) -> Session {
        let registry =
            BaseRegistryClient::new(registry_breg_client::BaseRegistryClientConfig::new(
                url::Url::parse("https://registry.example").unwrap(),
            ))
            .unwrap();
        Session::new(
            citizen.to_owned(),
            Arc::new(registry),
            "csrf".to_owned(),
            Instant::now() + Duration::from_secs(60),
        )
    }

    #[test]
    fn a_citizen_signing_in_again_replaces_their_oldest_session() {
        let store = Store::new(MAXIMUM_SESSIONS_PER_CITIZEN + 1, 1);
        let cookies: Vec<String> = (0..3 * MAXIMUM_SESSIONS_PER_CITIZEN)
            .map(|index| format!("a{index}"))
            .collect();
        for cookie in &cookies {
            let replaced = store
                .insert(cookie, session("a"))
                .expect("the citizen's own share");
            assert!(replaced.0.len() <= 1);
        }

        let (replaced, held) = cookies.split_at(cookies.len() - MAXIMUM_SESSIONS_PER_CITIZEN);
        assert!(replaced
            .iter()
            .all(|cookie| store.current(cookie).is_none()));
        assert!(held.iter().all(|cookie| store.current(cookie).is_some()));
        let replaced = store
            .insert("b", session("b"))
            .expect("room for another citizen");
        assert!(replaced.0.is_empty());
        assert!(store.insert("c", session("c")).is_err());
        let replaced = store
            .insert("a-again", session("a"))
            .expect("a full store still replaces");
        assert_eq!(replaced.0.len(), 1);
        assert!(store.current(&held[0]).is_none());
        assert!(store.current("b").is_some());
    }
}
