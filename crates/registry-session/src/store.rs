// SPDX-License-Identifier: Apache-2.0

//! Bounded in-memory sessions and pending sign-ins.
//!
//! Nothing here survives a restart, so a restart signs everyone out. A cookie
//! carries only a random 256-bit identifier; the store is keyed by its SHA-256
//! digest, so the store never holds a value a browser presents. A session
//! holds the person's tokens per audience and the verified, allow-listed
//! who-am-I claims, never a raw ID token.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use registry_platform_httputil::BearerToken;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::grants::{RefreshToken, Renewed};
use crate::revoker::EndedSessions;

/// The length of a base64url encoding of 32 random bytes.
pub const TOKEN_LENGTH: usize = 43;

/// How many sessions one person holds at once: enough for a phone, a
/// computer and a spare, few enough that one person signing in again and again
/// cannot fill the store. A sign-in past this share ends that person's oldest
/// session.
pub const MAXIMUM_SESSIONS_PER_PERSON: usize = 3;

/// A fresh base64url encoding of 32 bytes from the operating system.
pub fn random_token() -> Result<String, registry_platform_crypto::RandomTokenError> {
    registry_platform_crypto::random_base64url(32)
}

/// Whether `value` has the shape of a token this service issues.
#[must_use]
pub fn well_formed_token(value: &str) -> bool {
    value.len() == TOKEN_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Compare two tokens without an early exit on the first differing byte.
#[must_use]
pub fn tokens_match(presented: &str, expected: &str) -> bool {
    registry_platform_crypto::constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

fn digest(cookie: &str) -> [u8; 32] {
    Sha256::digest(cookie.as_bytes()).into()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock leaves plain data behind, never a
    // half-applied invariant, so the entries stay usable.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A sign-in the service started and the issuer has not yet returned. A kind
/// of sign-in with several audiences signs in once per audience, so the
/// pending sign-in also carries what the earlier hops obtained.
pub struct PendingSignIn {
    pub kind: String,
    /// The path the person returns to after sign-in.
    pub return_to: String,
    /// The audience of each hop, in the order the hops run.
    pub audiences: Vec<String>,
    /// The index of the hop in flight.
    pub hop: usize,
    pub state: Zeroizing<String>,
    pub nonce: Zeroizing<String>,
    pub verifier: Zeroizing<String>,
    /// The person's identifier and allow-listed claims, learned at hop 0.
    pub person: Option<Person>,
    /// What the hops already finished obtained.
    pub grants: Vec<AudienceGrant>,
    expires_at: Option<Instant>,
}

/// Who the first hop of a sign-in established.
#[derive(Clone, Debug)]
pub struct Person {
    pub subject: String,
    pub claims: Map<String, Value>,
}

impl PendingSignIn {
    #[must_use]
    pub fn new(
        kind: String,
        return_to: String,
        audiences: Vec<String>,
        state: String,
        nonce: String,
        verifier: String,
    ) -> Self {
        Self {
            kind,
            return_to,
            audiences,
            hop: 0,
            state: Zeroizing::new(state),
            nonce: Zeroizing::new(nonce),
            verifier: Zeroizing::new(verifier),
            person: None,
            grants: Vec::new(),
            expires_at: None,
        }
    }

    /// The audience of the hop in flight.
    #[must_use]
    pub fn audience(&self) -> Option<&str> {
        self.audiences.get(self.hop).map(String::as_str)
    }

    /// Whether the hop in flight is the last one.
    #[must_use]
    pub fn is_last_hop(&self) -> bool {
        self.hop + 1 >= self.audiences.len()
    }

    /// Record what the hop in flight obtained and move to the next hop with a
    /// fresh `state`, `nonce` and `verifier`.
    pub fn advance(
        &mut self,
        grant: AudienceGrant,
        state: String,
        nonce: String,
        verifier: String,
    ) {
        self.grants.push(grant);
        self.hop += 1;
        self.state = Zeroizing::new(state);
        self.nonce = Zeroizing::new(nonce);
        self.verifier = Zeroizing::new(verifier);
    }
}

impl fmt::Debug for PendingSignIn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingSignIn")
            .field("kind", &self.kind)
            .field("hop", &self.hop)
            .finish_non_exhaustive()
    }
}

/// What a session holds for one audience.
pub struct AudienceGrant {
    pub audience: String,
    pub access_token: BearerToken,
    pub expires_at: Instant,
    /// When the issuer issued the token, which gives its lifetime.
    pub issued_at: Instant,
    pub refresh_token: Option<RefreshToken>,
}

impl fmt::Debug for AudienceGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AudienceGrant")
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

pub struct Session {
    kind: String,
    issuer: String,
    subject: String,
    claims: Map<String, Value>,
    audiences: Vec<AudienceGrant>,
    deadline: Instant,
    /// The last time a request presented the session, set by the store.
    last_seen: Instant,
    renewal: Arc<tokio::sync::Mutex<()>>,
    /// The order the store admitted this session in, so a person's oldest
    /// session is the one with the smallest value.
    admitted: u64,
    /// Set after the issuer could not be reached for a renewal, so checks do
    /// not ask again at once.
    backoff: Option<Backoff>,
}

/// How long renewals wait after the issuer could not be reached: 5 seconds,
/// doubling with each further failure to at most 60.
const FIRST_BACKOFF: Duration = Duration::from_secs(5);
const MAXIMUM_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug)]
struct Backoff {
    failures: u32,
    retry_after: Instant,
}

impl Session {
    /// A session of `kind` for the person `subject` at `issuer`. `claims`
    /// holds allow-listed who-am-I values only. `deadline` is the absolute end
    /// of the session, whatever renewals it makes.
    #[must_use]
    pub fn new(
        kind: String,
        issuer: String,
        subject: String,
        claims: Map<String, Value>,
        audiences: Vec<AudienceGrant>,
        deadline: Instant,
    ) -> Self {
        Self {
            kind,
            issuer,
            subject,
            claims,
            audiences,
            deadline,
            last_seen: deadline,
            renewal: Arc::new(tokio::sync::Mutex::new(())),
            admitted: 0,
            backoff: None,
        }
    }

    /// The kind of sign-in the session was opened by.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The issuer that identified the person.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The person's identifier at the issuer.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Every refresh token the session holds, for revocation at sign-out.
    #[must_use]
    pub fn refresh_tokens(&self) -> Vec<RefreshToken> {
        self.audiences
            .iter()
            .filter_map(|grant| grant.refresh_token.clone())
            .collect()
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// What the check needs from a live session.
#[derive(Clone, Debug)]
pub struct Live {
    pub kind: String,
    /// Held by whoever renews this session's tokens, so one renewal runs at a
    /// time.
    pub renewal: Arc<tokio::sync::Mutex<()>>,
}

/// An access token and when it expires.
#[derive(Clone, Debug)]
pub struct Access {
    pub token: BearerToken,
    pub expires_at: Instant,
    pub issued_at: Instant,
    /// When the session may ask the issuer again, after a failure to reach it.
    pub retry_after: Option<Instant>,
}

impl Access {
    /// When the token is due for renewal: `renew_before` ahead of its expiry,
    /// or half its lifetime ahead when the issuer issues shorter tokens.
    #[must_use]
    pub fn renew_at(&self, renew_before: Duration) -> Instant {
        let lifetime = self.expires_at.saturating_duration_since(self.issued_at);
        let span = renew_before.min(lifetime / 2);
        self.expires_at.checked_sub(span).unwrap_or(self.issued_at)
    }
}

/// The store refused to hold another entry.
#[derive(Debug, Eq, PartialEq)]
pub struct Exhausted;

/// The person's sessions an insert ended to keep their share. They stay
/// ended: the caller revokes their refresh tokens at the issuer.
#[must_use]
pub struct Replaced(Vec<Session>);

impl fmt::Debug for Replaced {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Replaced")
            .field("sessions", &self.0.len())
            .finish()
    }
}

impl Replaced {
    /// How many sessions the insert ended.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The sessions the insert ended, whose refresh tokens are still live at
    /// the issuer until the caller revokes them.
    pub fn sessions(&self) -> impl Iterator<Item = &Session> {
        self.0.iter()
    }
}

type Key = [u8; 32];

/// The sessions, and for each person the keys of their sessions, so a
/// sign-in finds a person's share without walking the store.
#[derive(Default)]
struct Sessions {
    entries: HashMap<Key, Session>,
    by_person: HashMap<(String, String), Vec<Key>>,
    /// The last time a full store was swept for sessions that are over, so
    /// sign-ins into a full store do not each walk it.
    last_sweep: Option<Instant>,
}

impl Sessions {
    fn person(session: &Session) -> (String, String) {
        (session.issuer.clone(), session.subject.clone())
    }

    fn add(&mut self, key: Key, session: Session) {
        self.by_person
            .entry(Self::person(&session))
            .or_default()
            .push(key);
        self.entries.insert(key, session);
    }

    fn take(&mut self, key: &Key) -> Option<Session> {
        let session = self.entries.remove(key)?;
        let person = Self::person(&session);
        if let Some(keys) = self.by_person.get_mut(&person) {
            keys.retain(|held| held != key);
            if keys.is_empty() {
                self.by_person.remove(&person);
            }
        }
        Some(session)
    }
}

pub struct Store {
    clock: Arc<dyn Clock>,
    sessions: Mutex<Sessions>,
    pending: Mutex<HashMap<[u8; 32], PendingSignIn>>,
    maximum_sessions: usize,
    maximum_pending: usize,
    /// How long a session may go unused, when bounded.
    idle_lifetime: Option<Duration>,
    /// Where the refresh tokens of sessions that end without a sign-out go.
    ended: Option<EndedSessions>,
    /// How many sessions the store has admitted, which orders them.
    admitted: AtomicU64,
}

/// How often a full store is swept for sessions that are over.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

impl Store {
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, maximum_sessions: usize, maximum_pending: usize) -> Self {
        Self {
            clock,
            sessions: Mutex::new(Sessions::default()),
            pending: Mutex::new(HashMap::new()),
            maximum_sessions,
            maximum_pending,
            idle_lifetime: None,
            ended: None,
            admitted: AtomicU64::new(0),
        }
    }

    /// End a session that no request has presented for `lifetime`.
    #[must_use]
    pub fn with_idle_lifetime(mut self, lifetime: Duration) -> Self {
        self.idle_lifetime = Some(lifetime);
        self
    }

    /// Hand the refresh tokens of sessions that end without a sign-out
    /// (expiry, eviction) to `ended`.
    #[must_use]
    pub fn with_ended_sessions(mut self, ended: EndedSessions) -> Self {
        self.ended = Some(ended);
        self
    }

    /// Queue the refresh tokens of `session`, which ended without a sign-out,
    /// for revocation at the issuer.
    pub fn release(&self, session: &Session) {
        if let Some(ended) = &self.ended {
            ended.revoke(&session.kind, session.refresh_tokens());
        }
    }

    /// The store's own reading of the clock.
    #[must_use]
    pub fn now(&self) -> Instant {
        self.clock.now()
    }

    /// Whether `session` is past its absolute deadline or unused for too long.
    fn over(&self, session: &Session, now: Instant) -> bool {
        session.deadline <= now
            || self
                .idle_lifetime
                .is_some_and(|idle| now.saturating_duration_since(session.last_seen) >= idle)
    }

    /// Hold `pending` under `cookie` for `lifetime`.
    pub fn begin_sign_in(
        &self,
        cookie: &str,
        pending: PendingSignIn,
        lifetime: Duration,
    ) -> Result<(), Exhausted> {
        let mut pending = pending;
        let now = self.now();
        pending.expires_at = Some(now + lifetime);
        let mut entries = lock(&self.pending);
        if entries.len() >= self.maximum_pending {
            entries.retain(|_, entry| entry.expires_at.is_some_and(|end| end > now));
        }
        if entries.len() >= self.maximum_pending {
            return Err(Exhausted);
        }
        entries.insert(digest(cookie), pending);
        Ok(())
    }

    /// Remove and return the pending sign-in behind `cookie`. A sign-in
    /// cookie is good for one callback, whatever that callback carries.
    pub fn finish_sign_in(&self, cookie: &str) -> Option<PendingSignIn> {
        let pending = lock(&self.pending).remove(&digest(cookie))?;
        let now = self.now();
        pending
            .expires_at
            .is_some_and(|end| end > now)
            .then_some(pending)
    }

    /// Remove every session that is over from a full store, at most once per
    /// [`SWEEP_INTERVAL`], and return them.
    fn sweep(&self, sessions: &mut Sessions, now: Instant) -> Vec<Session> {
        if sessions
            .last_sweep
            .is_some_and(|last| now < last + SWEEP_INTERVAL)
        {
            return Vec::new();
        }
        sessions.last_sweep = Some(now);
        let over: Vec<Key> = sessions
            .entries
            .iter()
            .filter(|(_, held)| self.over(held, now))
            .map(|(key, _)| *key)
            .collect();
        over.iter().filter_map(|key| sessions.take(key)).collect()
    }

    /// Admit `session` under `cookie`. The person's own share is made first:
    /// their sessions that are over go, and at [`MAXIMUM_SESSIONS_PER_PERSON`]
    /// their oldest one ends. Only then is the store's own bound checked, and
    /// a full store first drops every session that is over, so a person signing
    /// in again never takes another slot. A refused insert ends only sessions
    /// that were over anyway; an admitted one returns the live sessions it
    /// ended. Insert is the last fallible step of a sign-in, because nothing
    /// brings an ended session back.
    pub fn insert(&self, cookie: &str, session: Session) -> Result<Replaced, Exhausted> {
        let mut session = session;
        let now = self.now();
        session.last_seen = now;
        let person = Sessions::person(&session);
        let mut sessions = lock(&self.sessions);
        let mut over = Vec::new();
        let mut held: Vec<(u64, Key)> = Vec::new();
        for key in sessions.by_person.get(&person).cloned().unwrap_or_default() {
            let Some(candidate) = sessions.entries.get(&key) else {
                continue;
            };
            if self.over(candidate, now) {
                over.extend(sessions.take(&key));
            } else {
                held.push((candidate.admitted, key));
            }
        }
        held.sort_unstable();
        let mut excess = (held.len() + 1).saturating_sub(MAXIMUM_SESSIONS_PER_PERSON);
        if sessions.entries.len() - excess >= self.maximum_sessions {
            over.extend(self.sweep(&mut sessions, now));
            held.retain(|(_, key)| sessions.entries.contains_key(key));
            excess = (held.len() + 1).saturating_sub(MAXIMUM_SESSIONS_PER_PERSON);
        }
        let outcome = if sessions.entries.len() - excess >= self.maximum_sessions {
            Err(Exhausted)
        } else {
            let replaced = held
                .into_iter()
                .take(excess)
                .filter_map(|(_, key)| sessions.take(&key))
                .collect();
            session.admitted = self.admitted.fetch_add(1, Ordering::Relaxed);
            sessions.add(digest(cookie), session);
            Ok(Replaced(replaced))
        };
        drop(sessions);
        for ended in &over {
            self.release(ended);
        }
        outcome
    }

    /// The live session behind `cookie`, which this request now counts as
    /// using. A session past its absolute deadline or unused for the idle
    /// lifetime is removed, its refresh tokens queued for revocation, and not
    /// returned.
    pub fn live(&self, cookie: &str) -> Option<Live> {
        let key = digest(cookie);
        let now = self.now();
        let mut sessions = lock(&self.sessions);
        if self.over(sessions.entries.get(&key)?, now) {
            let ended = sessions.take(&key);
            drop(sessions);
            if let Some(ended) = ended {
                self.release(&ended);
            }
            return None;
        }
        let session = sessions.entries.get_mut(&key)?;
        session.last_seen = now;
        Some(Live {
            kind: session.kind.clone(),
            renewal: session.renewal.clone(),
        })
    }

    /// The access token the session holds for `audience`.
    pub fn access(&self, cookie: &str, audience: &str) -> Option<Access> {
        let sessions = lock(&self.sessions);
        let session = sessions.entries.get(&digest(cookie))?;
        let grant = session
            .audiences
            .iter()
            .find(|grant| grant.audience == audience)?;
        Some(Access {
            token: grant.access_token.clone(),
            expires_at: grant.expires_at,
            issued_at: grant.issued_at,
            retry_after: session.backoff.map(|backoff| backoff.retry_after),
        })
    }

    /// The refresh token the session holds for `audience`, if it has one.
    pub fn refresh_token(&self, cookie: &str, audience: &str) -> Option<RefreshToken> {
        let sessions = lock(&self.sessions);
        sessions
            .entries
            .get(&digest(cookie))?
            .audiences
            .iter()
            .find(|grant| grant.audience == audience)?
            .refresh_token
            .clone()
    }

    /// Store a renewal for `audience`: the new access token and expiry, and
    /// the rotated refresh token when the issuer rotated it. When the session or
    /// the audience is gone the renewal is handed back, so the caller can
    /// revoke the rotated refresh token it carries.
    pub fn apply_renewed(
        &self,
        cookie: &str,
        audience: &str,
        renewed: Renewed,
    ) -> Result<(), Renewed> {
        let now = self.now();
        let mut sessions = lock(&self.sessions);
        let Some(session) = sessions.entries.get_mut(&digest(cookie)) else {
            return Err(renewed);
        };
        let Some(grant) = session
            .audiences
            .iter_mut()
            .find(|grant| grant.audience == audience)
        else {
            return Err(renewed);
        };
        grant.access_token = renewed.access_token;
        grant.expires_at = renewed.expires_at;
        grant.issued_at = now;
        if renewed.refresh_token.is_some() {
            grant.refresh_token = renewed.refresh_token;
        }
        session.backoff = None;
        Ok(())
    }

    /// Record that the issuer could not be reached for the session's renewal:
    /// no renewal is asked for until the backoff passes.
    pub fn note_unavailable(&self, cookie: &str) {
        let now = self.now();
        let mut sessions = lock(&self.sessions);
        if let Some(session) = sessions.entries.get_mut(&digest(cookie)) {
            let failures = session.backoff.map_or(1, |backoff| backoff.failures + 1);
            let doublings = failures.saturating_sub(1).min(4);
            let delay = (FIRST_BACKOFF * 2u32.pow(doublings)).min(MAXIMUM_BACKOFF);
            session.backoff = Some(Backoff {
                failures,
                retry_after: now + delay,
            });
        }
    }

    /// The issuer and subject of the live session's person.
    pub fn person(&self, cookie: &str) -> Option<(String, String)> {
        let sessions = lock(&self.sessions);
        let session = sessions.entries.get(&digest(cookie))?;
        (session.deadline > self.now()).then(|| (session.issuer.clone(), session.subject.clone()))
    }

    /// The allow-listed who-am-I claims of the live session.
    pub fn claims(&self, cookie: &str) -> Option<Map<String, Value>> {
        let sessions = lock(&self.sessions);
        let session = sessions.entries.get(&digest(cookie))?;
        (session.deadline > self.now()).then(|| session.claims.clone())
    }

    /// End the session and return it, so the caller can revoke its tokens.
    pub fn remove(&self, cookie: &str) -> Option<Session> {
        lock(&self.sessions).take(&digest(cookie))
    }

    /// How many sessions the store holds, expired or not.
    #[must_use]
    pub fn session_count(&self) -> usize {
        lock(&self.sessions).entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    fn store(maximum_sessions: usize, maximum_pending: usize) -> (Arc<ManualClock>, Store) {
        let clock = Arc::new(ManualClock::new());
        let store = Store::new(clock.clone(), maximum_sessions, maximum_pending);
        (clock, store)
    }

    fn pending() -> PendingSignIn {
        PendingSignIn::new(
            "citizen".to_owned(),
            "/apply/".to_owned(),
            vec!["urn:person".to_owned(), "urn:other".to_owned()],
            "state".to_owned(),
            "nonce".to_owned(),
            "verifier".to_owned(),
        )
    }

    fn grant(
        audience: &str,
        access: &str,
        expires_at: Instant,
        refresh: Option<&str>,
    ) -> AudienceGrant {
        AudienceGrant {
            audience: audience.to_owned(),
            access_token: BearerToken::new(access).expect("token"),
            expires_at,
            issued_at: Instant::now(),
            refresh_token: refresh.map(|token| RefreshToken::new(token).expect("token")),
        }
    }

    fn session_for(clock: &ManualClock, issuer: &str, subject: &str) -> Session {
        let now = clock.now();
        let mut claims = Map::new();
        claims.insert("sub".to_owned(), Value::from(subject));
        Session::new(
            "citizen".to_owned(),
            issuer.to_owned(),
            subject.to_owned(),
            claims,
            vec![
                grant(
                    "urn:person",
                    "access-person",
                    now + Duration::from_secs(300),
                    Some("refresh-person"),
                ),
                grant(
                    "urn:other",
                    "access-other",
                    now + Duration::from_secs(300),
                    None,
                ),
            ],
            now + Duration::from_secs(3600),
        )
    }

    #[test]
    fn tokens_are_256_bit_base64url() {
        let token = random_token().expect("random");
        assert!(well_formed_token(&token));
        assert_ne!(token, random_token().expect("random"));
        assert!(!well_formed_token(&format!("{}=", &token[..42])));
        assert!(!well_formed_token(&token[..42]));
        assert!(!well_formed_token(&format!("{token}A")));
    }

    #[test]
    fn tokens_match_only_when_every_byte_agrees() {
        let token = random_token().expect("random");
        assert!(tokens_match(&token, &token.clone()));
        let mut other = token.clone().into_bytes();
        other[42] = if other[42] == b'A' { b'B' } else { b'A' };
        let other = String::from_utf8(other).expect("ascii");
        assert!(!tokens_match(&token, &other));
        assert!(!tokens_match(&token, &token[..42]));
        assert!(!tokens_match(&token[..42], &token));
        assert!(!tokens_match("", &token));
    }

    #[test]
    fn a_pending_sign_in_advances_hop_by_hop_with_fresh_secrets() {
        let mut pending = pending();
        assert_eq!(pending.audience(), Some("urn:person"));
        assert!(!pending.is_last_hop());
        let now = Instant::now();
        pending.advance(
            grant("urn:person", "access-person", now, Some("refresh-person")),
            "state-two".to_owned(),
            "nonce-two".to_owned(),
            "verifier-two".to_owned(),
        );
        assert_eq!(pending.hop, 1);
        assert_eq!(pending.audience(), Some("urn:other"));
        assert!(pending.is_last_hop());
        assert_eq!(pending.grants.len(), 1);
        assert_eq!(pending.state.as_str(), "state-two");
        assert_eq!(pending.nonce.as_str(), "nonce-two");
        assert_eq!(pending.verifier.as_str(), "verifier-two");
        assert!(!format!("{pending:?}").contains("state-two"));
    }

    #[test]
    fn a_pending_sign_in_is_single_use_and_bounded() {
        let (_clock, store) = store(1, 1);
        let lifetime = Duration::from_secs(60);
        store.begin_sign_in("a", pending(), lifetime).expect("room");
        assert_eq!(
            store.begin_sign_in("b", pending(), lifetime),
            Err(Exhausted)
        );
        let finished = store.finish_sign_in("a").expect("pending");
        assert_eq!(finished.kind, "citizen");
        assert_eq!(finished.return_to, "/apply/");
        assert!(store.finish_sign_in("a").is_none());
        store
            .begin_sign_in("b", pending(), lifetime)
            .expect("room again");
    }

    #[test]
    fn an_expired_pending_sign_in_is_refused_and_evicted_to_make_room() {
        let (clock, store) = store(1, 1);
        store
            .begin_sign_in("a", pending(), Duration::from_secs(60))
            .expect("room");
        clock.advance(Duration::from_secs(61));
        store
            .begin_sign_in("b", pending(), Duration::from_secs(60))
            .expect("the expired entry made room");
        assert!(store.finish_sign_in("a").is_none());
        let (clock, store) = self::store(1, 1);
        store
            .begin_sign_in("a", pending(), Duration::from_secs(60))
            .expect("room");
        clock.advance(Duration::from_secs(61));
        assert!(store.finish_sign_in("a").is_none());
    }

    #[test]
    fn a_session_is_live_until_its_absolute_deadline() {
        let (clock, store) = store(4, 1);
        let _ = store
            .insert("a", session_for(&clock, "https://id.example", "p1"))
            .expect("room");
        let live = store.live("a").expect("live");
        assert_eq!(live.kind, "citizen");
        assert!(store.live("unknown").is_none());
        clock.advance(Duration::from_secs(3599));
        assert!(store.live("a").is_some());
        clock.advance(Duration::from_secs(1));
        assert!(store.live("a").is_none());
        assert_eq!(store.session_count(), 0, "an expired session is removed");
    }

    #[test]
    fn the_renewal_lock_is_one_per_session() {
        let (clock, store) = store(4, 1);
        let _ = store
            .insert("a", session_for(&clock, "https://id.example", "p1"))
            .expect("room");
        let _ = store
            .insert("b", session_for(&clock, "https://id.example", "p2"))
            .expect("room");
        let first = store.live("a").expect("live").renewal;
        assert!(Arc::ptr_eq(&first, &store.live("a").expect("live").renewal));
        assert!(!Arc::ptr_eq(
            &first,
            &store.live("b").expect("live").renewal
        ));
    }

    #[test]
    fn a_session_holds_tokens_per_audience() {
        let (clock, store) = store(4, 1);
        let _ = store
            .insert("a", session_for(&clock, "https://id.example", "p1"))
            .expect("room");
        let access = store.access("a", "urn:person").expect("person token");
        assert_eq!(
            access.token.authorization_header_value(),
            "Bearer access-person"
        );
        assert_eq!(access.expires_at, clock.now() + Duration::from_secs(300));
        assert!(store.access("a", "urn:missing").is_none());
        assert!(store.access("unknown", "urn:person").is_none());
        assert_eq!(
            store
                .refresh_token("a", "urn:person")
                .expect("refresh")
                .expose(),
            "refresh-person"
        );
        assert!(store.refresh_token("a", "urn:other").is_none());
    }

    #[test]
    fn a_renewal_replaces_the_token_and_the_rotated_refresh_token() {
        let (clock, store) = store(4, 1);
        let _ = store
            .insert("a", session_for(&clock, "https://id.example", "p1"))
            .expect("room");
        let later = clock.now() + Duration::from_secs(900);
        let renewed = |refresh: Option<&str>| Renewed {
            access_token: BearerToken::new("access-new").expect("token"),
            expires_at: later,
            refresh_token: refresh.map(|token| RefreshToken::new(token).expect("token")),
        };
        assert!(store
            .apply_renewed("a", "urn:person", renewed(Some("refresh-new")))
            .is_ok());
        let access = store.access("a", "urn:person").expect("token");
        assert_eq!(
            access.token.authorization_header_value(),
            "Bearer access-new"
        );
        assert_eq!(access.expires_at, later);
        assert_eq!(
            store
                .refresh_token("a", "urn:person")
                .expect("refresh")
                .expose(),
            "refresh-new"
        );
        // An issuer that does not rotate leaves the held refresh token alone.
        assert!(store
            .apply_renewed("a", "urn:person", renewed(None))
            .is_ok());
        assert_eq!(
            store
                .refresh_token("a", "urn:person")
                .expect("refresh")
                .expose(),
            "refresh-new"
        );
        assert!(store
            .apply_renewed("a", "urn:missing", renewed(None))
            .is_err());
        // A renewal for a session that is gone comes back with its rotated
        // refresh token.
        let handed_back = store
            .apply_renewed("unknown", "urn:person", renewed(Some("refresh-rotated")))
            .expect_err("the session is gone");
        assert_eq!(
            handed_back.refresh_token.expect("rotated").expose(),
            "refresh-rotated"
        );
    }

    #[test]
    fn claims_are_the_allow_listed_values_the_session_was_made_with() {
        let (clock, store) = store(4, 1);
        let _ = store
            .insert("a", session_for(&clock, "https://id.example", "p1"))
            .expect("room");
        let claims = store.claims("a").expect("claims");
        assert_eq!(claims.len(), 1);
        assert_eq!(claims["sub"], "p1");
        assert!(store.claims("unknown").is_none());
    }

    #[test]
    fn removing_a_session_returns_it_with_its_refresh_tokens() {
        let (clock, store) = store(4, 1);
        let _ = store
            .insert("a", session_for(&clock, "https://id.example", "p1"))
            .expect("room");
        let removed = store.remove("a").expect("session");
        let tokens = removed.refresh_tokens();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].expose(), "refresh-person");
        assert!(store.live("a").is_none());
        assert!(store.remove("a").is_none());
    }

    #[test]
    fn a_person_signing_in_again_replaces_their_oldest_session() {
        let (clock, store) = store(MAXIMUM_SESSIONS_PER_PERSON + 1, 1);
        let cookies: Vec<String> = (0..3 * MAXIMUM_SESSIONS_PER_PERSON)
            .map(|index| format!("a{index}"))
            .collect();
        for cookie in &cookies {
            let replaced = store
                .insert(cookie, session_for(&clock, "https://id.example", "a"))
                .expect("the person's own share");
            assert!(replaced.len() <= 1);
        }
        let (replaced, held) = cookies.split_at(cookies.len() - MAXIMUM_SESSIONS_PER_PERSON);
        assert!(replaced.iter().all(|cookie| store.live(cookie).is_none()));
        assert!(held.iter().all(|cookie| store.live(cookie).is_some()));
        let replaced = store
            .insert("b", session_for(&clock, "https://id.example", "b"))
            .expect("room for another person");
        assert!(replaced.is_empty());
        assert_eq!(
            store
                .insert("c", session_for(&clock, "https://id.example", "c"))
                .unwrap_err(),
            Exhausted
        );
        let replaced = store
            .insert("a-again", session_for(&clock, "https://id.example", "a"))
            .expect("a full store still replaces");
        assert_eq!(replaced.len(), 1);
        assert!(store.live(&held[0]).is_none());
        assert!(store.live("b").is_some());
    }

    #[test]
    fn the_same_subject_at_another_issuer_is_another_person() {
        let (clock, store) = store(MAXIMUM_SESSIONS_PER_PERSON * 2, 1);
        for index in 0..MAXIMUM_SESSIONS_PER_PERSON {
            let _ = store
                .insert(
                    &format!("x{index}"),
                    session_for(&clock, "https://one.example", "a"),
                )
                .expect("room");
        }
        let replaced = store
            .insert("y", session_for(&clock, "https://two.example", "a"))
            .expect("room");
        assert!(replaced.is_empty());
        assert!(store.live("x0").is_some());
    }

    #[test]
    fn a_session_an_insert_ended_stays_ended_and_is_handed_over_for_revocation() {
        let (clock, store) = store(8, 1);
        for index in 0..MAXIMUM_SESSIONS_PER_PERSON {
            let _ = store
                .insert(
                    &format!("a{index}"),
                    session_for(&clock, "https://id.example", "a"),
                )
                .expect("room");
        }
        let replaced = store
            .insert("new", session_for(&clock, "https://id.example", "a"))
            .expect("replaces the oldest");
        assert!(store.live("a0").is_none());
        assert_eq!(replaced.sessions().count(), 1);
        assert!(replaced
            .sessions()
            .all(|session| !session.refresh_tokens().is_empty()));
        store.remove("new").expect("the new session");
        assert!(store.live("a0").is_none());
    }

    #[test]
    fn an_expired_session_makes_room_and_is_not_counted_against_the_share() {
        let (clock, store) = store(1, 1);
        let _ = store
            .insert("old", session_for(&clock, "https://id.example", "a"))
            .expect("room");
        clock.advance(Duration::from_secs(3601));
        let _ = store
            .insert("new", session_for(&clock, "https://id.example", "b"))
            .expect("the expired session made room");
        assert!(store.live("new").is_some());
        assert!(store.live("old").is_none());
    }

    #[test]
    fn a_refused_insert_changes_nothing() {
        let (clock, store) = store(1, 1);
        let _ = store
            .insert("a", session_for(&clock, "https://id.example", "a"))
            .expect("room");
        assert!(store
            .insert("b", session_for(&clock, "https://id.example", "b"))
            .is_err());
        assert_eq!(store.session_count(), 1);
        assert!(store.live("a").is_some());
    }

    #[test]
    fn debug_output_never_carries_a_token_or_a_subject() {
        let (clock, store) = store(4, 1);
        let mut session = session_for(&clock, "https://id.example", "subject-canary");
        session.audiences[0].access_token = BearerToken::new("access-canary").expect("token");
        session.audiences[0].refresh_token =
            Some(RefreshToken::new("refresh-canary").expect("token"));
        let printed = format!("{session:?} {:?}", session.audiences[0]);
        assert!(!printed.contains("canary"), "{printed}");
        let printed = format!(
            "{:?}",
            PendingSignIn::new(
                "citizen".to_owned(),
                "/x/".to_owned(),
                vec!["urn:x".to_owned()],
                "state-canary".to_owned(),
                "nonce-canary".to_owned(),
                "verifier-canary".to_owned()
            )
        );
        assert!(!printed.contains("canary"), "{printed}");
        let _ = store;
    }

    #[test]
    fn a_session_unused_for_the_idle_lifetime_ends_and_use_extends_it() {
        let clock = Arc::new(ManualClock::new());
        let store = Store::new(clock.clone(), 4, 1).with_idle_lifetime(Duration::from_secs(600));
        let _ = store
            .insert("a", session_for(&clock, "https://id.example", "p1"))
            .expect("room");
        clock.advance(Duration::from_secs(599));
        assert!(store.live("a").is_some());
        clock.advance(Duration::from_secs(599));
        assert!(
            store.live("a").is_some(),
            "the check at 599 s counted as use"
        );
        clock.advance(Duration::from_secs(600));
        assert!(store.live("a").is_none());
        assert_eq!(store.session_count(), 0);
    }

    #[test]
    fn a_full_store_evicts_idle_sessions_first_and_then_refuses() {
        let clock = Arc::new(ManualClock::new());
        let store = Store::new(clock.clone(), 2, 1).with_idle_lifetime(Duration::from_secs(600));
        let _ = store
            .insert("a", session_for(&clock, "https://id.example", "p1"))
            .expect("room");
        let _ = store
            .insert("b", session_for(&clock, "https://id.example", "p2"))
            .expect("room");
        assert_eq!(
            store
                .insert("c", session_for(&clock, "https://id.example", "p3"))
                .unwrap_err(),
            Exhausted
        );
        clock.advance(Duration::from_secs(300));
        assert!(store.live("a").is_some());
        clock.advance(Duration::from_secs(400));
        // "b" was last used 700 s ago, "a" 400 s ago.
        let _ = store
            .insert("c", session_for(&clock, "https://id.example", "p3"))
            .expect("the idle session made room");
        assert!(store.live("b").is_none());
        assert!(store.live("a").is_some());
        assert!(store.live("c").is_some());
        assert_eq!(
            store
                .insert("d", session_for(&clock, "https://id.example", "p4"))
                .unwrap_err(),
            Exhausted,
            "nothing else is idle"
        );
    }

    #[test]
    fn the_person_index_follows_every_way_a_session_leaves() {
        let clock = Arc::new(ManualClock::new());
        let store = Store::new(clock.clone(), 10, 1).with_idle_lifetime(Duration::from_secs(600));
        let indexed = |store: &Store| lock(&store.sessions).by_person.len();
        for (cookie, person) in [("a", "p1"), ("b", "p1"), ("c", "p2")] {
            let _ = store
                .insert(cookie, session_for(&clock, "https://id.example", person))
                .expect("room");
        }
        assert_eq!(indexed(&store), 2);
        assert!(store.remove("c").is_some());
        assert_eq!(indexed(&store), 1);
        // The person's sessions replaced by their share leave the index too.
        for cookie in ["d", "e"] {
            let _ = store
                .insert(cookie, session_for(&clock, "https://id.example", "p1"))
                .expect("room");
        }
        assert_eq!(
            lock(&store.sessions)
                .by_person
                .values()
                .next()
                .map(Vec::len),
            Some(3)
        );
        assert_eq!(store.session_count(), 3);
        clock.advance(Duration::from_secs(600));
        assert!(store.live("d").is_none());
        let _ = store.live("e");
        let _ = store.live("a");
        let _ = store.live("b");
        assert_eq!(store.session_count(), 0);
        assert_eq!(indexed(&store), 0);
    }

    #[tokio::test]
    async fn sessions_that_end_by_eviction_have_their_refresh_tokens_queued() {
        let clock = Arc::new(ManualClock::new());
        let issuer = crate::grants::fake::FakeIssuer::new(clock.clone());
        let (ended, revoker) = crate::revoker::channel(4);
        tokio::spawn(revoker.run(issuer.clone()));
        let store = Store::new(clock.clone(), 1, 1)
            .with_idle_lifetime(Duration::from_secs(600))
            .with_ended_sessions(ended.clone());
        let (access_token, expires_at, refresh) = issuer.sign_in("urn:person");
        let mut first = session_for(&clock, "https://id.example", "p1");
        first.audiences = vec![AudienceGrant {
            audience: "urn:person".to_owned(),
            access_token,
            expires_at,
            issued_at: clock.now(),
            refresh_token: Some(refresh.clone()),
        }];
        let _ = store.insert("a", first).expect("room");
        clock.advance(Duration::from_secs(600));
        let _ = store
            .insert("b", session_for(&clock, "https://id.example", "p2"))
            .expect("the idle session made room");
        tokio::time::timeout(Duration::from_secs(5), async {
            while !issuer.family_revoked(&refresh) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the evicted session's family was revoked");
        assert_eq!(ended.failed(), 0);
        assert_eq!(ended.dropped(), 0);
    }
}
