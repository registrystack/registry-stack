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
    renewal: Arc<tokio::sync::Mutex<()>>,
    /// The order the store admitted this session in, so a person's oldest
    /// session is the one with the smallest value.
    admitted: u64,
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
            renewal: Arc::new(tokio::sync::Mutex::new(())),
            admitted: 0,
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
}

/// The store refused to hold another entry.
#[derive(Debug, Eq, PartialEq)]
pub struct Exhausted;

/// The person's sessions an insert ended to keep their share. They stay
/// ended: the caller revokes their refresh tokens at the issuer.
#[must_use]
pub struct Replaced(Vec<([u8; 32], Session)>);

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
        self.0.iter().map(|(_, session)| session)
    }
}

pub struct Store {
    clock: Arc<dyn Clock>,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    pending: Mutex<HashMap<[u8; 32], PendingSignIn>>,
    maximum_sessions: usize,
    maximum_pending: usize,
    /// How many sessions the store has admitted, which orders them.
    admitted: AtomicU64,
}

impl Store {
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, maximum_sessions: usize, maximum_pending: usize) -> Self {
        Self {
            clock,
            sessions: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            maximum_sessions,
            maximum_pending,
            admitted: AtomicU64::new(0),
        }
    }

    /// The store's own reading of the clock.
    #[must_use]
    pub fn now(&self) -> Instant {
        self.clock.now()
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

    /// Admit `session` under `cookie`. The person's own share is made first:
    /// their expired sessions go, and at [`MAXIMUM_SESSIONS_PER_PERSON`] their
    /// oldest one ends. Only then is the store's own bound checked, so a person
    /// signing in again never takes another slot. A refused insert changes
    /// nothing; an admitted one returns the sessions it ended. Insert is the last
    /// fallible step of a sign-in, because nothing brings an ended session back.
    pub fn insert(&self, cookie: &str, session: Session) -> Result<Replaced, Exhausted> {
        let mut session = session;
        let mut sessions = lock(&self.sessions);
        let now = self.now();
        let same_person =
            |held: &Session| held.issuer == session.issuer && held.subject == session.subject;
        sessions.retain(|_, held| !same_person(held) || held.deadline > now);
        let mut held: Vec<(u64, [u8; 32])> = sessions
            .iter()
            .filter(|(_, held)| same_person(held))
            .map(|(key, held)| (held.admitted, *key))
            .collect();
        held.sort_unstable();
        let excess = (held.len() + 1).saturating_sub(MAXIMUM_SESSIONS_PER_PERSON);
        if sessions.len() - excess >= self.maximum_sessions {
            sessions.retain(|_, held| held.deadline > now);
        }
        // The retain may have dropped some of the person's own sessions that
        // were counted above; recount against what is left.
        held.retain(|(_, key)| sessions.contains_key(key));
        let excess = (held.len() + 1).saturating_sub(MAXIMUM_SESSIONS_PER_PERSON);
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

    /// The live session behind `cookie`. A session past its absolute deadline
    /// is removed and not returned.
    pub fn live(&self, cookie: &str) -> Option<Live> {
        let key = digest(cookie);
        let mut sessions = lock(&self.sessions);
        let session = sessions.get(&key)?;
        if session.deadline <= self.now() {
            sessions.remove(&key);
            return None;
        }
        Some(Live {
            kind: session.kind.clone(),
            renewal: session.renewal.clone(),
        })
    }

    /// The access token the session holds for `audience`.
    pub fn access(&self, cookie: &str, audience: &str) -> Option<Access> {
        let sessions = lock(&self.sessions);
        let grant = sessions
            .get(&digest(cookie))?
            .audiences
            .iter()
            .find(|grant| grant.audience == audience)?;
        Some(Access {
            token: grant.access_token.clone(),
            expires_at: grant.expires_at,
        })
    }

    /// The refresh token the session holds for `audience`, if it has one.
    pub fn refresh_token(&self, cookie: &str, audience: &str) -> Option<RefreshToken> {
        let sessions = lock(&self.sessions);
        sessions
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
        let mut sessions = lock(&self.sessions);
        let Some(grant) = sessions.get_mut(&digest(cookie)).and_then(|session| {
            session
                .audiences
                .iter_mut()
                .find(|grant| grant.audience == audience)
        }) else {
            return Err(renewed);
        };
        grant.access_token = renewed.access_token;
        grant.expires_at = renewed.expires_at;
        if renewed.refresh_token.is_some() {
            grant.refresh_token = renewed.refresh_token;
        }
        Ok(())
    }

    /// The issuer and subject of the live session's person.
    pub fn person(&self, cookie: &str) -> Option<(String, String)> {
        let sessions = lock(&self.sessions);
        let session = sessions.get(&digest(cookie))?;
        (session.deadline > self.now()).then(|| (session.issuer.clone(), session.subject.clone()))
    }

    /// The allow-listed who-am-I claims of the live session.
    pub fn claims(&self, cookie: &str) -> Option<Map<String, Value>> {
        let sessions = lock(&self.sessions);
        let session = sessions.get(&digest(cookie))?;
        (session.deadline > self.now()).then(|| session.claims.clone())
    }

    /// End the session and return it, so the caller can revoke its tokens.
    pub fn remove(&self, cookie: &str) -> Option<Session> {
        lock(&self.sessions).remove(&digest(cookie))
    }

    /// How many sessions the store holds, expired or not.
    #[must_use]
    pub fn session_count(&self) -> usize {
        lock(&self.sessions).len()
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
}
