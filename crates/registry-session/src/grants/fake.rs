// SPDX-License-Identifier: Apache-2.0

//! An issuer double that behaves like the real one: refresh tokens are single
//! use, every refresh rotates, and presenting a used refresh token revokes the
//! whole family and answers `invalid_grant`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use registry_platform_httputil::BearerToken;
use tokio::sync::Notify;

use super::{GrantError, Grants, RefreshToken, Renewed};
use crate::clock::Clock;

/// How long an access token the double issues lasts.
pub(crate) const TOKEN_LIFETIME: Duration = Duration::from_secs(300);

#[derive(Default)]
struct State {
    next: usize,
    /// Refresh token text to the family it belongs to.
    family_of: HashMap<String, usize>,
    used: HashSet<String>,
    revoked_families: HashSet<usize>,
}

pub(crate) struct FakeIssuer {
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
    refreshes: AtomicUsize,
    revocations: AtomicUsize,
    unavailable: AtomicBool,
    /// Whether `refresh` waits at the gate before answering.
    gated: AtomicBool,
    open: Notify,
    started: Notify,
}

impl FakeIssuer {
    pub(crate) fn new(clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            clock,
            state: Mutex::new(State::default()),
            refreshes: AtomicUsize::new(0),
            revocations: AtomicUsize::new(0),
            unavailable: AtomicBool::new(false),
            gated: AtomicBool::new(false),
            open: Notify::new(),
            started: Notify::new(),
        })
    }

    /// A fresh family, as sign-in would issue it: an access token for
    /// `audience` and the first refresh token.
    pub(crate) fn sign_in(
        &self,
        audience: &str,
    ) -> (BearerToken, std::time::Instant, RefreshToken) {
        let mut state = self.state.lock().expect("state");
        state.next += 1;
        let family = state.next;
        let refresh = format!("refresh-{family}-0");
        state.family_of.insert(refresh.clone(), family);
        let access = format!("access-{audience}-{family}-0");
        (
            BearerToken::new(access).expect("token"),
            self.clock.now() + TOKEN_LIFETIME,
            RefreshToken::new(refresh).expect("token"),
        )
    }

    pub(crate) fn refresh_calls(&self) -> usize {
        self.refreshes.load(Ordering::SeqCst)
    }

    pub(crate) fn revoke_calls(&self) -> usize {
        self.revocations.load(Ordering::SeqCst)
    }

    /// Answer every refresh with a transport failure that consumes nothing.
    pub(crate) fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }

    /// Hold every refresh at the gate until [`FakeIssuer::open_gate`].
    pub(crate) fn close_gate(&self) {
        self.gated.store(true, Ordering::SeqCst);
    }

    pub(crate) fn open_gate(&self) {
        self.gated.store(false, Ordering::SeqCst);
        self.open.notify_waiters();
    }

    /// Resolves when a refresh has reached the gate.
    pub(crate) async fn refresh_started(&self) {
        self.started.notified().await;
    }

    /// Whether the family of `refresh` has been revoked.
    pub(crate) fn family_revoked(&self, refresh: &RefreshToken) -> bool {
        let state = self.state.lock().expect("state");
        state
            .family_of
            .get(refresh.expose())
            .is_some_and(|family| state.revoked_families.contains(family))
    }
}

impl Grants for FakeIssuer {
    async fn refresh(
        &self,
        _kind: &str,
        refresh_token: &RefreshToken,
        resource: &str,
    ) -> Result<Renewed, GrantError> {
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        // Register for the wake-up before announcing the start, so a gate
        // opened right after is not missed.
        let open = self.open.notified();
        tokio::pin!(open);
        open.as_mut().enable();
        self.started.notify_waiters();
        if self.gated.load(Ordering::SeqCst) {
            open.await;
        }
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(GrantError::Unavailable);
        }
        let mut state = self.state.lock().expect("state");
        let presented = refresh_token.expose().to_owned();
        let Some(&family) = state.family_of.get(&presented) else {
            return Err(GrantError::Refused);
        };
        if state.revoked_families.contains(&family) {
            return Err(GrantError::Refused);
        }
        if !state.used.insert(presented) {
            state.revoked_families.insert(family);
            return Err(GrantError::Refused);
        }
        state.next += 1;
        let generation = state.next;
        let rotated = format!("refresh-{family}-{generation}");
        state.family_of.insert(rotated.clone(), family);
        Ok(Renewed {
            access_token: BearerToken::new(format!("access-{resource}-{family}-{generation}"))
                .expect("token"),
            expires_at: self.clock.now() + TOKEN_LIFETIME,
            refresh_token: Some(RefreshToken::new(rotated).expect("token")),
        })
    }

    async fn revoke(&self, _kind: &str, refresh_token: &RefreshToken) -> Result<(), GrantError> {
        self.revocations.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("state");
        // RFC 7009 lets an issuer ignore a token it already spent: revoking
        // one revokes nothing, so only the current token of a family ends it.
        if state.used.contains(refresh_token.expose()) {
            return Ok(());
        }
        if let Some(&family) = state.family_of.get(refresh_token.expose()) {
            state.revoked_families.insert(family);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    fn issuer() -> Arc<FakeIssuer> {
        FakeIssuer::new(Arc::new(ManualClock::new()))
    }

    #[tokio::test]
    async fn a_refresh_token_is_single_use_and_each_refresh_rotates() {
        let issuer = issuer();
        let (_, _, first) = issuer.sign_in("api");
        let renewed = issuer.refresh("k", &first, "api").await.expect("first use");
        let second = renewed.refresh_token.expect("rotated");
        assert_ne!(first.expose(), second.expose());
        issuer
            .refresh("k", &second, "api")
            .await
            .expect("rotated token");
        assert_eq!(issuer.refresh_calls(), 2);
    }

    #[tokio::test]
    async fn reusing_a_refresh_token_revokes_the_family() {
        let issuer = issuer();
        let (_, _, first) = issuer.sign_in("api");
        let renewed = issuer.refresh("k", &first, "api").await.expect("first use");
        let second = renewed.refresh_token.expect("rotated");
        assert_eq!(
            issuer.refresh("k", &first, "api").await.unwrap_err(),
            GrantError::Refused
        );
        assert!(issuer.family_revoked(&second));
        assert_eq!(
            issuer.refresh("k", &second, "api").await.unwrap_err(),
            GrantError::Refused
        );
    }

    #[tokio::test]
    async fn an_unknown_token_and_a_transport_failure_are_told_apart() {
        let issuer = issuer();
        assert_eq!(
            issuer
                .refresh("k", &RefreshToken::new("nope").expect("token"), "api")
                .await
                .unwrap_err(),
            GrantError::Refused
        );
        let (_, _, first) = issuer.sign_in("api");
        issuer.set_unavailable(true);
        assert_eq!(
            issuer.refresh("k", &first, "api").await.unwrap_err(),
            GrantError::Unavailable
        );
        issuer.set_unavailable(false);
        issuer
            .refresh("k", &first, "api")
            .await
            .expect("a transport failure consumed nothing");
    }

    #[tokio::test]
    async fn revoking_a_spent_token_revokes_nothing_and_the_current_token_ends_the_family() {
        let issuer = issuer();
        let (_, _, first) = issuer.sign_in("api");
        let renewed = issuer.refresh("k", &first, "api").await.expect("first use");
        let second = renewed.refresh_token.expect("rotated");
        issuer.revoke("k", &first).await.expect("accepted");
        assert!(!issuer.family_revoked(&second));
        issuer.revoke("k", &second).await.expect("revoked");
        assert!(issuer.family_revoked(&second));
    }

    #[tokio::test]
    async fn revocation_ends_the_family() {
        let issuer = issuer();
        let (_, _, first) = issuer.sign_in("api");
        issuer.revoke("k", &first).await.expect("revoked");
        assert_eq!(issuer.revoke_calls(), 1);
        assert_eq!(
            issuer.refresh("k", &first, "api").await.unwrap_err(),
            GrantError::Refused
        );
    }
}
