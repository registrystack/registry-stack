"""Framework-neutral OIDC sign-in and renewable server-side sessions.

Authlib owns authorization-code, PKCE, token endpoint, and refresh protocol
mechanics. This module owns the Registry Stack binding across resource grants
and the atomic session lifecycle. Framework adapters own cookies and routes.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
import hmac
import math
import secrets
import threading
import time
from types import MappingProxyType
from typing import Any, Callable, ContextManager, Iterator, Mapping, Protocol
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from weakref import WeakValueDictionary


class AdmissionError(ValueError):
    """A browser callback did not establish the complete configured identity."""

    code = "authentication.refused"

    def __init__(self):
        super().__init__(self.code)


class ReauthenticationRequired(ValueError):
    """No complete usable server-side session remains."""

    code = "authentication.reauthenticate"

    def __init__(self):
        super().__init__(self.code)


class CSRFError(ValueError):
    """A cookie-authorized mutation failed its origin or CSRF binding."""

    code = "authentication.csrf-refused"

    def __init__(self):
        super().__init__(self.code)


@dataclass(frozen=True)
class GrantPolicy:
    """One required product grant for a configured holder or staff persona."""

    name: str
    resource: str
    scopes: tuple[str, ...]
    profile: str
    required_claims: Mapping[str, str]
    forward_resource: str | None = None

    def __post_init__(self):
        if (
            not _token(self.name)
            or not _resource_uri(self.resource)
            or not self.scopes
            or len(set(self.scopes)) != len(self.scopes)
            or any(not _token(scope) for scope in self.scopes)
            or not _token(self.profile)
            or not self.required_claims
            or any(
                not _token(name) or not _text(value)
                for name, value in self.required_claims.items()
            )
            or (
                self.forward_resource is not None
                and (
                    not _resource_uri(self.forward_resource)
                    or self.forward_resource == self.resource
                )
            )
        ):
            raise ValueError(
                "grant policy needs exact resource, profile, scopes and claims"
            )
        object.__setattr__(self, "scopes", tuple(self.scopes))
        object.__setattr__(
            self, "required_claims", MappingProxyType(dict(self.required_claims))
        )

    @property
    def requested_resources(self) -> tuple[str, ...]:
        if self.forward_resource is None:
            return (self.resource,)
        return (self.resource, self.forward_resource)


@dataclass(frozen=True)
class PortalConfig:
    issuer: str
    client_id: str
    redirect_uri: str
    origin: str
    persona: str
    grants: tuple[GrantPolicy, ...]
    session_seconds: float = 900
    pending_seconds: float = 300

    def __post_init__(self):
        if (
            not _absolute_url(self.issuer)
            or not _token(self.client_id)
            or not _absolute_url(self.redirect_uri)
            or not _origin(self.origin)
            or self.persona not in ("holder", "staff")
            or not self.grants
            or not math.isfinite(self.session_seconds)
            or self.session_seconds <= 0
            or not math.isfinite(self.pending_seconds)
            or self.pending_seconds <= 0
        ):
            raise ValueError("portal configuration is incomplete or unsafe")
        redirect = urlsplit(self.redirect_uri)
        origin = urlsplit(self.origin)
        if (redirect.scheme, redirect.netloc) != (origin.scheme, origin.netloc):
            raise ValueError("redirect_uri must use the configured origin")
        names = [grant.name for grant in self.grants]
        resources = [grant.resource for grant in self.grants]
        if len(set(names)) != len(names) or len(set(resources)) != len(resources):
            raise ValueError("portal grants need distinct names and resources")
        object.__setattr__(self, "grants", tuple(self.grants))


@dataclass(frozen=True, repr=False)
class VerifiedGrant:
    """A token set already verified by the configured token verifier."""

    access_token: str
    refresh_token: str
    id_token: str | None
    expires_at: float
    issuer: str
    client_id: str
    subject: str
    principal: str
    persona: str
    resource: str
    profile: str
    scopes: tuple[str, ...]
    claims: Mapping[str, Any]
    authorized_party: str | None = None
    client_id_claim: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "scopes", tuple(self.scopes))
        object.__setattr__(self, "claims", MappingProxyType(dict(self.claims)))


@dataclass(frozen=True, repr=False)
class PendingGrant:
    state: str
    chain_id: str
    nonce: str
    code_verifier: str
    grant_index: int
    created_at: float
    expires_at: float
    return_to: str
    grants: tuple[VerifiedGrant, ...]


@dataclass(frozen=True)
class AuthorizationRequest:
    url: str
    state: str
    chain_id: str


@dataclass(frozen=True)
class CallbackResult:
    authorization: AuthorizationRequest | None
    session_id: str | None
    return_to: str | None


@dataclass(frozen=True)
class LogoutResult:
    end_session_url: str | None
    issuer_logout_available: bool


@dataclass(frozen=True, repr=False)
class PortalContext:
    session_id: str
    subject: str
    principal: str
    persona: str
    _access_tokens: Mapping[str, str]
    csrf_token: str
    expires_at: float

    def __post_init__(self):
        object.__setattr__(
            self, "_access_tokens", MappingProxyType(dict(self._access_tokens))
        )

    def _token_for(self, product: str) -> str:
        """Internal adapter hook; holder handlers receive product clients instead."""
        try:
            return self._access_tokens[product]
        except KeyError:
            raise ReauthenticationRequired() from None


@dataclass(frozen=True, repr=False)
class PortalSession:
    session_id: str
    subject: str
    principal: str
    persona: str
    grants: tuple[VerifiedGrant, ...]
    csrf_token: str
    created_at: float
    expires_at: float
    generation: int


class OIDCClient(Protocol):
    def authorization_url(
        self,
        grant_policy: GrantPolicy,
        *,
        state: str,
        nonce: str,
        code_verifier: str,
    ) -> str: ...

    def exchange(
        self, callback_url: str, pending: PendingGrant, grant_policy: GrantPolicy
    ) -> VerifiedGrant: ...

    def refresh(
        self, current: VerifiedGrant, grant_policy: GrantPolicy
    ) -> VerifiedGrant: ...

    def end_session_url(
        self, session: PortalSession, *, state: str, switch: bool = False
    ) -> str: ...


class SessionStore(Protocol):
    def refresh_lock(self, session_id: str) -> ContextManager[None]: ...

    def put_pending(self, pending: PendingGrant) -> bool: ...

    def consume_pending(self, state: str) -> PendingGrant | None: ...

    def close_chain(self, chain_id: str) -> None: ...

    def create_session(self, chain_id: str, session: PortalSession) -> bool: ...

    def get_session(self, session_id: str) -> PortalSession | None: ...

    def replace_session(
        self, session_id: str, expected_generation: int, session: PortalSession
    ) -> bool: ...

    def delete_session(
        self, session_id: str, expected_generation: int | None = None
    ) -> PortalSession | None: ...


class MemorySessionStore:
    """Single-process session state. A new store intentionally loses all sessions."""

    def __init__(self):
        self._pending: dict[str, PendingGrant] = {}
        self._sessions: dict[str, PortalSession] = {}
        self._closed_chains: set[str] = set()
        self._lock = threading.Lock()
        self._refresh_locks = WeakValueDictionary()
        self._refresh_locks_guard = threading.Lock()

    @contextmanager
    def refresh_lock(self, session_id: str) -> Iterator[None]:
        with self._refresh_locks_guard:
            lock = self._refresh_locks.get(session_id)
            if lock is None:
                lock = threading.Lock()
                self._refresh_locks[session_id] = lock
        with lock:
            yield

    def put_pending(self, pending: PendingGrant) -> bool:
        with self._lock:
            if (
                pending.chain_id in self._closed_chains
                or pending.state in self._pending
            ):
                return False
            self._pending[pending.state] = pending
            return True

    def consume_pending(self, state: str) -> PendingGrant | None:
        with self._lock:
            pending = self._pending.pop(state, None)
            if pending is None or pending.chain_id in self._closed_chains:
                return None
            return pending

    def close_chain(self, chain_id: str) -> None:
        with self._lock:
            self._closed_chains.add(chain_id)
            self._pending = {
                state: pending
                for state, pending in self._pending.items()
                if pending.chain_id != chain_id
            }

    def create_session(self, chain_id: str, session: PortalSession) -> bool:
        with self._lock:
            if chain_id in self._closed_chains or session.session_id in self._sessions:
                return False
            self._sessions[session.session_id] = session
            self._closed_chains.add(chain_id)
            return True

    def get_session(self, session_id: str) -> PortalSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def replace_session(
        self, session_id: str, expected_generation: int, session: PortalSession
    ) -> bool:
        with self._lock:
            current = self._sessions.get(session_id)
            if current is None or current.generation != expected_generation:
                return False
            self._sessions[session_id] = session
            return True

    def delete_session(
        self, session_id: str, expected_generation: int | None = None
    ) -> PortalSession | None:
        with self._lock:
            current = self._sessions.get(session_id)
            if current is None or (
                expected_generation is not None
                and current.generation != expected_generation
            ):
                return None
            return self._sessions.pop(session_id)

    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)


class PortalSessions:
    """Complete multi-resource sign-in and generation-checked renewal."""

    def __init__(
        self,
        config: PortalConfig,
        oidc: OIDCClient,
        store: SessionStore,
        *,
        clock: Callable[[], float] = time.time,
    ):
        self._config = config
        self._oidc = oidc
        self._store = store
        self._clock = clock

    def start(self, return_to: str = "/") -> AuthorizationRequest:
        _return_target(return_to)
        chain_id = secrets.token_urlsafe(32)
        return self._authorization(chain_id, 0, (), return_to)

    def replace_account(
        self, session_id: str, return_to: str = "/"
    ) -> AuthorizationRequest:
        self._store.delete_session(session_id)
        return self.start(return_to)

    def callback(self, callback_url: str, *, state: str) -> CallbackResult:
        pending = self._store.consume_pending(state)
        if pending is None:
            raise AdmissionError()
        now = self._clock()
        try:
            if (
                pending.expires_at <= now
                or not _same_callback(callback_url, self._config.redirect_uri)
                or not _callback_state(callback_url, state)
            ):
                raise AdmissionError()
            grant_policy = self._config.grants[pending.grant_index]
            grant = self._oidc.exchange(callback_url, pending, grant_policy)
            if not grant.id_token:
                raise AdmissionError()
            self._validate_grant(grant, grant_policy, now)
            grants = pending.grants + (grant,)
            if grants[:-1]:
                baseline = grants[0]
                if (
                    grant.issuer != baseline.issuer
                    or grant.client_id != baseline.client_id
                    or grant.subject != baseline.subject
                    or grant.principal != baseline.principal
                    or grant.persona != baseline.persona
                ):
                    raise AdmissionError()
            next_index = pending.grant_index + 1
            if next_index < len(self._config.grants):
                request = self._authorization(
                    pending.chain_id, next_index, grants, pending.return_to
                )
                return CallbackResult(request, None, None)
            session_id = secrets.token_urlsafe(32)
            session = PortalSession(
                session_id=session_id,
                subject=grant.subject,
                principal=grant.principal,
                persona=grant.persona,
                grants=grants,
                csrf_token=secrets.token_urlsafe(32),
                created_at=now,
                expires_at=now + self._config.session_seconds,
                generation=0,
            )
            if not self._store.create_session(pending.chain_id, session):
                raise AdmissionError()
            return CallbackResult(None, session_id, pending.return_to)
        except AdmissionError:
            self._store.close_chain(pending.chain_id)
            raise
        except Exception:
            self._store.close_chain(pending.chain_id)
            raise AdmissionError() from None

    def cancel(self, chain_id: str) -> None:
        self._store.close_chain(chain_id)

    def context(
        self, session_id: str, *, minimum_valid_seconds: float = 30
    ) -> PortalContext:
        if minimum_valid_seconds < 0 or not math.isfinite(minimum_valid_seconds):
            raise ValueError("minimum_valid_seconds must be finite and nonnegative")
        session = self._store.get_session(session_id)
        now = self._clock()
        if session is None or session.expires_at <= now:
            if session is not None:
                self._store.delete_session(session_id, session.generation)
            raise ReauthenticationRequired()
        if any(
            grant.expires_at <= now + minimum_valid_seconds for grant in session.grants
        ):
            session = self._refresh(session, minimum_valid_seconds)
        return self._context(session)

    def authorize_mutation(
        self, session_id: str, *, origin: str, csrf_token: str
    ) -> PortalContext:
        context = self.context(session_id, minimum_valid_seconds=0)
        if origin != self._config.origin or not hmac.compare_digest(
            csrf_token, context.csrf_token
        ):
            raise CSRFError()
        return context

    def logout(self, session_id: str, *, switch: bool = False) -> LogoutResult:
        session = self._store.delete_session(session_id)
        if session is None:
            return LogoutResult(None, False)
        try:
            url = self._oidc.end_session_url(
                session, state=secrets.token_urlsafe(24), switch=switch
            )
            return LogoutResult(url, True)
        except Exception:
            return LogoutResult(None, False)

    def _authorization(
        self,
        chain_id: str,
        grant_index: int,
        grants: tuple[VerifiedGrant, ...],
        return_to: str,
    ) -> AuthorizationRequest:
        now = self._clock()
        pending = PendingGrant(
            state=secrets.token_urlsafe(32),
            chain_id=chain_id,
            nonce=secrets.token_urlsafe(32),
            code_verifier=secrets.token_urlsafe(64),
            grant_index=grant_index,
            created_at=now,
            expires_at=now + self._config.pending_seconds,
            return_to=return_to,
            grants=grants,
        )
        if not self._store.put_pending(pending):
            raise AdmissionError()
        try:
            url = self._oidc.authorization_url(
                self._config.grants[grant_index],
                state=pending.state,
                nonce=pending.nonce,
                code_verifier=pending.code_verifier,
            )
            return AuthorizationRequest(url, pending.state, chain_id)
        except Exception:
            self._store.close_chain(chain_id)
            raise AdmissionError() from None

    def _refresh(
        self, session: PortalSession, minimum_valid_seconds: float
    ) -> PortalSession:
        with self._store.refresh_lock(session.session_id):
            current = self._store.get_session(session.session_id)
            now = self._clock()
            if current is None or current.expires_at <= now:
                raise ReauthenticationRequired()
            if not any(
                grant.expires_at <= now + minimum_valid_seconds
                for grant in current.grants
            ):
                return current
            return self._refresh_locked(current, minimum_valid_seconds)

    def _refresh_locked(
        self, session: PortalSession, minimum_valid_seconds: float
    ) -> PortalSession:
        now = self._clock()
        updated: list[VerifiedGrant] = []
        try:
            for grant, policy in zip(session.grants, self._config.grants, strict=True):
                candidate = grant
                if grant.expires_at <= now + minimum_valid_seconds:
                    candidate = self._oidc.refresh(grant, policy)
                    self._validate_grant(candidate, policy, now)
                    if (
                        candidate.subject != session.subject
                        or candidate.principal != session.principal
                        or candidate.persona != session.persona
                    ):
                        raise AdmissionError()
                updated.append(candidate)
        except Exception:
            current = self._store.get_session(session.session_id)
            if current is not None and current.generation != session.generation:
                return current
            self._store.delete_session(session.session_id, session.generation)
            raise ReauthenticationRequired() from None
        now = self._clock()
        if session.expires_at <= now:
            self._store.delete_session(session.session_id, session.generation)
            raise ReauthenticationRequired()
        replacement = replace(
            session, grants=tuple(updated), generation=session.generation + 1
        )
        if self._store.replace_session(
            session.session_id, session.generation, replacement
        ):
            return replacement
        current = self._store.get_session(session.session_id)
        if current is None or current.expires_at <= now:
            raise ReauthenticationRequired()
        return current

    def _validate_grant(
        self, grant: VerifiedGrant, policy: GrantPolicy, now: float
    ) -> None:
        if (
            not grant.access_token
            or not grant.refresh_token
            or not math.isfinite(grant.expires_at)
            or grant.expires_at <= now
            or grant.issuer != self._config.issuer
            or grant.client_id != self._config.client_id
            or grant.authorized_party not in (None, self._config.client_id)
            or grant.client_id_claim not in (None, self._config.client_id)
            or not grant.subject
            or not grant.principal
            or grant.persona != self._config.persona
            or grant.resource != policy.resource
            or grant.profile != policy.profile
            or not set(policy.scopes).issubset(grant.scopes)
            or any(
                grant.claims.get(name) != value
                for name, value in policy.required_claims.items()
            )
        ):
            raise AdmissionError()

    def _context(self, session: PortalSession) -> PortalContext:
        return PortalContext(
            session_id=session.session_id,
            subject=session.subject,
            principal=session.principal,
            persona=session.persona,
            _access_tokens={
                grant_policy.name: grant.access_token
                for grant_policy, grant in zip(
                    self._config.grants, session.grants, strict=True
                )
            },
            csrf_token=session.csrf_token,
            expires_at=session.expires_at,
        )


TokenVerifier = Callable[
    [Mapping[str, Any], str | None, GrantPolicy, VerifiedGrant | None],
    VerifiedGrant,
]


class AuthlibOIDCClient:
    """Authlib authorization-code/PKCE transport plus exact token verification."""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str | None,
        redirect_uri: str,
        authorization_endpoint: str,
        token_endpoint: str,
        end_session_endpoint: str | None,
        verify_token: TokenVerifier,
        switch_redirect_uri: str | None = None,
        timeout_seconds: float = 5,
    ):
        if (
            not _token(client_id)
            or not _absolute_url(redirect_uri)
            or not _absolute_url(authorization_endpoint)
            or not _absolute_url(token_endpoint)
            or (
                end_session_endpoint is not None
                and not _absolute_url(end_session_endpoint)
            )
            or (
                switch_redirect_uri is not None
                and (
                    end_session_endpoint is None
                    or not _absolute_url(switch_redirect_uri)
                    or switch_redirect_uri
                    != urlunsplit(
                        urlsplit(redirect_uri)._replace(
                            path="/auth/login", query="", fragment=""
                        )
                    )
                )
            )
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("Authlib OIDC endpoints and timeout must be bounded")
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._authorization_endpoint = authorization_endpoint
        self._token_endpoint = token_endpoint
        self._end_session_endpoint = end_session_endpoint
        self._switch_redirect_uri = switch_redirect_uri
        self._verify_token = verify_token
        self._timeout_seconds = timeout_seconds

    def authorization_url(
        self,
        grant_policy: GrantPolicy,
        *,
        state: str,
        nonce: str,
        code_verifier: str,
    ) -> str:
        client = self._session(grant_policy)
        try:
            url, returned_state = client.create_authorization_url(
                self._authorization_endpoint,
                state=state,
                nonce=nonce,
                code_verifier=code_verifier,
                resource=(
                    grant_policy.resource
                    if grant_policy.forward_resource is None
                    else grant_policy.requested_resources
                ),
            )
        finally:
            client.close()  # pyright: ignore[reportAttributeAccessIssue]
        if returned_state != state:
            raise AdmissionError()
        return url

    def exchange(
        self, callback_url: str, pending: PendingGrant, grant_policy: GrantPolicy
    ) -> VerifiedGrant:
        client = self._session(grant_policy, state=pending.state)
        try:
            token = client.fetch_token(
                self._token_endpoint,
                authorization_response=callback_url,
                state=pending.state,
                code_verifier=pending.code_verifier,
                body=urlencode(
                    [("resource", value) for value in grant_policy.requested_resources]
                ),
            )
        finally:
            client.close()  # pyright: ignore[reportAttributeAccessIssue]
        return self._verify_token(token, pending.nonce, grant_policy, None)

    def refresh(
        self, current: VerifiedGrant, grant_policy: GrantPolicy
    ) -> VerifiedGrant:
        client = self._session(grant_policy)
        try:
            token = client.refresh_token(
                self._token_endpoint,
                refresh_token=current.refresh_token,
                body=urlencode(
                    [("resource", value) for value in grant_policy.requested_resources]
                ),
                scope=" ".join(grant_policy.scopes),
            )
        finally:
            client.close()  # pyright: ignore[reportAttributeAccessIssue]
        if "refresh_token" not in token:
            token["refresh_token"] = current.refresh_token
        return self._verify_token(token, None, grant_policy, current)

    def end_session_url(
        self, session: PortalSession, *, state: str, switch: bool = False
    ) -> str:
        if self._end_session_endpoint is None:
            raise RuntimeError("the issuer has no end-session endpoint")
        id_token = next(
            (grant.id_token for grant in session.grants if grant.id_token), None
        )
        query = {"client_id": self._client_id, "state": state}
        if switch:
            if self._switch_redirect_uri is None or id_token is None:
                raise RuntimeError("the issuer account-switch return is unavailable")
            query["post_logout_redirect_uri"] = self._switch_redirect_uri
        if id_token is not None:
            query["id_token_hint"] = id_token
        parts = urlsplit(self._end_session_endpoint)
        return urlunsplit(parts._replace(query=urlencode(query)))

    def _session(self, grant_policy: GrantPolicy, *, state: str | None = None):
        from authlib.integrations.requests_client import OAuth2Session  # pyright: ignore[reportMissingModuleSource]

        class ResourceSession(OAuth2Session):
            # Authlib 1.9.6 converts token form fields to a dict, dropping
            # repeated RFC 8707 resource parameters. Preserve the form body.
            def _fetch_token(
                self, url, body="", headers=None, auth=None, method="POST", **kwargs
            ):
                if method.upper() != "POST":
                    raise AdmissionError()
                response = self.session.post(
                    url, data=body, headers=headers, auth=auth, **kwargs
                )
                for hook in self.compliance_hook["access_token_response"]:
                    response = hook(response)
                return self.parse_response_token(response)

            def _http_post(self, url, body=None, auth=None, headers=None, **kwargs):
                return self.session.post(
                    url, data=body, headers=headers, auth=auth, **kwargs
                )

        scopes = tuple(
            dict.fromkeys(("openid", "offline_access", *grant_policy.scopes))
        )
        return ResourceSession(
            client_id=self._client_id,
            client_secret=self._client_secret,
            token_endpoint_auth_method=(
                "client_secret_post" if self._client_secret else "none"
            ),
            redirect_uri=self._redirect_uri,
            scope=" ".join(scopes),
            state=state,
            code_challenge_method="S256",
            default_timeout=self._timeout_seconds,
        )


def _callback_state(callback_url: str, expected: str) -> bool:
    try:
        query = parse_qs(
            urlsplit(callback_url).query,
            strict_parsing=True,
            keep_blank_values=True,
            max_num_fields=8,
        )
        return (
            query.get("state") == [expected]
            and len(query.get("code", ())) == 1
            and bool(query["code"][0])
            and "error" not in query
        )
    except (ValueError, KeyError):
        return False


def _same_callback(received: str, configured: str) -> bool:
    try:
        actual = urlsplit(received)
        expected = urlsplit(configured)
    except ValueError:
        return False
    return (
        actual.scheme,
        actual.netloc,
        actual.path,
        actual.fragment,
    ) == (
        expected.scheme,
        expected.netloc,
        expected.path,
        "",
    )


def _return_target(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value.startswith("//")
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("return_to must be a local absolute path")


def _absolute_url(value: str) -> bool:
    if not _text(value):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return bool(
        parts.scheme == "https"
        and parts.hostname
        and parts.username is None
        and parts.password is None
        and not parts.fragment
    )


def _resource_uri(value: str) -> bool:
    if not _text(value) or any(character.isspace() for character in value):
        return False
    try:
        parts = urlsplit(value)
        parts.port
    except ValueError:
        return False
    return bool(
        parts.scheme
        and (parts.path or parts.netloc)
        and not parts.fragment
        and parts.username is None
        and parts.password is None
        and (parts.scheme not in ("http", "https") or parts.hostname)
    )


def _origin(value: str) -> bool:
    if not _absolute_url(value):
        return False
    parts = urlsplit(value)
    return not parts.path.strip("/") and not parts.query


def _token(value: str) -> bool:
    return bool(
        isinstance(value, str)
        and 1 <= len(value) <= 256
        and value.strip() == value
        and not any(character.isspace() or ord(character) < 33 for character in value)
    )


def _text(value: str) -> bool:
    return bool(
        isinstance(value, str)
        and value
        and value.strip() == value
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )
