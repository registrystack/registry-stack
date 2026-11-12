from collections.abc import Callable, Mapping
from typing import Any, ContextManager, Protocol

class AdmissionError(ValueError):
    code: str

class ReauthenticationRequired(ValueError):
    code: str

class CSRFError(ValueError):
    code: str

class GrantPolicy:
    name: str
    resource: str
    scopes: tuple[str, ...]
    profile: str
    required_claims: Mapping[str, str]
    forward_resource: str | None
    requested_resources: tuple[str, ...]
    def __init__(
        self,
        name: str,
        resource: str,
        scopes: tuple[str, ...],
        profile: str,
        required_claims: Mapping[str, str],
        forward_resource: str | None = ...,
    ) -> None: ...

class PortalConfig:
    issuer: str
    client_id: str
    redirect_uri: str
    origin: str
    persona: str
    grants: tuple[GrantPolicy, ...]
    session_seconds: float
    pending_seconds: float
    def __init__(
        self,
        issuer: str,
        client_id: str,
        redirect_uri: str,
        origin: str,
        persona: str,
        grants: tuple[GrantPolicy, ...],
        session_seconds: float = ...,
        pending_seconds: float = ...,
    ) -> None: ...

class VerifiedGrant:
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
    authorized_party: str | None
    client_id_claim: str | None
    def __init__(
        self,
        access_token: str,
        refresh_token: str,
        id_token: str | None,
        expires_at: float,
        issuer: str,
        client_id: str,
        subject: str,
        principal: str,
        persona: str,
        resource: str,
        profile: str,
        scopes: tuple[str, ...],
        claims: Mapping[str, Any],
        authorized_party: str | None = ...,
        client_id_claim: str | None = ...,
    ) -> None: ...

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

class AuthorizationRequest:
    url: str
    state: str
    chain_id: str

class CallbackResult:
    authorization: AuthorizationRequest | None
    session_id: str | None
    return_to: str | None

class LogoutResult:
    end_session_url: str | None
    issuer_logout_available: bool

class PortalContext:
    session_id: str
    subject: str
    principal: str
    persona: str
    csrf_token: str
    expires_at: float
    def _token_for(self, product: str) -> str: ...

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
        self, session: PortalSession, *, state: str, switch: bool = ...
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
        self, session_id: str, expected_generation: int | None = ...
    ) -> PortalSession | None: ...

class MemorySessionStore(SessionStore):
    def __init__(self) -> None: ...
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
        self, session_id: str, expected_generation: int | None = ...
    ) -> PortalSession | None: ...
    def session_count(self) -> int: ...

class PortalSessions:
    def __init__(
        self,
        config: PortalConfig,
        oidc: OIDCClient,
        store: SessionStore,
        *,
        clock: Callable[[], float] = ...,
    ) -> None: ...
    def start(self, return_to: str = ...) -> AuthorizationRequest: ...
    def replace_account(
        self, session_id: str, return_to: str = ...
    ) -> AuthorizationRequest: ...
    def callback(self, callback_url: str, *, state: str) -> CallbackResult: ...
    def cancel(self, chain_id: str) -> None: ...
    def context(
        self, session_id: str, *, minimum_valid_seconds: float = ...
    ) -> PortalContext: ...
    def authorize_mutation(
        self, session_id: str, *, origin: str, csrf_token: str
    ) -> PortalContext: ...
    def logout(self, session_id: str, *, switch: bool = ...) -> LogoutResult: ...

TokenVerifier = Callable[
    [Mapping[str, Any], str | None, GrantPolicy, VerifiedGrant | None],
    VerifiedGrant,
]

class AuthlibOIDCClient(OIDCClient):
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
        switch_redirect_uri: str | None = ...,
        timeout_seconds: float = ...,
    ) -> None: ...
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
        self, session: PortalSession, *, state: str, switch: bool = ...
    ) -> str: ...
