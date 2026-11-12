from typing import Any, Mapping

from .portal import GrantPolicy, VerifiedGrant

class NativeGrantVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        persona: str,
        grants: Mapping[str, GrantPolicy],
        verifiers: Mapping[str, Any],
        principal_claim: str = ...,
        actor_kind_claim: str = ...,
    ) -> None: ...
    @classmethod
    def from_native(
        cls,
        *,
        issuer: str,
        client_id: str,
        persona: str,
        grants: tuple[GrantPolicy, ...],
        algorithm: str,
        access_token_type: str = ...,
        maximum_access_token_lifetime_seconds: int = ...,
        maximum_id_token_lifetime_seconds: int = ...,
        jwks_uri: str | None = ...,
        allow_insecure_http: bool = ...,
        principal_claim: str = ...,
        actor_kind_claim: str = ...,
    ) -> NativeGrantVerifier: ...
    def __call__(
        self,
        token_response: Mapping[str, Any],
        expected_nonce: str | None,
        policy: GrantPolicy,
        current: VerifiedGrant | None,
    ) -> VerifiedGrant: ...
