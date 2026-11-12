from collections.abc import Mapping, Sequence
from typing import Literal

TokenAlgorithm = Literal["EdDSA", "ES256", "ES384", "RS256", "RS384"]
TokenKind = Literal["access", "id"]

class TokenVerificationError(Exception):
    """A stable failure that contains no token or configured identity values."""

    kind: Literal["configuration", "verification", "runtime"]

class VerifiedToken:
    @property
    def kind(self) -> TokenKind: ...
    @property
    def issuer(self) -> str: ...
    @property
    def audiences(self) -> tuple[str, ...]: ...
    @property
    def subject(self) -> str: ...
    @property
    def client_id(self) -> str: ...
    @property
    def scopes(self) -> tuple[str, ...]: ...
    @property
    def expires_at(self) -> int: ...
    @property
    def issued_at(self) -> int: ...
    @property
    def not_before(self) -> int | None: ...
    @property
    def claims(self) -> Mapping[str, str]: ...

class AccessTokenVerifier:
    def __init__(
        self,
        issuer: str,
        resource: str,
        client_id: str,
        *,
        algorithm: TokenAlgorithm,
        maximum_access_token_lifetime_seconds: int,
        access_token_type: str = ...,
        maximum_id_token_lifetime_seconds: int = ...,
        clock_skew_seconds: int = ...,
        claim_names: Sequence[str] = ...,
        additional_audiences: Sequence[str] = ...,
        jwks_uri: str | None = ...,
        allow_insecure_http: bool = ...,
    ) -> None: ...
    @classmethod
    def from_static_jwks(
        cls,
        jwks_json: str,
        issuer: str,
        resource: str,
        client_id: str,
        *,
        algorithm: TokenAlgorithm,
        maximum_access_token_lifetime_seconds: int,
        access_token_type: str = ...,
        maximum_id_token_lifetime_seconds: int = ...,
        clock_skew_seconds: int = ...,
        claim_names: Sequence[str] = ...,
        additional_audiences: Sequence[str] = ...,
    ) -> AccessTokenVerifier: ...
    def verify(self, token: str) -> VerifiedToken: ...
    def verify_access_token(self, token: str) -> VerifiedToken: ...
    def verify_id_token(self, token: str, expected_nonce: str) -> VerifiedToken: ...
