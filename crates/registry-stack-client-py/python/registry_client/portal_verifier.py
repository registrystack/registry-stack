"""Turn native OIDC verification into one bounded personal product grant."""

from __future__ import annotations

from typing import Any, Mapping, TypeGuard, cast

from .portal import AdmissionError, GrantPolicy, VerifiedGrant


class NativeGrantVerifier:
    """One issuer/client/persona and one native verifier per product resource."""

    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        persona: str,
        grants: Mapping[str, GrantPolicy],
        verifiers: Mapping[str, Any],
        principal_claim: str = "registry_principal",
        actor_kind_claim: str = "registry_actor_kind",
    ):
        if (
            persona not in ("holder", "staff")
            or not grants
            or set(grants) != set(verifiers)
            or any(name != policy.name for name, policy in grants.items())
            or not principal_claim
            or not actor_kind_claim
        ):
            raise ValueError("native grant verifier needs exact per-resource policy")
        self._issuer = issuer
        self._client_id = client_id
        self._persona = persona
        self._grants = dict(grants)
        self._verifiers = dict(verifiers)
        self._principal_claim = principal_claim
        self._actor_kind_claim = actor_kind_claim

    @classmethod
    def from_native(
        cls,
        *,
        issuer: str,
        client_id: str,
        persona: str,
        grants: tuple[GrantPolicy, ...],
        algorithm: str,
        access_token_type: str = "at+jwt",
        maximum_access_token_lifetime_seconds: int = 300,
        maximum_id_token_lifetime_seconds: int = 3600,
        jwks_uri: str | None = None,
        allow_insecure_http: bool = False,
        principal_claim: str = "registry_principal",
        actor_kind_claim: str = "registry_actor_kind",
    ) -> NativeGrantVerifier:
        from .oidc import AccessTokenVerifier  # pyright: ignore[reportMissingImports]

        verifiers = {
            policy.name: AccessTokenVerifier(
                issuer,
                policy.resource,
                client_id,
                algorithm=algorithm,
                access_token_type=access_token_type,
                maximum_access_token_lifetime_seconds=maximum_access_token_lifetime_seconds,
                maximum_id_token_lifetime_seconds=maximum_id_token_lifetime_seconds,
                claim_names=tuple(
                    dict.fromkeys(
                        (principal_claim, actor_kind_claim, *policy.required_claims)
                    )
                ),
                jwks_uri=jwks_uri,
                allow_insecure_http=allow_insecure_http,
                additional_audiences=(
                    (policy.forward_resource,) if policy.forward_resource else ()
                ),
            )
            for policy in grants
        }
        return cls(
            issuer=issuer,
            client_id=client_id,
            persona=persona,
            grants={policy.name: policy for policy in grants},
            verifiers=verifiers,
            principal_claim=principal_claim,
            actor_kind_claim=actor_kind_claim,
        )

    def __call__(
        self,
        token_response: Mapping[str, Any],
        expected_nonce: str | None,
        policy: GrantPolicy,
        current: VerifiedGrant | None,
    ) -> VerifiedGrant:
        if self._grants.get(policy.name) != policy or (expected_nonce is None) == (
            current is None
        ):
            raise AdmissionError()
        access_token = token_response.get("access_token")
        refresh_token = token_response.get("refresh_token")
        id_token = token_response.get("id_token")
        if (
            not _bearer(access_token)
            or not _bearer(refresh_token)
            or (expected_nonce is not None and not _bearer(id_token))
        ):
            raise AdmissionError()
        verifier = self._verifiers[policy.name]
        try:
            access = verifier.verify(access_token)
            identity = (
                verifier.verify_id_token(id_token, expected_nonce)
                if expected_nonce is not None
                else None
            )
        except Exception:
            raise AdmissionError() from None
        claims = access.claims
        if (
            not isinstance(claims, Mapping)
            or not isinstance(access.scopes, (tuple, list))
            or any(not isinstance(scope, str) for scope in access.scopes)
        ):
            raise AdmissionError()
        principal = claims.get(self._principal_claim)
        if (
            access.kind != "access"
            or access.issuer != self._issuer
            or not isinstance(access.audiences, (tuple, list))
            or any(not isinstance(value, str) for value in access.audiences)
            or len(access.audiences) != len(policy.requested_resources)
            or set(access.audiences) != set(policy.requested_resources)
            or access.client_id != self._client_id
            or not isinstance(access.subject, str)
            or not access.subject
            or not isinstance(principal, str)
            or not principal
            or claims.get(self._actor_kind_claim) != "human"
            or not set(policy.scopes).issubset(access.scopes)
            or any(
                claims.get(name) != expected
                for name, expected in policy.required_claims.items()
            )
        ):
            raise AdmissionError()
        if identity is not None and (
            identity.kind != "id"
            or identity.issuer != self._issuer
            or identity.audiences != (self._client_id,)
            or identity.client_id != self._client_id
            or identity.subject != access.subject
        ):
            raise AdmissionError()
        if current is not None and (
            current.issuer != access.issuer
            or current.client_id != access.client_id
            or current.subject != access.subject
            or current.principal != principal
            or current.persona != self._persona
            or current.resource != policy.resource
            or current.profile != policy.profile
        ):
            raise AdmissionError()
        if identity is not None:
            selected_id_token = id_token
        else:
            if current is None:
                raise AdmissionError()
            selected_id_token = current.id_token
        return VerifiedGrant(
            access_token=access_token,
            refresh_token=refresh_token,
            id_token=selected_id_token,
            expires_at=access.expires_at,
            issuer=access.issuer,
            client_id=access.client_id,
            subject=access.subject,
            principal=principal,
            persona=self._persona,
            resource=policy.resource,
            profile=policy.profile,
            scopes=cast(tuple[str, ...], tuple(access.scopes)),
            claims=claims,
            authorized_party=access.client_id,
            client_id_claim=access.client_id,
        )


def _bearer(value: Any) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 8192
        and not any(character.isspace() for character in value)
    )
