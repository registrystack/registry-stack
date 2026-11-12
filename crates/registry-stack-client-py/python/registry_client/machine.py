"""Framework-neutral admission of a caller to one machine service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


class AdmissionError(ValueError):
    """The request has no verified machine authority for this service."""

    code = "authentication.refused"

    def __init__(self):
        super().__init__(self.code)


class AdmissionUnavailable(RuntimeError):
    """The verifier cannot establish caller authority at this time."""

    code = "authentication.unavailable"

    def __init__(self):
        super().__init__(self.code)


class _Verifier(Protocol):
    def verify(self, token: str) -> Any: ...


@dataclass(frozen=True)
class MachineContext:
    """A verified invoker, separate from the service's workload bindings."""

    subject: str
    client_id: str
    profile: str
    issuer: str
    resource: str
    persona: str = "service"


class MachineAdmission:
    """Apply exact machine persona policy after native signature verification."""

    def __init__(
        self,
        verifier: _Verifier,
        *,
        issuer: str,
        resource: str,
        client_id: str,
        profile: str,
        required_scopes: tuple[str, ...],
        required_claims: Mapping[str, str],
    ):
        self._verifier = verifier
        self._issuer = issuer
        self._resource = resource
        self._client_id = client_id
        self._profile = profile
        self._required_scopes = frozenset(required_scopes)
        self._required_claims = dict(required_claims)
        if (
            not issuer
            or not resource
            or not client_id
            or not profile
            or not required_scopes
            or not required_claims
        ):
            raise ValueError(
                "machine admission needs exact client, profile, scope and claim policy"
            )

    def admit(self, request_values: Mapping[str, Any]) -> MachineContext:
        """Read exactly one bearer; cookies and browser headers confer no authority."""
        authorization = request_values.get("authorization")
        if isinstance(authorization, str):
            headers = (authorization,)
        elif isinstance(authorization, (list, tuple)):
            headers = tuple(authorization)
        else:
            headers = ()
        if len(headers) != 1 or not isinstance(headers[0], str):
            raise AdmissionError()
        header = headers[0]
        if (
            not header.startswith("Bearer ")
            or len(header) > 8192
            or not header[7:]
            or any(char.isspace() for char in header[7:])
        ):
            raise AdmissionError()
        try:
            verified = self._verifier.verify(header[7:])
        except Exception as exc:
            if getattr(exc, "kind", None) == "verification":
                raise AdmissionError() from None
            raise AdmissionUnavailable() from None
        claims = getattr(verified, "claims", None)
        scopes = getattr(verified, "scopes", None)
        if (
            getattr(verified, "kind", None) != "access"
            or getattr(verified, "issuer", None) != self._issuer
            or getattr(verified, "audiences", None) != (self._resource,)
            or getattr(verified, "client_id", None) != self._client_id
            or not getattr(verified, "subject", None)
            or not isinstance(scopes, (tuple, list))
            or not self._required_scopes.issubset(scopes)
            or not isinstance(claims, Mapping)
            or any(
                claims.get(name) != value
                for name, value in self._required_claims.items()
            )
        ):
            raise AdmissionError()
        return MachineContext(
            verified.subject,
            verified.client_id,
            self._profile,
            verified.issuer,
            self._resource,
        )
