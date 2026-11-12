from typing import Any, Mapping, Protocol

class AdmissionError(ValueError):
    code: str

class AdmissionUnavailable(RuntimeError):
    code: str
    def __init__(self) -> None: ...

class TokenVerifier(Protocol):
    def verify(self, token: str) -> Any: ...

class MachineContext:
    subject: str
    client_id: str
    profile: str
    issuer: str
    resource: str
    persona: str

class MachineAdmission:
    def __init__(
        self,
        verifier: TokenVerifier,
        *,
        issuer: str,
        resource: str,
        client_id: str,
        profile: str,
        required_scopes: tuple[str, ...],
        required_claims: Mapping[str, str],
    ) -> None: ...
    def admit(self, request_values: Mapping[str, Any]) -> MachineContext: ...
