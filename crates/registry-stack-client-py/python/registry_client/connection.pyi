from pathlib import Path

from .workload import MessagingWorkload
from .workload_breg import BRegWorkload
from .machine import MachineContext
from typing import Any, Mapping

API_VERSION: str
CONNECTION_ENV: str

class ConnectionError(ValueError):
    diagnostics: tuple[Mapping[str, Any], ...]
    def __init__(self, message: str, *, diagnostics: tuple[Mapping[str, Any], ...] = ...) -> None: ...

class UnsupportedOperationError(AttributeError):
    code: str
    product: str
    operation: str
    def __init__(self, product: str, operation: str) -> None: ...

class WorkloadAuthority:
    fingerprint: str
    product: str
    issuer: str
    subject: str
    client_id: str
    profile: str
    resource: str
    scopes: tuple[str, ...]
    claims: Mapping[str, Any]

class _Binding:
    name: str
    product: str
    credential: Mapping[str, Any]

class BoundConnection:
    @property
    def authority(self) -> WorkloadAuthority: ...
    @property
    def breg(self) -> BRegWorkload: ...
    @property
    def messaging(self) -> MessagingWorkload: ...

class Connection:
    _bindings: Mapping[str, _Binding]
    _providers: Mapping[str, Any]
    def using(self, name: str) -> BoundConnection: ...
    def authority(self, product: str) -> WorkloadAuthority: ...
    def admit(self, request_values: Mapping[str, Any]) -> MachineContext: ...
    @property
    def breg(self) -> BRegWorkload: ...
    @property
    def messaging(self) -> MessagingWorkload: ...

def connect(*, path: str | Path | None = None) -> Connection: ...
def _secret(reference: str, providers: Mapping[str, Any]) -> str: ...
