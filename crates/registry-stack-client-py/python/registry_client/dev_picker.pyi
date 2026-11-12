from pathlib import Path
from typing import Any, Callable

from .connection import Connection
from .workload_breg import BRegWorkload
from .workload_casework import CaseworkWorkload

class PickerUnavailable(ValueError):
    code: str
class PickerAdmissionError(ValueError):
    code: str

class PickerChoice:
    label: str
    selector: str

class PickerForm:
    pending_id: str
    csrf_token: str
    choices: tuple[PickerChoice, ...]

class PickerSession:
    session_id: str
    csrf_token: str
    expires_at: float

class DevelopmentPerson:
    @property
    def session_id(self) -> str: ...
    @property
    def subject(self) -> str: ...
    @property
    def principal(self) -> str: ...
    @property
    def persona(self) -> str: ...
    @property
    def csrf_token(self) -> str: ...
    @property
    def expires_at(self) -> float: ...
    @property
    def breg(self) -> BRegWorkload: ...
    @property
    def casework(self) -> CaseworkWorkload: ...

class DevelopmentPicker:
    @classmethod
    def from_descriptor(cls, path: str | Path) -> DevelopmentPicker: ...
    @property
    def origin(self) -> str: ...
    @property
    def persona(self) -> str: ...
    @property
    def session_cookie(self) -> str: ...
    @property
    def pending_cookie(self) -> str: ...
    @property
    def workloads(self) -> Connection: ...
    def choices(self) -> tuple[PickerChoice, ...]: ...
    def begin(self) -> PickerForm: ...
    def select(
        self,
        pending_id: str,
        *,
        selector: str,
        origin: str,
        host: str,
        csrf_token: str,
    ) -> PickerSession: ...
    def context(self, session_id: str) -> DevelopmentPerson: ...
    def authorize_mutation(
        self, session_id: str, *, origin: str, csrf_token: str
    ) -> DevelopmentPerson: ...
    def logout(self, session_id: str) -> None: ...
    def session_count(self) -> int: ...

def install_flask(
    app: Any,
    picker: DevelopmentPicker,
    *,
    person_factory: Callable[[DevelopmentPerson], Any],
    request_seconds: float,
) -> None: ...

def install_fastapi(
    app: Any,
    picker: DevelopmentPicker,
    *,
    person_factory: Callable[[DevelopmentPerson], Any],
    request_seconds: float,
) -> None: ...
