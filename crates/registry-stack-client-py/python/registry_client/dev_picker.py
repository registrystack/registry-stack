"""Runner-bound local person selection for a trusted developer machine.

This simulates admission for the local edit loop. It is not OIDC, does not
mint credentials, and cannot be enabled by a boolean or a production
connection. The only entry point is an owner-only descriptor beneath a live
``rstack dev`` run whose supervisor still holds its run lock.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import html
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping, MutableMapping
from urllib.parse import parse_qs, urlsplit

from .connection import ConnectionError, _claims
from .portal import CSRFError, PortalContext, ReauthenticationRequired


DESCRIPTOR_VERSION = "id.registrystack.org/formats/platform/dev-person-picker/v1alpha1"
TOKEN_VERSION = "id.registrystack.org/formats/platform/dev-person-token/v1alpha1"
GENERATION_VERSION = "id.registrystack.org/formats/platform/dev-person-generation/v1alpha1"
CONNECTION_VERSION = "id.registrystack.org/formats/platform/python-connection/v1alpha1"
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_LOCAL_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{20,128}\Z")
_SCOPE = re.compile(r"\S{1,128}\Z")
_MAXIMUM_FILE_BYTES = 1_048_576
_MAXIMUM_FORM_BYTES = 65_536


class PickerUnavailable(ValueError):
    """The development run or one of its exact credentials is unavailable."""

    code = "development-picker.unavailable"

    def __init__(self, detail: str = "development picker is unavailable"):
        super().__init__(f"{self.code}: {detail}")


class PickerAdmissionError(ValueError):
    """A local browser selection did not establish one complete person."""

    code = "development-picker.admission-refused"

    def __init__(self):
        super().__init__(self.code)


@dataclass(frozen=True)
class PickerChoice:
    """The only non-secret person facts rendered into the selection form."""

    label: str
    selector: str


@dataclass(frozen=True, repr=False)
class PickerForm:
    pending_id: str
    csrf_token: str
    choices: tuple[PickerChoice, ...]


@dataclass(frozen=True, repr=False)
class PickerSession:
    session_id: str
    csrf_token: str
    expires_at: float


class DevelopmentPerson:
    """Request-local person facts and endpoint-bound product clients."""

    __slots__ = ("_context", "_person", "_products")

    def __init__(
        self,
        context: PortalContext,
        person: _Person,
        products: Mapping[str, Mapping[str, str]],
    ):
        self._context = context
        self._person = person
        self._products = products

    @property
    def subject(self) -> str:
        return self._context.subject

    @property
    def session_id(self) -> str:
        return self._context.session_id

    @property
    def principal(self) -> str:
        return self._context.principal

    @property
    def persona(self) -> str:
        return self._context.persona

    @property
    def csrf_token(self) -> str:
        return self._context.csrf_token

    @property
    def expires_at(self) -> float:
        return self._context.expires_at

    @property
    def breg(self):
        credential = self._person.credentials.get("breg")
        target = self._products.get("breg")
        if credential is None or target is None:
            raise ReauthenticationRequired()
        from . import breg
        from .workload_breg import BRegWorkload

        return BRegWorkload(
            breg.BaseRegistryClient(
                target["url"], authorization={"static": self._context._token_for("breg")}
            )
        )

    @property
    def casework(self):
        credential = self._person.credentials.get("casework")
        target = self._products.get("casework")
        if credential is None or target is None:
            raise ReauthenticationRequired()
        from . import casework
        from .workload_casework import CaseworkWorkload

        return CaseworkWorkload(
            casework.CaseworkClient(target["url"]),
            self._context._token_for("casework"),
            credential.profile,
        )


@dataclass(frozen=True, repr=False)
class _Credential:
    token_ref: str
    profile: str
    resource: str
    audiences: tuple[str, ...]
    scopes: tuple[str, ...]
    principal_claim: str


@dataclass(frozen=True, repr=False)
class _Person:
    selector: str
    label: str
    subject: str
    principal: str
    client_id: str
    credentials: Mapping[str, _Credential]


@dataclass(frozen=True, repr=False)
class _StoredSession:
    session_id: str
    selector: str
    subject: str
    principal: str
    client_id: str
    csrf_token: str
    expires_at: float


def _json(path: Path) -> Any:
    _private_file(path)
    try:
        contents = path.read_bytes()
    except OSError as exc:
        raise PickerUnavailable("runner state is unavailable") from exc
    if len(contents) > _MAXIMUM_FILE_BYTES:
        raise PickerUnavailable("runner state exceeds its size limit")

    def unique(pairs):
        value = {}
        for name, member in pairs:
            if name in value:
                raise PickerUnavailable("runner state contains a duplicate field")
            value[name] = member
        return value

    try:
        return json.loads(contents, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PickerUnavailable("runner state is malformed") from exc


def _private_file(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PickerUnavailable("runner state is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o177
    ):
        raise PickerUnavailable("runner state must be an owner-only regular file")
    return metadata


def _private_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PickerUnavailable("runner directory is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
    ):
        raise PickerUnavailable("runner directory must be owner-only")


def _object(value: Any, *, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise PickerUnavailable(f"{name} has unsupported or missing fields")
    return value


def _text(value: Any, *, name: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value.strip() != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PickerUnavailable(f"{name} is malformed")
    return value


def _epoch(value: Any, *, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PickerUnavailable(f"{name} is malformed")
    return value


def _scopes(value: Any, *, name: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 32
        or any(not isinstance(scope, str) or not _SCOPE.fullmatch(scope) for scope in value)
        or len(set(value)) != len(value)
    ):
        raise PickerUnavailable(f"{name} is malformed")
    return tuple(value)


def _resource(value: Any, *, name: str) -> str:
    value = _text(value, name=name, maximum=512)
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise PickerUnavailable(f"{name} is malformed") from exc
    if (
        not parsed.scheme
        or not (parsed.netloc or parsed.path)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or any(character.isspace() for character in value)
    ):
        raise PickerUnavailable(f"{name} is malformed")
    return value


def _loopback_origin(value: Any, *, name: str) -> str:
    value = _text(value, name=name, maximum=512)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise PickerUnavailable(f"{name} must be an exact loopback HTTP origin") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in ("127.0.0.1", "::1")
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise PickerUnavailable(f"{name} must be an exact loopback HTTP origin")
    return value.rstrip("/")


def _relative_file(root: Path, reference: Any, *, name: str, allow_parent: bool = False) -> Path:
    reference = _text(reference, name=name, maximum=256)
    candidate = Path(reference)
    if candidate.is_absolute() or "\\" in reference:
        raise PickerUnavailable(f"{name} must be a runner-local file reference")
    parts = candidate.parts
    if not allow_parent and any(part in ("", ".", "..") for part in parts):
        raise PickerUnavailable(f"{name} must be a runner-local file reference")
    try:
        resolved = (root / candidate).resolve(strict=True)
    except OSError as exc:
        raise PickerUnavailable(f"{name} is unavailable") from exc
    return resolved


def _b64_json(segment: str) -> Mapping[str, Any]:
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        value = json.loads(raw)
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise PickerUnavailable("runner person token is malformed") from exc
    if not isinstance(value, dict):
        raise PickerUnavailable("runner person token is malformed")
    return value


def _host(origin: str) -> str:
    return urlsplit(origin).netloc


class DevelopmentPicker:
    """One persona's run-scoped, memory-only local admission simulation."""

    def __init__(self, path: Path, document: Mapping[str, Any], digest: bytes):
        self._path = path
        self._digest = digest
        self._root = path.parents[2]
        self._picker_root = path.parent
        self._run_id = document["runId"]
        self._persona = document["persona"]
        self._origin = document["origin"]
        self._namespace = document["sessionNamespace"]
        self._issued_at = document["issuedAt"]
        self._expires_at = document["expiresAt"]
        self._generation_path = _relative_file(
            self._picker_root, document["generationRef"], name="generationRef"
        )
        self._products = document["products"]
        self._people = document["people"]
        self._workload_connection_path = document["workloadConnectionPath"]
        self._workloads = document["workloads"]
        self._pending: dict[str, tuple[str, float]] = {}
        self._sessions: dict[str, _StoredSession] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_descriptor(cls, path: str | Path) -> DevelopmentPicker:
        """Load only a descriptor at the fixed location of a live runner."""
        selected = Path(path)
        if not selected.is_absolute() or selected.name != "picker.json":
            raise PickerUnavailable("descriptor is not a private live development run reference")
        try:
            selected = selected.resolve(strict=True)
        except OSError as exc:
            raise PickerUnavailable("descriptor is unavailable") from exc
        if len(selected.parents) < 3 or selected.parent.parent.name != "python-picker":
            raise PickerUnavailable("descriptor is not a private live development run reference")
        for directory in (selected.parent, selected.parent.parent, selected.parents[2]):
            _private_directory(directory)
        raw = selected.read_bytes()
        document = _json(selected)
        document = cls._parse_descriptor(selected, document)
        picker = cls(selected, document, hashlib.sha256(raw).digest())
        picker._check_live()
        picker._read_generation()
        picker._validate_workload_connection()
        return picker

    @staticmethod
    def _parse_descriptor(path: Path, document: Any) -> Mapping[str, Any]:
        fields = {
            "apiVersion", "kind", "runId", "persona", "origin", "sessionNamespace",
            "issuedAt", "expiresAt", "generationRef", "products", "people",
            "workloadConnectionRef", "workloads",
        }
        document = _object(document, fields=fields, name="picker descriptor")
        if (
            document["apiVersion"] != DESCRIPTOR_VERSION
            or document["kind"] != "PlatformDevPersonPicker"
        ):
            raise PickerUnavailable("descriptor has an unsupported format")
        run_id = _text(document["runId"], name="runId", maximum=32)
        if not _RUN_ID.fullmatch(run_id) or path.parents[2].name != run_id:
            raise PickerUnavailable("descriptor run does not match its private run directory")
        persona = document["persona"]
        if persona not in ("holder", "staff") or path.parent.name != persona:
            raise PickerUnavailable("descriptor persona does not match its private directory")
        document["origin"] = _loopback_origin(document["origin"], name="origin")
        namespace = _text(document["sessionNamespace"], name="sessionNamespace", maximum=64)
        if not _OPAQUE.fullmatch(namespace):
            raise PickerUnavailable("sessionNamespace must be opaque runner state")
        issued_at = _epoch(document["issuedAt"], name="issuedAt")
        expires_at = _epoch(document["expiresAt"], name="expiresAt")
        if issued_at >= expires_at or expires_at <= int(time.time()):
            raise PickerUnavailable("development run has expired")
        if not isinstance(document["products"], dict) or not document["products"]:
            raise PickerUnavailable("descriptor needs exact product endpoints")
        products = {}
        for product, raw in document["products"].items():
            if not isinstance(product, str) or not _LOCAL_NAME.fullmatch(product):
                raise PickerUnavailable("descriptor product name is malformed")
            raw = _object(raw, fields={"url", "resource"}, name=f"products.{product}")
            products[product] = MappingProxyType({
                "url": _loopback_origin(raw["url"], name=f"products.{product}.url"),
                "resource": _resource(raw["resource"], name=f"products.{product}.resource"),
            })
        document["products"] = MappingProxyType(products)
        raw_people = document["people"]
        if not isinstance(raw_people, list) or not 1 <= len(raw_people) <= 32:
            raise PickerUnavailable("descriptor needs 1 to 32 eligible test people")
        people: dict[str, _Person] = {}
        credential_products: set[str] | None = None
        for index, raw in enumerate(raw_people):
            raw = _object(
                raw,
                fields={"selector", "label", "subject", "principal", "clientId", "credentials"},
                name=f"people[{index}]",
            )
            selector = _text(raw["selector"], name="selector", maximum=128)
            if not _OPAQUE.fullmatch(selector) or selector in people:
                raise PickerUnavailable("test-person selectors must be distinct and opaque")
            label = _text(raw["label"], name="label", maximum=128)
            subject = _text(raw["subject"], name="subject")
            principal = _text(raw["principal"], name="principal")
            client_id = _text(raw["clientId"], name="clientId")
            if selector in (label, subject, principal, client_id):
                raise PickerUnavailable("test-person selector exposes an identity field")
            if not isinstance(raw["credentials"], dict) or not raw["credentials"]:
                raise PickerUnavailable("each test person needs a complete product grant set")
            current_products = set(raw["credentials"])
            if credential_products is None:
                credential_products = current_products
            elif current_products != credential_products:
                raise PickerUnavailable("all eligible people need the same complete product set")
            credentials = {}
            for product, grant in raw["credentials"].items():
                if product not in products:
                    raise PickerUnavailable("person credential names an undeclared product")
                grant = _object(
                    grant,
                    fields={
                        "tokenRef", "profile", "resource", "audiences", "scopes",
                        "principalClaim",
                    },
                    name=f"people[{index}].credentials.{product}",
                )
                token_ref = _text(grant["tokenRef"], name="tokenRef", maximum=128)
                _relative_file(path.parent, token_ref, name="tokenRef")
                profile = _text(grant["profile"], name="profile", maximum=64)
                if not _LOCAL_NAME.fullmatch(profile):
                    raise PickerUnavailable("person credential profile is malformed")
                resource = _resource(grant["resource"], name="resource")
                if resource != products[product]["resource"]:
                    raise PickerUnavailable("person credential resource differs from its run product")
                audiences = grant["audiences"]
                if (
                    not isinstance(audiences, list)
                    or not audiences
                    or len(audiences) > 4
                    or any(not isinstance(value, str) for value in audiences)
                    or len(set(audiences)) != len(audiences)
                    or resource not in audiences
                ):
                    raise PickerUnavailable("person credential audiences are malformed")
                audiences = tuple(_resource(value, name="audience") for value in audiences)
                credentials[product] = _Credential(
                    token_ref,
                    profile,
                    resource,
                    audiences,
                    _scopes(grant["scopes"], name="scopes"),
                    _text(grant["principalClaim"], name="principalClaim", maximum=128),
                )
            people[selector] = _Person(
                selector, label, subject, principal, client_id, MappingProxyType(credentials)
            )
        document["people"] = MappingProxyType(people)
        connection_reference = document["workloadConnectionRef"]
        connection_path = None
        if connection_reference is not None:
            connection_path = _relative_file(
                path.parent,
                connection_reference,
                name="workloadConnectionRef",
                allow_parent=True,
            )
            run_root = path.parents[2]
            try:
                connection_path.relative_to(run_root)
            except ValueError as exc:
                raise PickerUnavailable(
                    "workload connection is outside the development run"
                ) from exc
        document["workloadConnectionPath"] = connection_path
        del document["workloadConnectionRef"]
        raw_workloads = document["workloads"]
        if not isinstance(raw_workloads, list) or len(raw_workloads) > 32:
            raise PickerUnavailable("descriptor workloads are malformed")
        workloads = {}
        workload_fields = {
            "name", "product", "default", "url", "issuer", "subject", "clientId",
            "profile", "resource", "scopes", "claims",
        }
        for index, raw in enumerate(raw_workloads):
            raw = _object(raw, fields=workload_fields, name=f"workloads[{index}]")
            name = _text(raw["name"], name="workload name", maximum=64)
            product = _text(raw["product"], name="workload product", maximum=64)
            if (
                not _LOCAL_NAME.fullmatch(name)
                or name in workloads
                or product not in products
                or not isinstance(raw["default"], bool)
            ):
                raise PickerUnavailable("descriptor workloads are malformed")
            workload = dict(raw)
            workload["url"] = _loopback_origin(raw["url"], name="workload url")
            workload["issuer"] = _resource(raw["issuer"], name="workload issuer")
            workload["resource"] = _resource(raw["resource"], name="workload resource")
            workload["scopes"] = _scopes(raw["scopes"], name="workload scopes")
            try:
                workload["claims"] = _claims(raw["claims"], "workload claims")
            except ConnectionError as exc:
                raise PickerUnavailable("descriptor workload claims are malformed") from exc
            for field in ("subject", "clientId", "profile"):
                workload[field] = _text(raw[field], name=f"workload {field}")
            if (
                workload["url"] != products[product]["url"]
                or workload["resource"] != products[product]["resource"]
            ):
                raise PickerUnavailable("workload target differs from its run product")
            workloads[name] = MappingProxyType(workload)
        if bool(workloads) != (connection_path is not None):
            raise PickerUnavailable(
                "workload connection reference must match the declared run workloads"
            )
        document["workloads"] = MappingProxyType(workloads)
        return MappingProxyType(document)

    @property
    def origin(self) -> str:
        return self._origin

    @property
    def persona(self) -> str:
        return self._persona

    @property
    def session_cookie(self) -> str:
        return f"registry-dev-{self._namespace}-session"

    @property
    def pending_cookie(self) -> str:
        return f"registry-dev-{self._namespace}-pending"

    def choices(self) -> tuple[PickerChoice, ...]:
        self._check_live()
        return tuple(
            PickerChoice(person.label, person.selector)
            for person in self._people.values()
        )

    def begin(self) -> PickerForm:
        self._check_live()
        now = time.time()
        pending_id = secrets.token_urlsafe(24)
        csrf_token = secrets.token_urlsafe(32)
        with self._lock:
            self._pending = {
                key: pending
                for key, pending in self._pending.items()
                if pending[1] > now
            }
            self._pending[pending_id] = (csrf_token, min(now + 300, self._expires_at))
        return PickerForm(pending_id, csrf_token, self.choices())

    def select(
        self,
        pending_id: str,
        *,
        selector: str,
        origin: str,
        host: str,
        csrf_token: str,
    ) -> PickerSession:
        self._check_live()
        now = time.time()
        with self._lock:
            pending = self._pending.get(pending_id)
        if (
            pending is None
            or pending[1] <= now
            or origin != self._origin
            or host.lower() != _host(self._origin).lower()
            or not hmac.compare_digest(pending[0], csrf_token)
        ):
            raise PickerAdmissionError()
        person = self._people.get(selector)
        if person is None:
            raise PickerAdmissionError()
        try:
            self._person_tokens(person, admission=True)
        except PickerUnavailable:
            raise PickerAdmissionError() from None
        session_id = secrets.token_urlsafe(32)
        stored = _StoredSession(
            session_id,
            selector,
            person.subject,
            person.principal,
            person.client_id,
            secrets.token_urlsafe(32),
            float(self._expires_at),
        )
        with self._lock:
            current = self._pending.get(pending_id)
            if current != pending or session_id in self._sessions:
                raise PickerAdmissionError()
            self._sessions[session_id] = stored
            del self._pending[pending_id]
        return PickerSession(session_id, stored.csrf_token, stored.expires_at)

    def context(self, session_id: str) -> DevelopmentPerson:
        try:
            self._check_live()
            marker = self._read_generation()
        except PickerUnavailable:
            self._drop_session(session_id)
            raise ReauthenticationRequired() from None
        if marker["status"] != "ready":
            self._drop_session(session_id)
            raise ReauthenticationRequired()
        with self._lock:
            stored = self._sessions.get(session_id)
        now = time.time()
        if stored is None or stored.expires_at <= now:
            self._drop_session(session_id)
            raise ReauthenticationRequired()
        person = self._people.get(stored.selector)
        if (
            person is None
            or person.subject != stored.subject
            or person.principal != stored.principal
            or person.client_id != stored.client_id
        ):
            self._drop_session(session_id)
            raise ReauthenticationRequired()
        try:
            tokens = self._person_tokens(person, admission=False)
        except ReauthenticationRequired:
            self._drop_session(session_id)
            raise
        context = PortalContext(
            stored.session_id,
            stored.subject,
            stored.principal,
            self._persona,
            tokens,
            stored.csrf_token,
            stored.expires_at,
        )
        return DevelopmentPerson(context, person, self._products)

    def authorize_mutation(
        self, session_id: str, *, origin: str, csrf_token: str
    ) -> DevelopmentPerson:
        person = self.context(session_id)
        if origin != self._origin or not hmac.compare_digest(
            person.csrf_token, csrf_token
        ):
            raise CSRFError()
        return person

    def logout(self, session_id: str) -> None:
        self._drop_session(session_id)

    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    @property
    def workloads(self):
        """Load only the runner-token connection fixed by this descriptor."""
        self._check_live()
        if self._workload_connection_path is None:
            raise PickerUnavailable("this picker declares no service workload authority")
        self._validate_workload_connection()
        from .connection import connect

        return connect(path=self._workload_connection_path)

    def _drop_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def _check_live(self) -> None:
        if (self._root / "stop").exists():
            raise PickerUnavailable("development run is stopping")
        try:
            current = self._path.read_bytes()
        except OSError as exc:
            raise PickerUnavailable("descriptor is unavailable") from exc
        _private_file(self._path)
        if not hmac.compare_digest(hashlib.sha256(current).digest(), self._digest):
            raise PickerUnavailable("descriptor changed during the development run")
        lock_path = self._root / "worker.lock"
        _private_file(lock_path)
        try:
            with lock_path.open("rb") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    fcntl.flock(lock, fcntl.LOCK_UN)
                    raise PickerUnavailable("descriptor is not owned by a live development run")
        except OSError as exc:
            raise PickerUnavailable("live development run cannot be verified") from exc
        report = _json(self._root / "report.json")
        if (
            not isinstance(report, dict)
            or report.get("schema_version") != "registry.rstack.dev.v1"
            or report.get("run_id") != self._run_id
            or report.get("status") != "ready"
            or report.get("expires_at") != self._expires_at
            or int(time.time()) >= self._expires_at
        ):
            raise PickerUnavailable("descriptor is not owned by a ready live development run")

    def _read_generation(self) -> Mapping[str, Any]:
        state = _object(
            _json(self._generation_path),
            fields={
                "apiVersion", "kind", "status", "runId", "picker", "generation",
                "runExpiresAt",
            },
            name="person generation",
        )
        if (
            state["apiVersion"] != GENERATION_VERSION
            or state["kind"] != "PlatformDevPersonGeneration"
            or state["status"] not in ("ready", "stopped")
            or state["runId"] != self._run_id
            or state["picker"] != self._persona
            or not isinstance(state["generation"], int)
            or isinstance(state["generation"], bool)
            or state["generation"] < 1
            or state["runExpiresAt"] != self._expires_at
        ):
            raise PickerUnavailable("person credential generation is malformed")
        return state

    def _person_tokens(self, person: _Person, *, admission: bool) -> Mapping[str, str]:
        first = self._read_generation()
        if first["status"] != "ready":
            raise ReauthenticationRequired()
        tokens = {}
        for product, credential in person.credentials.items():
            path = _relative_file(
                self._picker_root, credential.token_ref, name="person token reference"
            )
            state = _json(path)
            if not isinstance(state, dict) or state.get("generation") != first["generation"]:
                raise PickerUnavailable("person credentials rotated during admission")
            try:
                tokens[product] = self._person_token(
                    state, person=person, product=product, credential=credential,
                    generation=first["generation"],
                )
            except PickerUnavailable:
                if admission:
                    raise
                raise ReauthenticationRequired() from None
        second = self._read_generation()
        if second != first:
            raise PickerUnavailable("person credentials rotated during admission")
        return MappingProxyType(tokens)

    def _person_token(
        self,
        state: Any,
        *,
        person: _Person,
        product: str,
        credential: _Credential,
        generation: int,
    ) -> str:
        fields = {
            "apiVersion", "kind", "runId", "picker", "persona", "selector", "product",
            "issuer", "subject", "principal", "clientId", "profile", "resource",
            "audiences", "scopes", "principalClaim", "generation", "issuedAt",
            "expiresAt", "runExpiresAt", "token",
        }
        state = _object(state, fields=fields, name="person token")
        expected = {
            "apiVersion": TOKEN_VERSION,
            "kind": "PlatformDevPersonToken",
            "runId": self._run_id,
            "picker": self._persona,
            "persona": self._persona,
            "selector": person.selector,
            "product": product,
            "subject": person.subject,
            "principal": person.principal,
            "clientId": person.client_id,
            "profile": credential.profile,
            "resource": credential.resource,
            "audiences": list(credential.audiences),
            "scopes": list(credential.scopes),
            "principalClaim": credential.principal_claim,
            "generation": generation,
            "runExpiresAt": self._expires_at,
        }
        if any(state.get(name) != value for name, value in expected.items()):
            raise PickerUnavailable("person token differs from the declared run authority")
        issuer = _resource(state["issuer"], name="person token issuer")
        issued = _epoch(state["issuedAt"], name="person token issuedAt")
        expires = _epoch(state["expiresAt"], name="person token expiresAt")
        now = int(time.time())
        if (
            issued > now + 60
            or issued > expires
            or expires - issued > 300
            or expires > self._expires_at
            or now >= expires
        ):
            raise PickerUnavailable("person token is expired or has an invalid lifetime")
        token = state["token"]
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 8192
            or any(character.isspace() for character in token)
            or token.count(".") != 2
        ):
            raise PickerUnavailable("person token is malformed")
        claims = _b64_json(token.split(".")[1])
        audience = claims.get("aud")
        token_audiences = [audience] if isinstance(audience, str) else audience
        if (
            claims.get("iss") != issuer
            or token_audiences != list(credential.audiences)
            or claims.get("sub") != person.subject
            or claims.get("client_id") != person.client_id
            or claims.get("scope") != " ".join(sorted(credential.scopes))
            or claims.get(credential.principal_claim) != person.principal
            or claims.get("registry_dev_persona") != self._persona
            or claims.get("iat") != issued
            or claims.get("exp") != expires
        ):
            raise PickerUnavailable("person token claims differ from the declared run authority")
        return token

    def _validate_workload_connection(self) -> None:
        if self._workload_connection_path is None:
            if self._workloads:
                raise PickerUnavailable("workload connection is incomplete for this picker run")
            return
        document = _json(self._workload_connection_path)
        if not isinstance(document, dict):
            raise PickerUnavailable("workload connection is malformed")
        required = {
            "apiVersion", "kind", "service", "audience", "secretProviders", "bindings"
        }
        if (
            set(document) != required
            or document.get("apiVersion") != CONNECTION_VERSION
            or document.get("kind") != "PlatformPythonConnection"
            or document.get("service") != f"rstack-dev-{self._run_id}"
            or document.get("audience") != "service"
            or document.get("secretProviders")
            != {"file": {"root": str(self._workload_connection_path.parent)}}
            or not isinstance(document.get("bindings"), list)
        ):
            raise PickerUnavailable("workload connection is not confined to this development run")
        observed = {}
        for raw in document["bindings"]:
            if not isinstance(raw, dict) or set(raw) != {
                "name", "product", "url", "default", "credential"
            }:
                raise PickerUnavailable("workload binding is malformed")
            name = raw.get("name")
            expected = self._workloads.get(name)
            credential = raw.get("credential")
            if (
                expected is None
                or not isinstance(credential, dict)
                or credential.get("type") != "runner-token"
                or set(credential) != {
                    "type", "tokenRef", "runId", "binding", "issuer", "subject",
                    "clientId", "profile", "resource", "scopes", "claims",
                    "runExpiresAt",
                }
                or raw.get("product") != expected["product"]
                or raw.get("default") != expected["default"]
                or raw.get("url") != expected["url"]
                or credential.get("runId") != self._run_id
                or credential.get("binding") != name
                or credential.get("issuer") != expected["issuer"]
                or credential.get("subject") != expected["subject"]
                or credential.get("clientId") != expected["clientId"]
                or credential.get("profile") != expected["profile"]
                or credential.get("resource") != expected["resource"]
                or credential.get("scopes") != list(expected["scopes"])
                or credential.get("claims") != expected["claims"]
                or credential.get("runExpiresAt") != self._expires_at
                or not isinstance(credential.get("tokenRef"), str)
                or not credential["tokenRef"].startswith("secret:file/")
            ):
                raise PickerUnavailable("workload binding differs from the picker run")
            token_name = credential["tokenRef"][12:]
            if not token_name or "/" in token_name or token_name in (".", ".."):
                raise PickerUnavailable("workload token reference is not runner-local")
            observed[name] = True
        if set(observed) != set(self._workloads):
            raise PickerUnavailable("workload connection is incomplete for this picker run")


def _parse_form(content_type: str, body: bytes) -> Mapping[str, str]:
    if (
        content_type.split(";", 1)[0].strip().lower()
        != "application/x-www-form-urlencoded"
        or not 1 <= len(body) <= _MAXIMUM_FORM_BYTES
    ):
        raise PickerAdmissionError()
    try:
        fields = parse_qs(
            body.decode("ascii"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=16,
            encoding="utf-8",
            errors="strict",
        )
    except (UnicodeError, ValueError):
        raise PickerAdmissionError() from None
    required = {"pending_id", "selector", "csrf_token"}
    if set(fields) != required or any(len(fields[name]) != 1 for name in required):
        raise PickerAdmissionError()
    return MappingProxyType({name: fields[name][0] for name in required})


def _picker_html(form: PickerForm) -> str:
    options = "".join(
        f'<option value="{html.escape(choice.selector, quote=True)}">'
        f"{html.escape(choice.label)}</option>"
        for choice in form.choices
    )
    return (
        "<!doctype html><meta charset=\"utf-8\"><title>Choose test person</title>"
        '<form method="post" action="/auth/dev">'
        f'<input type="hidden" name="pending_id" value="{html.escape(form.pending_id, quote=True)}">'
        f'<input type="hidden" name="csrf_token" value="{html.escape(form.csrf_token, quote=True)}">'
        f'<select name="selector">{options}</select><button type="submit">Continue</button></form>'
    )


def _clear_cookie(response: Any, name: str) -> None:
    response.set_cookie(
        name, "", max_age=0, expires=0, secure=False, httponly=True,
        samesite="strict", path="/",
    )


def install_flask(
    app: Any,
    picker: DevelopmentPicker,
    *,
    person_factory: Callable[[DevelopmentPerson], Any],
    request_seconds: float,
) -> None:
    """Protect a loopback Flask starter with the run-bound picker."""
    from flask import Response, g, jsonify, redirect, request
    from .web import form_csrf_token, is_public
    from .workload import request_budget

    if not math.isfinite(request_seconds) or request_seconds <= 0:
        raise ValueError("request_seconds must be finite and positive")
    picker.choices()
    auth_paths = frozenset(("/auth/dev", "/auth/dev/logout"))

    def error(code: str, status: int):
        response = jsonify({"code": code})
        response.status_code = status
        response.headers["Cache-Control"] = "no-store"
        return response

    def exact_origin() -> bool:
        return request.host_url.rstrip("/") == picker.origin

    def authorized_mutation():
        session_id = request.cookies.get(picker.session_cookie)
        if not session_id:
            raise ReauthenticationRequired()
        csrf = request.headers.get("X-CSRF-Token", "")
        if not csrf and request.mimetype == "application/x-www-form-urlencoded":
            length = request.content_length
            if length is not None and 1 <= length <= _MAXIMUM_FORM_BYTES:
                csrf = form_csrf_token(
                    content_type=request.content_type or "",
                    content_length=length,
                    body=request.get_data(cache=True),
                )
        return picker.authorize_mutation(
            session_id, origin=request.headers.get("Origin", ""), csrf_token=csrf
        )

    @app.before_request
    def admit_request():
        budget = request_budget(request_seconds)
        budget.__enter__()
        g._registry_dev_budget = budget
        try:
            picker._check_live()
        except PickerUnavailable:
            return error(PickerUnavailable.code, 503)
        if not exact_origin():
            return error("development-picker.origin-refused", 400)
        if request.path in auth_paths or is_public(app.view_functions.get(request.endpoint)):
            return None
        session_id = request.cookies.get(picker.session_cookie)
        if not session_id:
            return error(ReauthenticationRequired.code, 401)
        try:
            context = (
                picker.context(session_id)
                if request.method in ("GET", "HEAD", "OPTIONS")
                else authorized_mutation()
            )
            g.registry_person = person_factory(context)
        except ReauthenticationRequired:
            return error(ReauthenticationRequired.code, 401)
        except CSRFError:
            return error(CSRFError.code, 403)
        return None

    @app.teardown_request
    def finish_request(_error):
        budget = getattr(g, "_registry_dev_budget", None)
        if budget is not None:
            budget.__exit__(None, None, None)

    @app.get("/auth/dev")
    def registry_dev_login():
        form = picker.begin()
        response = Response(_picker_html(form), content_type="text/html; charset=utf-8")
        response.set_cookie(
            picker.pending_cookie, form.pending_id, secure=False, httponly=True,
            samesite="Strict", path="/auth/dev",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/auth/dev")
    def registry_dev_select():
        try:
            values = _parse_form(request.content_type or "", request.get_data(cache=True))
            if request.cookies.get(picker.pending_cookie) != values["pending_id"]:
                raise PickerAdmissionError()
            session = picker.select(
                values["pending_id"],
                selector=values["selector"],
                origin=request.headers.get("Origin", ""),
                host=request.host,
                csrf_token=values["csrf_token"],
            )
        except PickerAdmissionError:
            return error(PickerAdmissionError.code, 403)
        response = redirect("/")
        response.set_cookie(
            picker.session_cookie, session.session_id, secure=False, httponly=True,
            samesite="Strict", path="/",
        )
        _clear_cookie(response, picker.pending_cookie)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/auth/dev/logout")
    def registry_dev_logout():
        try:
            authorized_mutation()
        except ReauthenticationRequired:
            return error(ReauthenticationRequired.code, 401)
        except (CSRFError, PickerAdmissionError):
            return error(CSRFError.code, 403)
        picker.logout(request.cookies[picker.session_cookie])
        response = redirect("/auth/dev")
        _clear_cookie(response, picker.session_cookie)
        response.headers["Cache-Control"] = "no-store"
        return response


def install_fastapi(
    app: Any,
    picker: DevelopmentPicker,
    *,
    person_factory: Callable[[DevelopmentPerson], Any],
    request_seconds: float,
) -> None:
    """Protect a loopback FastAPI starter with the same picker contract."""
    import asyncio
    from fastapi import Request
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
    from starlette.routing import Match
    from .web import form_csrf_token, is_public
    from .workload import request_budget

    # FastAPI resolves deferred annotations from module globals. Preserve the
    # core module's lazy optional dependency while exposing the real Request
    # type once this integration is explicitly installed.
    globals()["Request"] = Request

    if not math.isfinite(request_seconds) or request_seconds <= 0:
        raise ValueError("request_seconds must be finite and positive")
    picker.choices()
    auth_paths = frozenset(("/auth/dev", "/auth/dev/logout"))

    def error(code: str, status: int):
        return JSONResponse(
            {"code": code}, status_code=status, headers={"Cache-Control": "no-store"}
        )

    def route_is_public(scope: MutableMapping[str, Any]) -> bool:
        for route in app.router.routes:
            match, _ = route.matches(scope)
            if match == Match.FULL:
                return is_public(getattr(route, "endpoint", None))
        return False

    def request_origin(request: Request) -> str:
        return f"{request.url.scheme}://{request.headers.get('host', '')}"

    async def authorized_mutation(request: Request):
        session_id = request.cookies.get(picker.session_cookie)
        if not session_id:
            raise ReauthenticationRequired()
        csrf = request.headers.get("x-csrf-token", "")
        if not csrf:
            length = request.headers.get("content-length", "")
            if length.isascii() and length.isdecimal() and 1 <= int(length) <= _MAXIMUM_FORM_BYTES:
                csrf = form_csrf_token(
                    content_type=request.headers.get("content-type", ""),
                    content_length=int(length),
                    body=await request.body(),
                )
        return await asyncio.to_thread(
            picker.authorize_mutation,
            session_id,
            origin=request.headers.get("origin", ""),
            csrf_token=csrf,
        )

    @app.middleware("http")
    async def admit_request(request: Request, call_next: Callable):
        with request_budget(request_seconds):
            try:
                await asyncio.to_thread(picker._check_live)
            except PickerUnavailable:
                return error(PickerUnavailable.code, 503)
            if request_origin(request) != picker.origin:
                return error("development-picker.origin-refused", 400)
            if request.url.path in auth_paths or route_is_public(request.scope):
                return await call_next(request)
            session_id = request.cookies.get(picker.session_cookie)
            if not session_id:
                return error(ReauthenticationRequired.code, 401)
            try:
                context = (
                    await asyncio.to_thread(picker.context, session_id)
                    if request.method in ("GET", "HEAD", "OPTIONS")
                    else await authorized_mutation(request)
                )
                request.state.registry_person = await asyncio.to_thread(
                    person_factory, context
                )
            except ReauthenticationRequired:
                return error(ReauthenticationRequired.code, 401)
            except (CSRFError, PickerAdmissionError):
                return error(CSRFError.code, 403)
            return await call_next(request)

    @app.get("/auth/dev")
    async def registry_dev_login():
        form = await asyncio.to_thread(picker.begin)
        response = HTMLResponse(
            _picker_html(form), headers={"Cache-Control": "no-store"}
        )
        response.set_cookie(
            picker.pending_cookie, form.pending_id, secure=False, httponly=True,
            samesite="strict", path="/auth/dev",
        )
        return response

    @app.post("/auth/dev")
    async def registry_dev_select(request: Request):
        try:
            values = _parse_form(
                request.headers.get("content-type", ""), await request.body()
            )
            if request.cookies.get(picker.pending_cookie) != values["pending_id"]:
                raise PickerAdmissionError()
            session = await asyncio.to_thread(
                picker.select,
                values["pending_id"],
                selector=values["selector"],
                origin=request.headers.get("origin", ""),
                host=request.headers.get("host", ""),
                csrf_token=values["csrf_token"],
            )
        except PickerAdmissionError:
            return error(PickerAdmissionError.code, 403)
        response = RedirectResponse("/", status_code=302)
        response.set_cookie(
            picker.session_cookie, session.session_id, secure=False, httponly=True,
            samesite="strict", path="/",
        )
        _clear_cookie(response, picker.pending_cookie)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/auth/dev/logout")
    async def registry_dev_logout(request: Request):
        try:
            await authorized_mutation(request)
        except ReauthenticationRequired:
            return error(ReauthenticationRequired.code, 401)
        except (CSRFError, PickerAdmissionError):
            return error(CSRFError.code, 403)
        picker.logout(request.cookies[picker.session_cookie])
        response = RedirectResponse("/auth/dev", status_code=302)
        _clear_cookie(response, picker.session_cookie)
        response.headers["Cache-Control"] = "no-store"
        return response
