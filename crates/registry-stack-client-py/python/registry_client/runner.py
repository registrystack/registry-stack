"""Read a live runner's atomically rotated, run-bound workload credential."""

from __future__ import annotations

import os
from pathlib import Path
import threading
import time
from typing import Any, Mapping

from .connection import ConnectionError, _claims, _secret


TOKEN_VERSION = "id.registrystack.org/formats/platform/dev-workload-token/v1alpha1"
_STATE_FIELDS = frozenset((
    "apiVersion", "kind", "runId", "binding", "product", "issuer", "subject", "clientId",
    "profile", "resource", "scopes", "claims", "generation", "issuedAt", "expiresAt",
    "runExpiresAt", "token",
))
_STOPPED_FIELDS = (_STATE_FIELDS - {"token"}) | {"status"}


def check_runner_document(state: Any, *, allow_stopped: bool = False) -> None:
    """Check a runner envelope without granting it to a caller."""
    if (not isinstance(state, dict)
            or state.get("apiVersion") != TOKEN_VERSION
            or state.get("kind") != "PlatformDevWorkloadToken"):
        raise ConnectionError("runner token state has an unsupported format")
    stopped = state.get("status") == "stopped"
    expected_fields = _STOPPED_FIELDS if stopped else _STATE_FIELDS
    if set(state) != expected_fields or (stopped and not allow_stopped):
        raise ConnectionError("runner token state is unavailable or malformed")
    for field in ("runId", "binding", "product", "issuer", "subject", "clientId", "profile", "resource"):
        if not isinstance(state[field], str) or not state[field]:
            raise ConnectionError("runner token state has malformed authority")
    scopes = state["scopes"]
    if (not isinstance(scopes, list) or not scopes
            or any(not isinstance(scope, str) or not scope or any(char.isspace() for char in scope)
                   for scope in scopes)
            or len(set(scopes)) != len(scopes)):
        raise ConnectionError("runner token state has malformed authority")
    _claims(state["claims"], "runner token state.claims")
    generation, issued, expires, run_expires = (
        state[field] for field in ("generation", "issuedAt", "expiresAt", "runExpiresAt")
    )
    if (any(not isinstance(value, int) or isinstance(value, bool)
            for value in (generation, issued, expires, run_expires))
            or generation < 1 or run_expires <= 0 or issued > run_expires
            or (stopped and issued != expires)
            or (not stopped and (issued > expires or expires - issued > 300
                                 or expires > run_expires or issued > int(time.time()) + 60))):
        raise ConnectionError("runner token state has invalid generation or lifetime")
    if stopped:
        return
    if int(time.time()) >= expires or int(time.time()) >= run_expires:
        raise ConnectionError("runner token or development run expired; restart rstack dev")
    token = state["token"]
    if (not isinstance(token, str) or not token or len(token) > 8192
            or any(character.isspace() for character in token)):
        raise ConnectionError("runner token state is malformed")


class RunnerTokenSource:
    """One binding's finite run identity, checked at every protected call."""

    def __init__(self, binding: Any, providers: Mapping[str, Any]):
        self._binding = binding
        self._providers = providers
        self._lock = threading.Lock()
        self._generation = 0
        self._token: str | None = None

    def current(self) -> tuple[int, str]:
        with self._lock:
            try:
                contents = _secret(self._binding.credential["tokenRef"], self._providers).encode("utf-8")
            except UnicodeError as exc:
                raise ConnectionError("runner token state is unavailable or malformed") from exc
            from .yaml import ConfigReadError, read_document  # pyright: ignore[reportMissingImports]

            token_name = self._binding.credential["tokenRef"].split("/", 1)[1]
            token_path = Path(self._providers["file"]["root"]) / token_name
            try:
                state = read_document(
                    contents, file=os.fspath(token_path), api_version=TOKEN_VERSION,
                    kind="PlatformDevWorkloadToken",
                )
            except ConfigReadError as exc:
                raise ConnectionError(
                    "runner token document was refused", diagnostics=exc.diagnostics
                ) from None
            check_runner_document(state)
            credential = self._binding.credential
            expected = {
                "apiVersion": TOKEN_VERSION,
                "kind": "PlatformDevWorkloadToken",
                "runId": credential["runId"],
                "binding": self._binding.name,
                "product": self._binding.product,
                "issuer": credential["issuer"],
                "subject": credential["subject"],
                "clientId": credential["clientId"],
                "profile": credential["profile"],
                "resource": credential["resource"],
                "scopes": credential["scopes"],
                "claims": credential["claims"],
                "runExpiresAt": credential["runExpiresAt"],
            }
            if any(state.get(field) != value for field, value in expected.items()):
                raise ConnectionError("runner token state does not match the declared authority")
            generation = state["generation"]
            token = state["token"]
            if generation < self._generation:
                raise ConnectionError("runner token generation moved backwards")
            if generation == self._generation and token != self._token:
                raise ConnectionError("runner token changed without a new generation")
            self._generation = generation
            self._token = token
            return generation, token

    def bearer_token(self) -> str:
        return self.current()[1]


class RotatingNativeBReg:
    """Keep one public BReg handle while replacing a generation's static native client."""

    def __init__(self, url: str, source: RunnerTokenSource):
        self._url = url
        self._source = source
        self._lock = threading.Lock()
        self._generation = 0
        self._client: Any = None

    def __getattr__(self, operation: str):
        generation, token = self._source.current()
        with self._lock:
            if self._client is None or generation != self._generation:
                from . import breg
                client = breg.BaseRegistryClient(self._url, authorization={"static": token})
                self._client = client
                self._generation = generation
            return getattr(self._client, operation)
