"""Flask and FastAPI endpoints for the keyed Messaging effect example."""

import json
import os
from pathlib import Path
import sys
from typing import Any, Callable, Mapping

from effect import (
    CommandConflict,
    MessageEffect,
    MessageEffectStore,
    MessagingTargets,
    NoticeNotFound,
)

_MAXIMUM_COMMAND_BYTES = 4096


def create_app(
    *,
    database_path: str | Path,
    service_namespace: str,
    audit_key: bytes,
    audit_sink: Callable[[Mapping[str, str]], None],
    targets: Mapping[str, str | None],
    stack: Any | None = None,
    request_seconds: float = 2.0,
    maximum_inflight_submissions: int = 32,
):
    """Construct clients after worker start and protect every Flask route."""
    from flask import Flask, g, jsonify, request
    from registry_client import connect, flask_adapter

    if stack is None:
        stack = connect()
    if not callable(audit_sink):
        raise ValueError("audit_sink must be callable")
    store = MessageEffectStore(database_path)
    store.migrate()
    effect = MessageEffect(
        store,
        MessagingTargets(stack, targets),
        service_namespace=service_namespace,
        audit_key=audit_key,
        audit_sink=audit_sink,
        maximum_inflight_submissions=maximum_inflight_submissions,
    )
    app = Flask(__name__)
    app.extensions["registry_message_effect_store"] = store

    @app.post("/v1/message-effects")
    def message_effect():
        body = _read_command(request)
        if not _valid_command(body):
            return _response(
                jsonify,
                422,
                {"state": "refused", "code": "invalid-command"},
            )
        try:
            result = effect.execute(
                g.registry_context,
                body["key"],
                body["noticeId"],
            )
        except NoticeNotFound:
            return _response(
                jsonify,
                422,
                {"state": "refused", "code": "notice-not-found"},
            )
        except CommandConflict as error:
            return _response(
                jsonify,
                409,
                {"state": "uncertain", "recovery": error.recovery},
            )
        return _response(jsonify, result.status, result.body)

    flask_adapter.install(app, stack, request_seconds=request_seconds)
    return app


def create_fastapi_app(
    *,
    database_path: str | Path,
    service_namespace: str,
    audit_key: bytes,
    audit_sink: Callable[[Mapping[str, str]], None],
    targets: Mapping[str, str | None],
    stack: Any | None = None,
    request_seconds: float = 2.0,
    maximum_inflight_submissions: int = 32,
):
    """Construct clients after worker start and protect FastAPI routes by default."""
    from fastapi import Depends, FastAPI, Request
    from fastapi.responses import JSONResponse
    from registry_client import connect, fastapi_adapter, web

    if stack is None:
        stack = connect()
    if not callable(audit_sink):
        raise ValueError("audit_sink must be callable")
    store = MessageEffectStore(database_path)
    store.migrate()
    effect = MessageEffect(
        store,
        MessagingTargets(stack, targets),
        service_namespace=service_namespace,
        audit_key=audit_key,
        audit_sink=audit_sink,
        maximum_inflight_submissions=maximum_inflight_submissions,
    )
    app = FastAPI()
    app.state.registry_message_effect_store = store

    @app.get("/healthz")
    @web.public
    def healthz():
        return _fastapi_response(JSONResponse, 200, {"status": "ok"})

    async def command_body(request: Request):
        return await _read_fastapi_command(request)

    @app.post("/v1/message-effects")
    def message_effect(request: Request, body: Any = Depends(command_body)):
        if not _valid_command(body):
            return _fastapi_response(
                JSONResponse,
                422,
                {"state": "refused", "code": "invalid-command"},
            )
        try:
            result = effect.execute(
                request.state.registry_context,
                body["key"],
                body["noticeId"],
            )
        except NoticeNotFound:
            return _fastapi_response(
                JSONResponse,
                422,
                {"state": "refused", "code": "notice-not-found"},
            )
        except CommandConflict as error:
            return _fastapi_response(
                JSONResponse,
                409,
                {"state": "uncertain", "recovery": error.recovery},
            )
        return _fastapi_response(JSONResponse, result.status, result.body)

    fastapi_adapter.install(app, stack, request_seconds=request_seconds)
    return app


def create_app_from_environment():
    """Load non-secret example settings; `connect()` owns credential references."""
    return create_app(**_environment_arguments())


def create_fastapi_app_from_environment():
    """Load settings and construct one FastAPI worker after process startup."""
    return create_fastapi_app(**_environment_arguments())


def _environment_arguments() -> dict[str, Any]:
    database_path = os.environ.get("MESSAGE_EFFECT_DATABASE")
    service_namespace = os.environ.get("MESSAGE_EFFECT_SERVICE_NAMESPACE")
    raw_audit_key = os.environ.get("MESSAGE_EFFECT_AUDIT_KEY_HEX")
    raw_targets = os.environ.get("MESSAGE_EFFECT_TARGETS")
    if (
        not database_path
        or not service_namespace
        or not raw_audit_key
        or not raw_targets
    ):
        raise RuntimeError(
            "MESSAGE_EFFECT_DATABASE, MESSAGE_EFFECT_SERVICE_NAMESPACE, "
            "MESSAGE_EFFECT_AUDIT_KEY_HEX and MESSAGE_EFFECT_TARGETS are required"
        )
    if len(raw_audit_key) != 64 or any(
        character not in "0123456789abcdefABCDEF" for character in raw_audit_key
    ):
        raise RuntimeError(
            "MESSAGE_EFFECT_AUDIT_KEY_HEX must contain 64 hexadecimal characters"
        )
    audit_key = bytes.fromhex(raw_audit_key)
    try:
        targets = json.loads(raw_targets)
    except json.JSONDecodeError as error:
        raise RuntimeError("MESSAGE_EFFECT_TARGETS must be JSON") from error
    if not isinstance(targets, dict) or any(
        not isinstance(key, str) or (value is not None and not isinstance(value, str))
        for key, value in targets.items()
    ):
        raise RuntimeError(
            "MESSAGE_EFFECT_TARGETS must map authority IDs to binding names or null"
        )
    return {
        "database_path": database_path,
        "service_namespace": service_namespace,
        "audit_key": audit_key,
        "audit_sink": _stderr_audit,
        "targets": targets,
    }


def _stderr_audit(event: Mapping[str, str]) -> None:
    sys.stderr.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stderr.flush()


def _valid_command(body: Any) -> bool:
    return (
        isinstance(body, dict)
        and set(body) == {"key", "noticeId"}
        and _valid_text(body.get("key"), maximum_bytes=128)
        and _valid_text(body.get("noticeId"), maximum_bytes=128)
    )


def _valid_text(value: Any, *, maximum_bytes: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value.strip() == value
        and len(value.encode("utf-8")) <= maximum_bytes
        and all(ord(character) >= 33 and ord(character) != 127 for character in value)
    )


def _read_command(request) -> Any:
    length = request.content_length
    if (
        request.mimetype != "application/json"
        or not isinstance(length, int)
        or not 1 <= length <= _MAXIMUM_COMMAND_BYTES
    ):
        return None
    raw = request.get_data(cache=False)
    if len(raw) != length:
        return None
    return _decode_command(raw)


async def _read_fastapi_command(request) -> Any:
    lengths = request.headers.getlist("content-length")
    if len(lengths) != 1:
        return None
    try:
        length = int(lengths[0])
    except (TypeError, ValueError):
        return None
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
        or not 1 <= length <= _MAXIMUM_COMMAND_BYTES
    ):
        return None
    raw = bytearray()
    async for chunk in request.stream():
        if len(chunk) > length - len(raw) or len(chunk) > _MAXIMUM_COMMAND_BYTES - len(
            raw
        ):
            return None
        raw.extend(chunk)
    if len(raw) != length:
        return None
    return _decode_command(bytes(raw))


def _decode_command(raw: bytes) -> Any:
    def unique_members(pairs):
        value = {}
        for name, member in pairs:
            if name in value:
                raise ValueError("duplicate JSON member")
            value[name] = member
        return value

    try:
        return json.loads(raw, object_pairs_hook=unique_members)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return None


def _response(jsonify, status: int, body: Mapping[str, Any]):
    response = jsonify(body)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    if status == 429:
        response.headers["Retry-After"] = "1"
    return response


def _fastapi_response(response_type, status: int, body: Mapping[str, Any]):
    headers = {"Cache-Control": "no-store"}
    if status == 429:
        headers["Retry-After"] = "1"
    return response_type(body, status_code=status, headers=headers)


if __name__ == "__main__":
    create_app_from_environment().run(host="127.0.0.1", port=9011, debug=False)
