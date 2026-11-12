"""Flask machine endpoint for the keyed Messaging effect example."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

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
    store = MessageEffectStore(database_path)
    store.migrate()
    effect = MessageEffect(
        store,
        MessagingTargets(stack, targets),
        service_namespace=service_namespace,
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


def create_app_from_environment():
    """Load non-secret example settings; `connect()` owns credential references."""
    database_path = os.environ.get("MESSAGE_EFFECT_DATABASE")
    service_namespace = os.environ.get("MESSAGE_EFFECT_SERVICE_NAMESPACE")
    raw_targets = os.environ.get("MESSAGE_EFFECT_TARGETS")
    if not database_path or not service_namespace or not raw_targets:
        raise RuntimeError(
            "MESSAGE_EFFECT_DATABASE, MESSAGE_EFFECT_SERVICE_NAMESPACE and "
            "MESSAGE_EFFECT_TARGETS are required"
        )
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
    return create_app(
        database_path=database_path,
        service_namespace=service_namespace,
        targets=targets,
    )


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


if __name__ == "__main__":
    create_app_from_environment().run(host="127.0.0.1", port=9011, debug=False)
