"""Application factories and explicit encrypted-session store lifecycle commands."""

import argparse
import json
import os

from portal_example import (
    build_runtime,
    build_store,
    create_fastapi_app,
    create_flask_app,
    load_config,
)


def _environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"set {name} before constructing a portal worker")
    return value


def _configured_runtime():
    config = load_config(_environment("PORTAL_CONFIG"))
    runtime = build_runtime(config, _environment("PORTAL_PERSONA"))
    runtime.store.check_ready()
    return config, runtime


def create_flask():
    config, runtime = _configured_runtime()
    return create_flask_app(config, runtime)


def create_fastapi():
    config, runtime = _configured_runtime()
    return create_fastapi_app(config, runtime)


def main(arguments: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action", choices=("migrate", "check-store", "rotate-encryption")
    )
    parser.add_argument("--config", required=True)
    options = parser.parse_args(arguments)
    store = build_store(load_config(options.config))
    if options.action == "migrate":
        store.migrate()
        result = {"action": options.action, "status": "complete"}
    elif options.action == "check-store":
        store.check_ready()
        result = {"action": options.action, "status": "ready"}
    else:
        rewritten = store.rotate_encryption()
        result = {
            "action": options.action,
            "status": "complete",
            "rewritten": rewritten,
        }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
