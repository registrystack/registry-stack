"""Run the local simulator and control synthetic outcomes without an admin API."""

import argparse
import json
import re
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn

from .api import Settings, create_app
from .store import Store, dumps


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="serve the G2P and P2G APIs")
    serve.add_argument("--database", type=Path, required=True)
    serve.add_argument("--token-file", type=Path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8008)
    serve.add_argument("--manual", action="store_true", help="advance only through the local CLI")
    serve.add_argument("--producer", default="registry")
    serve.add_argument("--source-id", default="registry")
    for option in (
        "tenant",
        "institution",
        "program",
        "payer-account",
        "biller",
        "callback-url",
        "currency",
    ):
        serve.add_argument(f"--{option}", action="append")
    serve.add_argument("--mode", action="append", choices=("00", "01", "03"))

    scenario = commands.add_parser("scenario", help="choose outcomes for future batches")
    scenario.add_argument("--database", type=Path, required=True)
    scenario.add_argument("--producer", default="registry")
    scenario.add_argument("--tenant", default="pilot")
    scenario.add_argument("--name", choices=("success", "partial"), required=True)
    scenario.add_argument("--reject-request")

    collection = commands.add_parser("collection-scenario", help="choose future P2G outcomes")
    collection.add_argument("--database", type=Path, required=True)
    collection.add_argument("--producer", default="registry")
    collection.add_argument("--tenant", default="pilot")
    collection.add_argument("--biller", default="ministry")
    collection.add_argument("--outcome", choices=("paid", "failed", "expired"), required=True)

    advance = commands.add_parser(
        "advance", help="advance persisted instructions one or more steps"
    )
    advance.add_argument("--database", type=Path, required=True)
    advance.add_argument("--steps", type=int, default=1)

    inspect = commands.add_parser("inspect", help="read the local simulated-credit ledger")
    inspect.add_argument("--database", type=Path, required=True)
    inspect.add_argument("--batch-id")

    collections = commands.add_parser("inspect-collections", help="read simulated P2G payments")
    collections.add_argument("--database", type=Path, required=True)
    collections.add_argument("--transfer-request-id")

    schema = commands.add_parser("openapi", help="generate the implemented HTTP contract")
    schema.add_argument("--output", type=Path, default=Path("contracts/openapi.json"))
    schema.add_argument("--check", action="store_true", help="fail when the output differs")
    return root


def serve_settings(args):
    defaults = Settings()
    currencies = {}
    for currency in args.currency or ["USD:2"]:
        if not re.fullmatch(r"[A-Z]{3}:[0-6]", currency):
            raise ValueError("--currency must be CODE:SCALE, for example USD:2 (scale 0–6)")
        code, scale = currency.split(":")
        if code in currencies:
            raise ValueError("each --currency code must occur once")
        currencies[code] = int(scale)
    settings = Settings(
        token_file=args.token_file,
        producer=args.producer,
        source_id=args.source_id,
        tenants=tuple(args.tenant or defaults.tenants),
        institutions=tuple(args.institution or defaults.institutions),
        programs=tuple(args.program or defaults.programs),
        payer_accounts=tuple(args.payer_account or defaults.payer_accounts),
        billers=tuple(args.biller or defaults.billers),
        callback_urls=tuple(args.callback_url or defaults.callback_urls),
        currencies=currencies,
        modes=tuple(args.mode or defaults.modes),
        manual=args.manual,
    )
    for values, maximum in (
        (settings.tenants, 20),
        (settings.institutions, 12),
        (settings.programs, 20),
        (settings.payer_accounts, 30),
        (settings.billers, 20),
        ((settings.source_id,), 12),
        ((settings.producer,), 50),
    ):
        if any(not 1 <= len(value) <= maximum for value in values):
            raise ValueError("configured scope identifier exceeds its profile length")
    for url in settings.callback_urls:
        parsed = urlsplit(url)
        if len(url) > 100 or parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                "--callback-url must be an absolute HTTP(S) URL of at most 100 characters"
            )
    settings.token()  # Fail at startup with a useful error; re-read for each request on rotation.
    if args.token_file.stat().st_mode & 0o077:
        raise ValueError("token file must be private; run chmod 600 on it")
    return settings


def main():
    root = parser()
    args = root.parse_args()
    try:
        if args.command == "serve":
            settings = serve_settings(args)
            store = Store(args.database)
            # Access logs include query identifiers, so keep them off even for synthetic fixtures.
            uvicorn.run(
                create_app(settings, store), host=args.host, port=args.port, access_log=False
            )
        elif args.command == "scenario":
            if args.name == "partial" and (
                args.reject_request is None or not 1 <= len(args.reject_request) <= 16
            ):
                raise ValueError("partial requires --reject-request with 1–16 characters")
            if args.name == "success" and args.reject_request is not None:
                raise ValueError("--reject-request applies only to partial")
            Store(args.database).scenario(
                args.producer, args.tenant, args.name, args.reject_request
            )
        elif args.command == "advance":
            if not 1 <= args.steps <= 100:
                raise ValueError("--steps must be between 1 and 100")
            Store(args.database, create=False).advance(args.steps)
        elif args.command == "collection-scenario":
            if not (
                1 <= len(args.producer) <= 50
                and 1 <= len(args.tenant) <= 20
                and 1 <= len(args.biller) <= 20
            ):
                raise ValueError("collection scenario scope exceeds its profile length")
            Store(args.database).collection_scenario(
                args.producer, args.tenant, args.biller, args.outcome
            )
        elif args.command == "inspect":
            print(dumps(Store(args.database, create=False).inspect(args.batch_id), indent=2))
        elif args.command == "inspect-collections":
            print(
                dumps(
                    Store(args.database, create=False).inspect_collections(
                        args.transfer_request_id
                    ),
                    indent=2,
                )
            )
        else:
            content = json.dumps(create_app().openapi(), indent=2, sort_keys=True) + "\n"
            if args.check:
                if not args.output.is_file() or args.output.read_text() != content:
                    root.exit(
                        1, "OpenAPI differs; run payment-simulator openapi to regenerate it\n"
                    )
            else:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(content)
    except (ValueError, OSError, sqlite3.Error) as exc:
        root.exit(2, f"payment-simulator: {exc}\n")
