from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from tests.fixtures import ContractTarget, TargetSettings
from tests.fixtures.target import LOCAL_CAPABILITIES, unused_loopback_port


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("payment contract target")
    group.addoption(
        "--target-url",
        help="run portable assertions against this existing HTTP target",
    )
    group.addoption(
        "--token-file",
        type=Path,
        help="file containing the external target's bearer token",
    )
    group.addoption(
        "--external-sandbox",
        action="store_true",
        help="confirm that a non-loopback target is an isolated synthetic sandbox",
    )
    group.addoption(
        "--target-capability",
        action="append",
        default=[],
        choices=sorted(LOCAL_CAPABILITIES),
        help="capability provided by an external target fixture (repeatable)",
    )
    group.addoption("--target-producer", default="registry")
    group.addoption("--target-tenant", default="pilot")
    group.addoption("--target-institution", default="ministry")
    group.addoption("--target-biller", default="ministry")
    group.addoption("--target-source-id", default="registry")
    group.addoption("--target-program", default="cash-support")
    group.addoption("--target-payer-account", default="programme-account")
    group.addoption(
        "--target-registration-callback-url",
        default="https://programme.example.test/callback",
    )
    group.addoption(
        "--target-batch-callback-url",
        default="https://programme.example.test/api/v1/batch",
    )
    group.addoption("--target-currency", default="USD")
    group.addoption("--target-currency-scale", type=int, default=2)
    group.addoption("--target-poll-interval", type=float, default=0.05)
    group.addoption("--target-poll-timeout", type=float, default=5.0)


def pytest_configure(config: pytest.Config) -> None:
    target_url = config.getoption("--target-url")
    if not target_url:
        return
    parsed = urlsplit(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise pytest.UsageError("--target-url must be an absolute HTTP(S) URL")
    if parsed.hostname not in {"127.0.0.1", "::1", "localhost"} and not config.getoption(
        "--external-sandbox"
    ):
        raise pytest.UsageError(
            "refusing a non-loopback payment target without --external-sandbox; "
            "contract tests must never target a real banking environment"
        )
    if config.getoption("--token-file") is None:
        raise pytest.UsageError("--token-file is required with --target-url")


@dataclass(frozen=True)
class ContractIds:
    suffix: str

    def value(self, prefix: str, *, limit: int) -> str:
        value = f"{prefix}{self.suffix}"
        if len(value) > limit:
            raise ValueError(f"generated ID {value!r} exceeds {limit} characters")
        return value


@pytest.fixture
def ids(request: pytest.FixtureRequest) -> ContractIds:
    del request
    return ContractIds(secrets.token_hex(3)[:5])


@pytest.fixture
def target(request: pytest.FixtureRequest, tmp_path: Path) -> ContractTarget:
    config = request.config
    settings = TargetSettings(
        producer=config.getoption("--target-producer"),
        tenant=config.getoption("--target-tenant"),
        institution=config.getoption("--target-institution"),
        biller=config.getoption("--target-biller"),
        source_id=config.getoption("--target-source-id"),
        programme=config.getoption("--target-program"),
        payer_account=config.getoption("--target-payer-account"),
        registration_callback_url=config.getoption("--target-registration-callback-url"),
        batch_callback_url=config.getoption("--target-batch-callback-url"),
        currency=config.getoption("--target-currency"),
        currency_scale=config.getoption("--target-currency-scale"),
        poll_interval=config.getoption("--target-poll-interval"),
        poll_timeout=config.getoption("--target-poll-timeout"),
    )
    package_root = Path(__file__).resolve().parents[1]
    configured_url = config.getoption("--target-url")
    if configured_url:
        token_file = config.getoption("--token-file").resolve()
        if not token_file.is_file():
            raise pytest.UsageError(f"token file does not exist: {token_file}")
        harness = ContractTarget(
            base_url=configured_url.rstrip("/"),
            token_file=token_file,
            settings=settings,
            capabilities=frozenset(config.getoption("--target-capability")),
            package_root=package_root,
        )
    else:
        token_file = tmp_path / "token"
        token_file.write_text("synthetic-contract-token\n", encoding="utf-8")
        os.chmod(token_file, 0o600)
        harness = ContractTarget(
            base_url=f"http://127.0.0.1:{unused_loopback_port()}",
            token_file=token_file,
            settings=settings,
            capabilities=LOCAL_CAPABILITIES,
            package_root=package_root,
            database=tmp_path / "simulator.sqlite3",
            process_log=tmp_path / "service.log",
        )
    harness.start()
    try:
        yield harness
    finally:
        harness.stop()
