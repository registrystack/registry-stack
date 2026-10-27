from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

LOCAL_CAPABILITIES = frozenset(
    {
        "collection-expired",
        "collection-failed",
        "collection-paid",
        "success",
        "partial-failure",
        "hold-processing",
        "restart",
        "effect-witness",
        "lost-response",
    }
)


def decimal_json(response: httpx.Response) -> Any:
    return json.loads(response.content, parse_float=Decimal)


@dataclass(frozen=True)
class TargetSettings:
    producer: str = "registry"
    tenant: str = "pilot"
    institution: str = "ministry"
    biller: str = "ministry"
    source_id: str = "registry"
    programme: str = "cash-support"
    payer_account: str = "programme-account"
    registration_callback_url: str = "https://programme.example.test/callback"
    batch_callback_url: str = "https://programme.example.test/api/v1/batch"
    currency: str = "USD"
    currency_scale: int = 2
    poll_interval: float = 0.05
    poll_timeout: float = 5.0


@dataclass
class ContractTarget:
    base_url: str
    token_file: Path
    settings: TargetSettings
    capabilities: frozenset[str]
    package_root: Path
    database: Path | None = None
    process_log: Path | None = None
    _process: subprocess.Popen[bytes] | None = field(default=None, init=False)
    _log_handle: Any = field(default=None, init=False)

    @property
    def is_local_simulator(self) -> bool:
        return self.database is not None

    def token(self) -> str:
        token = self.token_file.read_text(encoding="utf-8").strip()
        if not token:
            pytest.fail("the target token file is empty")
        return token

    def headers(self, **overrides: str) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.token()}",
            "Platform-TenantId": self.settings.tenant,
        }
        headers.update(overrides)
        return headers

    def client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base_url, timeout=2.0)

    def require(self, capability: str, test_id: str) -> None:
        if capability not in self.capabilities:
            pytest.skip(
                f"NOT VERIFIED [{test_id}]: target fixture does not provide "
                f"the {capability!r} capability"
            )

    def start(self) -> None:
        if not self.is_local_simulator:
            return
        if self._process is not None:
            raise RuntimeError("target process is already running")
        assert self.database is not None
        assert self.process_log is not None
        self._log_handle = self.process_log.open("ab")
        host, port_text = self.base_url.removeprefix("http://").rsplit(":", 1)
        command = [
            sys.executable,
            "-m",
            "payment_simulator",
            "serve",
            "--database",
            str(self.database),
            "--token-file",
            str(self.token_file),
            "--host",
            host,
            "--port",
            port_text,
            "--manual",
            "--producer",
            self.settings.producer,
            "--tenant",
            self.settings.tenant,
            "--institution",
            self.settings.institution,
            "--biller",
            self.settings.biller,
            "--source-id",
            self.settings.source_id,
            "--program",
            self.settings.programme,
            "--payer-account",
            self.settings.payer_account,
            "--callback-url",
            self.settings.registration_callback_url,
            "--callback-url",
            self.settings.batch_callback_url,
            "--currency",
            f"{self.settings.currency}:{self.settings.currency_scale}",
            "--mode",
            "00",
        ]
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"
        self._process = subprocess.Popen(
            command,
            cwd=self.package_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
        )
        try:
            self._wait_until_ready()
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=3)
            self._process = None
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None

    def restart(self, test_id: str) -> None:
        self.require("restart", test_id)
        if not self.is_local_simulator:
            pytest.skip(f"NOT VERIFIED [{test_id}]: no external restart driver was configured")
        self.stop()
        self.start()

    def configure_scenario(
        self, name: str, test_id: str, *, reject_request: str | None = None
    ) -> None:
        required = "partial-failure" if name == "partial" else "success"
        self.require(required, test_id)
        if not self.is_local_simulator:
            if name == "success":
                return
            pytest.skip(
                f"NOT VERIFIED [{test_id}]: no external partial-failure driver was configured"
            )
        arguments = ["scenario", "--name", name]
        if reject_request is not None:
            arguments.extend(["--reject-request", reject_request])
        arguments.extend(
            [
                "--producer",
                self.settings.producer,
                "--tenant",
                self.settings.tenant,
            ]
        )
        self._run_cli(arguments)

    def configure_collection_scenario(self, outcome: str, test_id: str) -> None:
        capability = f"collection-{outcome}"
        self.require(capability, test_id)
        if not self.is_local_simulator:
            return
        self._run_cli(
            [
                "collection-scenario",
                "--outcome",
                outcome,
                "--producer",
                self.settings.producer,
                "--tenant",
                self.settings.tenant,
                "--biller",
                self.settings.biller,
            ]
        )

    def advance(self, test_id: str, *, steps: int = 2) -> None:
        self.require("hold-processing", test_id)
        if not self.is_local_simulator:
            pytest.skip(
                f"NOT VERIFIED [{test_id}]: no external processing-control driver was configured"
            )
        self._run_cli(["advance", "--steps", str(steps)])

    def inspect(self, test_id: str, *, batch_id: str | None = None) -> dict[str, Any]:
        self.require("effect-witness", test_id)
        if not self.is_local_simulator:
            pytest.skip(
                f"NOT VERIFIED [{test_id}]: no external effect-witness driver was configured"
            )
        arguments = ["inspect"]
        if batch_id is not None:
            arguments.extend(["--batch-id", batch_id])
        result = self._run_cli(arguments)
        return json.loads(result.stdout, parse_float=Decimal)

    def inspect_collections(
        self, test_id: str, *, transfer_request_id: str | None = None
    ) -> dict[str, Any]:
        self.require("effect-witness", test_id)
        if not self.is_local_simulator:
            pytest.skip(
                f"NOT VERIFIED [{test_id}]: no external collection-witness driver was configured"
            )
        arguments = ["inspect-collections"]
        if transfer_request_id is not None:
            arguments.extend(["--transfer-request-id", transfer_request_id])
        result = self._run_cli(arguments)
        return json.loads(result.stdout, parse_float=Decimal)

    def finish_processing(self, test_id: str) -> None:
        if self.is_local_simulator:
            self.advance(test_id, steps=2)

    def _run_cli(self, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        assert self.database is not None
        command = [
            sys.executable,
            "-m",
            "payment_simulator",
            *arguments,
            "--database",
            str(self.database),
        ]
        result = subprocess.run(
            command,
            cwd=self.package_root,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 0:
            pytest.fail(
                f"fixture driver failed with exit {result.returncode}: {result.stderr.strip()}"
            )
        return result

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self.settings.poll_timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if self._process is not None and self._process.poll() is not None:
                pytest.fail(
                    f"payment simulator exited during startup with "
                    f"status {self._process.returncode}; log: {self.process_log}"
                )
            try:
                response = httpx.get(f"{self.base_url}/healthz", timeout=0.5)
                if response.status_code == 200:
                    return
            except httpx.HTTPError as error:
                last_error = error
            time.sleep(0.05)
        pytest.fail(f"target did not become ready at {self.base_url}: {last_error}")


def unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])
