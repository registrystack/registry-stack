from pathlib import Path

import pytest

from tests.fixtures.target import ContractTarget, TargetSettings


def test_external_target_start_does_not_require_simulator_health_route(
    tmp_path: Path, monkeypatch
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("synthetic-external-token\n", encoding="utf-8")
    target = ContractTarget(
        base_url="https://sandbox.example.test",
        token_file=token_file,
        settings=TargetSettings(),
        capabilities=frozenset(),
        package_root=tmp_path,
    )

    def unexpected_health_probe() -> None:
        raise AssertionError("external targets must not require /healthz")

    monkeypatch.setattr(target, "_wait_until_ready", unexpected_health_probe)
    target.start()


def test_external_collection_scenario_requires_declared_capability(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("synthetic-external-token\n", encoding="utf-8")
    target = ContractTarget(
        base_url="https://sandbox.example.test",
        token_file=token_file,
        settings=TargetSettings(),
        capabilities=frozenset(),
        package_root=tmp_path,
    )

    with pytest.raises(pytest.skip.Exception, match="collection-paid"):
        target.configure_collection_scenario("paid", "P2G-FIXTURE")


def test_external_collection_scenario_accepts_provider_control(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("synthetic-external-token\n", encoding="utf-8")
    target = ContractTarget(
        base_url="https://sandbox.example.test",
        token_file=token_file,
        settings=TargetSettings(),
        capabilities=frozenset({"collection-paid"}),
        package_root=tmp_path,
    )

    target.configure_collection_scenario("paid", "P2G-FIXTURE")
