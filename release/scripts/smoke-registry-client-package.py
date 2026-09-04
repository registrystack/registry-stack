#!/usr/bin/env python3
"""Offline construction smoke for the unified Registry Stack wheel."""

from importlib.metadata import version

import registry_client


def main() -> None:
    if registry_client.__version__ != version("registry-stack-client"):
        raise SystemExit("the Registry Stack client module version is inconsistent")
    if not all(
        callable(value)
        for value in (
            registry_client.breg.BaseRegistryClient,
            registry_client.discovery.DiscoveryClient,
            registry_client.evidence.EvidenceClient,
            registry_client.relay.RelayClient,
        )
    ):
        raise SystemExit("a Registry Stack client constructor is missing")
    public_types = (
        ("breg", registry_client.breg.BaseRegistryClient),
        ("breg", registry_client.breg.BaseRegistryClientError),
        ("discovery", registry_client.discovery.DiscoveryClient),
        ("discovery", registry_client.discovery.DiscoveryClientError),
        ("evidence", registry_client.evidence.EvidenceClient),
        ("evidence", registry_client.evidence.EvidenceClientError),
        ("relay", registry_client.relay.RelayClient),
        ("relay", registry_client.relay.RelayClientError),
    )
    for product, value in public_types:
        expected_module = f"registry_client.{product}"
        if value.__module__ != expected_module:
            raise SystemExit(
                f"{value.__name__} reports {value.__module__}, expected {expected_module}"
            )
        module = getattr(registry_client, product)
        if getattr(module, value.__name__, None) is not value:
            raise SystemExit(
                f"{expected_module}.{value.__name__} cannot be resolved by public identity"
            )
        if value.__qualname__ != value.__name__:
            raise SystemExit(
                f"{expected_module}.{value.__name__} has an unstable qualname"
            )
    client = registry_client.breg.BaseRegistryClient(
        base_url="https://registry.invalid",
        authorization={"static": "placeholder-token"},
    )
    if client is None:
        raise SystemExit("Base Registry client construction returned no client")
    print("Unified Python Registry client package smoke passed")


if __name__ == "__main__":
    main()
