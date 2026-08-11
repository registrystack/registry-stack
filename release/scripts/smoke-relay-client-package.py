#!/usr/bin/env python3
"""Offline construction smoke for an installed Registry Relay Python wheel."""

import registry_relay_client as client_module


def main() -> None:
    # The reserved host and placeholder bearer make a network regression fail
    # closed if a future constructor accidentally performs I/O.
    client = client_module.RelayClient(
        base_url="https://relay.invalid",
        authorization="placeholder-token",
    )
    if client is None:
        raise SystemExit("Relay client construction returned no client")
    if not callable(client_module.RelayClient):
        raise SystemExit("RelayClient is not an exported constructor")

    print("Python Relay client package smoke passed")


if __name__ == "__main__":
    main()
