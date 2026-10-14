"""Negative typecheck fixture: a required Action input is deliberately missing."""
from project import ProjectClient

def missing_required_inputs(client: ProjectClient) -> None:
    client.register_facility({"name": "Example"}, "invalid-input")
