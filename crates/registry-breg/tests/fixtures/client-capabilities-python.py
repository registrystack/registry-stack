# SPDX-License-Identifier: Apache-2.0
"""Public installed Python package through a real BREG HTTP fixture."""
import os
from registry_client.breg import BaseRegistryClient, BRegPreparedCreate

client = BaseRegistryClient(os.environ["BREG_TEST_CLIENT_URL"])
metadata = client.registry_contract("operator")
assert metadata.operations
binding = metadata.select_create("records.entry.create", "operator")
data = {"code": "PYTHON", "label": "Python package", "validFrom": "2020-01-01"}
prepared = client.prepare_create(binding, data, "python-package-create")
first = client.create_record(binding, data, "python-package-create")
fresh = client.registry_contract("operator")
current_binding = fresh.select_create("records.entry.create", "operator")
restored = BRegPreparedCreate.from_bytes(prepared.to_bytes())
recovered = client.recover_create(current_binding, restored)
replay = client.execute_recovered_create(current_binding, recovered)
assert replay["value"]["data"]["recordIdentifier"] == first["value"]["data"]["recordIdentifier"]
current = client.list_current_records("entries", access_profile="operator")
assert len(current["value"]["items"]) == 1
snapshot = client.list_snapshot_records("entries", access_profile="operator")
assert len(snapshot["value"]["items"]) == 1
revisions = client.record_revisions("entries", first["value"]["data"]["recordIdentifier"], "operator")
assert isinstance(revisions["body"], bytes)
print("Installed public Python package completed real BREG reads and recovered mutation")
