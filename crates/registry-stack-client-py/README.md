# registry-stack-client

One versioned Python package for the Discovery, Evidence, Base Registry
Engine, Casework, Messaging, and Scheduling client APIs in Registry Stack.

The distribution installs as `registry-stack-client` and imports as
`registry_client`. The two spellings differ, so `import registry_stack_client`
raises `ModuleNotFoundError`.

```sh
python -m pip install "registry-stack-client==<version>"
```

```python
from registry_client import breg, casework, discovery, evidence, messaging, scheduling

registry = breg.BaseRegistryClient("https://registry.example.invalid/")
inbox = casework.CaseworkClient("https://casework.example.invalid/")
messages = messaging.MessagingClient("https://messaging.example.invalid/")
appointments = scheduling.SchedulingClient("https://scheduling.example.invalid/")
```

Each product remains in its own module namespace, `registry_client.breg`,
`registry_client.casework`, `registry_client.discovery`,
`registry_client.evidence`, `registry_client.messaging`, and
`registry_client.scheduling`, because each
product's routing, authentication, errors, and verification rules are different. These namespaces
also keep the unified distribution's files disjoint from earlier standalone
client distributions, so installing or uninstalling either package cannot
remove files owned by the other. The unified package is published beginning
with Registry Stack v0.26.1. The `casework` namespace is part of the unified
package beginning with Registry Stack v0.30.0.
The `messaging` namespace is part of the unified package beginning with
Registry Stack v0.38.0. The `scheduling` namespace is part of the unified
package beginning with Registry Stack v0.40.0.
Existing standalone client packages remain available for earlier versions, but
later releases use this unified entry point.

Wheels cover macOS arm64, Linux arm64 with glibc, and Linux x64 with glibc,
and require glibc 2.17 or newer on Linux. Install the exact client version that
matches the deployment.

The Casework client supports reviewer inbox ownership filters and the separate
`supervisory_review_tasks` discovery method. Supervisory rows carry bounded task
and accountability references with a holder-free string state; a single decided-task read exposes a
`decisionReceipt` only to the caller who recorded that decision.

The `registry_client.breg` namespace includes the typed retained-history page,
proposal, and inert result-reference classes exposed by the maintained BReg
binding. Their helpers inspect only an already loaded page and do not fetch
targets or advance pagination.

The `crates/registry-stack-client-py` directory in the Registry Stack
repository holds this public metadata and the Python facade. It is not built
directly. `release/scripts/assemble-registry-client-wheel.py` combines the six
version-matched internal native wheels with the facade and emits the only
publishable Python distribution, using this file as the PyPI description.
