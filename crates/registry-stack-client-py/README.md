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
`registry_client.scheduling`, because each product's routing, authentication,
errors, and verification rules are different. These namespaces
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
and require glibc 2.17 or newer on Linux. Install the client version selected by
your Registry Stack distribution; Discovery may have a different version.

The installed wheel includes the tested server baseline and compatible patch
line for Discovery in `registry_client/compatibility.json`:

```python
import json
from importlib.resources import files

compatibility = json.loads(
    files("registry_client").joinpath("compatibility.json").read_text(encoding="utf-8")
)
```

The Casework client uses compiled review policies, producer requests/results,
and human review tasks. Pass a bearer token and a Casework profile on producer,
reviewer, and Directory calls. Current-source context operations also take a source
profile; submitted-context reviews need no provider.
`casework.submission_digest(producer_id, source_namespace, request)` computes
the expected canonical submission digest locally. Admission through
`create_or_recover_review_request` takes the exact policy binding, caller-chosen
key, complete request, and digest. Retain them unchanged for response-loss
recovery; producer create/cancel calls are never automatically resent.
A `ReviewResult` records a review outcome and grants no external apply or write
authority.

Reviewer staffing uses `review_tasks`, `next_review_task`, and
`review_task_holdings`. Mutations take the task UUID, displayed revision, and
caller-chosen key. A decided-task read exposes `decisionReceipt` only to its
deciding caller; `own_review_decisions` discovers those retained receipts after
a fresh sign-in. `supervisory_review_tasks` exposes bounded task and
accountability references with a holder-free state. Keep staffing filters and
profiles unchanged across snapshot cursors; restart without the cursor after
`410 review.result-expired`.

The `registry_client.breg` namespace includes the typed retained-history page,
proposal, and inert result-reference classes exposed by the maintained BReg
binding. Their helpers inspect only an already loaded page and do not fetch
targets or advance pagination.

The `crates/registry-stack-client-py` directory in the Registry Stack
repository holds this public metadata and the Python facade. It is not built
directly. `release/scripts/assemble-registry-client-wheel.py` combines the version-selected
version-matched internal native wheels with the facade and emits the only
publishable Python distribution, using this file as the PyPI description.

The source facade includes `registry_client.coordinator`. The published
version's release roster determines availability; source integration alone is
not proof of published assets. Coordinator is optional for direct BReg and
Casework applications.

`from registry_client.auth import PrivateKeyJwt` selects the identical canonical
class exposed by the legacy `registry_client.breg.PrivateKeyJwt` spelling.
Configure a separate instance for each resource, audience, and scope set.
