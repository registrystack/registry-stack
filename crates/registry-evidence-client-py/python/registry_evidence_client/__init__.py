"""Python binding for the Evidence relying-party client, via PyO3.

Without this file, `python/registry_evidence_client/` is just a directory
holding a type stub next to a compiled extension of the same name, which
Python's import system treats as an empty PEP 420 namespace package: nothing
inside the compiled module is reachable. This file makes the directory an
ordinary package whose contents are the compiled module's own, matching
maturin's standard mixed Rust/Python layout.
"""

from .registry_evidence_client import *  # noqa: F401,F403

# The import system, not the `import *` above, is what binds the submodule's
# own name (`registry_evidence_client`) into this package's namespace:
# loading a submodule sets it as an attribute of its parent package. Drop it
# so the public surface matches the committed `__init__.pyi` exactly, with
# nothing extra for the stub-drift test to special-case. `pop` (not `del`)
# keeps this idempotent under `importlib.reload`, which re-executes this body
# against the existing namespace rather than a fresh one: on a second run the
# submodule is already in `sys.modules`, so the import system does not
# re-bind the attribute here, and a plain `del` would raise `NameError` on a
# name no longer present.
#
# The drop is not perfectly invisible: afterward, `import
# registry_evidence_client.registry_evidence_client` followed by attribute
# access still raises `AttributeError`, while `from registry_evidence_client
# import registry_evidence_client as sub` keeps working, since that form
# falls back to `sys.modules` directly.
globals().pop("registry_evidence_client", None)


def _bind_public_module() -> None:
    for value in tuple(globals().values()):
        if isinstance(value, type) and value.__module__ == "registry_evidence_client":
            value.__module__ = __name__


_bind_public_module()
del _bind_public_module
