"""Python binding for the Evidence relying-party client, via PyO3.

Without this file, `python/registry_evidence_client/` is just a directory
holding a type stub next to a compiled extension of the same name, which
Python's import system treats as an empty PEP 420 namespace package: nothing
inside the compiled module is reachable. This file makes the directory an
ordinary package whose contents are the compiled module's own, matching
maturin's standard mixed Rust/Python layout.
"""

from .registry_evidence_client import *  # noqa: F401,F403

# `import *` above also binds the submodule's own name (`registry_evidence_client`)
# into this package's namespace, alongside the classes and exceptions it
# actually exports; drop it so the public surface matches the committed
# `__init__.pyi` exactly, with nothing extra for the stub-drift test to
# special-case.
del registry_evidence_client
