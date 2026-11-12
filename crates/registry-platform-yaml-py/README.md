# registry-platform-yaml-py

Internal PyO3 binding for the shared Registry Stack configuration reader. The
unified Python client may assemble this module; it is not a separately
published package.

The public function is:

```python
read_document(
    contents: bytes,
    *,
    file: str,
    api_version: str,
    kind: str,
) -> dict[str, JSONValue]
```

It accepts bytes so the native reader owns UTF-8, input-size and syntax
decisions. JSON is read as YAML 1.2 flow content through
`registry-platform-yaml`, including duplicate-key, alias, tag, depth and
envelope checks. The caller supplies one expected current `apiVersion` and
`kind`; product-specific field and policy validation remains with the caller.

A refused document raises `ConfigReadError` with the fixed message
`Configuration document was refused`. Its `diagnostics` attribute is a tuple
of the shared reader's JSON diagnostic objects. The reader caps the input at
1 MiB and depth at 128. It retains at most 100 individual diagnostics and may
add one `config.too-many-problems` overflow diagnostic.
Diagnostic messages do not repeat scalar values from the document. The
binding additionally bounds the diagnostic file name to 4 KiB and each
expected format identifier to 256 bytes. The registered Python connection and
development workload-token envelopes are decoded into their closed native
types at the same boundary, including their non-empty authority sets. Other
formats receive the generic envelope and structural checks before their
product-specific validation.

The standalone development import is:

```python
from registry_platform_yaml import ConfigReadError, read_document
```

When the package is relocated into the unified client wheel, the intended
import is:

```python
from registry_client.yaml import ConfigReadError, read_document
```
