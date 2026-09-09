# registry-breg-client-py

Internal PyO3 binding for `registry-breg-client`. The release process bundles
this module into the public `registry-stack-client` wheel. It is not published
as a standalone PyPI project.

Use `action.with_reason(text)` on a promoted `reject_request` or
`request_revision` action to add optional reviewer text. It returns a copy and
validates before network effects. The original action omits the reason. Text
is preserved exactly, allows an empty string, and is limited to 4096 Unicode
characters with NUL refused. Reuse the same action and idempotency key for an
explicit retry.
