# Registry Platform SQLite

`registry-platform-sqlite` is the product-neutral SQLite security boundary used
by Registry Stack runtimes. It captures immutable snapshots, opens snapshot or
live databases read-only, validates reviewed statements, rejects mutating and
non-deterministic SQL, and executes under explicit queue, time, step, row, cell,
and response bounds.

Snapshot profiles bind a regular, unwritable, sidecar-free file to its identity
and SHA-256 digest and open it with SQLite's immutable mode. Live profiles bind
the main path identity, require an expected schema fingerprint, and re-verify
that fingerprint inside the same read transaction as each statement. Execution
provenance reports the profile, verified schema fingerprint when configured,
snapshot revision when available, and a domain-separated statement digest.

Schema inspection reads only `main.sqlite_schema` and SQLite's column metadata.
It returns ordered object and column declarations under fixed engine limits and
caller-supplied object, metadata-byte, step, and time bounds. It never samples a
table or view row.

The crate is SQLite-specific. It does not define a generic storage interface,
and it never places SQL, database paths, parameters, or returned values in an
error.

Pathname checks alone cannot detect a database substituted while SQLite opens
its pool and restored immediately afterward. On Unix, the crate therefore asks
SQLite's active VFS whether each actual `main` handle has moved, after pool
construction and before and after every statement. Rusqlite does not expose a
safe wrapper for `SQLITE_FCNTL_HAS_MOVED`, so one small documented FFI function
is the crate's only `unsafe` exception. The crate denies unsafe code everywhere
else, checks the SQLite return code conservatively, and never dereferences the
opaque connection pointer itself.

Production use is Unix-only until another target has an equivalent actual-open
handle proof. Non-Unix builds fail closed when opening a SQLite connection
rather than silently falling back to pathname checks.

The optional `fixture` feature enables materializing reviewed fixture seed SQL.
Production readers never use that authorizer-free connection.
