# Base Registry Engine

Base Registry Engine is the domain-neutral, configuration-compiled Registry Stack
system of record. The crate owns the governed model, deterministic compiler,
generated contract artifacts, PostgreSQL runtime, and HTTP service.

The default feature set is I/O-free so authoring tools can compile and inspect
a Registry project without initializing runtime resources. The `runtime`
feature enables the server binary and runtime integrations.

Domain concepts are configuration. Production code must not embed household,
farmer, disability, business, or other adopter-specific record types.
