# Security Policy

## Supported Versions

Registry Manifest follows the Registry Stack supported-release and branch policy.

## Reporting a Vulnerability

Please do not open a public issue for suspected vulnerabilities.

Use GitHub private vulnerability reporting for the Registry Stack monorepo:

https://github.com/registrystack/registry-stack/security/advisories/new

Include the affected version or commit, reproduction steps, impact, and any
known workaround. We will acknowledge the report, assess severity, and
coordinate a fix before public disclosure when appropriate.

The root [security policy](../../SECURITY.md) defines the reporting scope and
release-verification guidance for all Registry Stack products.

## Dependency advisory posture

Root CI runs `cargo deny check` for relevant pushes and pull requests, covering
the locked workspace dependency graph. Accepted advisory exceptions live in
the root [`deny.toml`](../../deny.toml); each carries a scoped rationale and a
review trigger.
Unsound or memory-safety advisories on direct dependencies (for example, the
`libyml` / `serde_yml` class of issues) escalate immediately and block the
release; the maintained equivalent is preferred over ignoring the advisory.
