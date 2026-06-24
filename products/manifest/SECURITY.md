# Security Policy

## Supported Versions

Registry Manifest is pre-1.0. Security fixes are targeted at the current `main`
branch until release branches are introduced.

## Reporting a Vulnerability

Please do not open a public issue for suspected vulnerabilities.

Use GitHub private vulnerability reporting for this repository:

https://github.com/jeremi/registry-manifest/security/advisories/new

Include the affected version or commit, reproduction steps, impact, and any
known workaround. We will acknowledge the report, assess severity, and
coordinate a fix before public disclosure when appropriate.

## Dependency Advisory Posture

CI runs `cargo audit` and `cargo deny check` on every push and pull request, so
new RustSec advisories surface immediately. Acceptable advisory ignores live in
`deny.toml`; each carries a scoped rationale and a review trigger, and the full
list is reviewed quarterly or whenever a transitive dependency upgrades.
Unsound or memory-safety advisories on direct dependencies (for example, the
`libyml` / `serde_yml` class of issues) escalate immediately and block the
release; the maintained equivalent is preferred over ignoring the advisory.
