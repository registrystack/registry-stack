# Security Policy

Registry Lab is a public demo and proof harness for RegistryStack components.
It is not a production deployment template.

## Supported Versions

Registry Lab is pre-1.0. Security fixes target the current `main` branch until
release branches or tagged support windows are introduced.

## Reporting A Vulnerability

Please do not open a public issue for suspected vulnerabilities.

Use GitHub private vulnerability reporting for this repository:

https://github.com/jeremi/registry-lab/security/advisories/new

Include the affected commit, reproduction steps, impact, and any known
workaround. Avoid including real credentials, private registry data, or personal
data in the report.

## Demo Boundaries

Committed demo credentials are intended for local or hosted demonstration only.
Do not reuse them in production or connect the default Lab topology to real
registry systems without a separate security review.

## Image And Supply-Chain Caveat

Registry Lab may build or reference demo images for hosted walkthroughs. Treat
those images as demo artifacts unless they are pinned to product image digests
that have their own release evidence. The first serious release does not claim
image-signature verification for Lab-built images, and Lab-hosted image builds
may not include SBOM or provenance attestations.

## Hosted Demo Secret Handling

Hosted Lab configuration may use platform-managed environment variables for demo
credentials and generated JSON snippets. Treat those values as demo-only, rotate
them before public walkthroughs, and do not connect hosted Lab services to real
registry data or production identity systems without a separate deployment
security review.
