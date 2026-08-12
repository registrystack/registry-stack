# Historical upgrade exercise records

This directory contains completed upgrade exercise reports from releases before
v0.19. They are immutable historical evidence, not templates or inputs to the
current release pipeline.

Current `main` does not provide the Relay V1 and `registryctl` schemas, asset
preparation tools, or validators that produced these records. To reproduce or
verify one, check out the exact Registry Stack tag named by the report and use
that tag's release documentation with its archived release assets.

Do not update a completed report to a newer schema or run it through current
release tooling. A new v0.19-or-later release uses the maintained candidate
manifest, checksums, SBOM, provenance, and digest-reconciliation flow instead.
