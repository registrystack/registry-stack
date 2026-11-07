# Public certificate check deployment project

This is the packaged form of
[`examples/public-check`](../../../../examples/public-check/): the complete
bundle and runtime document an operator would deploy for the unauthenticated
certificate check, `POST /v1/public-check`.

- `bundle/` is the output of `evidencectl package` on the example.
- `compiled-authority.yaml` is the target authority that activates the check. It
  is activated into the authority root before the first start, as with any
  Evidence deployment.
- `runtime.yaml` holds the process-local paths and listener settings.

The example target uses the `local` assurance profile with loopback issuer,
source and public origins, so a test can serve this bundle on one machine. A
deployment packages its own target with a deployable assurance profile and
HTTPS hosts; nothing else in the check changes.

The bundle is generated, so edit the example and package it again rather than
editing files here. A test in `crates/registry-evidencectl/tests/public_check.rs`
fails when this bundle drifts from the example, apart from the signing key file
and the package envelope, which belong to the deployment that generated them.
The fixtures run through the production fixture command with the other projects
in this directory.
