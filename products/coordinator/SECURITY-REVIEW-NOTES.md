# Registry Coordinator security review notes

Review notes for security-sensitive Coordinator changes, held in tracked
material because commit messages do not survive a squash. Each section names
the threat it answers, the defaults the product ships, where Rust enforces it,
the tests that pin it, and the residual risk it accepts.

## Coordinatorctl access-token files

### Threat

An authenticated `coordinatorctl` command reads `--token-file` before it calls
the service. Opening a FIFO with an ordinary blocking read can hold the command
indefinitely, and following a symbolic link means the named path does not
identify the file the operator intended to use.

### Enforcement and defaults

On Unix, `coordinatorctl` opens the token path read-only with `NOFOLLOW`,
`NONBLOCK`, and `CLOEXEC`, then verifies from the opened descriptor that it is
a regular file before reading any bytes. Other platforms reject a symlink or
non-regular path before opening it and verify that the opened handle is a
regular file. The existing 16,384-byte bound, compact-token validation, and
value-free diagnostics remain unchanged. This check applies only to
`--token-file`; ordinary authored input files keep their existing contract.

### Tests

- `crates/registry-coordinator/tests/cli_remote.rs`:
  `token_file_refuses_symlinks_and_fifos_without_blocking` bounds the child
  process wait, exercises a symbolic link and FIFO, and proves neither output
  stream contains the synthetic token.
- The same target's
  `a_relative_token_file_is_read_from_the_current_directory` keeps the normal
  regular-file path and relative-path behavior covered.

### Accepted residuals

- `coordinatorctl` remains local operator tooling on a trusted single-user
  machine. The Unix open is race-safe for the final path component; broader
  filesystem and directory-component races remain accepted for this adopter
  CLI rather than introducing a directory-descriptor traversal policy.

## OIDC issuer transport and private addresses

### Threat

The Coordinator fetches discovery and signing keys for
`deployment.authentication`. A fetch an attacker can steer may reach internal
services or cloud metadata, and a key set read over plain HTTP can be
substituted by an on-path attacker, whose keys would then mint access tokens
the Coordinator accepts.

### Enforcement and defaults

The Coordinator fetches under the shared issuer network policy that Casework,
Messaging, and Scheduling use, instead of the strict public policy, or the
development loopback policy under `development-loopback`:

- The declared issuer and a declared `jwksSource.uri` may resolve to a private
  or loopback address on any origin; both are operator configuration.
- A discovered `jwks_uri` inherits that allowance only on the issuer's own
  origin. On another origin it must use HTTPS and is refused when it resolves
  to a private or loopback address, under `development-loopback` too.
- Cloud metadata and link-local addresses are refused for declared and
  discovered endpoints alike. Redirects remain disabled.
- Plain HTTP is accepted at load only with
  `deployment.authentication.allowInsecureHttp: true`, or on loopback under
  `development-loopback`. That setting never extends plain HTTP to a
  discovered endpoint on another origin.

`OidcIssuerConfig::check` in `crates/registry-platform-config/src/blocks.rs`,
reached from `AccessConfig::findings` in
`crates/registry-coordinator/src/access.rs` when the runtime file is loaded,
refuses a plain HTTP issuer or key URI the rules above do not admit, at its
member and with the setting that would admit it. `AccessConfig::authenticator`
builds `IssuerNetworkPolicy` from the same block, fetches discovery through
`fetch_discovery_for_issuer`, and keeps the endpoint policy that function
returns for every later key refresh; a declared key URI keeps
`declared_jwks_fetch_policy`. When the opt-in is set, startup logs the fixed
warning from `insecure_http_startup_diagnostic`.

### Tests

- `crates/registry-coordinator/tests/deployment_surface.rs`:
  `a_remote_http_issuer_is_refused_without_the_opt_in` and
  `runtime_reads_the_explicit_http_issuer_opt_in`.
- `crates/registry-coordinator/src/access.rs`:
  `http_issuer_opt_in_has_a_startup_diagnostic`.
- `crates/registry-platform-oidc/src/lib.rs`, for the shared policy:
  `non_loopback_http_requires_the_named_opt_in_while_loopback_does_not`,
  `declared_loopback_http_jwks_under_an_https_issuer_is_accepted_without_the_opt_in`,
  `a_cross_origin_jwks_must_use_https_even_under_the_http_opt_in`,
  `discovered_cross_origin_private_or_loopback_jwks_stays_refused`, and
  `cloud_metadata_is_refused_for_declared_and_discovered_key_endpoints`.

### Accepted residuals

- Outside `development-loopback`, the declared issuer and a declared key URI
  may now resolve to a private address. An operator who declares an internal
  address points the Coordinator at it; the allowance covers only what the
  operator wrote, and cloud metadata stays refused.
- With `allowInsecureHttp: true`, an on-path attacker between the Coordinator
  and the issuer can substitute keys. The setting is explicit, named in the
  startup warning, and confined to the issuer's origin and the declared key
  URI.
- A deployment whose discovery document names a key endpoint on another
  private origin is refused at startup. The changelog names the migration:
  declare the key endpoint as `jwksSource.uri`, or serve it from the issuer's
  origin.
