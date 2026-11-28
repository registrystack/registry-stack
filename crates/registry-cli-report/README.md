# Registry CLI reports

`Report` writes the five common operator CLI headers in a fixed order, then
the binary's displayed `version`, flat command members, and a `diagnostics`
array. Products retain their command payloads, diagnostic contracts, and exit
decisions. The primitive adds no HTTP, runtime configuration, or authentication
dependency.

`Report::with_posture` adds a `posture` member with `value` (`development` or
`production`) and `source` (`flag`, `environment` or `default`) after the
command members. Without it the body is unchanged.

`Report::explicit_settings` adds an `explicitProductionSettings` list after
`posture`. Each line has `code`, `pointer`, an optional `line` and `column`,
and a value-free `summary`. It lists settings valid in every posture that
relax something, and it is not a diagnostic.

`status` is `complete`, `domain-refusal`, `usage-error`, or
`operational-failure`, corresponding to exit codes 0 through 3. A command's
more specific result, such as `declined`, is an `outcome`. An invalid envelope
returns an explicit programming error.

`install_panic_hook` is installed by binary entry points. It emits a value-free
`<binary>.internal-error` diagnostic and exits 3, without repeating the panic
payload or location. The entry point selects JSON from the requested output flags.

Run `cargo test --locked -p registry-cli-report` and the changed consuming
CLI's report and native command tests.
