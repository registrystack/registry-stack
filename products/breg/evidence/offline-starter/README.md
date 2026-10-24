# Independent offline Evidence project

Initialize this complete normalized project with `evidencectl init <directory>
--starter <this-directory> --profile local`, then run `check` and `test --target
<directory>/local-target.yaml`. It needs no BReg project, source import, credentials
or running service. Initialization generates disposable owner-only local key
material; the tracked project contains references only.

`evidence.yaml` owns the SQLite Source, exact selector profile, named extraction
and derive Functions, and `extract-record-active` definition. `local-target.yaml`
binds local process resources and names a placeholder path for the
`record-status-extract` file, while `dev-authority.yaml` supplies a complete local
caller grant. The 13 synthetic fixtures cover active and retired records,
no match and ambiguity, bounded results, stale extracts, statement and output
refusals, and hostile selector data remaining a bound parameter.

The Source's fixed statement lives under `queries/`; reviewed programs live under
`functions/`. Fixture extracts are private synthetic inputs. This starter neither
publishes a production extract nor grants access to a registry. The parent
composition journey optionally adds a BReg Source and two further definitions
without replacing this independent proof.
