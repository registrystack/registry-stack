# Independent offline Evidence project

Initialize this complete normalized project with `evidencectl init <directory>
--starter <this-directory> --profile local`, then run `check` and `test --target
<directory>/local-target.yaml`. It needs no BReg project, source import, credentials
or running service. Initialization generates disposable owner-only local key
material; the tracked project contains references only.

`evidence.yaml` owns the SQLite Source binding, exact selector profile, derive
Function and `extract-record-active` definition. The pinned adapter pack owns the
statement, response validation and fact extraction. `local-target.yaml` binds
local process resources and names a placeholder path for the
`record-status-extract` file, while `dev-authority.yaml` supplies a complete local
caller grant. The 13 synthetic fixtures cover active and retired records,
no match and ambiguity, bounded results, stale extracts, statement and output
refusals, and hostile selector data remaining a bound parameter.

The Source's fixed statement, schemas and extraction program live under its
`adapter-packs/` closure; assertion derivation remains under `functions/`.
Fixture extracts are private synthetic inputs. This starter neither publishes a
production extract nor grants access to a registry. The parent composition
journey optionally adds a BReg Source and two further definitions without
replacing this independent proof.
