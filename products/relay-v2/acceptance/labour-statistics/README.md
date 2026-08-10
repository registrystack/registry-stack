# Labour statistics acceptance definition

This synthetic deployment publishes reviewed, pre-aggregated SQLite views as
two governed statistical datasets. Each dataset has one fixed access rule and
selects one generated SDMX binding. It proves:

- format-neutral dimensions, quarterly time, one decimal measure, one
  controlled-code attribute, reviewed vocabularies, publication facts, and
  query bounds;
- required `bindings.sdmx`, with deterministic compiler defaults for the
  public dataset and explicit governed identity overrides for the protected
  dataset;
- the SDMX REST 2.2.2 read subset through keyed and omitted-key data aliases,
  plus dataflow and datastructure structure routes only;
- SDMX-JSON, SDMX-CSV, and SDMX structure JSON 2.1.0 without an authored wire
  version or alignment target;
- public access and a separately protected dataset with scope, purpose, and
  authority-row binding;
- exact typed SQLite predicates, typed JSON values, bounded deterministic
  execution, distinct data and structure audit surfaces, and exact-byte audit
  gates for both data wire formats; and
- generated exact dataflow and DSD package artifacts validated against the
  digest-locked official SDMX JSON schemas without committing upstream schema
  bytes.

Relay does not aggregate source rows, accept caller SQL, expose schema or
availability routes, implement history or structure maintenance, or advertise
SDMX versions through authored `registry.alignmentTargets`.
