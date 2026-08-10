# Labour statistics example

This synthetic project publishes reviewed, pre-aggregated SQLite views as
governed statistical datasets. Its primary authoring model uses ordinary
statistical terms and selects SDMX as a generated binding. It demonstrates:

- ordered dimensions, time, a measure, an observation attribute, concepts, and
  reviewed controlled vocabularies without requiring DSD authoring;
- deterministic SDMX identities for the public dataset, plus explicit identity
  overrides for the protected dataset to show the advanced publisher path;
- exact dimension selection and bounded `TIME_PERIOD` ranges;
- SDMX-JSON 2.1 and SDMX-CSV 2.1 data responses;
- generated SDMX structure metadata;
- public access plus scope, purpose, and authority-row-bound protected access;
  and
- bounded, deterministic, audited SQLite execution.

Relay does not aggregate the source rows, accept caller SQL, expose arbitrary
SDMX operators, or implement validity-schema generation, availability,
structure maintenance, or historical queries. The canonical schema and
availability surfaces return a value-free `501` rather than a Relay-specific
approximation.

## Start from an existing view

An adopter does not need to know SDMX to draft the dataset. Against an existing
SQLite database, inspect one reviewed statistical view without reading row
values:

```bash
relayctl inspect registry.sqlite \
  --starters generated \
  --statistical-view published_statistics \
  --time-column time_period \
  --measure-column observation_value \
  --attribute-column unit_measure
```

The generated `statistical-dataset-starter.yaml` is a copyable
`statisticalDatasets` fragment. It marks classification as `suggested`, uses
`REVIEW_REQUIRED` for the source and publication decisions, uses the explicitly
selected time and measure columns, keeps explicitly selected observation
attributes separate, proposes the remaining columns as dimensions,
and selects deterministic SDMX defaults with `sdmx: {}`. It never samples codes
or values and does not pretend that schema inspection can infer controlled
vocabularies or observation attributes.

Before `relayctl check`, the adopter reviews which proposed columns are truly
dimensions or attributes, fills the source and publication facts, attaches any
reviewed codelists, confirms concepts and classification, and chooses public or
protected access. Institutions that
already govern SDMX identities may then override the generated agency,
dataflow, DSD, and concept-scheme identifiers under `bindings.sdmx`; everyone
else leaves the empty binding unchanged. Relay derives the SDMX REST, JSON, and
CSV alignment versions from that binding; the adopter does not repeat them.
