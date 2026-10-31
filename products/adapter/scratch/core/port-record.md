# Governed-ingestion core port record

Recorded for the core model and checks of the governed-ingestion mode
(`products/adapter/CONCEPT.md` section 17, work items F3, F5, and the
format halves of F2 and F4). The pinned Camel source is the 4.23.0 clone
at `agent-scratch/camel-src/camel-4.23.0`. Citations below use the form
`camel-4.23.0:<path>#<field or test>`.

## The CSV decoder option model

The decoder lives in `crates/registry-adapter-core/src/job.rs`
(`CsvDecoder`), is selected on a `pollEnrich` step
(`crates/registry-adapter-core/src/route.rs`, `PollEnrichStep::decoder`),
and is held to the same rules as every bounded decoder: rows are maps
keyed by the header record, no type inference, and every size bound of
the job profile applies.

### Kept options

| Our key | Camel field | Default |
|---|---|---|
| `delimiter` | `camel-4.23.0:core/camel-core-model/src/main/java/org/apache/camel/model/dataformat/CsvDataFormat.java#delimiter` (the component the engine reads, `camel-4.23.0:components/camel-csv/src/main/java/org/apache/camel/dataformat/csv/CsvDataFormat.java#delimiter`, types it `Character`) | `,` |
| `quote` | same file, `#quote` | `"` |
| `quoteDisabled` | same file, `#quoteDisabled` | `false` |
| `header` | same file, `#headerDisabled`, complemented | `true` |
| `commentMarker` | same file, `#commentMarker` | absent (comments off) |
| `trim` | same file, `#trim` | `false` |
| `encoding` | no Camel counterpart; the charset rides the exchange in Camel. An addition, pinned to `utf-8` | `utf-8` |

Decisions recorded:

- `delimiter` is typed as one character, not a string: the component-side
  Java field is a `Character`, and a single character is the honest bound,
  refused at the reader.
- `header` is the boolean the brief sketches. Camel spells the complement
  (`headerDisabled`, default false) and its `header` string is a rename
  list for marshalling; renaming columns is mapping work here, so the
  boolean ports the effective unmarshal behavior (headers on by default)
  and the rename list is dropped.
- `commentMarkerDisabled` folds into absence: `commentMarker` unset is
  already the off state, so a second flag has no meaning.
- The empty mapping `{}` as a decoder value selects csv at Camel's
  defaults, because the options mapping is the csv form of the one
  `decoder` member.
- The bare names `csv`, `jsonl`, and `raw` select without options; an
  unknown name refuses at the checks under `adapter.job.decoder-unknown`,
  not at the reader, so the refusal carries the closed-set code the
  format assigns. The JSONL decoder has no options: an addition under
  section 5.4, not a port (CONCEPT 8.10, the JSONL row).

### Dropped options

Every remaining `CsvDataFormat` field, with the reason:

| Camel field | Reason |
|---|---|
| `format` | The reference format is fixed at `DEFAULT`; a second format (MYSQL, TSV, and cousins) is a new port-table row when a source needs it. The defaults below follow from `DEFAULT`. |
| `escape`, `escapeDisabled` | `CSVFormat.DEFAULT` escapes a quote with a quote; the bounded decoder keeps the reference behavior and offers no override. |
| `headerDisabled` | Folded into the complemented `header` boolean. |
| `allowMissingColumnNames` | Not ported. A row with fewer columns than the header pads its missing members with the empty string, deterministically: a recorded divergence from Camel's `toMap` short map, chosen so a source whose trailing columns are optional still reads. A row with more columns than the header refuses per item. |
| `ignoreEmptyLines` | Fixed at the `DEFAULT` format behavior Camel's default gives (empty lines are ignored); no source asked for the strict form. |
| `ignoreSurroundingSpaces` | Subsumed by `trim`. A recorded divergence sits inside `trim` itself: Commons CSV trims unquoted fields only, the reader trims quoted fields too, so a quoted field carrying meaningful surrounding blanks is stripped where Camel would keep it. |
| `nullString`, `nullStringDisabled` | Fixed at Camel's default (no null string): an empty field decodes as an empty string and never as null, so empty versus null is deterministic. |
| `recordSeparator`, `recordSeparatorDisabled` | The reference separators; a bounded reader accepts the platform line endings the file carries and the option buys nothing. |
| `skipHeaderRecord` | Marshalling only; the decoder never writes CSV. |
| `quoteMode` | Marshalling only (how much to quote on write). |
| `ignoreHeaderCase` | Row map keys stay exactly as the header record carries them; mapping owns any case folding, deterministically. |
| `trailingDelimiter` | Marshalling only. |
| `marshallerFactoryRef` | Registry lookup, marshalling; no registry in the engine. |
| `lazyLoad` | The decoder always reads one bounded page, never a stream over the whole file. |
| `useMaps` | Our rows are always maps keyed by the header record, so the option has no false form here. |
| `useOrderedMaps` | Row map member order follows the engine's JSON object rules, not the file's column order. |
| `recordConverterRef` | Registry lookup; the item contract is the only row shape. |
| `captureHeaderRecord` | The header would travel as a message header, a channel the exchange contract reserves; the decoder's page is the only output. |
| `commentMarkerDisabled` | Folded into `commentMarker` absence (see above). |

## Ported and excluded Camel unit tests

The camel-csv test tree at the tag holds 35 Java files under
`camel-4.23.0:components/camel-csv/src/test/java/`. The option-model work
ports the default and option assertions and records the rest.

Ported (assertions live in `job.rs`'s `csv_decoder_defaults_match_camel`
and `route.rs`'s `poll_enrich_step_round_trips`):

- `camel-4.23.0:components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvDataFormatTest.java#shouldUseDefaultFormat`: a bare
  decoder sits on `CSVFormat.DEFAULT`. Ported as: an empty mapping
  decodes with comma delimiter, double quote, quoting on, header record
  on, no comment marker, no trimming, UTF-8, and the defaults stay off
  the wire.
- `camel-4.23.0:components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvDataFormatTest.java#testTrim`: trim unset means
  the format's default false; true turns trimming on. Ported as the
  `trim` default and explicit-true assertions.
- `camel-4.23.0:components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalTabDelimiterTest.java` and
  `CsvUnmarshalPipeDelimiterTest.java` (and their Spring twins): a
  non-comma delimiter changes the field split. Ported as the explicit
  `delimiter` and `quote` round trip (`"\t"` and `'`).
- `camel-4.23.0:components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalCommentMarkerSpringTest.java`: a comment
  line is skipped when the marker is set. Ported as the `commentMarker`
  option round trip; the line-skipping behavior itself is the engine
  stream's decoder implementation test.
- `camel-4.23.0:components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalMapLineSpringTest.java`: rows as maps keyed
  by header. Ported as the always-maps decision above; the header
  collection is fixed on.
- `camel-4.23.0:components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalSkipFirstLineSpringTest.java`: the header
  record is consumed, not data. Ported as the `header: true` default.

Excluded, with the reason:

- `CsvDataFormatTest#shouldUseFormatFromConstructor`, `#shouldUseSpecifiedFormat`, `#shouldResolveFormatByName`, `#shouldResolveFormatByNameCaseInsensitive`: the `format` option is dropped, so no second reference format resolves.
- `CsvMarshal*Test`, `CsvMarshalHeader*Test`, `CsvMarshalPipeDelimiter*Test`, `CsvMarshalAutogenColumns*Test`, `CsvMarshalCharsetTest`, `CsvRoute*Test`: marshalling tests; the decoder never writes CSV.
- `CsvUnmarshalStreamTest`, `CsvUnmarshalStreamSpringTest`, `CsvUnmarshalTwoCsvDataFormatConcurrentTest`: streaming and concurrency shapes the one-bounded-page reader replaces.
- `CsvDataFormatCustomFactoryTest`, `CsvDataFormatCustomRecordConverterTest`, `CsvDataFormatResourceFactoryTest`, `CsvRecordConvertersTest`, `MyCsvDataFormatFactory`: registry and converter extension points the engine does not carry.
- `CsvUnmarshalTest`, `CsvUnmarshalPipeDelimiterSpringTest`, `CsvUnmarshalSkipFirstLineSpringTest` body assertions beyond the option defaults: list-shaped rows (`useMaps` false) that the always-maps decision replaces; the map-shaped cousins are ported above.
- `component/`, `converter/`, `main/` helpers: harness fixtures, no format contract.

The remaining ingestion rows (`file`, `sftp`, SQL, `pollEnrich`) carry
their option models in the route and pack types this stream added; their
conformance modules are the later stream's work named by the port table
(CONCEPT 8.10, Inc 4 rows).

## Additions and divergences recorded elsewhere

- The decoder selection sits on the `pollEnrich` step, so one declaration
  reads the same for a local `file:` and an `sftp:` drop (section 17.1);
  the port table row's "selected on a file or sftp endpoint" is realized
  through the step that reads the endpoint.
- `ItemPage` and its fault codes are additions under section 17.2, not
  ports; the job profile bounds are additions under section 17.2 and D39.
- `postgres:` sends carry named parameters under the existing send
  parameter shape, wire key `queryParameters`, bounded at sixteen
  (`adapter.job.postgres-parameters-unbounded`); the HTTP request members
  refuse on a postgres send under the existing send-shape code
  `adapter.route.graphql-send-members`, whose message this stream
  generalized to cover both components.
