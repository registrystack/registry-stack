# Camel ingestion port records

Status: current implementation record; Increment 4 remains pending.

This record maps the implemented ingestion subset to Apache Camel tests and documents the
Adapter-specific restrictions that a Camel reader would not predict.
The normative product contract remains the port table in `CONCEPT.md` section 8.10.
Recording a Rust test here or in `check-port-table.py` establishes that the named test exists.
It does not establish Increment 4 acceptance or the controlled deployment drill in `CONCEPT.md`
section 17.7.

The upstream reference is Apache Camel tag
[`camel-4.23.0`](https://github.com/apache/camel/tree/camel-4.23.0), commit
`b2329103df8f5d1edfca2ad262be09e3be95ee68`.
The readable Camel `next` manuals are useful orientation, but the manual source and Java tests at
that tag decide this record when the current site differs.

## File job source

The Adapter file source is a non-recursive, read-only job source.
It supports a flat `include` glob, optional `doneFileName`, `readLock` values `none` and `changed`,
and `maxMessagesPerPoll`.
It always sorts candidates by filename in ascending order.
There is no authored `sortBy` expression.

`readLock` defaults to `none`.
For `changed`, `readLockTimeoutMilliseconds` defaults to `10000`, and
`readLockCheckIntervalMilliseconds` defaults to `1000`.
The Adapter requires each bound to remain inside its declared finite range.
`maxMessagesPerPoll` defaults to `500`, where Camel's value `0` means unbounded.
The job profile applies its own row and byte bounds as well.

The source is always `noop` in the literal sense that it does not delete, move, rename, mark, or
lock source files.
This differs from Camel's `noop=true` consumer behavior: the Adapter re-reads unchanged bytes and
relies on the job item table to suppress another delivery. Raw files use
namespace-plus-content identity; decoded rows use their declared business key.
The fixed source directory, flat names, no-follow open, and symlink checks restrict traversal.
The checks do not turn the file client into an atomic operating-system jail.

Camel's [file manual](https://camel.apache.org/components/next/file-component.html) is the readable
reference.
The pinned source is the
[`file-component.adoc` manual](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-file/src/main/docs/file-component.adoc).

| Camel class and method | Rust test | Relationship |
| --- | --- | --- |
| [`FileConsumerNoopTest.testNoop`](https://github.com/apache/camel/blob/camel-4.23.0/core/camel-core/src/test/java/org/apache/camel/component/file/FileConsumerNoopTest.java) | `camel_file.rs::the_noop_divergence_re_reads_a_consumed_file` | Deliberate identity divergence |
| [`FileSortByExpressionTest.testSortFiles`](https://github.com/apache/camel/blob/camel-4.23.0/core/camel-core/src/test/java/org/apache/camel/component/file/FileSortByExpressionTest.java) | `camel_file.rs::a_raw_read_orders_the_files_and_ends_the_scan` | Restricted to fixed ascending `file:name` order |
| [`FilerConsumerDoneFileNameTest.testDoneFile`](https://github.com/apache/camel/blob/camel-4.23.0/core/camel-core/src/test/java/org/apache/camel/component/file/FilerConsumerDoneFileNameTest.java) | `camel_file.rs::the_done_file_forms_gate_candidates` | Literal or one `file:name` placeholder only |
| [`FileChangedReadLockTest.testChangedReadLock`](https://github.com/apache/camel/blob/camel-4.23.0/core/camel-core/src/test/java/org/apache/camel/component/file/strategy/FileChangedReadLockTest.java) | `camel_file.rs::the_changed_read_lock_paces_a_stable_file` | Bounded `changed` lock adaptation |
| [`FileConsumeMaxMessagesPerPollTest.testMaxMessagesPerPoll`](https://github.com/apache/camel/blob/camel-4.23.0/core/camel-core/src/test/java/org/apache/camel/component/file/FileConsumeMaxMessagesPerPollTest.java) | `camel_file.rs::max_messages_per_poll_bounds_the_candidates` | Finite default and job-profile cap |
| [`FileConsumerJailStartingDirectorySymlinkTest.fileLinkToOutsideIsSkippedAndReportedOnce`](https://github.com/apache/camel/blob/camel-4.23.0/core/camel-core/src/test/java/org/apache/camel/component/file/FileConsumerJailStartingDirectorySymlinkTest.java) | `camel_file.rs::a_symlink_escape_refuses_the_read` | Security divergence: refuse rather than skip |

`check-port-table.py` also records these existing file tests as evidence for the pending row.
The current mapping intentionally does not claim every supported option has an upstream-method
citation in its Rust doc comment.

## CSV decoder

The CSV decoder is selected on a file or SFTP endpoint, not through Camel's `unmarshal` step.
Its defaults are a comma delimiter, double-quote quoting enabled, a header record, no comment
marker, no trimming, and UTF-8.
`delimiter`, `quote`, and `commentMarker` each accept one ASCII character.
With headers enabled, rows are maps of strings.
With `header: false`, rows are arrays of strings.
The decoder performs no type inference, so `007` stays `"007"`.

Paging and row bounds are Adapter additions.
The source cursor binds the file content digest and byte position.
A malformed CSV record fails the read closed, leaves the cursor unchanged, and is encountered
again after repair or replacement of the source file.
The CSV row in `CONCEPT.md` section 8.10 requires deterministic per-record reporting.
It does not require continuation after a bad record.
The decoder identifies the zero-based record ordinal, including the header.
File and SFTP route failures retain that typed location through the job page failure.
The pass reports `record: {ordinal}` beside its closed code and retains the same location in
its value-free stop reason. It returns no partial page and does not advance the cursor.
There is no error variant in the closed `SourceItem` wire shape.

CSV and JSONL require one declared `keyPointer` selecting a non-empty string business key.
The identity combines a versioned, length-delimited namespace with that exact key, preserving
leading zeros; it does not include file digest or position. Reordering unchanged rows therefore
retains their keys, and changing a row with the same key uses the job's revised-item rule.
Whole-file prevalidation refuses a duplicate business key before any page escapes, including a
duplicate beyond the current page. Existing row and field bounds apply during prevalidation.
Changing the identity contract requires operator reconciliation of prior effects; the store must
not silently adopt a new selector over nonempty legacy state.

Camel's [CSV manual](https://camel.apache.org/components/next/dataformats/csv-dataformat.html) is the
readable reference.
The pinned source is the
[`csv-dataformat.adoc` manual](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-csv/src/main/docs/csv-dataformat.adoc).

| Camel class and method | Rust test | Relationship |
| --- | --- | --- |
| [`CsvUnmarshalPipeDelimiterTest.testCsvUnMarshal`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalPipeDelimiterTest.java) | `camel_csv.rs::the_pipe_delimiter_reads_maps` | Ported delimiter, strings retained |
| [`CsvDataFormatTest.shouldOverrideQuote`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvDataFormatTest.java) | `camel_csv.rs::a_quoted_multiline_field_decodes_whole` | Quote option plus Adapter multiline boundary |
| [`CsvUnmarshalCommentMarkerSpringTest.testCsvUnmarshal`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalCommentMarkerSpringTest.java) | `camel_csv.rs::a_comment_marker_line_is_not_a_record` | Ported comment marker |
| [`CsvUnmarshalSkipFirstLineSpringTest.testCsvUnMarshal`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalSkipFirstLineSpringTest.java) | `camel_csv.rs::the_header_disabled_decoder_reads_arrays` | Complement adapted as `header: false` |
| [`CsvUnmarshalTest.shouldUseLazyLoading`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalTest.java) | `camel_file.rs::an_oversized_csv_row_refuses_the_read` | Bounded-page addition, not Camel streaming |

No `CsvUnmarshalTest.testCsvUnMarshalMultiLine` method exists at the pinned tag.
The quote-option test is the upstream source for the option, while the multiline decoding case is an
Adapter boundary test.
`decoder.rs::csv_defaults_decode_deterministic_rows` separately establishes that a short record
uses an empty string for the missing trailing field, not JSON `null`.

## JSONL decoder

The JSON Lines (JSONL) decoder is an Adapter addition.
Camel 4.23.0 has no corresponding JSONL data format or Java conformance method for this row.
The decoder accepts one bounded JSON value per line, counts and skips a malformed line, retains the
line ordinal for diagnostics, uses a declared business key for item identity, pages at the job row
bound, and refuses an oversized line.

The evidence is entirely Adapter-owned:

- `camel_jsonl.rs::a_malformed_line_continues_with_a_count`
- `camel_jsonl.rs::jsonl_pages_at_the_rows_bound`
- `camel_jsonl.rs::an_oversized_line_refuses_the_read`

## Read-only PostgreSQL source

The PostgreSQL source accepts one digest-pinned, plain `SELECT` with a root `ORDER BY`.
It does not accept dynamic SQL, multiple statements, utility commands, a data-changing common table
expression, or a query with more than 16 positional parameters.
`parameterOrder` gives each contiguous `$1`-onward position a reviewed name.
Runtime values bind as text, checked integers, double-precision numbers, or booleans.

Every page runs in its own read-only, read-committed transaction with a local statement timeout and
bounded rows, row bytes, field bytes, and response bytes.
Root ordering makes one statement deterministic, but it does not make several offset pages one
snapshot.
An editable source therefore still needs an immutable snapshot, monotonic cursor, or bounded rescan
discipline.

Camel's [SQL manual](https://camel.apache.org/components/next/sql-component.html) is the readable
reference.
The pinned source is the
[`sql-component.adoc` manual](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-sql/src/main/docs/sql-component.adoc).

| Camel class and method | Rust test | Relationship |
| --- | --- | --- |
| [`SqlProducerNamedParametersTest.testNamedParametersFromBody`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-sql/src/test/java/org/apache/camel/component/sql/SqlProducerNamedParametersTest.java) | `camel_sql.rs::the_query_compile_refuses_everything_but_one_plain_select`, `postgres_source_host.rs::actual_named_parameters_bind_text_integer_float_and_boolean_values` | Hardened, reviewed parameters |
| [`SqlProducerOutputTypeSelectListTest.testOutputType`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-sql/src/test/java/org/apache/camel/component/sql/SqlProducerOutputTypeSelectListTest.java) | `camel_sql.rs::a_send_over_the_seam_pages_and_shapes_rows` | Bounded object rows |
| [`SqlConsumerFetchSizeTest.testConsume`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-sql/src/test/java/org/apache/camel/component/sql/SqlConsumerFetchSizeTest.java) | `camel_sql.rs::a_real_fetch_bounds_its_rows_and_statement` | Profile row bound and statement timeout |
| [`SqlTransactedRouteTest.testCommit`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-sql/src/test/java/org/apache/camel/component/sql/SqlTransactedRouteTest.java) | `camel_sql.rs::the_read_only_transaction_refuses_a_write` | Security divergence: transaction is always read-only |
| [`ProducerQueryTimeoutTest`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-sql/src/test/java/org/apache/camel/component/sql/stored/ProducerQueryTimeoutTest.java) | `postgres_source.rs::cancelled_read_is_detached_before_same_pool_creates_fresh_backend` | Adapter cancellation hardening |

The mapped plaintext cancellation case and
`postgres_source.rs::tls_cancelled_read_is_detached_before_same_pool_creates_fresh_backend`
exercise both cancellation transports. The TLS case uses the production verified connector and
bounded CA loader, a one-slot pool, a delayed old cancel request, a different replacement backend,
`pg_stat_ssl.ssl = true`, read-only mode, statement timeout, and normal replacement-backend reuse.
`test-postgres-source-tls.sh` owns its TLS-only fixture and runs that exact case behind the
`postgres-tls-test` feature; `test-job-postgres.sh` invokes it even with a caller-supplied database.
This is loopback TLS transport evidence, not production private-network egress acceptance.

## SFTP job source

The SFTP source is implemented at the job-host boundary, not in a facade conformance module.
The gate therefore maps its existing `job:src` and `job:tests` cases.
No facade SFTP reachability is asserted or implied.

The runtime requires a normalized absolute `baseDirectory`, one pinned OpenSSH host key, and a
password or private-key credential through secret references.
The default port is `22`.
An optional flat `include` glob selects candidates.
`maximumListingEntries` defaults to `500` and is bounded at `10000`.
The source exposes no file-source `readLock` option.
Its operation deadline and completion rechecks bound an interrupted read instead.

Exactly one producer completion protocol is required:

- `completed-name` requires `producerAtomicHandover: true`; the producer closes temporary bytes and
  atomically renames them into the final candidate name.
- `done-file` requires a literal or `file:name` marker; the producer removes a stale marker before
  replacement, atomically renames complete bytes into place, and publishes the marker last.

The deployment must give the source a dedicated read-only account whose server-side authorization
confines it to `baseDirectory`.
Client pathname, canonical-path, symlink, and recheck logic is defense in depth.
SFTP v3 provides no portable atomic open-beneath operation, so the client does not establish an
atomic SSH jail.
The selected cipher paths use AWS-LC while key exchange and signatures also use RustCrypto.
This is not a whole-session Federal Information Processing Standards (FIPS) validation claim.

Camel's [SFTP manual](https://camel.apache.org/components/next/sftp-component.html) is the readable
reference.
The pinned source is the
[`sftp-component.adoc` manual](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-ftp/src/main/docs/sftp-component.adoc).

| Camel class and method | Rust test | Relationship |
| --- | --- | --- |
| [`MinaSftpHostKeyVerificationIT.testKnownHostsFromByteArrayWithMismatchFails`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-mina-sftp/src/test/java/org/apache/camel/component/file/remote/mina/integration/MinaSftpHostKeyVerificationIT.java) | `sftp_cli_host.rs::check_refuses_invalid_or_unsupported_host_keys_without_effects`, `sftp_source.rs::incorrect_host_key_does_not_reach_credential_resolution_or_authentication` | Mandatory exact pin before credentials |
| [`SftpSimpleConsumeWithAntIncludeIT.testSftpSimpleConsume`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-ftp/src/test/java/org/apache/camel/component/file/remote/sftp/integration/SftpSimpleConsumeWithAntIncludeIT.java) | `sftp_source.rs::done_file_gates_partial_file_and_completed_file_is_read_only` | Flat candidate selection only |
| [`FtpConsumerDoneFileNameIT.testDoneFileName`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-ftp/src/test/java/org/apache/camel/component/file/remote/integration/FtpConsumerDoneFileNameIT.java) | `sftp_source.rs::done_file_gates_partial_file_and_completed_file_is_read_only` | Required completion protocol |
| [`SftpChangedReadLockIT.testChangedReadLock`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-ftp/src/test/java/org/apache/camel/component/file/remote/sftp/integration/SftpChangedReadLockIT.java) | `sftp_source.rs::stalled_and_oversize_reads_are_bounded` | Deadline and recheck adaptation, no `readLock` option |
| [`FromFtpNoopIT.testNoop`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-ftp/src/test/java/org/apache/camel/component/file/remote/integration/FromFtpNoopIT.java) | `sftp_cli_host.rs::actual_cli_pass_recovers_cursor_and_same_name_replacement` | Read-only, digest-based replacement identity |
| [`MinaSftpSymlinkIT.testCamelConsumerWithRelativeSymlink`](https://github.com/apache/camel/blob/camel-4.23.0/components/camel-mina-sftp/src/test/java/org/apache/camel/component/file/remote/mina/integration/MinaSftpSymlinkIT.java) | `sftp_source.rs::traversal_symlink_and_off_root_candidates_are_refused` | Security divergence: refuse links rather than follow them |

The mapped job tests also cover bounded transfer and same-name replacement.
They do not establish a facade route, an atomic server confinement boundary, or whole-session FIPS
validation.

## Job-only pollEnrich

The Adapter's `pollEnrich` is a job-source read step over a static `file:`, `rabbitmq:`, or `sftp:`
URI.
`timeoutMilliseconds` is mandatory and bounded from `1` to `10000`.
Absent an aggregation strategy, the bounded item page replaces the route body.
The closed aggregation-strategy set may merge the page, but arbitrary processors are not accepted.
Dynamic endpoint expressions, `consumerSendTo`, and streaming are not ported.

The step is refused in every facade-reachable route.
A job read starts without facade request headers and returns the closed ItemPage body plus its source
metadata.
Camel's header-preservation behavior in
`PollEnrichHeaderPropagationTest.testHeadersPreservedAfterPollEnrich` is therefore inapplicable,
not an untested facade promise.

Camel's [Poll Enrich manual](https://camel.apache.org/components/next/eips/pollEnrich-eip.html) is
the readable reference.
The pinned source is the
[`pollEnrich-eip.adoc` manual](https://github.com/apache/camel/blob/camel-4.23.0/core/camel-core-engine/src/main/docs/modules/eips/pages/pollEnrich-eip.adoc).

| Camel class and method | Rust test | Relationship |
| --- | --- | --- |
| [`FileConsumePollEnrichFileTest.testPollEnrich`](https://github.com/apache/camel/blob/camel-4.23.0/core/camel-core/src/test/java/org/apache/camel/component/file/FileConsumePollEnrichFileTest.java) | `checks.rs::poll_steps_check_their_uri_timeout_and_decoder`, `camel_file.rs::a_raw_read_orders_the_files_and_ends_the_scan` | Static URI and mandatory bounded timeout |
| [`FileConsumePollEnrichFileUsingProcessorTest.testPollEnrich`](https://github.com/apache/camel/blob/camel-4.23.0/core/camel-core/src/test/java/org/apache/camel/component/file/FileConsumePollEnrichFileUsingProcessorTest.java) | `camel_csv.rs::the_read_aggregates_like_an_enrich` | Closed aggregation strategy only |
| [`PollEnrichHeaderPropagationTest.testHeadersPreservedAfterPollEnrich`](https://github.com/apache/camel/blob/camel-4.23.0/core/camel-core/src/test/java/org/apache/camel/component/file/PollEnrichHeaderPropagationTest.java) | No Rust counterpart by design | Inapplicable to the closed job read exchange |
| n/a, Adapter trust boundary | `adapter_job.rs::the_default_build_refuses_a_file_job` | Facade and default-build isolation |

## Evidence and acceptance limits

The port-table gate records 30 existing Rust test references across the six rows in this record.
`INCREMENT_DELIVERED` remains `1`, so the file, CSV, JSONL, PostgreSQL, SFTP, and job-only
`pollEnrich` rows stay pending.
The mappings do not promote Increment 4, the GraphQL row, the controlled deployment drill, or full
ingestion acceptance.
They also do not convert plaintext PostgreSQL cancellation evidence into TLS evidence or job-host
SFTP tests into facade reachability.
