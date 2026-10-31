# ENGINE stream port record: the file source, the read step, and the decoders

Stream: ENGINE (this directory). Branch: `feat/adapter-components`.
Upstream pin: camel-4.23.0, commit `b2329103df8f5d1edfca2ad262be09e3be95ee68`
(clone read at `/Volumes/CodexWorktrees/agent-scratch/camel-src/camel-4.23.0`).

Everything here is a port record, not a claim: CONCEPT 17.7 holds each
row to its acceptance case before anything is claimed.

## What landed

- Feature gates `job-file` and `job-postgres` on `registry-adapter`,
  both off by default; the facade binary compiles neither.
- The runtime config's engine-side `sources` block
  (`crates/registry-adapter/src/job_sources.rs`), the file source
  (`src/component/file.rs`), the decoders (`src/decoder.rs`), the
  `pollEnrich` processor (`src/processor/poll_enrich.rs`), and their
  conformance suites (`tests/camel_file.rs`, `tests/camel_csv.rs`,
  `tests/camel_jsonl.rs`, plus the decoder unit tests in
  `src/decoder.rs`).

## Recorded simplification: one file per read

Camel's file consumer polls many files into one batch. The job read
processes at most ONE file per `pollEnrich` step, and the cursor
(`{digest, position, resumeAfter}`) names the file, the byte offset
after the last emitted row, and the file to resume after. The next read
resumes the named file at its offset while its bytes still carry the
pinned digest, passes it once consumed, re-reads a replaced file from
zero under its new digest, and otherwise starts at the first candidate
after the resume name. A bounded page therefore never needs the
remaining file names inside the cursor; the directory listing is the
remaining state, and it is re-derived per read.

## The noop divergence (recorded case)

camel-file's `noop` strategy implies `idempotent`
(camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/component/file/FileConsumeNoopIdempotentAutoTest.java):
a consumed file is not re-emitted. WE DIVERGE: the read never suppresses
re-reads; the item table owns identity, and a second read of unchanged
content returns the same items under the same namespace-plus-digest key.
The asserting case is
`tests/camel_file.rs::the_noop_divergence_re_reads_a_consumed_file`.
Consequences upstream: `preMove` and `moveFailed` are refused too (they
write the source), so nothing in the read can move a file out of the
scan.

## The doneFileName spelling (recorded divergence)

The runtime loader substitutes every `${...}` in a runtime value, so the
runtime config cannot carry the `${file:name}` spelling; the port reads
Camel's equivalent `$simple{file:name}` spelling
(camel-4.23.0:components/camel-file/src/main/java/org/apache/camel/component/file/GenericFileEndpoint.java,
`createDoneFileName` resolves both identically) beside the literal form.
`${file:name.noext}` is not ported; any other `${` refuses as an
unresolved placeholder.

## maxMessagesPerPoll default (recorded divergence)

camel-file's field default is 0, no limit
(camel-4.23.0:components/camel-file/src/main/java/org/apache/camel/component/file/GenericFileEndpoint.java,
`protected int maxMessagesPerPoll;`). A bounded read cannot port "no
limit"; the port's default is 500, applied to the candidates one read
considers, and the profile's rows bound caps the emitted rows beneath
it.

## Ported upstream test cases

Every adapted case names the upstream class and method at the tag.

| Upstream case (camel-4.23.0, core/camel-core/src/test/java/org/apache/camel/component/file/) | Our case |
|---|---|
| FileConsumeMaxMessagesPerPollTest | tests/camel_file.rs::max_messages_per_poll_bounds_the_candidates |
| FileConsumeNoopTest (noop re-read semantics, inverted by the recorded divergence) | tests/camel_file.rs::the_noop_divergence_re_reads_a_consumed_file |
| AntPathMatcherGenericFileFilterTest | tests/camel_file.rs::the_include_glob_selects_candidates; unit tests in src/component/file.rs |
| FileConsumeDoneFileIssueTest | tests/camel_file.rs::the_done_file_forms_gate_candidates |
| FileChangedReadLockTest, FileChangedReadLockTimeoutTest | tests/camel_file.rs::the_changed_read_lock_paces_a_stable_file, the_compile_holds_the_read_lock_bounds |
| FileChangedZeroLengthReadLockTest (minLength 1: a zero-length file never locks) | the changed lock requires length >= 1; unit-asserted in the lock implementation's guard |
| FileConsumerJailStartingDirectorySymlinkTest (escape refused) | tests/camel_file.rs::a_symlink_escape_refuses_the_read |
| FileConsumeSingleDirectoryOnlyTest (non-recursive) | tests/camel_file.rs::a_nested_directory_holds_no_candidates |
| FileConsumerExcludeExtTest/IncludeExtTest (filter refusals) | the include glob + oversize refusals, tests/camel_file.rs::an_oversized_file_refuses_whole |

CSV decoder cases (camel-4.23.0, components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/):

| Upstream case | Our case |
|---|---|
| CsvUnmarshalPipeDelimiterTest | tests/camel_csv.rs::the_pipe_delimiter_reads_maps |
| CsvUnmarshalTest::testCsvUnMarshalMultiLine | tests/camel_csv.rs::a_quoted_multiline_field_decodes_whole |
| CsvUnmarshalCommentMarkerSpringTest | tests/camel_csv.rs::a_comment_marker_line_is_not_a_record |
| CsvUnmarshalSkipFirstLineSpringTest | tests/camel_csv.rs::the_header_disabled_decoder_reads_arrays |
| CsvMarshalHeaderTest (header record on by default) | tests/camel_csv.rs::the_bare_csv_name_reads_at_the_defaults |
| CsvDataFormatTest (option wiring) | unit tests in src/decoder.rs and the landed `CsvDecoder` defaults in registry-adapter-core |

The JSONL decoder is an addition under CONCEPT 5.4 (no upstream exists);
tests/camel_jsonl.rs is its suite, marked as an addition.

## Recorded as inapplicable, with the reason

The upstream file consumer's test suite holds 247 classes under
core/camel-core/src/test/java/org/apache/camel/component/file/ plus 19
under file/strategy/. They group as follows; every group is recorded,
not silently dropped.

1. Source writes (delete, move, preMove, moveFailed, rename strategies,
   commit/begin strategies, marker files, `GenericFileDeleteProcessStrategy*`,
   `FileConsume*Delete*`, `FileConsumer*Move*`, `File*KeepLastModified`,
   `FileEagerDeleteTargetFile*`): the read is read-only always; each
   option writes, renames, or deletes the source, so the behaviors the
   classes assert have no ported counterpart.
2. Idempotent repositories (`FileConsumerIdempotent*`,
   `FileIdempotent*ReadLock*`, `FileConsumeNoopIdempotent*`): identity
   is the item table's; the engine keeps no idempotent repository, and
   the noop divergence above records the behavioral difference.
3. Consumer lifecycle (suspend/resume, poll strategies, batch consumer,
   templates, `ConsumerTemplate*`, bridge error handler, custom
   schedulers, backoff, starting-directory probes): the job trigger
   owns the cadence (the landed trigger block ports the scheduler
   options); the read step runs one bounded read per call and has no
   consumer to suspend.
4. Strategy classes under file/strategy/ other than the changed lock
   (fileLock, markerFile, rename, idempotent-rename,
   idempotent-changed): each writes or locks the source; the changed
   lock is ported and its cases are listed above.
5. Header/property exposure (`FileHeaderFileNameProducedTest`,
   `FileConsumeAlterFileNameHeaderIssueTest`, exchange properties the
   consumer sets): the read emits the item contract page; no
   `CamelFile*` headers are ported, because a route reads its page from
   the body under CONCEPT 17.2.
6. Charset conversions (`FileConsumeCharsetTest`,
   `FileConvertBodyToUTF8Test`): the decoders read UTF-8 only; the
   encoding is a closed constant, so a charset option cannot exist.
7. Ordering and filtering breadth (`FileConsumer*Filter*`,
   include/exclude name and ext pairs): the port keeps one Ant-style
   `include` and the `sortBy` name-ascending default; the exclude pair
   and the expression sorters are not ported, and the filter classes
   reduce to the glob case above.
8. Resume strategies (`FileConsumerResume*`), dynamic done-file forms
   with two dots, `$simple{...}` beyond the file-name placeholder,
   absolute/relative path juggling, root-directory specials: each rides
   a capability the bounded read does not carry (no per-file state
   beside the cursor, no dynamic expressions, the directory is fixed
   and canonical in the runtime config).

## Core additions this stream needs (for the core stream)

- `AdapterRuntimeConfig` may eventually carry the `sources` block
  itself (today the engine reads it through its own strict wrapper in
  `src/job_sources.rs`, which keeps the core reader's unknown-key
  refusal and strips only `sources`, `apiVersion`, and `kind`); moving
  it into core would delete the engine wrapper and extend the runtime
  schema to operators' editors.
- `check_runtime`'s endpoint-coverage rule (one binding per pack
  endpoint) has no shape for a file/sftp/postgres source; the job
  compile filters the coverage finding when every unbound endpoint is a
  job source and replaces it with its own source-coverage rule under
  `adapter.job.source-unbound`. A core `sources`-aware coverage rule
  would retire the filter.


## done-file match on both static sides (recorded divergence)

Camel's `isDoneFile` matches the pattern's static text as a prefix when
the placeholder is not at the start, else as a suffix, never both
(camel-4.23.0:components/camel-file/src/main/java/org/apache/camel/component/file/GenericFileEndpoint.java,
`isDoneFile`). The port matches prefix and suffix together, so a
pattern with static text on both sides (`done-${file:name}.ok`)
recognizes the done file its own `createDoneFileName` spelling
produces; Camel's prefix-only match does not.

## The redelivery delay cap is always on (recorded divergence)

Camel's `maximumRedeliveryDelay` of zero disables the delay cap
(camel-4.23.0:core/camel-core-processor/src/main/java/org/apache/camel/processor/errorhandler/RedeliveryPolicy.java,
`calculateRedeliveryDelay`). The bounded model carries the cap as a
positive bound with a 60-second default and cannot express "no cap";
the same situation as `maxMessagesPerPoll` above.

## The breaker's node key (follow-up, not ported)

The resilience state keys breaker and throttle nodes by the address of
the served step (`std::ptr::from_ref(step)`), an identity that holds
under the documented invariant that the compiled step tree is never
moved or rebuilt after compile. A structural key, a step index vector
produced by the same walk the interpreter uses, would keep the
identity by construction under any future restructuring; noted here
for the pass that next touches resilience.
