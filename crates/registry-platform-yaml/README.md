# registry-platform-yaml

The shared Registry Stack configuration reader. Every configuration file a
person or an agent writes, YAML or JSON, is read here: one YAML subset, one
scalar table, one envelope check, and typed decoding whose diagnostics name
the file, the line and column, the JSON pointer, what is wrong, and the fix.
The rules it enforces are `products/platform/CONFIG-CONVENTIONS.md`; the rule
IDs below (`CFG-...`) refer to that document.

## Trust boundary

The reader treats its input as untrusted text and its diagnostics as output
that may reach a terminal, a CI log, or an agent's context:

- the input is bounded before parsing: 1 MiB (`yaml.too-large`) and 128
  levels of nesting (`yaml.too-deep`), with no stack growth proportional to
  the input;
- anchors, aliases, merge keys, tags, several documents, and non-string keys
  are refused, so a document is a plain tree and an alias cannot expand it;
- a diagnostic never repeats a scalar value from the file or the
  environment (CFG-SEC-3). Messages name keys, paths, accepted values,
  bounds, and the expected envelope. A message a type's own `Deserialize`
  code writes is never passed through, and keys and file names are escaped
  of control characters in human output. Human output also shortens a path
  longer than 120 characters to its first and last 60, joined by `...`;
  JSON output carries the whole path;
- the `Debug` output of a `Text`, and so of a `Node`, `Document`, or
  `Decoded` document, shows `<redacted>` for every text value, since a
  substituted value may be a secret. Keys and spans still show. A product's
  own decoded types print what their own `Debug` prints.

The reader does not open files, read the environment, or resolve secrets.
The caller passes bytes and the file name diagnostics should carry. Runtime
`${NAME}` substitution is a [`ScalarHook`](#hooks) that
`registry-platform-config` supplies; authored formats refuse substitution
through the same hook.

## Use

```rust
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};

const FORMAT: FormatSpec = FormatSpec {
    kind: "ExampleRuntime",
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current("example.registrystack.org/v1")],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

let decoded = Reader::new("runtime.yaml").decode::<Runtime>(bytes, &Expect::one(&FORMAT))?;
```

The public surface:

| Item | Purpose |
|---|---|
| `Reader::new(file)`, `.with_hook(&mut hook)` | One read of one file. `file` is reported as given. |
| `Reader::scan(bytes) -> Result<Option<Node>, Report>` | The YAML subset only, no envelope. `None` for an empty or comment-only stream. |
| `Reader::read(bytes, &Expect) -> Result<Document, Report>` | The tree, the matched envelope, and no removed key. |
| `Reader::decode::<T>(bytes, &Expect) -> Result<Decoded<T>, Report>` | `read`, then typed decoding. |
| `read_document`, `decode_document` | The same, without a hook. |
| `Document::decode::<T>()`, `decode_at::<T>(pointer)` | Decode the whole document or one member, with paths from the root. |
| `Document::span_of(pointer)`, `key_span_of(pointer)` | Positions for a product's own semantic checks. |
| `Document::diagnostic_at_value(..)`, `diagnostic_at_key(..)` | A product diagnostic placed by pointer. |
| `Document::to_json_value()` | The checked tree as JSON, for pointer-based checks and digests. |
| `FormatSpec`, `EnvelopeRule`, `ApiVersion`, `RetiredApiVersion`, `RemovedKey`, `Expect` | What a read accepts. `Expect::new` takes several formats for a command that dispatches on `kind`. |
| `Diagnostic`, `Report`, `Severity`, `Source`, `Related` | The one diagnostic shape (CFG-DIAG-1), JSON and human rendering. |
| `CODES` | Every reader code and its meaning. |
| `ScalarHook`, `ScalarSite`, `Refusal` | Inspect or replace scalars while the tree is built. |
| `Invalid`, `Invalid::into_error()` | What a checking type returns: the expectation and the fix, never the value. `into_error()` turns it into any deserializer's error. |
| `LocalId`, `ExternalId`, `Digest`, `Url`, `ProjectIdentity`, `DataLiteral` | Shared value types (CFG-ID, CFG-VAL). |
| `BoundedU32<MIN, MAX>`, `BoundedU64<MIN, MAX>` | Integers with both bounds in the type and the schema (CFG-QTY-4). |
| `UniqueList<T>`, `UniqueIdList<T>` with `Identified` | A set (`config.duplicate-item`) and a list of named items (`config.duplicate-id`) (CFG-ID-5, CFG-ID-6). |
| `tagged_union!`, `shape_union!`, `SHARED_BLOCK_PREFIX` | The serde recipes below. |
| `MAXIMUM_DOCUMENT_BYTES`, `MAXIMUM_DEPTH`, `MAXIMUM_DIAGNOSTICS_PER_FILE`, `MAXIMUM_EXTERNAL_ID_CHARS`, `MAXIMUM_URL_CHARS` | The bounds. |

The `schema` feature derives `JsonSchema` for the shared types, with the
same bounds, patterns, and closedness the reader enforces.

There is no path type: a file name is text the caller chose, and a pointer
is a `&str` in RFC 6901 form. There is no directory helper: a command that
reads a directory lists `.yaml` and `.yml` files itself and reads each one.

## Diagnostics

A `Report` holds every diagnostic of one read, sorted by position.
`Report::to_json_value()` gives the JSON array a ctl puts in its report
envelope:

```json
{"severity": "error", "code": "config.expected-integer", "artifact": "MessagingRuntimeConfig",
 "path": "/audit/retentionDays", "message": "expected a whole number of days from 1 to 36500; quoted values are text",
 "suggestedAction": "Remove the quotes.", "source": {"file": "runtime.yaml", "line": 6, "column": 18}}
```

`Report::render_human()` gives the form a terminal shows: the position first,
the message, the fix, a `note:` line per related place, and a summary line.

```text
error[yaml.duplicate-key] runtime.yaml:7:1 /listener
  the key is already defined in this mapping
  next: Keep one definition of the key.
  note: runtime.yaml:3:1 /listener the first definition
1 error, 0 warnings in 1 file
```

Severities are `error` and `warning`. A deprecated `apiVersion` is the only
warning the reader emits.

Positions (CFG-DIAG-1): a key problem points at the key; a value problem at
the value's first character; a missing member at the key of the mapping that
lacks it (1:1 for the top level); an empty value at its key, or at the `-`
of its list item.

A `yaml.syntax` error inside a `[` or `{` that is still open names the
bracket and the line it was opened on, since a missing `]` or `}` is the
usual cause. A tab after `:` before an unquoted value is named at the tab:
the parser reads a tab there as separation only before a quoted or
bracketed value.

What a read reports together (CFG-DIAG-5): every structural problem (YAML
subset, duplicate keys, ambiguous numbers, hook refusals) and every envelope
problem, without decoding. When the structure is sound, decoding reports
every removed key, every unknown key it reaches, and the first other error,
then checks the rest of the mapping it stopped in for unknown keys. A size,
encoding, or syntax error stops the read alone.

### Codes

Reader codes have two segments; product codes have three.

| Code | Meaning |
|---|---|
| `yaml.too-large` | the document is larger than 1 MiB |
| `yaml.not-utf8` | the document is not UTF-8 |
| `yaml.syntax` | the YAML is not well formed and no narrower code applies |
| `yaml.tab-indentation` | a tab is used for indentation |
| `yaml.unclosed-quote` | a quoted value is not closed, or its continuation is not indented |
| `yaml.invalid-escape` | a backslash in a double-quoted value starts an escape sequence YAML does not define |
| `yaml.text-after-quote` | text follows the closing quote of a quoted value |
| `yaml.colon-in-plain-value` | a `: ` inside an unquoted value starts a mapping |
| `yaml.unexpected-end` | the document ends inside an unfinished construct |
| `yaml.duplicate-key` | a mapping holds the same key twice |
| `yaml.anchor` | an anchor (`&name`) is used |
| `yaml.alias` | an alias (`*name`) is used |
| `yaml.merge-key` | a merge key (`<<`) is used |
| `yaml.tag` | an explicit tag (`!!str`, `!custom`) is used |
| `yaml.non-string-key` | a mapping key is not a string |
| `yaml.multiple-documents` | the file holds more than one document |
| `yaml.ambiguous-number` | an unquoted value looks like a number but is not a plain decimal |
| `yaml.too-deep` | the document nests deeper than 128 levels |
| `config.missing-envelope` | the document is empty, or its top-level mapping lacks apiVersion or kind |
| `config.wrong-kind` | kind is not one the reader accepts |
| `config.unsupported-api-version` | apiVersion is not one the reader accepts for this kind |
| `config.retired-api-version` | apiVersion is retired |
| `config.deprecated-api-version` | apiVersion is deprecated (warning) |
| `config.removed-key` | a key was removed or renamed |
| `config.unknown-key` | a key is not a member of its mapping |
| `config.missing-key` | a required member is absent |
| `config.unknown-variant` | a value is not one of the accepted names |
| `config.invalid-type` | a value has the wrong shape, or a union holds a form it does not accept |
| `config.invalid-value` | a value has the right shape but is not valid |
| `config.invalid-length` | a list has the wrong number of items |
| `config.duplicate-key` | a member is given twice, under two spellings the type accepts |
| `config.duplicate-item` | a list that is a set repeats an item |
| `config.duplicate-id` | a list of named items repeats an id |
| `config.null-value` | a member is null |
| `config.expected-string` | a text member holds something other than text |
| `config.expected-integer` | an integer member holds something other than an integer |
| `config.expected-number` | a number member holds something other than a number |
| `config.expected-boolean` | a boolean member holds something other than true or false |
| `config.out-of-range` | a number is outside its bounds |
| `config.substitution` | a `${...}` expression cannot be filled: it is not well formed, its variable is unset or empty, `${NAME:?message}` refused, or the value holds a NUL byte (reported by a substitution hook) |
| `config.substitution-not-allowed` | a `${...}` expression is written where substitution is not allowed, or an envelope member was substituted |
| `config.too-many-problems` | the file has more problems than the reader shows; this last diagnostic counts the rest |

A test fails when a code in the source is missing from this table or the
table holds a code with other than two kebab-case segments.

A report holds at most `MAXIMUM_DIAGNOSTICS_PER_FILE` (100) diagnostics for
one file, the first ones by position, then one `config.too-many-problems`
diagnostic counting the rest ("50 more problems in this file are not
shown"). It is an error when any problem it counts is one.

## The subset and the scalar table

The reader accepts YAML 1.2 block and flow content, so JSON is read by the
same code (CFG-YAML-1). A leading byte order mark is ignored; LF and CRLF are
read with the same positions; a leading `---` and a final `...` are accepted.
An empty or comment-only file is `config.missing-envelope`.

Plain scalars resolve through one table (CFG-VAL-1), documented in
`src/scalar.rs`:

- `true` and `false` (also `True`, `TRUE`, `False`, `FALSE`) are booleans;
  `yes`, `no`, `on`, and `off` are text;
- a decimal integer is an integer, and with a fraction or an exponent
  (`1.5`, `1e3`) a number; `-0` reads as 0;
- `~`, `null` (in three casings), and an empty value are null, which only
  `DataLiteral` accepts (CFG-EMPTY-1); an optional member is written by
  leaving the key out;
- a leading zero (`0123`), a bare point (`.5`, `5.`), a base prefix
  (`0x1F`, `0o17`, `0b101`), and `.inf` or `.nan` are refused as
  `yaml.ambiguous-number`;
- everything else, including `1_000` and `09:00`, is text.

Quoted and block scalars are always text. Text in an integer, number, or
boolean position is refused, and the message says why (CFG-DIAG-6): a
quoted number gets "Remove the quotes.", a unit suffix (`5s`) gets "Write
the number of seconds as digits." with the member's own unit, `1_000` and
`1e6` in an integer position get "Write digits only.", and `yes` in a
boolean position says that `yes`, `no`, `on`, and `off` are text.

An unquoted integer outside `i64::MIN..=u64::MAX`, or a number past
binary64, is refused by the member that reads it: a text member says to
quote it (`config.expected-string`), an integer member states its bounds,
and anywhere else, including under an unknown key, it is
`config.out-of-range` for the reader's range. Such a number fails the read
as a structural problem does, so the decode's other problems are not
reported with it. `Reader::scan` and `Reader::read`, which know no member
types, refuse it as out of the reader's range.

A whole number's message states both bounds (CFG-QTY-4): the ones a format
declares, or else its type's extremes. A `BoundedU32<1, 36500>` member named
`retentionDays` reads "a whole number of days from 1 to 36500", and a `u16`
member "a whole number from 0 to 65535".

When an unquoted value holding a `#` with no space before it is refused, as
`port: 8080#main` is, the fix adds "A `#` starts a comment only after a space: put a space
before the `#` that starts the comment." The sentence names no part of the
value (CFG-SEC-3) and is not added for a value a `ScalarHook` substituted.

Every struct refuses unknown keys, whatever its serde attributes say; the
action suggests the closest accepted key when one is within two edits (one
for keys of four characters or fewer), and otherwise lists the accepted keys.
A mapping lists them once, at its first such unknown key; a later one says
"the accepted keys are listed at line N". A top-level `x-` key is unknown,
with the fix "extension fields are not supported; use a comment".
An unknown variant gets the same closest-name rule: its fix names the
accepted value that differs only in letter case ("Use `strict`; letter case
matters.") or is within the same edit distance, and otherwise lists the
accepted values. No hint is given for a value a `ScalarHook` substituted.

## Serde recipes

The decoder is its own `serde::Deserializer` over the checked tree. Most
derives work unchanged; three serde features buffer a mapping through
serde's private content type and lose positions and closedness, so the crate
ships a replacement for each (CFG-SCHEMA-8).

- **Shared blocks instead of `#[serde(flatten)]`.** Mark the field with
  `#[serde(rename(deserialize = "registry-platform-yaml/shared-block/<name>"))]`
  (and `#[schemars(flatten)]` for the schema). The block's members sit
  beside the host's, keep their positions, and an unknown key names every
  accepted key. `#[serde(flatten)]` still decodes, but serde places every
  error inside the block at the host mapping, reports only its first
  unknown key, and reports none at all unless the host has
  `deny_unknown_fields`: an unknown key under a flattened host without it is
  silently dropped, where the reader cannot see it.
- **`tagged_union!` instead of `#[serde(tag = "...")]`.** An internally
  tagged enum chooses its variant by a member (`type` by default, or one the
  macro names). Derive with `#[serde(remote = "Self")]` and call
  `tagged_union!(Enum)` or `tagged_union!(Enum, tag = "op")`. Positions are
  kept inside the variant, and an unknown or missing tag names the
  variants. An externally tagged enum (one key names the variant) needs no
  macro.
- **`shape_union!` instead of `#[serde(untagged)]`.** A union chooses by
  node kind only (scalar, list, mapping): `shape_union!(Scopes { scalar =>
  One, list => Many })`. For the schema, derive `JsonSchema` with
  `#[schemars(untagged)]`; serde never reads that attribute.

In every union, every variant is a struct variant, `Variant {}` when it has
no members, so a variant refuses unknown keys like any struct.

Closedness holds under the reader only. The shared types and the recipes
still decode under `serde_json` or another deserializer, and an `Invalid`
then shows its sentence alone (`expected ...`), but nothing refuses an
unknown key the type does not refuse itself: a struct without
`deny_unknown_fields` and every `tagged_union!` variant drop one silently.
An HTTP body or a JSON file that reuses these types is closed only when it
is read through the reader.

A member given under two spellings the type accepts (an `alias`) is
`config.duplicate-key` at the second key.

## Writing a checking type

A checking type refuses a value whose shape is right but whose content the
format does not accept. It refuses with an `Invalid` and nothing else; the
reader then reports `config.invalid-value` (or `config.out-of-range`) at the
value, in its own words, with the type's fix. `tests/reader_decode.rs` holds
these examples to the output shown.

```rust
use registry_platform_yaml::Invalid;
use serde::{Deserialize, Deserializer};

/// A queue name: 1 to 32 lowercase letters or `-`.
#[derive(Debug, Deserialize)]
#[serde(try_from = "String")]
pub struct QueueName(String);

impl TryFrom<String> for QueueName {
    type Error = Invalid;

    fn try_from(text: String) -> Result<QueueName, Invalid> {
        let valid = (1..=32).contains(&text.len())
            && text.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'-');
        if !valid {
            return Err(Invalid::expected(
                "a queue name of 1 to 32 lowercase letters or `-`",
                "Use lowercase letters and `-` only, at most 32 characters.",
            ));
        }
        Ok(QueueName(text))
    }
}

/// A worker count: a power of two, at most 64.
#[derive(Debug)]
pub struct Workers(u32);

impl<'de> Deserialize<'de> for Workers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Workers, D::Error> {
        let count = u32::deserialize(deserializer)?;
        if !(1..=64).contains(&count) {
            return Err(Invalid::out_of_range(1, 64).into_error());
        }
        if !count.is_power_of_two() {
            return Err(Invalid::expected("a power of two", "Use 1, 2, 4, 8, 16, 32, or 64.")
                .into_error());
        }
        Ok(Workers(count))
    }
}
```

`workers: 6` on line 3 is reported as:

```text
error[config.invalid-value] runtime.yaml:3:10 /workers
  expected a power of two
  next: Use 1, 2, 4, 8, 16, 32, or 64.
```

The rules:

- **Static text only.** `Invalid::expected` takes `&'static str`, so the
  compiler keeps a value out of the message and the fix (CFG-SEC-3). Name
  the grammar, the bounds, or the accepted values, never the value read.
- **Prefer the shared types.** A bounded integer is `BoundedU32<MIN, MAX>`
  or `BoundedU64<MIN, MAX>`, which also puts the bounds in the schema; use
  `Invalid::out_of_range` only when the type checks more than its bounds.
- **No other error text.** `Error::custom("...")`, `Error::custom(format!(..))`,
  or a `TryFrom` whose error is a `String` or another error type still
  refuses the value, but the reader cannot vouch for the text and reports
  the generic "the value is not valid here" with "Check the value against
  the format's reference for this member."
- **Never a value in `expecting`.** The reader shows a visitor's `expecting`
  text only for serde's own primitives and the reader's types; any other
  visitor's text gives way to the same generic sentence, since it may carry
  part of the value. A custom visitor refuses through `Invalid`.

A type sees one value. A rule that relates two members (a minimum above a
maximum) or a member to another file (a reference to an id another file
declares) is a semantic check: decode first, check the decoded value, and
report with the product's own code (CFG-DIAG-3) at the member whose value
the fix changes. `Document::diagnostic_at_value` places it at the value,
`diagnostic_at_key` at the key, and the other place goes in `related`, with
the other file's name and position for a cross-file check:

```rust
let document = Reader::new("runtime.yaml").read(bytes, &Expect::one(&FORMAT))?;
let runtime: Runtime = document.decode()?;
let mut report = Report::new(Vec::new());
if runtime.pool.minimum > runtime.pool.maximum {
    let mut diagnostic = document.diagnostic_at_value(
        Severity::Error,
        "example.pool.minimum-above-maximum",
        "/pool/minimum",
        "the minimum is greater than the maximum",
        "Lower `minimum` to at most `maximum`, or raise `maximum`.",
    );
    let maximum = document.span_of("/pool/maximum").map(|span| span.start);
    diagnostic.related.push(Related {
        file: document.file().to_string(),
        line: maximum.map(|position| position.line),
        column: maximum.map(|position| position.column),
        path: "/pool/maximum".to_string(),
        message: "the maximum".to_string(),
    });
    report.push(diagnostic);
}
```

The message, the fix, and each `related` message follow the same rule:
static text naming keys, bounds, and accepted values, never a value read
from the file.

## Hooks

`ScalarHook` sees every mapping key and every value that resolves to text,
with its pointer, the keys on the way from the root, its style, and its span,
before the envelope check. It may return a replacement, which is stored as
substituted text and never resolved again (a substituted `8080` in an
integer position is refused with "substitution fills text values only"), or
a `Refusal`, which is reported with the structural problems. A substituted
`apiVersion` or `kind` is refused (`config.substitution-not-allowed`).

## Parser choice

The reader parses with [`saphyr-parser`](https://crates.io/crates/saphyr-parser)
`=0.1.0`, pinned exactly in the workspace `Cargo.toml`. It was chosen over
`unsafe-libyaml-norway` 0.2.15 (the libyaml translation `serde_norway`
already pulls in) on these criteria:

| Criterion | `saphyr-parser` 0.1.0 | `unsafe-libyaml-norway` 0.2.15 |
|---|---|---|
| Unsafe code | none in the crate (5,352 lines). Its one dependency with unsafe code, `arraydeque` 0.5.1, backs `BufferedInput` only; the reader parses through `Parser::new_from_str`, which does not use it. | a C-to-Rust translation: 241 `unsafe` mentions in 11,871 lines; the workspace forbids `unsafe_code`, so the reader would need its own lint table and a module of `SAFETY` comments |
| Events against the suite | matches the vendored yaml-test-suite cases (below) | not run: excluded on the unsafe criterion |
| Marks | char-accurate line and column on every event, correct across CRLF | line, column, and byte index on every event |
| Refusal hooks | anchor ids, alias events, tags, collection events in key position, document starts, and scalar styles are all exposed | the same, through raw pointers |
| License | MIT OR Apache-2.0; `arraydeque` MIT/Apache-2.0 | MIT |
| `cargo deny check` | passes | already in the lock |

The vetting evidence lives in `tests/yaml_test_suite.rs`, which reads 54
cases vendored from yaml-test-suite (branch `data-2022-01-17`, MIT, license
in `tests/yaml-test-suite/LICENSE`). It renders saphyr's events in the
suite's `test.event` notation and compares them for every case, requires
every error case to fail, and then runs the reader over the same cases:
well-formed subset cases are read, and anchor, alias, tag, complex-key,
several-document, and malformed cases are refused with their code and a
position.

What the reader adds on top of the parser, and why:

- **Byte order mark and encoding.** saphyr does not strip a BOM; the reader
  strips one leading BOM and refuses bytes that are not UTF-8 at the first
  bad byte before parsing.
- **Duplicate keys and merge keys.** saphyr reports neither; the reader
  detects both while building the tree. A quoted `"<<"` is an ordinary key.
- **Anchor and tag positions.** saphyr's node events carry the content
  position, not the position of a preceding `&anchor` or `!tag`; the reader
  recovers that position by scanning the text between the previous event
  and the content, skipping comments.
- **Empty values.** saphyr places an empty value at its `:` or after its
  `-`; the reader places it at its key or at the `-`.
- **Depth.** The reader stops at 128 levels on the event stream. saphyr's
  scanner keeps its flow level in a `u8` and stops deep flow nesting with
  "recursion limit exceeded" before the reader's bound can apply; the
  reader reports that as `yaml.too-deep`. A test reads 1 MiB of `[` without
  overflowing the stack, and the `yaml_reader` fuzz target covers the same
  input.
- **Syntax messages.** The reader classifies parser errors into the closed
  syntax codes and appends saphyr's text as a note only when it is one of
  the parser's fixed strings. In 0.1.0 the only error text built from input
  is "unexpected character" (`scanner.rs`), which the reader drops. **On
  any version bump, re-audit every `ScanError::new` call site for text
  built from input**, rerun the suite comparison, and re-check the depth and
  empty-value behavior above.

## Tests

Test names start with the rule they prove (`cfg_yaml_2_...`,
`cfg_diag_5_...`), so a rule's coverage is one search away.

```bash
cargo test --locked -p registry-platform-yaml --all-features
```

- `tests/reader_subset.rs`: the YAML subset, scalar table, bounds, and
  syntax codes;
- `tests/reader_envelope.rs`: envelope, retired and deprecated versions,
  removed keys;
- `tests/reader_decode.rs`: typed decoding, positions, redaction, shared
  types, unions, and shared blocks;
- `tests/reader_schema.rs` (`schema` feature): the schemas the shared types
  and the recipes emit;
- `tests/yaml_test_suite.rs`: the parser vetting above.

The `yaml_reader` fuzz target in `products/platform/fuzz` feeds arbitrary
bytes to the reader, with and without a substituting hook, and decodes the
result into a type that uses every shared type and recipe.
