#!/usr/bin/env python3
"""Fail when CI selects no build that runs a feature-gated registry-breg test.

A test behind a Cargo feature is silently left out of every `cargo test` that
does not enable the feature: the command builds, runs nothing for that test,
and exits green. This gate reads the crate and the CI commands and refuses a
gated test that no command selects.

What counts as a gated test:

- an integration target with `required-features`, or whose file opens with an
  inner `#![cfg(...)]` naming a feature;
- a `#[test]` or `#[tokio::test]` function carrying a `#[cfg(...)]` that names
  a feature, in `tests/*.rs` or anywhere under `src/`;
- a `mod` item carrying such a `#[cfg(...)]`, in the same files.

What counts as selecting it: the Rust test shard that owns the crate, and
every literal `cargo test ... -p registry-breg` command in INVOCATION_SOURCES,
when the command builds the test's target with features that satisfy every
condition on it.

Limits, stated so nobody trusts this for more than it reads:

- Each item is checked against its own conditions and its file's, not against
  the conditions of a module that encloses it.
- Files under `tests/<directory>/` and tests produced by macros are not read.
- A command with a test-name filter, `--ignored`, `--skip`, a shell variable,
  or a flag this script does not know selects nothing here, because the gate
  cannot enumerate what such a command runs.
- The shard is modelled as one `cargo test` over the shard's packages: the
  crate's default features plus the features the other shard members request
  on it in their own manifests. Whether CI still runs that shard, or a listed
  script, is held by the workflow and its own gates, not by this one.
- A `#[cfg(...)]` that shares its line with other code, or a predicate other
  than `feature`, `test`, `unix`, `all`, `any`, and `not`, stops the gate with
  an error instead of being guessed.
"""

from __future__ import annotations

import re
import shlex
import sys
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from ci_changes import SHARDS


ROOT = Path(__file__).resolve().parents[2]
CRATE = "registry-breg"

# Files whose literal `cargo test` commands CI runs.
INVOCATION_SOURCES = (
    ".github/workflows/ci.yml",
    "products/breg/scripts/check-client-contract.sh",
    "products/breg/scripts/test-attachment-s3.sh",
    "products/breg/scripts/test-postgres-tls.sh",
    "products/breg/scripts/test-postgres.sh",
)

# Gated tests no CI invocation selects, recorded so the gate can refuse the
# next one. Selecting any of them is a PostgreSQL lane change of its own. The
# gate fails on an entry that is selected or gone, so remove the entry in the
# change that starts running the test; do not add one to get a test past the
# gate.
_WITHOUT_POSTGRES_TEST = "test-postgres.sh builds this target without postgres-test"
_NO_LIBRARY_RUN = "no invocation runs the library tests with postgres-test"
KNOWN_UNSELECTED: dict[str, str] = {
    "tests/postgres_action_handlers.rs::wasm_handler_declaration_fails_typed_and_statelessly_without_the_executor": (
        "runs only without wasm; the PostgreSQL lanes build this target with default features"
    ),
    "tests/postgres_statistics_load.rs": (
        "one ignored one-million-unit measurement, run by hand and named by no script"
    ),
    "tests/runtime_config.rs::database_test_only_plaintext_connects_without_tls_in_test_builds": _WITHOUT_POSTGRES_TEST,
    "tests/runtime_config.rs::pinned_loopback_https_event_profile_activates_with_exact_test_tls_and_ceilings": _WITHOUT_POSTGRES_TEST,
    "tests/startup_http.rs::serve_returns_after_graceful_shutdown_signal": _WITHOUT_POSTGRES_TEST,
    "tests/startup_http.rs::shutdown_signal_failure_still_stops_and_joins_the_bound_server": _WITHOUT_POSTGRES_TEST,
    "tests/startup_http.rs::listener_bind_failure_never_starts_or_detaches_the_webhook_worker": _WITHOUT_POSTGRES_TEST,
    "tests/startup_http.rs::shutdown_timeout_aborts_and_joins_the_webhook_worker_before_returning": _WITHOUT_POSTGRES_TEST,
    "tests/startup_http.rs::a_panicking_background_task_stops_serve_with_a_distinct_error": _WITHOUT_POSTGRES_TEST,
    "tests/startup_http.rs::an_early_returning_background_task_stops_serve_with_a_distinct_error": _WITHOUT_POSTGRES_TEST,
    "tests/startup_http.rs::a_requested_shutdown_reports_no_background_task_stop": _WITHOUT_POSTGRES_TEST,
    "src/attachment_store.rs::mod test_support": (
        "support code for the PostgreSQL integration targets; it holds no tests"
    ),
    "src/mutation.rs::mod tests": _NO_LIBRARY_RUN,
    "src/postgres/config.rs::connection_debug_never_contains_database_secrets": _NO_LIBRARY_RUN,
    "src/postgres/history_read.rs::mod tests": _NO_LIBRARY_RUN,
    "src/postgres/interlock.rs::failed_resume_and_ddl_timeout_are_fail_closed_on_real_postgres": _NO_LIBRARY_RUN,
    "src/postgres/mod.rs::mod stored_bytes_probe": _NO_LIBRARY_RUN,
    "src/postgres/revision_read.rs::mod tests": _NO_LIBRARY_RUN,
    "src/request_store.rs::mod tests": _NO_LIBRARY_RUN,
    "src/review_store.rs::mod transaction_instant_tests": _NO_LIBRARY_RUN,
    "src/task_grant/tests.rs::write_idempotency_separates_grants_without_changing_read_authority": _NO_LIBRARY_RUN,
}

# Predicates that hold in every CI test build of the crate.
ALWAYS_TRUE = frozenset({"test", "unix"})
BARE_CARGO_FLAGS = frozenset({"--locked", "--frozen", "--offline", "--quiet", "-q", "--no-fail-fast"})
BARE_HARNESS_FLAGS = frozenset({"--include-ignored", "--nocapture", "--no-capture", "--show-output"})

CARGO_TEST = re.compile(r"\bcargo test\b")
NAMES_CRATE = re.compile(rf"(?:-p|--package)[ =]{re.escape(CRATE)}(?![\w-])")
CFG_TOKEN = re.compile(r'\s*(?:(\w+)|"([^"]*)"|([(),=]))')
CFG_LINE = re.compile(r"^#(!?)\[cfg\((.*)\)\]$")
TEST_ATTRIBUTE = re.compile(r"^#\[(?:tokio::)?test\b")
ITEM = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?(?:(?:async\s+)?fn\s+(\w+)|mod\s+(\w+))")


class GateError(Exception):
    """The gate met input it refuses to interpret."""


@dataclass(frozen=True)
class Invocation:
    """One `cargo test` over the crate: where it is, what it enables and builds."""

    source: str
    features: frozenset[str]
    lib: bool
    # Integration targets named with `--test`; None selects every one.
    tests: frozenset[str] | None


@dataclass(frozen=True)
class GatedTest:
    """A test, test module, or test target that only some feature sets build."""

    key: str
    # Integration target name; None for the library.
    target: str | None
    conditions: tuple[str, ...]


def feature_closure(
    table: Mapping[str, Iterable[str]], requested: Iterable[str], *, default_features: bool
) -> frozenset[str]:
    enabled = set(requested)
    if default_features and "default" in table:
        enabled.add("default")
    pending = list(enabled)
    while pending:
        for implied in table.get(pending.pop(), ()):
            if implied in table and implied not in enabled:
                enabled.add(implied)
                pending.append(implied)
    return frozenset(enabled)


def cfg_holds(expression: str, features: frozenset[str]) -> bool:
    """Evaluate a `cfg` predicate for a CI test build with these features."""
    tokens: list[str] = []
    position = 0
    while position < len(expression):
        match = CFG_TOKEN.match(expression, position)
        if match is None or match.end() == position:
            if expression[position:].strip():
                raise GateError(f"unreadable cfg predicate: {expression}")
            break
        position = match.end()
        tokens.append(f'"{match[2]}"' if match[2] is not None else match[1] or match[3])

    def take(expected: str | None = None) -> str:
        if not tokens or (expected is not None and tokens[0] != expected):
            raise GateError(f"unreadable cfg predicate: {expression}")
        return tokens.pop(0)

    def predicate() -> bool:
        name = take()
        if name in ("all", "any", "not"):
            take("(")
            values = []
            while tokens and tokens[0] != ")":
                values.append(predicate())
                if tokens and tokens[0] == ",":
                    take(",")
            take(")")
            if name == "not":
                if len(values) != 1:
                    raise GateError(f"unreadable cfg predicate: {expression}")
                return not values[0]
            return all(values) if name == "all" else any(values)
        if name == "feature":
            take("=")
            value = take()
            if not value.startswith('"'):
                raise GateError(f"unreadable cfg predicate: {expression}")
            return value.strip('"') in features
        if name in ALWAYS_TRUE and (not tokens or tokens[0] in (",", ")")):
            return True
        raise GateError(f"unsupported cfg predicate `{name}` in: {expression}")

    result = predicate()
    if tokens:
        raise GateError(f"unreadable cfg predicate: {expression}")
    return result


def read_invocation(
    command: str, source: str, table: Mapping[str, Iterable[str]]
) -> Invocation | None:
    """Read one command line; None when it selects nothing the gate can state."""
    start = CARGO_TEST.search(command)
    if start is None:
        return None
    try:
        words = shlex.split(command[start.start() :], comments=True)[2:]
    except ValueError:
        return None
    if any("$" in word for word in words):
        return None
    harness: list[str] = []
    if "--" in words:
        split = words.index("--")
        words, harness = words[:split], words[split + 1 :]

    packages: list[str] = []
    requested: set[str] = set()
    tests: set[str] = set()
    default_features = True
    targeted = False
    index = 0
    while index < len(words):
        word = words[index]
        index += 1
        if word in ("-p", "--package", "--features", "-F", "--test"):
            if index == len(words):
                return None
            value = words[index]
            index += 1
            if word in ("-p", "--package"):
                packages.append(value)
            elif word == "--test":
                tests.add(value)
                targeted = True
            else:
                requested.update(
                    feature.removeprefix(f"{CRATE}/")
                    for feature in re.split(r"[ ,]+", value)
                    if feature
                )
        elif word == "--lib":
            targeted = True
        elif word == "--no-default-features":
            default_features = False
        elif word not in BARE_CARGO_FLAGS:
            # A test-name filter, `--no-run`, or a flag the gate does not know.
            return None
    index = 0
    while index < len(harness):
        word = harness[index]
        index += 1
        if word == "--test-threads" and index < len(harness):
            index += 1
        elif word not in BARE_HARNESS_FLAGS and not word.startswith("--test-threads="):
            return None
    if packages != [CRATE]:
        return None
    return Invocation(
        source=source,
        features=feature_closure(table, requested, default_features=default_features),
        lib="--lib" in words or not targeted,
        tests=frozenset(tests) if targeted else None,
    )


def source_invocations(
    text: str, source: str, table: Mapping[str, Iterable[str]]
) -> tuple[list[Invocation], int]:
    """Return the readable commands in one file and how many were set aside."""
    invocations: list[Invocation] = []
    ignored = 0
    for line in text.replace("\\\n", " ").splitlines():
        if line.lstrip().startswith("#") or not CARGO_TEST.search(line):
            continue
        if not NAMES_CRATE.search(line):
            continue
        invocation = read_invocation(line, source, table)
        if invocation is None:
            ignored += 1
        else:
            invocations.append(invocation)
    return invocations, ignored


def shard_packages(shards: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    owners = [packages for packages in shards.values() if CRATE in packages]
    if len(owners) != 1:
        raise GateError(f"{CRATE} must belong to exactly one Rust test shard")
    return owners[0]


def shard_invocation(
    root: Path, packages: Iterable[str], table: Mapping[str, Iterable[str]]
) -> Invocation:
    """Model the shard: every target, with the features its members unify."""
    requested: set[str] = set()
    for package in packages:
        if package == CRATE:
            continue
        manifest = tomllib.loads(
            (root / "crates" / package / "Cargo.toml").read_text(encoding="utf-8")
        )
        for dependencies in ("dependencies", "dev-dependencies"):
            entry = manifest.get(dependencies, {}).get(CRATE)
            if isinstance(entry, dict):
                requested.update(entry.get("features", ()))
        own = manifest.get("features", {})
        for feature in feature_closure(own, (), default_features=True):
            for item in own.get(feature, ()):
                if item.startswith((f"{CRATE}/", f"{CRATE}?/")):
                    requested.add(item.split("/", 1)[1])
    return Invocation(
        source="Rust test shard",
        features=feature_closure(table, requested, default_features=True),
        lib=True,
        tests=None,
    )


def scan(path: Path, label: str) -> tuple[tuple[str, ...], list[tuple[str, tuple[str, ...]]]]:
    """Return a file's inner feature conditions and its gated tests and modules."""
    lines = path.read_text(encoding="utf-8").splitlines()
    file_conditions: list[str] = []
    items: list[tuple[str, tuple[str, ...]]] = []
    index = 0
    while index < len(lines):
        if not lines[index].lstrip().startswith(("#[", "#![")):
            index += 1
            continue
        conditions: list[str] = []
        is_test = False
        while index < len(lines):
            line = lines[index].strip()
            if line.startswith("//"):
                index += 1
                continue
            if not line.startswith(("#[", "#![")):
                break
            start = index
            depth = line.count("[") - line.count("]")
            index += 1
            while depth > 0 and index < len(lines):
                part = lines[index].strip()
                line += part if line.endswith("(") or part.startswith(")") else f" {part}"
                depth += part.count("[") - part.count("]")
                index += 1
            if line.startswith(("#[cfg(", "#![cfg(")):
                match = CFG_LINE.match(line)
                if match is None:
                    raise GateError(
                        f"{label}:{start + 1}: cfg attribute shares its line with other "
                        "code; the gate cannot read it"
                    )
                if "feature" in match[2]:
                    (file_conditions if match[1] else conditions).append(match[2])
            is_test = is_test or TEST_ATTRIBUTE.match(line) is not None
        item = ITEM.match(lines[index].strip()) if index < len(lines) else None
        if conditions and item is not None:
            if item[2] is not None:
                items.append((f"mod {item[2]}", tuple(conditions)))
            elif is_test:
                items.append((item[1], tuple(conditions)))
        index += 1
    return tuple(file_conditions), items


def gated_tests(crate: Path) -> list[GatedTest]:
    manifest = tomllib.loads((crate / "Cargo.toml").read_text(encoding="utf-8"))
    declared = {
        target.get("path", f"tests/{target['name']}.rs"): (
            target["name"],
            tuple(f'feature = "{feature}"' for feature in target.get("required-features", ())),
        )
        for target in manifest.get("test", ())
    }
    found: list[GatedTest] = []
    for path in sorted((crate / "tests").glob("*.rs")):
        relative = path.relative_to(crate).as_posix()
        target, required = declared.get(relative, (path.stem, ()))
        file_conditions, items = scan(path, relative)
        base = required + file_conditions
        if base:
            found.append(GatedTest(relative, target, base))
        found.extend(
            GatedTest(f"{relative}::{name}", target, base + conditions)
            for name, conditions in items
        )
    for path in sorted((crate / "src").rglob("*.rs")):
        relative = path.relative_to(crate).as_posix()
        file_conditions, items = scan(path, relative)
        found.extend(
            GatedTest(f"{relative}::{name}", None, file_conditions + conditions)
            for name, conditions in items
        )
    return found


def selects(invocation: Invocation, test: GatedTest) -> bool:
    if test.target is None:
        if not invocation.lib:
            return False
    elif invocation.tests is not None and test.target not in invocation.tests:
        return False
    return all(cfg_holds(condition, invocation.features) for condition in test.conditions)


def violations(
    tests: Iterable[GatedTest],
    invocations: Iterable[Invocation],
    known_unselected: Mapping[str, str],
) -> list[str]:
    invocations = list(invocations)
    unselected = [
        test for test in tests if not any(selects(invocation, test) for invocation in invocations)
    ]
    # A target nothing builds is one finding, not one per test inside it.
    whole = {test.key for test in unselected if "::" not in test.key}
    unselected = [
        test
        for test in unselected
        if "::" not in test.key or test.key.split("::", 1)[0] not in whole
    ]
    keys = {test.key for test in unselected}
    problems = [
        f"{test.key}: no CI invocation selects it; it needs "
        f"{'the library' if test.target is None else f'target {test.target}'} "
        f"built with {' and '.join(test.conditions)}"
        for test in unselected
        if test.key not in known_unselected
    ]
    problems.extend(
        f"{key}: listed in KNOWN_UNSELECTED but selected now or no longer a gated test; "
        "remove the entry"
        for key in sorted(known_unselected)
        if key not in keys
    )
    return problems


def ci_invocations(
    root: Path,
    sources: Iterable[str] = INVOCATION_SOURCES,
    shard: Iterable[str] | None = None,
) -> tuple[list[Invocation], int]:
    table = tomllib.loads((root / "crates" / CRATE / "Cargo.toml").read_text(encoding="utf-8"))[
        "features"
    ]
    invocations = [shard_invocation(root, shard or shard_packages(SHARDS), table)]
    ignored = 0
    for source in sources:
        found, skipped = source_invocations(
            (root / source).read_text(encoding="utf-8"), source, table
        )
        invocations.extend(found)
        ignored += skipped
    return invocations, ignored


def repository_violations(
    root: Path,
    *,
    sources: Iterable[str] = INVOCATION_SOURCES,
    shard: Iterable[str] | None = None,
    known_unselected: Mapping[str, str] | None = None,
) -> list[str]:
    invocations, _ = ci_invocations(root, sources, shard)
    return violations(
        gated_tests(root / "crates" / CRATE),
        invocations,
        KNOWN_UNSELECTED if known_unselected is None else known_unselected,
    )


def main() -> int:
    try:
        tests = gated_tests(ROOT / "crates" / CRATE)
        invocations, ignored = ci_invocations(ROOT)
        problems = violations(tests, invocations, KNOWN_UNSELECTED)
    except GateError as error:
        print(f"gated test selection gate cannot read its input: {error}", file=sys.stderr)
        return 2
    if problems:
        print(f"feature-gated {CRATE} tests without a CI invocation:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    print(
        f"{len(tests)} feature-gated {CRATE} tests, modules, and targets checked against "
        f"{len(invocations)} CI invocations ({ignored} partial invocations set aside); "
        f"{len(KNOWN_UNSELECTED)} recorded as selected by none"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
