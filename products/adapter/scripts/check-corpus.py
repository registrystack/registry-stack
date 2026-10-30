#!/usr/bin/env python3
"""Hold the bad-authoring corpus to exact codes.

Every member directory under products/adapter/fixtures/corpus/bad/ must
make `adapterctl check` refuse, and the refusal must carry the member's
own code. The directory name is the expected code; the manifest's five
suffixed members (products/adapter/fixtures/corpus/README.md) expect the
longest registered code their name starts with, at a kebab or segment
boundary (`config.unknown-key-predicate` -> `config.unknown-key`). The
base/ control must pass with zero findings. Members are discovered from
the corpus directory and the code vocabulary is read from the owning
registries (the authoring codes in the core crate's diagnostics.rs and
the platform reader codes in registry-platform-yaml's messages.rs);
neither is listed here.

TRANSITIONAL: a member may additionally emit a partner code while the
workspace derivation's cascade co-fires (X1 F4-3) last. A partner code is
admissible only while it is another discovered member's own expectation;
when those co-fires stop, this rule is deleted and the expectation
tightens to exact equality.

Before it spends an adapterctl run, the runner self-tests its decision
logic on synthetic data, including the case this gate exists for: a
member whose refusal carries only another member's code fails, never
passes. `--self-test` runs that proof alone, without the corpus.

Deterministic and offline: standard library only, no network, no
timestamps. Exit 0 when the corpus holds, 1 with one FAIL line per
violation, 2 on usage error.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CORPUS = REPO_ROOT / "products" / "adapter" / "fixtures" / "corpus"

#: The owning registries of the codes a corpus refusal can carry: the
#: authoring diagnostics catalog of the core crate and the platform YAML
#: reader's code catalog.
REGISTRIES = (
    REPO_ROOT / "crates" / "registry-adapter-core" / "src" / "diagnostics.rs",
    REPO_ROOT / "crates" / "registry-platform-yaml" / "src" / "messages.rs",
)

#: A registered code as a quoted literal: dot-separated lowercase kebab
#: segments, at least two. The inner dots must be matched: a scan whose
#: segment class lacks the dot reads nothing.
CODE = re.compile(r'"([a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+)"')


def registered_codes() -> set[str]:
    """The codes the owning registries register, read live."""
    codes: set[str] = set()
    for registry in REGISTRIES:
        codes.update(CODE.findall(registry.read_text(encoding="utf-8")))
    return codes


def expectation(member: str, codes: set[str]) -> str | None:
    """The code a corpus member must refuse with.

    An exact code name is its own expectation; a suffixed member takes
    the longest registered code its name starts with, where the name
    continues with a kebab segment or a deeper path.
    """
    if member in codes:
        return member
    longest = ""
    for code in codes:
        rest = member[len(code) :]
        if member.startswith(code) and rest[:1] in ("-", ".") and len(code) > len(longest):
            longest = code
    return longest or None


def member_failures(
    member: str, primary: str, emitted: list[str], admissible: set[str]
) -> list[str]:
    """The violations in one member's emitted codes, if any.

    The member's own code must be among what was emitted: a refusal that
    carries only a co-fired partner code is a wrong-code refusal, not a
    pass. A further code is admissible, transitionally, only while it is
    another discovered member's own expectation (X1 F4-3).
    """
    if primary not in emitted:
        return [f"FAIL: {member}: emitted {emitted}, expected its own code {primary}"]
    partners = [code for code in emitted if code != primary and code not in admissible]
    if partners:
        return [
            f"FAIL: {member}: emitted {emitted}, expected [{primary}] plus, "
            "transitionally, another member's expectation"
        ]
    return []


def self_test() -> tuple[int, list[str]]:
    """Decide synthetic cases the gate must get right; return the count
    of cases decided and any failures."""
    problems: list[str] = []
    checked = 0

    # The registry scan reads multi-segment codes, and only codes.
    literal = 'Self::PackScriptUncompilable => "adapter.pack.script-uncompilable",'
    if CODE.findall(literal) != ["adapter.pack.script-uncompilable"]:
        problems.append("FAIL: self-test: the code scan misses a multi-segment code")
    checked += 1
    if CODE.findall("no codes here") != []:
        problems.append("FAIL: self-test: the code scan invents codes")
    checked += 1

    codes = {
        "adapter.pack.script-uncompilable",
        "adapter.route.direct-cycle",
        "adapter.runtime.insecure-origin",
        "config.unknown-key",
    }
    cases: list[tuple[str, str | None]] = [
        ("adapter.route.direct-cycle", "adapter.route.direct-cycle"),
        ("adapter.runtime.insecure-origin-token-endpoint", "adapter.runtime.insecure-origin"),
        ("config.unknown-key-predicate", "config.unknown-key"),
        ("config.unknown-key-redelivery", "config.unknown-key"),
        ("config.unknown-keyx", None),
        ("adapter.route.unknown-operation.bogus", None),
    ]
    for member, want in cases:
        if expectation(member, codes) != want:
            problems.append(f"FAIL: self-test: '{member}' must expect {want}")
        checked += 1

    # The wrong-code refusal this gate exists for: a member whose refusal
    # carries only another member's expectation fails, never passes.
    primary = "adapter.route.direct-cycle"
    partner = "adapter.pack.script-uncompilable"
    stranger = "config.invalid-value"
    emissions: list[tuple[list[str], bool]] = [
        ([primary], True),
        ([primary, partner], True),
        ([partner], False),
        ([], False),
        ([primary, stranger], False),
    ]
    for emitted, holds in emissions:
        failed = bool(member_failures("member", primary, emitted, {partner}))
        if failed == holds:
            problems.append(f"FAIL: self-test: a member emitting {emitted} must {'hold' if holds else 'fail'}")
        checked += 1

    return checked, problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(
            "usage: check-corpus.py <path-to-adapterctl> | check-corpus.py --self-test",
            file=sys.stderr,
        )
        return 2

    checked, problems = self_test()
    if problems:
        for line in problems:
            print(line)
        print(f"self-test: {len(problems)} failed")
        return 1
    print(f"self-test holds ({checked} cases)")
    if argv[1] == "--self-test":
        return 0

    if missing := [path for path in REGISTRIES if not path.is_file()]:
        for path in missing:
            print(f"FAIL: {path}: not found")
        return 1
    codes = registered_codes()
    if not codes:
        print(f"FAIL: no registered codes found in {[str(p) for p in REGISTRIES]}")
        return 1

    if not CORPUS.is_dir():
        print(f"FAIL: {CORPUS}: not found")
        return 1
    members = sorted(path.name for path in (CORPUS / "bad").iterdir() if path.is_dir())
    if not members:
        print(f"FAIL: {CORPUS / 'bad'}: no corpus members discovered")
        return 1

    expected: dict[str, str] = {}
    for member in members:
        code = expectation(member, codes)
        if code is None:
            print(f"FAIL: {member}: neither a registered code nor prefixed by one")
            return 1
        expected[member] = code

    bin_path = argv[1]
    failures: list[str] = []
    for member in members:
        directory = CORPUS / "bad" / member
        command = [bin_path, "--format=json", "check", str(directory / "project.yaml")]
        if (directory / "runtime.yaml").is_file():
            command += ["--runtime", str(directory / "runtime.yaml")]
        run = subprocess.run(command, capture_output=True, text=True)
        if run.returncode == 0:
            failures.append(f"FAIL: {member}: the check passed, expected refusal")
            continue
        try:
            diagnostics = json.loads(run.stdout)["diagnostics"]
        except (json.JSONDecodeError, KeyError):
            failures.append(
                f"FAIL: {member}: the check exited {run.returncode} without a JSON report: "
                f"{run.stderr.strip()}"
            )
            continue
        emitted = sorted({diagnostic["code"] for diagnostic in diagnostics})
        failures.extend(member_failures(member, expected[member], emitted, set(expected.values())))

    control = CORPUS / "base"
    run = subprocess.run(
        [bin_path, "--format=json", "check", str(control / "project.yaml")],
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        failures.append(f"FAIL: base: the control exited {run.returncode}, expected pass")
    else:
        try:
            findings = json.loads(run.stdout)["diagnostics"]
        except (json.JSONDecodeError, KeyError):
            failures.append("FAIL: base: the control passed without a JSON report")
        else:
            if findings:
                emitted = sorted({finding["code"] for finding in findings})
                failures.append(f"FAIL: base: the control emitted {emitted}")

    for line in failures:
        print(line)
    if failures:
        print(f"{len(failures)} failed")
        return 1
    print(f"corpus holds: {len(members)} members refuse with their own code, base control clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
