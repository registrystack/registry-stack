#!/usr/bin/env python3
"""Check the product OpenAPI documents against what the TypeScript clients assume.

A page client tells the session service's own answers apart from a product's by the
service's marker header, and refuses to follow a redirect, so two things must hold in every
document the clients' generator reads (the `inputs` table in
`clients/typescript/generate-all.ts`):

* No product declares a problem code that starts with `session.`. Those codes belong to the
  session service.
* No route declares a 3xx answer. A redirected route would send a page's request, body and
  idempotency key somewhere the client cannot check. `304 Not Modified` answers a conditional
  read with no body and no new target, so it is allowed.

Usage: check-client-assumptions.py [REPOSITORY_ROOT]
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

GENERATOR = Path("clients/typescript/generate-all.ts")
METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
NOT_A_REDIRECT = {"304"}


# One table entry: a name, then the quoted path of a document, with an optional trailing comment.
ENTRY = re.compile(r"""^\s*['"]?[\w-]+['"]?\s*:\s*(['"])(?P<name>[^'"]+\.json)\1\s*,?\s*(//.*)?$""")


def documents(root: Path) -> list[Path]:
    source = (root / GENERATOR).read_text(encoding="utf-8")
    start = source.find("const inputs = {")
    if start < 0:
        raise ValueError(f"{GENERATOR}: no `inputs` table")
    # The table ends at the first closing brace on a line of its own, so a brace in a comment does not cut it.
    table = source[start:].split("\n", 1)[1].split("\n}", 1)[0]
    names = []
    for line in table.splitlines():
        if not line.strip() or line.strip().startswith("//"):
            continue
        entry = ENTRY.match(line)
        if entry is None:
            raise ValueError(f"{GENERATOR}: cannot read this `inputs` line: {line.strip()}")
        names.append(entry.group("name"))
    if not names:
        raise ValueError(f"{GENERATOR}: the `inputs` table names no document")
    return [root / "products" / name for name in names]


def session_codes(node: object, pointer: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            at = f"{pointer}/{key}"
            if key in {"const", "default", "example"} and isinstance(value, str) and value.startswith("session."):
                found.append((at, value))
            elif key in {"enum", "examples"} and isinstance(value, list):
                found.extend((f"{at}/{index}", item) for index, item in enumerate(value)
                             if isinstance(item, str) and item.startswith("session."))
            found.extend(session_codes(value, at))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(session_codes(value, f"{pointer}/{index}"))
    return found


def redirects(document: dict) -> list[str]:
    found = []
    for path, item in document.get("paths", {}).items():
        for method, operation in item.items():
            if method not in METHODS or not isinstance(operation, dict):
                continue
            for status in operation.get("responses", {}):
                text = str(status)
                if text.startswith("3") and text not in NOT_A_REDIRECT:
                    found.append(f"{method.upper()} {path} declares {text}")
    return found


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[3]
    try:
        paths = documents(root)
    except (OSError, ValueError) as error:
        print(f"check-client-assumptions: {error}", file=sys.stderr)
        return 2
    findings = []
    for path in paths:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            print(f"check-client-assumptions: {path}: {error}", file=sys.stderr)
            return 2
        name = path.relative_to(root).as_posix()
        findings.extend(f"{name}: {pointer} declares the session problem code {code}"
                        for pointer, code in session_codes(document))
        findings.extend(f"{name}: {finding}" for finding in redirects(document))
    if findings:
        print("\n".join(findings))
        print(f"check-client-assumptions: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print(f"check-client-assumptions: ok ({len(paths)} documents)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
