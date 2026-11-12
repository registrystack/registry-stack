"""Offline checks for Python connection and development token read-back files."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from .connection import API_VERSION, ConnectionError, _secret, connect
from .runner import TOKEN_VERSION, RunnerTokenSource, check_runner_document


_MAXIMUM_PRINTED_DIAGNOSTICS = 10


def _bounded_field(value: Any, maximum: int, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    value = "".join(
        character if ord(character) >= 32 and character != "\x7f" else "?"
        for character in value
    )
    return value[:maximum] or fallback


def _diagnostic_lines(diagnostics: tuple[Mapping[str, Any], ...]) -> list[str]:
    lines = []
    for diagnostic in diagnostics[:_MAXIMUM_PRINTED_DIAGNOSTICS]:
        code = _bounded_field(diagnostic.get("code"), 128, "configuration.refused")
        path = _bounded_field(diagnostic.get("path"), 512, "/")
        line = f"{code} at {path}"
        source = diagnostic.get("source")
        if isinstance(source, Mapping):
            file = _bounded_field(source.get("file"), 512, "<document>")
            source_line = source.get("line")
            column = source.get("column")
            if isinstance(source_line, int) and not isinstance(source_line, bool) and source_line > 0:
                file += f":{source_line}"
                if isinstance(column, int) and not isinstance(column, bool) and column > 0:
                    file += f":{column}"
            line += f" ({file})"
        lines.append(line)
    omitted = len(diagnostics) - len(lines)
    if omitted > 0:
        lines.append(f"{omitted} additional diagnostics omitted")
    return lines


def _document(path: Path) -> tuple[str, dict[str, Any]]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1_048_576:
                raise ConnectionError("the read-back file must be a bounded regular file")
            raw = source.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ConnectionError("the read-back file exceeds the size limit")
    except OSError as exc:
        raise ConnectionError("the read-back file is unavailable") from exc
    from .yaml import ConfigReadError, read_document  # pyright: ignore[reportMissingImports]

    for api_version, kind in (
        (API_VERSION, "PlatformPythonConnection"),
        (TOKEN_VERSION, "PlatformDevWorkloadToken"),
    ):
        try:
            document = read_document(raw, file=os.fspath(path), api_version=api_version, kind=kind)
            return kind, document
        except ConfigReadError as exc:
            wrong_kind = bool(exc.diagnostics) and all(
                diagnostic.get("code") == "config.wrong-kind"
                for diagnostic in exc.diagnostics
            )
            if kind == "PlatformPythonConnection" and wrong_kind:
                continue
            raise ConnectionError(
                "the read-back document was refused", diagnostics=exc.diagnostics
            ) from None
    raise ConnectionError("the read-back document was refused")


def check_file(path: str | Path) -> None:
    """Check shape and local references without contacting an issuer or product."""
    selected = Path(path)
    kind, document = _document(selected)
    if kind == "PlatformPythonConnection":
        connection = connect(path=selected)
        for binding in connection._bindings.values():
            if binding.credential["type"] == "runner-token":
                RunnerTokenSource(binding, connection._providers).current()
            else:
                try:
                    key = json.loads(
                        _secret(binding.credential["clientKeyRef"], connection._providers)
                    )
                except (json.JSONDecodeError, UnicodeError):
                    raise ConnectionError("the declared client key is not a JWK object") from None
                if not isinstance(key, dict):
                    raise ConnectionError("the declared client key is not a JWK object")
        return
    if kind == "PlatformDevWorkloadToken":
        check_runner_document(document, allow_stopped=True)
        if document.get("status") != "stopped":
            providers = {"file": {"root": str(selected.parent)}}
            from .yaml import ConfigReadError, read_document  # pyright: ignore[reportMissingImports]

            try:
                private_document = read_document(
                    _secret(f"secret:file/{selected.name}", providers).encode("utf-8"),
                    file=os.fspath(selected), api_version=TOKEN_VERSION,
                    kind="PlatformDevWorkloadToken",
                )
            except ConfigReadError as exc:
                raise ConnectionError(
                    "runner token document was refused", diagnostics=exc.diagnostics
                ) from None
            check_runner_document(private_document)
        return
    raise ConnectionError("the read-back kind is unsupported")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a Python connection or runner token file without network calls."
    )
    parser.add_argument("file", help="connection or stopped/live token JSON file")
    args = parser.parse_args()
    try:
        check_file(args.file)
    except ConnectionError as exc:
        lines = _diagnostic_lines(exc.diagnostics)
        detail = "".join(f"{line}\n" for line in lines)
        parser.exit(2, f"{exc}\n{detail}")
    print("read-back file valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
