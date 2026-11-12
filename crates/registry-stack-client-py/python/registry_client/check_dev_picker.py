"""Check a development picker read-back file's shape without contacting a service."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping, Sequence

from . import __version__ as CLIENT_VERSION
from .connection import ConnectionError
from .dev_picker import (
    DESCRIPTOR_VERSION,
    GENERATION_VERSION,
    TOKEN_VERSION,
    DevelopmentPicker,
    PickerUnavailable,
    PickerValidationError,
    _validate_generation_document,
    _validate_token_document,
)


FORMATS = {
    "descriptor": (DESCRIPTOR_VERSION, "PlatformDevPickerDescriptor"),
    "generation": (GENERATION_VERSION, "PlatformDevPickerGeneration"),
    "token": (TOKEN_VERSION, "PlatformDevPickerToken"),
}
MAXIMUM_FILE_BYTES = 1_048_576
REPORT_API_VERSION = "id.registrystack.org/formats/platform/dev-picker-check-report/v1alpha1"
REPORT_KIND = "PlatformDevPickerCheckReport"
REPORT_COMMAND = "dev-picker check"


class _UsageError(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(message)


def _diagnostic(
    file: str | Path | None,
    *,
    code: str = "config.invalid-value",
    path: str = "",
    message: str = "the generated picker state is inconsistent",
    suggested_action: str = "Regenerate the development picker state.",
) -> dict[str, Any]:
    diagnostic: dict[str, Any] = {
        "severity": "error",
        "code": code,
        "path": path,
        "message": message,
        "suggestedAction": suggested_action,
    }
    if file is not None:
        diagnostic["source"] = {"file": os.fspath(file)}
    return diagnostic


def _report(status: str, diagnostics: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    errors = sum(diagnostic.get("severity") == "error" for diagnostic in diagnostics)
    warnings = sum(diagnostic.get("severity") == "warning" for diagnostic in diagnostics)
    return {
        "ok": status == "complete",
        "command": REPORT_COMMAND,
        "status": status,
        "apiVersion": REPORT_API_VERSION,
        "kind": REPORT_KIND,
        "version": CLIENT_VERSION,
        "filesChecked": 1 if status in ("complete", "domain-refusal") else 0,
        "errors": errors,
        "warnings": warnings,
        "diagnostics": list(diagnostics),
    }


def _json_requested(arguments: Sequence[str]) -> bool:
    for index, argument in enumerate(arguments):
        if argument == "--":
            return False
        if argument == "--format=json":
            return True
        if argument == "--format" and index + 1 < len(arguments):
            return arguments[index + 1] == "json"
    return False


def _human_lines(diagnostics: Sequence[Mapping[str, Any]]) -> list[str]:
    lines = []
    for diagnostic in diagnostics:
        severity = diagnostic.get("severity", "error")
        code = diagnostic.get("code", "config.invalid-value")
        path = diagnostic.get("path") or ""
        source = diagnostic.get("source")
        location = "<document>"
        if isinstance(source, Mapping):
            location = str(source.get("file") or location)
            line = source.get("line")
            column = source.get("column")
            if isinstance(line, int) and not isinstance(line, bool) and line > 0:
                location += f":{line}"
                if isinstance(column, int) and not isinstance(column, bool) and column > 0:
                    location += f":{column}"
        lines.append(f"{severity}[{code}] {location} {path}".rstrip())
        lines.append(f"  {diagnostic.get('message', 'the input was refused')}")
        lines.append(f"  next: {diagnostic.get('suggestedAction', 'Correct the input and retry.')}")
    errors = sum(diagnostic.get("severity") == "error" for diagnostic in diagnostics)
    warnings = sum(diagnostic.get("severity") == "warning" for diagnostic in diagnostics)
    lines.append(
        f"{errors} {'error' if errors == 1 else 'errors'}, "
        f"{warnings} {'warning' if warnings == 1 else 'warnings'} in 1 file"
    )
    return lines


def _display_source(selected: Path, source: Path | None) -> Path:
    if source is None:
        return selected
    try:
        resolved_selected = selected.resolve(strict=True)
    except OSError:
        return source
    bases = [(resolved_selected.parent, selected.parent)]
    if len(resolved_selected.parents) >= 3 and len(selected.parents) >= 3:
        bases.append((resolved_selected.parents[2], selected.parents[2]))
    for resolved_base, given_base in bases:
        try:
            return given_base / source.relative_to(resolved_base)
        except ValueError:
            continue
    return source


def check_file(path: str | Path, *, kind: str) -> None:
    """Validate one generated picker document and its local references."""
    selected = Path(path)
    try:
        descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAXIMUM_FILE_BYTES:
                raise ConnectionError(
                    "picker state was refused",
                    diagnostics=(_diagnostic(selected),),
                )
            contents = source.read(MAXIMUM_FILE_BYTES + 1)
        if len(contents) > MAXIMUM_FILE_BYTES:
            raise ConnectionError("picker state was refused", diagnostics=(_diagnostic(selected),))
    except OSError as exc:
        raise ConnectionError(
            "picker state was refused", diagnostics=(_diagnostic(selected),)
        ) from exc

    from .yaml import ConfigReadError, read_document  # pyright: ignore[reportMissingImports]

    api_version, format_kind = FORMATS[kind]
    try:
        document = read_document(
            contents,
            file=os.fspath(selected),
            api_version=api_version,
            kind=format_kind,
        )
    except ConfigReadError as exc:
        raise ConnectionError("picker state was refused", diagnostics=exc.diagnostics) from None
    try:
        if kind == "descriptor":
            DevelopmentPicker.check_descriptor(selected, document)
        elif kind == "generation":
            _validate_generation_document(document)
        elif kind == "token":
            state = _validate_token_document(document)
            if "token" in state and (
                metadata.st_uid != os.getuid() or metadata.st_nlink != 1 or metadata.st_mode & 0o177
            ):
                raise PickerUnavailable("live person token file is not private")
        else:
            raise PickerUnavailable("picker state kind is unsupported")
    except PickerValidationError as exc:
        raise ConnectionError(
            "picker state was refused",
            diagnostics=(_diagnostic(_display_source(selected, exc.source), path=exc.path),),
        ) from None
    except PickerUnavailable:
        raise ConnectionError(
            "picker state was refused",
            diagnostics=(_diagnostic(selected),),
        ) from None


def main() -> int:
    arguments = sys.argv[1:]
    json_output = _json_requested(arguments)
    parser = _Parser(description=__doc__)
    parser.add_argument("--kind", required=True, choices=tuple(FORMATS))
    parser.add_argument("file", help="development picker descriptor, token, or generation file")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument("--deny-warnings", action="store_true")
    try:
        args = parser.parse_args(arguments)
    except _UsageError:
        diagnostics = (
            _diagnostic(
                None,
                code="check-dev-picker.usage-error",
                message="the command arguments are invalid",
                suggested_action="Use --help to review the accepted arguments.",
            ),
        )
        if json_output:
            print(json.dumps(_report("usage-error", diagnostics)))
        else:
            parser.print_usage(sys.stderr)
            print("check-dev-picker: the command arguments are invalid", file=sys.stderr)
        return 2
    try:
        check_file(args.file, kind=args.kind)
    except ConnectionError as exc:
        if args.format == "json":
            print(json.dumps(_report("domain-refusal", exc.diagnostics)))
            return 1
        print("\n".join(_human_lines(exc.diagnostics)), file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps(_report("complete", ())))
        return 0
    print("picker read-back file valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
