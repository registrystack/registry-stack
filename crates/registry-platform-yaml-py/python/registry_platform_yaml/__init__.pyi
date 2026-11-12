from typing import NotRequired, TypeAlias, TypedDict

JSONScalar: TypeAlias = None | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]

class Source(TypedDict):
    file: str
    line: NotRequired[int]
    column: NotRequired[int]

class Related(TypedDict):
    file: str
    line: NotRequired[int]
    column: NotRequired[int]
    path: str
    message: str

class Diagnostic(TypedDict):
    severity: str
    code: str
    artifact: NotRequired[str]
    path: str
    message: str
    suggestedAction: str
    source: NotRequired[Source]
    related: NotRequired[list[Related]]

class ConfigReadError(Exception):
    """A configuration document was refused with value-free diagnostics."""

    diagnostics: tuple[Diagnostic, ...]

def read_document(
    contents: bytes,
    *,
    file: str,
    api_version: str,
    kind: str,
) -> dict[str, JSONValue]: ...
