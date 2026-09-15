#!/usr/bin/env python3
"""Report review-only ELF exposure facts for one release image executable.

The report lists the executable's loader inputs, its undefined dynamic
symbols, every relocation against dlsym or dlvsym, and every located dlsym or
dlvsym lookup site, reached through its PLT stub or its GOT slot. It is not a
gate: it records facts and marks what it cannot establish as requiring review.

A lookup name is reported only when the nearest preceding write to %rsi in the
same linear instruction run is a RIP-relative lea into %rsi, no direct branch
lands between that lea and the lookup, and the address holds a bounded
printable NUL-terminated string in a file-backed section. Anything else leaves
the name null and requires review. Indirect branch targets, such as jump
tables, are not visible to this analysis.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from array import array
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "registry-stack.image-exposure.v1"
DYNAMIC_LOADING_APIS = frozenset({"dladdr", "dlmopen", "dlopen", "dlsym", "dlvsym"})
LOOKUP_FUNCTIONS = frozenset({"dlsym", "dlvsym"})
PLT_SYMBOLS = {f"{function}@plt": function for function in LOOKUP_FUNCTIONS}
SLOT_RELOCATIONS = frozenset({"R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"})
BINUTILS = ("objdump", "readelf")
LOOKBACK_LIMIT = 32
MAX_NAME_LENGTH = 256
MAX_SYMLINK_HOPS = 8
MAX_SECTIONS = 4096
MAX_TOOL_DETAIL = 2000

ELF_MACHINE_X86_64 = 62
SHT_NULL = 0
SHT_NOBITS = 8
SHF_ALLOC = 0x2
SHF_TLS = 0x400

INSTRUCTION_RE = re.compile(r" *([0-9a-f]+):\t(.*)")
LABEL_RE = re.compile(r"([0-9a-f]+) <(.*)>:")
COMMENT_RE = re.compile(r"\s+#\s+([0-9a-f]+)(?:\s+<(.*)>)?$")
DIRECT_TARGET_RE = re.compile(r"([0-9a-f]+)(?:\s+<(.*)>)?")
RIP_SLOT_RE = re.compile(r"\*-?0x[0-9a-f]+\(%rip\)")
RIP_NAME_LEA_RE = re.compile(r"-?0x[0-9a-f]+\(%rip\),%rsi")
STRING_OPERATION_RE = re.compile(r"(?:cmps|lods|movs|outs)[bwlq]?")
RELOCATION_RE = re.compile(
    r"([0-9a-f]+)\s+[0-9a-f]+\s+(R_X86_64_\w+)\s+[0-9a-f]+\s+(\S+)\s+[+-]\s+\S+"
)
INSTRUCTION_PREFIXES = frozenset(
    {
        "addr32",
        "bnd",
        "cs",
        "data16",
        "data32",
        "ds",
        "es",
        "fs",
        "gs",
        "lock",
        "notrack",
        "rep",
        "repe",
        "repne",
        "repnz",
        "repz",
        "ss",
    }
)
# Instructions after which %rsi no longer holds a value set earlier in the
# same linear run: control leaves, or a call clobbers the register.
STOP_MNEMONICS = frozenset(
    {
        "(bad)",
        "call",
        "callq",
        "hlt",
        "int3",
        "iret",
        "iretq",
        "jmp",
        "jmpq",
        "lcall",
        "ljmp",
        "lret",
        "lretq",
        "ret",
        "retq",
        "sysret",
        "ud2",
    }
)
RSI_REGISTERS = frozenset({"%rsi", "%esi", "%si", "%sil"})
BIT_TEST_MNEMONICS = frozenset({"bt", "btl", "btq", "btw"})
READ_ONLY_PREFIXES = ("cmp", "push", "test")
MULTI_WRITE_PREFIXES = ("cmpxchg", "mulx", "xadd", "xchg")


class ExposureError(RuntimeError):
    """ELF exposure facts could not be reported exactly."""


@dataclass(frozen=True)
class Section:
    kind: int
    flags: int
    address: int
    offset: int
    size: int


@dataclass(frozen=True)
class ElfImage:
    data: bytes
    sections: tuple[Section, ...]


@dataclass(frozen=True)
class LookupSite:
    site: int
    instruction: str
    via: str
    function: str
    name_address: int | None
    review_reason: str | None


def load_advisory_baselines() -> ModuleType:
    path = SCRIPT_DIR / "check-advisory-baselines.py"
    spec = importlib.util.spec_from_file_location(
        "image_exposure_advisory_baselines", path
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ADVISORY_BASELINES = load_advisory_baselines()


def parse_elf_image(data: bytes) -> ElfImage:
    if data[:4] != b"\x7fELF":
        raise ExposureError("executable is not an ELF file")
    if len(data) < 64:
        raise ExposureError("truncated ELF header")
    if data[4] != 2:
        raise ExposureError("only ELF64 executables are supported")
    if data[5] != 1:
        raise ExposureError("only little-endian ELF executables are supported")
    if struct.unpack_from("<H", data, 18)[0] != ELF_MACHINE_X86_64:
        raise ExposureError("only x86-64 ELF executables are supported")
    table_offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size, count = struct.unpack_from("<HH", data, 58)
    if (
        entry_size != 64
        or count == 0
        or count > MAX_SECTIONS
        or table_offset + count * entry_size > len(data)
    ):
        raise ExposureError("malformed ELF section header table")
    sections = []
    for index in range(count):
        _name, kind, flags, address, offset, size, *_rest = struct.unpack_from(
            "<IIQQQQIIQQ", data, table_offset + index * entry_size
        )
        if kind not in (SHT_NULL, SHT_NOBITS) and offset + size > len(data):
            raise ExposureError(f"ELF section {index} is outside the file")
        sections.append(Section(kind, flags, address, offset, size))
    return ElfImage(data, tuple(sections))


def read_c_string(image: ElfImage, address: int, limit: int = MAX_NAME_LENGTH) -> str:
    matches = [
        section
        for section in image.sections
        if section.kind not in (SHT_NULL, SHT_NOBITS)
        and section.flags & SHF_ALLOC
        and not section.flags & SHF_TLS
        and section.address <= address < section.address + section.size
    ]
    if not matches:
        raise ExposureError(f"address {address:#x} is not inside a file-backed section")
    if len(matches) > 1:
        raise ExposureError(
            f"address {address:#x} is inside more than one file-backed section"
        )
    section = matches[0]
    start = section.offset + address - section.address
    end = min(section.offset + section.size, start + limit + 1)
    terminator = image.data.find(b"\0", start, end)
    if terminator < 0:
        raise ExposureError(
            f"string at {address:#x} is not NUL-terminated within {limit} bytes "
            "inside its section"
        )
    value = image.data[start:terminator]
    if not value or any(byte < 0x20 or byte > 0x7E for byte in value):
        raise ExposureError(
            f"string at {address:#x} is not a nonempty printable ASCII string"
        )
    return value.decode("ascii")


def parse_lookup_relocations(output: str) -> list[tuple[int, str, str]]:
    relocations = []
    for line in output.splitlines():
        fields = line.split()
        if not any(field.split("@", 1)[0] in LOOKUP_FUNCTIONS for field in fields):
            continue
        match = RELOCATION_RE.fullmatch(line.strip())
        if match is None:
            raise ExposureError(f"unrecognized readelf relocation line: {line!r}")
        function = match.group(3).split("@", 1)[0]
        if function in LOOKUP_FUNCTIONS:
            relocations.append((int(match.group(1), 16), match.group(2), function))
    return sorted(relocations)


def parse_lookup_slots(output: str) -> dict[int, str]:
    return {
        offset: function
        for offset, kind, function in parse_lookup_relocations(output)
        if kind in SLOT_RELOCATIONS
    }


def split_instruction(text: str) -> tuple[str, str, int | None, str | None]:
    """Return an objdump instruction's mnemonic, operands, and comment target."""

    comment_address: int | None = None
    comment_symbol: str | None = None
    if "#" in text:
        comment = COMMENT_RE.search(text)
        if comment is not None:
            comment_address = int(comment.group(1), 16)
            comment_symbol = comment.group(2)
            text = text[: comment.start()]
    tokens = text.split()
    index = 0
    while index < len(tokens) - 1 and (
        tokens[index] in INSTRUCTION_PREFIXES or tokens[index].startswith("rex")
    ):
        index += 1
    if not tokens:
        return "", "", comment_address, comment_symbol
    return tokens[index], " ".join(tokens[index + 1 :]), comment_address, comment_symbol


def split_operands(operands: str) -> list[str]:
    values = []
    depth = 0
    current = []
    for character in operands:
        if character == "," and depth == 0:
            values.append("".join(current))
            current = []
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        current.append(character)
    if current:
        values.append("".join(current))
    return [value.strip() for value in values]


def writes_rsi(mnemonic: str, operands: str) -> bool:
    if STRING_OPERATION_RE.fullmatch(mnemonic):
        return True
    if "si" not in operands:
        return False
    values = split_operands(operands)
    if mnemonic.startswith(MULTI_WRITE_PREFIXES):
        return any(value in RSI_REGISTERS for value in values)
    if not values or values[-1] not in RSI_REGISTERS:
        return False
    return not (
        mnemonic.startswith(READ_ONLY_PREFIXES) or mnemonic in BIT_TEST_MNEMONICS
    )


def infer_name(
    window: Iterable[tuple[int, str, str, int | None]],
) -> tuple[int | None, int | None, str | None]:
    """Return the name address, the lea that set it, and any review reason."""

    for address, mnemonic, operands, comment_address in reversed(list(window)):
        if not writes_rsi(mnemonic, operands):
            continue
        if (
            mnemonic in ("lea", "leaq")
            and RIP_NAME_LEA_RE.fullmatch(operands)
            and comment_address is not None
        ):
            return comment_address, address, None
        return None, None, "name_argument_not_constant"
    return None, None, "name_argument_not_found"


def find_lookup_sites(
    lines: Iterable[str], slots: Mapping[int, str]
) -> list[LookupSite]:
    """Locate dlsym and dlvsym uses in `objdump -d --no-show-raw-insn` output."""

    window: deque[tuple[int, str, str, int | None]] = deque(maxlen=LOOKBACK_LIMIT)
    targets = array("Q")
    sites: list[LookupSite] = []
    name_instructions: dict[int, int] = {}
    in_plt_stub = False
    instructions = 0
    for line in lines:
        line = line.rstrip("\n")
        match = INSTRUCTION_RE.fullmatch(line)
        if match is None:
            label = LABEL_RE.fullmatch(line)
            if label is not None:
                in_plt_stub = label.group(2).endswith("@plt")
                window.clear()
            elif line.startswith("Disassembly of section "):
                in_plt_stub = False
                window.clear()
            elif line.strip() == "...":
                window.clear()
            continue
        instructions += 1
        address = int(match.group(1), 16)
        mnemonic, operands, comment_address, comment_symbol = split_instruction(
            match.group(2)
        )
        branch = mnemonic.startswith(("j", "call", "loop"))
        direct = DIRECT_TARGET_RE.fullmatch(operands) if branch else None
        if direct is not None:
            targets.append(int(direct.group(1), 16))
        if not in_plt_stub:
            function: str | None = None
            via = ""
            if branch:
                if direct is not None and direct.group(2) in PLT_SYMBOLS:
                    function, via = PLT_SYMBOLS[direct.group(2)], "plt"
                elif (
                    RIP_SLOT_RE.fullmatch(operands)
                    and comment_address is not None
                    and comment_address in slots
                ):
                    function, via = slots[comment_address], "got"
                if function is not None:
                    name_address, name_instruction, reason = infer_name(window)
                    if name_instruction is not None:
                        name_instructions[address] = name_instruction
                    instruction = {"callq": "call", "jmpq": "jmp"}.get(
                        mnemonic, mnemonic
                    )
                    sites.append(
                        LookupSite(
                            address, instruction, via, function, name_address, reason
                        )
                    )
            elif comment_symbol in PLT_SYMBOLS:
                sites.append(
                    LookupSite(
                        address,
                        "reference",
                        "plt",
                        PLT_SYMBOLS[comment_symbol],
                        None,
                        "lookup_address_taken",
                    )
                )
            elif comment_address is not None and comment_address in slots:
                sites.append(
                    LookupSite(
                        address,
                        "reference",
                        "got",
                        slots[comment_address],
                        None,
                        "lookup_address_taken",
                    )
                )
        if not mnemonic or mnemonic in STOP_MNEMONICS:
            window.clear()
        else:
            window.append((address, mnemonic, operands, comment_address))
    if instructions == 0:
        raise ExposureError("objdump produced no instructions")
    joined = branch_joined_sites(name_instructions, targets)
    return sorted(
        (
            LookupSite(
                site.site,
                site.instruction,
                site.via,
                site.function,
                None,
                "branch_target_between_name_and_call",
            )
            if site.site in joined
            else site
            for site in sites
        ),
        key=lambda site: site.site,
    )


def branch_joined_sites(
    name_instructions: Mapping[int, int], targets: Iterable[int]
) -> set[int]:
    """Return sites a direct branch can reach after their name was set."""

    if not name_instructions:
        return set()
    low = min(name_instructions.values())
    high = max(name_instructions)
    joined = set()
    for target in targets:
        if low < target <= high:
            joined.update(
                site
                for site, name_instruction in name_instructions.items()
                if name_instruction < target <= site
            )
    return joined


def lookup_entry(image: ElfImage, site: LookupSite) -> dict[str, Any]:
    name: str | None = None
    reason = site.review_reason
    if site.name_address is not None and reason is None:
        try:
            name = read_c_string(image, site.name_address)
        except ExposureError:
            reason = "name_address_unreadable"
    return {
        "site": f"{site.site:#x}",
        "instruction": site.instruction,
        "via": site.via,
        "function": site.function,
        "name": name,
        "name_address": (
            f"{site.name_address:#x}" if site.name_address is not None else None
        ),
        "review_required": reason is not None,
        "review_reason": reason,
    }


def build_report(
    path: Path,
    *,
    image: str,
    executable: str,
    relocations: str,
    disassembly: Iterable[str],
) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ExposureError(f"cannot read executable {path}: {error}") from error
    elf = parse_elf_image(data)
    try:
        metadata = ADVISORY_BASELINES.parse_elf(path)
    except (OSError, ValueError, struct.error) as error:
        raise ExposureError(f"cannot read ELF dynamic metadata: {error}") from error
    relocation_facts = parse_lookup_relocations(relocations)
    slots = {
        offset: function
        for offset, kind, function in relocation_facts
        if kind in SLOT_RELOCATIONS
    }
    sites = find_lookup_sites(disassembly, slots)
    lookups = [lookup_entry(elf, site) for site in sites]
    lookup_relocations = [
        {
            "offset": f"{offset:#x}",
            "type": kind,
            "function": function,
            "review_required": kind not in SLOT_RELOCATIONS,
        }
        for offset, kind, function in relocation_facts
    ]
    undefined = metadata.undefined_dynamic_symbols
    located = {site.function for site in sites}
    unlocated = sorted((LOOKUP_FUNCTIONS & undefined) - located)
    review_required_count = (
        sum(entry["review_required"] for entry in lookups)
        + sum(entry["review_required"] for entry in lookup_relocations)
        + len(unlocated)
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "purpose": "review_only",
        "image": image,
        "executable": executable,
        "executable_sha256": f"sha256:{hashlib.sha256(data).hexdigest()}",
        "interpreter": metadata.interpreter,
        "needed": list(metadata.needed),
        "dynamic_loading_imports": sorted(DYNAMIC_LOADING_APIS & undefined),
        "undefined_dynamic_symbols": sorted(undefined),
        "lookup_relocations": lookup_relocations,
        "dynamic_lookups": lookups,
        "unlocated_lookup_imports": unlocated,
        "review_required_count": review_required_count,
    }


def require_binutils() -> None:
    missing = [tool for tool in BINUTILS if shutil.which(tool) is None]
    if missing:
        raise ExposureError(
            f"ELF exposure analysis requires binutils; missing: {', '.join(missing)}"
        )


def tool_environment() -> dict[str, str]:
    return {**os.environ, "LC_ALL": "C"}


def tool_failure(tool: str, status: int, detail: str) -> ExposureError:
    detail = detail.strip()[-MAX_TOOL_DETAIL:]
    return ExposureError(f"{tool} failed with exit status {status}: {detail}")


def analyze_executable(path: Path, *, image: str, executable: str) -> dict[str, Any]:
    require_binutils()
    relocations = subprocess.run(
        ["readelf", "-r", "-W", str(path)],
        check=False,
        capture_output=True,
        encoding="utf-8",
        env=tool_environment(),
        errors="replace",
    )
    if relocations.returncode != 0:
        raise tool_failure("readelf", relocations.returncode, relocations.stderr)
    with tempfile.TemporaryFile() as errors:

        def objdump_failure(status: int) -> ExposureError:
            errors.seek(0)
            return tool_failure(
                "objdump", status, errors.read().decode("utf-8", errors="replace")
            )

        with subprocess.Popen(
            ["objdump", "-d", "--no-show-raw-insn", str(path)],
            encoding="utf-8",
            env=tool_environment(),
            errors="replace",
            stderr=errors,
            stdout=subprocess.PIPE,
        ) as process:
            assert process.stdout is not None
            try:
                report = build_report(
                    path,
                    image=image,
                    executable=executable,
                    relocations=relocations.stdout,
                    disassembly=process.stdout,
                )
            except BaseException as error:
                process.kill()
                status = process.wait()
                # An objdump that already exited unsuccessfully explains a
                # truncated disassembly better than the parse failure does.
                if isinstance(error, ExposureError) and status > 0:
                    raise objdump_failure(status) from error
                raise
            status = process.wait()
        if status != 0:
            raise objdump_failure(status)
    return report


def archive_parts(path: str) -> list[str]:
    return [part for part in path.split("/") if part not in ("", ".")]


def archive_index(
    archive: tarfile.TarFile,
) -> tuple[dict[str, tarfile.TarInfo], frozenset[str]]:
    members: dict[str, tarfile.TarInfo] = {}
    directories: set[str] = set()
    for member in archive.getmembers():
        parts = archive_parts(member.name)
        if ".." in parts:
            raise ExposureError(
                f"archive member name {member.name!r} contains a parent-directory "
                "component"
            )
        if not parts:
            continue
        members["/".join(parts)] = member
        for index in range(1, len(parts)):
            directories.add("/".join(parts[:index]))
    return members, frozenset(directories)


def resolve_archive_member(
    archive: tarfile.TarFile, path: str, max_hops: int = MAX_SYMLINK_HOPS
) -> tarfile.TarInfo:
    """Resolve an absolute image path to a regular member without leaving the archive."""

    if not path.startswith("/"):
        raise ExposureError(f"executable path {path!r} must be absolute")
    members, directories = archive_index(archive)
    pending = archive_parts(path)
    resolved: list[str] = []
    hops = 0
    while pending:
        part = pending.pop(0)
        if part == "..":
            if not resolved:
                raise ExposureError(f"{path} escapes the archive root")
            resolved.pop()
            continue
        name = "/".join([*resolved, part])
        member = members.get(name)
        if member is not None and member.issym():
            hops += 1
            if hops > max_hops:
                raise ExposureError(f"{path} exceeds {max_hops} symlink hops")
            if member.linkname.startswith("/"):
                resolved = []
            pending = archive_parts(member.linkname) + pending
            continue
        if member is None and name not in directories:
            raise ExposureError(f"{path} does not exist in the archive: {name}")
        if pending and member is not None and not member.isdir():
            raise ExposureError(f"{path} traverses {name}, which is not a directory")
        resolved.append(part)
    member = members.get("/".join(resolved))
    if member is None or not member.isreg():
        raise ExposureError(f"{path} does not resolve to a regular file in the archive")
    return member


def copy_archive_file(archive_path: Path, path: str, destination: Path) -> None:
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            member = resolve_archive_member(archive, path)
            source = archive.extractfile(member)
            if source is None:
                raise ExposureError(f"{path} has no readable content in the archive")
            with source, destination.open("wb") as target:
                shutil.copyfileobj(source, target, 1024 * 1024)
        copied = destination.stat().st_size
    except (OSError, tarfile.TarError) as error:
        raise ExposureError(
            f"cannot read {path} from {archive_path}: {error}"
        ) from error
    if copied != member.size:
        raise ExposureError(
            f"{path} copied {copied} bytes from {archive_path}; expected {member.size}"
        )


def report_archive_executable(
    archive_path: Path, executable: str, *, image: str, temporary: Path
) -> dict[str, Any]:
    descriptor, name = tempfile.mkstemp(prefix="executable.", dir=temporary)
    os.close(descriptor)
    copy = Path(name)
    try:
        copy_archive_file(archive_path, executable, copy)
        return analyze_executable(copy, image=image, executable=executable)
    finally:
        copy.unlink(missing_ok=True)


def render_report(report: Mapping[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs-tar", required=True, type=Path)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--image", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        with tempfile.TemporaryDirectory(
            prefix="registry-stack-image-exposure."
        ) as temporary:
            report = report_archive_executable(
                args.rootfs_tar,
                args.executable,
                image=args.image,
                temporary=Path(temporary),
            )
    except ExposureError as error:
        print(f"image exposure report failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(render_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
