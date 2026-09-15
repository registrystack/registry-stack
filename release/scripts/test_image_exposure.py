#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
from pathlib import Path


SCRIPT = Path(__file__).with_name("image_exposure.py")

SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_NOBITS = 8
SHT_DYNSYM = 11
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_TLS = 0x400

RODATA_ADDRESS = 0x2000
RODATA = b"getrandom\0__pthread_get_minstack\0unterminated"
DYNSTR = b"\0libc.so.6\0dlsym\0dladdr\0free\0dlvsym\0"
READELF_FIXTURE = """\

Relocation section '.rela.dyn' at offset 0x5a8 contains 4 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000003db8  0000000000000008 R_X86_64_RELATIVE                         1130
0000000000003fc0  0000000400000006 R_X86_64_GLOB_DAT      0000000000000000 dlsym@GLIBC_2.34 + 0
0000000000003fc8  0000000500000006 R_X86_64_GLOB_DAT      0000000000000000 dladdr@GLIBC_2.34 + 0
0000000000003fe8  0000000500000001 R_X86_64_64            0000000000000000 dlvsym@GLIBC_2.34 + 0

Relocation section '.rela.plt' at offset 0x650 contains 2 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000003fd0  0000000200000007 R_X86_64_JUMP_SLOT     0000000000000000 dlsym@GLIBC_2.34 + 0
0000000000003fd8  0000000300000007 R_X86_64_JUMP_SLOT     0000000000000000 dlvsym + 0
"""
SLOTS = {0x3FC0: "dlsym", 0x3FD0: "dlsym", 0x3FD8: "dlvsym"}


def load_module():
    spec = importlib.util.spec_from_file_location("image_exposure", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = load_module()


def elf_file(
    sections: list[dict],
    *,
    interpreter: str | None = None,
    machine: int = 62,
    elf_class: int = 2,
    byte_order: int = 1,
) -> bytes:
    interpreter_bytes = interpreter.encode() + b"\0" if interpreter else b""
    cursor = 64 + (56 if interpreter else 0)
    interpreter_offset = cursor
    cursor += len(interpreter_bytes)
    contents = bytearray(interpreter_bytes)
    headers = [struct.pack("<IIQQQQIIQQ", *([0] * 10))]
    for section in sections:
        content = section.get("content", b"")
        headers.append(
            struct.pack(
                "<IIQQQQIIQQ",
                0,
                section["type"],
                section.get("flags", 0),
                section.get("address", 0),
                cursor,
                section.get("size", len(content)),
                section.get("link", 0),
                0,
                1,
                section.get("entsize", 0),
            )
        )
        contents.extend(content)
        cursor += len(content)
    ident = b"\x7fELF" + bytes([elf_class, byte_order, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3,
        machine,
        1,
        0,
        64 if interpreter else 0,
        cursor,
        0,
        64,
        56,
        1 if interpreter else 0,
        64,
        len(headers),
        0,
    )
    program = b""
    if interpreter:
        program = struct.pack(
            "<IIQQQQQQ",
            3,
            4,
            interpreter_offset,
            interpreter_offset,
            interpreter_offset,
            len(interpreter_bytes),
            len(interpreter_bytes),
            1,
        )
    return header + program + bytes(contents) + b"".join(headers)


def dynamic_executable(**overrides) -> bytes:
    symbols = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    for name_offset in (11, 17, 24):
        symbols += struct.pack("<IBBHQQ", name_offset, 0x12, 0, 0, 0, 0)
    dynamic = struct.pack("<qQ", 1, 1) + struct.pack("<qQ", 0, 0)
    sections = [
        {"type": SHT_STRTAB, "flags": SHF_ALLOC, "address": 0x400, "content": DYNSTR},
        {
            "type": SHT_DYNSYM,
            "flags": SHF_ALLOC,
            "address": 0x500,
            "content": symbols,
            "link": 1,
            "entsize": 24,
        },
        {
            "type": SHT_DYNAMIC,
            "flags": SHF_ALLOC | SHF_WRITE,
            "address": 0x600,
            "content": dynamic,
            "link": 1,
            "entsize": 16,
        },
        {
            "type": SHT_PROGBITS,
            "flags": SHF_ALLOC,
            "address": RODATA_ADDRESS,
            "content": RODATA,
        },
        {
            "type": SHT_NOBITS,
            "flags": SHF_ALLOC | SHF_WRITE,
            "address": 0x3000,
            "size": 0x100,
        },
        {
            "type": SHT_PROGBITS,
            "flags": SHF_ALLOC | SHF_WRITE | SHF_TLS,
            "address": 0x4000,
            "content": b"tls\0",
        },
        {
            "type": SHT_PROGBITS,
            "flags": 0,
            "address": 0,
            "content": b"comment\0",
        },
    ]
    options = {"interpreter": "/lib64/ld-linux-x86-64.so.2", **overrides}
    return elf_file(sections, **options)


def row(address: int, text: str) -> str:
    return f"{address:8x}:\t{text}"


def label(address: int, name: str) -> str:
    return f"{address:016x} <{name}>:"


def disassembly(*lines: str) -> list[str]:
    return [
        "",
        "fixture:     file format elf64-x86-64",
        "",
        "",
        "Disassembly of section .plt.sec:",
        "",
        label(0x1050, "dlsym@plt"),
        row(0x1050, "endbr64"),
        row(0x1054, "bnd jmp *0x2f75(%rip)        # 3fd0 <dlsym@GLIBC_2.34>"),
        row(0x105B, "nopl   0x0(%rax,%rax,1)"),
        "",
        label(0x1060, "dlvsym@plt"),
        row(0x1060, "endbr64"),
        row(0x1064, "bnd jmp *0x2f6d(%rip)        # 3fd8 <dlvsym@GLIBC_2.34>"),
        row(0x106B, "nopl   0x0(%rax,%rax,1)"),
        "",
        "Disassembly of section .text:",
        "",
        *lines,
    ]


def lookup(sites, address: int):
    matches = [site for site in sites if site.site == address]
    if len(matches) != 1:
        raise AssertionError(f"expected one site at {address:#x}, got {sites!r}")
    return matches[0]


class RelocationParserTest(unittest.TestCase):
    def test_lookup_slots_come_from_glob_dat_and_jump_slot_relocations(self) -> None:
        self.assertEqual(SLOTS, MODULE.parse_lookup_slots(READELF_FIXTURE))

    def test_every_lookup_relocation_is_reported(self) -> None:
        self.assertEqual(
            [
                (0x3FC0, "R_X86_64_GLOB_DAT", "dlsym"),
                (0x3FD0, "R_X86_64_JUMP_SLOT", "dlsym"),
                (0x3FD8, "R_X86_64_JUMP_SLOT", "dlvsym"),
                (0x3FE8, "R_X86_64_64", "dlvsym"),
            ],
            MODULE.parse_lookup_relocations(READELF_FIXTURE),
        )


class DisassemblyParserTest(unittest.TestCase):
    def sites(self, *lines: str):
        return MODULE.find_lookup_sites(disassembly(*lines), SLOTS)

    def test_plt_call_with_constant_rip_relative_name(self) -> None:
        site = lookup(
            self.sites(
                label(0x1100, "plt_call"),
                row(0x1100, "endbr64"),
                row(0x1104, "lea    0xefd(%rip),%rsi        # 2008 <_IO_stdin_used+0x8>"),
                row(0x110B, "xor    %edi,%edi"),
                row(0x110D, "call   1050 <dlsym@plt>"),
                row(0x1112, "ret"),
            ),
            0x110D,
        )
        self.assertEqual(
            ("call", "plt", "dlsym", 0x2008, None),
            (site.instruction, site.via, site.function, site.name_address, site.review_reason),
        )

    def test_plt_tail_jump_is_a_lookup_site(self) -> None:
        site = lookup(
            self.sites(
                label(0x1120, "plt_tail"),
                row(0x1120, "lea    0xed9(%rip),%rsi        # 2000"),
                row(0x1127, "xor    %edi,%edi"),
                row(0x1129, "jmp    1050 <dlsym@plt>"),
            ),
            0x1129,
        )
        self.assertEqual(("jmp", "plt", 0x2000), (site.instruction, site.via, site.name_address))

    def test_got_indirect_call_matches_the_glob_dat_slot_not_the_symbol_comment(self) -> None:
        sites = self.sites(
            row(0x777A9F, "int3"),
            row(0x777AA0, "push   %rbx"),
            row(0x777AA1, "lea    -0x5f2672(%rip),%rsi        # 2000 <malloc@plt-0x129be9a>"),
            row(0x777AA8, "xor    %edi,%edi"),
            row(0x777AAA, "call   *0x9e84f0(%rip)        # 3fc0 <dladdr@plt+0x394a0>"),
            row(0x777AB0, "test   %rax,%rax"),
            row(0x777AB3, "call   *0x9e84f0(%rip)        # 3fc8 <dlsym@plt+0x10>"),
        )
        self.assertEqual(1, len(sites))
        site = lookup(sites, 0x777AAA)
        self.assertEqual(("call", "got", "dlsym", 0x2000), (site.instruction, site.via, site.function, site.name_address))

    def test_bnd_and_notrack_prefixed_indirect_jump_through_slot(self) -> None:
        site = lookup(
            self.sites(
                row(0x2000, "lea    0x1(%rip),%rsi        # 2000"),
                row(0x2007, "notrack jmp *0x1fb3(%rip)        # 3fd0 <x>"),
            ),
            0x2007,
        )
        self.assertEqual(("jmp", "got", 0x2000), (site.instruction, site.via, site.name_address))

    def test_plt_stubs_are_not_reported_as_sites(self) -> None:
        self.assertEqual([], self.sites(row(0x1100, "ret")))

    def test_runtime_name_argument_requires_review(self) -> None:
        site = lookup(
            self.sites(
                row(0x11513E4, "ret"),
                row(0x11513E5, "int3"),
                row(0x11513F0, "mov    %rsi,%rdi"),
                row(0x11513F3, "mov    %rdx,%rsi"),
                row(0x11513F6, "jmp    1050 <dlsym@plt>"),
            ),
            0x11513F6,
        )
        self.assertIsNone(site.name_address)
        self.assertEqual("name_argument_not_constant", site.review_reason)

    def test_missing_name_write_before_a_previous_call_requires_review(self) -> None:
        site = lookup(
            self.sites(
                row(0x1200, "lea    0xe00(%rip),%rsi        # 2000"),
                row(0x1207, "call   1300 <helper>"),
                row(0x120C, "xor    %edi,%edi"),
                row(0x120E, "call   1050 <dlsym@plt>"),
            ),
            0x120E,
        )
        self.assertIsNone(site.name_address)
        self.assertEqual("name_argument_not_found", site.review_reason)

    def test_intervening_rsi_writes_null_the_name(self) -> None:
        for write in (
            "mov    %rax,%rsi",
            "xor    %esi,%esi",
            "pop    %rsi",
            "movzbl %al,%esi",
            "xchg   %rsi,%rax",
            "rep movsb %ds:(%rsi),%es:(%rdi)",
            "add    $0x1,%rsi",
            "cmove  %rbx,%rsi",
            "lea    0x1(%rip),%esi        # 2000",
        ):
            with self.subTest(write=write):
                site = lookup(
                    self.sites(
                        row(0x1200, "lea    0xe00(%rip),%rsi        # 2000"),
                        row(0x1207, write),
                        row(0x120B, "call   1050 <dlsym@plt>"),
                    ),
                    0x120B,
                )
                self.assertIsNone(site.name_address)
                self.assertEqual("name_argument_not_constant", site.review_reason)

    def test_reads_of_rsi_do_not_null_the_name(self) -> None:
        site = lookup(
            self.sites(
                row(0x1200, "lea    0xe00(%rip),%rsi        # 2000"),
                row(0x1207, "mov    %rsi,%rdi"),
                row(0x120A, "push   %rsi"),
                row(0x120B, "cmp    %rsi,%rax"),
                row(0x120E, "test   %esi,%esi"),
                row(0x1210, "mov    %rax,(%rsi)"),
                row(0x1213, "mov    %rax,0x8(%rsi,%rdi,1)"),
                row(0x1218, "jne    1230 <elsewhere>"),
                row(0x121A, "call   1050 <dlsym@plt>"),
            ),
            0x121A,
        )
        self.assertEqual((0x2000, None), (site.name_address, site.review_reason))

    def test_lookback_stops_at_a_function_boundary(self) -> None:
        site = lookup(
            self.sites(
                label(0x1200, "previous"),
                row(0x1200, "lea    0xe00(%rip),%rsi        # 2000"),
                "",
                label(0x1210, "next"),
                row(0x1210, "xor    %edi,%edi"),
                row(0x1212, "call   1050 <dlsym@plt>"),
            ),
            0x1212,
        )
        self.assertEqual("name_argument_not_found", site.review_reason)

    def test_lookback_is_bounded(self) -> None:
        padding = [
            row(0x1300 + index, "nop") for index in range(MODULE.LOOKBACK_LIMIT)
        ]
        site = lookup(
            self.sites(
                row(0x12F0, "lea    0xe00(%rip),%rsi        # 2000"),
                *padding,
                row(0x1400, "call   1050 <dlsym@plt>"),
            ),
            0x1400,
        )
        self.assertEqual("name_argument_not_found", site.review_reason)

    def test_branch_target_between_name_and_call_requires_review(self) -> None:
        for target in (0x1207, 0x1209):
            with self.subTest(target=target):
                site = lookup(
                    self.sites(
                        row(0x1200, "lea    0xe00(%rip),%rsi        # 2000"),
                        row(0x1207, "xor    %edi,%edi"),
                        row(0x1209, "call   1050 <dlsym@plt>"),
                        row(0x120E, "ret"),
                        row(0x1210, "mov    %rbx,%rsi"),
                        row(0x1213, f"jmp    {target:x} <x>"),
                    ),
                    0x1209,
                )
                self.assertIsNone(site.name_address)
                self.assertEqual(
                    "branch_target_between_name_and_call", site.review_reason
                )

    def test_branch_to_the_name_instruction_itself_keeps_the_name(self) -> None:
        site = lookup(
            self.sites(
                row(0x11F0, "je     1200 <x>"),
                row(0x11F2, "jmp    1300 <x>"),
                row(0x1200, "lea    0xe00(%rip),%rsi        # 2000"),
                row(0x1207, "call   1050 <dlsym@plt>"),
            ),
            0x1207,
        )
        self.assertEqual((0x2000, None), (site.name_address, site.review_reason))

    def test_dlvsym_sites_are_reported(self) -> None:
        site = lookup(
            self.sites(
                row(0x1500, "lea    0xb00(%rip),%rdx        # 2010"),
                row(0x1507, "lea    0xaf2(%rip),%rsi        # 2000"),
                row(0x150E, "call   1060 <dlvsym@plt>"),
            ),
            0x150E,
        )
        self.assertEqual(("dlvsym", "plt", 0x2000), (site.function, site.via, site.name_address))

    def test_conditional_tail_jump_is_a_lookup_site(self) -> None:
        site = lookup(
            self.sites(
                row(0x1500, "lea    0xb00(%rip),%rsi        # 2000"),
                row(0x1507, "test   %rax,%rax"),
                row(0x150A, "jne    1050 <dlsym@plt>"),
            ),
            0x150A,
        )
        self.assertEqual(("jne", "plt", 0x2000), (site.instruction, site.via, site.name_address))

    def test_address_taken_lookup_is_a_review_reference(self) -> None:
        sites = self.sites(
            row(0x1600, "mov    0x29b9(%rip),%rax        # 3fc0 <x>"),
            row(0x1607, "lea    -0x5be(%rip),%rcx        # 1050 <dlsym@plt>"),
            row(0x160E, "call   *%rax"),
        )
        self.assertEqual(
            [
                (0x1600, "reference", "got", "dlsym", "lookup_address_taken"),
                (0x1607, "reference", "plt", "dlsym", "lookup_address_taken"),
            ],
            [
                (site.site, site.instruction, site.via, site.function, site.review_reason)
                for site in sites
            ],
        )

    def test_empty_disassembly_is_refused(self) -> None:
        with self.assertRaisesRegex(MODULE.ExposureError, "no instructions"):
            MODULE.find_lookup_sites(["", "fixture:     file format elf64-x86-64"], SLOTS)


class ElfImageTest(unittest.TestCase):
    def test_reads_nul_terminated_strings_through_section_headers(self) -> None:
        image = MODULE.parse_elf_image(dynamic_executable())
        self.assertEqual("getrandom", MODULE.read_c_string(image, RODATA_ADDRESS))
        self.assertEqual(
            "__pthread_get_minstack", MODULE.read_c_string(image, RODATA_ADDRESS + 10)
        )

    def test_refuses_unmapped_nobits_tls_and_unallocated_addresses(self) -> None:
        image = MODULE.parse_elf_image(dynamic_executable())
        for address in (0x9000, 0x3010, 0x4000, 0x0, RODATA_ADDRESS + len(RODATA)):
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(MODULE.ExposureError, "file-backed"):
                    MODULE.read_c_string(image, address)

    def test_refuses_unterminated_strings(self) -> None:
        image = MODULE.parse_elf_image(dynamic_executable())
        with self.assertRaisesRegex(MODULE.ExposureError, "not NUL-terminated"):
            MODULE.read_c_string(image, RODATA_ADDRESS + len(RODATA) - 4)

    def test_refuses_strings_longer_than_the_bound(self) -> None:
        image = MODULE.parse_elf_image(dynamic_executable())
        with self.assertRaisesRegex(MODULE.ExposureError, "not NUL-terminated"):
            MODULE.read_c_string(image, RODATA_ADDRESS, limit=4)

    def test_refuses_empty_and_non_printable_strings(self) -> None:
        sections = [
            {
                "type": SHT_PROGBITS,
                "flags": SHF_ALLOC,
                "address": 0x2000,
                "content": b"\0bad\x01\0",
            }
        ]
        image = MODULE.parse_elf_image(elf_file(sections))
        for address in (0x2000, 0x2001):
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(MODULE.ExposureError, "printable"):
                    MODULE.read_c_string(image, address)

    def test_refuses_sections_that_extend_past_the_file(self) -> None:
        sections = [
            {
                "type": SHT_PROGBITS,
                "flags": SHF_ALLOC,
                "address": 0x2000,
                "content": b"name\0",
                "size": 0x10000,
            }
        ]
        with self.assertRaisesRegex(MODULE.ExposureError, "outside the file"):
            MODULE.parse_elf_image(elf_file(sections))

    def test_refuses_overlapping_file_backed_sections(self) -> None:
        sections = [
            {"type": SHT_PROGBITS, "flags": SHF_ALLOC, "address": 0x2000, "content": b"one\0"},
            {"type": SHT_PROGBITS, "flags": SHF_ALLOC, "address": 0x2002, "content": b"two\0"},
        ]
        image = MODULE.parse_elf_image(elf_file(sections))
        with self.assertRaisesRegex(MODULE.ExposureError, "more than one"):
            MODULE.read_c_string(image, 0x2002)

    def test_refuses_other_elf_classes_byte_orders_and_machines(self) -> None:
        valid = dynamic_executable()
        cases = {
            "not an ELF": b"\x7fNOPE" + valid[5:],
            "ELF64": valid[:4] + b"\x01" + valid[5:],
            "little-endian": valid[:5] + b"\x02" + valid[6:],
            "x86-64": dynamic_executable(machine=183),
            "truncated": valid[:40],
        }
        for message, data in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(MODULE.ExposureError, message):
                    MODULE.parse_elf_image(data)


class ReportTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.executable = self.root / "service"
        self.executable.write_bytes(dynamic_executable())

    def lines(self) -> list[str]:
        return disassembly(
            row(0x777AA1, "lea    -0x5f2672(%rip),%rsi        # 200a <x>"),
            row(0x777AA8, "xor    %edi,%edi"),
            row(0x777AAA, "call   *0x9e84f0(%rip)        # 3fc0 <dladdr@plt+0x394a0>"),
            row(0x777AB0, "ret"),
            row(0x777AC0, "lea    -0x5f2672(%rip),%rsi        # 2000 <x>"),
            row(0x777AC7, "jmp    1050 <dlsym@plt>"),
            row(0x777AD0, "mov    %rdx,%rsi"),
            row(0x777AD3, "jmp    1050 <dlsym@plt>"),
            row(0x777AE0, "lea    0x1(%rip),%rsi        # 9000"),
            row(0x777AE7, "jmp    1050 <dlsym@plt>"),
        )

    def test_report_is_deterministic_and_review_only(self) -> None:
        report = MODULE.build_report(
            self.executable,
            image="relay",
            executable="/usr/local/bin/relay",
            relocations=READELF_FIXTURE,
            disassembly=iter(self.lines()),
        )
        self.assertEqual(
            {
                "schema_version": "registry-stack.image-exposure.v1",
                "purpose": "review_only",
                "image": "relay",
                "executable": "/usr/local/bin/relay",
                "executable_sha256": "sha256:"
                + hashlib.sha256(self.executable.read_bytes()).hexdigest(),
                "interpreter": "/lib64/ld-linux-x86-64.so.2",
                "needed": ["libc.so.6"],
                "dynamic_loading_imports": ["dladdr", "dlsym"],
                "undefined_dynamic_symbols": ["dladdr", "dlsym", "free"],
                "lookup_relocations": [
                    {"offset": "0x3fc0", "type": "R_X86_64_GLOB_DAT", "function": "dlsym", "review_required": False},
                    {"offset": "0x3fd0", "type": "R_X86_64_JUMP_SLOT", "function": "dlsym", "review_required": False},
                    {"offset": "0x3fd8", "type": "R_X86_64_JUMP_SLOT", "function": "dlvsym", "review_required": False},
                    {"offset": "0x3fe8", "type": "R_X86_64_64", "function": "dlvsym", "review_required": True},
                ],
                "dynamic_lookups": [
                    {
                        "site": "0x777aaa",
                        "instruction": "call",
                        "via": "got",
                        "function": "dlsym",
                        "name": "__pthread_get_minstack",
                        "name_address": "0x200a",
                        "review_required": False,
                        "review_reason": None,
                    },
                    {
                        "site": "0x777ac7",
                        "instruction": "jmp",
                        "via": "plt",
                        "function": "dlsym",
                        "name": "getrandom",
                        "name_address": "0x2000",
                        "review_required": False,
                        "review_reason": None,
                    },
                    {
                        "site": "0x777ad3",
                        "instruction": "jmp",
                        "via": "plt",
                        "function": "dlsym",
                        "name": None,
                        "name_address": None,
                        "review_required": True,
                        "review_reason": "name_argument_not_constant",
                    },
                    {
                        "site": "0x777ae7",
                        "instruction": "jmp",
                        "via": "plt",
                        "function": "dlsym",
                        "name": None,
                        "name_address": "0x9000",
                        "review_required": True,
                        "review_reason": "name_address_unreadable",
                    },
                ],
                "unlocated_lookup_imports": [],
                "review_required_count": 3,
            },
            report,
        )
        rendered = MODULE.render_report(report)
        self.assertTrue(rendered.endswith("}\n"))
        self.assertEqual(report, json.loads(rendered))
        self.assertEqual(
            json.dumps(report, indent=2, sort_keys=True) + "\n", rendered
        )

    def test_imported_lookup_without_a_located_site_requires_review(self) -> None:
        report = MODULE.build_report(
            self.executable,
            image="relay",
            executable="/usr/local/bin/relay",
            relocations="",
            disassembly=disassembly(row(0x1100, "ret")),
        )
        self.assertEqual(["dlsym"], report["unlocated_lookup_imports"])
        self.assertEqual([], report["dynamic_lookups"])
        self.assertEqual(1, report["review_required_count"])

    def fake_tools(
        self,
        *,
        objdump_status: int = 0,
        readelf_status: int = 0,
        objdump_output: bool = True,
    ) -> Path:
        tools = self.root / "tools"
        tools.mkdir()
        (self.root / "readelf.txt").write_text(READELF_FIXTURE, encoding="utf-8")
        (self.root / "objdump.txt").write_text(
            "\n".join(self.lines()) + "\n" if objdump_output else "",
            encoding="utf-8",
        )
        for name, status in (("readelf", readelf_status), ("objdump", objdump_status)):
            script = tools / name
            script.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$*\" >> '{self.root}/{name}.args'\n"
                f"cat '{self.root}/{name}.txt'\n"
                f"if [ {status} -ne 0 ]; then echo '{name} synthetic failure' >&2; fi\n"
                f"exit {status}\n",
                encoding="utf-8",
            )
            script.chmod(0o755)
        return tools

    def search_path(self, tools: Path) -> str:
        return f"{tools}{os.pathsep}{os.environ.get('PATH', '')}"

    def test_analyze_executable_runs_binutils_and_builds_the_report(self) -> None:
        tools = self.fake_tools()
        with unittest.mock.patch.dict(os.environ, {"PATH": self.search_path(tools)}):
            report = MODULE.analyze_executable(
                self.executable, image="relay", executable="/usr/local/bin/relay"
            )
        self.assertEqual(3, report["review_required_count"])
        self.assertEqual(
            f"-r -W {self.executable}",
            (self.root / "readelf.args").read_text(encoding="utf-8").strip(),
        )
        self.assertEqual(
            f"-d --no-show-raw-insn {self.executable}",
            (self.root / "objdump.args").read_text(encoding="utf-8").strip(),
        )

    def test_binutils_failures_are_refused(self) -> None:
        for tool in ("readelf", "objdump"):
            with self.subTest(tool=tool):
                shutil.rmtree(self.root / "tools", ignore_errors=True)
                tools = self.fake_tools(**{f"{tool}_status": 3})
                with unittest.mock.patch.dict(os.environ, {"PATH": self.search_path(tools)}):
                    with self.assertRaisesRegex(
                        MODULE.ExposureError, f"{tool} .*synthetic failure"
                    ):
                        MODULE.analyze_executable(
                            self.executable,
                            image="relay",
                            executable="/usr/local/bin/relay",
                        )

    def test_objdump_failure_is_reported_over_its_truncated_output(self) -> None:
        tools = self.fake_tools(objdump_status=3, objdump_output=False)
        with unittest.mock.patch.dict(os.environ, {"PATH": self.search_path(tools)}):
            with self.assertRaisesRegex(
                MODULE.ExposureError, "objdump failed with exit status 3: .*synthetic failure"
            ):
                MODULE.analyze_executable(
                    self.executable,
                    image="relay",
                    executable="/usr/local/bin/relay",
                )

    def test_missing_binutils_are_refused(self) -> None:
        with unittest.mock.patch.object(MODULE.shutil, "which", return_value=None):
            with self.assertRaisesRegex(MODULE.ExposureError, "objdump.*readelf"):
                MODULE.require_binutils()

    def test_non_elf_executables_are_refused(self) -> None:
        self.executable.write_bytes(b"#!/bin/sh\n")
        with self.assertRaisesRegex(MODULE.ExposureError, "not an ELF"):
            MODULE.build_report(
                self.executable,
                image="relay",
                executable="/usr/local/bin/relay",
                relocations="",
                disassembly=[],
            )


class ArchiveMemberTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / "rootfs.tar"

    def write_archive(self, *entries: tuple[str, str, object]) -> None:
        with tarfile.open(self.archive, "w") as archive:
            for kind, name, value in entries:
                info = tarfile.TarInfo(name)
                data = b""
                if kind == "file":
                    data = value
                    info.size = len(data)
                elif kind == "dir":
                    info.type = tarfile.DIRTYPE
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = value
                elif kind == "hardlink":
                    info.type = tarfile.LNKTYPE
                    info.linkname = value
                elif kind == "fifo":
                    info.type = tarfile.FIFOTYPE
                archive.addfile(info, io.BytesIO(data) if data else None)

    def copy(self, path: str) -> bytes:
        destination = self.root / "copy"
        MODULE.copy_archive_file(self.archive, path, destination)
        return destination.read_bytes()

    def test_reads_a_regular_member_without_directory_entries(self) -> None:
        self.write_archive(("file", "usr/local/bin/relay", b"\x7fELF relay"))
        self.assertEqual(b"\x7fELF relay", self.copy("/usr/local/bin/relay"))

    def test_normalizes_dot_prefixed_member_names(self) -> None:
        self.write_archive(
            ("dir", "./", None),
            ("dir", "./usr/", None),
            ("file", "./usr/local/bin/relay", b"relay"),
        )
        self.assertEqual(b"relay", self.copy("/usr/local/bin/relay"))

    def test_resolves_symlink_chains_inside_the_archive(self) -> None:
        self.write_archive(
            ("dir", "usr", None),
            ("symlink", "usr/local", "../opt/local"),
            ("dir", "opt/local/bin", None),
            ("symlink", "opt/local/bin/relay", "relay-current"),
            ("symlink", "opt/local/bin/relay-current", "/app/releases/relay"),
            ("file", "app/releases/relay", b"resolved"),
        )
        self.assertEqual(b"resolved", self.copy("/usr/local/bin/relay"))

    def test_refuses_paths_and_links_that_escape_the_archive(self) -> None:
        cases = {
            "/../usr/local/bin/relay": [("file", "usr/local/bin/relay", b"x")],
            "/usr/local/bin/escape": [
                ("symlink", "usr/local/bin/escape", "../../../../etc/passwd"),
                ("file", "etc/passwd", b"x"),
            ],
            "/usr/local/bin/absolute": [
                ("symlink", "usr/local/bin/absolute", "/../etc/passwd"),
                ("file", "etc/passwd", b"x"),
            ],
        }
        for path, entries in cases.items():
            with self.subTest(path=path):
                self.write_archive(*entries)
                with self.assertRaisesRegex(MODULE.ExposureError, "escapes"):
                    self.copy(path)

    def test_refuses_relative_request_paths(self) -> None:
        self.write_archive(("file", "usr/local/bin/relay", b"x"))
        with self.assertRaisesRegex(MODULE.ExposureError, "absolute"):
            self.copy("usr/local/bin/relay")

    def test_refuses_archive_member_names_with_parent_components(self) -> None:
        self.write_archive(("file", "usr/../usr/local/bin/relay", b"x"))
        with self.assertRaisesRegex(MODULE.ExposureError, "member name"):
            self.copy("/usr/local/bin/relay")

    def test_refuses_non_regular_final_members(self) -> None:
        cases = {
            "directory": [("dir", "usr/local/bin/relay", None)],
            "implicit directory": [("file", "usr/local/bin/relay/inner", b"x")],
            "hard link": [
                ("file", "usr/local/bin/real", b"x"),
                ("hardlink", "usr/local/bin/relay", "usr/local/bin/real"),
            ],
            "fifo": [("fifo", "usr/local/bin/relay", None)],
            "dangling": [("symlink", "usr/local/bin/relay", "missing")],
        }
        for description, entries in cases.items():
            with self.subTest(description=description):
                self.write_archive(*entries)
                with self.assertRaisesRegex(
                    MODULE.ExposureError, "regular file|does not exist"
                ):
                    self.copy("/usr/local/bin/relay")

    def test_refuses_traversal_through_a_regular_file(self) -> None:
        self.write_archive(("file", "usr/local", b"x"))
        with self.assertRaisesRegex(MODULE.ExposureError, "not a directory"):
            self.copy("/usr/local/bin/relay")

    def test_refuses_missing_members(self) -> None:
        self.write_archive(("file", "usr/local/bin/other", b"x"))
        with self.assertRaisesRegex(MODULE.ExposureError, "does not exist"):
            self.copy("/usr/local/bin/relay")

    def test_symlink_hops_are_bounded(self) -> None:
        self.write_archive(
            ("symlink", "usr/local/bin/relay", "a"),
            ("symlink", "usr/local/bin/a", "b"),
            ("symlink", "usr/local/bin/b", "relay"),
        )
        with self.assertRaisesRegex(MODULE.ExposureError, "symlink"):
            self.copy("/usr/local/bin/relay")


class CommandLineTest(unittest.TestCase):
    def test_command_line_requires_its_arguments(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)], capture_output=True, text=True
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("--rootfs-tar", result.stderr)

    def test_command_line_reports_refusals_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "rootfs.tar"
            with tarfile.open(archive, "w"):
                pass
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--rootfs-tar",
                    str(archive),
                    "--executable",
                    "/usr/local/bin/relay",
                    "--image",
                    "relay",
                ],
                capture_output=True,
                text=True,
            )
        self.assertEqual(1, result.returncode)
        self.assertIn("image exposure report failed", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual("", result.stdout)


@unittest.skipUnless(
    sys.platform.startswith("linux")
    and shutil.which("cc") is not None
    and shutil.which("objdump") is not None
    and shutil.which("readelf") is not None,
    "requires a Linux glibc toolchain with binutils",
)
class LinuxToolchainTest(unittest.TestCase):
    SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>

__attribute__((noinline)) void *lookup_constant(void) {
    return dlsym(RTLD_DEFAULT, "getrandom");
}

__attribute__((noinline)) void *lookup_runtime(const char *name) {
    return dlsym(RTLD_DEFAULT, name);
}

int main(int argc, char **argv) {
    void *constant = lookup_constant();
    void *runtime = lookup_runtime(argc > 1 ? argv[1] : "getpid");
    return constant != NULL && runtime != NULL ? 0 : 1;
}
"""

    def report(self, *flags: str) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "lookup.c"
            source.write_text(self.SOURCE, encoding="utf-8")
            executable = root / "lookup"
            subprocess.run(
                ["cc", "-O2", *flags, str(source), "-o", str(executable)],
                check=True,
            )
            subprocess.run([str(executable)], check=True)
            archive = root / "rootfs.tar"
            with tarfile.open(archive, "w") as tar:
                info = tar.gettarinfo(str(executable), "app/bin/lookup")
                with executable.open("rb") as handle:
                    tar.addfile(info, handle)
                link = tarfile.TarInfo("usr/local/bin/lookup")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../../app/bin/lookup"
                tar.addfile(link)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--rootfs-tar",
                    str(archive),
                    "--executable",
                    "/usr/local/bin/lookup",
                    "--image",
                    "fixture",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual("", result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(
                "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest(),
                report["executable_sha256"],
            )
            return report

    def assert_lookups(self, report: dict, via: str) -> None:
        self.assertEqual("/usr/local/bin/lookup", report["executable"])
        self.assertIn("libc.so.6", report["needed"])
        self.assertIn("dlsym", report["dynamic_loading_imports"])
        self.assertIsNotNone(report["interpreter"])
        lookups = report["dynamic_lookups"]
        self.assertEqual(
            [
                (via, "getrandom", False, None),
                (via, None, True, "name_argument_not_constant"),
            ],
            [
                (item["via"], item["name"], item["review_required"], item["review_reason"])
                for item in sorted(lookups, key=lambda item: item["name"] is None)
            ],
        )
        self.assertTrue(
            all(item["instruction"] in {"call", "jmp"} for item in lookups)
        )
        self.assertEqual([], report["unlocated_lookup_imports"])
        self.assertEqual(1, report["review_required_count"])

    def test_plt_lookups_report_constant_and_runtime_names(self) -> None:
        self.assert_lookups(self.report(), "plt")

    def test_got_lookups_report_constant_and_runtime_names(self) -> None:
        self.assert_lookups(self.report("-fno-plt", "-Wl,-z,now"), "got")


if __name__ == "__main__":
    unittest.main()
