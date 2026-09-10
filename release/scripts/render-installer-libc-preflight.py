#!/usr/bin/env python3
"""Write the shared libc preflight into every published installer script.

An installer is fetched with curl and piped to bash, so it cannot read a file
from the repository at run time: everything it needs has to be inside the one
script. The glibc floor still has a single home in release/glibc-floor.env, and
this generator copies it into the installers so no number is maintained twice.

  render-installer-libc-preflight.py --check   fail when an installer is stale
  render-installer-libc-preflight.py --write   rewrite the generated blocks
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FLOOR_FILE = Path("release/glibc-floor.env")
FLOOR_RE = re.compile(r"^REGISTRY_GLIBC_FLOOR=([0-9]+\.[0-9]+)$", re.MULTILINE)

BEGIN = "# BEGIN generated libc preflight"
END = "# END generated libc preflight"
# The preflight goes after the platform case that sets os_label, and before the
# first line that would reach the network.
ANCHOR = 'base_url="https://github.com/${repo}/releases/download/${version}"'


class Installer:
    def __init__(self, path: str, product: str) -> None:
        self.path = Path(path)
        self.product = product


INSTALLERS = (
    Installer("crates/registry-breg/install.sh", "the Base Registry Engine"),
    Installer("crates/registry-casework/install.sh", "Registry Casework"),
    Installer("crates/registry-evidencectl/install.sh", "the Evidence toolset"),
    Installer("crates/registry-relay-v2/install.sh", "Registry Relay"),
)

TEMPLATE = """\
{begin}
# Generated from release/glibc-floor.env by
# release/scripts/render-installer-libc-preflight.py. Do not edit by hand.
#
# The published Linux binaries are dynamically linked against GNU libc. On a
# musl system, or on a glibc older than the floor below, they cannot start, and
# the dynamic linker only says so at the first run, long after this installer
# would have reported success. Refuse here instead, before anything downloads.
if [ "$os_label" = "linux" ]; then
{i}libc_floor="{floor}"
{i}# musl's ldd exits non-zero when asked for a version, and this installer runs
{i}# under pipefail, so its report is captured once here instead of being read
{i}# through a pipeline whose status would hide the match.
{i}libc_report=""
{i}if command -v ldd >/dev/null 2>&1; then
{i}{i}libc_report="$(ldd --version 2>&1 || true)"
{i}fi
{i}# Only glibc's getconf answers GNU_LIBC_VERSION, so an answer names the libc
{i}# this system runs on, whatever else is installed beside it: a musl loader
{i}# kept for cross builds does not make a musl system. Without an answer, musl
{i}# is recognised by its ldd report or its loader. The report is matched by a
{i}# pattern rather than through grep, which can exit before the report is
{i}# fully written and, under pipefail, lose the match.
{i}detected_libc=""
{i}if command -v getconf >/dev/null 2>&1; then
{i}{i}detected_libc="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{{print $2}}' || true)"
{i}fi
{i}musl_system=0
{i}if [ -z "$detected_libc" ]; then
{i}{i}case "$libc_report" in
{i}{i}*[Mm][Uu][Ss][Ll]*) musl_system=1 ;;
{i}{i}esac
{i}{i}if ls /lib/ld-musl-*.so.1 >/dev/null 2>&1; then
{i}{i}{i}musl_system=1
{i}{i}fi
{i}fi
{i}if [ "$musl_system" = 1 ]; then
{i}{i}printf 'No musl build of {product} is published for this platform.\\n' >&2
{i}{i}printf 'Every published Linux binary needs GNU libc %s or newer, so none of them can start here.\\n' \\
{i}{i}{i}"$libc_floor" >&2
{i}{i}printf 'Install on a GNU libc distribution, or run the published container images.\\n' >&2
{i}{i}printf 'If you need musl builds, ask for them at https://github.com/%s/issues so the demand is recorded.\\n' \\
{i}{i}{i}"$repo" >&2
{i}{i}exit 1
{i}fi
{i}if [ -z "$detected_libc" ]; then
{i}{i}detected_libc="$(printf '%s\\n' "$libc_report" | awk 'NR == 1 {{print $NF}}')"
{i}fi
{i}case "$detected_libc" in
{i}[0-9]*.[0-9]*) ;;
{i}*) detected_libc="" ;;
{i}esac
{i}if [ -z "$detected_libc" ]; then
{i}{i}printf 'Could not read the GNU libc version of this system, so the %s floor is unchecked.\\n' \\
{i}{i}{i}"$libc_floor" >&2
{i}elif ! awk -v have="$detected_libc" -v floor="$libc_floor" '
{i}{i}BEGIN {{
{i}{i}{i}split(have, h, ".")
{i}{i}{i}split(floor, f, ".")
{i}{i}{i}exit !(h[1] > f[1] || (h[1] == f[1] && h[2] >= f[2]))
{i}{i}}}
{i}'; then
{i}{i}printf 'This system has GNU libc %s. The published binaries of {product} need %s or newer.\\n' \\
{i}{i}{i}"$detected_libc" "$libc_floor" >&2
{i}{i}printf 'Nothing was installed: the binaries would fail to start with a dynamic linker error.\\n' >&2
{i}{i}printf 'Upgrade the distribution, or run the published container images.\\n' >&2
{i}{i}exit 1
{i}fi
fi

{end}
"""


def read_floor(root: Path = ROOT) -> str:
    text = (root / FLOOR_FILE).read_text(encoding="utf-8")
    match = FLOOR_RE.search(text)
    if match is None:
        raise SystemExit(
            f"{FLOOR_FILE} must declare REGISTRY_GLIBC_FLOOR=MAJOR.MINOR"
        )
    return match.group(1)


def detect_indent(text: str) -> str:
    """The indentation the installer already uses, so shfmt stays satisfied."""
    for line in text.splitlines():
        if line.startswith("\t"):
            return "\t"
        if line.startswith("    "):
            return "    "
    raise SystemExit("an installer with no indented line has no shape to match")


def render(installer: Installer, floor: str, indent: str = "\t") -> str:
    return TEMPLATE.format(
        begin=BEGIN,
        end=END,
        i=indent,
        floor=floor,
        product=installer.product,
    )


def apply(text: str, block: str, relative: Path) -> str:
    """Return the installer text with exactly one current preflight block."""
    begin = text.find(BEGIN)
    end = text.find(END)
    if (begin < 0) != (end < 0):
        raise SystemExit(f"{relative}: the generated preflight markers are unpaired")
    if begin >= 0:
        if end < begin:
            raise SystemExit(f"{relative}: the generated preflight markers are inverted")
        text = text[:begin] + text[end + len(END) + 1 :]
    anchor = text.find(ANCHOR)
    if anchor < 0:
        raise SystemExit(f"{relative}: no {ANCHOR!r} line to place the preflight before")
    return text[:anchor] + block + text[anchor:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args(argv)

    root = arguments.root.resolve()
    floor = read_floor(root)
    stale: list[Path] = []
    for installer in INSTALLERS:
        path = root / installer.path
        text = path.read_text(encoding="utf-8")
        block = render(installer, floor, detect_indent(text))
        wanted = apply(text, block, installer.path)
        if wanted == text:
            continue
        stale.append(installer.path)
        if arguments.write:
            path.write_text(wanted, encoding="utf-8")

    if arguments.write:
        for relative in stale:
            print(f"rewrote {relative}")
        print(f"installer libc preflight written for the GLIBC_{floor} floor.")
        return 0
    if stale:
        print("installer libc preflight is stale:", file=sys.stderr)
        for relative in stale:
            print(f"- {relative}", file=sys.stderr)
        print(
            "Run: python3 release/scripts/render-installer-libc-preflight.py --write",
            file=sys.stderr,
        )
        return 1
    print(f"installer libc preflight matches the GLIBC_{floor} floor.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
