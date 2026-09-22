#!/usr/bin/env python3
"""Bundle the shared AWS-LC-FIPS dylibs used by staged native clients."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from macos_fips_packaging import bundle_macos_fips


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer", action="append", type=Path, required=True)
    parser.add_argument("--library-root", action="append", type=Path, required=True)
    parser.add_argument("--library-directory", type=Path, required=True)
    args = parser.parse_args()

    try:
        libraries = bundle_macos_fips(
            consumers=args.consumer,
            library_roots=args.library_root,
            library_directory=args.library_directory,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
        return 2
    for library in libraries:
        print(library)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
