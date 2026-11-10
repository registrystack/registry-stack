# SPDX-License-Identifier: Apache-2.0

"""Make the synthetic source and journey helpers in the example importable."""

import sys
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parents[2] / "examples/external-views"
if str(EXAMPLE) not in sys.path:
    sys.path.insert(0, str(EXAMPLE))
