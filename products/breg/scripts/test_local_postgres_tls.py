"""Exercise checkout-name sanitization without executing the TLS bootstrap."""

import os
from pathlib import Path
import re
import subprocess
import unittest


class CheckoutNameTests(unittest.TestCase):
    def test_actual_helper_expression_preserves_safe_names_and_sanitizes_others(self):
        source = Path(__file__).with_name("local-postgres-tls.sh").read_text()
        expressions = re.findall(r"\| tr -c '([^']+)' '-'", source)
        self.assertEqual(len(expressions), 1)
        for original, expected in (
            (b"health-native-default-424-proof\n", b"health-native-default-424-proof\n"),
            (b"Studio_42.v1\n", b"Studio_42.v1\n"),
            (b"checkout name:@[x]\n", b"checkout-name---x-\n"),
        ):
            with self.subTest(original=original):
                result = subprocess.run(
                    ["/usr/bin/tr", "-c", expressions[0], "-"],
                    input=original,
                    capture_output=True,
                    env={**os.environ, "LC_ALL": "C"},
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(result.stderr, b"")
                self.assertEqual(result.stdout, expected)


if __name__ == "__main__":
    unittest.main()
