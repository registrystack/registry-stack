#!/usr/bin/env python3
"""Keep the disposable PostgreSQL gate on the final TCP listener."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("test-postgres.sh")


class PostgresGateTest(unittest.TestCase):
    def test_readiness_and_query_use_tcp_before_cargo(self):
        with tempfile.TemporaryDirectory(prefix="adapter-pg-gate-") as scratch:
            root = Path(scratch)
            binary = root / ".cargo" / "bin"
            binary.mkdir(parents=True)
            docker = binary / "docker"
            docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf "%s\\n" "$*" >> "$PROBE_LOG"\n'
                'case "$1" in\n'
                'run) printf "synthetic-container\\n" ;;\n'
                'exec) if [[ "$3" == psql ]]; then printf "1\\n"; fi ;;\n'
                'port) printf "127.0.0.1:55444\\n" ;;\n'
                'ps) printf "synthetic-container\\n" ;;\n'
                'rm) ;;\n'
                '*) exit 2 ;;\n'
                "esac\n"
            )
            cargo = binary / "cargo"
            cargo.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf "cargo\\n" >> "$PROBE_LOG"\n'
            )
            docker.chmod(0o700)
            cargo.chmod(0o700)
            log = root / "probes"
            env = os.environ.copy()
            env.pop("ADAPTER_TEST_DATABASE_URL", None)
            env.update(HOME=str(root), PATH=f"{binary}:{env['PATH']}", PROBE_LOG=str(log))
            result = subprocess.run(
                ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, check=False
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text().splitlines()
            probes = [line for line in calls if line.startswith("exec ")]
            self.assertEqual(len(probes), 2)
            self.assertTrue(any(" pg_isready " in line for line in probes))
            self.assertTrue(any(" psql " in line for line in probes))
            for line in probes:
                self.assertIn(" -h 127.0.0.1 ", line)
            self.assertGreater(calls.index("cargo"), max(calls.index(line) for line in probes))


if __name__ == "__main__":
    unittest.main()
