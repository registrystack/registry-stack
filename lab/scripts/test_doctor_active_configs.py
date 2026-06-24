#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def write_fake_doctor(path: Path, product: str, status: str = "ok") -> None:
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "config = sys.argv[sys.argv.index('--config') + 1]\n"
        "json.dump({\n"
        "  'schema_version': 'registry.config.diagnostic_report.v1',\n"
        f"  'product': {product!r},\n"
        "  'generated_at': '2026-06-20T00:00:00Z',\n"
        "  'source': {'kind': 'file', 'path': config},\n"
        f"  'status': {status!r},\n"
        "  'summary': {'error': 0, 'warning': 0, 'info': 0},\n"
        "  'diagnostics': []\n"
        "}, sys.stdout)\n"
        "sys.stdout.write('\\n')\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def run_with_fake_doctors(relay_status: str = "ok", notary_status: str = "ok") -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        write_fake_doctor(fake_bin / "registry-relay", "registry-relay", relay_status)
        write_fake_doctor(fake_bin / "registry-notary", "registry-notary", notary_status)
        out_dir = tmp_path / "doctor-output"
        env = {
            **os.environ,
            "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "REGISTRY_LAB_DOCTOR_OUTPUT_DIR": str(out_dir),
        }
        result = subprocess.run(
            ["bash", "scripts/doctor-active-configs.sh"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            assert summary["schema_version"] == "registry.lab.config_doctor_summary.v1"
            assert summary["relay_config_count"] == 8
            assert summary["notary_config_count"] == 15
            assert len(list((out_dir / "relay").glob("*.json"))) == 8
            assert len(list((out_dir / "notary").glob("*.json"))) == 15
        return result


def test_doctor_active_configs_covers_all_active_relay_and_notary_configs() -> None:
    result = run_with_fake_doctors()
    assert result.returncode == 0, result.stderr


def test_doctor_active_configs_fails_when_a_product_report_has_errors() -> None:
    result = run_with_fake_doctors(relay_status="error")
    assert result.returncode != 0
    assert "active config doctor check" in result.stderr


if __name__ == "__main__":
    test_doctor_active_configs_covers_all_active_relay_and_notary_configs()
    test_doctor_active_configs_fails_when_a_product_report_has_errors()
