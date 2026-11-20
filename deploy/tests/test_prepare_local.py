import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_local import (
    PrepareError, database_password, input_file, postgres_manifest, role_password_needed, set_role_passwords, unchanged,
)

# Verifiers that PostgreSQL 18.4 stored for synthetic passwords. They cover an
# ASCII password, SASLprep mapping and normalisation, and the raw-password
# fallback for a prohibited character, a mixed-direction string and a password
# that maps to nothing. The cases with a soft hyphen differ between the
# prepared and the raw form, so each one fixes which form PostgreSQL used.
SCRAM_VECTORS = {
    "prohibited after mapping": (
        "­synth",
        "SCRAM-SHA-256$4096:wh/uNBnlEuyI7XHykxxZOw==$Hvjc4Y8Pe0ZBOCuQgs4CVM++D7o/S6uoVfK2GVFarbw="
        ":8qVtao7pzBVe4LhgluCnFShIN9c0geBL2se4eXL7jlU=",
    ),
    "mixed direction after mapping": (
        "­اa",
        "SCRAM-SHA-256$4096:wleYJMQMVAA1CoHTyvJBeA==$+wSSueGd6EWpDAQHoGEPbQNm38qhMzuMcDp64mvFerw="
        ":JcOwQojm4QD6C3ucX0D4xqpPMI+9bUeKp6Yx2ANN/CE=",
    ),
    "mapped to nothing": (
        "­­",
        "SCRAM-SHA-256$4096:33WNQe7FygbCkCZpZthjIA==$Yky+dZfyms5VF+mZf/90T6ySK991S5Jp7E9QCpt/fU4="
        ":El75IdGxXh95L89lbSDGyx4PS4i6DMPnN1HFrdDdbnw=",
    ),
    "right to left after mapping": (
        "ا­ب",
        "SCRAM-SHA-256$4096:wTn7qRgKXIUEXnEPA5VAYA==$zQQSVukptGcagWETvyvYaAqqdcKpwYAUfXimQMr9azU="
        ":77Bily9hg9wymzu+vTLF5r/5yRCwq7wc20st9D3ERIA=",
    ),
    "ascii": (
        "synthetic-runtime-password+42",
        "SCRAM-SHA-256$4096:f2YbV5uDWhx0/hyqa2oYvA==$JwDVwuTMl7Nxp1H9ruffNpPV+72K7Bb1V5gO+ZhtkzQ="
        ":uBKzJ3cOF1UsUDkDDCR2RZ99ABwhbr9L5UGVFEziUhA=",
    ),
    "mapped": (
        "Synth\u00a0\ufb01\u00adtic",
        "SCRAM-SHA-256$4096:7H0ooXypbMMcUjCQzV4oOQ==$Y8si0ofT1YadbpyP9xK6I/5xAFLaUup86jT8SwZVUVY="
        ":871UvuJmHbd6ZrzG6CaHujnI8Rf6D+HW4BcN6sl8wwc=",
    ),
    "prohibited": (
        "synth\ue000tic",
        "SCRAM-SHA-256$4096:B6/RIorrcwCDteg9vHA/WA==$50+hJ7VWOhKwrgtfvYOVOpVuFLJkRgH4gcXWv4qP4mA="
        ":d3FqMaqpcme619cv6g2gYasrRanBVjMGWAaLfNqMgcc=",
    ),
    "bidi": (
        "\u0627a",
        "SCRAM-SHA-256$4096:GHUqPplnJsbszzIY5cU7dg==$o3VrFcLCftzLJC4LPjFnfIYJmXQeHgd8EPJpVeNSCbU="
        ":i3B0htCkXxto7Fp2cMWfieCocqkyn5FKTRut437b2Xo=",
    ),
}


class LocalInputsTest(unittest.TestCase):
    def test_database_credentials_only_name_the_local_role_and_database(self):
        expected = "registry-postgres.directory.svc.cluster.local"
        url = f"postgresql://registry_runtime:safe%2Bexample@{expected}:5432/registry_breg"
        self.assertEqual(database_password(url, "registry_runtime", "directory"), "safe+example")
        for malformed in (
            url.replace(expected, "another-db.example.org"),
            url.replace("registry_runtime", "postgres"),
            url.replace("registry_breg", "another_database"),
            url + "?sslmode=disable",
            url.replace("safe%2Bexample", "encoded%0Anewline"),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(PrepareError):
                database_password(malformed, "registry_runtime", "directory")

    def test_input_replay_requires_the_same_immutable_object_data(self):
        desired = {"kind": "Secret", "type": "Opaque", "immutable": True, "data": {"key": "Yg=="}}
        self.assertTrue(unchanged({**desired, "metadata": {"resourceVersion": "8"}}, desired))
        self.assertFalse(unchanged({**desired, "immutable": False}, desired))
        self.assertFalse(unchanged({**desired, "data": {"key": "YQ=="}}, desired))

    def test_postgres_tls_renewal_changes_only_the_named_secret(self):
        original = postgres_manifest("registry-postgres-tls")
        renewed = postgres_manifest("registry-postgres-tls-v2")
        self.assertEqual(renewed.replace("registry-postgres-tls-v2", "registry-postgres-tls"), original)
        self.assertIn("secretName: registry-postgres-tls-v2", renewed)


class InputFileTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.elsewhere = self.root / "elsewhere"
        self.elsewhere.write_bytes(b"bytes outside the inputs")
        self.elsewhere.chmod(0o600)

    def test_reads_a_nonempty_regular_file(self):
        values = self.root / "values.json"
        values.write_bytes(b"{}")
        self.assertEqual(input_file(values), b"{}")

    def test_refuses_links_special_files_and_empty_files(self):
        link = self.root / "link"
        link.symlink_to(self.elsewhere)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        directory = self.root / "directory"
        directory.mkdir()
        empty = self.root / "empty"
        empty.touch()
        for path in (link, fifo, directory, empty, self.root / "missing"):
            with self.subTest(path=path.name), self.assertRaisesRegex(PrepareError, "nonempty regular file"):
                input_file(path)

    def test_a_link_that_appears_after_the_check_is_not_followed(self):
        link = self.root / "pg-server.key"
        link.symlink_to(self.elsewhere)
        with patch("pathlib.Path.is_symlink", return_value=False), self.assertRaises(PrepareError):
            input_file(link, private=True)

    def test_private_inputs_must_be_readable_only_by_their_owner(self):
        key = self.root / "pg-bootstrap"
        key.write_bytes(b"synthetic")
        key.chmod(0o640)
        with self.assertRaisesRegex(PrepareError, "readable only by its owner"):
            input_file(key, private=True)
        key.chmod(0o600)
        self.assertEqual(input_file(key, private=True), b"synthetic")


class RolePasswordTest(unittest.TestCase):
    def test_role_without_a_password_is_set(self):
        self.assertTrue(role_password_needed("t|\n", "registry_runtime", "synthetic"))

    def test_postgresql_verifiers_match_their_passwords(self):
        for name, (password, verifier) in SCRAM_VECTORS.items():
            with self.subTest(name=name):
                self.assertFalse(role_password_needed(f"f|{verifier}\n", "registry_runtime", password))
        mapped = SCRAM_VECTORS["mapped"][1]
        self.assertFalse(role_password_needed(f"f|{mapped}", "registry_runtime", "Synth fitic"))

    def test_a_different_password_is_refused_without_revealing_either_credential(self):
        password, verifier = SCRAM_VECTORS["ascii"]
        with self.assertRaisesRegex(PrepareError, "does not rotate") as raised:
            role_password_needed(f"f|{verifier}", "registry_runtime", "synthetic-rotated-password")
        message = str(raised.exception)
        self.assertIn("registry_runtime", message)
        self.assertNotIn("synthetic-rotated-password", message)
        self.assertNotIn(verifier.split("$")[2], message)

    def test_unknown_role_states_are_refused(self):
        for row in ("", "t|unexpected", "x|"):
            with self.subTest(row=row), self.assertRaisesRegex(PrepareError, "not provisioned"):
                role_password_needed(row, "registry_runtime", "synthetic")
        for verifier in ("md5" + "0" * 32, "plaintext", "SCRAM-SHA-256$0:AA==$AA==:AA=="):
            with self.subTest(verifier=verifier), self.assertRaisesRegex(PrepareError, "SCRAM-SHA-256"):
                role_password_needed(f"f|{verifier}", "registry_runtime", "synthetic")

    def test_every_role_is_checked_before_any_password_is_set(self):
        rows = {"registry_runtime": "t|", "registry_migration": f"f|{SCRAM_VECTORS['ascii'][1]}"}
        calls = []

        def postgres_command(*command, data=None):
            calls.append((command, data))
            return next((row for role, row in rows.items() if f"'{role}'" in command[-1]), "")

        passwords = {"registry_runtime": "runtime-secret", "registry_migration": "rotated-secret"}
        with self.assertRaisesRegex(PrepareError, "registry_migration"):
            set_role_passwords(postgres_command, passwords)
        self.assertFalse([call for call in calls if call[1] is not None])

        passwords["registry_migration"] = SCRAM_VECTORS["ascii"][0]
        calls.clear()
        set_role_passwords(postgres_command, passwords)
        writes = [call for call in calls if call[1] is not None]
        self.assertEqual(writes, [(("-c", "\\password registry_runtime"), "runtime-secret\nruntime-secret\n")])
