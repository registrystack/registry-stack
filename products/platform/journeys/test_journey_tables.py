"""Static check of the acceptance journey tables.

It reads the data files in this folder and the journey scripts if present. It
starts no container and builds no binary. Run it with PyYAML available:

    uv run --no-project --with PyYAML==6.0.2 python3 -m unittest products/platform/journeys/test_journey_tables.py

The JOURNEY_TABLES_DIR environment variable points the test at another folder
with the same layout, which is how the test is shown to fail on a broken copy.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
TABLES = Path(os.environ.get("JOURNEY_TABLES_DIR", HERE)).resolve()
REPO = HERE.parents[2]

JOURNEYS = ("own-provider", "rstack-dev", "promote")
BASES = ("predicted", "observed")
TIERS = ("primary", "supporting")
HARD_CONDITIONS = (
    "certificate",
    "token-hook-or-mapper",
    "provisioning-sql",
    "image-build",
    "signature-verifier",
    "no-refusal",
)
# A journey script may call only product binaries, docker (run, rm, port,
# inspect, logs), curl, jq and perl. Each of these is something the pass rule
# forbids a reader to do, so only lib-assists.sh may use it.
FORBIDDEN_TOOLS = ("openssl", "mkcert", "keytool", "psql")
FORBIDDEN_DOCKER = re.compile(r"\bdocker\s+(build|exec)\b")
FORBIDDEN_IN_SCRIPTS = re.compile(r"(?<![\w./-])(%s)(?![\w-])" % "|".join(FORBIDDEN_TOOLS))
ASSIST_SCRIPT = "lib-assists.sh"


def load(name: str):
    with (TABLES / name).open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def cell(row) -> tuple[str, str]:
    return (row["journey"], row["product"])


class ProductsTable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load("products.yaml")
        cls.products = cls.data["products"]

    def test_schema_and_row_keys(self):
        self.assertEqual(self.data["schema"], "registry.journey-products/v1")
        keys = {
            "id", "tier", "binary", "crate", "ctl", "cargoPackages", "cargoFeatures",
            "usesPostgres", "verifiesTokens", "rstackDevPlan",
        }
        for product in self.products:
            allowed = keys | ({"parent"} if product["tier"] == "supporting" else set())
            self.assertEqual(set(product), allowed, product["id"])
            self.assertIn(product["tier"], TIERS, product["id"])
            for flag in ("usesPostgres", "verifiesTokens", "rstackDevPlan"):
                self.assertIsInstance(product[flag], bool, f"{product['id']}.{flag}")

    def test_sixteen_unique_runtimes(self):
        ids = [p["id"] for p in self.products]
        self.assertEqual(len(ids), len(set(ids)), "duplicate product id")
        self.assertEqual(len(ids), 16)

    def test_supporting_runtimes_name_a_primary_parent(self):
        primary = {p["id"] for p in self.products if p["tier"] == "primary"}
        for product in self.products:
            if product["tier"] == "supporting":
                self.assertIn(product["parent"], primary, product["id"])

    def test_crates_and_binaries_exist_in_the_repository(self):
        for product in self.products:
            manifest = REPO / "crates" / product["crate"] / "Cargo.toml"
            self.assertTrue(manifest.is_file(), f"{product['id']}: no {manifest}")
            text = manifest.read_text(encoding="utf-8")
            self.assertRegex(text, r'(?m)^name = "%s"$' % re.escape(product["binary"]),
                             f"{product['id']}: binary {product['binary']} not in {manifest.name}")
            for package in product["cargoPackages"]:
                self.assertTrue((REPO / "crates" / package / "Cargo.toml").is_file(),
                                f"{product['id']}: package {package}")
            if product["ctl"] is not None:
                self.assertTrue((REPO / "crates" / product["ctl"] / "Cargo.toml").is_file(),
                                f"{product['id']}: ctl {product['ctl']}")

    def test_rstack_dev_plan_flag_matches_the_plan_product_type(self):
        plan = (REPO / "crates/registry-rstack-dev/src/plan.rs").read_text(encoding="utf-8")
        match = re.search(r"pub\(super\) enum Product \{(.*?)\}", plan, re.S)
        self.assertIsNotNone(match, "plan.rs no longer has the Product enum")
        members = {m.lower() for m in re.findall(r"\b([A-Z][a-z]+)\b,", match.group(1))}
        flagged = {p["id"] for p in self.products if p["rstackDevPlan"]}
        self.assertEqual(flagged, members)

    def test_own_provider_image_matches_the_repository_pin(self):
        script = (REPO / "products/breg/scripts/test-issuer-portability.py").read_text(encoding="utf-8")
        match = re.search(r'^KEYCLOAK = "([^"]+)"', script, re.M)
        self.assertIsNotNone(match, "the portability journey no longer pins KEYCLOAK")
        issuer = self.data["ownProviderIssuer"]
        self.assertEqual(issuer["name"], "keycloak")
        self.assertEqual(issuer["image"], match.group(1))


class PassRule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rule = load("first-hour-pass-rule.yaml")

    def test_end_points_and_exclusions(self):
        self.assertEqual(set(self.rule["endPoints"]), {"t1", "t2"})
        self.assertTrue(self.rule["notCounted"])

    def test_hard_conditions_are_the_six(self):
        self.assertEqual(tuple(c["id"] for c in self.rule["hardConditions"]), HARD_CONDITIONS)
        for condition in self.rule["hardConditions"]:
            self.assertTrue(condition["text"].strip())

    def test_ten_counters_with_both_thresholds(self):
        counters = self.rule["counters"]
        self.assertEqual([c["id"] for c in counters], list(range(1, 11)))
        self.assertEqual(len({c["name"] for c in counters}), 10)
        for counter in counters:
            for path in ("rstackDev", "ownProvider"):
                value = counter[path]
                self.assertIs(type(value), int, f"counter {counter['id']} {path}")
                self.assertGreaterEqual(value, 0)
            self.assertTrue(counter["how"].strip())
        planted = counters[9]
        self.assertEqual(planted["direction"], "at-least")
        self.assertEqual((planted["rstackDev"], planted["ownProvider"]), (3, 3))

    def test_the_rstack_dev_path_is_never_looser_than_own_provider(self):
        for counter in self.rule["counters"]:
            if counter.get("direction") == "at-least":
                continue
            self.assertLessEqual(counter["rstackDev"], counter["ownProvider"],
                                 f"counter {counter['id']}")

    def test_reader_time_model_constants(self):
        model = self.rule["readerTimeModel"]
        self.assertEqual(
            set(model),
            {
                "typingCharactersPerMinute", "readingWordsPerMinute", "secondsPerHandWrittenLine",
                "secondsPerConceptFirstMet", "minutesPerRefusalMet", "minutesPerAssistUsed",
            },
        )
        for name, value in model.items():
            self.assertIs(type(value), int, name)
            self.assertGreater(value, 0, name)

    def test_pass_definition(self):
        self.assertEqual(self.rule["pass"], "all-hard-conditions-and-all-counters")


class Concepts(unittest.TestCase):
    def test_closed_list_is_well_formed(self):
        data = load("concepts.yaml")
        ids = [c["id"] for c in data["concepts"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate concept id")
        self.assertGreaterEqual(len(ids), 24)
        for concept in data["concepts"]:
            self.assertEqual(set(concept), {"id", "meaning"})
            self.assertRegex(concept["id"], r"^[a-z0-9]+(-[a-z0-9]+)*$")
            self.assertTrue(concept["meaning"].strip(), concept["id"])


class ExpectedFailures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load("expected-failures.yaml")
        products = load("products.yaml")["products"]
        cls.product_ids = [p["id"] for p in products]
        cls.rows = (
            [("failure", r) for r in cls.data["expectedFailures"]]
            + [("unreached", r) for r in cls.data["unreached"]]
        )

    def test_schema_and_journeys(self):
        self.assertEqual(self.data["schema"], "registry.journey-expected-failures/v1")
        self.assertEqual(tuple(self.data["journeys"]), JOURNEYS)
        for journey, body in self.data["journeys"].items():
            self.assertEqual(len(body["steps"]), len(set(body["steps"])), journey)

    def test_every_cell_has_exactly_one_disposition(self):
        seen: dict[tuple[str, str], list[str]] = {}
        for kind, row in self.rows:
            seen.setdefault(cell(row), []).append(kind)
        for product in self.data["passes"]:
            seen.setdefault(cell(product), []).append("pass")
        for journey in JOURNEYS:
            for product in self.product_ids:
                self.assertEqual(len(seen.get((journey, product), [])), 1,
                                 f"{journey} x {product}: {seen.get((journey, product))}")
        self.assertEqual(set(seen), {(j, p) for j in JOURNEYS for p in self.product_ids},
                         "a row names an unknown journey or product")

    def test_steps_belong_to_their_journey(self):
        for kind, row in self.rows:
            steps = self.data["journeys"][row["journey"]]["steps"]
            self.assertIn(row["step"], steps, f"{kind} {cell(row)}")

    def test_basis_is_recorded_on_every_row(self):
        for kind, row in self.rows:
            self.assertIn(row["basis"], BASES, f"{kind} {cell(row)}")
            if row["basis"] == "observed":
                self.assertTrue(str(row.get("observedOn", "")).strip(), f"observed row needs observedOn {cell(row)}")

    def test_every_row_says_why(self):
        for kind, row in self.rows:
            self.assertTrue(row["reason"].strip(), f"{kind} {cell(row)}")

    def test_failure_rows_name_a_code_and_the_change_that_removes_them(self):
        changes = set(self.data["changes"])
        for row in self.data["expectedFailures"]:
            self.assertEqual(
                set(row) - {"observedOn"},
                {"journey", "product", "step", "code", "removedBy", "basis", "reason"},
                cell(row),
            )
            self.assertIn(row["removedBy"], changes, cell(row))
            self.assertTrue(self.code_is_valid(row["code"]), f"{cell(row)}: {row['code']}")

    def test_unreached_rows_have_no_code(self):
        for row in self.data["unreached"]:
            self.assertEqual(set(row) - {"observedOn"},
                             {"journey", "product", "step", "basis", "reason"}, cell(row))

    def test_passes_are_listed_by_cell_only(self):
        for row in self.data["passes"]:
            self.assertEqual(set(row) - {"observedOn"}, {"journey", "product", "basis"}, cell(row))

    def test_supporting_runtimes_are_never_listed_as_failures(self):
        supporting = {p["id"] for p in load("products.yaml")["products"] if p["tier"] == "supporting"}
        for row in self.data["expectedFailures"]:
            self.assertNotIn(row["product"], supporting, cell(row))

    def code_is_valid(self, code: str) -> bool:
        suffixes = self.data["journeyCodeSuffixes"]
        parts = code.split(".")
        if parts[0] == "journey" and len(parts) == 3:
            return parts[1] in suffixes and parts[2] in suffixes[parts[1]]
        if parts[0] == "http" and len(parts) == 3:
            return bool(re.fullmatch(r"[1-5][0-9]{2}", parts[1])) and parts[2] in self.data["authenticationStages"]
        if parts[0] == "product" and len(parts) >= 2:
            return all(re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", part) for part in parts[1:])
        return False


class JourneyFiles(unittest.TestCase):
    """Checks that apply to files the journey scripts add. They pass when the files are absent."""

    def test_scripts_stay_inside_the_allowed_tools(self):
        for script in sorted(TABLES.glob("*.sh")):
            if script.name == ASSIST_SCRIPT:
                continue
            for number, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                self.assertIsNone(FORBIDDEN_IN_SCRIPTS.search(code), f"{script.name}:{number}: {line.strip()}")
                self.assertIsNone(FORBIDDEN_DOCKER.search(code), f"{script.name}:{number}: {line.strip()}")

    def test_realm_import_has_no_protocol_mappers(self):
        realm = TABLES / "keycloak" / "realm.json"
        if realm.is_file():
            self.assertNotIn("protocolMappers", realm.read_text(encoding="utf-8"))


class LoggedStage(unittest.TestCase):
    """`logged_stage` maps the last refusal line's `failed_check` label onto a stage word."""

    CASES = (
        ('{"stage":"token-type","msg":"refused"}', ""),
        ("WARN refused stage=audience", ""),
        ('failed_check="token-time"\n{"stage":"extract"}', "time"),
        ('INFO request refused decision="refused" failed_check="token-type" suppressed=0', "token-type"),
        ('{"fields":{"decision":"refused","failed_check":"credential-malformed"}}', "header"),
        ('failed_check="token-client"', "client"),
        ('failed_check="token-assertion-issuer"', "client"),
        ('failed_check="key-source-unavailable"', "unavailable"),
        ('failed_check="token-key"\nfailed_check="token-time"', "time"),
        ('failed_check="credential-missing"', ""),
        ('failed_check="token-time"\nfailed_check="operation"', ""),
        ('failed_check="token-type"\nfailed_check="access-profile"', ""),
        ("no refusal here", ""),
    )

    @staticmethod
    def function(script: str) -> str:
        text = (TABLES / script).read_text(encoding="utf-8")
        match = re.search(r"^logged_stage\(\) \{\n.*?^\}\n", text, re.S | re.M)
        assert match, f"{script} has no logged_stage"
        return match.group(0)

    def test_the_last_refusal_label_decides_the_stage(self):
        for script in ("own-provider.sh", "promote.sh"):
            function = self.function(script)
            for log, expected in self.CASES:
                with self.subTest(script=script, log=log):
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / "server.log"
                        path.write_text(log + "\n", encoding="utf-8")
                        result = subprocess.run(
                            ["bash", "-c", function + '\nlogged_stage "$1"', "bash", str(path)],
                            capture_output=True,
                            text=True,
                            check=True,
                        )
                    self.assertEqual(result.stdout, expected)


if __name__ == "__main__":
    unittest.main()
