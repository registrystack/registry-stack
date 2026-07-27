from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "validate-product-input-lifecycle.py"
TEMPLATE = (
    ROOT
    / "release"
    / "exercises"
    / "product-input-lifecycle"
    / "product-input-lifecycle-v1.template.json"
)
SCHEMA = TEMPLATE.with_name("product-input-lifecycle-v1.schema.json")


def load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_product_input_lifecycle",
        SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


class ProductInputLifecycleValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.run_git("init", "-q")
        self.run_git("config", "user.name", "Registry Stack Test")
        self.run_git("config", "user.email", "test@registry.invalid")
        (self.root / "source.txt").write_text("prepare\n", encoding="utf-8")
        self.run_git("add", "source.txt")
        self.run_git("commit", "-q", "-m", "prepare")
        self.source_ref = self.git_output("rev-parse", "HEAD")

        manifest_path = (
            self.root / "release" / "manifests" / "registry-stack-beta-20.yaml"
        )
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text(
            "\n".join(
                (
                    "stack:",
                    "  release: beta-20",
                    "  version: 1.2.3",
                    "  source_repo: registrystack/registry-stack",
                    f"  source_ref: {self.source_ref}",
                    "  source_tag: v1.2.3",
                    "artifacts:",
                    "  registry-relay: 1.2.3",
                    "  registry-notary: 1.2.3",
                    "",
                )
            ),
            encoding="utf-8",
        )
        self.run_git("add", "release/manifests/registry-stack-beta-20.yaml")
        self.run_git("commit", "-q", "-m", "candidate")
        self.source_commit = self.git_output("rev-parse", "HEAD")
        self.candidate_asset_root = self.root / "candidate-assets"
        self.candidate_asset_directory = self.candidate_asset_root / "v1.2.3"
        self.candidate_asset_directory.mkdir(parents=True)
        (
            self.candidate_asset_directory / "registryctl-v1.2.3-image-lock.json"
        ).write_text("{}\n", encoding="utf-8")
        self.receipt_path = (
            self.candidate_asset_directory / "release-candidate-receipt.json"
        )
        self.receipt_path.write_text("{}\n", encoding="utf-8")
        self.receipt_sha256 = self.module.sha256_bytes(self.receipt_path.read_bytes())
        tag_binding = "\n".join(
            (
                "registry-stack-release-candidate-v1",
                "run_id: 123",
                "run_attempt: 2",
                f"receipt_sha256: {self.receipt_sha256.removeprefix('sha256:')}",
            )
        )
        self.tag_binding = tag_binding
        self.run_git("tag", "-a", "v1.2.3", "-m", tag_binding)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_git(self, *args: str) -> None:
        subprocess.run(
            ("git", *args),
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        )

    def git_output(self, *args: str) -> str:
        return subprocess.run(
            ("git", *args),
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def candidate(self) -> dict:
        replacements = {
            "<EXERCISE_ID>": "product-input-lifecycle-0123456789abcdef",
            "<RECORDED_AT>": "2026-07-26T12:00:02Z",
            "<RELEASE_ID>": "beta-20",
            "<VERSION>": "v1.2.3",
            "<SOURCE_REF>": self.source_ref,
            "<SOURCE_COMMIT>": self.source_commit,
        }

        def replace(value):
            if isinstance(value, dict):
                return {key: replace(item) for key, item in value.items()}
            if isinstance(value, list):
                return [replace(item) for item in value]
            if not isinstance(value, str) or not value.startswith("<"):
                return value
            if value in replacements:
                return replacements[value]
            return digest(value)

        record = replace(copy.deepcopy(self.template))
        record["record_kind"] = "candidate_evidence"
        record["attestations"] = {
            "candidate_frozen": True,
            "candidate_independently_verified": True,
        }
        manifest_path = Path("release/manifests/registry-stack-beta-20.yaml")
        record["candidate"]["release_manifest_sha256"] = self.module.sha256_bytes(
            self.module.git_bytes(self.root, self.source_commit, manifest_path)
        )
        record["candidate"]["candidate_receipt_sha256"] = self.receipt_sha256
        record["candidate_binding_sha256"] = self.module.canonical_sha256(
            record["candidate"]
        )
        record["product_inputs"]["relay"]["trust_generation"] = 7
        record["product_inputs"]["notary"]["trust_generation"] = 8
        record["product_input_set_sha256"] = self.module.canonical_sha256(
            record["product_inputs"]
        )
        record["activation"]["stack_generation"] = 9

        results = [
            result
            for group in self.module.EVIDENCE_GROUPS
            for result in record["evidence"][group]
        ]
        for index, result in enumerate(results):
            result.update(
                {
                    "outcome": "passed",
                    "subject_sha256": digest(f"subject-{result['check_id']}"),
                    "observed_at": "2026-07-26T12:00:00Z",
                    "evidence_label": f"evidence-{index + 1:016x}",
                    "evidence_sha256": digest(f"evidence-{result['check_id']}"),
                }
            )
        bindings = self.module.result_subject_bindings(
            record["product_inputs"],
            record["activation"],
            candidate_binding_sha256=record["candidate_binding_sha256"],
            product_input_set_sha256=record["product_input_set_sha256"],
        )
        for result in results:
            if result["check_id"] in bindings:
                result["subject_sha256"] = bindings[result["check_id"]]

        for index, review in enumerate(record["reviews"]):
            review.update(
                {
                    "outcome": "passed",
                    "independence_attested": True,
                    "reviewer_label": f"reviewer-{index + 1:016x}",
                    "observed_at": "2026-07-26T12:00:01Z",
                    "evidence_label": f"evidence-{index + 101:016x}",
                    "evidence_sha256": digest(f"review-{review['review_class']}"),
                }
            )
        return record

    def authenticated_candidate(self, _manifest_path: Path, _image_lock_path: Path):
        return {
            "release_id": "beta-20",
            "version": "1.2.3",
            "source_repo": "registrystack/registry-stack",
            "source_ref": self.source_ref,
            "source_tag": "v1.2.3",
            "tag_target": self.source_commit,
            "manifest_sha256": self.module.sha256_bytes(_manifest_path.read_bytes()),
            "image_lock_sha256": digest("<IMAGE_LOCK_SHA256>"),
            "release_capsule_sha256": digest("<RELEASE_CAPSULE_SHA256>"),
            "relay_image": (
                "ghcr.io/registrystack/registry-relay@" + digest("<RELAY_IMAGE_DIGEST>")
            ),
            "notary_image": (
                "ghcr.io/registrystack/registry-notary@"
                + digest("<NOTARY_IMAGE_DIGEST>")
            ),
            "topology": "release-owned",
            "solmara_source_ref": None,
        }

    def validated_receipt(self, document, **kwargs):
        if document != {}:
            raise self.module.CandidateReceiptError("unexpected receipt")
        expected = {
            "expected_source_sha": self.source_ref,
            "expected_version": "1.2.3",
            "expected_release_id": "beta-20",
        }
        for field, value in expected.items():
            if kwargs.get(field) != value:
                raise self.module.CandidateReceiptError("receipt binding mismatch")
        return {
            "workflow": {"run_id": 123, "run_attempt": 2},
            "release": {
                "version": "1.2.3",
                "release_id": "beta-20",
                "source_sha": self.source_ref,
            },
            "validity": {
                "created_at": "2026-07-26T11:00:00Z",
                "expires_at": "2026-07-26T13:00:00Z",
            },
            "images": [
                {
                    "name": "registry-relay",
                    "index_digest": digest("<RELAY_IMAGE_DIGEST>"),
                },
                {
                    "name": "registry-notary",
                    "index_digest": digest("<NOTARY_IMAGE_DIGEST>"),
                },
            ],
        }

    def validate(self, record: dict, **kwargs) -> None:
        kwargs.setdefault("candidate_asset_root", self.candidate_asset_root)
        kwargs.setdefault("candidate_loader", self.authenticated_candidate)
        kwargs.setdefault("receipt_validator", self.validated_receipt)
        self.module.validate_record(record, root=self.root, **kwargs)

    def discover(self, directory: Path):
        return self.module.discover_records(
            directory,
            root=self.root,
            candidate_asset_root=self.candidate_asset_root,
            candidate_loader=self.authenticated_candidate,
            receipt_validator=self.validated_receipt,
        )

    def prepare_discovery(self, directory: Path) -> Path:
        records = directory / self.module.LIFECYCLE_DIRECTORY
        records.mkdir(parents=True)
        (records / self.module.SCHEMA_FILENAME).write_bytes(SCHEMA.read_bytes())
        (records / self.module.TEMPLATE_FILENAME).write_bytes(TEMPLATE.read_bytes())
        return records

    def result(self, record: dict, check_id: str) -> dict:
        for group in self.module.EVIDENCE_GROUPS:
            for result in record["evidence"][group]:
                if result["check_id"] == check_id:
                    return result
        raise AssertionError(f"missing result {check_id}")

    def refresh_subject_bindings(
        self,
        record: dict,
        *,
        exclude: set[str] | None = None,
    ) -> None:
        bindings = self.module.result_subject_bindings(
            record["product_inputs"],
            record["activation"],
            candidate_binding_sha256=record["candidate_binding_sha256"],
            product_input_set_sha256=record["product_input_set_sha256"],
        )
        for check_id, subject in bindings.items():
            if exclude is None or check_id not in exclude:
                self.result(record, check_id)["subject_sha256"] = subject

    def test_template_is_valid_preparation_but_never_candidate_evidence(self) -> None:
        self.validate(self.template, allow_template=True)
        with self.assertRaisesRegex(
            self.module.LifecycleError, "not candidate evidence"
        ):
            self.validate(self.template, allow_template=False)
        with self.assertRaisesRegex(
            self.module.LifecycleError, "never passing evidence"
        ):
            self.validate(
                self.template,
                allow_template=True,
                require_all_passed=True,
            )

    def test_schema_and_runtime_share_the_exact_versioned_contract(self) -> None:
        schema = self.module.lifecycle_schema()
        self.assertEqual(
            self.module.SCHEMA_VERSION,
            schema["properties"]["schema_version"]["const"],
        )
        self.assertEqual(
            {
                group: list(checks)
                for group, checks in self.module.EVIDENCE_GROUPS.items()
            },
            schema["x-registry-evidence-groups"],
        )
        self.assertEqual(
            list(self.module.REVIEW_CLASSES),
            schema["x-registry-review-classes"],
        )
        self.assertEqual(
            set(self.module.ALL_CHECKS),
            set(schema["$defs"]["checkId"]["enum"]),
        )
        candidate = self.candidate()
        self.assertEqual(
            set(self.module.ALL_CHECKS),
            set(
                self.module.result_subject_bindings(
                    candidate["product_inputs"],
                    candidate["activation"],
                    candidate_binding_sha256=candidate["candidate_binding_sha256"],
                    product_input_set_sha256=candidate["product_input_set_sha256"],
                )
            ),
        )
        self.assertEqual(
            set(schema["required"]),
            set(schema["properties"]),
        )
        self.assertFalse(schema["additionalProperties"])

        def assert_closed_objects(value, path="$"):
            if isinstance(value, dict):
                if value.get("type") == "object" and "required" in value:
                    with self.subTest(schema_path=path):
                        self.assertIs(
                            False,
                            value.get("additionalProperties"),
                        )
                        self.assertEqual(
                            set(value["required"]),
                            set(value["properties"]),
                        )
                for key, item in value.items():
                    if key != "if":
                        assert_closed_objects(item, f"{path}.{key}")
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    assert_closed_objects(item, f"{path}[{index}]")

        assert_closed_objects(schema)

    def test_schema_validates_both_template_and_candidate_shapes(self) -> None:
        self.module.validate_schema_document(self.template)
        self.module.validate_schema_document(self.candidate())

    def test_schema_rejects_nested_unknowns_and_record_kind_crossovers(
        self,
    ) -> None:
        record = self.candidate()
        record["product_inputs"]["relay"]["unknown"] = digest("unknown")
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "closed product-input lifecycle schema",
        ):
            self.module.validate_schema_document(record)

        record = self.candidate()
        record["candidate"]["candidate_receipt_sha256"] = "<CANDIDATE_RECEIPT_SHA256>"
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "closed product-input lifecycle schema",
        ):
            self.module.validate_schema_document(record)

        template = copy.deepcopy(self.template)
        template["evidence"]["authoring_and_build"][0]["outcome"] = "passed"
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "closed product-input lifecycle schema",
        ):
            self.module.validate_schema_document(template)

    def test_schema_condition_does_not_mask_malformed_rules(self) -> None:
        malformed = {
            "if": {"allOf": ["not-an-object-rule"]},
            "then": {"const": "then"},
            "else": {"const": "ok"},
        }
        with self.assertRaisesRegex(
            self.module.SchemaValidationError,
            "invalid allOf rule",
        ):
            self.module.validate_against_schema(
                "ok",
                malformed,
                {},
                "probe",
            )

    def test_complete_candidate_record_passes_the_closed_contract(self) -> None:
        self.validate(
            self.candidate(),
            allow_template=False,
            require_all_passed=True,
        )

    def test_candidate_evidence_requires_authenticated_release_assets(self) -> None:
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "--candidate-asset-root",
        ):
            self.validate(
                self.candidate(),
                allow_template=False,
                candidate_asset_root=None,
            )

    def test_authenticated_asset_coordinates_must_match_the_record(self) -> None:
        def mismatched_loader(manifest_path, image_lock_path):
            authenticated = self.authenticated_candidate(
                manifest_path,
                image_lock_path,
            )
            authenticated["relay_image"] = (
                "ghcr.io/registrystack/registry-relay@"
                + digest("different-relay-image")
            )
            return authenticated

        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "authenticated release assets do not match",
        ):
            self.validate(
                self.candidate(),
                allow_template=False,
                candidate_loader=mismatched_loader,
            )

    def test_authenticated_current_manifest_digest_must_match_the_loaded_bytes(
        self,
    ) -> None:
        def mismatched_loader(manifest_path, image_lock_path):
            authenticated = self.authenticated_candidate(
                manifest_path,
                image_lock_path,
            )
            authenticated["manifest_sha256"] = digest("different-current-manifest")
            return authenticated

        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "authenticated release assets do not match",
        ):
            self.validate(
                self.candidate(),
                allow_template=False,
                candidate_loader=mismatched_loader,
            )

    def test_candidate_receipt_bytes_and_annotated_tag_are_exactly_bound(
        self,
    ) -> None:
        record = self.candidate()
        self.receipt_path.write_text('{"changed":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "retained receipt bytes",
        ):
            self.validate(record, allow_template=False)

        self.receipt_path.write_text("{}\n", encoding="utf-8")
        self.run_git("tag", "-d", "v1.2.3")
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "annotated tag binding is unavailable",
        ):
            self.validate(record, allow_template=False)

    def test_lightweight_tag_with_exact_binding_shaped_commit_message_is_rejected(
        self,
    ) -> None:
        record = self.candidate()
        self.run_git("tag", "-d", "v1.2.3")
        self.run_git("commit", "--allow-empty", "-q", "-m", self.tag_binding)
        self.run_git("tag", "v1.2.3", "HEAD")

        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "annotated tag binding is unavailable",
        ):
            self.validate(record, allow_template=False)

    def test_failed_result_is_honest_closed_evidence_but_not_passing_evidence(
        self,
    ) -> None:
        record = self.candidate()
        self.result(record, "rollback_exercised")["outcome"] = "failed"
        self.validate(record, allow_template=False)
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "every lifecycle check",
        ):
            self.validate(
                record,
                allow_template=False,
                require_all_passed=True,
            )

    def test_incomplete_candidate_record_is_rejected(self) -> None:
        record = self.candidate()
        record["evidence"]["advanced_operations"].pop()
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "closed product-input lifecycle schema",
        ):
            self.validate(record, allow_template=False)

    def test_unknown_fields_are_rejected_at_every_closed_boundary(self) -> None:
        mutations = (
            lambda record: record.update({"country": "hidden-country"}),
            lambda record: record["candidate"].update({"manifest_path": "undeclared"}),
            lambda record: record["product_inputs"]["relay"].update(
                {"private_key": "redacted"}
            ),
            lambda record: self.result(
                record,
                "authored_revision_closed",
            ).update({"raw_output": "redacted"}),
            lambda record: record["reviews"][0].update({"review_notes": "redacted"}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                record = self.candidate()
                mutate(record)
                with self.assertRaisesRegex(
                    self.module.LifecycleError,
                    "unknown |closed product-input lifecycle schema",
                ):
                    self.validate(record, allow_template=False)

    def test_placeholders_cannot_enter_candidate_evidence(self) -> None:
        mutations = (
            (
                lambda record: record["candidate"].update(
                    {"candidate_receipt_sha256": "<CANDIDATE_RECEIPT_SHA256>"}
                ),
                "closed product-input lifecycle schema",
            ),
            (
                lambda record: self.result(
                    record,
                    "authored_revision_closed",
                ).update({"evidence_label": "<EVIDENCE_LABEL>"}),
                "closed product-input lifecycle schema",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                record = self.candidate()
                mutate(record)
                with self.assertRaisesRegex(
                    self.module.LifecycleError,
                    message,
                ):
                    self.validate(record, allow_template=False)

    def test_secret_and_location_sentinels_are_rejected_before_retention(self) -> None:
        sentinels = (
            "Bearer abcdef",
            "password=correct-horse",
            "token=opaque",
            "-----BEGIN PRIVATE KEY-----",
            "/Users/operator/evidence.json",
            "https://country.example/evidence",
            "AKIAABCDEFGHIJKLMNOP",
            ("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0In0.abcdefghijklmnop"),
        )
        for sentinel in sentinels:
            with self.subTest(sentinel=sentinel):
                record = self.candidate()
                self.result(record, "authored_revision_closed")["evidence_label"] = (
                    sentinel
                )
                with self.assertRaisesRegex(
                    self.module.LifecycleError,
                    "forbidden sensitive or location data",
                ):
                    self.validate(record, allow_template=False)

    def test_generation_boundaries_are_positive_and_not_boolean(self) -> None:
        locations = (
            lambda record: record["product_inputs"]["relay"].update(
                {"trust_generation": 0}
            ),
            lambda record: record["product_inputs"]["notary"].update(
                {"trust_generation": True}
            ),
            lambda record: record["activation"].update({"stack_generation": 0}),
        )
        for mutate in locations:
            with self.subTest(mutation=mutate):
                record = self.candidate()
                mutate(record)
                with self.assertRaisesRegex(
                    self.module.LifecycleError,
                    "closed product-input lifecycle schema",
                ):
                    self.validate(record, allow_template=False)

    def test_product_input_set_digest_closes_product_input_mutation(self) -> None:
        record = self.candidate()
        record["product_inputs"]["relay"]["trust_generation"] += 1
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "product_input_set_sha256 does not match",
        ):
            self.validate(record, allow_template=False)

    def test_trust_generation_remains_bound_after_product_set_is_rehashed(
        self,
    ) -> None:
        record = self.candidate()
        record["product_inputs"]["relay"]["trust_generation"] += 1
        record["product_input_set_sha256"] = self.module.canonical_sha256(
            record["product_inputs"]
        )
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "does not match its lifecycle object",
        ):
            self.validate(
                record,
                allow_template=False,
                require_all_passed=True,
            )

    def test_stack_generation_is_bound_to_activation_evidence(self) -> None:
        record = self.candidate()
        record["activation"]["stack_generation"] += 1
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "does not match its lifecycle object",
        ):
            self.validate(
                record,
                allow_template=False,
                require_all_passed=True,
            )

    def test_authoring_and_advanced_subjects_reject_cross_context_mixing(
        self,
    ) -> None:
        check_ids = (
            "authored_revision_closed",
            "fixture_coverage_closed",
            "preflight_closed",
            "capabilities_closed",
            "promotion_closed",
            "upgrade_exercised",
            "recovery_exercised",
            "rollback_exercised",
        )
        for check_id in check_ids:
            with self.subTest(check_id=check_id):
                record = self.candidate()
                record["candidate_binding_sha256"] = self.module.canonical_sha256(
                    record["candidate"]
                )
                record["product_input_set_sha256"] = self.module.canonical_sha256(
                    record["product_inputs"]
                )
                self.result(record, check_id)["subject_sha256"] = digest(
                    f"mixed-context-{check_id}"
                )
                with self.assertRaisesRegex(
                    self.module.LifecycleError,
                    "does not match its lifecycle object",
                ):
                    self.validate(record, allow_template=False)

    def test_bundle_verification_binds_trust_generation_set_and_lineage(
        self,
    ) -> None:
        fields = (
            "trust_generation",
            "trust_set_sha256",
            "anti_rollback_lineage_sha256",
        )
        for product in ("relay", "notary"):
            for field in fields:
                with self.subTest(product=product, field=field):
                    record = self.candidate()
                    product_input = record["product_inputs"][product]
                    if field == "trust_generation":
                        product_input[field] += 1
                    else:
                        product_input[field] = digest(f"different-{product}-{field}")
                    record["product_input_set_sha256"] = self.module.canonical_sha256(
                        record["product_inputs"]
                    )
                    target = f"{product}_bundle_verified"
                    bindings = self.module.result_subject_bindings(
                        record["product_inputs"],
                        record["activation"],
                        candidate_binding_sha256=record["candidate_binding_sha256"],
                        product_input_set_sha256=record["product_input_set_sha256"],
                    )
                    for check_id, subject in bindings.items():
                        if check_id != target:
                            self.result(record, check_id)["subject_sha256"] = subject
                    with self.assertRaisesRegex(
                        self.module.LifecycleError,
                        "does not match its lifecycle object",
                    ):
                        self.validate(record, allow_template=False)

    def test_relay_and_notary_inputs_bundles_trust_and_lineage_are_separate(
        self,
    ) -> None:
        paths = (
            ("unsigned_input_sha256", "unsigned_input_sha256"),
            ("signed_bundle_sha256", "signed_bundle_sha256"),
            ("trust_set_sha256", "trust_set_sha256"),
            ("anti_rollback_lineage_sha256", "anti_rollback_lineage_sha256"),
        )
        for relay_field, notary_field in paths:
            with self.subTest(field=relay_field):
                record = self.candidate()
                record["product_inputs"]["notary"][notary_field] = record[
                    "product_inputs"
                ]["relay"][relay_field]
                record["product_input_set_sha256"] = self.module.canonical_sha256(
                    record["product_inputs"]
                )
                with self.assertRaisesRegex(
                    self.module.LifecycleError,
                    "must remain separate",
                ):
                    self.validate(record, allow_template=False)

    def test_candidate_coordinate_is_bound_once_by_its_canonical_digest(self) -> None:
        record = self.candidate()
        record["candidate"]["candidate_receipt_sha256"] = digest(
            "different-candidate-receipt"
        )
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "one exact candidate coordinate",
        ):
            self.validate(record, allow_template=False)

    def test_candidate_manifest_must_match_the_exact_git_coordinate(self) -> None:
        record = self.candidate()
        record["candidate"]["release_manifest_sha256"] = digest("wrong-manifest")
        record["candidate_binding_sha256"] = self.module.canonical_sha256(
            record["candidate"]
        )
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "does not match the exact candidate",
        ):
            self.validate(record, allow_template=False)

    def test_passed_contract_mismatch_requires_exactly_zero_source_calls(self) -> None:
        record = self.candidate()
        record["activation"]["consultation_contract_mismatch"][
            "observed_source_calls"
        ] = 1
        self.refresh_subject_bindings(record)
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "exactly zero source calls",
        ):
            self.validate(record, allow_template=False)

    def test_failed_zero_source_call_check_can_record_a_nonzero_observation(
        self,
    ) -> None:
        record = self.candidate()
        record["activation"]["consultation_contract_mismatch"][
            "observed_source_calls"
        ] = 1
        self.refresh_subject_bindings(record)
        self.result(
            record,
            "consultation_contract_mismatch_zero_source_calls",
        )["outcome"] = "failed"
        self.validate(record, allow_template=False)
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "every lifecycle check",
        ):
            self.validate(
                record,
                allow_template=False,
                require_all_passed=True,
            )

    def test_activation_subjects_are_bound_to_the_exact_separate_bundles(self) -> None:
        record = self.candidate()
        self.result(record, "relay_staged_activation")["subject_sha256"] = record[
            "product_inputs"
        ]["notary"]["signed_bundle_sha256"]
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "does not match its lifecycle object",
        ):
            self.validate(record, allow_template=False)

    def test_reviews_are_independent_distinct_and_follow_the_lifecycle(self) -> None:
        record = self.candidate()
        record["reviews"][1]["reviewer_label"] = record["reviews"][0]["reviewer_label"]
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "distinct independent reviewer labels",
        ):
            self.validate(record, allow_template=False)

        record = self.candidate()
        record["reviews"][0]["observed_at"] = "2026-07-26T11:59:59Z"
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "must follow lifecycle evidence",
        ):
            self.validate(record, allow_template=False)

    def test_lifecycle_timestamps_cannot_run_backwards(self) -> None:
        record = self.candidate()
        self.result(record, "upgrade_exercised")["observed_at"] = "2026-07-26T11:59:59Z"
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "must follow lifecycle order",
        ):
            self.validate(record, allow_template=False)

    def test_recorded_at_is_a_real_utc_time_after_evidence_and_reviews(
        self,
    ) -> None:
        record = self.candidate()
        record["recorded_at"] = "2026-99-99T12:00:02Z"
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "not a valid UTC timestamp",
        ):
            self.validate(record, allow_template=False)

        record = self.candidate()
        record["recorded_at"] = "2026-07-26T12:00:00Z"
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "must not precede",
        ):
            self.validate(record, allow_template=False)

    def test_duplicate_json_fields_are_rejected_before_schema_validation(
        self,
    ) -> None:
        raw = TEMPLATE.read_text(encoding="utf-8").replace(
            '"record_kind": "template"',
            '"record_kind": "candidate_evidence", "record_kind": "template"',
            1,
        )
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(raw, encoding="utf-8")
        result = subprocess.run(
            ("python3", str(SCRIPT), "--template", str(duplicate)),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("must not contain duplicate fields", result.stderr)

    def test_evidence_limitations_cannot_be_upgraded_by_a_local_record(self) -> None:
        record = self.candidate()
        record["evidence_limitations"]["live_country_interoperability_proven"] = True
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "closed product-input lifecycle schema",
        ):
            self.validate(record, allow_template=False)

    def test_discovery_counts_template_as_non_evidence(self) -> None:
        discovery_root = self.root / "discovery"
        self.prepare_discovery(discovery_root)
        self.assertEqual(
            (1, 0),
            self.discover(discovery_root),
        )

    def test_discovery_requires_real_records_to_be_complete_and_passing(self) -> None:
        discovery_root = self.root / "discovery"
        records = self.prepare_discovery(discovery_root)
        candidate_path = records / "product-input-lifecycle-beta-20.json"
        candidate = self.candidate()
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        self.assertEqual(
            (1, 1),
            self.discover(discovery_root),
        )

        candidate["evidence"]["advanced_operations"].pop()
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "closed product-input lifecycle schema",
        ):
            self.discover(discovery_root)

        candidate = self.candidate()
        self.result(candidate, "recovery_exercised")["outcome"] = "failed"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "every lifecycle check",
        ):
            self.discover(discovery_root)

    def test_discovery_rejects_unrecognized_json_and_symlink_records(self) -> None:
        unrecognized_root = self.root / "discovery-unrecognized"
        records = self.prepare_discovery(unrecognized_root)
        (records / "unexpected.json").write_text(
            json.dumps(self.template),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "unrecognized JSON filename",
        ):
            self.discover(unrecognized_root)

        symlink_root = self.root / "discovery-symlink"
        records = self.prepare_discovery(symlink_root)
        (records / "product-input-lifecycle-beta-20.json").symlink_to(TEMPLATE)
        with self.assertRaisesRegex(
            self.module.LifecycleError,
            "bounded regular non-symlink",
        ):
            self.discover(symlink_root)

    def test_record_loader_uses_one_no_follow_file_descriptor_snapshot(self) -> None:
        record = self.root / "record.json"
        record.write_text(json.dumps(self.template), encoding="utf-8")
        with mock.patch.object(
            self.module,
            "read_regular_file_no_follow",
            side_effect=self.module.CandidateAssetError("concurrent replacement"),
        ) as safe_read:
            with self.assertRaisesRegex(
                self.module.LifecycleError,
                "bounded regular non-symlink JSON file",
            ):
                self.module.load_closed_json_file(record)
        safe_read.assert_called_once_with(
            record,
            max_bytes=self.module.MAX_RECORD_BYTES,
        )

    def test_cli_validates_the_committed_template_and_discovery_directory(self) -> None:
        single = subprocess.run(
            ("python3", str(SCRIPT), "--template", str(TEMPLATE)),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, single.returncode, single.stderr)
        self.assertIn("template preparation validation passed", single.stdout)

        discovered = subprocess.run(
            (
                "python3",
                str(SCRIPT),
                "--discover",
                str(ROOT / "release" / "exercises"),
            ),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, discovered.returncode, discovered.stderr)
        self.assertIn(
            "1 non-evidence template(s), 0 candidate evidence record(s)",
            discovered.stdout,
        )


if __name__ == "__main__":
    unittest.main()
