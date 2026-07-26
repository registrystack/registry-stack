#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "validate-first-country-acceptance.py"
sys.path.insert(0, str(SCRIPT.parent))


def load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_first_country_acceptance", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FirstCountryAcceptanceTest(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()
        cls.schema = cls.module.load_schema()
        cls.template = cls.module.validate_shape(
            cls.module.load_json(cls.module.TEMPLATE_PATH), cls.schema
        )

    @staticmethod
    def replace_zero_digests(value: object, label: str = "record") -> object:
        if isinstance(value, dict):
            return {
                key: FirstCountryAcceptanceTest.replace_zero_digests(
                    item, f"{label}.{key}"
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                FirstCountryAcceptanceTest.replace_zero_digests(
                    item, f"{label}[{index}]"
                )
                for index, item in enumerate(value)
            ]
        if value == "sha256:" + "0" * 64:
            return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()
        return value

    def make_passing_record(self) -> dict[str, object]:
        record = self.replace_zero_digests(copy.deepcopy(self.template))
        assert isinstance(record, dict)
        record["record_kind"] = "candidate_acceptance_evidence"
        record["is_evidence"] = True
        record["evidence_state"] = "passed_non_production"
        record["overall_outcome"] = "passed"

        binding = record["binding"]
        assert isinstance(binding, dict)
        candidate = binding["candidate"]
        assert isinstance(candidate, dict)
        candidate["release_tag"] = "v1.2.3"
        candidate["source_commit"] = "1" * 40
        candidate["candidate_assets_verified"] = True
        candidate["authenticity_verified"] = True
        candidate["exact_candidate_approved"] = True

        project = binding["project"]
        assert isinstance(project, dict)
        project["generated_files_unchanged"] = True
        project["generated_files_edited"] = False
        project["product_code_changes_required"] = False

        environment = binding["environment"]
        assert isinstance(environment, dict)
        environment["secret_values_retained"] = False
        environment["authority_widening_detected"] = False

        source = binding["source_profile"]
        assert isinstance(source, dict)
        source["exact_version_bound"] = True
        source["exact_read_operation_bound"] = True
        source["non_production_only"] = True
        source["approved_input_class"] = "synthetic"
        source["zero_one_call_probe_approved"] = True

        binding_digest = self.module.canonical_binding_sha256(binding)
        record["acceptance_binding_sha256"] = binding_digest
        cases = record["cases"]
        assert isinstance(cases, list)
        for case, (_, result_class, source_class, _) in zip(
            cases, self.module.CASE_CONTRACT
        ):
            case["outcome"] = "passed"
            case["result_class"] = result_class
            case["acceptance_binding_sha256"] = binding_digest
            case["source_call_classification"] = source_class

        claims = record["scope_claims"]
        assert isinstance(claims, dict)
        claims["platform_complete"] = True
        claims["country_ready"] = True
        claims["first_country_success"] = True

        human = record["human_acceptance"]
        assert isinstance(human, dict)
        human["outcome"] = "passed"
        human["published_candidate_artifacts_only"] = True
        human["private_maintainer_instructions_used"] = False
        for field in (
            "authored_intent_understood",
            "environment_binding_understood",
            "generated_artifacts_understood",
            "signed_product_inputs_understood",
            "operator_trust_understood",
            "runtime_state_understood",
        ):
            human[field] = True
        human["country_owner_usability_acceptance"] = "accepted"
        human["maintainability_acceptance"] = "accepted"

        handling = record["evidence_handling"]
        assert isinstance(handling, dict)
        handling["restricted_storage"]["approved"] = True
        handling["retention"]["approved"] = True
        handling["retention"]["failed_run_retention_approved"] = True
        handling["deletion"]["procedure_approved"] = True
        handling["deletion"][
            "completion_state"
        ] = "scheduled-within-approved-policy"
        handling["redaction"]["canary_scan_passed"] = True
        handling["redaction"]["public_private_split_confirmed"] = True

        governance = record["governance"]
        assert isinstance(governance, dict)
        governance["privacy_acceptance"]["status"] = "accepted"
        governance["legal_acceptance"]["status"] = "accepted"
        governance["country_technical_acceptance"]["status"] = "accepted"

        publication = record["publication_review"]
        assert isinstance(publication, dict)
        publication["status"] = "passed"
        publication["public_restricted_comparison_confirmed"] = True
        publication["forbidden_content_absent"] = True

        teardown_case = cases[-1]
        teardown = record["teardown"]
        assert isinstance(teardown, dict)
        teardown["attempted"] = True
        teardown["finally_path"] = True
        teardown["outcome"] = "completed"
        teardown["within_approved_bound"] = True
        for field in (
            "source_call_classification",
            "public_evidence_sha256",
            "restricted_evidence_sha256",
            "owner_attestation_sha256",
            "owner_roles",
        ):
            teardown[field] = copy.deepcopy(teardown_case[field])
        return record

    def validate(self, record: dict[str, object]) -> str:
        shaped = self.module.validate_shape(record, self.schema)
        return self.module.validate_evidence(shaped)

    def test_checked_in_packet_is_closed_and_template_is_non_evidence(self) -> None:
        self.module.check_packet()
        self.assertFalse(self.template["is_evidence"])
        self.assertEqual("template", self.template["record_kind"])
        self.assertEqual("planned_not_executed", self.template["evidence_state"])
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "candidate acceptance record"
        ):
            self.module.validate_evidence(copy.deepcopy(self.template))

    def test_packet_rejects_optional_fields_in_closed_objects(self) -> None:
        schema = copy.deepcopy(self.schema)
        schema["$defs"]["case"]["required"].remove("owner_attestation_sha256")
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "must require every field"
        ):
            self.module.assert_closed_schema(schema)

    def test_template_binding_is_canonical_and_repeated_for_every_case(self) -> None:
        digest = self.module.canonical_binding_sha256(self.template["binding"])
        self.assertEqual(digest, self.template["acceptance_binding_sha256"])
        self.assertEqual(
            {digest},
            {
                case["acceptance_binding_sha256"]
                for case in self.template["cases"]
            },
        )

    def test_template_rejects_planted_unexecuted_attestations(self) -> None:
        mutations = (
            (
                ("binding", "project", "generated_files_edited"),
                True,
                "unexecuted prerequisites",
            ),
            (
                ("binding", "environment", "authority_widening_detected"),
                True,
                "unexecuted prerequisites",
            ),
            (
                ("human_acceptance", "authored_intent_understood"),
                True,
                "human acceptance",
            ),
        )
        for path, value, message in mutations:
            with self.subTest(path=path):
                record = copy.deepcopy(self.template)
                target = record
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                if path[0] == "binding":
                    digest = self.module.canonical_binding_sha256(record["binding"])
                    record["acceptance_binding_sha256"] = digest
                    for case in record["cases"]:
                        case["acceptance_binding_sha256"] = digest
                with self.assertRaisesRegex(self.module.AcceptanceError, message):
                    self.module.validate_template(record)

    def test_closed_case_set_covers_every_split_acceptance_requirement(self) -> None:
        case_ids = [item[0] for item in self.module.CASE_CONTRACT]
        self.assertEqual(21, len(case_ids))
        self.assertEqual(len(case_ids), len(set(case_ids)))
        for required in (
            "offline-clean-journey",
            "missing-caller-credential-denial",
            "wrong-caller-credential-denial",
            "missing-purpose-denial",
            "wrong-purpose-denial",
            "disallowed-service-policy-denial",
            "allowed-relay-consultation",
            "no-match",
            "ambiguity",
            "subject-mismatch",
            "source-unavailable",
            "source-rejected",
            "source-malformed",
            "source-late",
            "notary-value-claim",
            "notary-predicate-claim",
            "notary-redacted-claim",
            "consultation-contract-mismatch",
            "promotion",
            "rollback-recovery",
            "teardown",
        ):
            self.assertIn(required, case_ids)

    def test_passing_record_closes_only_bounded_states(self) -> None:
        record = self.make_passing_record()
        self.assertEqual("passed", self.validate(record))
        claims = record["scope_claims"]
        self.assertTrue(claims["first_country_success"])
        self.assertFalse(claims["production_authorized"])
        self.assertFalse(claims["broad_interoperability"])
        self.assertFalse(claims["upstream_product_certification"])

    def test_candidate_binding_tamper_is_rejected(self) -> None:
        record = self.make_passing_record()
        record["binding"]["environment"]["environment_sha256"] = (
            "sha256:" + "b" * 64
        )
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "canonical binding"
        ):
            self.validate(record)

    def test_passing_record_rejects_digest_reuse_across_evidence_domains(self) -> None:
        mutations = (
            (
                lambda record: record["cases"][0],
                "restricted_evidence_sha256",
                lambda record: record["cases"][0]["public_evidence_sha256"],
                "must bind distinct public, restricted",
            ),
            (
                lambda record: record["human_acceptance"],
                "restricted_evidence_sha256",
                lambda record: record["human_acceptance"][
                    "public_evidence_sha256"
                ],
                "human acceptance must bind distinct",
            ),
            (
                lambda record: record["evidence_handling"]["redaction"],
                "restricted_index_sha256",
                lambda record: record["evidence_handling"]["redaction"][
                    "public_summary_sha256"
                ],
                "redaction must bind distinct",
            ),
            (
                lambda record: record["publication_review"],
                "review_evidence_sha256",
                lambda record: record["cases"][0]["public_evidence_sha256"],
                "publication review evidence must be distinct",
            ),
        )
        for owner, field, value, message in mutations:
            with self.subTest(field=field, message=message):
                record = self.make_passing_record()
                owner(record)[field] = value(record)
                with self.assertRaisesRegex(self.module.AcceptanceError, message):
                    self.validate(record)

    def test_passing_record_rejects_candidate_digest_reuse(self) -> None:
        record = self.make_passing_record()
        candidate = record["binding"]["candidate"]
        candidate["notary_product_sha256"] = candidate["relay_product_sha256"]
        binding_digest = self.module.canonical_binding_sha256(record["binding"])
        record["acceptance_binding_sha256"] = binding_digest
        for case in record["cases"]:
            case["acceptance_binding_sha256"] = binding_digest
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "candidate artifacts.*distinct digests"
        ):
            self.validate(record)

    def test_case_binding_tamper_is_rejected(self) -> None:
        record = self.make_passing_record()
        record["cases"][0]["acceptance_binding_sha256"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "not bound to the canonical"
        ):
            self.validate(record)

    def test_passing_denial_must_prove_pre_source_enforcement(self) -> None:
        record = self.make_passing_record()
        denial = record["cases"][1]
        denial["source_call_classification"] = "consulted-within-profile"
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "source-call classification"
        ):
            self.validate(record)

    def test_passing_notary_claim_must_use_reviewed_disclosure_class(self) -> None:
        record = self.make_passing_record()
        claim = next(
            item
            for item in record["cases"]
            if item["case_id"] == "notary-predicate-claim"
        )
        claim["result_class"] = "notary-value-approved-disclosure"
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "reviewed result class"
        ):
            self.validate(record)

    def test_schema_rejects_production_or_broad_interoperability_claims(self) -> None:
        for field in ("production_authorized", "broad_interoperability"):
            with self.subTest(field=field):
                record = self.make_passing_record()
                record["scope_claims"][field] = True
                with self.assertRaisesRegex(
                    self.module.AcceptanceError, "must equal False"
                ):
                    self.validate(record)

    def test_closed_schema_rejects_raw_or_location_fields(self) -> None:
        for owner, field, value in (
            (
                lambda record: record,
                "raw_log",
                "forbidden",
            ),
            (
                lambda record: record["binding"]["source_profile"],
                "source_url",
                "forbidden",
            ),
            (
                lambda record: record["cases"][0],
                "record_identifier",
                "forbidden",
            ),
        ):
            with self.subTest(field=field):
                record = self.make_passing_record()
                owner(record)[field] = value
                with self.assertRaisesRegex(
                    self.module.AcceptanceError, "unknown fields"
                ):
                    self.validate(record)

    def test_failed_run_is_valid_but_must_remain_non_closing(self) -> None:
        record = self.make_passing_record()
        case = record["cases"][10]
        case["outcome"] = "failed"
        case["result_class"] = "execution-failed"
        case["source_call_classification"] = "unknown"
        record["evidence_state"] = "failed_non_production"
        record["overall_outcome"] = "failed"
        record["scope_claims"]["platform_complete"] = False
        record["scope_claims"]["country_ready"] = False
        record["scope_claims"]["first_country_success"] = False
        self.assertEqual("failed", self.validate(record))

        record["scope_claims"]["country_ready"] = True
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "must remain non-closing"
        ):
            self.validate(record)

    def test_failed_run_can_record_a_source_call_bound_breach(self) -> None:
        record = self.make_passing_record()
        case = record["cases"][1]
        case["outcome"] = "failed"
        case["result_class"] = "execution-failed"
        case["source_call_classification"] = "source-call-bound-breached"
        record["evidence_state"] = "failed_non_production"
        record["overall_outcome"] = "failed"
        for field in ("platform_complete", "country_ready", "first_country_success"):
            record["scope_claims"][field] = False
        self.assertEqual("failed", self.validate(record))

    def test_failed_denial_rejects_safe_consultation_classification(self) -> None:
        record = self.make_passing_record()
        case = record["cases"][1]
        case["outcome"] = "failed"
        case["result_class"] = "execution-failed"
        case["source_call_classification"] = "consulted-within-profile"
        record["evidence_state"] = "failed_non_production"
        record["overall_outcome"] = "failed"
        for field in ("platform_complete", "country_ready", "first_country_success"):
            record["scope_claims"][field] = False
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "contradictory source-call classification"
        ):
            self.validate(record)

    def test_passing_record_requires_restricted_evidence_lifecycle(self) -> None:
        mutations = (
            (
                ("evidence_handling", "restricted_storage", "approved"),
                False,
                "storage is not approved",
            ),
            (
                ("evidence_handling", "retention", "failed_run_retention_approved"),
                False,
                "retention are not approved",
            ),
            (
                ("evidence_handling", "deletion", "completion_state"),
                "not_scheduled",
                "deletion is not approved",
            ),
            (
                ("evidence_handling", "redaction", "canary_scan_passed"),
                False,
                "redaction evidence is incomplete",
            ),
        )
        for path, value, message in mutations:
            with self.subTest(path=path):
                record = self.make_passing_record()
                target = record
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                with self.assertRaisesRegex(self.module.AcceptanceError, message):
                    self.validate(record)

    def test_evidence_lifecycle_requires_accountable_owner_roles(self) -> None:
        mutations = (
            (
                ("evidence_handling", "restricted_storage", "owner_role"),
                "product-signing-authority",
                "approved operator role",
            ),
            (
                ("evidence_handling", "retention", "owner_role"),
                "approved-operator",
                "privacy and legal owner role",
            ),
            (
                ("evidence_handling", "deletion", "owner_role"),
                "approved-operator",
                "privacy and legal owner role",
            ),
        )
        for path, value, message in mutations:
            with self.subTest(path=path):
                record = self.make_passing_record()
                target = record
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                with self.assertRaisesRegex(self.module.AcceptanceError, message):
                    self.validate(record)

    def test_publication_review_must_compare_restricted_evidence(self) -> None:
        record = self.make_passing_record()
        record["publication_review"][
            "public_restricted_comparison_confirmed"
        ] = False
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "publication review is not complete"
        ):
            self.validate(record)

    def test_teardown_summary_must_match_the_case(self) -> None:
        record = self.make_passing_record()
        record["teardown"]["restricted_evidence_sha256"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "teardown.restricted_evidence_sha256"
        ):
            self.validate(record)

    def test_failed_teardown_summary_must_match_the_failed_case(self) -> None:
        record = self.make_passing_record()
        teardown_case = record["cases"][-1]
        teardown_case["outcome"] = "failed"
        teardown_case["result_class"] = "execution-failed"
        teardown_case["source_call_classification"] = "source-call-bound-breached"
        record["teardown"]["source_call_classification"] = (
            "source-call-bound-breached"
        )
        record["evidence_state"] = "failed_non_production"
        record["overall_outcome"] = "failed"
        for field in ("platform_complete", "country_ready", "first_country_success"):
            record["scope_claims"][field] = False
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "completed teardown contradicts"
        ):
            self.validate(record)

        record["teardown"]["outcome"] = "failed"
        self.assertEqual("failed", self.validate(record))

    def test_candidate_evidence_always_records_finally_path_teardown(self) -> None:
        record = self.make_passing_record()
        record["cases"][0]["outcome"] = "failed"
        record["cases"][0]["result_class"] = "execution-failed"
        record["cases"][0]["source_call_classification"] = "unknown"
        record["evidence_state"] = "failed_non_production"
        record["overall_outcome"] = "failed"
        for field in ("platform_complete", "country_ready", "first_country_success"):
            record["scope_claims"][field] = False
        record["teardown"]["finally_path"] = False
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "teardown attempt from a finally path"
        ):
            self.validate(record)

    def test_owner_roles_are_closed_and_case_specific(self) -> None:
        record = self.make_passing_record()
        record["cases"][18]["owner_roles"] = list(self.module.SOURCE_CASE_ROLES)
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "exact ordered owner-role set"
        ):
            self.validate(record)

    def test_evidence_rejects_unselected_source_input_class(self) -> None:
        record = self.make_passing_record()
        record["binding"]["source_profile"]["approved_input_class"] = "not-selected"
        binding_digest = self.module.canonical_binding_sha256(record["binding"])
        record["acceptance_binding_sha256"] = binding_digest
        for case in record["cases"]:
            case["acceptance_binding_sha256"] = binding_digest
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "approved safe input class"
        ):
            self.validate(record)

    def test_cli_accepts_pass_and_labels_failed_record_non_closing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            passed_path = directory / "passed.json"
            passed_path.write_text(
                json.dumps(self.make_passing_record()) + "\n", encoding="utf-8"
            )
            passed = subprocess.run(
                [sys.executable, str(SCRIPT), "validate", str(passed_path)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, passed.returncode, passed.stderr)
            self.assertIn("bounded non-production only", passed.stdout)

            failed_record = self.make_passing_record()
            failed_record["cases"][0]["outcome"] = "failed"
            failed_record["cases"][0]["result_class"] = "execution-failed"
            failed_record["cases"][0]["source_call_classification"] = "unknown"
            failed_record["evidence_state"] = "failed_non_production"
            failed_record["overall_outcome"] = "failed"
            for field in (
                "platform_complete",
                "country_ready",
                "first_country_success",
            ):
                failed_record["scope_claims"][field] = False
            failed_path = directory / "failed.json"
            failed_path.write_text(
                json.dumps(failed_record) + "\n", encoding="utf-8"
            )
            failed = subprocess.run(
                [sys.executable, str(SCRIPT), "validate", str(failed_path)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, failed.returncode, failed.stderr)
            self.assertIn("valid non-closing evidence", failed.stdout)


if __name__ == "__main__":
    main()
