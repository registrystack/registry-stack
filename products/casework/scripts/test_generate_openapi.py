#!/usr/bin/env python3
"""Focused generator proofs. The full generator additionally checks the real runtime."""
from __future__ import annotations
import copy
import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT=Path(__file__).with_name("generate_openapi.py")
SPEC=importlib.util.spec_from_file_location("casework_openapi",SCRIPT)
GEN=importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name]=GEN
SPEC.loader.exec_module(GEN)


def contract():
    entries=[{"code":"request.invalid","uri":"https://id.registrystack.org/problems/registry-casework/request/invalid","title":"Invalid request","description":"The request is invalid.","httpStatuses":[400]}]
    operations=[{"method":endpoint.method,"path":endpoint.path,"successStatuses":[200],"acceptsJson":endpoint.body is not None,"extractsPath":"{" in endpoint.path,"extractsQuery":endpoint.query is not None,"problems":["request.invalid"]} for endpoint in GEN.ENDPOINTS]
    return {"entries":entries,"operations":operations,"frameworkProblems":[],"reviewWireExamples":{}}

class GeneratedContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wire=GEN.load_wire_schemas(GEN.ROOT)
        cls.schemas=GEN.merge_wire_schemas(cls.wire)
        cls.contract=contract()
        cls.document=GEN.document(cls.contract,cls.wire)

    def operation(self,path,method="get"):
        return self.document["paths"][path][method]

    def test_wire_model_has_exact_policy_binding_and_no_legacy_workflow(self):
        create=self.schemas["ReviewCreateRequest"]
        self.assertIn("policy",create["required"])
        self.assertNotIn("kind",create["properties"])
        for removed in ["WorkItem","ReviewerTask","ReviewKindPolicy","SourceBinding","TaskProposalIdentity"]:
            self.assertNotIn(removed,self.schemas)
        GEN.verify_source(GEN.ROOT,self.document)

    def test_context_modes_and_decisions_come_from_rust_tagged_unions(self):
        context=self.schemas["InputReviewContext"]
        self.assertEqual({variant["properties"]["mode"]["const"] for variant in context["oneOf"]},{"submitted","current-source"})
        decisions=self.schemas["InputDecisionKind"]
        self.assertEqual({variant["properties"]["type"]["const"] for variant in decisions["oneOf"]},{"approve","reject","changes-requested","answer"})
        for variant in decisions["oneOf"]:self.assertFalse(variant["additionalProperties"])

    def test_output_presence_and_input_omission_are_separate_contracts(self):
        self.assertIn("deadlineAt",self.schemas["ReviewTask"]["required"])
        self.assertNotIn("queue",self.schemas["ReviewCaseloadMoveRequest"].get("required",[]))
        for field in ["subject","requesterReference","createdAt"]:self.assertIn(field,self.schemas["ReviewTask"]["required"])
        self.assertIn("dependencies",self.schemas["ReviewPolicyClosure"]["required"])

    def test_subject_binding_uses_exact_serde_type_name(self):
        binding=self.schemas["InputSubjectBinding"]
        self.assertIn("type",binding["required"])
        self.assertNotIn("subjectType",binding["properties"])
        self.assertEqual(set(binding["required"]),{"source","type","id","version","digest"})

    def test_component_references_resolve_and_digest_shape_is_closed(self):
        GEN.verify_refs(self.document)
        self.assertEqual(self.schemas["ContentDigest"]["pattern"],"^sha256:[0-9a-f]{64}$")
        changed=copy.deepcopy(self.document)
        changed["components"]["schemas"]["ReviewTask"]["properties"]["subject"]={"$ref":"#/components/schemas/Absent"}
        with self.assertRaisesRegex(ValueError,"unresolved"):GEN.verify_refs(changed)

    def test_deleted_paths_and_service_profile_boundaries(self):
        self.assertFalse(any(path.startswith(("/v1/work-items","/events/sources")) for path in self.document["paths"]))
        parameters=self.operation("/v1/task-grants/{grant_id}/assertion","post")["parameters"]
        self.assertFalse(any(parameter["name"] in (GEN.PROFILE,GEN.SOURCE_PROFILE) for parameter in parameters))
        parameters=self.operation("/v1/review-requests","post")["parameters"]
        self.assertFalse(any(parameter["name"]==GEN.SOURCE_PROFILE for parameter in parameters))
        self.assertTrue(any(parameter["name"]==GEN.PROFILE and parameter["required"] for parameter in parameters))

    def test_mutation_revision_and_idempotency_fences_are_explicit(self):
        parameters=self.operation("/v1/review-tasks/{task_id}/decisions","post")["parameters"]
        self.assertEqual({parameter["name"] for parameter in parameters if parameter["required"] and parameter["in"]=="header"},{GEN.PROFILE,"If-Match","Idempotency-Key"})
        body=self.operation("/v1/review-tasks/{task_id}/decisions","post")["requestBody"]
        self.assertEqual(body["content"]["application/json"]["schema"],GEN.ref("ReviewTaskDecisionRequest"))
        preview=self.operation("/v1/directory/caseload/preview","post")
        self.assertEqual(preview["requestBody"]["content"]["application/json"]["schema"],GEN.ref("ReviewCaseloadMoveRequest"))
        apply=self.operation("/v1/directory/caseload/apply","post")
        self.assertEqual(apply["requestBody"]["content"]["application/json"]["schema"],GEN.ref("ReviewCaseloadApplyRequest"))

    def test_paired_validation_headers_use_closed_rust_reason_enum(self):
        headers=self.operation("/v1/review-requests","post")["responses"]["400"]["headers"]
        self.assertIn("Registry-Casework-Validation-Path",headers)
        self.assertEqual(headers["Registry-Casework-Validation-Reason"]["schema"],GEN.ref("ReviewValidationReason"))
        self.assertIn("policy-not-allowed",self.schemas["ReviewValidationReason"]["enum"])
        self.assertNotIn("kind-not-allowed",self.schemas["ReviewValidationReason"]["enum"])

    def test_result_lookup_keeps_pending_concealed_and_expired_bodyless(self):
        changed=contract()
        for op in changed["operations"]:
            if op["path"]=="/v1/review-requests/{request_id}/result":op["successStatuses"]=[200,202,404,410]
        responses=GEN.document(changed,self.wire)["paths"]["/v1/review-requests/{request_id}/result"]["get"]["responses"]
        for status in ["202","404","410"]:self.assertNotIn("content",responses[status])
        self.assertEqual(responses["200"]["content"]["application/json"]["schema"],GEN.ref("ReviewResult"))

    def test_runtime_inventory_extraction_and_problem_drift_are_refused(self):
        changed=contract();changed["operations"].pop()
        with self.assertRaisesRegex(ValueError,"inventory"):GEN.document(changed,self.wire)
        changed=contract();changed["operations"][0]["acceptsJson"]=True
        with self.assertRaisesRegex(ValueError,"extraction"):GEN.document(changed,self.wire)
        changed=copy.deepcopy(self.document)
        changed["paths"]["/v1/review-tasks"]["get"]["responses"].pop("400")
        with self.assertRaisesRegex(ValueError,"problem response"):GEN.verify_operation_responses(changed,self.contract)

    def test_problem_table_uses_runtime_statuses_and_preserves_other_tables(self):
        source="- id: introduction\n  rows: []\n- id: problem-codes\n  rows: []\n- id: unchanged\n  title: Keep this\n"
        result=GEN.problem_table(source,self.contract)
        self.assertTrue(result.startswith("- id: introduction\n  rows: []\n"))
        self.assertTrue(result.endswith("- id: unchanged\n  title: Keep this\n"))
        self.assertIn("['`request.invalid`', '400', 'The request is invalid.']",result)
        self.assertEqual(result,GEN.problem_table(result,self.contract))
        with self.assertRaisesRegex(ValueError,"absent"):GEN.problem_table("- id: another\n",self.contract)

    def test_rust_jsonschema_validation_checks_wire_examples(self):
        sample={"policy":{"id":"notice-review","version":"1","digest":"sha256:"+"a"*64},"subject":{"source":"notice","type":"notice","id":"1","version":"1","digest":"sha256:"+"b"*64},"requesterReference":"notice-1","context":{"mode":"submitted","snapshot":{"title":"Notice"}}}
        GEN.validate_wire_examples(GEN.ROOT,self.document,{"ReviewCreateRequest":[sample]})
        sample["kind"]="retired-kind"
        with self.assertRaises(__import__("subprocess").CalledProcessError):GEN.validate_wire_examples(GEN.ROOT,self.document,{"ReviewCreateRequest":[sample]})

if __name__=="__main__":unittest.main()
