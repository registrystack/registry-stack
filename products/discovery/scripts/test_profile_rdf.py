#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validate_profile_rdf", ROOT / "scripts/validate_profile_rdf.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProfileRdfTest(unittest.TestCase):
    def test_fixtures_transform_to_the_pinned_rdf_projection(self) -> None:
        for fixture in sorted((ROOT / "fixtures/descriptions").glob("*.jsonld")):
            MODULE.check_fixture(fixture)

    def test_selected_shacl_refuses_missing_endpoint_in_constructed_graph(self) -> None:
        document = MODULE.load(ROOT / "fixtures/descriptions/evidence.jsonld")
        context = MODULE.local_context()
        graph = MODULE.build_graph(document, context)
        endpoint = MODULE.iri(MODULE.expand("endpointURL", context))
        graph = {triple for triple in graph if triple[1] != endpoint}
        with self.assertRaises(MODULE.ProfileRdfError):
            MODULE.evaluate_selected_shacl(graph, context, MODULE.local_shapes())

    def test_selected_shacl_refuses_invalid_service_kind_in_constructed_graph(self) -> None:
        document = MODULE.load(ROOT / "fixtures/descriptions/evidence.jsonld")
        context = MODULE.local_context()
        graph = MODULE.build_graph(document, context)
        service_kind = MODULE.iri(MODULE.expand("serviceKind", context))
        graph = {
            (subject, predicate, '"unapproved-kind"') if predicate == service_kind else (subject, predicate, object_)
            for subject, predicate, object_ in graph
        }
        with self.assertRaises(MODULE.ProfileRdfError):
            MODULE.evaluate_selected_shacl(graph, context, MODULE.local_shapes())

    def test_closed_profile_refuses_general_graph_features(self) -> None:
        document = MODULE.load(ROOT / "fixtures/descriptions/relay.jsonld")
        document["@graph"] = []
        with self.assertRaises(MODULE.ProfileRdfError):
            MODULE.transform(document)

    def test_pinned_context_binding_identity_alias_is_an_executable_input(self) -> None:
        context = MODULE.load_json(MODULE.CONTEXT_PATH)
        context["@context"]["bindingId"] = {"@id": "registry:bindingId", "@type": "@id"}
        with self.assertRaises(MODULE.ProfileRdfError):
            MODULE.parse_context(context)

    def test_pinned_shacl_semantic_drift_is_refused_before_graph_validation(self) -> None:
        shape = MODULE.SHAPES_PATH.read_text(encoding="utf-8")
        drifted = shape.replace("sh:minCount 1 ; sh:maxCount 1 ; sh:hasValue", "sh:minCount 0 ; sh:maxCount 1 ; sh:hasValue", 1)
        with self.assertRaises(MODULE.ProfileRdfError):
            MODULE.parse_shapes(drifted)


if __name__ == "__main__":
    unittest.main()
