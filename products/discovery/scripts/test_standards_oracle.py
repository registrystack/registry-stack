#!/usr/bin/env python3
from __future__ import annotations

import json
import socket
import unittest
from pathlib import Path
from unittest import mock

from pyshacl import validate
from rdflib import BNode, Graph, URIRef

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "profile/context/registry-discovery-v1alpha1.jsonld"
SHAPES = ROOT / "profile/shapes/registry-discovery-v1alpha1.shacl.ttl"
DESCRIPTIONS = ROOT / "fixtures/descriptions"
RDF_FIXTURES = ROOT / "fixtures/rdf"
ENDPOINT_URL = URIRef("http://www.w3.org/ns/dcat#endpointURL")
SERVICE_ID = URIRef(
    "https://registrystack.org/discovery/vocab/v1alpha1#serviceId"
)
SEMANTIC_CLASS_ID = URIRef(
    "https://registrystack.org/discovery/vocab/v1alpha1#semanticClassId"
)
OPERATION_FAMILY_ID = URIRef(
    "https://registrystack.org/discovery/vocab/v1alpha1#operationFamilyId"
)


def _deny_network(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("the standards oracle attempted network access")


def _term(term: object) -> str:
    if isinstance(term, BNode):
        return "_:catalog"
    return term.n3()  # type: ignore[no-any-return, union-attr]


def normalized_ntriples(graph: Graph) -> set[str]:
    return {
        f"{_term(subject)} {_term(predicate)} {_term(obj)} ."
        for subject, predicate, obj in graph
    }


def expected_ntriples(path: Path) -> set[str]:
    return set(path.read_text(encoding="utf-8").splitlines())


class StandardsOracleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.context = json.loads(CONTEXT.read_text(encoding="utf-8"))["@context"]
        cls.shapes = Graph().parse(SHAPES, format="turtle")

    def graph_for(self, path: Path) -> Graph:
        document = json.loads(path.read_text(encoding="utf-8"))
        document["@context"] = self.context
        with mock.patch.object(socket.socket, "connect", _deny_network):
            return Graph().parse(
                data=json.dumps(document),
                format="json-ld",
                publicID="https://registrystack.org/discovery/offline-fixture",
            )

    def assert_conforms(self, graph: Graph) -> None:
        with mock.patch.object(socket.socket, "connect", _deny_network):
            conforms, _report_graph, report_text = validate(
                data_graph=graph,
                shacl_graph=self.shapes,
                inference="none",
                advanced=False,
                js=False,
                meta_shacl=False,
            )
        self.assertTrue(conforms, report_text)

    def test_json_ld_and_shacl_oracles_validate_every_profile_fixture(self) -> None:
        for description in sorted(DESCRIPTIONS.glob("*.jsonld")):
            with self.subTest(description=description.name):
                graph = self.graph_for(description)
                self.assertTrue(graph)
                expected = RDF_FIXTURES / f"{description.stem}.nt"
                self.assertEqual(
                    normalized_ntriples(graph), expected_ntriples(expected)
                )
                self.assert_conforms(graph)

    def test_shacl_oracle_rejects_missing_endpoint(self) -> None:
        graph = self.graph_for(DESCRIPTIONS / "evidence.jsonld")
        graph.remove((None, ENDPOINT_URL, None))
        with mock.patch.object(socket.socket, "connect", _deny_network):
            conforms, report_graph, _report_text = validate(
                data_graph=graph,
                shacl_graph=self.shapes,
                inference="none",
                advanced=False,
                js=False,
                meta_shacl=False,
            )
        self.assertFalse(conforms)
        self.assertTrue(report_graph)

    def test_distinct_binding_nodes_preserve_repeated_service_id_capability_correlation(
        self,
    ) -> None:
        graph = self.graph_for(DESCRIPTIONS / "repeated-service-bindings.jsonld")
        search = URIRef(
            "urn:registrystack:discovery:binding:sha256:"
            "b656d363871acb25cc8fce88863b6782a60bd7be3eb00dc6ae09d9a532c4203e"
        )
        lookup = URIRef(
            "urn:registrystack:discovery:binding:sha256:"
            "f347e0da0897c48163f2da565b842c2ebb1e02ff7f5f979e46054644d23e2e54"
        )
        shared_service = {URIRef("urn:example:service:shared-relay")}

        self.assertNotEqual(search, lookup)
        self.assertEqual(set(graph.objects(search, SERVICE_ID)), shared_service)
        self.assertEqual(set(graph.objects(lookup, SERVICE_ID)), shared_service)
        self.assertEqual(
            set(graph.objects(search, SEMANTIC_CLASS_ID)),
            {URIRef("https://example.org/vocab#RegisteredBusiness")},
        )
        self.assertEqual(
            set(graph.objects(search, OPERATION_FAMILY_ID)),
            {URIRef("https://example.org/operations#search")},
        )
        self.assertEqual(
            set(graph.objects(lookup, SEMANTIC_CLASS_ID)),
            {URIRef("https://example.org/vocab#Person")},
        )
        self.assertEqual(
            set(graph.objects(lookup, OPERATION_FAMILY_ID)),
            {URIRef("https://example.org/operations#lookup")},
        )

    def test_json_ld_oracle_preserves_fragment_iris(self) -> None:
        graph = self.graph_for(DESCRIPTIONS / "repeated-service-bindings.jsonld")
        self.assertIn(
            URIRef("https://example.org/vocab#RegisteredBusiness"),
            set(graph.objects(None, SEMANTIC_CLASS_ID)),
        )
        self.assertIn(
            URIRef("https://example.org/operations#search"),
            set(graph.objects(None, OPERATION_FAMILY_ID)),
        )


if __name__ == "__main__":
    unittest.main()
