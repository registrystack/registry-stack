#!/usr/bin/env python3
"""Offline closed-profile JSON-LD expansion and selected SHACL validation.

This tooling accepts only Registry Discovery's pinned context, produces its
finite deterministic N-Triples projection, parses only the selected local
SHACL subset, and evaluates that subset over the constructed graph. It is not
a generic JSON-LD, RDF, SHACL, import, graph-store, or SPARQL implementation.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTEXT_PATH = ROOT / "profile/context/registry-discovery-v1alpha1.jsonld"
SHAPES_PATH = ROOT / "profile/shapes/registry-discovery-v1alpha1.shacl.ttl"
CONTEXT_URL = "https://registrystack.org/discovery/context/v1alpha1"
PROFILE = "registry-discovery-v1alpha1"
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
DCAT = "http://www.w3.org/ns/dcat#"
DCT = "http://purl.org/dc/terms/"
REGISTRY = "https://registrystack.org/discovery/vocab/v1alpha1#"


class ProfileRdfError(ValueError):
    """A closed-profile, context, RDF, or selected-SHACL refusal."""


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def iri(value: str) -> str:
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        raise ProfileRdfError("IRI constraint failed")
    return f"<{value}>"


def literal(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProfileRdfError("literal constraint failed")
    return json.dumps(value, ensure_ascii=False)


def parse_context(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"@context"} or not isinstance(value["@context"], dict):
        raise ProfileRdfError("pinned JSON-LD context is not a closed context object")
    context = value["@context"]
    expected_prefixes = {"dcat": DCAT, "dct": DCT, "registry": REGISTRY}
    if {key: context.get(key) for key in expected_prefixes} != expected_prefixes:
        raise ProfileRdfError("pinned JSON-LD prefix mapping drifted")
    if context.get("bindingId") != "@id":
        raise ProfileRdfError("bindingId must remain the local @id alias")
    expected = {
        "serviceId": {"@id": "registry:serviceId", "@type": "@id"},
        "serviceKind": "registry:serviceKind", "title": "dct:title",
        "description": "dct:description", "publisherId": {"@id": "registry:publisherId", "@type": "@id"},
        "operatorId": {"@id": "registry:operatorId", "@type": "@id"},
        "registryAuthorityId": {"@id": "registry:registryAuthorityId", "@type": "@id"},
        "legalIssuerId": {"@id": "registry:legalIssuerId", "@type": "@id"},
        "technicalProviderId": {"@id": "registry:technicalProviderId", "@type": "@id"},
        "endpointURL": {"@id": "dcat:endpointURL", "@type": "@id"},
        "jurisdictions": {"@id": "dct:spatial", "@type": "@id", "@container": "@set"},
        "conformsTo": {"@id": "dct:conformsTo", "@type": "@id", "@container": "@set"},
        "evidenceTypeIds": {"@id": "registry:evidenceTypeId", "@type": "@id", "@container": "@set"},
        "semanticClassIds": {"@id": "registry:semanticClassId", "@type": "@id", "@container": "@set"},
        "operationFamilyIds": {"@id": "registry:operationFamilyId", "@type": "@id", "@container": "@set"},
        "services": {"@id": "dcat:service", "@container": "@set"}, "profile": "registry:profile",
    }
    if {key: context.get(key) for key in expected} != expected:
        raise ProfileRdfError("pinned JSON-LD term mapping drifted")
    if set(context) != set(expected_prefixes) | set(expected) | {"bindingId"}:
        raise ProfileRdfError("pinned JSON-LD context has an unsupported term")
    return context


def local_context() -> dict[str, Any]:
    return parse_context(load_json(CONTEXT_PATH))


def expand(term: str, context: dict[str, Any]) -> str:
    value = context[term]
    if isinstance(value, dict):
        value = value["@id"]
    if not isinstance(value, str) or ":" not in value:
        raise ProfileRdfError("pinned JSON-LD term has no supported IRI mapping")
    prefix, suffix = value.split(":", 1)
    if prefix not in {"dcat", "dct", "registry"}:
        raise ProfileRdfError("pinned JSON-LD term uses an unsupported prefix")
    return context[prefix] + suffix


def parse_shapes(source: str) -> dict[str, dict[str, Any]]:
    if "owl:imports" in source or "sh:select" in source or "sh:SPARQL" in source:
        raise ProfileRdfError("selected SHACL must not import or execute SPARQL")
    supported = {"NodeShape", "targetClass", "property", "path", "minCount", "maxCount", "hasValue", "nodeKind", "IRI", "Literal", "in"}
    if set(re.findall(r"sh:([A-Za-z]+)", source)) - supported:
        raise ProfileRdfError("selected SHACL contains an unsupported feature")
    shapes: dict[str, dict[str, Any]] = {}
    for name in ("CatalogShape", "DataServiceShape"):
        match = re.search(rf"registry:{name}\s+(.*?)(?:\n\n|\Z)", source, re.DOTALL)
        if not match:
            raise ProfileRdfError("selected SHACL shape is missing")
        body = match.group(1)
        target = re.search(r"sh:targetClass\s+([a-z]+:[A-Za-z]+)", body)
        if not target:
            raise ProfileRdfError("selected SHACL target class is missing")
        properties: dict[str, dict[str, Any]] = {}
        for block in re.findall(r"\[\s*(.*?)\s*\]", body, re.DOTALL):
            path = re.search(r"sh:path\s+([a-z]+:[A-Za-z]+)", block)
            if not path:
                raise ProfileRdfError("selected SHACL property path is missing")
            rule: dict[str, Any] = {}
            for key in ("minCount", "maxCount"):
                count = re.search(rf"sh:{key}\s+(\d+)", block)
                if count:
                    rule[key] = int(count.group(1))
            has_value = re.search(r'sh:hasValue\s+"([^"]+)"', block)
            if has_value:
                rule["hasValue"] = has_value.group(1)
            node_kind = re.search(r"sh:nodeKind\s+sh:(IRI|Literal)", block)
            if node_kind:
                rule["nodeKind"] = node_kind.group(1)
            choices = re.search(r'sh:in\s+\(\s*"([^"]+)"\s+"([^"]+)"\s*\)', block)
            if choices:
                rule["in"] = [choices.group(1), choices.group(2)]
            properties[path.group(1)] = rule
        shapes[name] = {"target": target.group(1), "properties": properties}
    expected = {
        "CatalogShape": {"target": "dcat:Catalog", "properties": {"registry:profile": {"minCount": 1, "maxCount": 1, "hasValue": PROFILE}, "dcat:service": {"minCount": 1, "nodeKind": "IRI"}}},
        "DataServiceShape": {"target": "dcat:DataService", "properties": {"registry:serviceId": {"minCount": 1, "maxCount": 1, "nodeKind": "IRI"}, "dct:title": {"minCount": 1, "maxCount": 1, "nodeKind": "Literal"}, "dct:description": {"minCount": 1, "maxCount": 1, "nodeKind": "Literal"}, "dcat:endpointURL": {"minCount": 1, "maxCount": 1, "nodeKind": "IRI"}, "dct:spatial": {"minCount": 1, "nodeKind": "IRI"}, "dct:conformsTo": {"minCount": 1, "nodeKind": "IRI"}, "registry:serviceKind": {"minCount": 1, "maxCount": 1, "in": ["evidence", "relay"]}}},
    }
    if shapes != expected:
        raise ProfileRdfError("pinned selected SHACL semantics drifted")
    return shapes


def local_shapes() -> dict[str, dict[str, Any]]:
    return parse_shapes(SHAPES_PATH.read_text(encoding="utf-8"))


def closed_document(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"@context", "@type", "profile", "services"}:
        raise ProfileRdfError("closed profile root constraint failed")
    if value.get("@context") != CONTEXT_URL or value.get("@type") != "dcat:Catalog" or value.get("profile") != PROFILE:
        raise ProfileRdfError("closed profile catalog constraint failed")
    services = value.get("services")
    if not isinstance(services, list) or not services:
        raise ProfileRdfError("closed profile catalog service constraint failed")
    allowed = {"@type", "bindingId", "serviceId", "serviceKind", "title", "description", "endpointURL", "publisherId", "operatorId", "registryAuthorityId", "legalIssuerId", "technicalProviderId", "jurisdictions", "conformsTo", "evidenceTypeIds", "semanticClassIds", "operationFamilyIds"}
    for service in services:
        if not isinstance(service, dict) or not set(service).issubset(allowed) or service.get("@type") != "dcat:DataService":
            raise ProfileRdfError("closed profile service constraint failed")
        if service.get("serviceKind") not in {"evidence", "relay"}:
            raise ProfileRdfError("closed profile service-kind constraint failed")
        for required in ("bindingId", "serviceId", "title", "description", "endpointURL", "jurisdictions", "conformsTo"):
            if required not in service:
                raise ProfileRdfError("closed profile required property is missing")
    return value


Graph = set[tuple[str, str, str]]


def build_graph(document: dict[str, Any], context: dict[str, Any]) -> Graph:
    closed_document(document)
    graph: Graph = {
        ("_:catalog", iri(RDF_TYPE), iri(f"{DCAT}Catalog")),
        ("_:catalog", iri(expand("profile", context)), literal(PROFILE)),
    }
    for service in document["services"]:
        subject = iri(service["bindingId"])
        graph.update({
            ("_:catalog", iri(expand("services", context)), subject),
            (subject, iri(RDF_TYPE), iri(f"{DCAT}DataService")),
            (subject, iri(expand("title", context)), literal(service["title"])),
            (subject, iri(expand("description", context)), literal(service["description"])),
            (subject, iri(expand("endpointURL", context)), iri(service["endpointURL"])),
            (subject, iri(expand("serviceKind", context)), literal(service["serviceKind"])),
            (subject, iri(expand("serviceId", context)), iri(service["serviceId"])),
        })
        for name in ("publisherId", "operatorId", "registryAuthorityId", "legalIssuerId", "technicalProviderId"):
            if name in service:
                graph.add((subject, iri(expand(name, context)), iri(service[name])))
        for name in ("jurisdictions", "conformsTo", "evidenceTypeIds", "semanticClassIds", "operationFamilyIds"):
            values = service.get(name, [])
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                raise ProfileRdfError("closed profile identifier collection constraint failed")
            for value in values:
                graph.add((subject, iri(expand(name, context)), iri(value)))
    return graph


def shape_term(term: str, context: dict[str, Any]) -> str:
    prefix, suffix = term.split(":", 1)
    return iri(context[prefix] + suffix)


def evaluate_selected_shacl(graph: Graph, context: dict[str, Any], shapes: dict[str, dict[str, Any]]) -> None:
    for shape in shapes.values():
        target = iri(context[shape["target"].split(":", 1)[0]] + shape["target"].split(":", 1)[1])
        subjects = {subject for subject, predicate, object_ in graph if predicate == iri(RDF_TYPE) and object_ == target}
        for subject in subjects:
            for path, rule in shape["properties"].items():
                predicate = shape_term(path, context)
                objects = [object_ for source, current, object_ in graph if source == subject and current == predicate]
                if len(objects) < rule.get("minCount", 0) or len(objects) > rule.get("maxCount", len(objects)):
                    raise ProfileRdfError("selected SHACL cardinality constraint failed")
                if "hasValue" in rule and literal(rule["hasValue"]) not in objects:
                    raise ProfileRdfError("selected SHACL hasValue constraint failed")
                if rule.get("nodeKind") == "IRI" and any(not object_.startswith("<") for object_ in objects):
                    raise ProfileRdfError("selected SHACL IRI node-kind constraint failed")
                if rule.get("nodeKind") == "Literal" and any(not object_.startswith('"') for object_ in objects):
                    raise ProfileRdfError("selected SHACL literal node-kind constraint failed")
                if "in" in rule and any(value not in rule["in"] for value in objects_literal_values(objects)):
                    raise ProfileRdfError("selected SHACL in constraint failed")


def objects_literal_values(objects: list[str]) -> list[str]:
    values = []
    for object_ in objects:
        if not object_.startswith('"'):
            raise ProfileRdfError("selected SHACL in node-kind constraint failed")
        values.append(json.loads(object_))
    return values


def transform(document: dict[str, Any]) -> str:
    context = local_context()
    graph = build_graph(document, context)
    evaluate_selected_shacl(graph, context, local_shapes())
    return "\n".join(f"{subject} {predicate} {object_} ." for subject, predicate, object_ in sorted(graph)) + "\n"


def load(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise ProfileRdfError("profile document must be an object")
    return value


def check_fixture(path: Path) -> None:
    rendered = transform(load(path))
    expected = ROOT / "fixtures/rdf" / f"{path.stem}.nt"
    if not expected.is_file() or expected.read_text(encoding="utf-8") != rendered:
        raise ProfileRdfError(f"RDF fixture drift: {path.name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--input", type=Path)
    arguments = parser.parse_args()
    if arguments.check == (arguments.input is not None):
        parser.error("choose exactly one of --check or --input")
    if arguments.check:
        for fixture in sorted((ROOT / "fixtures/descriptions").glob("*.jsonld")):
            check_fixture(fixture)
        print("Registry Discovery local JSON-LD expansion and selected SHACL validation are current.")
    else:
        print(transform(load(arguments.input)), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
