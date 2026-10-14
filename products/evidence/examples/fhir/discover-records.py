import json
import os
import re
from urllib.parse import urlencode, urlsplit
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

DEFAULT_BASE_URL = "https://r4.smarthealthit.org"
BASE_URL = os.environ.get("FHIR_TUTORIAL_TEST_BASE_URL", DEFAULT_BASE_URL)
if BASE_URL != DEFAULT_BASE_URL:
    parsed_origin = urlsplit(BASE_URL)
    if (
        parsed_origin.scheme != "http"
        or parsed_origin.hostname != "127.0.0.1"
        or parsed_origin.port is None
        or parsed_origin.username is not None
        or parsed_origin.password is not None
        or parsed_origin.path not in {"", "/"}
        or parsed_origin.query
        or parsed_origin.fragment
    ):
        raise RuntimeError("the tutorial test origin must be numeric loopback HTTP")
BASE_URL = BASE_URL.rstrip("/")
MAXIMUM_BYTES = 1_048_576
FHIR_ID = re.compile(r"^[A-Za-z0-9.-]{1,64}$")
ORGANIZATION_TYPE_SYSTEM = (
    "http://terminology.hl7.org/CodeSystem/organization-type"
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


OPENER = build_opener(ProxyHandler({}), NoRedirect)


def read_fhir(path, parameters=None, missing_ok=False):
    query = f"?{urlencode(parameters)}" if parameters else ""
    request = Request(
        f"{BASE_URL}/{path}{query}",
        headers={"Accept": "application/fhir+json"},
    )
    try:
        with OPENER.open(request, timeout=20) as response:
            if response.status != 200:
                raise RuntimeError("FHIR server returned a non-success status")
            if response.headers.get_content_type() not in {
                "application/fhir+json",
                "application/json",
            }:
                raise RuntimeError("FHIR server returned an unexpected media type")
            body = response.read(MAXIMUM_BYTES + 1)
    except HTTPError as error:
        if missing_ok and error.code in {404, 410}:
            return None
        raise RuntimeError("FHIR server returned a non-success status") from None
    if len(body) > MAXIMUM_BYTES:
        raise RuntimeError("FHIR response exceeded the discovery bound")
    resource = json.loads(body)
    if not isinstance(resource, dict):
        raise RuntimeError("FHIR response is not an object")
    return resource


def resources(bundle, resource_type):
    if not isinstance(bundle, dict) or bundle.get("resourceType") != "Bundle":
        raise RuntimeError("FHIR search did not return a Bundle")
    entries = bundle.get("entry", [])
    if not isinstance(entries, list):
        raise RuntimeError("FHIR search entries are not an array")
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("resource", {}), dict):
            raise RuntimeError("FHIR search entry is not a resource object")
        resource = entry.get("resource", {})
        if resource.get("resourceType") == resource_type:
            yield resource


def main():
    coverage_selection = None
    coverage_bundle = read_fhir(
        "Coverage",
        {"status": "active", "_count": "100"},
    )
    for coverage in resources(coverage_bundle, "Coverage"):
        coverage_id = coverage.get("id")
        beneficiary = coverage.get("beneficiary", {})
        if not isinstance(beneficiary, dict):
            continue
        reference = beneficiary.get("reference", "")
        if (
            coverage.get("status") != "active"
            or not isinstance(coverage_id, str)
            or not FHIR_ID.fullmatch(coverage_id)
            or not isinstance(reference, str)
            or not reference.startswith("Patient/")
        ):
            continue
        patient_id = reference.removeprefix("Patient/")
        if not FHIR_ID.fullmatch(patient_id):
            continue
        patient = read_fhir(f"Patient/{patient_id}", missing_ok=True)
        if (
            patient is not None
            and patient.get("resourceType") == "Patient"
            and patient.get("id") == patient_id
        ):
            coverage_selection = {
                "subjects": [
                    {"role": "patient", "field": "patient_id", "value": patient_id},
                    {
                        "role": "coverage-record",
                        "field": "coverage_id",
                        "value": coverage_id,
                    },
                ]
            }
            break

    organization_selection = None
    organization_bundle = read_fhir(
        "Organization",
        {
            "active": "true",
            "type": f"{ORGANIZATION_TYPE_SYSTEM}|prov",
            "_count": "100",
        },
    )
    for organization in resources(organization_bundle, "Organization"):
        organization_id = organization.get("id")
        organization_types = organization.get("type", [])
        if (
            not isinstance(organization_types, list)
            or not 1 <= len(organization_types) <= 4
            or not all(isinstance(item, dict) for item in organization_types)
        ):
            continue
        coding_groups = [
            organization_type.get("coding", [])
            for organization_type in organization_types
        ]
        if not all(
            isinstance(group, list)
            and 1 <= len(group) <= 8
            and all(isinstance(coding, dict) for coding in group)
            for group in coding_groups
        ):
            continue
        codings = [
            coding
            for coding_group in coding_groups
            for coding in coding_group
        ]
        if (
            organization.get("active") is True
            and isinstance(organization_id, str)
            and FHIR_ID.fullmatch(organization_id)
            and len(codings) == 1
            and codings[0].get("system") == ORGANIZATION_TYPE_SYSTEM
            and codings[0].get("code") == "prov"
        ):
            organization_selection = {
                "subjects": [
                    {
                        "role": "organization",
                        "field": "organization_id",
                        "value": organization_id,
                    }
                ]
            }
            break

    if coverage_selection is None or organization_selection is None:
        raise RuntimeError("no coherent tutorial records are currently available")

    for path, selection in [
        ("fhir-coverage-subjects.json", coverage_selection),
        ("fhir-organization-subjects.json", organization_selection),
    ]:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            json.dump(selection, destination, separators=(",", ":"))
            destination.write("\n")

    print("Coverage selector file: ready")
    print("Organization selector file: ready")


if __name__ == "__main__":
    main()
