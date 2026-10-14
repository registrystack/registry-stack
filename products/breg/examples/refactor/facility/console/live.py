"""Execute the generated Python adapter against the PostgreSQL proving fixture."""
import ctypes
import os
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[6]
runtime = os.environ.get('REGISTRY_CARGO_RUNTIME_LIBRARY_PATH')
if runtime:
    for library in Path(runtime).glob('libaws_lc_fips*_crypto.dylib'):
        ctypes.CDLL(str(library), mode=ctypes.RTLD_GLOBAL)
sys.path.insert(0, os.environ['BREG_PYTHON_MODULE_ROOT'])
sys.path.insert(0, str(root / 'products/breg/generated/refactor/generated/sdk'))
from registry_breg_client import BaseRegistryClient
from project import ProjectClient
from console import facility_console

def client(url, profile):
    return ProjectClient(BaseRegistryClient(os.environ[url]), profile)

reader = client('BREG_READER_URL', 'facility-reader')
registrar = client('BREG_REGISTRAR_URL', 'facility-registrar')
author = client('BREG_AUTHOR_URL', 'facility-correction-author')
applier = client('BREG_APPLIER_URL', 'facility-correction-applier')
identifier = os.environ['BREG_FACILITY_ID']
result = facility_console(reader, registrar, author, identifier,
    {'facilityCode':'LIVE-CONSOLE','name':'Second clinic','addressLine':'2 Main Road','city':'Bangkok','postalCode':'10200','operatorId':os.environ['BREG_OPERATOR_ID'],'jurisdiction':'zone-a'},
    {'facilityId':identifier,'addressLine':'3 Main Road','city':'Bangkok','postalCode':'10200'})
assert result['title'] == 'Live clinic'
assert result['operator']['title'] == 'OP-LIVE'
redacted = client('BREG_REDACTED_URL', 'fixture-redacted-reader').read('facility', identifier)
assert redacted['title'] == identifier
assert 'name' not in redacted['data']
assert result['proposal'].document['state'] == 'submitted'
draft = author.deactivate_facility({'facilityId':identifier}, 'live-deactivate')
submitted = author.execute(author.prepare(draft, 'submit', {}, 'live-deactivate-submit'))
current = next(item for item in applier.list_proposals('deactivate-facility')['items'] if item.document['id'] == submitted.document['id'])
assert current.document['links']['apply']['availability']['available']
attempt = applier.prepare(current, 'apply', {'submissionVersion':current.document['submissionVersion'],'effectDigest':current.document['effectDigest']}, 'live-deactivate-apply')
applied = applier.execute(attempt)
assert applied.document['state'] == 'applied'
assert applier.execute(attempt).document['application']['applicationId'] == applied.document['application']['applicationId']
assert reader.read('facility', identifier)['data']['status'] == 'inactive'
print('generated Python console live PostgreSQL journey passed')
