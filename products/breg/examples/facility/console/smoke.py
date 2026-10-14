"""Execute the generated Python adapter against a local deterministic boundary."""
from types import SimpleNamespace
from console import facility_console
from project import ProjectClient

FACILITY = '00000000-0000-4000-8000-000000000001'
ASSIGNMENT = '00000000-0000-4000-8000-000000000002'
OPERATOR = '00000000-0000-4000-8000-000000000003'
calls = []

def record(identifier, data):
    return {'recordIdentifier': identifier, 'revisionIdentifier': '1', 'domainData': data}

class Native:
    def registry_contract(self, profile):
        return SimpleNamespace(select_action=lambda action, _: (action, profile), select_proposals=lambda _: profile)
    def get_record(self, route, identifier, **options):
        data = {'name': 'Central facility'} if route == 'facilities' else {'facility': FACILITY, 'operator': OPERATOR} if route == 'facility-assignments' else {'operatorCode': 'OP-1'}
        return {'value': {'data': record(identifier, data)}}
    def list_records(self, route, **options):
        assert options['filter'] == f"facility eq '{FACILITY}'"
        return {'value': {'items': [record(ASSIGNMENT, {'facility': FACILITY, 'operator': OPERATOR})]}, 'continuation': 'native-cursor'}
    def continue_list(self, continuation):
        assert continuation == 'native-cursor'
        calls.append('next')
        return {'value': {'items': []}}
    def invoke_action(self, binding, inputs, key, conditions=None):
        calls.append(('invoke', binding))
        return {'value': {'action': binding[0], 'applicationId': FACILITY, 'results': {}}}
    def start_proposal(self, binding, inputs, key):
        calls.append(('start', binding))
        return SimpleNamespace(document={'id': FACILITY, 'state': 'draft'})
    def prepare_proposal(self, proposal, transition, body, key):
        assert transition == 'submit' and body == {}
        return (proposal, key)
    def execute_proposal(self, attempt):
        return SimpleNamespace(document={'id': FACILITY, 'state': 'submitted'})
    def list_proposals(self, collection, query):
        assert collection == 'author' and query['action'] == 'correct-address'
        return SimpleNamespace(items=[SimpleNamespace(document={'id': FACILITY, 'state': 'submitted'})], next_cursor=None)
    def read_proposal(self, proposal):
        calls.append('resume')
        return proposal

native = Native()
reader, registrar, author = (ProjectClient(native, profile) for profile in ('reader', 'registrar', 'author'))
result = facility_console(reader, registrar, author, FACILITY,
    {'facilityCode': 'F-1', 'name': 'Central facility', 'addressLine': 'Main street', 'city': 'Example', 'postalCode': '12345', 'operatorId': OPERATOR, 'jurisdiction': 'local'},
    {'facilityId': FACILITY, 'addressLine': 'Second street', 'city': 'Example', 'postalCode': '12345'})
assert result['title'] == 'Central facility'
assert result['operator']['title'] == 'OP-1'
page = reader.related('facility', FACILITY, 'assignments')
assert page['next']()['items'] == []
assert 'next' in calls and 'resume' in calls
assert ('invoke', ('register-facility', 'registrar')) in calls
assert ('start', ('correct-address', 'author')) in calls
print('generated Python console smoke passed')
