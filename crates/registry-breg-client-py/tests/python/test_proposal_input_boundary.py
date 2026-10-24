"""Native Proposal preflight uses canonical input bytes before protected I/O."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from bootstrap import ensure_built

ensure_built()
from registry_breg_client import BaseRegistryClient, BaseRegistryClientError, BRegPreparedProposal

ID = '00000000-0000-4000-8000-000000000001'
REVISION = 'sha256:' + 'a' * 64
MAXIMUM = 3 * 1024 * 1024
METADATA = {'id': 'proposal-input', 'version': '1', 'revision': REVISION, 'metadataVersion': '2',
            'recordTypes': [], 'operations': [], 'actions': [], 'proposals': {
                'get': {'method': 'GET', 'path': '/v1/proposals/{proposal_id}', 'accessProfiles': ['writer']},
                'actions': [{'actionId': 'correct', 'accessProfile': 'writer',
                             'operations': ['get'], 'readableInputs': [], 'readableContextFields': []}]}}


def input_with_canonical_size(size):
    # JCS expands this exponent while the language's JSON representation stays smaller.
    # Keep the native Python conversion below its 100,000-node limit.
    value = {key: [1e20] * 22000 for key in ['a', 'b', 'c', 'd']}
    padding, remainder = divmod(size - 1936025 - 12, 4)
    for index, key in enumerate(value):
        value[key].append('x' * (padding + (index < remainder)))
    return value


class ProposalInputBoundaryTests(unittest.TestCase):
    def test_canonical_input_bound_in_preparation_and_recovery(self):
        document = None
        requests = []
        bodies = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.answer(METADATA if self.path.startswith('/v1/registry') else document)

            def do_POST(self):
                bodies.append(self.rfile.read(int(self.headers.get('content-length', '0'))))
                requests.append(self.path)
                self.answer(document)

            def answer(self, value):
                payload = json.dumps(value).encode()
                self.send_response(200)
                for key, val in [('content-type', 'application/json'), ('cache-control', 'no-store'),
                                 ('vary', 'authorization, accept'), ('content-length', str(len(payload))),
                                 ('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01')]:
                    self.send_header(key, val)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = BaseRegistryClient(f'http://127.0.0.1:{server.server_port}/')
            get = client.registry_contract('writer').select_proposal_get('writer')
            for operation, state in [('edit', 'draft'), ('revise', 'submitted'),
                                     ('rebase', 'draft'), ('rebase', 'submitted')]:
                with self.subTest(operation=operation, state=state):
                    document = {'id': ID, 'actionId': 'correct', 'actionRevision': REVISION,
                                'submissionVersion': 1, 'revision': 2, 'state': state, 'links': {
                                    'self': {'method': 'GET', 'path': f'/v1/proposals/{ID}',
                                             'accessProfile': 'writer', 'operation': 'get'},
                                    operation: {'method': 'POST', 'path': f'/v1/proposals/{ID}/{operation}',
                                                'accessProfile': 'writer', 'operation': operation,
                                                'ifMatch': '"condition"'}}}
                    if state == 'submitted':
                        document['effectDigest'] = REVISION
                    held = client.get_proposal(get, ID)
                    before = len(requests)
                    oversized = {'input': input_with_canonical_size(MAXIMUM + 1)}
                    self.assertLess(len(json.dumps(oversized, separators=(',', ':')).encode()), 2 * 1024 * 1024)
                    with self.assertRaises(BaseRegistryClientError):
                        client.prepare_proposal(held, operation, oversized, 'bounded-input')
                    attempt = client.prepare_proposal(held, operation,
                                                      {'input': input_with_canonical_size(MAXIMUM)}, 'bounded-input')
                    saved = attempt.to_bytes()
                    restored = BRegPreparedProposal.from_bytes(saved)
                    recovered = client.recover_proposal(held, restored)
                    self.assertEqual(recovered.to_bytes(), saved)
                    invalid = json.loads(saved)
                    invalid['body'] = json.dumps(oversized)
                    with self.assertRaises(BaseRegistryClientError):
                        BRegPreparedProposal.from_bytes(json.dumps(invalid).encode())
                    self.assertEqual(len(requests), before)
                    document.update(state='draft', revision=3, submissionVersion=2 if state == 'submitted' else 1)
                    document.pop('effectDigest', None)
                    client.execute_proposal(recovered)
                    self.assertEqual(len(requests), before + 1)
                    self.assertEqual(bodies[-1], json.loads(saved)['body'].encode())
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
