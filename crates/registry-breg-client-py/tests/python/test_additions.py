"""Supporting-file additions use the canonical Rust binary contract."""
import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from bootstrap import ensure_built

ensure_built()
from registry_breg_client import BaseRegistryClient, BaseRegistryClientError


class AdditionTests(unittest.TestCase):
    def test_addition_and_download_keep_the_exact_submission(self):
        proposal_id = '00000000-0000-4000-8000-000000000001'
        addition_id = '00000000-0000-4000-8000-000000000002'
        revision = 'sha256:' + 'a' * 64
        content = b'support'
        requests = []
        metadata = {'id': 'additions', 'version': '1', 'revision': revision, 'metadataVersion': '2',
                    'recordTypes': [], 'operations': [], 'actions': [], 'proposals': {
                        'actions': [{'actionId': 'correct', 'accessProfile': 'writer', 'operations': ['get'], 'readableInputs': [], 'readableContextFields': []}],
                        'get': {'method': 'GET', 'path': '/v1/proposals/{proposal_id}', 'accessProfiles': ['writer']}}}
        document = {'id': proposal_id, 'actionId': 'correct', 'actionRevision': revision, 'submissionVersion': 1,
                    'revision': 2, 'state': 'submitted', 'effectDigest': revision, 'links': {}, 'additions': {'other': {
                        'id': 'other', 'maximumBytes': 64, 'maximumCount': 2, 'contentTypes': ['text/plain'],
                        'classification': 'restricted', 'items': [], 'links': {'add': {'method': 'POST',
                            'path': f'/v1/proposals/{proposal_id}/additions/other', 'accessProfile': 'writer', 'operation': 'add', 'ifMatch': '"condition"'}}}}}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(('GET', self.path, dict(self.headers), b''))
                if f'/additions/{addition_id}?' in self.path:
                    self.respond(content, 'text/plain', True)
                else:
                    self.respond(json.dumps(metadata if '/registry?' in self.path else document).encode())

            def do_POST(self):
                body = self.rfile.read(int(self.headers['content-length']))
                requests.append(('POST', self.path, dict(self.headers), body))
                document['revision'] += 1
                document['additions']['other']['items'].append({'id': addition_id, 'submissionVersion': 1,
                    'sha256': hashlib.sha256(content).hexdigest(), 'byteSize': len(content), 'contentType': 'text/plain',
                    'addedAt': '2026-11-27T00:00:00Z', 'verificationStatus': 'notRequired', 'links': {'download': {
                        'method': 'GET', 'path': f'/v1/proposals/{proposal_id}/additions/{addition_id}?submissionVersion=1',
                        'accessProfile': 'writer', 'operation': 'download'}}})
                self.respond(json.dumps(document).encode())

            def respond(self, payload, media='application/json', download=False):
                self.send_response(200)
                for key, value in [('content-type', media), ('cache-control', 'no-store'), ('content-length', str(len(payload))),
                                   ('vary', 'authorization' if download else 'authorization, accept'),
                                   ('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01')]:
                    self.send_header(key, value)
                if download:
                    self.send_header('content-disposition', 'attachment')
                    self.send_header('x-content-type-options', 'nosniff')
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                return

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = BaseRegistryClient(f'http://127.0.0.1:{server.server_port}/tenant/')
            self.assertTrue(hasattr(client, 'add_proposal_addition'))
            self.assertTrue(hasattr(client, 'download_proposal_addition'))
            contract = client.registry_contract('writer')
            prior = client.get_proposal(contract.select_proposal_get('writer'), proposal_id)
            before = len(requests)
            with self.assertRaises(BaseRegistryClientError):
                client.add_proposal_addition(prior, 'other', 'application/pdf', content, 'refused')
            self.assertEqual(len(requests), before)
            added = client.add_proposal_addition(prior, 'other', 'text/plain', content, 'addition-one')
            self.assertEqual(added.document['submissionVersion'], 1)
            self.assertEqual(client.download_proposal_addition(added, addition_id)['body'], content)
            upload = requests[before]
            self.assertEqual(upload[0], 'POST')
            self.assertEqual(upload[1], f'/tenant/v1/proposals/{proposal_id}/additions/other?accessProfile=writer')
            self.assertEqual(upload[3], content)
            headers = {key.lower(): value for key, value in upload[2].items()}
            self.assertEqual(headers['if-match'], '"condition"')
            self.assertEqual(headers['idempotency-key'], 'addition-one')
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
