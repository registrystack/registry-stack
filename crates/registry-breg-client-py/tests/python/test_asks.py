"""Ask answers use the canonical Rust command contract."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from bootstrap import ensure_built

ensure_built()
from registry_breg_client import BaseRegistryClient, BaseRegistryClientError


class AskTests(unittest.TestCase):
    def test_answer_uses_the_promoted_ask_etag_and_caller_key(self):
        proposal = '00000000-0000-4000-8000-000000000001'
        ask = '00000000-0000-4000-8000-000000000007'
        digest = 'sha256:' + 'a' * 64
        metadata = {'id': 'asks', 'version': '1', 'revision': digest, 'metadataVersion': '2', 'recordTypes': [], 'operations': [], 'actions': [],
                    'proposals': {'actions': [{'actionId': 'correct', 'accessProfile': 'author', 'operations': ['get', 'answer'], 'readableInputs': [], 'readableContextFields': []}],
                                  'get': {'method': 'GET', 'path': '/v1/proposals/{proposal_id}', 'accessProfiles': ['author']}}}
        document = {'id': proposal, 'actionId': 'correct', 'actionRevision': digest, 'submissionVersion': 1, 'revision': 2, 'state': 'submitted', 'effectDigest': digest, 'links': {},
                    'asks': [{'id': ask, 'text': 'Why?', 'wants': [{'kind': 'answer'}], 'askedAt': '2026-11-27T00:00:00Z', 'state': 'open', 'links': {
                        'answer': {'method': 'POST', 'path': f'/v1/proposals/{proposal}/asks/{ask}/answer', 'accessProfile': 'author', 'operation': 'answer', 'ifMatch': '"condition"', 'availability': {'available': True, 'observedRevision': 2}}}}]}
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(('GET', self.path, dict(self.headers), None))
                self.respond(metadata if '/registry?' in self.path else document)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['content-length'])))
                requests.append(('POST', self.path, dict(self.headers), body))
                document['revision'] = 3
                document['asks'][0]['state'] = 'answered'
                document['asks'][0]['answer'] = {**body, 'additions': [], 'answeredAt': '2026-11-27T01:00:00Z'}
                document['asks'][0]['links']['answer']['availability'] = {'available': False, 'observedRevision': 3, 'reason': 'ask-answered', 'recovery': 'receipt-only'}
                self.respond(document)

            def respond(self, value):
                payload = json.dumps(value).encode()
                self.send_response(200)
                for key, value in [('content-type', 'application/json'), ('cache-control', 'no-store'), ('vary', 'authorization, accept'),
                                   ('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'), ('content-length', str(len(payload)))]:
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                return

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = BaseRegistryClient(f'http://127.0.0.1:{server.server_port}/tenant/')
            self.assertTrue(hasattr(client, 'answer_proposal_ask'))
            contract = client.registry_contract('author')
            prior = client.get_proposal(contract.select_proposal_get('author'), proposal)
            before = len(requests)
            with self.assertRaises(BaseRegistryClientError):
                client.answer_proposal_ask(prior, ask, {'text': ' '}, 'invalid')
            self.assertEqual(len(requests), before)
            document['asks'][0]['wants'] = []
            without_wants = client.get_proposal(contract.select_proposal_get('author'), proposal)
            before_empty = len(requests)
            for body in [{}, {'additions': []}]:
                with self.assertRaises(BaseRegistryClientError):
                    client.answer_proposal_ask(without_wants, ask, body, 'empty')
            self.assertEqual(len(requests), before_empty)
            document['asks'][0]['wants'] = [{'kind': 'answer'}]
            answered = client.answer_proposal_ask(prior, ask, {'text': 'The explanation'}, 'answer-one')
            self.assertEqual(answered.document['asks'][0]['answer']['text'], 'The explanation')
            wire = requests[-1]
            self.assertEqual(wire[1], f'/tenant/v1/proposals/{proposal}/asks/{ask}/answer?accessProfile=author')
            headers = {key.lower(): value for key, value in wire[2].items()}
            self.assertEqual(headers['if-match'], '"condition"')
            self.assertEqual(headers['idempotency-key'], 'answer-one')
            self.assertEqual(wire[3], {'text': 'The explanation'})
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
