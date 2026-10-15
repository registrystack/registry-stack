"""Promoted Proposal Get works independently of List and Start authority."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from bootstrap import ensure_built

ensure_built()
from registry_breg_client import BaseRegistryClient, BaseRegistryClientError

ID = '00000000-0000-4000-8000-000000000001'
REVISION = 'sha256:' + 'a' * 64
METADATA = {
    'id': 'proposal-lookup', 'version': '1', 'revision': REVISION,
    'metadataVersion': '1', 'recordTypes': [], 'operations': [], 'actions': [],
    'proposals': {'method': 'GET', 'path': '/v1/proposals', 'accessProfiles': [],
                  'get': {'method': 'GET', 'path': '/v1/proposals/{proposal_id}', 'accessProfiles': ['reader']}},
}
PROPOSAL = {
    'id': ID, 'actionId': 'correct', 'actionRevision': REVISION,
    'submissionVersion': 1, 'revision': 2, 'state': 'draft',
    'input': {'addressLine': 'Disclosed address'},
    'links': {'self': {'method': 'GET', 'path': '/v1/proposals/' + ID,
                       'accessProfile': 'reader', 'operation': 'get'}},
}


class ProposalLookupTests(unittest.TestCase):
    def test_get_only_capability_retains_origin_prefix_and_projection(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                value = METADATA if self.path.startswith('/tenant/v1/registry') else PROPOSAL
                payload = json.dumps(value).encode()
                self.send_response(200)
                for key, val in [('content-type', 'application/json'), ('cache-control', 'no-store'),
                                 ('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'),
                                 ('vary', 'authorization, accept'), ('content-length', str(len(payload)))]:
                    self.send_header(key, val)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = BaseRegistryClient(f'http://127.0.0.1:{server.server_port}/tenant/')
            metadata = client.registry_contract('reader')
            with self.assertRaises(BaseRegistryClientError):
                metadata.select_proposals('reader')
            binding = metadata.select_proposal_get('reader')
            proposal = client.get_proposal(binding, ID)
            self.assertEqual(proposal.input, {'addressLine': 'Disclosed address'})
            self.assertEqual(requests[-1], f'/tenant/v1/proposals/{ID}?accessProfile=reader')
            count = len(requests)
            for identifier in ['../secret', '00000000-0000-4000-8000-00000000000A']:
                with self.assertRaises(BaseRegistryClientError):
                    client.get_proposal(binding, identifier)
            other = BaseRegistryClient(f'http://127.0.0.1:{server.server_port}/other/')
            with self.assertRaises(BaseRegistryClientError):
                other.get_proposal(binding, ID)
            self.assertEqual(len(requests), count)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


class ProposalPageTests(unittest.TestCase):
    def test_returned_cursors_are_usable_for_explicit_bounded_continuation(self):
        value = {'items': []}
        requests = []
        metadata = dict(METADATA, proposals=dict(METADATA['proposals'], accessProfiles=['reader']))

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                payload = json.dumps(metadata if self.path.startswith('/tenant/v1/registry') else value).encode()
                self.send_response(200)
                for key, val in [('content-type', 'application/json'), ('cache-control', 'no-store'),
                                 ('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'),
                                 ('vary', 'authorization, accept'), ('content-length', str(len(payload)))]:
                    self.send_header(key, val)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = BaseRegistryClient(f'http://127.0.0.1:{server.server_port}/tenant/')
            collection = client.registry_contract('reader').select_proposals('reader')
            for cursor in ['', ' ', 'cursor\nvalue', 'cursor\tvalue', 'é', 'x' * 513]:
                value = {'items': [], 'nextCursor': cursor}
                count = len(requests)
                with self.assertRaises(BaseRegistryClientError) as raised:
                    client.list_proposals(collection, {})
                self.assertEqual(raised.exception.kind, 'invalid-request')
                self.assertEqual(len(requests), count + 1)
            for cursor in [ID, 'x' * 512]:
                value = {'items': [], 'nextCursor': cursor}
                page = client.list_proposals(collection, {})
                self.assertEqual(page.next_cursor, cursor)
                value = {'items': []}
                final_page = client.list_proposals(collection, {'cursor': page.next_cursor})
                self.assertIn('cursor=' + cursor, requests[-1])
                self.assertIsNone(final_page.next_cursor)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


class ProposalStartTests(unittest.TestCase):
    def test_start_accepts_exact_draft_replay_but_refuses_valid_non_draft_responses(self):
        value = dict(PROPOSAL, state='draft', submissionVersion=1)
        requests = []
        metadata = dict(METADATA, actions=[{
            'id': 'correct', 'apiName': 'correct', 'revision': REVISION, 'display': {}, 'execution': {'mode': 'proposal'},
            'route': '/v1/actions/correct/proposals', 'inputMode': 'fixed', 'inputs': [], 'referenceInputs': [],
            'requiredConditionKeys': [], 'resultEffects': [], 'access': {'selectedProfile': 'reader'},
            'routes': {'start': {'method': 'POST', 'path': '/v1/actions/correct/proposals', 'operationId': 'actions.correct.start',
                                 'requiresIdempotencyKey': True, 'inputSchema': 'action-correct-invoke-input', 'responseSchema': 'action-correct-invoke-response'}},
            'bounds': {'maximumTargets': 16, 'maximumFieldMutations': 128, 'maximumSnapshotBytes': 2097152}}])

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.respond()

            def do_POST(self):
                self.respond()

            def respond(self):
                body = self.rfile.read(int(self.headers.get('content-length', '0')))
                requests.append((self.path, body, self.headers.get('idempotency-key')))
                payload = json.dumps(metadata if self.path.startswith('/tenant/v1/registry') else value).encode()
                self.send_response(201 if self.command == 'POST' else 200)
                for key, val in [('content-type', 'application/json'), ('cache-control', 'no-store'),
                                 ('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'),
                                 ('vary', 'authorization, accept'), ('content-length', str(len(payload)))]:
                    self.send_header(key, val)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = BaseRegistryClient(f'http://127.0.0.1:{server.server_port}/tenant/')
            contract = client.registry_contract('reader')
            start = contract.select_action('correct', 'reader')
            get = contract.select_proposal_get('reader')
            first = client.start_proposal(start, {}, 'exact-draft-start')
            repeated = client.start_proposal(start, {}, 'exact-draft-start')
            self.assertEqual(first.document, repeated.document)
            self.assertEqual(requests[-1], requests[-2])
            for state in ['submitted', 'applied', 'cancelled']:
                value = dict(PROPOSAL, state=state, submissionVersion=1)
                if state == 'submitted':
                    value['effectDigest'] = REVISION
                self.assertEqual(client.get_proposal(get, ID).document['state'], state)
                count = len(requests)
                with self.assertRaises(BaseRegistryClientError) as raised:
                    client.start_proposal(start, {}, 'wrong-start-' + state)
                self.assertEqual(raised.exception.kind, 'invalid-request')
                self.assertEqual(len(requests), count + 1)
                self.assertEqual(requests[-1][0], '/tenant/v1/actions/correct/proposals?accessProfile=reader')
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
