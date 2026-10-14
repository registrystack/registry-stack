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


if __name__ == '__main__':
    unittest.main()
