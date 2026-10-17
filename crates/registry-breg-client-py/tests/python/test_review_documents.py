"""A Review display grant downloads its own projected document without Get."""
import copy
import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode, urlsplit, parse_qs
from bootstrap import ensure_built

ensure_built()
from registry_breg_client import BaseRegistryClient, BaseRegistryClientError, BRegProposalReviewBinding


class ReviewDocumentTests(unittest.TestCase):
    def test_review_only_context_download_and_local_binding_refusals(self):
        identifier = '00000000-0000-4000-8000-000000000001'
        concealed_id = '00000000-0000-4000-8000-000000000002'
        malformed_batch = False
        revision = 'sha256:' + 'a' * 64
        body = b'%PDF-1.7 synthetic review document'
        requests = []
        metadata = {'id': 'review-documents', 'version': '1', 'revision': revision,
                    'metadataVersion': '2', 'recordTypes': [], 'operations': [], 'actions': [],
                    'proposals': {'actions': [
                        {'actionId': 'correct', 'accessProfile': 'reviewer', 'operations': ['get-review-context'], 'readableInputs': []},
                        {'actionId': 'correct', 'accessProfile': 'status', 'operations': ['get-review-status'], 'readableInputs': []}]}}
        query = urlencode({'submissionVersion': '1', 'reviewContextField': 'support',
                           'effectDigest': revision, 'contextSchemaDigest': revision})
        context = {'id': identifier, 'actionId': 'correct', 'actionRevision': revision,
                   'submissionVersion': 1, 'revision': 2, 'effectDigest': revision, 'reviewable': True,
                   'subject': {'source': 'review-documents', 'subjectType': 'proposal', 'id': identifier,
                               'version': '1', 'digest': revision},
                   'context': {'reference': 'opaque',
                               'contract': {'id': 'urn:registry:breg:review-context:review-documents:correct:review',
                                            'revision': revision, 'schemaDigest': revision},
                               'fields': {'support': {'type': 'document', 'slotId': 'support',
                                                      'sha256': hashlib.sha256(body).hexdigest(),
                                                      'contentType': 'application/pdf', 'byteSize': len(body),
                                                      'download': {'method': 'GET', 'operation': 'get-review-context',
                                                                   'accessProfile': 'reviewer',
                                                                   'path': f'/v1/proposals/{identifier}/attachments/support?{query}'}}}}}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                requests.append(self.path)
                attachment = '/attachments/' in self.path
                batch = {'items': [] if malformed_batch else [
                    {'id': identifier, 'status': 'visible', 'context': context},
                    {'id': concealed_id, 'status': 'concealed'}]}
                payload = body if attachment else json.dumps(
                    metadata if '/registry?' in self.path else batch
                    if '/proposals/review-context?' in self.path else context).encode()
                self.send_response(200)
                for name, value in [('content-type', 'application/pdf' if attachment else 'application/json'),
                                    ('content-length', str(len(payload))), ('cache-control', 'no-store'),
                                    ('vary', 'authorization' if attachment else 'authorization, accept'),
                                    ('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01')]:
                    self.send_header(name, value)
                if attachment:
                    self.send_header('content-disposition', 'attachment')
                    self.send_header('x-content-type-options', 'nosniff')
                self.end_headers()
                self.wfile.write(payload)

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = BaseRegistryClient(base_url=f'http://127.0.0.1:{server.server_port}/tenant/')
            contract = client.registry_contract('reviewer')
            with self.assertRaises(BaseRegistryClientError):
                contract.select_proposal_get('reviewer')
            binding = contract.select_proposal_review_context('reviewer', 'correct')
            self.assertIsInstance(binding, BRegProposalReviewBinding)
            observed = client.read_proposal_review_by_id(binding, identifier)['value']
            batch = client.read_proposal_review_context_batch(binding, [identifier, concealed_id])
            self.assertEqual(batch['value'], [observed, None])
            batch_url = urlsplit(requests[-1])
            self.assertEqual(batch_url.path, '/tenant/v1/proposals/review-context')
            self.assertEqual(parse_qs(batch_url.query)['ids'], [f'{identifier},{concealed_id}'])
            self.assertEqual(parse_qs(batch_url.query)['accessProfile'], ['reviewer'])
            before_batch_refusals = len(requests)
            for ids in [[], [identifier, identifier]]:
                with self.assertRaises(BaseRegistryClientError):
                    client.read_proposal_review_context_batch(binding, ids)
            with self.assertRaises(BaseRegistryClientError):
                client.read_proposal_review_context_batch(
                    contract.select_proposal_review_status('status', 'correct'), [identifier])
            self.assertEqual(len(requests), before_batch_refusals)
            malformed_batch = True
            with self.assertRaises(BaseRegistryClientError):
                client.read_proposal_review_context_batch(binding, [identifier, concealed_id])
            malformed_batch = False
            downloaded = client.download_proposal_review_document(binding, observed, 'support')
            self.assertEqual(downloaded['body'], body)
            self.assertEqual(downloaded['media_type'], 'application/pdf')
            url = urlsplit(requests[-1])
            self.assertEqual(url.path, f'/tenant/v1/proposals/{identifier}/attachments/support')
            self.assertEqual(parse_qs(url.query)['accessProfile'], ['reviewer'])
            before = len(requests)
            tampered = copy.deepcopy(observed)
            tampered['context']['fields']['support']['download']['path'] = 'https://untrusted.invalid/file'
            with self.assertRaises(BaseRegistryClientError):
                client.download_proposal_review_document(binding, tampered, 'support')
            with self.assertRaises(BaseRegistryClientError):
                client.download_proposal_review_document(contract.select_proposal_review_status('status', 'correct'), observed, 'support')
            self.assertEqual(len(requests), before)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
