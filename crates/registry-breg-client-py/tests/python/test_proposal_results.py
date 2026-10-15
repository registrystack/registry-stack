"""Native Proposal receipts, disclosure and exact protected recovery."""
import copy
import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from bootstrap import ensure_built

ensure_built()
from registry_breg_client import BaseRegistryClient, BaseRegistryClientError, BRegPreparedProposal

ID = '00000000-0000-4000-8000-000000000001'
TARGET = '00000000-0000-4000-8000-000000000003'
DIGEST = 'sha256:' + 'a' * 64
METADATA = {'id': 'registry', 'version': '1', 'revision': DIGEST, 'metadataVersion': '1', 'recordTypes': [], 'operations': [],
            'proposals': {'method': 'GET', 'path': '/v1/proposals', 'accessProfiles': [],
                          'get': {'method': 'GET', 'path': '/v1/proposals/{proposal_id}', 'accessProfiles': ['reader']}}}


def document():
    return {'id': ID, 'actionId': 'correct', 'actionRevision': DIGEST, 'submissionVersion': 2, 'revision': 8, 'state': 'applied',
            'effectDigest': DIGEST, 'links': {'self': {'method': 'GET', 'path': '/v1/proposals/' + ID, 'accessProfile': 'reader', 'operation': 'get'}},
            'application': {'applicationId': ID, 'submissionVersion': 2, 'effectDigest': DIGEST,
                            'resultLinks': [{'recordType': 'person', 'recordId': TARGET, 'revision': 4}]}}


def status_document(state):
    value = document()
    value['state'] = state if state in ('applied', 'cancelled') else 'submitted'
    if state != 'applied':
        del value['application']
    status = {'state': state, 'mode': 'automatic'}
    if state in ('pending', 'blocked'):
        status['automaticRetry'] = {'scheduled': state == 'pending', 'attempts': 0 if state == 'pending' else 1, 'maximumAttempts': 3}
    if state == 'blocked':
        status.update(reason='dependency-outage', recovery='retry')
    value['applicationStatus'] = status
    return value


class ProposalResultTests(unittest.TestCase):
    def setUp(self):
        self.value = document()
        self.requests = []
        self.download_bytes = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.respond()

            def do_POST(self):
                self.respond()

            def do_PATCH(self):
                self.respond()

            def do_DELETE(self):
                self.respond()

            def respond(self):
                body = self.rfile.read(int(self.headers.get('content-length', '0')))
                owner.requests.append((self.path, dict(self.headers), body))
                if owner.download_bytes is not None and self.command == 'GET' and '/attachments/' in self.path:
                    self.send_response(200)
                    for key, value in [('content-type', 'application/pdf'), ('content-disposition', 'attachment'), ('x-content-type-options', 'nosniff'),
                                       ('cache-control', 'no-store'), ('vary', 'authorization'),
                                       ('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'), ('content-length', str(len(owner.download_bytes)))]:
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(owner.download_bytes)
                    return
                payload = json.dumps(METADATA if self.path.startswith('/tenant/v1/registry') else owner.value).encode()
                self.send_response(200)
                for key, value in [('content-type', 'application/json'), ('cache-control', 'no-store'), ('vary', 'authorization, accept'),
                                   ('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'), ('content-length', str(len(payload)))]:
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BaseRegistryClient(f'http://127.0.0.1:{self.server.server_port}/tenant/')
        self.binding = self.client.registry_contract('reader').select_proposal_get('reader')

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_authorized_result_references_are_inert_and_redacted(self):
        proposal = self.client.get_proposal(self.binding, ID)
        self.assertEqual(proposal.document['application']['resultLinks'], [{'recordType': 'person', 'recordId': TARGET, 'revision': 4}])
        for secret in [ID, TARGET, 'person']:
            self.assertNotIn(secret, repr(proposal))
        count = len(self.requests)
        with self.assertRaises(BaseRegistryClientError):
            self.client.prepare_proposal(proposal, 'apply', {}, 'ungranted')
        self.assertEqual(len(self.requests), count)
        self.value['application']['resultLinks'] = []
        self.assertEqual(self.client.get_proposal(self.binding, ID).document['application']['resultLinks'], [])
        del self.value['application']
        self.assertNotIn('application', self.client.get_proposal(self.binding, ID).document)

    def test_application_status_preserves_current_progress_and_retained_evidence_absence(self):
        for state in ('pending', 'blocked', 'applied', 'cancelled'):
            self.value = status_document(state)
            with self.subTest(state=state):
                observed = self.client.get_proposal(self.binding, ID).document
                self.assertEqual(observed['applicationStatus'], self.value['applicationStatus'])
                self.assertEqual(observed['submissionVersion'], 2)
                self.assertEqual(observed['effectDigest'], DIGEST)
        for state in ('applied', 'cancelled'):
            self.value = status_document(state)
            for field in ('applicationStatus', 'application', 'effectDigest'):
                self.value.pop(field, None)
            with self.subTest(erased_state=state):
                observed = self.client.get_proposal(self.binding, ID).document
                self.assertNotIn('applicationStatus', observed)

    def test_malformed_and_widened_receipts_are_refused(self):
        for path, value in [(('submissionVersion',), 1), (('effectDigest',), 'sha256:UPPERCASE'),
                            (('resultLinks', 0, 'revision'), 0), (('resultLinks', 0, 'recordId'), 'not-a-uuid'),
                            (('actorReference',), 'private-canary'), (('reason',), 'private-canary'),
                            (('resultLinks', 0, 'href'), 'https://elsewhere.invalid/private')]:
            self.value = document()
            target = self.value['application']
            for member in path[:-1]:
                target = target[member]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(BaseRegistryClientError):
                self.client.get_proposal(self.binding, ID)

    def test_exact_input_and_prepared_edit_recovery(self):
        self.value = document()
        self.value.update(state='draft', input={'wide': 9007199254740993, 'decimal': '12.3400', 'nullable': None})
        del self.value['application']
        self.value['links']['edit'] = {'method': 'POST', 'path': '/v1/proposals/' + ID + '/edit', 'accessProfile': 'reader', 'operation': 'edit', 'ifMatch': '"edit-condition"'}
        proposal = self.client.get_proposal(self.binding, ID)
        self.assertEqual(proposal.input, self.value['input'])
        self.assertNotIn('undisclosed', proposal.input)
        body = {'input': copy.deepcopy(proposal.input)}
        prepared = self.client.prepare_proposal(proposal, 'edit', body, 'exact-edit')
        saved = prepared.to_bytes()
        self.assertEqual(repr(prepared), 'BRegPreparedProposal(<redacted>)')
        restored = BRegPreparedProposal.from_bytes(saved)
        count = len(self.requests)
        with self.assertRaises(BaseRegistryClientError):
            self.client.execute_proposal(restored)
        self.assertEqual(len(self.requests), count)
        recovered = self.client.recover_proposal(self.client.read_proposal(proposal), restored)
        self.assertEqual(recovered.to_bytes(), saved)
        self.client.execute_proposal(recovered)
        path, headers, wire = self.requests[-1]
        headers = {key.lower(): value for key, value in headers.items()}
        self.assertEqual(path, '/tenant/v1/proposals/' + ID + '/edit?accessProfile=reader')
        self.assertEqual(json.loads(wire), body)
        self.assertIn(b'9007199254740993', wire)
        self.assertEqual(headers['if-match'], '"edit-condition"')
        self.assertEqual(headers['idempotency-key'], 'exact-edit')


    def test_promoted_review_status_refuses_display_fields_but_context_preserves_them(self):
        self.value = document()
        self.value['state'] = 'submitted'
        del self.value['application']
        for name, suffix, operation in [('reviewStatus', 'review-status', 'get-review-status'), ('reviewContext', 'review-context', 'get-review-context')]:
            self.value['links'][name] = {'method': 'GET', 'path': '/v1/proposals/' + ID + '/' + suffix, 'accessProfile': 'reader', 'operation': operation}
        prior = self.client.get_proposal(self.binding, ID)
        status = {'id': ID, 'actionId': 'correct', 'actionRevision': DIGEST, 'submissionVersion': 2, 'revision': 8, 'effectDigest': DIGEST,
                  'subject': {'source': 'directory', 'subjectType': 'proposal', 'id': ID, 'version': '2', 'digest': DIGEST},
                  'context': {'reference': 'breg:directory:correct:proposal:2'}, 'reviewable': True}
        self.value = copy.deepcopy(status)
        self.assertEqual(self.client.read_proposal_review_status(prior)['value']['context'], status['context'])
        for fields in [{}, {'private': 'private-canary'}]:
            self.value = copy.deepcopy(status)
            self.value['context']['fields'] = fields
            count = len(self.requests)
            with self.assertRaises(BaseRegistryClientError) as raised:
                self.client.read_proposal_review_status(prior)
            self.assertEqual(raised.exception.kind, 'invalid-request')
            self.assertNotIn('private-canary', str(raised.exception))
            self.assertEqual(len(self.requests), count + 1)
            self.assertTrue(self.requests[-1][0].endswith('/review-status?accessProfile=reader'))
        self.value['context']['contract'] = {'id': 'urn:registry:breg:review-context:directory:correct:review', 'revision': DIGEST, 'schemaDigest': DIGEST}
        self.assertEqual(self.client.read_proposal_review_context(prior)['value']['context']['fields'], {'private': 'private-canary'})

    def test_non_rebase_transitions_and_attachment_writes_preserve_action_revision(self):
        successor = 'sha256:' + 'b' * 64
        self.value = document()
        self.value['state'] = 'draft'
        del self.value['application']
        self.value['links']['edit'] = {'method': 'POST', 'path': '/v1/proposals/' + ID + '/edit', 'accessProfile': 'reader', 'operation': 'edit', 'ifMatch': '"edit-condition"'}
        self.value['attachments'] = {'support': {'id': 'support', 'required': False, 'maximumBytes': 1024, 'contentTypes': ['application/pdf'], 'classification': 'restricted',
            'links': {name: {'method': method, 'path': '/v1/proposals/' + ID + '/attachments/support', 'accessProfile': 'reader', 'operation': name, 'ifMatch': '"attachment-condition"'}
                      for name, method in [('upload', 'PATCH'), ('remove', 'DELETE')]}}}
        prior = self.client.get_proposal(self.binding, ID)
        current = copy.deepcopy(self.value)
        current['revision'] += 1
        attempt = self.client.prepare_proposal(prior, 'edit', {'input': {}}, 'edit-binding')
        for operation, send in [('edit', lambda: self.client.execute_proposal(attempt)),
                                ('upload', lambda: self.client.upload_proposal_attachment(prior, 'support', 'application/pdf', b'%PDF-fixture', 'upload-binding')),
                                ('remove', lambda: self.client.delete_proposal_attachment(prior, 'support', 'remove-binding'))]:
            self.value = copy.deepcopy(current)
            self.assertEqual(send().document['actionRevision'], DIGEST)
            self.value['actionRevision'] = successor
            count = len(self.requests)
            with self.assertRaises(BaseRegistryClientError) as raised:
                send()
            self.assertEqual(raised.exception.kind, 'invalid-request')
            self.assertEqual(len(self.requests), count + 1)
        self.assertEqual(self.client.read_proposal(prior).document['actionRevision'], successor)

    def test_explicit_rebase_and_exact_recovery_admit_only_next_successor_draft(self):
        for state, before, after in [('draft', 0, 0), ('submitted', 2, 3)]:
            self.value = document()
            self.value.update(state=state, submissionVersion=before)
            del self.value['application']
            self.value['links']['rebase'] = {'method': 'POST', 'path': '/v1/proposals/' + ID + '/rebase', 'accessProfile': 'reader', 'operation': 'rebase', 'ifMatch': '"rebase-condition"',
                                           'availability': {'available': True, 'observedRevision': 8}}
            prior = self.client.get_proposal(self.binding, ID)
            attempt = self.client.prepare_proposal(prior, 'rebase', {'input': {}}, 'rebase-' + state)
            saved = attempt.to_bytes()
            self.value.update(state='draft', submissionVersion=after, revision=9, actionRevision='sha256:' + 'b' * 64)
            self.value['links']['rebase']['availability']['observedRevision'] = 9
            rebased = self.client.execute_proposal(attempt)
            restored = BRegPreparedProposal.from_bytes(saved)
            recovered = self.client.recover_proposal(rebased, restored)
            self.assertEqual(recovered.to_bytes(), saved)
            self.assertEqual(self.client.execute_proposal(recovered).document['actionRevision'], self.value['actionRevision'])
            self.value['revision'] = 10
            self.value['links']['rebase']['availability']['observedRevision'] = 10
            later = self.client.get_proposal(self.binding, ID)
            count = len(self.requests)
            with self.assertRaises(BaseRegistryClientError) as raised:
                self.client.recover_proposal(later, restored)
            self.assertEqual(raised.exception.kind, 'invalid-request')
            self.assertEqual(len(self.requests), count)


    def test_retained_attachment_download_uses_value_size_but_upload_uses_current_policy(self):
        self.download_bytes = b'%PDF-retained'
        self.value = document()
        self.value['state'] = 'draft'
        del self.value['application']
        self.value['attachments'] = {'support': {'id': 'support', 'required': False, 'maximumBytes': 4, 'contentTypes': ['text/plain'], 'classification': 'restricted',
            'value': {'submissionVersion': 2, 'sha256': hashlib.sha256(self.download_bytes).hexdigest(), 'contentType': 'application/pdf', 'byteSize': len(self.download_bytes), 'verificationStatus': 'notRequired'},
            'links': {'download': {'method': 'GET', 'path': '/v1/proposals/' + ID + '/attachments/support?submissionVersion=2', 'accessProfile': 'reader', 'operation': 'download'},
                      'upload': {'method': 'PATCH', 'path': '/v1/proposals/' + ID + '/attachments/support', 'accessProfile': 'reader', 'operation': 'upload', 'ifMatch': '"attachment-condition"'}}}}
        retained = self.client.get_proposal(self.binding, ID)
        self.assertEqual(self.client.download_proposal_attachment(retained, 'support')['body'], self.download_bytes)
        count = len(self.requests)
        for media, body in [('application/pdf', b'%PDF'), ('text/plain', b'12345')]:
            with self.assertRaises(BaseRegistryClientError) as raised:
                self.client.upload_proposal_attachment(retained, 'support', media, body, 'refused-upload')
            self.assertEqual(raised.exception.kind, 'invalid-request')
        self.assertEqual(len(self.requests), count)
        self.client.upload_proposal_attachment(retained, 'support', 'text/plain', b'ok', 'allowed-upload')
        self.download_bytes += b'x'
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.download_proposal_attachment(retained, 'support')
        self.assertEqual(raised.exception.kind, 'transport')
        self.assertEqual(raised.exception.transport_kind, 'response-too-large')


if __name__ == '__main__':
    unittest.main()
