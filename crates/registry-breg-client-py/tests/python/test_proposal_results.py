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
METADATA = {'id': 'registry', 'version': '1', 'revision': DIGEST, 'metadataVersion': '2', 'recordTypes': [], 'operations': [],
            'proposals': {'method': 'GET', 'path': '/v1/proposals', 'accessProfiles': [], 'actions': [],
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
    if state in ('awaiting-review', 'pending', 'blocked'):
        status['automaticRetry'] = {'scheduled': state == 'pending', 'attempts': 0 if state == 'pending' else 1, 'maximumAttempts': 3}
    if state == 'blocked':
        status.update(reason='dependency-outage', recovery='retry')
    value['applicationStatus'] = status
    return value


class ProposalResultTests(unittest.TestCase):
    def setUp(self):
        self.value = document()
        self.reply_status = 200
        self.metadata = copy.deepcopy(METADATA)
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
                payload = json.dumps(owner.metadata if self.path.startswith('/tenant/v1/registry') else owner.value).encode()
                self.send_response(owner.reply_status)
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
        del self.value['effectDigest']
        self.assertNotIn('application', self.client.get_proposal(self.binding, ID).document)

    def test_application_identity_is_canonical_and_preserves_exact_receipt_recovery(self):
        self.value = document()
        self.value['state'] = 'submitted'
        del self.value['application']
        self.value['links']['apply'] = {'method': 'POST', 'path': '/v1/proposals/' + ID + '/apply', 'accessProfile': 'reader', 'operation': 'apply', 'ifMatch': '"apply-condition"'}
        held = self.client.get_proposal(self.binding, ID)
        attempt = self.client.prepare_proposal(held, 'apply', {'submissionVersion': 2, 'effectDigest': DIGEST}, 'canonical-application')
        canonical = '123e4567-e89b-42d3-a456-426614174000'
        receipt = dict(copy.deepcopy(self.value), state='applied', revision=9, application=dict(document()['application'], applicationId=canonical))
        receipt['links']['apply']['availability'] = {'available': False, 'observedRevision': 9, 'reason': 'already-applied', 'recovery': 'receipt-only'}
        for application_id in [canonical.upper(), canonical.replace('-', ''), '00000000-0000-0000-0000-000000000000']:
            self.value = copy.deepcopy(receipt)
            self.value['application']['applicationId'] = application_id
            with self.subTest(application_id=application_id), self.assertRaises(BaseRegistryClientError) as raised:
                self.client.get_proposal(self.binding, ID)
            self.assertEqual(raised.exception.kind, 'invalid-request')
            with self.assertRaises(BaseRegistryClientError) as raised:
                self.client.execute_proposal(attempt)
            self.assertEqual(raised.exception.kind, 'protocol')
            self.assertTrue(raised.exception.outcome_unknown)
        self.value = receipt
        committed = self.client.execute_proposal(attempt)
        self.assertEqual(committed.document['application']['applicationId'], canonical)
        sent = self.requests[-1]
        recovered = self.client.recover_proposal(committed, BRegPreparedProposal.from_bytes(attempt.to_bytes()))
        self.assertEqual(recovered.to_bytes(), attempt.to_bytes())
        self.client.execute_proposal(recovered)
        self.assertEqual(self.requests[-1], sent)

    def test_attachment_availability_requires_complete_unavailable_details(self):
        self.value = document()
        self.value['state'] = 'draft'
        del self.value['application']
        del self.value['effectDigest']
        self.value['links']['edit'] = {'method': 'POST', 'path': '/v1/proposals/' + ID + '/edit', 'accessProfile': 'reader', 'operation': 'edit', 'ifMatch': '"edit-condition"'}
        self.value['attachments'] = {'support': {'id': 'support', 'required': False, 'maximumBytes': 1024, 'contentTypes': ['application/pdf'], 'classification': 'restricted',
            'links': {'upload': {'method': 'PATCH', 'path': '/v1/proposals/' + ID + '/attachments/support', 'accessProfile': 'reader', 'operation': 'upload', 'ifMatch': '"upload-condition"'}}}}
        held = self.client.get_proposal(self.binding, ID)
        attempt = self.client.prepare_proposal(held, 'edit', {'input': {}}, 'availability-edit')
        original = copy.deepcopy(self.value)
        for missing in ['reason', 'recovery']:
            self.value = copy.deepcopy(original)
            availability = {'available': False, 'observedRevision': 8, 'reason': 'stale-revision', 'recovery': 'refresh'}
            del availability[missing]
            self.value['attachments']['support']['links']['upload']['availability'] = availability
            with self.subTest(missing=missing), self.assertRaises(BaseRegistryClientError) as raised:
                self.client.get_proposal(self.binding, ID)
            self.assertEqual(raised.exception.kind, 'invalid-request')
            self.value['revision'] = availability['observedRevision'] = 9
            with self.assertRaises(BaseRegistryClientError) as raised:
                self.client.execute_proposal(attempt)
            self.assertEqual(raised.exception.kind, 'protocol')
            self.assertTrue(raised.exception.outcome_unknown)
        for availability in [None, {'available': True, 'observedRevision': 8},
                             {'available': False, 'observedRevision': 8, 'reason': 'stale-revision', 'recovery': 'refresh'}]:
            self.value = copy.deepcopy(original)
            if availability is not None:
                self.value['attachments']['support']['links']['upload']['availability'] = availability
            self.client.get_proposal(self.binding, ID)

    def test_application_result_record_identifiers_retain_canonical_spelling(self):
        canonical = '123e4567-e89b-42d3-a456-426614174000'
        for record_id in [canonical, '00000000-0000-0000-0000-000000000000']:
            self.value = document()
            self.value['application']['resultLinks'][0]['recordId'] = record_id
            self.assertEqual(self.client.get_proposal(self.binding, ID).document['application']['resultLinks'][0]['recordId'], record_id)
        for record_id in [canonical.upper(), canonical.replace('-', '')]:
            self.value = document()
            self.value['application']['resultLinks'][0]['recordId'] = record_id
            count = len(self.requests)
            with self.subTest(record_id=record_id), self.assertRaises(BaseRegistryClientError) as raised:
                self.client.get_proposal(self.binding, ID)
            self.assertEqual(raised.exception.kind, 'invalid-request')
            self.assertEqual(len(self.requests), count + 1)

    def test_application_status_preserves_current_progress_and_retained_evidence_absence(self):
        for state in ('awaiting-review', 'pending', 'blocked', 'applied', 'cancelled'):
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
        del self.value['effectDigest']
        self.value['links']['edit'] = {'method': 'POST', 'path': '/v1/proposals/' + ID + '/edit', 'accessProfile': 'reader', 'operation': 'edit', 'ifMatch': '"edit-condition"'}
        proposal = self.client.get_proposal(self.binding, ID)
        self.assertEqual(proposal.input, self.value['input'])
        self.assertNotIn('undisclosed', proposal.input)
        body = {'input': copy.deepcopy(proposal.input)}
        count = len(self.requests)
        with self.assertRaises(BaseRegistryClientError) as refused:
            self.client.prepare_proposal(proposal, 'edit', body, 'exact-edit')
        self.assertEqual(refused.exception.kind, 'invalid-request')
        self.assertEqual(len(self.requests), count)
        # Reads preserve exact integers; edits must also fit the storage JCS policy.
        # This wide neighbor is exactly representable without changing its value.
        body['input']['wide'] = 9007199254740994
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
        self.value['revision'] += 1
        self.client.execute_proposal(recovered)
        path, headers, wire = self.requests[-1]
        headers = {key.lower(): value for key, value in headers.items()}
        self.assertEqual(path, '/tenant/v1/proposals/' + ID + '/edit?accessProfile=reader')
        self.assertEqual(json.loads(wire), body)
        self.assertIn(b'9007199254740994', wire)
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

    def test_documents_require_version_and_state_appropriate_frozen_evidence(self):
        for state in ('draft', 'submitted', 'applied', 'cancelled'):
            self.value = document()
            self.value.update(state=state, submissionVersion=0)
            del self.value['application']
            if state == 'draft':
                del self.value['effectDigest']
            with self.subTest(state=state), self.assertRaises(BaseRegistryClientError) as raised:
                self.client.get_proposal(self.binding, ID)
            self.assertEqual(raised.exception.kind, 'invalid-request')
        self.value = document()
        self.value['state'] = 'submitted'
        del self.value['application']
        del self.value['effectDigest']
        with self.assertRaises(BaseRegistryClientError):
            self.client.get_proposal(self.binding, ID)
        self.value.update(state='draft', effectDigest=DIGEST)
        with self.assertRaises(BaseRegistryClientError):
            self.client.get_proposal(self.binding, ID)
        del self.value['effectDigest']
        self.assertEqual(self.client.get_proposal(self.binding, ID).document['state'], 'draft')
        self.value = document()
        del self.value['application']
        with self.assertRaises(BaseRegistryClientError):
            self.client.get_proposal(self.binding, ID)

    def test_review_status_pending_terminal_expired_and_context_without_results(self):
        self.value['state'] = 'submitted'
        del self.value['application']
        for name, suffix, operation in [('reviewStatus', 'review-status', 'get-review-status'), ('reviewContext', 'review-context', 'get-review-context')]:
            self.value['links'][name] = {'method': 'GET', 'path': '/v1/proposals/' + ID + '/' + suffix, 'accessProfile': 'reader', 'operation': operation}
        prior = self.client.get_proposal(self.binding, ID)
        base = {'id': ID, 'actionId': 'correct', 'actionRevision': DIGEST, 'submissionVersion': 2, 'revision': 8, 'effectDigest': DIGEST,
                'subject': {'source': 'directory', 'subjectType': 'proposal', 'id': ID, 'version': '2', 'digest': DIGEST},
                'context': {'reference': 'breg:directory:correct:' + ID + ':2'}, 'reviewable': True}
        configured = dict(base, authority='review-provider', policy={'id': 'review', 'version': '1', 'digest': DIGEST})
        canonical_id = '123e4567-e89b-42d3-a456-426614174000'
        terminal = {'state': 'approved', 'resultId': TARGET, 'completedAt': '2026-10-01T00:00:00.000000Z', 'availableUntil': '2026-10-02T00:00:00.000000Z'}
        self.value = copy.deepcopy(base)
        self.assertNotIn('result', self.client.read_proposal_review_status(prior)['value'])
        for result in [{'state': 'pending'}] + [dict(terminal, state=state) for state in ('approved', 'rejected', 'changes-requested', 'answered', 'cancelled', 'superseded', 'expired')]:
            self.value = dict(copy.deepcopy(configured), requestId=ID, result=result)
            with self.subTest(result=result):
                self.assertEqual(self.client.read_proposal_review_status(prior)['value']['result'], result)
        for correlation_id in ['123e4567-e89b-12d3-a456-426614174000', canonical_id, '0192a870-1234-7abc-8def-123456789abc']:
            self.value = dict(copy.deepcopy(configured), requestId=correlation_id, result=dict(terminal, resultId=correlation_id))
            observed = self.client.read_proposal_review_status(prior)['value']
            self.assertEqual(observed['requestId'], correlation_id)
            self.assertEqual(observed['result']['resultId'], correlation_id)
        self.value = dict(copy.deepcopy(configured), result={'state': 'pending'})
        self.assertNotIn('requestId', self.client.read_proposal_review_status(prior)['value'])
        self.value['result'] = terminal
        with self.assertRaises(BaseRegistryClientError):
            self.client.read_proposal_review_status(prior)
        invalid_results = [{'state': 'pending', field: terminal[field]} for field in ('resultId', 'completedAt', 'availableUntil')]
        for field in ('resultId', 'completedAt', 'availableUntil'):
            result = dict(terminal)
            del result[field]
            invalid_results.append(result)
        expired = dict(terminal, state='expired')
        del expired['availableUntil']
        invalid_results += [dict(terminal, resultId=result_id) for result_id in [canonical_id.upper(), canonical_id.replace('-', '')]]
        invalid_results += [dict(terminal, resultId='not-a-uuid'), dict(terminal, resultId='00000000-0000-0000-0000-000000000000'),
                            dict(terminal, completedAt='2026-10-01'), dict(terminal, availableUntil='private-canary'),
                            dict(terminal, availableUntil=terminal['completedAt']), dict(terminal, availableUntil='2026-09-30T00:00:00Z'),
                            expired, dict(terminal, state='unknown')]
        for result in invalid_results:
            self.value = dict(copy.deepcopy(configured), requestId=ID, result=result)
            count = len(self.requests)
            with self.subTest(invalid_result=result), self.assertRaises(BaseRegistryClientError) as raised:
                self.client.read_proposal_review_status(prior)
            self.assertEqual(raised.exception.kind, 'invalid-request')
            self.assertNotIn('private-canary', str(raised.exception))
            self.assertEqual(len(self.requests), count + 1)
        for invalid in [dict(base, result={'state': 'pending'}), configured]:
            self.value = copy.deepcopy(invalid)
            with self.assertRaises(BaseRegistryClientError):
                self.client.read_proposal_review_status(prior)
        self.value = copy.deepcopy(configured)
        self.value['context']['contract'] = {'id': 'urn:registry:breg:review-context:directory:correct:review', 'revision': DIGEST, 'schemaDigest': DIGEST}
        self.value['context']['fields'] = {'private': 'private-canary'}
        self.assertEqual(self.client.read_proposal_review_context(prior)['value']['context']['fields'], {'private': 'private-canary'})
        self.value['result'] = {'state': 'pending'}
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.read_proposal_review_context(prior)
        self.assertEqual(raised.exception.kind, 'invalid-request')
        self.assertNotIn('private-canary', str(raised.exception))

    def test_non_rebase_transitions_and_attachment_writes_preserve_action_revision(self):
        successor = 'sha256:' + 'b' * 64
        self.value = document()
        self.value['state'] = 'draft'
        del self.value['application']
        del self.value['effectDigest']
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
            self.assertEqual(raised.exception.kind, 'protocol')
            self.assertTrue(raised.exception.outcome_unknown)
            self.assertEqual(len(self.requests), count + 1)
            for field, value in [('revision', 8), ('revision', 10), ('state', 'submitted'), ('submissionVersion', 3)]:
                self.value = copy.deepcopy(current)
                self.value[field] = value
                count = len(self.requests)
                with self.subTest(operation=operation, field=field, value=value), self.assertRaises(BaseRegistryClientError) as raised:
                    send()
                self.assertEqual(raised.exception.kind, 'protocol')
                self.assertTrue(raised.exception.outcome_unknown)
                self.assertEqual(len(self.requests), count + 1)
        for version in [current['submissionVersion'], current['submissionVersion'] + 1]:
            self.value = dict(copy.deepcopy(current), submissionVersion=version)
            self.assertEqual(self.client.read_proposal(prior).document['actionRevision'], DIGEST)
            self.value['actionRevision'] = successor
            count = len(self.requests)
            with self.subTest(refresh_version=version), self.assertRaises(BaseRegistryClientError) as raised:
                self.client.read_proposal(prior)
            self.assertEqual(raised.exception.kind, 'invalid-request')
            self.assertEqual(len(self.requests), count + 1)

    def test_start_receipt_failure_preserves_unknown_outcome_and_original_command(self):
        from pathlib import Path
        fixture = json.loads((Path(__file__).resolve().parents[3] / 'registry-breg-client/tests/fixtures/attachments.json').read_text())
        start_action = copy.deepcopy(fixture['metadata']['actions'][0])
        start_action['access']['selectedProfile'] = 'reader'
        self.metadata['actions'] = [start_action]
        action = self.client.registry_contract('reader').select_action('correct', 'reader')
        draft = document()
        draft['state'] = 'draft'
        del draft['application']
        del draft['effectDigest']
        wrong_profile = copy.deepcopy(draft)
        wrong_profile['links']['self']['accessProfile'] = 'other'
        self.reply_status = 201
        for invalid in [{}, dict(draft, actionRevision='sha256:' + 'b' * 64), wrong_profile,
                        dict(draft, state='submitted', effectDigest=DIGEST)]:
            self.value = invalid
            count = len(self.requests)
            with self.assertRaises(BaseRegistryClientError) as raised:
                self.client.start_proposal(action, {}, 'recover-start')
            self.assertEqual(raised.exception.kind, 'protocol')
            self.assertTrue(raised.exception.outcome_unknown)
            self.assertEqual(raised.exception.status, 201)
            self.assertEqual(len(self.requests), count + 1)
            sent = self.requests[-1]
            self.value = copy.deepcopy(draft)
            self.assertEqual(self.client.start_proposal(action, {}, 'recover-start').document['state'], 'draft')
            self.assertEqual(self.requests[-1], sent)

    def test_submit_exact_receipt_replay_and_saved_recovery_after_later_progress(self):
        self.value = document()
        self.value.update(state='draft', submissionVersion=1)
        del self.value['application']
        del self.value['effectDigest']
        self.value['links']['submit'] = {'method': 'POST', 'path': '/v1/proposals/' + ID + '/submit', 'accessProfile': 'reader', 'operation': 'submit', 'ifMatch': '"submit-condition"'}
        prior = self.client.get_proposal(self.binding, ID)
        initial = copy.deepcopy(self.value)
        attempt = self.client.prepare_proposal(prior, 'submit', {}, 'exact-submit')
        saved = attempt.to_bytes()
        receipt = dict(copy.deepcopy(initial), revision=9, state='submitted', effectDigest=DIGEST)
        for invalid in [initial, dict(receipt, revision=8), dict(receipt, revision=10),
                        dict(receipt, state='draft'), dict(receipt, state='applied'), dict(receipt, submissionVersion=2)]:
            self.value = invalid
            count = len(self.requests)
            with self.subTest(receipt=invalid), self.assertRaises(BaseRegistryClientError) as raised:
                self.client.execute_proposal(attempt)
            self.assertEqual(raised.exception.kind, 'protocol')
            self.assertTrue(raised.exception.outcome_unknown)
            self.assertEqual(len(self.requests), count + 1)
        self.value = receipt
        self.assertEqual(self.client.execute_proposal(attempt).document['state'], 'submitted')
        sent = self.requests[-1]
        self.assertEqual(self.client.execute_proposal(attempt).document['revision'], 9)
        self.assertEqual(self.requests[-1], sent)
        self.value = dict(copy.deepcopy(receipt), revision=10, state='applied',
                          application=dict(document()['application'], submissionVersion=1))
        self.value['links']['submit']['availability'] = {'available': False, 'observedRevision': 10, 'reason': 'already-applied', 'recovery': 'receipt-only'}
        current = self.client.read_proposal(prior)
        count = len(self.requests)
        recovered = self.client.recover_proposal(current, BRegPreparedProposal.from_bytes(saved))
        self.assertEqual(len(self.requests), count)
        self.assertEqual(recovered.to_bytes(), saved)
        self.value = receipt
        self.assertEqual(self.client.execute_proposal(recovered).document['revision'], 9)
        self.assertEqual(self.requests[-1], sent)

    def test_held_reads_refuse_backward_revisions_but_permit_equal_and_later(self):
        held = self.client.get_proposal(self.binding, ID)
        self.value['revision'] = 7
        count = len(self.requests)
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.read_proposal(held)
        self.assertEqual(raised.exception.kind, 'invalid-request')
        self.assertEqual(len(self.requests), count + 1)
        for revision in [8, 9]:
            self.value['revision'] = revision
            self.assertEqual(self.client.read_proposal(held).document['revision'], revision)

    def test_explicit_rebase_and_exact_recovery_admit_only_next_successor_draft(self):
        for state, before, after in [('draft', 1, 1), ('submitted', 2, 3)]:
            self.value = document()
            self.value.update(state=state, submissionVersion=before)
            del self.value['application']
            if state == 'draft':
                del self.value['effectDigest']
            self.value['links']['rebase'] = {'method': 'POST', 'path': '/v1/proposals/' + ID + '/rebase', 'accessProfile': 'reader', 'operation': 'rebase', 'ifMatch': '"rebase-condition"',
                                           'availability': {'available': True, 'observedRevision': 8}}
            prior = self.client.get_proposal(self.binding, ID)
            attempt = self.client.prepare_proposal(prior, 'rebase', {'input': {}}, 'rebase-' + state)
            saved = attempt.to_bytes()
            self.value.update(state='draft', submissionVersion=after, revision=9, actionRevision='sha256:' + 'b' * 64)
            self.value.pop('effectDigest', None)
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
        del self.value['effectDigest']
        self.value['attachments'] = {'support': {'id': 'support', 'required': False, 'maximumBytes': 4, 'contentTypes': ['text/plain'], 'classification': 'restricted',
            'value': {'submissionVersion': 2, 'uploadedAt': '2026-10-15T00:00:00.000000Z', 'sha256': hashlib.sha256(self.download_bytes).hexdigest(), 'contentType': 'application/pdf', 'byteSize': len(self.download_bytes), 'verificationStatus': 'notRequired'},
            'links': {'download': {'method': 'GET', 'path': '/v1/proposals/' + ID + '/attachments/support?submissionVersion=2', 'accessProfile': 'reader', 'operation': 'download'},
                      'upload': {'method': 'PATCH', 'path': '/v1/proposals/' + ID + '/attachments/support', 'accessProfile': 'reader', 'operation': 'upload', 'ifMatch': '"attachment-condition"'}}}}
        disclosed = copy.deepcopy(self.value)
        for uploaded_at in [None, 'private-canary', '2026-10-15']:
            self.value = copy.deepcopy(disclosed)
            if uploaded_at is None:
                del self.value['attachments']['support']['value']['uploadedAt']
            else:
                self.value['attachments']['support']['value']['uploadedAt'] = uploaded_at
            with self.subTest(uploaded_at=uploaded_at), self.assertRaises(BaseRegistryClientError) as raised:
                self.client.get_proposal(self.binding, ID)
            self.assertEqual(raised.exception.kind, 'invalid-request')
            self.assertNotIn('private-canary', str(raised.exception))
        self.value = disclosed
        retained = self.client.get_proposal(self.binding, ID)
        self.assertEqual(self.client.download_proposal_attachment(retained, 'support')['body'], self.download_bytes)
        count = len(self.requests)
        for media, body in [('application/pdf', b'%PDF'), ('text/plain', b'12345')]:
            with self.assertRaises(BaseRegistryClientError) as raised:
                self.client.upload_proposal_attachment(retained, 'support', media, body, 'refused-upload')
            self.assertEqual(raised.exception.kind, 'invalid-request')
        self.assertEqual(len(self.requests), count)
        self.value['revision'] += 1
        self.value['attachments']['support']['value'].update(sha256=hashlib.sha256(b'ok').hexdigest(), contentType='text/plain', byteSize=2)
        self.client.upload_proposal_attachment(retained, 'support', 'text/plain', b'ok', 'allowed-upload')
        self.download_bytes += b'x'
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.download_proposal_attachment(retained, 'support')
        self.assertEqual(raised.exception.kind, 'transport')
        self.assertEqual(raised.exception.transport_kind, 'response-too-large')


if __name__ == '__main__':
    unittest.main()
