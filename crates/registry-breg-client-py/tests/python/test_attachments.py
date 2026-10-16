"""First-class Proposal attachment exchanges through the public Python binding."""
import copy
import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from bootstrap import ensure_built
ensure_built()
from registry_breg_client import BaseRegistryClient, BaseRegistryClientError
FIXTURE=json.loads((Path(__file__).resolve().parents[3]/'registry-breg-client/tests/fixtures/attachments.json').read_text())
SLOT='supporting-file'
CONTENT=FIXTURE['content'].encode()
class AttachmentTests(unittest.TestCase):
 def setUp(self):
  self.requests=[]
  requests=self.requests
  self.mutate_receipt=None
  owner=self
  class Handler(BaseHTTPRequestHandler):
   def respond(self):
    body=self.rfile.read(int(self.headers.get('content-length','0')));requests.append((self.command,self.path,dict(self.headers),body))
    binary=self.command=='GET' and not self.path.startswith('/v1/registry')
    value=copy.deepcopy(FIXTURE['metadata'] if self.path.startswith('/v1/registry') else FIXTURE['proposal'])
    if self.command in ('PATCH','DELETE'):
     value['revision']+=1
     if self.command=='PATCH':value['attachments'][SLOT]['value'].update(sha256=hashlib.sha256(body).hexdigest(),contentType=self.headers['content-type'],byteSize=len(body))
     else:value['attachments'][SLOT].pop('value',None)
     if owner.mutate_receipt:owner.mutate_receipt(value)
    payload=CONTENT if binary else json.dumps(value).encode()
    self.send_response(200);self.send_header('content-type','application/pdf' if binary else 'application/json');self.send_header('cache-control','no-store');self.send_header('vary','authorization' if binary else 'authorization, accept');self.send_header('traceparent','00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');self.send_header('content-length',str(len(payload)))
    if binary:self.send_header('content-disposition','attachment');self.send_header('x-content-type-options','nosniff')
    self.end_headers();self.wfile.write(payload)
   do_GET=respond
   do_POST=respond
   do_PATCH=respond
   do_DELETE=respond
   def log_message(self,*args):pass
  self.server=HTTPServer(('127.0.0.1',0),Handler);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
  self.client=BaseRegistryClient(f'http://127.0.0.1:{self.server.server_port}')
  metadata=self.client.registry_contract('writer');self.proposal=self.client.start_proposal(metadata.select_action('correct','writer'),{},'start')
 def tearDown(self):self.server.shutdown();self.thread.join();self.server.server_close()
 def test_policy_is_on_the_proposal_instance(self):
  self.assertEqual(self.proposal.document['attachments'][SLOT]['maximumBytes'],1024)
  import registry_breg_client
  self.assertFalse(hasattr(registry_breg_client,'BRegAttachmentSlot'))
 def test_disallowed_bytes_never_leave_native_boundary(self):
  for mime,body in [('text/plain',CONTENT),('application/pdf',b''),('application/pdf',b'x'*1025)]:
   with self.assertRaises(BaseRegistryClientError):self.client.upload_proposal_attachment(self.proposal,SLOT,mime,body,'bad')
  self.assertEqual(len(self.requests),2)
 def test_three_exchanges_follow_promoted_paths(self):
  uploaded=self.client.upload_proposal_attachment(self.proposal,SLOT,'application/pdf',CONTENT,'upload').document
  self.assertEqual(uploaded['revision'],FIXTURE['proposal']['revision']+1);self.assertEqual(uploaded['submissionVersion'],FIXTURE['proposal']['submissionVersion']);self.assertEqual(uploaded['state'],'draft')
  self.assertEqual(self.client.download_proposal_attachment(self.proposal,SLOT)['body'],CONTENT)
  removed=self.client.delete_proposal_attachment(self.proposal,SLOT,'remove').document
  self.assertEqual(removed['revision'],FIXTURE['proposal']['revision']+1);self.assertEqual(removed['submissionVersion'],FIXTURE['proposal']['submissionVersion']);self.assertEqual(removed['state'],'draft')
  path=f"/v1/proposals/{FIXTURE['proposal']['id']}/attachments/{SLOT}"
  self.assertEqual(self.requests[2][1],path+'?accessProfile=writer');self.assertEqual(self.requests[2][3],CONTENT);self.assertEqual(self.requests[2][2]['if-match'],'"condition"')
  self.assertEqual(self.requests[3][1],path+'?accessProfile=writer&submissionVersion=2');self.assertEqual(self.requests[4][0],'DELETE')
 def test_another_client_source_cannot_use_the_handle(self):
  other=BaseRegistryClient('http://127.0.0.1:1')
  with self.assertRaises(BaseRegistryClientError):other.download_proposal_attachment(self.proposal,SLOT)
  self.assertEqual(len(self.requests),2)

 def test_receipts_bind_disclosed_selected_slot_effects(self):
  replacement=b'replacement-private-canary'
  for field,value in [('sha256','a'*64),('contentType','text/plain'),('byteSize',len(replacement)+1)]:
   self.mutate_receipt=lambda receipt,field=field,value=value:receipt['attachments'][SLOT]['value'].__setitem__(field,value)
   count=len(self.requests)
   with self.subTest(field=field),self.assertRaises(BaseRegistryClientError) as raised:
    self.client.upload_proposal_attachment(self.proposal,SLOT,'application/pdf',replacement,'exact-upload')
   self.assertEqual(raised.exception.kind,'protocol');self.assertTrue(raised.exception.outcome_unknown)
   self.assertNotIn('replacement-private-canary',str(raised.exception));self.assertEqual(len(self.requests),count+1)
  self.mutate_receipt=lambda receipt:receipt['attachments'][SLOT].__setitem__('value',copy.deepcopy(FIXTURE['proposal']['attachments'][SLOT]['value']))
  for deletion in [False,True]:
   count=len(self.requests)
   with self.subTest(deletion=deletion),self.assertRaises(BaseRegistryClientError) as raised:
    if deletion:self.client.delete_proposal_attachment(self.proposal,SLOT,'exact-remove')
    else:self.client.upload_proposal_attachment(self.proposal,SLOT,'application/pdf',replacement,'exact-upload')
   self.assertEqual(raised.exception.kind,'protocol');self.assertTrue(raised.exception.outcome_unknown);self.assertEqual(len(self.requests),count+1)
  self.mutate_receipt=lambda receipt:receipt['attachments'].__delitem__(SLOT)
  with self.assertRaises(BaseRegistryClientError):self.client.upload_proposal_attachment(self.proposal,SLOT,'application/pdf',replacement,'missing-slot')
 def test_omitted_value_metadata_remains_permitted(self):
  self.mutate_receipt=lambda receipt:receipt['attachments'][SLOT].pop('value',None)
  self.client.upload_proposal_attachment(self.proposal,SLOT,'application/pdf',b'replacement','omitted-upload')
  self.client.delete_proposal_attachment(self.proposal,SLOT,'absent-remove')
