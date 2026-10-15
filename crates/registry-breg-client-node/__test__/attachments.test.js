'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const {test}=require('node:test');
const {createHash}=require('node:crypto');
const {BaseRegistryClient}=process.env.BREG_CLIENT_PACKAGE ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');
const fixture=require('../../registry-breg-client/tests/fixtures/attachments.json');
const slot='supporting-file';
const bytes=Buffer.from(fixture.content);
async function harness(mutateReceipt) {
 const requests=[];
 const server=http.createServer(async(request,response)=>{
  const chunks=[];for await(const chunk of request)chunks.push(chunk);
  requests.push({method:request.method,url:request.url,headers:request.headers,body:Buffer.concat(chunks)});
  response.setHeader('traceparent','00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');response.setHeader('cache-control','no-store');
  if(request.method==='GET'&&!request.url.startsWith('/v1/registry')) {
   response.setHeader('content-type','application/pdf');response.setHeader('content-disposition','attachment');response.setHeader('x-content-type-options','nosniff');response.setHeader('vary','authorization');return response.end(bytes);
  }
  const value=structuredClone(request.url.startsWith('/v1/registry')?fixture.metadata:fixture.proposal);
  if(['PATCH','DELETE'].includes(request.method)) {
   value.revision++;
   if(request.method==='PATCH')Object.assign(value.attachments[slot].value,{sha256:createHash('sha256').update(Buffer.concat(chunks)).digest('hex'),contentType:request.headers['content-type'],byteSize:Buffer.concat(chunks).length});
   else delete value.attachments[slot].value;
   if(mutateReceipt)mutateReceipt(value,request.method);
  }
  response.setHeader('content-type','application/json');response.setHeader('vary','authorization, accept');response.end(JSON.stringify(value));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const client=new BaseRegistryClient({baseUrl:`http://127.0.0.1:${server.address().port}`});
 const metadata=await client.registryContract('writer');const proposal=await client.startProposal(metadata.selectAction('correct','writer'),'{}','start');
 return {client,proposal,requests,close:()=>new Promise(resolve=>server.close(resolve))};
}
test('Proposal attachments expose served policy without Record slot constructors',async()=>{
 const h=await harness();try {
  const document=JSON.parse(h.proposal.documentJson);assert.equal(document.attachments[slot].maximumBytes,1024);
  assert.equal(document.attachments[slot].classification,'restricted');assert.equal(require('..').BRegAttachmentSlot,undefined);
 } finally {await h.close();}
});
test('disallowed bytes and missing slots never leave the native boundary',async()=>{
 const h=await harness();try {
  for(const [mime,body] of [['text/plain',bytes],['application/pdf',Buffer.alloc(0)],['application/pdf',Buffer.alloc(1025)]]) {
   await assert.rejects(h.client.uploadProposalAttachment(h.proposal,slot,mime,body,'bad'),error=>error.kind==='invalid-request');
  }
  await assert.rejects(h.client.deleteProposalAttachment(h.proposal,'missing','bad'),error=>error.kind==='invalid-request');assert.equal(h.requests.length,2);
 } finally {await h.close();}
});
test('three binary exchanges follow exact promoted paths and conditions',async()=>{
 const h=await harness();try {
  const uploaded=JSON.parse((await h.client.uploadProposalAttachment(h.proposal,slot,'application/pdf',bytes,'upload')).documentJson);
  assert.equal(uploaded.revision,fixture.proposal.revision+1);assert.equal(uploaded.submissionVersion,fixture.proposal.submissionVersion);assert.equal(uploaded.state,'draft');
  const raw=await h.client.downloadProposalAttachment(h.proposal,slot);assert.deepEqual(raw.body,bytes);
  const removed=JSON.parse((await h.client.deleteProposalAttachment(h.proposal,slot,'remove')).documentJson);
  assert.equal(removed.revision,fixture.proposal.revision+1);assert.equal(removed.submissionVersion,fixture.proposal.submissionVersion);assert.equal(removed.state,'draft');
  const path=`/v1/proposals/${fixture.proposal.id}/attachments/${slot}`;
  assert.equal(h.requests[2].url,`${path}?accessProfile=writer`);assert.equal(h.requests[2].method,'PATCH');assert.equal(h.requests[2].headers['if-match'],'"condition"');assert.equal(h.requests[2].headers['idempotency-key'],'upload');assert.deepEqual(h.requests[2].body,bytes);
  assert.equal(h.requests[3].url,`${path}?accessProfile=writer&submissionVersion=2`);assert.equal(h.requests[3].headers.accept,'*/*');
  assert.equal(h.requests[4].method,'DELETE');assert.equal(h.requests[4].headers['idempotency-key'],'remove');
 } finally {await h.close();}
});
test('Proposal slot authority remains source bound',async()=>{
 const h=await harness();try {
  const other=new BaseRegistryClient({baseUrl:'http://127.0.0.1:1'});
  await assert.rejects(other.downloadProposalAttachment(h.proposal,slot),error=>error.kind==='invalid-request');assert.equal(h.requests.length,2);
 } finally {await h.close();}
});

test('attachment receipts bind disclosed selected-slot effects and preserve omitted metadata',async()=>{
 const replacement=Buffer.from('replacement-private-canary');
 for(const [name,mutate] of [
  ['unchanged',value=>{value.attachments[slot].value=structuredClone(fixture.proposal.attachments[slot].value);}],
  ['digest',value=>{value.attachments[slot].value.sha256='a'.repeat(64);}],
  ['media',value=>{value.attachments[slot].value.contentType='text/plain';}],
  ['size',value=>{value.attachments[slot].value.byteSize++;}],
  ['missing',value=>{delete value.attachments[slot];}]
 ]) {
  const h=await harness(mutate);try {
   await assert.rejects(h.client.uploadProposalAttachment(h.proposal,slot,'application/pdf',replacement,'exact-upload'),error=>error.kind==='protocol'&&error.outcomeUnknown&&!error.message.includes('replacement-private-canary'));
   assert.equal(h.requests.length,3,name+': malformed 200 is not resent');
  } finally {await h.close();}
 }
 const stale=await harness(value=>{value.attachments[slot].value=structuredClone(fixture.proposal.attachments[slot].value);});try {
  await assert.rejects(stale.client.deleteProposalAttachment(stale.proposal,slot,'exact-remove'),error=>error.kind==='protocol'&&error.outcomeUnknown);
  assert.equal(stale.requests.length,3);
 } finally {await stale.close();}
 const omitted=await harness(value=>{delete value.attachments[slot].value;});try {
  await omitted.client.uploadProposalAttachment(omitted.proposal,slot,'application/pdf',replacement,'omitted-upload');
  await omitted.client.deleteProposalAttachment(omitted.proposal,slot,'absent-remove');
 } finally {await omitted.close();}
});
