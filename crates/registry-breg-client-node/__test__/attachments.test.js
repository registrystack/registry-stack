'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const {test}=require('node:test');
const {BaseRegistryClient}=process.env.BREG_CLIENT_PACKAGE ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');
const fixture=require('../../registry-breg-client/tests/fixtures/attachments.json');
const slot='supporting-file';
const bytes=Buffer.from(fixture.content);
async function harness() {
 const requests=[];
 const server=http.createServer(async(request,response)=>{
  const chunks=[];for await(const chunk of request)chunks.push(chunk);
  requests.push({method:request.method,url:request.url,headers:request.headers,body:Buffer.concat(chunks)});
  response.setHeader('traceparent','00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');response.setHeader('cache-control','no-store');
  if(request.method==='GET'&&!request.url.startsWith('/v1/registry')) {
   response.setHeader('content-type','application/pdf');response.setHeader('content-disposition','attachment');response.setHeader('x-content-type-options','nosniff');response.setHeader('vary','authorization');return response.end(bytes);
  }
  response.setHeader('content-type','application/json');response.setHeader('vary','authorization, accept');response.end(JSON.stringify(request.url.startsWith('/v1/registry')?fixture.metadata:fixture.proposal));
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
  await h.client.uploadProposalAttachment(h.proposal,slot,'application/pdf',bytes,'upload');
  const raw=await h.client.downloadProposalAttachment(h.proposal,slot);assert.deepEqual(raw.body,bytes);
  await h.client.deleteProposalAttachment(h.proposal,slot,'remove');
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
