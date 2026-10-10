'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const http=require('node:http');
const {CaseworkClient}=require('../client');
const item='00000000-0000-4000-8000-000000000001';
const grant='00000000-0000-4000-8000-000000000002';
const preview={id:'verify-status',version:'1',label:'Verify status',agent:{issuer:'https://issuer.example',subject:'agent-one'},client:'agent-client',resource:'urn:evidence',scopes:['evidence:invoke'],evidenceContext:{requesterTags:['licensing-authority'],audience:'urn:licensing:review'},purpose:'verify-status',bounds:{type:'evidence',requirement:'status'},subjects:{person_reference:'synthetic-reference'},lifetimeSeconds:900};
const view={id:grant,templateId:preview.id,templateVersion:preview.version,agent:preview.agent,client:preview.client,resource:preview.resource,scopes:preview.scopes,evidenceContext:preview.evidenceContext,purpose:preview.purpose,bounds:preview.bounds,expiresAt:2000000900,invalidated:false};
for (const mode of [undefined, 'deferred']) {
test(`${mode ?? 'immediate'} task grants preserve preview, approval revision/key and token-only machine calls`,async(t)=>{
 const shownPreview=mode?{...preview,authorizationMode:mode,lifetimeSeconds:604800}:{...preview};
 const shownView=mode?{...view,authorizationMode:mode,expiresAt:2000604800}:{...view};
 const requests=[];
 const server=http.createServer((req,res)=>{let body='';req.on('data',b=>body+=b);req.on('end',()=>{requests.push({path:req.url,method:req.method,headers:req.headers,body});let value;
 if(req.url.endsWith('/task-templates'))value={itemRevision:7,templates:[shownPreview]};
 else if(req.url.endsWith('/assertion'))value={assertion:'synthetic-assertion',expiresAt:2000000060,grantExpiresAt:shownView.expiresAt};
 else if(req.url.endsWith('/status'))value={active:false};
 else if(req.url.endsWith('/revoke'))value={id:grant,invalidated:true};
 else value=req.method==='POST'?shownView:{grants:[shownView]};
 res.writeHead(200,{'content-type':'application/json',traceparent:'00-0123456789abcdef0123456789abcdef-0123456789abcdef-01'});res.end(JSON.stringify(value));});});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const client=new CaseworkClient({baseUrl:`http://127.0.0.1:${server.address().port}/`});
 assert.equal(client.taskAssertionEndpoint(grant),`http://127.0.0.1:${server.address().port}/v1/task-grants/${grant}/assertion`);
 assert.deepEqual((await client.previewTaskTemplates('human-token','staff','source-reviewer',item)).value.templates,[shownPreview]);
 assert.deepEqual((await client.listTaskGrants('human-token','staff','source-reviewer',item)).value.grants,[shownView]);
 const approval={templateId:'verify-status',templateVersion:'1'};
 assert.deepEqual((await client.approveTaskGrant('human-token','staff','source-reviewer',item,7,'caller-attempt-key',approval)).value,shownView);
 assert.deepEqual(JSON.parse(requests[2].body),approval);assert.equal(requests[2].headers['if-match'],'"7"');assert.equal(requests[2].headers['idempotency-key'],'caller-attempt-key');
 await client.revokeTaskGrant('human-token','staff','source-reviewer',item,grant);
 assert.equal(requests[3].body,'');
 assert.deepEqual((await client.taskAssertion('bootstrap-token',grant)).value,{assertion:'synthetic-assertion',expiresAt:2000000060,grantExpiresAt:shownView.expiresAt});
 assert.deepEqual((await client.taskGrantStatus('resource-token',grant)).value,{active:false});
 for(const request of requests.slice(0,4)){assert.equal(request.headers['registry-casework-profile'],'staff');assert.equal(request.headers['registry-source-profile'],'source-reviewer');}
 for(const request of requests.slice(4)){assert.equal(request.headers['registry-casework-profile'],undefined);assert.equal(request.headers['registry-source-profile'],undefined);}
 const before=requests.length;
 await assert.rejects(client.approveTaskGrant('human-token','staff','source-reviewer',item,7,'caller-attempt-key',{...approval,resource:'urn:other'}),e=>e.kind==='invalid-request');
 await assert.rejects(client.approveTaskGrant('human-token','staff','source-reviewer',item,7,'caller-attempt-key',{...approval,authorizationMode:'deferred'}),e=>e.kind==='invalid-request');
 await assert.rejects(client.taskAssertion('bootstrap-token','not-a-grant-id'),e=>e.kind==='invalid-request');
 assert.throws(()=>client.taskAssertionEndpoint('not-a-grant-id'),e=>e.kind==='invalid-request');
 assert.equal(requests.length,before);
 shownPreview.authorizationMode='unbounded';
 await assert.rejects(client.previewTaskTemplates('human-token','staff','source-reviewer',item),e=>e.kind==='protocol');
});
}
