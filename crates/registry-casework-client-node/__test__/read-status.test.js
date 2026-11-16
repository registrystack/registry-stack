'use strict';
const assert=require('node:assert/strict'), http=require('node:http');
const {test}=require('node:test');
const id='00000000-0000-4000-8000-000000000001';
const traceparent='00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
function readonly(result){assert.equal(result.responseStatus,200);assert.throws(()=>{result.responseStatus=201;},TypeError);assert.throws(()=>{delete result.responseStatus;},TypeError);}
const {CaseworkClient}=process.env.REGISTRY_CLIENT_PACKAGE?require(process.env.REGISTRY_CLIENT_PACKAGE).casework:require('../client');
const task={taskId:id,requestId:'00000000-0000-4000-8000-000000000009',subject:{source:'registry',type:'proposal',id:'proposal-7',version:'3',digest:`sha256:${'a'.repeat(64)}`},requesterReference:'REF-7',displayReference:'REF-7',createdAt:'2026-10-14T00:00:00Z',deadlineAt:'2026-10-20T00:00:00Z',stageId:'review',stageIndex:0,queue:'review',revision:3,eligibleProfiles:['staff'],state:{held:{holder:{issuer:'https://issuer.example',subject:'staff-1'}}}};
for(const method of ['reviewTask','reviewTasks'])test(method+': actual response status is readonly and scoped',async t=>{
 let status=200,count=0,body;
 const server=http.createServer((req,res)=>{count++;assert.equal(req.headers['registry-casework-profile'],'staff');res.writeHead(status,{'content-type':'application/json',traceparent});res.end(body??JSON.stringify(method==='reviewTask'||req.url.split('?')[0].endsWith('/next')?task:{items:[task],status:'complete'}));});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));});
 const client=new CaseworkClient({baseUrl:`http://127.0.0.1:${server.address().port}`});const read=()=>method==='reviewTask'?client.reviewTask('synthetic-token','staff',id):client.reviewTasks('synthetic-token','staff',{ownership:'assigned-to-me',queue:'review'});
 const actual=await read();readonly(actual);assert.equal(count,1);assert.equal(actual.kind,'complete');
 if(method==='reviewTasks')assert.equal(actual.value.status,'complete','page status is not transport status');
 const next=await client.nextReviewTask('synthetic-token','staff',{ownership:'assigned-to-me',queue:'review'});
 assert.equal(Object.hasOwn(next,'responseStatus'),false,'other reads keep their legacy results');

 for(status of [201,202,204,206,403,404,500]){const before=count;await assert.rejects(read());assert.equal(count,before+1);assert.equal(actual.responseStatus,200);}
 status=200;body='{';await assert.rejects(read());
});
