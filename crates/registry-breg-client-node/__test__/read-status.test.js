'use strict';
const assert=require('node:assert/strict'), http=require('node:http');
const {test}=require('node:test');
const id='00000000-0000-4000-8000-000000000001';
const traceparent='00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
function readonly(result){assert.equal(result.responseStatus,200);assert.throws(()=>{result.responseStatus=201;},TypeError);assert.throws(()=>{delete result.responseStatus;},TypeError);}
const {BaseRegistryClient}=process.env.REGISTRY_CLIENT_PACKAGE?require(process.env.REGISTRY_CLIENT_PACKAGE).breg:require('..');
const meta={registryIdentifier:'registry',datasetIdentifier:'dataset',recordTypeIdentifier:'company'};
const record={recordIdentifier:id,revisionIdentifier:'1',domainData:{status:'domain-status',responseStatus:201}};
for(const method of ['getRecord','listRecords'])test(method+': actual response status is readonly and scoped',async t=>{
 let status=200,count=0,body;
 const server=http.createServer((req,res)=>{count++;res.writeHead(status,{'content-type':'application/json',traceparent,link:'<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", </v1/schemas/company>; rel="describedby"',...(method==='getRecord'?{etag:'"breg-record-000000000001"'}:{})});res.end(body??JSON.stringify(method==='getRecord'?{data:record,meta}:{items:[record],pageInfo:{nextCursor:new URL(req.url,'http://fixture.invalid').searchParams.has('$skiptoken')?null:'next'},meta}));});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));});
 const client=new BaseRegistryClient({baseUrl:`http://127.0.0.1:${server.address().port}`});
 const read=()=>method==='getRecord'?client.getRecord('companies',id,{accessProfile:'reader'}):client.listRecords('companies',{accessProfile:'reader'});
 const actual=await read();readonly(actual);assert.equal(count,1);assert.equal(actual.kind,'complete');
 const alias=method==='getRecord'?await client.getRecordJson('companies',id,{accessProfile:'reader'}):await client.listRecordsJson('companies',{accessProfile:'reader'});
 assert.equal(Object.hasOwn(alias,'responseStatus'),false,'JSON aliases retain their existing result');
 if(method==='getRecord')assert.equal(actual.value.data.domainData.responseStatus,201,'domain status is not transport status');
 else {assert(actual.continuation);const next=await client.continueList(actual.continuation);assert.equal(Object.hasOwn(next,'responseStatus'),false,'continuations do not reuse first-page status');}

 for(status of [201,202,204,206,403,404,500]){const before=count;await assert.rejects(read());assert.equal(count,before+1);assert.equal(actual.responseStatus,200);}
 status=200;body='{';await assert.rejects(read());
});
