const assert = require('node:assert/strict');
const {test} = require('node:test');
const {createServer} = require('node:http');
const {createHash} = require('node:crypto');
const {RenderClient} = require('../client');

test('provider authenticates one document; invalid input precedes acquisition', async () => {
  const pdf=Buffer.from('%PDF-native-client');
  let requests=0;let tokens=0;
  const server=createServer((request,response) => {
    requests++;
    assert.equal(request.url,'/v1/render/receipt');
    assert.equal(request.headers.authorization,'Bearer canary-render-token');
    request.resume();request.on('end',()=> {
      response.writeHead(200,{'content-type':'application/json','traceparent':'00-1234567890abcdef1234567890abcdef-1234567890abcdef-01'});
      response.end(JSON.stringify({pdfBase64:pdf.toString('base64'),pdfSha256:createHash('sha256').update(pdf).digest('hex'),dataSha256:'0'.repeat(64),documentVersion:'receipt v1',warnings:[]}));
    });
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const client=new RenderClient({baseUrl:`http://127.0.0.1:${server.address().port}`});
    const provider={bearerToken:async()=>{tokens++;return 'canary-render-token';}};
    await assert.rejects(client.render(provider,'../receipt',{issuedAt:'2026-10-23T00:00:00Z',data:{}}));
    assert.equal(tokens,0);assert.equal(requests,0);
    for (const invalid of [
      {issuedAt:'not-a-date',data:{}},
      {issuedAt:'2026-10-23T00:00:00Z',data:{},assets:{'../private':'AAAA'}},
      {issuedAt:'2026-10-23T00:00:00Z',data:{},assets:{photo:'aGVsbG8='}},
    ]) {
      await assert.rejects(client.render(provider,'receipt',invalid));
      assert.equal(tokens,0);assert.equal(requests,0);
    }
    const result=await client.render(provider,'receipt',{issuedAt:'2026-10-23T00:00:00Z',data:{number:'R-1'}});
    assert.equal(result.documentVersion,'receipt v1');assert.equal(tokens,1);assert.equal(requests,1);
    const png=Buffer.alloc(1024*1024);Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]).copy(png);
    await client.render(provider,'receipt',{issuedAt:'2026-10-23T00:00:00Z',data:{},assets:{photo:png.toString('base64')}});
    assert.equal(tokens,2);assert.equal(requests,2);
    const original=new Error('value-free provider refusal');original.kind='token';
    await assert.rejects(client.render({bearerToken:async()=>{throw original;}},'receipt',{issuedAt:'2026-10-23T00:00:00Z',data:{}}),error=>error===original);
    assert.equal(requests,2);

  } finally { await new Promise(resolve=>server.close(resolve)); }
});

test('shared PrivateKeyJwt endpoint failure retains its canonical token error', async () => {
  const {PrivateKeyJwt,BaseRegistryClientError}=require('../../registry-breg-client-node');
  const {generateKeyPairSync}=require('node:crypto');
  let acquisitions=0;let renders=0;
  const server=createServer((request,response)=> {
    request.resume();
    if(request.url==='/token')acquisitions++;else renders++;
    response.writeHead(503,{'content-type':'text/plain'});response.end('issuer unavailable');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const base=`http://127.0.0.1:${server.address().port}`;
    const clientKey=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey.export({format:'jwk'});
    Object.assign(clientKey,{alg:'ES256',kid:'canary-client'});
    const provider=new PrivateKeyJwt({tokenEndpoint:base+'/token',clientId:'canary-client',clientKey,resource:'urn:render:test',scopes:['render:render']});
    const caller=new RenderClient({baseUrl:base});
    await assert.rejects(caller.render(provider,'receipt',{issuedAt:'2026-10-23T00:00:00Z',data:{}}),error=>error instanceof BaseRegistryClientError && error.kind==='token' && error.status===503);
    assert.equal(acquisitions,1);assert.equal(renders,0);
  } finally {await new Promise(resolve=>server.close(resolve));}
});

test('native transport failures expose whether an exchange may have completed', async () => {
  let requests=0;
  const server=createServer((request,response)=> {
    requests++;request.resume();
    request.on('end',()=> {
      response.writeHead(200,{'content-type':'application/json','content-length':'10000','connection':'close','traceparent':'00-1234567890abcdef1234567890abcdef-1234567890abcdef-01'});
      response.end('{}');
    });
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const base=`http://127.0.0.1:${server.address().port}`;
  const request={issuedAt:'2026-10-23T00:00:00Z',data:{}};
  try {
    await assert.rejects(new RenderClient({baseUrl:base}).render('canary-render-token','receipt',request),error=>error.kind==='transport' && error.transportKind==='exchange' && error.outcomeUnknown===true);
    assert.equal(requests,1);
  } finally {await new Promise(resolve=>server.close(resolve));}
  await assert.rejects(new RenderClient({baseUrl:base}).render('canary-render-token','receipt',request),error=>error.kind==='transport' && error.transportKind==='connect' && error.outcomeUnknown===false);
});
