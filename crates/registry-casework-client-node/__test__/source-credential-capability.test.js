'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function facade(NativeCaseworkClient) {
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../client.js'), 'utf8'), {
    module, exports: module.exports, Buffer, Object, Array,
    require: name => name === './index' ? { CaseworkClient: NativeCaseworkClient } : require(name),
  });
  return module.exports;
}
const contract = 'registry.casework.human-source-credential.v1';

test('separate source calls cannot silently downgrade to an older loaded addon', () => {
  let requests = 0;
  class OldNative {
    reviewTasks() { requests++; return Promise.resolve({}); }
  }
  const { CaseworkClient } = facade(OldNative);
  const client = new CaseworkClient({ baseUrl: 'https://casework.example.test/' });
  assert.throws(() => client.humanSourceCredentialContract());
  assert.throws(() => client.reviewTasks('casework-canary', 'staff', {}, undefined,
    { sourceProfile: 'source-reader', token: 'source-canary' }));
  assert.equal(requests, 0);
});

test('native capability is exact and separate authority stays per invocation', async () => {
  const observed = [];
  class Native {
    humanSourceCredentialContract() { return contract; }
    reviewTasks(...args) { observed.push(args); return Promise.resolve({ kind: 'complete', value: {} }); }
    listReviewTaskGrants(...args) { observed.push(args); return Promise.resolve({ kind: 'complete', value: {} }); }
  }
  const { CaseworkClient } = facade(Native);
  const client = new CaseworkClient({ baseUrl: 'https://casework.example.test/' });
  assert.equal(client.humanSourceCredentialContract(), contract);
  const credential = { sourceProfile: 'source-reader', token: 'source-canary' };
  await client.reviewTasks('casework-canary', 'staff', {}, undefined, credential);
  await client.reviewTasks('casework-canary', 'staff');
  await client.listReviewTaskGrants('casework-canary', 'staff', { taskId: 'one', sourceCredential: credential });
  assert.equal(observed[0][4].token, credential.token);
  assert.equal(observed[0][4].sourceProfile, credential.sourceProfile);
  assert.equal(observed[1].length, 2);
  assert.equal(observed[2][2].sourceCredential.token, 'source-canary');
  class Wrong extends Native { humanSourceCredentialContract() { return 'unknown-contract'; } }
  const wrong = new (facade(Wrong).CaseworkClient)({ baseUrl: 'https://casework.example.test/' });
  assert.throws(() => wrong.reviewTasks('casework-canary', 'staff', {}, undefined, credential));
  assert.equal(observed.length, 3);
});


test('new credential validation never invokes accessors or intercepts legacy query data', async () => {
  let invoked = 0;
  let requests = 0;
  class Native {
    humanSourceCredentialContract() { return contract; }
    reviewTasks() { requests++; return Promise.resolve({}); }
  }
  const client = new (facade(Native).CaseworkClient)({ baseUrl: 'https://casework.example.test/' });
  const credential = { sourceProfile: 'source-reader', get token() { invoked++; return 'secret'; } };
  assert.throws(() => client.reviewTasks('casework', 'staff', {}, undefined, credential));
  assert.equal(invoked, 0);
  assert.equal(requests, 0);
  await client.reviewTasks('casework', 'staff', { token: 'ordinary-query-data', sourceProfile: 'ordinary-query-data' });
  assert.equal(requests, 1);
});
