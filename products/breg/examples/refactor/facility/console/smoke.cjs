'use strict';
// Run against JavaScript emitted from the checked TypeScript fixture.
const assert = require('node:assert/strict');
const path = require('node:path');
const build = process.env.BREG_CONSOLE_BUILD;
if (!build) throw new Error('BREG_CONSOLE_BUILD must name the compiler output directory');
const { ProjectClient } = require(path.join(build, 'products/breg/generated/refactor/generated/sdk/project.js'));
const { facilityConsole } = require(path.join(build, 'products/breg/examples/refactor/facility/console/console.js'));
const facility = '00000000-0000-4000-8000-000000000001';
const assignment = '00000000-0000-4000-8000-000000000002';
const operator = '00000000-0000-4000-8000-000000000003';
const calls = [];
const record = (id, domainData) => ({recordIdentifier: id, revisionIdentifier: '1', domainData});
const handle = state => ({documentJson: JSON.stringify({id: facility, actionId: 'correct-address', state, links: {
  apply: {availability: {available: false, observedRevision: 2, reason: 'pending-review', recovery: 'refresh'}}}})});
const continuation = {opaque: 'native continuation'};
const native = {
  async getRecord(route, id, options) {
    calls.push(['read', route, options.accessProfile]);
    const data = route === 'facilities' ? {name: 'Central facility'} : route === 'facility-assignments' ? {operator, facility} : {operatorCode: 'OP-1'};
    return {value: {data: record(id, data)}};
  },
  async listRecords(route, options) {
    assert.equal(route, 'facility-assignments');
    assert.equal(options.filter, `facility eq '${facility}'`);
    return {value: {items: [record(assignment, {facility, operator})]}, continuation};
  },
  async continueList(current) { assert.equal(current, continuation); calls.push(['next']); return {value: {items: []}}; },
  async registryContract(profile) { return {selectAction: action => ({action, profile}), selectProposals: () => ({profile})}; },
  async invokeAction(binding, input, key) { calls.push(['invoke', binding.action, binding.profile, key]); return {value: {action: binding.action, applicationId: facility, results: {}}}; },
  async startProposal(binding, input, key) { calls.push(['start', binding.action, binding.profile, key]); assert.equal(JSON.parse(input).facilityId, facility); return handle('draft'); },
  prepareProposal(proposal, transition, body, key) { assert.equal(transition, 'submit'); assert.equal(body, '{}'); return {proposal, key}; },
  async executeProposal(attempt) { assert.equal(attempt.key, 'console-submit-1'); return handle('submitted'); },
  async listProposals(collection, query) { assert.equal(collection.profile, 'author'); assert.equal(JSON.parse(query).action, 'correct-address'); return {items: [handle('submitted')], nextCursor: null}; },
  async readProposal(proposal) { calls.push(['resume']); return proposal; },
};
(async () => {
  const reader = new ProjectClient(native, 'reader');
  const registrar = new ProjectClient(native, 'registrar');
  const author = new ProjectClient(native, 'author');
  const result = await facilityConsole(reader, registrar, author, facility,
    {facilityCode: 'F-1', name: 'Central facility', addressLine: 'Main street', city: 'Example', postalCode: '12345', operatorId: operator, jurisdiction: 'local'},
    {facilityId: facility, addressLine: 'Second street', city: 'Example', postalCode: '12345'});
  assert.equal(result.title, 'Central facility');
  assert.equal(result.operatorTitle, 'OP-1');
  assert.equal(result.unavailableReason, 'pending-review');
  assert.deepEqual(result.nextAssignments.items, []);
  assert(calls.some(call => call[0] === 'next'));
  assert(calls.some(call => call[0] === 'resume'));
  assert(calls.some(call => call[0] === 'invoke' && call[2] === 'registrar'));
  assert(calls.some(call => call[0] === 'start' && call[2] === 'author'));
  // A caller-filtered projection without the authored title never fabricates it.
  const redacted = new ProjectClient({...native, getRecord: async () => ({value: {data: record(facility, {})}})}, 'restricted');
  assert.equal((await redacted.read('facility', facility)).title, facility);
  console.log('generated console smoke passed');
})().catch(error => {console.error(error);process.exitCode = 1;});
