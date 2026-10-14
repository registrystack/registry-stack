'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const root = path.resolve(__dirname, '../../../../../..');
const { BaseRegistryClient } = require(path.join(root, 'crates/registry-breg-client-node'));
const { ProjectClient } = require(path.join(process.env.BREG_CONSOLE_BUILD, 'products/breg/generated/refactor/generated/sdk/project.js'));
const { facilityConsole } = require(path.join(process.env.BREG_CONSOLE_BUILD, 'products/breg/examples/refactor/facility/console/console.js'));
const client = (url, profile) => new ProjectClient(new BaseRegistryClient({baseUrl: url}), profile);
(async () => {
  const reader = client(process.env.BREG_READER_URL, 'facility-reader');
  const registrar = client(process.env.BREG_REGISTRAR_URL, 'facility-registrar');
  const author = client(process.env.BREG_AUTHOR_URL, 'facility-correction-author');
  const applier = client(process.env.BREG_APPLIER_URL, 'facility-correction-applier');
  const id = process.env.BREG_FACILITY_ID;
  const result = await facilityConsole(reader, registrar, author, id,
    {facilityCode:'LIVE-CONSOLE',name:'Second clinic',addressLine:'2 Main Road',city:'Bangkok',postalCode:'10200',operatorId:process.env.BREG_OPERATOR_ID,jurisdiction:'zone-a'},
    {facilityId:id,addressLine:'3 Main Road',city:'Bangkok',postalCode:'10200'});
  assert.equal(result.title, 'Live clinic');
  assert.equal(result.operatorTitle, 'OP-LIVE');
  const redacted = await client(process.env.BREG_REDACTED_URL, 'fixture-redacted-reader').read('facility', id);
  assert.equal(redacted.title, id);
  assert.equal(redacted.data.name, undefined);
  assert.equal(result.current.document.state, 'submitted');
  const draft = await author.invoke('deactivate-facility', {facilityId:id}, 'live-deactivate');
  const submitted = await author.execute(author.prepare(draft, 'submit', {}, 'live-deactivate-submit'));
  const listing = await applier.listProposals('deactivate-facility');
  const current = listing.items.find(item => item.document.id === submitted.document.id);
  assert(current);
  assert.equal(current.document.links.apply.availability.available, true);
  const attempt = applier.prepare(current, 'apply', {submissionVersion:current.document.submissionVersion,effectDigest:current.document.effectDigest}, 'live-deactivate-apply');
  const applied = await applier.execute(attempt);
  assert.equal(applied.document.state, 'applied');
  assert.equal((await applier.execute(attempt)).document.application.applicationId, applied.document.application.applicationId);
  assert.equal((await reader.read('facility',id)).data.status, 'inactive');
  console.log('generated TypeScript console live PostgreSQL journey passed');
})().catch(error => {console.error(error);process.exitCode=1;});
