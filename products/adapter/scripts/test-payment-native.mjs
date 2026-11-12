#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Synthetic native acceptance. Existing fixture BReg stays owned by its launcher.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { authorization, command, exchange, hash, loopback, privateFile, ready, relay, secret, sleep, sourceSnapshot, start, unusedPort } from './payment-native-support.mjs';

const argumentNames = ['fixture', 'bin-dir', 'simulator-bin', 'admin-url-file', 'ca-file', 'state-dir', 'build-record'];
const options = parseArgs({ options: Object.fromEntries(argumentNames.map((name) => [name, { type: 'string' }])) }).values;
for (const name of argumentNames) assert(options[name], `--${name} is required`);
const repository = fileURLToPath(new URL('../../..', import.meta.url));
const root = resolve(options['state-dir']);
const binaries = resolve(options['bin-dir']);
const simulatorBin = resolve(options['simulator-bin']);
await mkdir(root, { mode: 0o700 }); // A new private run only; no overwrites or cleanup of other runs.
const secrets = join(root, 'secrets'); await mkdir(secrets, { mode: 0o700 });
const fixture = JSON.parse(await readFile(options.fixture, 'utf8'));
assert.equal(fixture.mode, 'synthetic-loopback-only');
const bregOrigin = loopback(fixture.baseUrl);
await exchange('GET', `${bregOrigin}/ready`);
const admin = new URL(await secret(options['admin-url-file']));
assert(['postgres:', 'postgresql:'].includes(admin.protocol) && ['127.0.0.1', 'localhost', '[::1]'].includes(admin.hostname), 'owned loopback PostgreSQL is required');
await privateFile(join(secrets, 'postgres-ca'), await readFile(options['ca-file']));
await privateFile(join(secrets, 'registry-token'), await secret(fixture.credentials.paymentAdapter));
await privateFile(join(secrets, 'provider-token'), randomBytes(32).toString('hex'));
await privateFile(join(secrets, 'changed-provider-token'), randomBytes(32).toString('hex'));
for (const name of ['state-key', 'admission-key', 'audit-key']) await privateFile(join(secrets, name), randomBytes(32));
let issuer;
const reporter = await secret(fixture.credentials.paymentAdapter);
const serviceToken = await secret(fixture.credentials.issuanceService);
const readOnlyToken = await secret(fixture.credentials.serviceCoordinator);
let paymentToken;
const suffix = randomUUID().replaceAll('-', '').slice(0, 12);
const handles = []; const relays = []; const evidence = { mode: 'synthetic-native', checks: [] };
let adapter; let simulator; let coordinator;
function check(name) { evidence.checks.push(name); console.log(`PASS ${name}`); }
function sql(text, url = admin) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('PG')));
  Object.assign(env, { PGHOST: url.hostname.replaceAll('[', '').replaceAll(']', ''), PGPORT: url.port || '5432',
    PGUSER: decodeURIComponent(url.username), PGPASSWORD: decodeURIComponent(url.password), PGDATABASE: url.pathname.slice(1),
    PGSSLMODE: 'verify-full', PGSSLROOTCERT: resolve(options['ca-file']), PGCONNECT_TIMEOUT: '5' });
  return command('psql', ['--no-psqlrc', '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1'], { env, input: text, json: false });
}
async function database(kind) {
  const name = `payment_${kind}_${suffix}`; const migration = `${name}_m`; const runtime = `${name}_r`;
  const password = randomBytes(24).toString('hex');
  sql(`CREATE ROLE ${migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '${password}';
CREATE ROLE ${runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '${password}';
CREATE DATABASE ${name} OWNER ${migration} ENCODING 'UTF8' TEMPLATE template0;`);
  const owner = new URL(admin); owner.pathname = `/${name}`;
  sql(`ALTER SCHEMA public OWNER TO ${migration}; REVOKE ALL ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO ${runtime};`, owner);
  const url = (role) => { const value = new URL(owner); value.username = role; value.password = password; value.search = '?sslmode=require'; return value.toString(); };
  await privateFile(join(secrets, `${kind}-migration`), url(migration));
  await privateFile(join(secrets, `${kind}-runtime`), url(runtime));
  return { name, migration, runtime, owner };
}
function ctl(args) { return command(join(binaries, 'coordinatorctl'), ['--format', 'json', ...args]); }
const simDatabase = join(root, 'simulator.sqlite');
let simulatorPort; let adapterPort; let coordinatorPort;
let adapterOrigin; let coordinatorOrigin; let collectionPath;
let runtimePath; let paymentsPath; let configuration; let simulatorProxy; let registryProxy; let coordinatorProxy;
function simControl(args) { return command(simulatorBin, [...args, '--database', simDatabase], { json: args[0] === 'inspect-collections' }); }
const ledger = () => simControl(['inspect-collections']);
async function startSimulator() {
  simulator = start(simulatorBin, ['serve', '--manual', '--database', simDatabase, '--token-file', join(secrets, 'provider-token'), '--port', String(simulatorPort)], join(root, 'simulator.log'));
  handles.push(simulator); await ready(`http://127.0.0.1:${simulatorPort}/healthz`, simulator);
}
async function startAdapter() {
  adapter = start(join(binaries, 'adapter'), ['serve', '--runtime-config', runtimePath, '--payments-config', paymentsPath], join(root, `adapter-${handles.length}.log`));
  handles.push(adapter); await ready(`${collectionPath}/${randomUUID()}`, adapter, [401]);
}
async function restartAdapter() { await adapter.stop(); await startAdapter(); }
async function createBill(label) {
  const requestId = `${label}-${suffix}`;
  const input = { institutionId: 'institution-a', serviceId: 'licence-issuance', requestId,
    payerId: 'synthetic-payer', payerFinancialAddress: '+99123456789', billDigest: hash(requestId), simulation: true };
  const response = await exchange('POST', bregOrigin + fixture.create.path, { token: serviceToken, body: { input }, key: requestId });
  return { billId: response.body.results.bill.recordId, billVersion: 1, requestId, issuanceId: randomUUID() };
}
const intent = (bill) => ({ billId: bill.billId, billVersion: bill.billVersion });
async function readBill(bill) {
  const response = await exchange('GET', `${bregOrigin}/v1/records/${fixture.recordRoute}/${bill.billId}?accessProfile=${fixture.readProfile}`, { token: reporter });
  return response.body.data.domainData;
}
async function collect(bill, key, expected = [202], token = paymentToken, extra = {}) {
  return exchange('POST', collectionPath, { token, body: { ...intent(bill), ...extra }, key, expected });
}
async function observe(id, expected = [200], token = paymentToken) {
  return exchange('GET', `${collectionPath}/${id}`, { token, expected });
}
async function report(id, key, expected = [200]) {
  return exchange('POST', `${collectionPath}/${id}/record-receipt`, { token: paymentToken, body: { collectionId: id }, key, expected });
}
async function issue(bill, receipt, key, expected = [200]) {
  const path = `/v1/actions/${fixture.issue.action}`;
  const query = `?accessProfile=${fixture.issue.profile}`;
  const conditions = await exchange('POST', bregOrigin + path + '/target-conditions' + query, { token: serviceToken, body: { input: { billId: bill.billId } } });
  const input = { ...intent(bill), requestId: bill.requestId, paymentReceiptId: receipt, issuanceId: bill.issuanceId };
  return exchange('POST', bregOrigin + path + query, { token: serviceToken, body: { input, preconditions: conditions.body.preconditions }, key: `${key}-${suffix}`, expected });
}

async function preflightAndGrant(db, runtime, payments, label) {
  const log = join(root, `${label}-preflight.log`);
  const initial = start(join(binaries, 'adapter'), ['serve', '--runtime-config', runtime, '--payments-config', payments], log);
  handles.push(initial);
  const result = await Promise.race([initial.exited, sleep(15000).then(() => null)]);
  assert(result && result.code !== 0, 'split runtime must refuse before payment table grants');
  assert.match(await readFile(log, 'utf8'), /\badapter\.payment\.configuration\b/, 'preflight must fail at the payment privilege diagnostic');
  sql(`GRANT SELECT, INSERT, UPDATE ON adapter_payment_attempts TO ${db.runtime};
GRANT SELECT, INSERT ON adapter_payment_commands, adapter_payment_events TO ${db.runtime};
GRANT USAGE, SELECT ON SEQUENCE adapter_payment_events_sequence_seq TO ${db.runtime};`, db.owner);
}

async function independentStores(originalConfiguration) {
  const prior = ledger(); const collections = [];
  simControl(['collection-scenario', '--outcome', 'paid']);
  const configPath = join(root, 'independent-payments.yaml');
  await privateFile(configPath, originalConfiguration);
  for (const kind of ['independent_a', 'independent_b']) {
    const db = await database(kind); evidence.databases.push(db.name);
    const port = await unusedPort(); const origin = `http://127.0.0.1:${port}`;
    const runtime = JSON.parse(await readFile(runtimePath, 'utf8'));
    runtime.id = `${kind.replaceAll('_', '-')}-${suffix}`;
    runtime.listener.bind = `127.0.0.1:${port}`;
    runtime.database.runtimeUrlRef = `secret:file/${kind}-runtime`;
    runtime.database.migrationUrlRef = `secret:file/${kind}-migration`;
    const path = join(root, `${kind}-runtime.yaml`); await privateFile(path, runtime);
    await preflightAndGrant(db, path, configPath, kind);
    const process = start(join(binaries, 'adapter'), ['serve', '--runtime-config', path, '--payments-config', configPath], join(root, `${kind}.log`));
    handles.push(process);
    const route = `${origin}/v1/payments/licence-fees/collections`;
    await ready(`${route}/${randomUUID()}`, process, [401]);
    const bill = await createBill(kind);
    const accepted = (await exchange('POST', route, { token: paymentToken, body: intent(bill), key: kind, expected: [202] })).body;
    assert.deepEqual((await exchange('POST', route, { token: paymentToken, body: intent(bill), key: `${kind}-repeat`, expected: [202] })).body, accepted);
    collections.push({ route, bill, accepted });
  }
  // Both fresh stores start from identical provider scope, payer and amount.
  assert.notEqual(collections[0].accepted.collectionId, collections[1].accepted.collectionId);
  assert.equal(ledger().requestCount, prior.requestCount + 2, 'independent bills must create two provider requests');
  simControl(['advance', '--steps', '2']);
  const receipts = [];
  for (const { route, bill, accepted } of collections) {
    const path = `${route}/${accepted.collectionId}`;
    const observation = (await exchange('GET', path, { token: paymentToken })).body;
    assert.equal(observation.state, 'confirmed');
    const receipt = (await exchange('POST', `${path}/record-receipt`, { token: paymentToken, body: { collectionId: accepted.collectionId }, key: 'independent-receipt' })).body;
    assert.equal((await readBill(bill)).paymentReceiptId, receipt.receiptId);
    receipts.push(receipt);
  }
  assert.notEqual(receipts[0].receiptId, receipts[1].receiptId);
  assert.notEqual(receipts[0].providerReference, receipts[1].providerReference);
  const payments = ledger().payments.filter((payment) => receipts.some((receipt) => receipt.providerReference === payment.PaymentReferenceID));
  assert.equal(payments.length, 2);
  for (const field of ['transferRequestId', 'RequestId', 'rtpId', 'billId']) assert.notEqual(payments[0][field], payments[1][field]);
  assert.equal(ledger().payments.length, prior.payments.length + 2);
  evidence.independentStores = { collections: collections.map(({ bill, accepted }) => ({ bill, accepted })), payments };
  check('independent Adapter databases preserve distinct same-payer same-amount bills and provider payments');
}

try {
  issuer = await authorization(secrets);
  paymentToken = issuer.token('payment-coordinator', 'urn:registry:payment-adapter', 'payments:collect');
  simulatorPort = await unusedPort(); adapterPort = await unusedPort(); coordinatorPort = await unusedPort();
  adapterOrigin = `http://127.0.0.1:${adapterPort}`; coordinatorOrigin = `http://127.0.0.1:${coordinatorPort}`;
  collectionPath = `${adapterOrigin}/v1/payments/licence-fees/collections`;
  evidence.transport = { postgres: 'TLS with trusted CA', services: 'synthetic numeric-loopback HTTP' };
  evidence.source = await sourceSnapshot(repository, root);
  evidence.build = { ...JSON.parse(await readFile(options['build-record'], 'utf8')), kind: 'operator-supplied-attestation' };
  assert(evidence.build.source?.head && evidence.build.source?.patchSha256 && evidence.build.command?.length && evidence.build.toolchain,
    'build attestation requires source, command and toolchain facts');
  evidence.binaries = {};
  for (const name of ['adapter', 'adapterctl', 'coordinator', 'coordinatorctl']) {
    evidence.binaries[name] = hash(await readFile(join(binaries, name)));
    assert.equal(evidence.build.binaries[name].sha256, evidence.binaries[name], 'build record must describe the actual executable');
    assert(Array.isArray(evidence.build.binaries[name].features) && evidence.build.binaries[name].profile,
      'build attestation requires enabled features and profile facts');
  }
  evidence.fixtureBinaries = fixture.binaryProvenance;
  for (const name of ['breg', 'bregctl']) {
    const binary = fixture.binaryProvenance[name];
    assert.equal(hash(await readFile(binary.path)), binary.sha256, 'BReg handoff binary must retain its recorded identity');
  }
  const imported = command(join(dirname(simulatorBin), 'python'), ['-c', `import hashlib, json, pathlib, platform, payment_simulator
root = pathlib.Path(payment_simulator.__file__).resolve().parent
print(json.dumps({'path':str(root), 'python':platform.python_version(), 'files':[{'path':str(path.relative_to(root)), 'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(root.rglob('*.py'))]}))`]);
  const packagePrefix = 'tools/payment-simulator/src/payment_simulator/';
  const expectedPackage = evidence.source.files.filter((file) => file.path.startsWith(packagePrefix) && file.path.endsWith('.py'))
    .map((file) => ({ ...file, path: file.path.slice(packagePrefix.length) }));
  assert.deepEqual(imported.files, expectedPackage, 'simulator must import the recorded package content');
  evidence.simulator = { executableSha256: hash(await readFile(simulatorBin)), imported,
    source: evidence.source.files.filter((file) => file.path.startsWith('tools/payment-simulator/')) };
  const adapterDb = await database('adapter'); const coordinatorDb = await database('coordinator');
  evidence.databases = [adapterDb.name, coordinatorDb.name];
  await startSimulator();
  simulatorProxy = await relay(`http://127.0.0.1:${simulatorPort}`); relays.push(simulatorProxy);
  registryProxy = await relay(bregOrigin); relays.push(registryProxy);
  configuration = { apiVersion: 'id.registrystack.org/formats/adapter/payments/v1alpha1', kind: 'AdapterPayments', connections: [{
    id: 'licence-fees', institutionId: 'institution-a', serviceId: 'licence-issuance', allowedClients: ['coordinator-payments'], requiredScope: 'payments:collect',
    binding: { simulation: true, currency: 'USD', currencyScale: 2, providerCredentialRef: 'secret:file/provider-token', providerCredentialIdentity: 'registry', replayWindowSeconds: 3600,
      provider: { type: 'simulator', connection: { baseUrl: simulatorProxy.url, tenant: 'pilot', biller: 'ministry', billerName: 'Ministry', callbackUrl: 'https://programme.example.test/callback', payerFiBic: 'SIMBANK' } },
      registry: { baseUrl: registryProxy.url, recordType: fixture.recordType, recordRoute: fixture.recordRoute, readProfile: fixture.readProfile,
        bindProfile: fixture.bind.profile, receiptProfile: fixture.receipt.profile, bindAction: fixture.bind.action, receiptAction: fixture.receipt.action,
        credentialRef: 'secret:file/registry-token', credentialIdentity: 'payment-adapter' } },
  }] };
  const originalConfiguration = structuredClone(configuration);
  paymentsPath = join(root, 'payments.yaml'); runtimePath = join(root, 'adapter-runtime.yaml');
  await privateFile(paymentsPath, configuration);
  await privateFile(runtimePath, { apiVersion: 'id.registrystack.org/formats/adapter/runtime/v1alpha1', kind: 'AdapterRuntimeConfig', id: `payment-native-${suffix}`,
    endpoints: [], listener: { bind: `127.0.0.1:${adapterPort}` }, secretProviders: { file: { root: secrets } },
    database: { runtimeUrlRef: 'secret:file/adapter-runtime', migrationUrlRef: 'secret:file/adapter-migration', trustedRootCertificateRef: 'secret:file/postgres-ca' },
    oidc: { issuer: issuer.issuer, audience: 'urn:registry:payment-adapter', jwksSource: { type: 'static', documentRef: 'secret:file/jwks' } },
    allowedClients: ['coordinator-payments'], allowedPrivateCidrs: ['127.0.0.0/8'], audit: { retentionDays: 90 } });
  await preflightAndGrant(adapterDb, runtimePath, paymentsPath, 'adapter');
  await startAdapter(); check('PostgreSQL TLS startup and exact split-role payment privilege diagnostic');

  const bill = await createBill('recovery');
  await issue(bill, 'absent-receipt', 'unpaid-issue', [412]);
  await collect(bill, 'extra-facts', [422], paymentToken, { amount: 1, paid: true });
  await collect(bill, 'missing-scope', [403], issuer.token('payment-coordinator', 'urn:registry:payment-adapter', ''));
  await collect(bill, 'citizen', [401], null);
  assert.equal(ledger().requestCount, 0); check('unpaid issuance, forged financial fields and unauthorized callers refused');

  registryProxy.drop(`/v1/actions/${fixture.bind.action}`);
  await collect(bill, 'original', [503]); assert.equal(ledger().requestCount, 0);
  await restartAdapter(); simulatorProxy.drop('/rtpRequest');
  await collect(bill, 'original', [503]); assert.equal(ledger().requestCount, 1);
  const beforeLookup = simulatorProxy.records.length;
  await exchange('POST', `${collectionPath}/receipt`, { token: paymentToken, body: intent(bill), key: 'original', expected: [404] });
  assert.equal(simulatorProxy.records.length, beforeLookup);
  await simulator.stop(); await startSimulator();
  const originalBinding = structuredClone(configuration.connections[0].binding);
  Object.assign(configuration.connections[0].binding.provider.connection, { baseUrl: 'http://127.0.0.1:9/', tenant: 'changed-tenant', biller: 'changed-biller' });
  configuration.connections[0].binding.providerCredentialRef = 'secret:file/changed-provider-token';
  configuration.connections[0].binding.providerCredentialIdentity = 'changed-producer';
  await privateFile(paymentsPath, configuration); await restartAdapter();
  const accepted = (await collect(bill, 'original')).body;
  assert.deepEqual((await collect(bill, 'another-workflow-key')).body, accepted);
  assert.equal(ledger().requestCount, 1);
  const sends = simulatorProxy.records.filter((record) => record.path === '/rtpRequest');
  assert.equal(sends.length, 2); assert.equal(sends[0].bodyHash, sends[1].bodyHash);
  assert(sends.every((record) => record.tenant === 'pilot' && record.biller === 'ministry'));
  check('lost bind/provider responses recover across restarts under original command and binding');

  await observe(accepted.collectionId, [404], issuer.token('another-subject', 'urn:registry:payment-adapter', 'payments:collect'));
  await observe(accepted.collectionId, [403], issuer.token('payment-coordinator', 'urn:registry:payment-adapter', ''));
  await collect({ ...bill, billVersion: 2 }, 'original', [409]);
  simControl(['advance', '--steps', '1']);
  assert.equal((await observe(accepted.collectionId)).body.state, 'pending');
  await report(accepted.collectionId, 'too-early', [409]);
  assert.equal((await readBill(bill)).paymentState, 'attempt-bound');
  check('read isolation, changed-key-body refusal and COM/PENDING never release the bill');
  simControl(['advance', '--steps', '1']); simulatorProxy.corrupt(true);
  await observe(accepted.collectionId, [502]); await report(accepted.collectionId, 'corrupt-observation', [409]);
  simulatorProxy.corrupt(false);
  const paid = (await observe(accepted.collectionId)).body;
  assert.equal(paid.state, 'confirmed'); assert.deepEqual(paid.money, { value: '25.00', currency: 'USD', scale: 2 });
  registryProxy.drop(`/v1/actions/${fixture.receipt.action}`);
  await report(accepted.collectionId, 'receipt', [503]); await restartAdapter();
  const receipt = (await report(accepted.collectionId, 'receipt')).body;
  assert.deepEqual((await report(accepted.collectionId, 'new-receipt-key')).body, receipt);
  assert.equal(registryProxy.records.filter((record) => record.path === `/v1/actions/${fixture.receipt.action}`).length, 1);
  assert.equal((await readBill(bill)).paymentReceiptId, receipt.receiptId);
  assert.equal(ledger().payments.length, 1);
  await issue(bill, receipt.receiptId, 'issue-once'); await issue(bill, receipt.receiptId, 'issue-twice', [412]);
  assert.equal((await readBill(bill)).paymentState, 'issued');
  await exchange('POST', bregOrigin + fixture.receipt.path, { token: readOnlyToken, body: { input: {} }, key: 'unauthorized-report', expected: [404] });
  check('exact-money correlation and lost receipt acknowledgement recover one receipt and one issuance');

  configuration.connections[0].binding = originalBinding; await privateFile(paymentsPath, configuration); await restartAdapter();
  coordinatorProxy = await relay(adapterOrigin); relays.push(coordinatorProxy);
  const packagePath = join(root, 'coordinator-package');
  const packaged = ctl(['package', '--project', join(repository, 'products/coordinator/examples/payment-collections'), '--output', packagePath]);
  const coordinatorRuntime = join(root, 'coordinator-runtime.yaml');
  await privateFile(coordinatorRuntime, { apiVersion: 'id.registrystack.org/formats/coordinator/runtime/v1alpha1', kind: 'CoordinatorRuntimeConfig',
    secretProviders: { file: { root: secrets } }, database: { runtimeUrlRef: 'secret:file/coordinator-runtime', migrationUrlRef: 'secret:file/coordinator-migration', trustedRootCertificateRef: 'secret:file/postgres-ca' },
    namespace: 'coordinator_payment_native', connections: { 'licence-fees': { type: 'payments', baseUrl: coordinatorProxy.url, paymentConnection: 'licence-fees', resultCheckSeconds: 60,
      authorization: { tokenEndpoint: `${issuer.origin}/token`, clientAssertionAudience: issuer.issuer, clientId: 'coordinator-payments', signingKeyRef: 'secret:file/coordinator-payments-jwk', resource: 'urn:registry:payment-adapter', scopes: ['payments:collect'] } } },
    deployment: { databaseId: `coordinator-payment-${suffix}`, runtimeRole: coordinatorDb.runtime,
      packages: [{ root: packagePath, expectedDigest: packaged.packageDigest }], listener: { bind: `127.0.0.1:${coordinatorPort}`, tlsTermination: 'development-loopback' },
      authentication: { issuer: issuer.issuer, audience: 'urn:example:coordinator', scopeClaim: 'scope', jwksSource: { type: 'static', documentRef: 'secret:file/jwks' },
        policies: { 'licence-service': { subjects: ['licence-service'], requiredScopes: ['coordinator:start'], workflows: ['payment-collections'], actions: ['start', 'status'] },
          'payment-operator': { subjects: ['payment-operator'], requiredScopes: ['coordinator:operate'], workflows: ['payment-collections'], actions: ['status', 'inspect', 'reconcile', 'retry-same'], operator: true } } },
      auditFile: join(root, 'coordinator-audit.jsonl'), auditKeyRef: 'secret:file/audit-key', activeStateKey: 1, stateKeys: { '1': { keyRef: 'secret:file/state-key' } }, admissionKeyRef: 'secret:file/admission-key' } });
  ctl(['--runtime-config', coordinatorRuntime, 'check', '--deny-warnings']);
  ctl(['--runtime-config', coordinatorRuntime, 'plan']);
  const applied = ctl(['--runtime-config', coordinatorRuntime, 'apply']); assert.equal(applied.activation.roleMode, 'split');
  coordinator = start(join(binaries, 'coordinator'), ['--runtime-config', coordinatorRuntime], join(root, 'coordinator.log')); handles.push(coordinator);
  await ready(`${coordinatorOrigin}/health`, coordinator);
  const caller = issuer.token('licence-service', 'urn:example:coordinator', 'coordinator:start', 'licence-service');
  const operator = issuer.token('payment-operator', 'urn:example:coordinator', 'coordinator:operate', 'payment-operator');
  const contract = (await exchange('GET', `${coordinatorOrigin}/v1/workflows/payment-collections`, { token: caller })).body;
  const workflowBill = await createBill('workflow');
  coordinatorProxy.drop('/v1/payments/licence-fees/collections');
  const run = (await exchange('POST', `${coordinatorOrigin}/v1/runs`, { token: caller, key: `run-${suffix}`,
    body: { workflow: 'payment-collections', workflowRevision: contract.workflowRevision, input: intent(workflowBill) } })).body;
  async function untilPaused({ finish = false } = {}) {
    const deadline = Date.now() + 150000;
    while (Date.now() < deadline) {
      const status = (await exchange('GET', `${coordinatorOrigin}/v1/runs/${run.runId}`, { token: caller })).body;
      evidence.coordinatorRun = status;
      // A scheduled retry retains attention until the worker proves its outcome.
      if (status.state !== 'running' && (!finish || status.state !== 'attention')) return status;
      await sleep(500);
    }
    throw new Error('native Coordinator did not pause or finish within its acceptance budget');
  }
  const requestHold = await untilPaused();
  evidence.coordinatorRequestHold = requestHold;
  assert.equal(requestHold.state, 'attention'); assert.equal(requestHold.step, 'request-collection');
  assert.equal(requestHold.uncertain, true); assert.equal(ledger().requestCount, 2);
  const coordinatorRequest = coordinatorProxy.records.find((record) => record.path === '/v1/payments/licence-fees/collections');
  assert(coordinatorRequest?.key);
  const workflowCollection = (await exchange('POST', `${collectionPath}/receipt`, {
    token: paymentToken, body: intent(workflowBill), key: coordinatorRequest.key,
  })).body;
  coordinatorProxy.drop(`/v1/payments/licence-fees/collections/${workflowCollection.collectionId}/record-receipt`);
  await exchange('POST', `${coordinatorOrigin}/v1/runs/${run.runId}/reconcile`, { token: operator, body: { reason: 'native-payment-response-loss' } });
  assert.equal(coordinatorProxy.records.filter((record) => record.path === '/v1/payments/licence-fees/collections').length, 1);
  assert.equal(ledger().requestCount, 2);
  simControl(['advance', '--steps', '2']);
  const receiptHold = await untilPaused();
  evidence.coordinatorReceiptHold = receiptHold;
  assert.equal(receiptHold.state, 'attention'); assert.equal(receiptHold.step, 'record-receipt'); assert.equal(receiptHold.uncertain, true);
  assert.equal((await readBill(workflowBill)).paymentState, 'paid');
  const receiptMutations = registryProxy.records.filter((record) => record.path === `/v1/actions/${fixture.receipt.action}`).length;
  await exchange('POST', `${coordinatorOrigin}/v1/runs/${run.runId}/retry-same`, { token: operator, body: { reason: 'native-receipt-response-loss' } });
  const settled = await untilPaused({ finish: true });
  assert(settled && settled.outcome === 'receipt-recorded', 'native Coordinator did not reach the receipt outcome');
  assert.equal(registryProxy.records.filter((record) => record.path === `/v1/actions/${fixture.receipt.action}`).length, receiptMutations);
  const receiptSends = coordinatorProxy.records.filter((record) => record.path.endsWith('/record-receipt'));
  assert.equal(receiptSends.length, 2); assert.equal(receiptSends[0].key, receiptSends[1].key);
  assert.equal(receiptSends[0].bodyHash, receiptSends[1].bodyHash);
  assert.equal(settled.output.billId, workflowBill.billId); assert.equal(settled.output.simulation, true);
  assert.equal((await readBill(workflowBill)).paymentReceiptId, settled.output.receiptId);
  assert(issuer.grants > 0); assert.equal(ledger().payments.length, 2);
  await issue(workflowBill, settled.output.receiptId, 'workflow-issue');
  check('native Coordinator request reconciliation, named completion, exact receipt retry and BReg issuance');

  simControl(['collection-scenario', '--outcome', 'failed']);
  const declined = await createBill('declined'); const failed = (await collect(declined, 'declined')).body;
  simControl(['advance', '--steps', '2']); assert.equal((await observe(failed.collectionId)).body.state, 'failed');
  const count = ledger().requestCount;
  await restartAdapter(); assert.deepEqual((await collect(declined, 'after-decline')).body, failed);
  assert.equal(ledger().requestCount, count); await report(failed.collectionId, 'declined-report', [409]);
  assert.equal((await readBill(declined)).paymentState, 'attempt-bound');
  check('definitive failure permanently reserves its bill across restart and new command keys');

  configuration.connections[0].binding.replayWindowSeconds = 1;
  await privateFile(paymentsPath, configuration); await restartAdapter();
  const expired = await createBill('expired-recovery');
  simulatorProxy.drop('/rtpRequest'); await collect(expired, 'expired-recovery', [503]);
  const expiredCount = ledger().requestCount; await sleep(1100);
  configuration.connections[0].binding.replayWindowSeconds = 86400;
  await privateFile(paymentsPath, configuration); await restartAdapter();
  const held = await collect(expired, 'fresh-key-after-expiry', [409]);
  assert.equal(held.body.code, 'adapter.payment.recovery-held');
  assert.equal(ledger().requestCount, expiredCount);
  const heldBill = await readBill(expired);
  assert.equal(heldBill.paymentState, 'attempt-bound');
  assert.equal((await observe(heldBill.paymentAttemptId)).body.state, 'unknown');
  await report(heldBill.paymentAttemptId, 'held-report', [409]);
  check('expired original replay window stays held after restart, config extension and a new command key');
  await independentStores(originalConfiguration);
  evidence.provider = ledger(); evidence.providerCommands = simulatorProxy.records;
  evidence.registryCommands = registryProxy.records; evidence.coordinatorRun = settled;
  evidence.coordinatorCommands = coordinatorProxy.records;
  evidence.registryPackage = { digest: fixture.packageDigest, schemaFingerprint: fixture.schemaFingerprint };
} finally {
  if (simulatorProxy) evidence.providerCommands = simulatorProxy.records;
  if (registryProxy) evidence.registryCommands = registryProxy.records;
  if (coordinatorProxy) evidence.coordinatorCommands = coordinatorProxy.records;
  const stopped = await Promise.allSettled(handles.reverse().map((handle) => handle.stop()));
  const closed = await Promise.allSettled([...relays.reverse().map((proxy) => proxy.close()), ...(issuer ? [issuer.close()] : [])]);
  evidence.shutdown = [...stopped, ...closed].every((result) => result.status === 'fulfilled') ? 'passed' : 'failed';
  await privateFile(join(root, 'progress.json'), evidence);
  assert.equal(evidence.shutdown, 'passed', 'native fixture shutdown failed; inspect owned process logs');
}
evidence.result = 'passed';
await privateFile(join(root, 'acceptance.json'), evidence);
console.log(`Native payment acceptance passed: ${evidence.checks.length} checks. Private evidence: ${join(root, 'acceptance.json')}`);
