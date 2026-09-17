// OpenFn job: read a payment record back through a least-privilege breg
// reader profile, render its receipt, and deliver the PDF. Shape follows the
// App Kit's tested jobs (notify.js): validate configuration, destructure the
// bridge envelope, check status, return a minimized final state.
// Deterministic rendering makes the bridge's at-least-once redelivery safe:
// a retry or dead-letter replay returns the same bytes. This exact shape was
// walked end to end against a live `render serve` and a real breg dev
// registry; see JOURNEY.md in this directory.
//
// Configuration (private job config, e.g. notification.json):
//   renderUrl:     "http://127.0.0.1:3200"   (loopback to render serve)
//   renderApiKey:  "<32+ byte API key>"      (the value; render's own
//                                             runtime keeps its secret-file ref)
//   breg: { baseUrl, apiKey, accessProfile } (least-privilege reader)
//   delivery: { endpoint, apiKey }           (email/SMS adaptor destination)
fn(async state => {
  const { renderUrl, renderApiKey, breg, delivery, expectedSource, eventTypes } = state.configuration;
  const { event, data } = state.data;
  // breg's record API exposes field ids under camelCase HTTP property names;
  // the template's JSON Schema uses the kebab-case spellings. This table is
  // the reviewed data contract: the readableFields on the reader profile are
  // exactly these fields.
  const contract = {
    reference: 'reference', payerNameAr: 'payer-name-ar', payerNameFr: 'payer-name-fr',
    payerId: 'payer-id', region: 'region', amount: 'amount', currency: 'currency',
    date: 'date', methodAr: 'method-ar', purposeAr: 'purpose-ar', verifyUrl: 'verify-url',
    bidiNote: 'bidi-note',
  };
  if (typeof renderUrl !== 'string' || !/^https?:\/\/[\w.-]+(:\d+)?$/.test(renderUrl) ||
      typeof renderApiKey !== 'string' || !/^[\x21-\x7e]{32,256}$/.test(renderApiKey) ||
      typeof breg?.baseUrl !== 'string' || !/^https?:\/\/[\w.-]+(:\d+)?$/.test(breg.baseUrl) ||
      typeof breg?.apiKey !== 'string' || !/^[\x21-\x7e]{16,2048}$/.test(breg.apiKey) ||
      typeof breg?.accessProfile !== 'string' || !/^[a-z][a-z0-9-]*$/.test(breg.accessProfile) ||
      typeof delivery?.endpoint !== 'string' || !/^https?:\/\/[\w.-]+(:\d+)?\/deliveries$/.test(delivery.endpoint) ||
      typeof delivery?.apiKey !== 'string' || !/^[\x21-\x7e]{16,256}$/.test(delivery.apiKey) ||
      event.source !== expectedSource || !Array.isArray(eventTypes) || !eventTypes.includes(event.type) ||
      !/^[0-9a-f]{64}$/.test(state.eventEffectId)) {
    throw new Error('receipt configuration or event refused');
  }
  const transition = data.request?.transition;
  // No wall-clock fallback: an event without a transition time cannot claim
  // an issuance time, so it fails loudly instead of minting one.
  if (!transition?.at) {
    throw new Error('event carries no transition time; refusing to invent issuedAt');
  }

  // Least-privilege read-back: the reader profile's readableFields are the
  // template's data contract, so the projection cannot carry more than the
  // receipt shows (no code, label, or status travels to the renderer).
  const record = await util.request(
    'GET',
    `${breg.baseUrl}/v1/records/records/${data.recordId}?accessProfile=${breg.accessProfile}`,
    {
      headers: { authorization: `Bearer ${breg.apiKey}`, accept: 'application/json' },
      parseAs: 'json', timeout: 10000,
    },
  );
  if (record.statusCode !== 200 || record.body?.data?.recordIdentifier !== data.recordId) {
    throw new Error(`read-back failed: ${record.statusCode}`);
  }
  const projected = record.body.data.domainData;
  if (Object.keys(projected).sort().join() !== Object.keys(contract).slice().sort().join()) {
    throw new Error('read-back projection does not equal the template data contract');
  }
  const receiptData = {};
  for (const [apiName, schemaName] of Object.entries(contract)) receiptData[schemaName] = projected[apiName];

  const rendered = await util.request('POST', `${renderUrl}/v1/render/receipt`, {
    headers: {
      authorization: `Bearer ${renderApiKey}`,
      'content-type': 'application/json',
      accept: 'application/json',               // pdfBase64 for transport
      'idempotency-key': state.eventEffectId,   // correlation only; rendering
    },                                           // is idempotent by construction
    body: {
      issuedAt: transition.at,
      data: receiptData,
      // assets: { photo: base64 }             // for card-type documents
    },
    parseAs: 'json', timeout: 30000,
  });
  if (rendered.statusCode !== 200 || !rendered.body?.pdfBase64) {
    throw new Error(`render failed: ${rendered.statusCode}`);
  }

  // Deliver the PDF; the delivery key never travels with the document.
  const delivered = await util.request('POST', delivery.endpoint, {
    headers: {
      authorization: `Bearer ${delivery.apiKey}`,
      'content-type': 'application/json',
      'idempotency-key': state.eventEffectId,
    },
    body: {
      recordId: data.recordId,
      pdfBase64: rendered.body.pdfBase64,
      pdfSha256: rendered.body.pdfSha256,
      idempotencyKey: state.eventEffectId,
    },
    parseAs: 'json', timeout: 10000,
  });
  if (delivered.statusCode !== 202 || delivered.body?.accepted !== true) {
    throw new Error(`delivery failed: ${delivered.statusCode}`);
  }

  // Return only what the pipeline needs — hashes for the audit trail.
  return {
    data: { receipt: { sha256: rendered.body.pdfSha256, version: rendered.body.documentVersion } },
    eventEffectId: state.eventEffectId,
  };
});
