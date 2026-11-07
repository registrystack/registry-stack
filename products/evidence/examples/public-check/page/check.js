// Public certificate check page. No dependencies, no build step. Every value
// that came from the network is written with textContent, never as markup.

export const ANSWER_SCHEMA = 'registry.evidence.public-check/v1alpha1';

export const MESSAGES = {
  notFound: 'No certificate matches this number and check code',
  badFormat: 'The number or code is not in the expected format',
  unavailable: 'The check service is unavailable, try again later',
};

export const STATUS_LABELS = {
  valid: 'Valid',
  suspended: 'Suspended',
  revoked: 'Revoked',
  expired: 'Expired',
};

// Labels for the printed fields of the example project. A field without an
// entry is shown under its own key.
export const FIELD_LABELS = {
  holderName: 'Holder',
  profession: 'Profession',
  issuedOn: 'Issued on',
  expiresOn: 'Expires on',
};

// Reads "#n=<number>&c=<code>". Returns null when neither member is present.
export function parseFragment(hash) {
  const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
  const number = params.get('n');
  const code = params.get('c');
  if (number === null && code === null) {
    return null;
  }
  return { number: number ?? '', code: code ?? '' };
}

// Removes the spaces and hyphens a printed code may be grouped with. Case and
// length are the server's to judge.
export function normalizeCode(code) {
  return code.replace(/[\s-]+/g, '');
}

export function buildRequestBody(number, code) {
  return JSON.stringify({
    documentNumber: number.trim(),
    checkCode: normalizeCode(code),
  });
}

// Maps an HTTP status to one fixed message. Status 0 stands for a network
// error. Rate limits (429), outages (503) and anything unexpected share the
// unavailable message.
export function messageForStatus(status) {
  if (status === 404) {
    return MESSAGES.notFound;
  }
  if (status === 400) {
    return MESSAGES.badFormat;
  }
  return MESSAGES.unavailable;
}

// Turns a 200 body into display rows, or returns null when it is not an
// answer this page understands.
export function describeAnswer(answer) {
  if (
    answer === null ||
    typeof answer !== 'object' ||
    answer.schema !== ANSWER_SCHEMA ||
    typeof answer.status !== 'string' ||
    answer.fields === null ||
    typeof answer.fields !== 'object' ||
    typeof answer.observedAt !== 'string'
  ) {
    return null;
  }
  const rows = Object.entries(answer.fields).map(([key, value]) => [
    FIELD_LABELS[key] ?? key,
    String(value),
  ]);
  return {
    status: STATUS_LABELS[answer.status] ?? answer.status,
    rows,
    observedAt: answer.observedAt,
  };
}

async function runCheck(endpoint, number, code) {
  let response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: buildRequestBody(number, code),
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
    });
  } catch {
    return { problem: messageForStatus(0) };
  }
  if (response.status !== 200) {
    return { problem: messageForStatus(response.status) };
  }
  let answer;
  try {
    answer = describeAnswer(await response.json());
  } catch {
    answer = null;
  }
  return answer === null ? { problem: MESSAGES.unavailable } : { answer };
}

function show(document, outcome) {
  const result = document.getElementById('result');
  const message = document.getElementById('message');
  const list = document.getElementById('answer');
  const observed = document.getElementById('observed');
  list.replaceChildren();
  observed.textContent = '';
  if ('problem' in outcome) {
    message.dataset.kind = 'problem';
    message.textContent = outcome.problem;
  } else {
    const { status, rows, observedAt } = outcome.answer;
    message.dataset.kind = 'valid';
    message.textContent = `Status: ${status}`;
    for (const [label, value] of rows) {
      const term = document.createElement('dt');
      const detail = document.createElement('dd');
      term.textContent = label;
      detail.textContent = value;
      list.append(term, detail);
    }
    observed.textContent = `Checked at ${new Date(observedAt).toLocaleString()}`;
  }
  result.hidden = false;
}

function start(document, location) {
  const meta = document.querySelector('meta[name="check-endpoint"]');
  const endpoint = meta === null ? '' : meta.content;
  document.getElementById('origin').textContent = `Check origin: ${new URL(endpoint).origin}`;
  const numberInput = document.getElementById('number');
  const codeInput = document.getElementById('code');
  const form = document.getElementById('check-form');

  const submit = async () => {
    show(document, await runCheck(endpoint, numberInput.value, codeInput.value));
  };
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submit();
  });

  const fromFragment = parseFragment(location.hash);
  if (fromFragment !== null) {
    numberInput.value = fromFragment.number;
    codeInput.value = fromFragment.code;
    submit();
  }
}

if (typeof document !== 'undefined') {
  start(document, window.location);
}
