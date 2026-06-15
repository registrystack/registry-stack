const ORIENTING_SENTENCE = "Relay shows what an authorized system can read. Notary returns only the fact a service asked for.";
const CIVIL_NOTARY_DEFAULT = {
  serviceId: "civil-notary",
  claimId: "person-is-alive",
  subjectScheme: "national_id",
  subjectValue: "NID-1001",
  disclosure: "predicate",
  format: "application/vnd.registry-notary.claim-result+json",
  purpose: ["https:", "//demo.example.gov/purpose/decentralized-evidence-demo"].join("")
};

const text = (value) => value == null ? "" : String(value);
const byId = (id) => document.getElementById(id);

const state = {
  catalog: [],
  metadata: null,
  evaluation: null,
  selectedService: CIVIL_NOTARY_DEFAULT.serviceId,
  selectedClaim: CIVIL_NOTARY_DEFAULT.claimId,
  subjectScheme: CIVIL_NOTARY_DEFAULT.subjectScheme,
  subjectValue: CIVIL_NOTARY_DEFAULT.subjectValue,
  disclosure: CIVIL_NOTARY_DEFAULT.disclosure,
  format: CIVIL_NOTARY_DEFAULT.format,
  purpose: CIVIL_NOTARY_DEFAULT.purpose
};

function escapeHtml(value) {
  return text(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  }[char]));
}

function prettyJson(value) {
  if (typeof value === "string") return value;
  return JSON.stringify(value ?? {}, null, 2);
}

function sameOriginExplorerPath(path) {
  return typeof path === "string" && path.startsWith("/api/explorer/");
}

async function explorerFetch(path, options = {}) {
  if (!sameOriginExplorerPath(path)) throw new Error("Explorer requests must use same-origin /api/explorer/ routes.");
  const response = await fetch(path, {cache: "no-store", ...options});
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = body.error || body.message || `HTTP ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.body = body;
    throw error;
  }
  return body;
}

function normalizeItems(payload, keys) {
  if (Array.isArray(payload)) return payload;
  for (const key of keys) {
    if (Array.isArray(payload?.[key])) return payload[key];
  }
  return [];
}

function normalizeCollection(value) {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") return Object.values(value);
  return [];
}

function endpoint(path) {
  const url = new URL(path, window.location.origin);
  return `${url.pathname}${url.search}`;
}

function labelFor(item, fallback) {
  return item?.label || item?.name || item?.title || item?.id || fallback;
}

function ensureShell() {
  const existing = byId("claims-explorer-root") || byId("claims-explorer") || byId("explorer") || byId("explorer-root");
  const root = existing || document.createElement("section");
  root.id = root.id || "claims-explorer";
  root.classList.add("explorer-shell");
  if (!existing) {
    const main = document.querySelector("main") || document.body;
    main.appendChild(root);
  }
  if (!document.body.textContent.includes(ORIENTING_SENTENCE)) {
    root.insertAdjacentHTML("beforebegin", `<p class="orienting-sentence">${escapeHtml(ORIENTING_SENTENCE)}</p>`);
  }
  return root;
}

function renderLoading(root) {
  root.innerHTML = `
    ${comparisonPanel()}
    <section class="loading-card" aria-live="polite">
      <strong>Loading the Civil Notary example.</strong>
      <p class="meta">The first screen will show the yes/no answer. Request details stay collapsed until needed.</p>
    </section>
  `;
}

function renderUnavailable(root, error) {
  root.innerHTML = `
    ${comparisonPanel()}
    <section class="unavailable-card" aria-live="polite">
      <h2>Claims Explorer unavailable</h2>
      <p>The Civil Notary first-load evaluation could not be loaded from the same-origin explorer API.</p>
      <p class="meta">${escapeHtml(error?.message || "Reload or retry when the lab service is ready.")}</p>
      <div class="actions"><button class="primary" type="button" data-retry>Retry</button></div>
    </section>
  `;
}

function comparisonPanel() {
  return `
    <section class="comparison-panel compact-comparison">
      <div>
        <p class="eyebrow">Relay plus Notary</p>
        <h2>Relay can read rows. Notary returns a limited answer.</h2>
        <p class="meta">The relying service gets the answer it asked for, not the source row.</p>
      </div>
    </section>
  `;
}

function claimItems() {
  const raw = state.metadata?.claim_service?.claims || state.metadata?.claims || state.metadata?.service?.claims || [];
  const items = normalizeCollection(raw);
  if (items.length) return items;
  return [{id: CIVIL_NOTARY_DEFAULT.claimId, label: "Vital Status Attestation"}];
}

function serviceOptions() {
  const items = state.catalog.length ? state.catalog : [{id: "civil-notary", label: "Civil Notary"}];
  return items.map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === state.selectedService ? "selected" : ""}>${escapeHtml(labelFor(item, item.id))}</option>`).join("");
}

function selectedClaim() {
  return byId("claim-select")?.value || state.selectedClaim || CIVIL_NOTARY_DEFAULT.claimId;
}

function selectedScheme() {
  return byId("scheme-input")?.value || byId("scheme-select")?.value || state.subjectScheme || CIVIL_NOTARY_DEFAULT.subjectScheme;
}

function selectedSubject() {
  return byId("subject-input")?.value || state.subjectValue || CIVIL_NOTARY_DEFAULT.subjectValue;
}

function selectedDisclosure() {
  return byId("disclosure-select")?.value || state.disclosure || CIVIL_NOTARY_DEFAULT.disclosure;
}

function selectedFormat() {
  return byId("format-select")?.value || state.format || CIVIL_NOTARY_DEFAULT.format;
}

function selectedPurpose() {
  return byId("purpose-input")?.value || state.purpose || CIVIL_NOTARY_DEFAULT.purpose;
}

function evaluationPayload() {
  return {
    claim_id: selectedClaim(),
    subject: {
      scheme: selectedScheme(),
      value: selectedSubject()
    },
    disclosure: selectedDisclosure(),
    format: selectedFormat(),
    purpose: selectedPurpose()
  };
}

function evaluationStatePayload() {
  return {
    claim_id: state.selectedClaim,
    subject: {
      scheme: state.subjectScheme,
      value: state.subjectValue
    },
    disclosure: state.disclosure,
    format: state.format,
    purpose: state.purpose
  };
}

function minimization() {
  const item = state.evaluation?.minimization || state.evaluation?.data_minimization || {};
  return {
    relayFieldsUsed: item.relay_fields_used ?? item.relay_fields_used_count ?? item.relayFieldCount ?? 7,
    returnedToService: item.returned_to_service ?? item.returned_fields_count ?? item.returnedFieldCount ?? 1,
    rawRowReturned: item.raw_row_returned === true ? "yes" : "no"
  };
}

function responseStatus() {
  return state.evaluation?.response_source?.status ?? state.evaluation?.response?.status ?? null;
}

function answerProblem(value) {
  const status = responseStatus();
  if (status && Number(status) >= 400) {
    const title = value?.title || state.evaluation?.response_source?.body?.title || "Notary request failed";
    const detail = value?.detail || state.evaluation?.response_source?.body?.detail || `HTTP ${status}`;
    return `${title}: ${detail}`;
  }
  if (state.evaluation?.mode === "retry") return "The Notary service did not return an answer.";
  return "";
}

function answerState() {
  const value = state.evaluation?.answer ?? state.evaluation?.result ?? state.evaluation?.claim_result ?? {};
  if (typeof value === "string") return {label: value, note: "", status: "answered"};
  const problem = answerProblem(value);
  if (problem) return {label: "not evaluated", note: problem, status: "problem"};
  if (value.satisfied === true) return {label: "yes", note: "", status: "answered"};
  if (value.satisfied === false) {
    const note = value.subject_found === false ? "No matching preview subject was found." : "";
    return {label: "no", note, status: "answered"};
  }
  if (value.value != null) return {label: value.value, note: "", status: "answered"};
  if (state.evaluation?.satisfied === true) return {label: "yes", note: "", status: "answered"};
  if (state.evaluation?.satisfied === false) return {label: "no", note: "", status: "answered"};
  return {label: "not evaluated", note: "The Notary response did not include a claim result.", status: "empty"};
}

function answerValue() {
  return answerState().label;
}

function sourceInfo() {
  return state.evaluation?.source || state.evaluation?.source_binding || state.metadata?.source_binding || {};
}

function selectedServiceSummary() {
  return state.metadata?.claim_service || state.catalog.find((item) => item.id === state.selectedService) || {};
}

function selectedClaimSummary() {
  return claimItems().find((item) => item.id === state.selectedClaim) || claimItems()[0] || {};
}

function curlValue(payload) {
  return payload?.curl || payload?.request?.curl || payload?.request_source?.curl || "";
}

function sourceValue(payload, kind) {
  return payload?.[kind] || payload?.[`${kind}_source`] || payload?.source?.[kind] || null;
}

function disclosure(title, value, copyLabel) {
  const content = typeof value === "string" ? value : prettyJson(value);
  return `
    <details>
      <summary>${escapeHtml(title)}</summary>
      <div class="details-body">
        <div class="copy-row"><button type="button" data-copy="${escapeHtml(content)}">${escapeHtml(copyLabel || "Copy")}</button></div>
        <pre>${escapeHtml(content || "Not available from API response.")}</pre>
      </div>
    </details>
  `;
}

function renderClaimQuestion() {
  const claims = claimItems();
  return `
    <section class="claim-question-panel">
      <div class="field-control">
        <label for="claim-select">Claim</label>
        <select id="claim-select">${claims.map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === state.selectedClaim ? "selected" : ""}>${escapeHtml(labelFor(item, item.id))}</option>`).join("")}</select>
      </div>
      <div class="field-control">
        <label for="scheme-input">Subject identifier scheme</label>
        <input id="scheme-input" value="${escapeHtml(state.subjectScheme || CIVIL_NOTARY_DEFAULT.subjectScheme)}">
      </div>
      <div class="field-control">
        <label for="subject-input">Subject identifier</label>
        <input id="subject-input" value="${escapeHtml(state.subjectValue || CIVIL_NOTARY_DEFAULT.subjectValue)}">
      </div>
      <div class="actions"><button class="primary" type="button" data-evaluate>Evaluate</button></div>
    </section>
  `;
}

function renderControls() {
  const claim = selectedClaimSummary();
  const disclosures = normalizeCollection(claim.allowed_disclosures).length ? normalizeCollection(claim.allowed_disclosures) : [state.disclosure || CIVIL_NOTARY_DEFAULT.disclosure];
  const formats = normalizeCollection(claim.formats).length ? normalizeCollection(claim.formats) : [state.format || CIVIL_NOTARY_DEFAULT.format];
  return `
    <details class="explorer-control-panel">
      <summary>Advanced evaluation settings</summary>
      <div class="control-grid">
        <div class="field-control">
          <label for="disclosure-select">What to return</label>
          <select id="disclosure-select">${disclosures.map((item) => `<option value="${escapeHtml(item)}" ${item === state.disclosure ? "selected" : ""}>${escapeHtml(item === "predicate" ? "just yes/no" : item)}</option>`).join("")}</select>
        </div>
        <div class="field-control">
          <label for="format-select">Format</label>
          <select id="format-select">${formats.map((item) => `<option value="${escapeHtml(item)}" ${item === state.format ? "selected" : ""}>claim-result JSON</option>`).join("")}</select>
        </div>
        <div class="field-control">
          <label>Acting as</label>
          <div class="source-line">a service allowed to ask questions, not read records</div>
        </div>
        <div class="field-control">
          <label for="purpose-input">Purpose for this request</label>
          <input id="purpose-input" value="${escapeHtml(state.purpose || CIVIL_NOTARY_DEFAULT.purpose)}">
        </div>
        <details>
          <summary>Refine query</summary>
          <div class="details-body">
            <p class="meta">The Civil first load uses the seeded subject NID-1001. Change it only when you want to test another synthetic subject.</p>
          </div>
        </details>
      </div>
    </details>
  `;
}

function renderSourceInfo() {
  const source = sourceInfo();
  return `
    <div class="source-card">
      <h4>Where this answer came from, with no personal data shown</h4>
      <div class="result-summary">
        <div class="summary-item"><span>Registry source</span><strong>${escapeHtml(source.registry || source.registry_id || "civil")}</strong></div>
        <div class="summary-item"><span>Dataset</span><strong>${escapeHtml(source.dataset || source.dataset_id || "civil_registry")}</strong></div>
        <div class="summary-item"><span>Entity</span><strong>${escapeHtml(source.entity || source.entity_id || "civil_person")}</strong></div>
        <div class="summary-item"><span>Lookup field</span><strong>${escapeHtml(source.lookup_field || source.subject_field || "national_id")}</strong></div>
        <div class="summary-item"><span>Required scope</span><strong>${escapeHtml(source.required_scope || "not shown")}</strong></div>
        <div class="summary-item"><span>Source connector type</span><strong>${escapeHtml(source.connector_type || source.connector || "relay")}</strong></div>
      </div>
      <p class="meta">No source row values are shown in this panel.</p>
    </div>
  `;
}

function renderResult() {
  const mini = minimization();
  const claim = selectedClaimSummary();
  const answer = answerState();
  const minimizationDetails = {
    relay_fields_used: mini.relayFieldsUsed,
    returned_to_relying_service: mini.returnedToService,
    raw_row_returned: mini.rawRowReturned
  };
  return `
    <section class="explorer-result-panel" aria-live="polite">
      <h3>Claim result</h3>
      <div class="result-focus">
        <div class="answer-card">
          <h4>Answer</h4>
          <p class="answer-value ${answer.status === "problem" ? "problem" : ""}"><strong>${escapeHtml(answer.label)}</strong></p>
          ${answer.note ? `<p class="answer-note">${escapeHtml(answer.note)}</p>` : ""}
          <p class="meta">Claim: ${escapeHtml(labelFor(claim, state.selectedClaim))}</p>
          <p class="meta">What to return: ${escapeHtml(state.disclosure === "predicate" ? "just yes/no" : state.disclosure)}</p>
          <p class="privacy-note">No source row returned.</p>
        </div>
      </div>
      <details class="secondary-details">
        <summary>Source and technical details</summary>
        <div class="details-body">
          ${renderSourceInfo()}
          ${disclosure("Minimization details", minimizationDetails, "Copy minimization")}
          ${disclosure("Request details", sourceValue(state.evaluation, "request") || evaluationPayload(), "Copy request")}
          ${disclosure("Response details", sourceValue(state.evaluation, "response") || {answer: answerValue(), raw_row_returned: mini.rawRowReturned}, "Copy response")}
          ${disclosure("Raw JSON", state.evaluation, "Copy JSON")}
          ${disclosure("Curl", curlValue(state.evaluation), "Copy curl")}
        </div>
      </details>
    </section>
  `;
}

function renderReady(root) {
  const selected = selectedServiceSummary();
  root.innerHTML = `
    ${comparisonPanel()}
    <section class="explorer-panel">
      <div class="explorer-selector">
        <div class="field-control">
          <label for="service-select">Claim service</label>
          <select id="service-select">${serviceOptions()}</select>
        </div>
        <div class="explorer-link-row"><a class="button" href="/registry-explorer">Compare with Relay data</a></div>
        <details class="technical-summary">
          <summary>API details</summary>
          <div class="details-body">
            <span class="pill ok">same-origin API</span>
            <div>
              <div class="label">Base URL</div>
              <div class="source-line">${escapeHtml(selected.base_url || selected.url || "hidden behind /api/explorer/")}</div>
            </div>
          </div>
        </details>
      </div>
      <div class="explorer-workbench">
        ${renderClaimQuestion()}
        ${renderResult()}
        ${renderControls()}
      </div>
    </section>
  `;
}

async function loadClaimsExample(root) {
  renderLoading(root);
  const catalog = await explorerFetch("/api/explorer/claims.json");
  state.catalog = normalizeItems(catalog, ["claim_services", "services", "items"]);
  await loadSelectedService(root, CIVIL_NOTARY_DEFAULT.serviceId);
}

async function loadSelectedService(root, serviceId) {
  state.selectedService = serviceId;
  state.metadata = await explorerFetch(`/api/explorer/claims/${encodeURIComponent(state.selectedService)}/metadata.json`);
  const selected = selectedServiceSummary();
  state.selectedClaim = selected.default_claim || claimItems()[0]?.id || CIVIL_NOTARY_DEFAULT.claimId;
  state.subjectScheme = selected.default_identifier_scheme || CIVIL_NOTARY_DEFAULT.subjectScheme;
  state.subjectValue = selected.default_subject || CIVIL_NOTARY_DEFAULT.subjectValue;
  state.purpose = selected.default_purpose || CIVIL_NOTARY_DEFAULT.purpose;
  const claim = selectedClaimSummary();
  state.disclosure = claim.default_disclosure || CIVIL_NOTARY_DEFAULT.disclosure;
  state.format = normalizeCollection(claim.formats)[0] || CIVIL_NOTARY_DEFAULT.format;
  state.evaluation = await explorerFetch(endpoint(`/api/explorer/claims/${encodeURIComponent(state.selectedService)}/evaluate.json`), {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      claim_id: state.selectedClaim,
      subject: {
        scheme: state.subjectScheme,
        value: state.subjectValue
      },
      disclosure: state.disclosure,
      format: state.format,
      purpose: state.purpose
    })
  });
  renderReady(root);
}

async function evaluateClaim(root) {
  const button = root.querySelector("[data-evaluate]");
  if (button) button.disabled = true;
  try {
    state.selectedClaim = selectedClaim();
    state.subjectScheme = selectedScheme();
    state.subjectValue = selectedSubject();
    state.disclosure = selectedDisclosure();
    state.format = selectedFormat();
    state.purpose = selectedPurpose();
    state.evaluation = await explorerFetch(endpoint(`/api/explorer/claims/${encodeURIComponent(state.selectedService)}/evaluate.json`), {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(evaluationPayload())
    });
    renderReady(root);
  } catch (error) {
    const result = root.querySelector(".explorer-result-panel");
    if (result) {
      result.innerHTML = `<section class="unavailable-card"><h3>Evaluation unavailable</h3><p>${escapeHtml(error.message)}</p><div class="actions"><button class="primary" type="button" data-evaluate>Retry evaluation</button></div></section>`;
    }
  } finally {
    const nextButton = root.querySelector("[data-evaluate]");
    if (nextButton) nextButton.disabled = false;
  }
}

async function evaluateSelectedClaim(root) {
  state.evaluation = await explorerFetch(endpoint(`/api/explorer/claims/${encodeURIComponent(state.selectedService)}/evaluate.json`), {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(evaluationStatePayload())
  });
  renderReady(root);
}

function wire(root) {
  document.addEventListener("click", async (event) => {
    const target = event.target instanceof Element ? event.target : null;
    const retry = target?.closest("[data-retry]");
    const run = target?.closest("[data-evaluate]");
    const copy = target?.closest("[data-copy]");
    if (retry) loadClaimsExample(root).catch((error) => renderUnavailable(root, error));
    if (run) evaluateClaim(root);
    if (copy) {
      const label = copy.textContent;
      try {
        await navigator.clipboard.writeText(copy.getAttribute("data-copy") || "");
        copy.textContent = "Copied";
      } catch (_error) {
        copy.textContent = "Copy failed";
      }
      setTimeout(() => { copy.textContent = label || "Copy"; }, 1200);
    }
  });
  document.addEventListener("change", async (event) => {
    const serviceSelect = event.target instanceof Element ? event.target.closest("#service-select") : null;
    if (serviceSelect) {
      await loadSelectedService(root, serviceSelect.value).catch((error) => renderUnavailable(root, error));
      return;
    }
    const claimSelect = event.target instanceof Element ? event.target.closest("#claim-select") : null;
    if (!claimSelect) return;
    state.selectedClaim = claimSelect.value;
    const claim = selectedClaimSummary();
    state.disclosure = claim.default_disclosure || state.disclosure;
    state.format = normalizeCollection(claim.formats)[0] || state.format;
    await evaluateSelectedClaim(root).catch((error) => renderUnavailable(root, error));
  });
}

async function start() {
  const root = ensureShell();
  wire(root);
  try {
    await loadClaimsExample(root);
  } catch (error) {
    renderUnavailable(root, error);
  }
}

window.ClaimsExplorer = {start, loadClaimsExample, evaluateClaim};
start();
