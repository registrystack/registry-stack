const ORIENTING_SENTENCE = "This Notary-only example evaluates an applicant declaration without consulting a registry.";
const SELF_ATTESTED_DEFAULT = {
  serviceId: "self-attested-notary",
  claimId: "applicant-declaration",
  subjectScheme: "applicant_id",
  subjectValue: "demo-applicant",
  disclosure: "predicate",
  format: "application/vnd.registry-notary.claim-result+json",
  purpose: "application-processing"
};

const text = (value) => value == null ? "" : String(value);
const byId = (id) => document.getElementById(id);

const state = {
  catalog: [],
  metadata: null,
  evaluation: null,
  selectedService: SELF_ATTESTED_DEFAULT.serviceId,
  selectedClaim: SELF_ATTESTED_DEFAULT.claimId,
  subjectScheme: SELF_ATTESTED_DEFAULT.subjectScheme,
  subjectValue: SELF_ATTESTED_DEFAULT.subjectValue,
  targetGroupKey: "",
  targetValues: {},
  disclosure: SELF_ATTESTED_DEFAULT.disclosure,
  format: SELF_ATTESTED_DEFAULT.format,
  purpose: SELF_ATTESTED_DEFAULT.purpose
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
    const message = (body.error && body.error.message) || body.error || body.message || `HTTP ${response.status}`;
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
      <strong>Loading the self-attested Notary example.</strong>
      <p class="meta">The first screen shows the declaration result. Request details stay collapsed until needed.</p>
    </section>
  `;
}

function renderUnavailable(root, error) {
  root.innerHTML = `
    ${comparisonPanel()}
    <section class="unavailable-card" aria-live="polite">
      <h2>Claims Explorer unavailable</h2>
      <p>The self-attested Notary evaluation could not be loaded from the same-origin explorer API.</p>
      <p class="meta">${escapeHtml(error?.message || "Reload or retry when the lab service is ready.")}</p>
      <div class="actions"><button class="primary" type="button" data-retry>Retry</button></div>
    </section>
  `;
}

function comparisonPanel() {
  return `
    <section class="comparison-panel compact-comparison">
      <div>
        <p class="eyebrow">Notary-only</p>
        <h2>The applicant supplies the declaration directly.</h2>
        <p class="meta">No Relay or registry source is part of this evaluation.</p>
      </div>
    </section>
  `;
}

function claimItems() {
  const raw = state.metadata?.claim_service?.claims || state.metadata?.claim_service?.data || state.metadata?.claims || state.metadata?.data || state.metadata?.service?.claims || state.metadata?.service?.data || [];
  const items = normalizeCollection(raw);
  if (items.length) return items;
  return [{id: SELF_ATTESTED_DEFAULT.claimId, label: "Applicant declaration"}];
}

function serviceOptions() {
  const items = state.catalog.length ? state.catalog : [{id: "self-attested-notary", label: "Self-attested Notary"}];
  return items.map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === state.selectedService ? "selected" : ""}>${escapeHtml(labelFor(item, item.id))}</option>`).join("");
}

function selectedClaim() {
  return byId("claim-select")?.value || state.selectedClaim || SELF_ATTESTED_DEFAULT.claimId;
}

function selectedScheme() {
  return byId("scheme-input")?.value || byId("scheme-select")?.value || state.subjectScheme || SELF_ATTESTED_DEFAULT.subjectScheme;
}

function selectedSubject() {
  return byId("subject-input")?.value || state.subjectValue || SELF_ATTESTED_DEFAULT.subjectValue;
}

function targetInputMethods(claim = selectedClaimSummary()) {
  return normalizeCollection(claim?.target_inputs);
}

function targetInputGroups(claim = selectedClaimSummary()) {
  const groups = [];
  targetInputMethods(claim).forEach((method, methodIndex) => {
    normalizeCollection(method?.groups).forEach((group, groupIndex) => {
      const inputs = normalizeCollection(group?.inputs).filter((item) => item && typeof item === "object");
      if (!inputs.length) return;
      groups.push({
        key: `${method.method || methodIndex}:${groupIndex}`,
        method: method.method || "",
        targetType: method.target_type || claim.subject_type || "Person",
        label: targetGroupLabel(group, inputs),
        inputs
      });
    });
  });
  return groups;
}

function targetGroupLabel(group, inputs) {
  if (group?.label) return group.label;
  return inputs.map((input) => input.label || labelFromName(input.name || input.path || input.kind || "Target input")).join(" + ");
}

function labelFromName(value) {
  const words = text(value).replace(/^target\.(identifiers|attributes)\./, "").split(/[_\s.-]+/).filter(Boolean);
  if (!words.length) return text(value);
  return words.map((word) => `${word.charAt(0).toUpperCase()}${word.slice(1)}`).join(" ");
}

function selectedTargetGroup() {
  const groups = targetInputGroups();
  if (!groups.length) return null;
  const key = byId("target-group-select")?.value || state.targetGroupKey || groups[0].key;
  return groups.find((group) => group.key === key) || groups[0];
}

function targetValueKey(input) {
  return input.path || `${input.kind || "input"}:${input.name || ""}`;
}

function defaultTargetValue(input, selected = selectedServiceSummary(), claim = selectedClaimSummary()) {
  if (input.default_value != null) return text(input.default_value);
  const name = text(input.name);
  const scheme = claim.default_identifier_scheme || selected.default_identifier_scheme || SELF_ATTESTED_DEFAULT.subjectScheme;
  if (input.kind === "identifier" && name === scheme) {
    return claim.default_subject || selected.default_subject || SELF_ATTESTED_DEFAULT.subjectValue;
  }
  return "";
}

function resetTargetValues(claim = selectedClaimSummary()) {
  state.targetValues = {};
  const selected = selectedServiceSummary();
  targetInputGroups(claim).forEach((group) => {
    group.inputs.forEach((input) => {
      state.targetValues[targetValueKey(input)] = defaultTargetValue(input, selected, claim);
    });
  });
  state.targetGroupKey = targetInputGroups(claim)[0]?.key || "";
}

function readTargetValue(input, index) {
  const key = targetValueKey(input);
  return state.targetValues[key] ?? defaultTargetValue(input);
}

function captureTargetValues() {
  const group = selectedTargetGroup();
  if (!group) return;
  state.targetGroupKey = group.key;
  group.inputs.forEach((input, index) => {
    state.targetValues[targetValueKey(input)] = readTargetValue(input, index);
  });
}

function targetFromInputs(group) {
  const target = {type: group.targetType || "Person"};
  const identifiers = [];
  const attributes = {};
  group.inputs.forEach((input, index) => {
    const value = readTargetValue(input, index);
    if (input.kind === "id") target.id = value;
    if (input.kind === "identifier") identifiers.push({scheme: input.name || "id", value});
    if (input.kind === "attribute") attributes[input.name || targetValueKey(input)] = value;
  });
  if (identifiers.length) target.identifiers = identifiers;
  if (Object.keys(attributes).length) target.attributes = attributes;
  return target;
}

function selectedDisclosure() {
  return byId("disclosure-select")?.value || state.disclosure || SELF_ATTESTED_DEFAULT.disclosure;
}

function selectedFormat() {
  return byId("format-select")?.value || state.format || SELF_ATTESTED_DEFAULT.format;
}

function selectedPurpose() {
  return byId("purpose-input")?.value || state.purpose || SELF_ATTESTED_DEFAULT.purpose;
}

function evaluationPayload() {
  const group = selectedTargetGroup();
  const payload = {
    claim_id: selectedClaim(),
    disclosure: selectedDisclosure(),
    format: selectedFormat(),
    purpose: selectedPurpose()
  };
  if (group) {
    payload.target = targetFromInputs(group);
  } else {
    payload.subject = {
      scheme: selectedScheme(),
      value: selectedSubject()
    };
  }
  return payload;
}

function evaluationStatePayload() {
  const group = selectedTargetGroup();
  const payload = {
    claim_id: state.selectedClaim,
    disclosure: state.disclosure,
    format: state.format,
    purpose: state.purpose
  };
  if (group) {
    payload.target = targetFromInputs(group);
  } else {
    payload.subject = {
      scheme: state.subjectScheme,
      value: state.subjectValue
    };
  }
  return payload;
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
  const claim = selectedClaimSummary();
  const groups = targetInputGroups(claim);
  return `
    <section class="claim-question-panel">
      <div class="field-control">
        <label for="claim-select">Claim</label>
        <select id="claim-select">${claims.map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === state.selectedClaim ? "selected" : ""}>${escapeHtml(labelFor(item, item.id))}</option>`).join("")}</select>
      </div>
      ${groups.length ? renderTargetInputControls(groups) : renderLegacySubjectControls()}
      <div class="actions"><button class="primary" type="button" data-evaluate>Evaluate</button></div>
    </section>
  `;
}

function renderLegacySubjectControls() {
  return `
    <div class="field-control">
      <label for="scheme-input">Subject identifier scheme</label>
      <input id="scheme-input" value="${escapeHtml(state.subjectScheme || SELF_ATTESTED_DEFAULT.subjectScheme)}">
    </div>
    <div class="field-control">
      <label for="subject-input">Subject identifier</label>
      <input id="subject-input" value="${escapeHtml(state.subjectValue || SELF_ATTESTED_DEFAULT.subjectValue)}">
    </div>
  `;
}

function renderTargetInputControls(groups) {
  const group = selectedTargetGroup() || groups[0];
  const groupSelect = groups.length > 1 ? `
    <div class="field-control">
      <label for="target-group-select">Input mode</label>
      <select id="target-group-select">${groups.map((item) => `<option value="${escapeHtml(item.key)}" ${item.key === group.key ? "selected" : ""}>${escapeHtml(item.label)}</option>`).join("")}</select>
    </div>
  ` : "";
  return `
    ${groupSelect}
    ${group.inputs.map((input, index) => `
      <div class="field-control">
        <label for="target-input-${index}">${escapeHtml(input.label || labelFromName(input.name || input.path || "Target input"))}</label>
        <input id="target-input-${index}" data-target-key="${escapeHtml(targetValueKey(input))}" value="${escapeHtml(readTargetValue(input, index))}">
      </div>
    `).join("")}
  `;
}

function renderControls() {
  const claim = selectedClaimSummary();
  const disclosures = normalizeCollection(claim.allowed_disclosures).length ? normalizeCollection(claim.allowed_disclosures) : [state.disclosure || SELF_ATTESTED_DEFAULT.disclosure];
  const formats = normalizeCollection(claim.formats).length ? normalizeCollection(claim.formats) : [state.format || SELF_ATTESTED_DEFAULT.format];
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
          <input id="purpose-input" value="${escapeHtml(state.purpose || SELF_ATTESTED_DEFAULT.purpose)}">
        </div>
        <details>
          <summary>Refine query</summary>
          <div class="details-body">
            <p class="meta">The example uses a synthetic applicant identifier. It is not looked up in a registry.</p>
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
      <h4>How this answer was acquired</h4>
      <div class="result-summary">
        <div class="summary-item"><span>Acquisition path</span><strong>${escapeHtml(source.acquisition_path || "self_attested")}</strong></div>
        <div class="summary-item"><span>Evidence authority</span><strong>${escapeHtml(source.authority || "applicant")}</strong></div>
        <div class="summary-item"><span>Registry consulted</span><strong>${source.registry_consulted ? "Yes" : "No"}</strong></div>
      </div>
      <p class="meta">This topology has no source row or registry credential.</p>
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
  await loadSelectedService(root, SELF_ATTESTED_DEFAULT.serviceId);
}

async function loadSelectedService(root, serviceId) {
  state.selectedService = serviceId;
  state.metadata = await explorerFetch(`/api/explorer/claims/${encodeURIComponent(state.selectedService)}/metadata.json`);
  const selected = selectedServiceSummary();
  state.selectedClaim = selected.default_claim || claimItems()[0]?.id || SELF_ATTESTED_DEFAULT.claimId;
  state.subjectScheme = selected.default_identifier_scheme || SELF_ATTESTED_DEFAULT.subjectScheme;
  state.subjectValue = selected.default_subject || SELF_ATTESTED_DEFAULT.subjectValue;
  state.purpose = selected.default_purpose || SELF_ATTESTED_DEFAULT.purpose;
  const claim = selectedClaimSummary();
  state.purpose = claim.default_purpose || state.purpose;
  state.subjectScheme = claim.default_identifier_scheme || state.subjectScheme;
  state.subjectValue = claim.default_subject || state.subjectValue;
  resetTargetValues(claim);
  state.disclosure = claim.default_disclosure || SELF_ATTESTED_DEFAULT.disclosure;
  state.format = normalizeCollection(claim.formats)[0] || SELF_ATTESTED_DEFAULT.format;
  state.evaluation = await explorerFetch(endpoint(`/api/explorer/claims/${encodeURIComponent(state.selectedService)}/evaluate.json`), {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(evaluationStatePayload())
  });
  renderReady(root);
}

async function evaluateClaim(root) {
  const button = root.querySelector("[data-evaluate]");
  if (button) button.disabled = true;
  try {
    state.selectedClaim = selectedClaim();
    captureTargetValues();
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
  root.addEventListener("click", async (event) => {
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
  root.addEventListener("change", async (event) => {
    const serviceSelect = event.target instanceof Element ? event.target.closest("#service-select") : null;
    if (serviceSelect) {
      await loadSelectedService(root, serviceSelect.value).catch((error) => renderUnavailable(root, error));
      return;
    }
    const claimSelect = event.target instanceof Element ? event.target.closest("#claim-select") : null;
    const targetGroupSelect = event.target instanceof Element ? event.target.closest("#target-group-select") : null;
    if (targetGroupSelect) {
      state.targetGroupKey = targetGroupSelect.value;
      renderReady(root);
      return;
    }
    if (!claimSelect) return;
    state.selectedClaim = claimSelect.value;
    const claim = selectedClaimSummary();
    state.subjectScheme = claim.default_identifier_scheme || selectedServiceSummary().default_identifier_scheme || state.subjectScheme;
    state.subjectValue = claim.default_subject || selectedServiceSummary().default_subject || state.subjectValue;
    state.purpose = claim.default_purpose || selectedServiceSummary().default_purpose || state.purpose;
    resetTargetValues(claim);
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
