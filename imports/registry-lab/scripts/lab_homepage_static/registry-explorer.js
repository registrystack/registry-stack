const ORIENTING_SENTENCE = "Relay shows what an authorized system can read. Notary returns only the fact a service asked for.";
const CIVIL_DEFAULT = {
  registryId: "civil",
  datasetId: "civil_registry",
  entityId: "civil_person",
  limit: 10,
  purpose: ["https:", "//demo.example.gov/purpose/decentralized-evidence-demo"].join("")
};

const text = (value) => value == null ? "" : String(value);
const byId = (id) => document.getElementById(id);

const state = {
  catalog: [],
  metadata: null,
  schema: null,
  records: null,
  selectedRegistry: CIVIL_DEFAULT.registryId,
  selectedDataset: CIVIL_DEFAULT.datasetId,
  selectedEntity: CIVIL_DEFAULT.entityId,
  limit: CIVIL_DEFAULT.limit,
  purpose: CIVIL_DEFAULT.purpose
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

function labelFor(item, fallback) {
  return item?.label || item?.name || item?.title || item?.id || fallback;
}

function endpoint(path, params = {}) {
  const url = new URL(path, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, value);
  }
  return `${url.pathname}${url.search}`;
}

function ensureShell() {
  const existing = byId("registry-explorer-root") || byId("registry-explorer") || byId("explorer") || byId("explorer-root");
  const root = existing || document.createElement("section");
  root.id = root.id || "registry-explorer";
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
    <section class="loading-card"><strong>Loading the Civil registry example.</strong><p class="meta">The first screen will show a bounded row-reader result. Request details stay collapsed until needed.</p></section>
  `;
}

function renderUnavailable(root, error) {
  root.innerHTML = `
    ${comparisonPanel()}
    <section class="unavailable-card" aria-live="polite">
      <h2>Registry Explorer unavailable</h2>
      <p>The Civil first-load example could not be loaded from the same-origin explorer API.</p>
      <p class="meta">${escapeHtml(error?.message || "Reload or retry when the lab service is ready.")}</p>
      <div class="actions"><button class="primary" type="button" data-retry>Retry</button></div>
    </section>
  `;
}

function comparisonPanel() {
  return `
    <section class="comparison-panel compact-comparison">
      <div>
        <p class="eyebrow">Relay row access</p>
        <h2>Browse the records a row-reader can inspect.</h2>
        <p class="meta">Use this to see the wider Relay view before comparing it with the narrower Claims Explorer answer.</p>
      </div>
    </section>
  `;
}

function selectedDataset() {
  return byId("dataset-select")?.value || state.selectedDataset || CIVIL_DEFAULT.datasetId;
}

function selectedEntity() {
  return byId("entity-select")?.value || state.selectedEntity || CIVIL_DEFAULT.entityId;
}

function selectedLimit() {
  const parsed = Number.parseInt(byId("limit-input")?.value || String(state.limit || CIVIL_DEFAULT.limit), 10);
  return Number.isFinite(parsed) ? Math.min(Math.max(parsed, 1), 10) : CIVIL_DEFAULT.limit;
}

function selectedPurpose() {
  return byId("purpose-input")?.value || state.purpose || CIVIL_DEFAULT.purpose;
}

function selectedFilters() {
  const field = byId("filter-field")?.value || "";
  const op = byId("filter-op")?.value || "eq";
  const value = (byId("filter-value")?.value || "").trim();
  return field && value ? [{field, op, value}] : [];
}

function filterQueryParams(filters) {
  const params = {};
  for (const filter of filters) {
    const suffix = filter.op === "eq" ? "" : `.${filter.op}`;
    params[`filter.${filter.field}${suffix}`] = filter.value;
  }
  return params;
}

function registryOptions() {
  const items = state.catalog.length ? state.catalog : [{id: "civil", label: "Civil"}];
  return items.map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === state.selectedRegistry ? "selected" : ""}>${escapeHtml(labelFor(item, item.id))}</option>`).join("");
}

function metadataDatasets() {
  const raw = state.metadata?.datasets || state.metadata?.registry?.datasets || [];
  const items = normalizeCollection(raw);
  if (items.length) return items;
  return [{id: CIVIL_DEFAULT.datasetId, label: "Civil registry"}];
}

function metadataEntities() {
  const datasetId = state.selectedDataset || selectedDataset();
  const dataset = metadataDatasets().find((item) => item.id === datasetId) || {};
  const raw = dataset.entities || state.metadata?.entities || [];
  const items = normalizeCollection(raw);
  if (items.length) return items;
  return [{id: CIVIL_DEFAULT.entityId, label: "Civil person"}];
}

function defaultDatasetId() {
  const selected = state.catalog.find((item) => item.id === state.selectedRegistry) || state.metadata?.registry || {};
  return selected.default_dataset || metadataDatasets()[0]?.id || CIVIL_DEFAULT.datasetId;
}

function defaultEntityId(datasetId) {
  const selected = state.catalog.find((item) => item.id === state.selectedRegistry) || state.metadata?.registry || {};
  const dataset = metadataDatasets().find((item) => item.id === datasetId) || {};
  return selected.default_entity || normalizeCollection(dataset.entities)[0]?.id || CIVIL_DEFAULT.entityId;
}

function selectedRegistrySummary() {
  return state.catalog.find((item) => item.id === state.selectedRegistry) || state.metadata?.registry || {};
}

function schemaFields() {
  const raw = state.schema?.fields || state.schema?.entity?.fields || state.metadata?.fields || [];
  if (Array.isArray(raw) && raw.length) return raw;
  const firstRow = recordRows()[0] || {};
  return Object.keys(firstRow).map((name) => ({name, id: name, type: typeof firstRow[name]}));
}

function filterableFields() {
  return schemaFields().filter((field) => normalizeCollection(field.filter_ops || field.operators || field.allowed_operators || field.filterable_operators).length);
}

function recordRows() {
  const body = state.records || {};
  if (Array.isArray(body)) return body;
  for (const key of ["records", "rows", "data", "items"]) {
    if (Array.isArray(body[key])) return body[key];
  }
  return [];
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

function renderTable(rows) {
  if (!rows.length) return `<div class="source-note">No records returned.</div>`;
  const columns = Object.keys(rows[0]).slice(0, 12);
  return `<div class="table-wrap"><table>
    <thead><tr>${columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((row) => `<tr>${columns.map((column) => `<td>${escapeHtml(row[column])}</td>`).join("")}</tr>`).join("")}</tbody>
  </table></div>`;
}

function renderFieldList(fields) {
  if (!fields.length) return `<div class="source-note">No field metadata returned.</div>`;
  return `<div class="field-list">${fields.map((field) => {
    const name = field.name || field.id || field.field || "";
    const operators = field.operators || field.allowed_operators || field.filterable_operators || [];
    const sensitive = field.sensitive || field.is_sensitive ? "sensitive" : "";
    return `<div class="field-row">
      <strong>${escapeHtml(name)}</strong>
      <span>${escapeHtml(field.type || field.kind || "field")}</span>
      <span>${escapeHtml(Array.isArray(operators) ? operators.join(", ") : operators)}</span>
      <span>${escapeHtml(sensitive)}</span>
    </div>`;
  }).join("")}</div>`;
}

function renderControls() {
  const datasets = metadataDatasets();
  const entities = metadataEntities();
  const datasetId = state.selectedDataset || defaultDatasetId();
  const entityId = state.selectedEntity || defaultEntityId(datasetId);
  const filters = filterableFields();
  const defaultFilter = filters[0] || {};
  const operators = normalizeCollection(defaultFilter.filter_ops || defaultFilter.operators || defaultFilter.allowed_operators || defaultFilter.filterable_operators);
  return `
    <section class="registry-query-panel">
      <div class="field-control">
        <label for="dataset-select">Dataset</label>
        <select id="dataset-select">${datasets.map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === datasetId ? "selected" : ""}>${escapeHtml(labelFor(item, item.id))}</option>`).join("")}</select>
      </div>
      <div class="field-control">
        <label for="entity-select">Entity</label>
        <select id="entity-select">${entities.map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === entityId ? "selected" : ""}>${escapeHtml(labelFor(item, item.id))}</option>`).join("")}</select>
      </div>
      <div class="field-control compact-field">
        <label for="limit-input">Limit</label>
        <input id="limit-input" type="number" min="1" max="10" value="${escapeHtml(state.limit || CIVIL_DEFAULT.limit)}">
      </div>
      <div class="actions"><button class="primary" type="button" data-run-query>Run query</button></div>
      <details class="secondary-details query-refinement">
        <summary>Filter and purpose</summary>
        <div class="details-body">
          <div class="filter-grid">
            <select id="filter-field" aria-label="Filter field">${filters.map((field) => {
              const name = field.name || field.id || field.field || "";
              const fieldOps = normalizeCollection(field.filter_ops || field.operators || field.allowed_operators || field.filterable_operators).join(",");
              return `<option value="${escapeHtml(name)}" data-operators="${escapeHtml(fieldOps)}">${escapeHtml(name)}</option>`;
            }).join("")}</select>
            <select id="filter-op" aria-label="Filter operator">${(operators.length ? operators : ["eq"]).map((op) => `<option value="${escapeHtml(op)}">${escapeHtml(op === "eq" ? "equals" : op)}</option>`).join("")}</select>
            <input id="filter-value" aria-label="Filter value" placeholder="optional value">
          </div>
          <div class="field-control">
            <label for="purpose-input">Purpose for this request</label>
            <input id="purpose-input" value="${escapeHtml(state.purpose || CIVIL_DEFAULT.purpose)}">
          </div>
        </div>
      </details>
    </section>
  `;
}

function renderResult() {
  const fields = schemaFields();
  const rows = recordRows();
  const status = state.records?.status || state.records?.http_status || "available";
  const dataset = state.records?.dataset || metadataDatasets().find((item) => item.id === state.selectedDataset) || {};
  const entity = state.records?.entity || metadataEntities().find((item) => item.id === state.selectedEntity) || {};
  const actingAs = state.records?.summary?.acting_as || "a row-reader service allowed to inspect records";
  const filters = state.records?.validated?.filters || [];
  const activeFilter = filters.length ? `${filters[0].field} ${filters[0].op === "eq" ? "equals" : filters[0].op} ${filters[0].value}` : "";
  const context = {
    status,
    records_returned: rows.length,
    fields_visible: fields.length || (rows[0] ? Object.keys(rows[0]).length : 0),
    acting_as: actingAs,
    purpose: selectedPurpose(),
    filters
  };
  return `
    <section class="explorer-result-panel" aria-live="polite">
      <div class="result-heading">
        <div>
          <h3>Records</h3>
          <p class="meta">Showing ${escapeHtml(rows.length)} ${escapeHtml(labelFor(entity, state.selectedEntity))} record${rows.length === 1 ? "" : "s"} from ${escapeHtml(labelFor(dataset, state.selectedDataset))}.</p>
        </div>
        <div class="status-strip">
          <span class="pill ok">${escapeHtml(status)}</span>
          <span class="privacy-note">${escapeHtml(context.fields_visible)} fields visible</span>
        </div>
      </div>
      ${activeFilter ? `<p class="active-filter">Filter: ${escapeHtml(activeFilter)}</p>` : ""}
      ${renderTable(rows)}
      <details class="secondary-details">
        <summary>Schema and technical details</summary>
        <div class="details-body">
          ${disclosure("Query context", context, "Copy context")}
          <div>
            <h4>Field list</h4>
            ${renderFieldList(fields)}
          </div>
          ${disclosure("Request details", sourceValue(state.records, "request") || {dataset: selectedDataset(), entity: selectedEntity(), limit: selectedLimit(), purpose: selectedPurpose()}, "Copy request")}
          ${disclosure("Response details", sourceValue(state.records, "response") || {records_returned: rows.length, fields_visible: fields.length}, "Copy response")}
          ${disclosure("Raw JSON", state.records, "Copy JSON")}
          ${disclosure("Curl", curlValue(state.records), "Copy curl")}
        </div>
      </details>
    </section>
  `;
}

function renderReady(root) {
  const selected = selectedRegistrySummary();
  root.innerHTML = `
    ${comparisonPanel()}
    <section class="explorer-panel">
      <div class="explorer-selector">
        <div class="field-control">
          <label for="registry-select">Registry</label>
          <select id="registry-select">${registryOptions()}</select>
        </div>
        <div class="explorer-link-row"><a class="button" href="/claims-explorer">View related claims</a></div>
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
        ${renderControls()}
        ${renderResult()}
      </div>
    </section>
  `;
}

function updateFilterOperators(root) {
  const fieldSelect = root.querySelector("#filter-field");
  const operatorSelect = root.querySelector("#filter-op");
  if (!fieldSelect || !operatorSelect) return;
  const selected = fieldSelect.selectedOptions?.[0];
  const operators = (selected?.dataset?.operators || "eq").split(",").filter(Boolean);
  operatorSelect.innerHTML = operators.map((op) => `<option value="${escapeHtml(op)}">${escapeHtml(op === "eq" ? "equals" : op)}</option>`).join("");
}

async function loadRegistryExample(root) {
  renderLoading(root);
  const catalog = await explorerFetch("/api/explorer/registries.json");
  state.catalog = normalizeItems(catalog, ["registries", "items", "services"]);
  await loadSelectedRegistry(root, CIVIL_DEFAULT.registryId);
}

async function loadSelectedRegistry(root, registryId) {
  state.selectedRegistry = registryId;
  state.metadata = await explorerFetch(`/api/explorer/registries/${encodeURIComponent(state.selectedRegistry)}/metadata.json`);
  const selected = selectedRegistrySummary();
  state.selectedDataset = selected.default_dataset || defaultDatasetId();
  state.selectedEntity = selected.default_entity || defaultEntityId(state.selectedDataset);
  state.limit = selected.default_limit || CIVIL_DEFAULT.limit;
  state.purpose = selected.purpose || CIVIL_DEFAULT.purpose;
  state.schema = await explorerFetch(endpoint(`/api/explorer/registries/${encodeURIComponent(state.selectedRegistry)}/entity-schema.json`, {
    dataset: state.selectedDataset,
    entity: state.selectedEntity
  }));
  state.records = await explorerFetch(endpoint(`/api/explorer/registries/${encodeURIComponent(state.selectedRegistry)}/records.json`, {
    dataset: state.selectedDataset,
    entity: state.selectedEntity,
    limit: state.limit
  }));
  renderReady(root);
}

async function runQuery(root) {
  const button = root.querySelector("[data-run-query]");
  if (button) button.disabled = true;
  try {
    state.selectedDataset = selectedDataset();
    state.selectedEntity = selectedEntity();
    state.limit = selectedLimit();
    state.purpose = selectedPurpose();
    const filters = selectedFilters();
    state.schema = await explorerFetch(endpoint(`/api/explorer/registries/${encodeURIComponent(state.selectedRegistry)}/entity-schema.json`, {
      dataset: state.selectedDataset,
      entity: state.selectedEntity
    }));
    state.records = await explorerFetch(endpoint(`/api/explorer/registries/${encodeURIComponent(state.selectedRegistry)}/records.json`, {
      dataset: state.selectedDataset,
      entity: state.selectedEntity,
      limit: state.limit,
      purpose: state.purpose,
      ...filterQueryParams(filters)
    }));
    renderReady(root);
  } catch (error) {
    const result = root.querySelector(".explorer-result-panel");
    if (result) {
      result.innerHTML = `<section class="unavailable-card"><h3>Query unavailable</h3><p>${escapeHtml(error.message)}</p><div class="actions"><button class="primary" type="button" data-run-query>Retry query</button></div></section>`;
    }
  } finally {
    const nextButton = root.querySelector("[data-run-query]");
    if (nextButton) nextButton.disabled = false;
  }
}

function wire(root) {
  document.addEventListener("click", async (event) => {
    const target = event.target instanceof Element ? event.target : null;
    const retry = target?.closest("[data-retry]");
    const run = target?.closest("[data-run-query]");
    const copy = target?.closest("[data-copy]");
    if (retry) loadRegistryExample(root).catch((error) => renderUnavailable(root, error));
    if (run) runQuery(root);
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
    const select = event.target instanceof Element ? event.target.closest("#registry-select") : null;
    if (select) {
      await loadSelectedRegistry(root, select.value).catch((error) => renderUnavailable(root, error));
      return;
    }
    const filterField = event.target instanceof Element ? event.target.closest("#filter-field") : null;
    if (filterField) updateFilterOperators(root);
  });
}

async function start() {
  const root = ensureShell();
  wire(root);
  try {
    await loadRegistryExample(root);
  } catch (error) {
    renderUnavailable(root, error);
  }
}

window.RegistryExplorer = {start, loadRegistryExample, runQuery};
start();
