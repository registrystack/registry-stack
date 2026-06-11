// The page template publishes the active scenario as a body data attribute
// instead of an inline <script>, so the strict script-src 'self' CSP holds.
const ACTIVE_SCENARIO = document.body.dataset.activeScenario || "";
const text = (value) => value == null ? "" : String(value);
const byId = (id) => document.getElementById(id);
const state = { completed: new Set(), story: null, runnable: true };

function escapeHtml(value) {
  return text(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  }[char]));
}

function prettyJson(value) {
  if (typeof value === "string") return value;
  return JSON.stringify(value ?? {}, null, 2);
}

function compactJson(value) {
  if (typeof value === "string") return value;
  return JSON.stringify(value ?? {});
}

function shellQuote(value) {
  return "'" + text(value).replace(/'/g, "'\"'\"'") + "'";
}

function curlCommand(value) {
  const method = value.method || "GET";
  const parts = ["curl", "-X", shellQuote(method), shellQuote(value.url || "")];
  for (const [name, headerValue] of Object.entries(value.headers || {})) {
    parts.push("-H", shellQuote(`${name}: ${headerValue}`));
  }
  if (value.body != null) parts.push("--data", shellQuote(compactJson(value.body)));
  return parts.join(" ");
}

function sourceRows(entries) {
  const rows = Object.entries(entries || {});
  if (!rows.length) return `<div class="source-note">No values captured.</div>`;
  return `<div class="source-table">${rows.map(([name, value]) => `
    <div class="source-row"><div class="source-label">${escapeHtml(name)}</div><div class="source-value">${escapeHtml(value)}</div></div>
  `).join("")}</div>`;
}

function sourceSection(title, content) {
  if (!content) return "";
  return `<div class="source-section"><h4>${escapeHtml(title)}</h4>${content}</div>`;
}

function renderRequestSource(value, isPreview) {
  const canCurl = value.method && value.method !== "SIMULATE" && value.url && !value.internal;
  const previewLabel = isPreview ? `<p class="preview-eyebrow">Request preview, not sent yet</p>` : "";
  return `<div class="source-card">
    ${previewLabel}
    ${canCurl ? `<div class="source-toolbar"><button class="copy-curl" type="button" data-copy-curl="${escapeHtml(curlCommand(value))}">Copy as curl</button></div>` : ""}
    ${value.internal ? `<div class="source-note">Internal lab call. It authenticates with a runtime-only credential that is never published, so there is no runnable curl for it.</div>` : ""}
    <div class="source-line">${escapeHtml(value.method || "")} ${escapeHtml(value.url || "")}</div>
    ${sourceSection("Headers", sourceRows(value.headers || {}))}
    ${value.body == null ? "" : sourceSection("Body", `<pre class="source-code">${escapeHtml(prettyJson(value.body))}</pre>`)}
  </div>`;
}

function renderResponseSource(value, reused) {
  const status = value.status == null ? "No HTTP status" : value.status;
  return `<div class="source-card">
    ${reused ? sourceSection("Reused from discovery", sourceRows(reused)) : ""}
    <div class="source-line">HTTP status ${escapeHtml(status)}</div>
    ${sourceSection("Headers", sourceRows(value.headers || {}))}
    ${sourceSection("Body", `<pre class="source-code">${escapeHtml(prettyJson(value.body))}</pre>`)}
    ${value.error ? sourceSection("Client error", `<div class="source-note">${escapeHtml(value.error)}</div>`) : ""}
  </div>`;
}

function sourceBlock(value, isPreview) {
  const source = value || {};
  if (source.note) return `<div class="source-card"><div class="source-note">${escapeHtml(source.note)}</div></div>`;
  if (source.evaluation && source.render) {
    return `
      <div class="source-section">
        <h4>Evaluation</h4>
        ${sourceBlock(source.evaluation, isPreview)}
      </div>
      <div class="source-section">
        <h4>Render</h4>
        ${sourceBlock(source.render, isPreview)}
      </div>
    `;
  }
  if (source.method && source.url) return renderRequestSource(source, isPreview);
  if (source.http) return renderResponseSource(source.http, source.reused_from_discovery);
  if ("status" in source || "headers" in source || "body" in source || "error" in source) return renderResponseSource(source);
  return `<pre class="source-code">${escapeHtml(prettyJson(source))}</pre>`;
}

function renderFacts(facts) {
  return (facts || []).map((fact) => `<div class="fact"><span>${escapeHtml(fact.label)}</span><strong>${escapeHtml(fact.value)}</strong></div>`).join("");
}

function renderChooser(items, defaultId) {
  // Order: default story first, then remaining hosted-runnable, then local-only walkthroughs.
  const sorted = [
    ...items.filter((item) => item.id === defaultId),
    ...items.filter((item) => item.id !== defaultId && item.runnable),
    ...items.filter((item) => item.id !== defaultId && !item.runnable),
  ];
  byId("chooser").innerHTML = `
    <p class="badge-explanation">
      <strong>Hosted</strong> stories run live in this lab from the browser.
      <strong>Local-only</strong> stories are read-only walkthroughs here and runnable via the GitHub repo locally.
    </p>
    <section class="chooser-grid" aria-label="Scenario chooser">
    ${sorted.map((item) => {
      const isDefault = item.id === defaultId;
      const cardClass = isDefault ? "scenario-card scenario-card--default" : "scenario-card";
      return `<article class="${cardClass}">
        ${isDefault ? `<span class="start-here-badge">Start here</span>` : ""}
        <span class="availability ${escapeHtml(item.availability)}">${escapeHtml(item.availability === "local-only" ? "Local only" : "Hosted")}</span>
        ${item.domain ? `<span class="domain-tag">${escapeHtml(item.domain)}</span>` : ""}
        <div><h2>${escapeHtml(item.title)}</h2><p>${escapeHtml(item.proves)}</p></div>
        ${item.availability_note ? `<p class="card-meta">${escapeHtml(item.availability_note)}</p>` : ""}
        <p class="card-meta">${escapeHtml(item.steps)} steps</p>
        <div class="actions"><a class="button primary" href="/scenarios/${encodeURIComponent(item.id)}">${item.runnable ? "Open story" : "Read the walkthrough"}</a></div>
      </article>`;
    }).join("")}
    </section>`;
}

function renderReuse(items) {
  if (!items || !items.length) return "";
  return `<div class="reuse-box"><h4>Reuses from the previous step</h4><div class="facts">${renderFacts(items)}</div></div>`;
}

function canRun(index) {
  if (index === 0) return true;
  return state.completed.has(state.story.steps[index - 1].id);
}

function statusLabel(status) {
  if (status === "done") return "Done";
  if (status === "running") return "Running";
  if (status === "denied_as_expected") return "Denied as expected";
  if (status === "needs_attention") return "Needs attention";
  if (status === "local_only") return "Local only";
  return "Not run";
}

function renderLocalOnlyBlock(story) {
  return `
    <div class="story-setup local-run">
      <div>
        <p class="eyebrow">Run this story on your machine</p>
        <p>The hosted lab does not run the services this story needs. Clone the repository, start the local lab profile, then open this page from your local homepage.</p>
        <pre>git clone https://github.com/jeremi/registry-lab</pre>
        ${story.availability_note ? `<p class="meta">${escapeHtml(story.availability_note)}</p>` : ""}
      </div>
    </div>
  `;
}

function renderStory(story, runnable) {
  state.story = story;
  state.runnable = runnable !== false;
  byId("chooser").innerHTML = "";
  byId("eyebrow").textContent = story.availability === "local-only" ? "Guided demo · local only" : "Guided demo";
  byId("title").textContent = story.title;
  byId("subtitle").textContent = story.intro;
  byId("story").innerHTML = `
    <section class="story-setup">
      <div>
        <p class="eyebrow">User story</p>
        <h2>${escapeHtml(story.short_title || story.title)}</h2>
        <p>${escapeHtml(story.proves)}</p>
        ${story.availability_note && state.runnable ? `<p class="meta">${escapeHtml(story.availability_note)}</p>` : ""}
      </div>
      <div class="setup-grid">
        <div class="setup-item"><span>Actor</span><strong>${escapeHtml(story.actor || "")}</strong></div>
        <div class="setup-item"><span>Subject</span><strong>${escapeHtml(story.subject.name)} · ${escapeHtml(story.subject.identifier)}</strong></div>
        <div class="setup-item"><span>Allowed</span><strong>${escapeHtml(story.boundary.allowed)}</strong></div>
        <div class="setup-item"><span>Not allowed</span><strong>${escapeHtml(story.boundary.not_allowed)}</strong></div>
      </div>
    </section>
    ${!state.runnable ? renderLocalOnlyBlock(story) : ""}
    <div class="actions story-actions"><button type="button" data-reset-story>Reset story</button></div>
    <section class="step-list">${story.steps.map(renderStep).join("")}</section>
    <section class="receipt" id="receipt"><div><p class="eyebrow">Final receipt</p><h2>What the demo proved</h2></div><div class="facts">${renderFacts(story.receipt || [])}</div></section>
  `;
}

const LOCAL_ONLY_NOTE = "Available when the story runs on the local lab profile.";

function renderStep(step, index) {
  if (!state.runnable) {
    return `<article class="step" id="step-${escapeHtml(step.id)}">
      <div class="step-head">
        <span class="step-number">${index + 1}</span>
        <div><h3>${escapeHtml(step.label)}</h3><p>${escapeHtml(step.prompt)}</p></div>
        <span class="status-pill local_only">Local only</span>
      </div>
      <div class="step-body">
        <div class="request-text"><strong>What this request will do:</strong> ${escapeHtml(step.request_summary)}</div>
        ${renderReuse(step.reuses || [])}
        <p class="meta">This step runs on the local lab profile.</p>
        <details><summary>Show technical request</summary><div data-request-source-for="${escapeHtml(step.id)}">${sourceBlock({ note: LOCAL_ONLY_NOTE })}</div></details>
        <details><summary>Show technical response</summary><div data-response-source-for="${escapeHtml(step.id)}">${sourceBlock({ note: LOCAL_ONLY_NOTE })}</div></details>
      </div>
    </article>`;
  }
  const runnable = canRun(index);
  const ariaDisabled = runnable ? "" : `aria-disabled="true"`;
  const lockedHint = !runnable && index > 0 ? `<p class="meta" data-locked-hint-for="${escapeHtml(step.id)}">Locked until step ${index} completes.</p>` : "";
  const preview = step.request_preview || {};
  const previewHtml = preview.method || (preview.evaluation && preview.render)
    ? sourceBlock(preview, true)
    : sourceBlock({ note: "Run this step to capture the request source." });
  return `<article class="step ${runnable ? "" : "locked"}" id="step-${escapeHtml(step.id)}">
    <div class="step-head">
      <span class="step-number">${index + 1}</span>
      <div><h3>${escapeHtml(step.label)}</h3><p>${escapeHtml(step.prompt)}</p></div>
      <span class="status-pill" role="status" data-status-for="${escapeHtml(step.id)}">Not run</span>
    </div>
    <div class="step-body">
      <div class="request-text"><strong>What this request will do:</strong> ${escapeHtml(step.request_summary)}</div>
      ${renderReuse(step.reuses || [])}
      ${lockedHint}
      <div class="actions"><button class="primary" type="button" data-run-step="${escapeHtml(step.id)}" data-run-label="${escapeHtml(step.button)}" ${ariaDisabled}>${escapeHtml(step.button)}</button></div>
      <div class="friendly-response" aria-live="polite" data-friendly-for="${escapeHtml(step.id)}"></div>
      <details><summary>Show technical request</summary><div data-request-source-for="${escapeHtml(step.id)}">${previewHtml}</div></details>
      <details><summary>Show technical response</summary><div data-response-source-for="${escapeHtml(step.id)}">${sourceBlock({ note: "Run this step to capture the response source." })}</div></details>
    </div>
  </article>`;
}

function wireStepButtons() {
  document.querySelectorAll("[data-run-step]").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.getAttribute("aria-disabled") === "true") return;
      runStep(button.getAttribute("data-run-step") || "", button);
    });
  });
}

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch (_error) {}
  }
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  textarea.setSelectionRange(0, textarea.value.length);
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("Copy failed");
}

function wireCurlCopyButtons() {
  document.addEventListener("click", async (event) => {
    const button = event.target instanceof Element ? event.target.closest("[data-copy-curl]") : null;
    if (!button) return;
    const label = button.textContent;
    try {
      await copyText(button.getAttribute("data-copy-curl") || "");
      button.textContent = "Copied";
    } catch (_error) {
      button.textContent = "Copy failed";
    }
    setTimeout(() => { button.textContent = label || "Copy as curl"; }, 1200);
  });
}

function updateStatus(stepId, status) {
  const node = document.querySelector(`[data-status-for="${CSS.escape(stepId)}"]`);
  if (!node) return;
  node.textContent = statusLabel(status);
  node.className = `status-pill ${status || ""}`;
}

function renderFriendly(stepId, friendly) {
  const node = document.querySelector(`[data-friendly-for="${CSS.escape(stepId)}"]`);
  if (!node) return;
  node.className = `friendly-response visible ${friendly.status === "needs_attention" ? "needs_attention" : ""}`;
  node.innerHTML = `<div><h4>${escapeHtml(friendly.title)}</h4><p>${escapeHtml(friendly.message)}</p></div><div class="facts">${renderFacts(friendly.facts || [])}</div>`;
}

function setSource(stepId, kind, value) {
  const node = document.querySelector(`[data-${kind}-source-for="${CSS.escape(stepId)}"]`);
  if (node) node.innerHTML = sourceBlock(value);
}

function progressKey(scenarioId) {
  return `lab-progress:${scenarioId}`;
}

function saveProgress(scenarioId) {
  const ids = Array.from(state.completed);
  try {
    sessionStorage.setItem(progressKey(scenarioId), JSON.stringify(ids));
  } catch (err) {
    console.warn("Progress will not survive a reload; sessionStorage is unavailable:", err);
  }
}

function loadProgress(scenarioId) {
  try {
    const raw = sessionStorage.getItem(progressKey(scenarioId));
    return raw ? new Set(JSON.parse(raw)) : new Set();
  } catch (_err) {
    return new Set();
  }
}

function resetProgress(scenarioId) {
  try {
    sessionStorage.removeItem(progressKey(scenarioId));
  } catch (err) {
    console.warn("Could not clear saved progress; sessionStorage is unavailable:", err);
  }
  location.reload();
}

function wireResetButton() {
  const btn = document.querySelector("[data-reset-story]");
  if (btn) btn.addEventListener("click", () => resetProgress(ACTIVE_SCENARIO));
}

function unlockNextSteps(completedStepId, restoring) {
  const story = state.story;
  let firstUnlocked = null;
  for (const button of document.querySelectorAll("[data-run-step]")) {
    const stepId = button.getAttribute("data-run-step") || "";
    const stepIndex = story.steps.findIndex((step) => step.id === stepId);
    const runnable = canRun(stepIndex);
    if (runnable) {
      button.removeAttribute("aria-disabled");
      const hint = document.querySelector(`[data-locked-hint-for="${CSS.escape(stepId)}"]`);
      if (hint) hint.remove();
      if (!firstUnlocked && !state.completed.has(stepId)) firstUnlocked = button;
    } else {
      button.setAttribute("aria-disabled", "true");
    }
    button.closest(".step")?.classList.toggle("locked", !runnable);
  }
  if (restoring) return;
  const allDone = story.steps.every((step) => state.completed.has(step.id));
  if (allDone) {
    const receipt = byId("receipt");
    receipt?.classList.add("visible");
    receipt?.scrollIntoView({ block: "start" });
  } else if (firstUnlocked) {
    firstUnlocked.focus({ preventScroll: true });
    firstUnlocked.closest(".step")?.scrollIntoView({ block: "start" });
  }
}

function restoreCompleted(story) {
  if (!ACTIVE_SCENARIO) return;
  const saved = loadProgress(ACTIVE_SCENARIO);
  if (!saved.size) return;
  for (const step of story.steps) {
    if (saved.has(step.id)) {
      state.completed.add(step.id);
      updateStatus(step.id, "done");
      const node = document.querySelector(`[data-friendly-for="${CSS.escape(step.id)}"]`);
      if (node) {
        node.className = "friendly-response visible";
        node.innerHTML = `<p class="meta">Completed earlier in this session. Run it again to see the live result.</p>`;
      }
    }
  }
  unlockNextSteps(null, true);
}

async function runStep(stepId, button) {
  button.setAttribute("aria-disabled", "true");
  updateStatus(stepId, "running");
  const response = await fetch(`/api/scenarios/${encodeURIComponent(state.story.id)}/${encodeURIComponent(stepId)}`, {method: "POST"});
  const data = await response.json();
  renderFriendly(stepId, data.friendly || {});
  setSource(stepId, "request", data.request_source || {});
  setSource(stepId, "response", data.response_source || {});
  const status = data.friendly?.status || "done";
  updateStatus(stepId, status);
  if (status === "done" || status === "denied_as_expected") {
    state.completed.add(stepId);
    saveProgress(state.story.id);
    setTimeout(() => unlockNextSteps(stepId, false), 80);
  } else {
    button.removeAttribute("aria-disabled");
    if (status === "needs_attention") button.textContent = "Try again";
  }
}

async function start() {
  try {
    const catalogue = await (await fetch("/api/scenarios.json", {cache: "no-store"})).json();
    if (!ACTIVE_SCENARIO) {
      renderChooser(catalogue.scenarios || [], catalogue.default_scenario_id || "");
      wireCurlCopyButtons();
      return;
    }
    const data = await (await fetch(`/api/scenarios/${encodeURIComponent(ACTIVE_SCENARIO)}.json`, {cache: "no-store"})).json();
    if (!data.story) {
      byId("story").innerHTML = `<div class="story-setup"><h2>Scenario not found</h2><p>${escapeHtml(ACTIVE_SCENARIO)}</p></div>`;
      return;
    }
    renderStory(data.story, data.runnable !== false);
    restoreCompleted(data.story);
    wireStepButtons();
    wireCurlCopyButtons();
    wireResetButton();
  } catch (err) {
    console.error("Scenario data failed to load:", err);
    const target = byId(ACTIVE_SCENARIO ? "story" : "chooser");
    target.innerHTML = `<div class="story-setup"><h2>The scenarios did not load</h2><p>The lab API did not respond. Reload the page to try again.</p></div>`;
  }
}
start();
