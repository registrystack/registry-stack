const text = (value) => value == null ? "" : String(value);
const byId = (id) => document.getElementById(id);

function escapeHtml(value) {
  return text(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  }[char]));
}

async function copyValue(value, button) {
  await navigator.clipboard.writeText(value);
  const previous = button.textContent;
  button.textContent = "Copied";
  setTimeout(() => button.textContent = previous, 1200);
}

function renderWallet(wallet) {
  const issuer = wallet.issuer || "";
  const credentialConfigurationId = wallet.credential_configuration_id || "";
  const offerStart = wallet.offer_start_url || (
    issuer && credentialConfigurationId
      ? `${issuer.replace(/\/$/, "")}/oid4vci/offer/start?credential_configuration_id=${encodeURIComponent(credentialConfigurationId)}`
      : wallet.offer_url || ""
  );
  const walletUrl = wallet.wallet_url || "https://wallet.lab.registrystack.org/signup";
  const identity = wallet.demo_identity || {};
  const negative = wallet.negative_control || {};
  byId("wallet-grid").innerHTML = `
    <div class="step-list" aria-label="Wallet issuance steps">
      <div class="step-card"><span class="step-number">1</span><div><strong>Open the hosted wallet.</strong><p>Create or open a demo wallet, then use its scan or import-offer screen.</p><div class="actions"><a class="button" href="${escapeHtml(walletUrl)}" target="_blank" rel="noreferrer">Open wallet</a><button type="button" data-copy="${escapeHtml(walletUrl)}">Copy wallet URL</button></div></div></div>
      <div class="step-card"><span class="step-number">2</span><div><strong>Start credential issuance.</strong><p>The Notary will redirect to eSignet before it renders the wallet offer.</p><div class="actions"><a class="button primary" href="${escapeHtml(offerStart)}" target="_blank" rel="noreferrer">Start issuance</a><button type="button" data-copy="${escapeHtml(offerStart)}">Copy start URL</button></div></div></div>
      <div class="step-card"><span class="step-number">3</span><div><strong>Copy the generated offer into the wallet.</strong><p>After login, copy the <code>openid-credential-offer://</code> URI from the Notary page and paste it into the wallet scan/import screen within 300 seconds. The hosted demo no longer requires a separate issuer PIN.</p></div></div>
    </div>
    <div class="kv"><span>Sign in as</span><strong>${escapeHtml(identity.name)}</strong><div class="meta">Use ID ${escapeHtml(identity.identifier)}, OTP ${escapeHtml(identity.generated_code)}, and PIN ${escapeHtml(identity.pin)} if eSignet asks.</div></div>
    <div class="kv"><span>Your wallet should receive</span><strong>${escapeHtml(wallet.credential_name || wallet.credential_configuration_id)}</strong><div class="meta">${escapeHtml(identity.expected_result || wallet.user_story || "")}</div></div>
    <div class="kv"><span>Why this matters</span><strong>A service gets a yes/no proof, not the full civil record.</strong><div class="meta">${escapeHtml(wallet.user_story || "")}</div></div>
    <div class="kv"><span>Test a rejected case</span><strong>${escapeHtml(negative.identifier)}</strong><div class="meta">${escapeHtml(negative.expected_result)}</div></div>
    <div class="kv"><span>For developers</span><strong>Issuer and credential type</strong><div class="meta">${escapeHtml(issuer)} &middot; ${escapeHtml(credentialConfigurationId)}</div></div>
  `;
}

function credentialBlock(credential) {
  const scopes = (credential.scopes || []).join(", ");
  const token = credential.token || "";
  const curl = credential.curl || "";
  const headerRows = Object.entries(credential.required_headers || {})
    .map(([key, value]) => `<div class="meta">${escapeHtml(key)}: ${escapeHtml(value)}</div>`)
    .join("");
  return `
    <div class="cred-block">
      <div>
        <div class="cred-name">${escapeHtml(credential.label)}</div>
        <div class="meta">${escapeHtml(scopes)}</div>
        ${headerRows}
      </div>
      <div class="token-box">
        <code class="token" title="${escapeHtml(token)}">${escapeHtml(token || "Missing env value")}</code>
        <button type="button" data-copy="${escapeHtml(token)}" ${token ? "" : "disabled"}>Copy token</button>
      </div>
      <pre>${escapeHtml(curl)}</pre>
      <div class="actions">
        <button type="button" data-copy="${escapeHtml(curl)}">Copy curl</button>
      </div>
    </div>
  `;
}

function renderServices(services) {
  byId("services-grid").innerHTML = services.map((service) => {
    const creds = (service.credentials || []).map(credentialBlock).join("");
    // The Open link starts hidden; loadStatus reveals it only when the service is
    // reachable and not auth-gated, so we never link to a 401 page or a dead host.
    return `
      <article class="credential">
        <div>
          <h3>${escapeHtml(service.label)}</h3>
          <div class="meta">${escapeHtml(service.purpose || "")}</div>
        </div>
        <div class="status-row">
          <span class="pill" data-status-for="${escapeHtml(service.id)}">checking</span>
          <a class="button hidden" data-open-for="${escapeHtml(service.id)}" href="${escapeHtml(service.url)}" target="_blank" rel="noreferrer">Open</a>
        </div>
        ${creds ? `<details class="cred-disclosure"><summary>Demo credentials &amp; curl</summary><div class="cred-list">${creds}</div></details>` : ""}
      </article>
    `;
  }).join("");
}

function wireCopyButtons() {
  document.querySelectorAll("[data-copy]").forEach((button) => {
    if (button.dataset.copyWired === "true") return;
    button.dataset.copyWired = "true";
    button.addEventListener("click", () => copyValue(button.getAttribute("data-copy") || "", button));
  });
}

async function loadStatus() {
  try {
    const response = await fetch("/api/status.json", {cache: "no-store"});
    const status = await response.json();
    let ok = 0;
    let bad = 0;
    for (const check of status.checks || []) {
      const node = document.querySelector(`[data-status-for="${CSS.escape(check.id)}"]`);
      const openNode = document.querySelector(`[data-open-for="${CSS.escape(check.id)}"]`);
      // Only offer the Open link when there is something to see: the service is up and its
      // base URL is browsable unauthenticated. A token-gated API or a down host shows nothing.
      if (openNode) openNode.classList.toggle("hidden", !(check.ok && check.browsable));
      if (check.ok) {
        ok += 1;
        if (node) {
          node.textContent = check.auth_gated ? "up - auth required" : `up - ${check.status_code}`;
          node.className = "pill ok";
        }
      } else {
        bad += 1;
        if (node) {
          node.textContent = check.status_code ? `down - ${check.status_code}` : `down`;
          node.className = "pill bad";
        }
      }
    }
    const total = ok + bad;
    byId("status-line").textContent = bad === 0
      ? `All ${total} services up · synthetic data only`
      : `${ok} of ${total} services up · synthetic data only`;
  } catch (error) {
    byId("status-line").textContent = "Status unavailable";
  }
}

async function start() {
  try {
    const response = await fetch("/api/lab.json", {cache: "no-store"});
    const data = await response.json();
    byId("subtitle").textContent = data.subtitle || "";
    renderServices(data.services || []);
    renderWallet(data.wallet || {});
    wireCopyButtons();
    loadStatus();
  } catch (err) {
    console.error("Lab configuration failed to load:", err);
    byId("subtitle").textContent = "The lab configuration did not load. Reload the page to try again.";
  }
}
start();
