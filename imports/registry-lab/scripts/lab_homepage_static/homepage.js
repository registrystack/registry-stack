const text = (value) => value == null ? "" : String(value);
const byId = (id) => document.getElementById(id);

const journeyTargets = new Map([
  ["registrystack.org", "marketing"],
  ["docs.registrystack.org", "docs"],
  ["github.com", "github"],
  ["wallet.lab.registrystack.org", "wallet"],
  ["portal.lab.registrystack.org", "citizen-portal"],
  ["citizen-notary.lab.registrystack.org", "notary"],
]);

function track(eventName, data = {}) {
  if (!window.umami?.track) return;
  window.umami.track(eventName, data);
}

function linkText(node) {
  return text(node.textContent).replace(/\s+/g, " ").trim().slice(0, 80);
}

function journeyUrl(anchor, targetSite) {
  const url = new URL(anchor.href);
  if (targetSite === "marketing" || targetSite === "docs") {
    url.searchParams.set("utm_source", "registry_lab");
    url.searchParams.set("utm_medium", "lab");
    url.searchParams.set("utm_campaign", "cross_site");
    url.searchParams.set("utm_content", window.location.pathname);
  }
  return url;
}

function prepareJourneyLinks() {
  document.querySelectorAll("a[href]").forEach((anchor) => {
    try {
      const url = new URL(anchor.href);
      const targetSite = journeyTargets.get(url.hostname);
      if (!targetSite) return;
      anchor.href = journeyUrl(anchor, targetSite).toString();
    } catch (_error) {}
  });
}

function wireJourneyTracking() {
  document.addEventListener("click", (event) => {
    const anchor = event.target instanceof Element ? event.target.closest("a[href]") : null;
    if (!anchor) return;
    try {
      const url = new URL(anchor.href);
      const scenarioMatch = url.origin === window.location.origin && url.pathname.startsWith("/scenarios/");
      if (scenarioMatch) {
        track("lab_scenario_open", {
          scenario_id: decodeURIComponent(url.pathname.replace("/scenarios/", "").replace(/\/$/, "")),
          source_path: window.location.pathname,
          link_text: linkText(anchor),
        });
        return;
      }
      const targetSite = journeyTargets.get(url.hostname);
      if (!targetSite) return;
      track("lab_link_click", {
        target_site: targetSite,
        target_path: url.pathname,
        source_path: window.location.pathname,
        link_text: linkText(anchor),
      });
    } catch (_error) {}
  });
}

function escapeHtml(value) {
  return text(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  }[char]));
}

async function copyValue(value, button) {
  await navigator.clipboard.writeText(value);
  track("lab_copy", {
    source_path: window.location.pathname,
    copy_label: linkText(button),
  });
  const previous = button.textContent;
  button.textContent = "Copied";
  setTimeout(() => button.textContent = previous, 1200);
}

function walletCredentialOptions(wallet) {
  const configured = Array.isArray(wallet.credential_options) && wallet.credential_options.length
    ? wallet.credential_options
    : [wallet];
  return configured.map((option) => ({
    ...wallet,
    ...option,
    demo_identity: option.demo_identity || wallet.demo_identity || {},
    negative_control: option.negative_control || wallet.negative_control || {},
  }));
}

function credentialOfferStart(wallet, option) {
  const issuer = option.issuer || wallet.issuer || "";
  const credentialConfigurationId = option.credential_configuration_id || "";
  return option.offer_start_url || (
    issuer && credentialConfigurationId
      ? `${issuer.replace(/\/$/, "")}/oid4vci/offer/start?credential_configuration_id=${encodeURIComponent(credentialConfigurationId)}`
      : option.offer_url || wallet.offer_url || ""
  );
}

function walletCredentialCard(wallet, option, index) {
  const issuer = option.issuer || wallet.issuer || "";
  const credentialConfigurationId = option.credential_configuration_id || "";
  const offerStart = credentialOfferStart(wallet, option);
  const identity = option.demo_identity || {};
  const negative = option.negative_control || {};
  return `
    <div class="step-card">
      <span class="step-number">${index + 2}</span>
      <div>
        <strong>${escapeHtml(option.credential_name || credentialConfigurationId)}</strong>
        <p>${escapeHtml(option.user_story || "")}</p>
        <div class="actions"><a class="button primary" href="${escapeHtml(offerStart)}" target="_blank" rel="noreferrer">Start issuance</a><button type="button" data-copy="${escapeHtml(offerStart)}">Copy start URL</button></div>
        <div class="meta">Sign in as ${escapeHtml(identity.name)} (${escapeHtml(identity.identifier)}), OTP ${escapeHtml(identity.generated_code)}.</div>
        <div class="meta">Wallet result: ${escapeHtml(identity.expected_result || "")}</div>
        <div class="meta">Developer configuration: ${escapeHtml(issuer)} &middot; ${escapeHtml(credentialConfigurationId)}</div>
        <div class="meta">Control: ${escapeHtml(negative.identifier || "")} ${escapeHtml(negative.expected_result || "")}</div>
      </div>
    </div>
  `;
}

function renderWallet(wallet) {
  const walletUrl = wallet.wallet_url || "https://wallet.lab.registrystack.org/signup";
  const options = walletCredentialOptions(wallet);
  const optionCards = options.map((option, index) => walletCredentialCard(wallet, option, index)).join("");
  const credentialNames = options
    .map((option) => option.credential_name || option.credential_configuration_id || "")
    .filter(Boolean)
    .join(", ");
  byId("wallet-grid").innerHTML = `
    <div class="step-list" aria-label="Wallet issuance steps">
      <div class="step-card"><span class="step-number">1</span><div><strong>Open the hosted wallet.</strong><p>Create or open a demo wallet, then use its scan or import-offer screen.</p><div class="actions"><a class="button" href="${escapeHtml(walletUrl)}" target="_blank" rel="noreferrer">Open wallet</a><button type="button" data-copy="${escapeHtml(walletUrl)}">Copy wallet URL</button></div></div></div>
      ${optionCards}
      <div class="step-card"><span class="step-number">${options.length + 2}</span><div><strong>Copy the generated offer into the wallet.</strong><p>After login, copy the <code>openid-credential-offer://</code> URI from the Notary page and paste it into the wallet scan/import screen within 300 seconds. The hosted demo no longer requires a separate issuer PIN.</p></div></div>
    </div>
    <div class="kv"><span>Your wallet can receive</span><strong>${escapeHtml(credentialNames)}</strong><div class="meta">Choose the simple vital-status proof or the richer CRVS birth certificate credential.</div></div>
    <div class="kv"><span>Why this matters</span><strong>A service gets a signed answer, not a copied registry.</strong><div class="meta">The CRVS option carries proper BirthEvidence, while the wallet proof remains bound to the signed-in citizen.</div></div>
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
    prepareJourneyLinks();
    loadStatus();
  } catch (err) {
    console.error("Lab configuration failed to load:", err);
    byId("subtitle").textContent = "The lab configuration did not load. Reload the page to try again.";
  }
}
wireJourneyTracking();
start();
