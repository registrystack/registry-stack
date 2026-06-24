<script lang="ts">
  import type { ProofTrace } from '$lib/types';
  import { IDENTITY_TRACE_ID } from './canned-traces.js';

  type Props = {
    traces: ProofTrace[];
    activeTraceId?: string;
    connected?: boolean;
  };

  let { traces, activeTraceId, connected = true }: Props = $props();

  // Depth expansion state per trace id
  let expandedDepth2 = $state<Record<string, boolean>>({});
  let expandedDepth3 = $state<Record<string, boolean>>({});
  // Raw SD-JWT expanded per trace id
  let expandedRaw = $state<Record<string, boolean>>({});
  // "verify again" flash state per trace id
  let verifyFlash = $state<Record<string, boolean>>({});
  // Copy-as-curl notification per trace id
  let copiedCurl = $state<Record<string, boolean>>({});

  // Separate the identity-binding entry (pinned to bottom)
  let identityTrace = $derived(traces.find((t) => t.id === IDENTITY_TRACE_ID));
  let inFlightTraces = $derived(traces.filter((t) => t.status === 'in_flight'));
  let mainTraces = $derived(
    traces
      .filter((t) => t.id !== IDENTITY_TRACE_ID && t.status !== 'in_flight')
      .slice()
      .sort((a, b) => b.seq - a.seq)
  );

  function toggleDepth2(id: string) {
    expandedDepth2[id] = !expandedDepth2[id];
  }

  function toggleDepth3(id: string) {
    expandedDepth3[id] = !expandedDepth3[id];
  }

  function toggleRaw(id: string) {
    expandedRaw[id] = !expandedRaw[id];
  }

  function buildCurlCommand(trace: ProofTrace): string {
    const body = JSON.stringify(trace.request.body, null, 2);
    return (
      `curl -X ${trace.request.method} '${trace.request.url}' \\\n` +
      `  -H 'Authorization: Bearer $NOTARY_TOKEN' \\\n` +
      `  -H 'Content-Type: application/json' \\\n` +
      `  -d '${body}'`
    );
  }

  async function copyCurl(trace: ProofTrace) {
    const cmd = buildCurlCommand(trace);
    await navigator.clipboard.writeText(cmd);
    copiedCurl[trace.id] = true;
    setTimeout(() => {
      copiedCurl[trace.id] = false;
    }, 2000);
  }

  function verifyAgain(id: string) {
    verifyFlash[id] = true;
    setTimeout(() => {
      verifyFlash[id] = false;
    }, 2500);
  }

  function statusLabel(trace: ProofTrace): string {
    switch (trace.status) {
      case 'in_flight':
        return 'In flight';
      case 'ok':
        return 'Verified';
      case 'false':
        return 'False (signed)';
      case 'denied':
        return 'Denied';
      case 'error':
        return 'Error';
    }
  }

  function statusClass(trace: ProofTrace): string {
    switch (trace.status) {
      case 'in_flight':
        return 'status-inflight';
      case 'ok':
        return 'status-ok';
      case 'false':
        return 'status-false';
      case 'denied':
        return 'status-denied';
      case 'error':
        return 'status-error';
    }
  }

  function authorityLabel(authority: string | undefined): string {
    switch (authority) {
      case 'civil':
        return 'Civil Registry';
      case 'social':
        return 'Social Welfare';
      case 'agri':
        return 'Agriculture';
      case 'certs':
        return 'Certificates';
      default:
        return authority ?? 'Unknown';
    }
  }

  function authorityIcon(authority: string | undefined): string {
    switch (authority) {
      case 'civil':
        return '👤';
      case 'social':
        return '🏠';
      case 'agri':
        return '🌾';
      case 'certs':
        return '📜';
      default:
        return '◧';
    }
  }

  function formatTs(ts: string): string {
    try {
      return new Date(ts).toLocaleTimeString('en-GB', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch {
      return ts;
    }
  }

  function formatJson(obj: Record<string, unknown>): string {
    return JSON.stringify(obj, null, 2);
  }
</script>

<aside class="proof-inspector" aria-label="Proof Inspector">
  <header class="inspector-header">
    <span class="inspector-icon" aria-hidden="true">◧</span>
    <span class="inspector-title">PROOF INSPECTOR</span>
    {#if !connected}
      <span class="reconnect-pill" role="status" aria-live="polite">
        <span class="reconnect-dot" aria-hidden="true"></span>
        Reconnecting to audit feed
      </span>
    {/if}
  </header>

  <div class="entries-list" aria-label="Proof entries">

    <!-- In-flight skeleton entries (pinned at top) -->
    {#each inFlightTraces as trace (trace.id)}
      <div class="entry entry-inflight" aria-label="Request in flight: {trace.headline}">
        <div class="entry-top">
          <span class="authority-icon" aria-hidden="true">{authorityIcon(trace.authority)}</span>
          <span class="entry-id">{trace.id}</span>
          <span class="heartbeat-dot" aria-label="In flight" title="Request in flight"></span>
          <span class="entry-ts">{formatTs(trace.ts)}</span>
        </div>
        <p class="headline skeleton-text">{trace.headline}</p>
        <p class="not-disclosed">
          <span class="not-disclosed-label">Not disclosed:</span>
          {trace.notDisclosed}
        </p>
      </div>
    {/each}

    <!-- Resolved entries (newest first) -->
    {#each mainTraces as trace (trace.id)}
      {@const isActive = trace.id === activeTraceId}
      {@const d2open = expandedDepth2[trace.id] ?? false}
      {@const d3open = expandedDepth3[trace.id] ?? false}
      {@const rawOpen = expandedRaw[trace.id] ?? false}
      {@const flashVerify = verifyFlash[trace.id] ?? false}
      {@const copied = copiedCurl[trace.id] ?? false}
      <div
        class="entry {statusClass(trace)}"
        class:entry-active={isActive}
        id="proof-{trace.id}"
      >
        <!-- Depth 1: always visible -->
        <div class="entry-top">
          <span class="authority-icon" aria-hidden="true">{authorityIcon(trace.authority)}</span>
          <span class="entry-id">{trace.id}</span>
          <span class="status-chip {statusClass(trace)}">
            {statusLabel(trace)}
          </span>
          <time class="entry-ts" datetime={trace.ts}>{formatTs(trace.ts)}</time>
        </div>

        <p class="headline">{trace.headline}</p>
        <p class="answered">{trace.answered}</p>

        <!-- NOT DISCLOSED: always at depth 1, never hidden -->
        <p class="not-disclosed">
          <span class="not-disclosed-label">Not disclosed:</span>
          {trace.notDisclosed}
        </p>

        {#if trace.fieldId}
          <p class="for-field">
            <span aria-hidden="true">&#8627;</span> for field
            <span class="field-ref">"{trace.fieldId}"</span>
          </p>
        {/if}

        <!-- Depth 2 toggle -->
        {#if trace.response}
          <button
            class="expand-btn"
            onclick={() => toggleDepth2(trace.id)}
            aria-expanded={d2open}
            aria-controls="depth2-{trace.id}"
          >
            <span class="expand-arrow" aria-hidden="true">{d2open ? '▾' : '▸'}</span>
            Request and response
            {#if !copied}
              <span
                class="copy-curl-btn"
                role="button"
                tabindex="0"
                onclick={(e) => { e.stopPropagation(); copyCurl(trace); }}
                onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.stopPropagation(); copyCurl(trace); } }}
                aria-label="Copy request as curl command"
              >
                [Copy as curl]
              </span>
            {:else}
              <span class="copy-curl-btn copy-curl-done" aria-live="polite">Copied</span>
            {/if}
          </button>

          {#if d2open}
            <div id="depth2-{trace.id}" class="depth2">
              <code class="wire-line">
                {trace.request.method} {trace.request.url}
              </code>
              <code class="wire-line wire-auth">
                Authorization: Bearer <span class="redacted" aria-label="Bearer token redacted">&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;</span> (redacted)
              </code>
              <pre class="wire-body">{formatJson(trace.request.body)}</pre>

              {#if trace.response}
                <div class="response-divider">
                  <span class="response-status">{trace.response.status} {trace.response.status === 200 ? 'OK' : trace.response.status === 403 ? 'Forbidden' : ''}</span>
                </div>
                <pre class="wire-body">{formatJson(trace.response.body)}</pre>
              {/if}

              <!-- Depth 3 toggle (inside depth 2 expansion) -->
              {#if trace.proof}
                <button
                  class="expand-btn expand-btn-inner"
                  onclick={() => toggleDepth3(trace.id)}
                  aria-expanded={d3open}
                  aria-controls="depth3-{trace.id}"
                >
                  <span class="expand-arrow" aria-hidden="true">{d3open ? '▾' : '▸'}</span>
                  Proof and credential (signature, issuer, VC)
                </button>

                {#if d3open}
                  <div id="depth3-{trace.id}" class="depth3">
                    <table class="proof-table" aria-label="Cryptographic proof details">
                      <tbody>
                        <tr>
                          <th scope="row">Signed by</th>
                          <td>{trace.proof.signedBy}</td>
                        </tr>
                        <tr>
                          <th scope="row">Algorithm</th>
                          <td>{trace.proof.algorithm}</td>
                        </tr>
                        <tr>
                          <th scope="row">Issuer key</th>
                          <td class="mono">{trace.proof.issuerKey}</td>
                        </tr>
                        <tr>
                          <th scope="row">Holder bound</th>
                          <td>{trace.proof.holderBound}</td>
                        </tr>
                        <tr>
                          <th scope="row">Credential</th>
                          <td>{trace.proof.credential}</td>
                        </tr>
                        <tr>
                          <th scope="row">Audit id</th>
                          <td class="mono">{trace.proof.auditId}</td>
                        </tr>
                      </tbody>
                    </table>

                    <div class="proof-actions">
                      <button
                        class="verify-again-btn"
                        onclick={() => verifyAgain(trace.id)}
                        aria-label="Verify credential signature again"
                      >
                        [verify again]
                      </button>
                      {#if flashVerify}
                        <span class="verify-flash" aria-live="polite" role="status">
                          &#x2713; valid
                        </span>
                      {/if}
                    </div>

                    <button
                      class="expand-btn expand-btn-inner"
                      onclick={() => toggleRaw(trace.id)}
                      aria-expanded={rawOpen}
                      aria-controls="raw-{trace.id}"
                    >
                      <span class="expand-arrow" aria-hidden="true">{rawOpen ? '▾' : '▸'}</span>
                      Raw SD-JWT
                    </button>
                    {#if rawOpen}
                      <div id="raw-{trace.id}" class="raw-jwt">
                        <code class="mono" aria-label="Raw SD-JWT credential (synthetic)"
                          >eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.&#x2B;[synthetic-demo-data]&#x2B;.&#x2B;_disclosure_&#x2B;</code
                        >
                        <p class="raw-note">
                          (Synthetic demo data - not a real credential)
                        </p>
                      </div>
                    {/if}
                  </div>
                {/if}
              {/if}
            </div>
          {/if}
        {/if}
      </div>
    {/each}

    <!-- Identity-binding entry: pinned to bottom as the foundation -->
    {#if identityTrace}
      {@const trace = identityTrace}
      {@const d2open = expandedDepth2[trace.id] ?? false}
      {@const d3open = expandedDepth3[trace.id] ?? false}
      {@const rawOpen = expandedRaw[trace.id] ?? false}
      {@const flashVerify = verifyFlash[trace.id] ?? false}
      {@const copied = copiedCurl[trace.id] ?? false}
      <div class="entry entry-identity {statusClass(trace)}" aria-label="Identity binding (foundation)">
        <div class="entry-top">
          <span class="authority-icon" aria-hidden="true">{authorityIcon(trace.authority)}</span>
          <span class="entry-id">{trace.id}</span>
          <span class="identity-badge">Identity foundation</span>
          <time class="entry-ts" datetime={trace.ts}>{formatTs(trace.ts)}</time>
        </div>

        <p class="headline">{trace.headline}</p>
        <p class="answered">{trace.answered}</p>

        <p class="not-disclosed">
          <span class="not-disclosed-label">Not disclosed:</span>
          {trace.notDisclosed}
        </p>

        <button
          class="expand-btn"
          onclick={() => toggleDepth2(trace.id)}
          aria-expanded={d2open}
          aria-controls="depth2-{trace.id}"
        >
          <span class="expand-arrow" aria-hidden="true">{d2open ? '▾' : '▸'}</span>
          Request and response
          {#if !copied}
            <span
              class="copy-curl-btn"
              role="button"
              tabindex="0"
              onclick={(e) => { e.stopPropagation(); copyCurl(trace); }}
              onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.stopPropagation(); copyCurl(trace); } }}
              aria-label="Copy request as curl command"
            >
              [Copy as curl]
            </span>
          {:else}
            <span class="copy-curl-btn copy-curl-done" aria-live="polite">Copied</span>
          {/if}
        </button>

        {#if d2open}
          <div id="depth2-{trace.id}" class="depth2">
            <code class="wire-line">
              {trace.request.method} {trace.request.url}
            </code>
            <code class="wire-line wire-auth">
              Authorization: Bearer <span class="redacted" aria-label="Bearer token redacted">&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;</span> (redacted)
            </code>
            <pre class="wire-body">{formatJson(trace.request.body)}</pre>
            {#if trace.response}
              <div class="response-divider">
                <span class="response-status">{trace.response.status} OK</span>
              </div>
              <pre class="wire-body">{formatJson(trace.response.body)}</pre>
            {/if}

            {#if trace.proof}
              <button
                class="expand-btn expand-btn-inner"
                onclick={() => toggleDepth3(trace.id)}
                aria-expanded={d3open}
                aria-controls="depth3-{trace.id}"
              >
                <span class="expand-arrow" aria-hidden="true">{d3open ? '▾' : '▸'}</span>
                Proof and credential (signature, issuer, VC)
              </button>

              {#if d3open}
                <div id="depth3-{trace.id}" class="depth3">
                  <table class="proof-table" aria-label="Cryptographic proof details">
                    <tbody>
                      <tr>
                        <th scope="row">Signed by</th>
                        <td>{trace.proof.signedBy}</td>
                      </tr>
                      <tr>
                        <th scope="row">Algorithm</th>
                        <td>{trace.proof.algorithm}</td>
                      </tr>
                      <tr>
                        <th scope="row">Issuer key</th>
                        <td class="mono">{trace.proof.issuerKey}</td>
                      </tr>
                      <tr>
                        <th scope="row">Holder bound</th>
                        <td>{trace.proof.holderBound}</td>
                      </tr>
                      <tr>
                        <th scope="row">Credential</th>
                        <td>{trace.proof.credential}</td>
                      </tr>
                      <tr>
                        <th scope="row">Audit id</th>
                        <td class="mono">{trace.proof.auditId}</td>
                      </tr>
                    </tbody>
                  </table>

                  <div class="proof-actions">
                    <button
                      class="verify-again-btn"
                      onclick={() => verifyAgain(trace.id)}
                      aria-label="Verify credential signature again"
                    >
                      [verify again]
                    </button>
                    {#if flashVerify}
                      <span class="verify-flash" aria-live="polite" role="status">
                        &#x2713; valid
                      </span>
                    {/if}
                  </div>

                  <button
                    class="expand-btn expand-btn-inner"
                    onclick={() => toggleRaw(trace.id)}
                    aria-expanded={rawOpen}
                    aria-controls="raw-{trace.id}"
                  >
                    <span class="expand-arrow" aria-hidden="true">{rawOpen ? '▾' : '▸'}</span>
                    Raw SD-JWT
                  </button>
                  {#if rawOpen}
                    <div id="raw-{trace.id}" class="raw-jwt">
                      <code class="mono" aria-label="Raw SD-JWT credential (synthetic)"
                        >eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.&#x2B;[synthetic-demo-data]&#x2B;.&#x2B;_disclosure_&#x2B;</code
                      >
                      <p class="raw-note">(Synthetic demo data - not a real credential)</p>
                    </div>
                  {/if}
                </div>
              {/if}
            {/if}
          </div>
        {/if}
      </div>
    {/if}
  </div>
</aside>

<style>
  .proof-inspector {
    display: flex;
    flex-direction: column;
    background: var(--color-surface-raised);
    border-left: 2px solid var(--color-chrome);
    font-family: var(--font-ui);
    font-size: var(--text-sm);
    min-width: 320px;
    max-width: 480px;
    height: 100%;
    overflow: hidden;
  }

  .inspector-header {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-4);
    background: var(--color-chrome);
    color: #fff;
    flex-shrink: 0;
  }

  .inspector-icon {
    font-size: var(--text-lg);
  }

  .inspector-title {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.1em;
    flex: 1;
  }

  .reconnect-pill {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    background: var(--color-channel-amber);
    color: #fff;
    font-size: var(--text-xs);
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-full);
  }

  .reconnect-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #fff;
    animation: pulse 1.2s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }

  .entries-list {
    flex: 1;
    overflow-y: auto;
    padding: var(--space-2) 0;
  }

  .entry {
    padding: var(--space-3) var(--space-4);
    border-bottom: 1px solid color-mix(in srgb, var(--color-chrome) 10%, transparent);
    animation: slide-in 300ms ease;
  }

  @keyframes slide-in {
    from {
      opacity: 0;
      transform: translateY(-8px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .entry-active {
    background: color-mix(in srgb, var(--color-channel-fetch) 6%, transparent);
    border-left: 3px solid var(--color-channel-fetch);
  }

  .entry-inflight {
    background: color-mix(in srgb, var(--color-chrome) 4%, transparent);
  }

  .entry-identity {
    background: color-mix(in srgb, var(--color-accent-seal) 6%, transparent);
    border-top: 2px solid var(--color-accent-seal);
    margin-top: auto;
  }

  .entry-top {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-bottom: var(--space-2);
  }

  .authority-icon {
    font-size: var(--text-base);
    flex-shrink: 0;
  }

  .entry-id {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    color: color-mix(in srgb, var(--color-chrome) 50%, transparent);
    flex-shrink: 0;
  }

  .entry-ts {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    color: color-mix(in srgb, var(--color-chrome) 50%, transparent);
    margin-left: auto;
    flex-shrink: 0;
  }

  .heartbeat-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-channel-verify);
    animation: pulse 0.8s ease-in-out infinite;
    flex-shrink: 0;
  }

  .status-chip {
    font-size: var(--text-xs);
    font-family: var(--font-mono);
    padding: 1px var(--space-2);
    border-radius: var(--radius-full);
    font-weight: 600;
  }

  .status-chip.status-ok {
    background: color-mix(in srgb, var(--color-channel-verify) 15%, transparent);
    color: var(--color-channel-verify);
  }

  .status-chip.status-false {
    background: color-mix(in srgb, var(--color-channel-amber) 15%, transparent);
    color: var(--color-channel-amber);
  }

  .status-chip.status-denied {
    background: color-mix(in srgb, var(--color-channel-denied) 15%, transparent);
    color: var(--color-channel-denied);
  }

  .status-chip.status-error {
    background: color-mix(in srgb, var(--color-channel-denied) 15%, transparent);
    color: var(--color-channel-denied);
  }

  .status-chip.status-inflight {
    background: color-mix(in srgb, var(--color-chrome) 10%, transparent);
    color: var(--color-chrome);
  }

  .identity-badge {
    font-size: var(--text-xs);
    font-family: var(--font-mono);
    padding: 1px var(--space-2);
    border-radius: var(--radius-full);
    background: color-mix(in srgb, var(--color-accent-seal) 20%, transparent);
    color: color-mix(in srgb, var(--color-accent-seal) 80%, #000);
    font-weight: 600;
  }

  .headline {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--color-chrome);
    margin: 0 0 var(--space-1);
    line-height: 1.4;
  }

  .skeleton-text {
    color: color-mix(in srgb, var(--color-chrome) 50%, transparent);
    font-style: italic;
  }

  .answered {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    color: color-mix(in srgb, var(--color-chrome) 70%, transparent);
    margin: 0 0 var(--space-1);
  }

  /* Not disclosed: always visible at depth 1, the "money shot" */
  .not-disclosed {
    font-size: var(--text-xs);
    color: color-mix(in srgb, var(--color-chrome) 80%, transparent);
    margin: 0 0 var(--space-1);
    padding: var(--space-1) var(--space-2);
    background: color-mix(in srgb, var(--color-accent-seal) 8%, transparent);
    border-left: 2px solid var(--color-accent-seal);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
  }

  .not-disclosed-label {
    font-weight: 700;
    color: color-mix(in srgb, var(--color-accent-seal) 80%, #000);
  }

  .for-field {
    font-size: var(--text-xs);
    color: color-mix(in srgb, var(--color-chrome) 50%, transparent);
    margin: var(--space-1) 0 0;
  }

  .field-ref {
    font-family: var(--font-mono);
    color: var(--color-channel-fetch);
  }

  .expand-btn {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    background: none;
    border: none;
    cursor: pointer;
    color: color-mix(in srgb, var(--color-chrome) 70%, transparent);
    font-size: var(--text-xs);
    font-family: var(--font-ui);
    padding: var(--space-1) 0;
    margin-top: var(--space-2);
    text-align: left;
    width: 100%;
  }

  .expand-btn:hover {
    color: var(--color-chrome);
  }

  .expand-btn:focus-visible {
    outline: none;
    box-shadow: var(--ring-focus);
    border-radius: var(--radius-sm);
  }

  .expand-btn-inner {
    margin-top: var(--space-1);
    padding-left: 0;
  }

  .expand-arrow {
    font-size: 0.6rem;
    flex-shrink: 0;
  }

  .copy-curl-btn {
    margin-left: auto;
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    color: var(--color-channel-fetch);
    cursor: pointer;
    text-decoration: underline;
    user-select: none;
    padding: 0 var(--space-1);
  }

  .copy-curl-btn:focus-visible {
    outline: 2px solid var(--color-channel-fetch);
    border-radius: var(--radius-sm);
  }

  .copy-curl-done {
    color: var(--color-channel-verify);
    text-decoration: none;
    cursor: default;
  }

  .depth2 {
    margin-top: var(--space-2);
    padding: var(--space-2);
    background: color-mix(in srgb, var(--color-chrome) 4%, transparent);
    border-radius: var(--radius-sm);
    font-family: var(--font-mono);
    font-size: var(--text-xs);
  }

  .wire-line {
    display: block;
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--color-chrome);
    margin-bottom: var(--space-1);
  }

  .wire-auth {
    color: color-mix(in srgb, var(--color-chrome) 70%, transparent);
  }

  .redacted {
    color: var(--color-channel-denied);
    letter-spacing: 0.05em;
  }

  .wire-body {
    white-space: pre-wrap;
    word-break: break-all;
    color: color-mix(in srgb, var(--color-chrome) 80%, transparent);
    margin: var(--space-1) 0;
    font-size: var(--text-xs);
  }

  .response-divider {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin: var(--space-2) 0;
  }

  .response-divider::before,
  .response-divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: color-mix(in srgb, var(--color-chrome) 20%, transparent);
  }

  .response-status {
    font-weight: 600;
    color: color-mix(in srgb, var(--color-chrome) 60%, transparent);
    font-size: var(--text-xs);
    white-space: nowrap;
  }

  .depth3 {
    margin-top: var(--space-2);
    padding: var(--space-2);
    background: color-mix(in srgb, var(--color-accent-seal) 5%, transparent);
    border-radius: var(--radius-sm);
    border: 1px solid color-mix(in srgb, var(--color-accent-seal) 25%, transparent);
  }

  .proof-table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--text-xs);
    font-family: var(--font-mono);
    margin-bottom: var(--space-2);
  }

  .proof-table th {
    text-align: left;
    font-weight: 600;
    color: color-mix(in srgb, var(--color-chrome) 60%, transparent);
    padding: 2px var(--space-2) 2px 0;
    white-space: nowrap;
    vertical-align: top;
  }

  .proof-table td {
    color: var(--color-chrome);
    padding: 2px 0;
    word-break: break-all;
  }

  .proof-table .mono {
    font-family: var(--font-mono);
    font-size: 0.7rem;
  }

  .proof-actions {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-bottom: var(--space-2);
  }

  .verify-again-btn {
    background: none;
    border: 1px solid color-mix(in srgb, var(--color-accent-seal) 40%, transparent);
    border-radius: var(--radius-sm);
    padding: 2px var(--space-2);
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    cursor: pointer;
    color: color-mix(in srgb, var(--color-accent-seal) 80%, #000);
    transition: background var(--transition-fast);
  }

  .verify-again-btn:hover {
    background: color-mix(in srgb, var(--color-accent-seal) 10%, transparent);
  }

  .verify-again-btn:focus-visible {
    outline: none;
    box-shadow: var(--ring-focus);
  }

  .verify-flash {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    font-weight: 700;
    color: var(--color-channel-verify);
    animation: flash-in 300ms ease;
  }

  @keyframes flash-in {
    from { opacity: 0; transform: scale(0.9); }
    to { opacity: 1; transform: scale(1); }
  }

  .raw-jwt {
    padding: var(--space-2);
    background: color-mix(in srgb, var(--color-chrome) 6%, transparent);
    border-radius: var(--radius-sm);
    margin-top: var(--space-1);
  }

  .raw-jwt .mono {
    font-family: var(--font-mono);
    font-size: 0.65rem;
    word-break: break-all;
    display: block;
    color: color-mix(in srgb, var(--color-chrome) 70%, transparent);
  }

  .raw-note {
    font-size: var(--text-xs);
    font-style: italic;
    color: color-mix(in srgb, var(--color-chrome) 40%, transparent);
    margin: var(--space-1) 0 0;
  }
</style>
