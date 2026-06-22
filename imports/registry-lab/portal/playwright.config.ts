import { defineConfig } from '@playwright/test';

export default defineConfig({
  // The portal BFF is a single-process server whose proof feed is an in-process
  // singleton that accumulates traces across requests (and a long-lived SSE feed on
  // /proof/stream). Parallel browser contexts would see each other's traces and
  // contend on that shared state. The live demo is single-user (one context), so we
  // run the e2e suite serially to mirror the real flow and keep the shared feed
  // predictable across tests.
  workers: 1,
  fullyParallel: false,
  webServer: {
    // Build then start the adapter-node server. PORT=4000 is the default for
    // adapter-node; set explicitly so the URL below is always correct.
    command: 'pnpm build && PORT=4000 node build',
    port: 4000,
    timeout: 120_000,
    reuseExistingServer: false
  },
  testDir: 'e2e',
  use: {
    baseURL: 'http://localhost:4000'
  }
});
