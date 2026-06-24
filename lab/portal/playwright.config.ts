import { defineConfig } from '@playwright/test';

export default defineConfig({
  // The portal BFF is a single-process server whose proof feed is an in-process
  // store with a long-lived SSE feed on /proof/stream. Hosted sessions are scoped
  // per opaque cookie, but the e2e suite still runs serially so trace timing stays
  // deterministic across tests.
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
