import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  AUDIENCE,
  bregctlChildEnvironment,
  CLIENT_ID,
  ISSUER,
  SUBJECT,
  TOKEN_LIFETIME_SECONDS,
  refreshBregSourceToken,
  startDemoServer,
} from "./demo-server.mjs";

const SOURCE_TOKEN = "synthetic-source-token-not-for-production";

function decodeJsonPart(part) {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

async function makeState(root) {
  const stateDir = join(root, "state");
  await mkdir(join(stateDir, "contracts"), { recursive: true });
  await writeFile(
    join(stateDir, "contracts", "dhis2.json"),
    JSON.stringify({ openapi: "3.1.0", info: { title: "DHIS2" } }),
  );
  await writeFile(
    join(stateDir, "contracts", "breg.json"),
    JSON.stringify({ openapi: "3.1.0", info: { title: "BReg" } }),
  );
  return stateDir;
}

async function makeFakeBregctl(root, { fail = false } = {}) {
  const path = join(root, fail ? "failing-bregctl.mjs" : "fake-bregctl.mjs");
  const source = `#!/usr/bin/env node
import { existsSync } from "node:fs";
import { chmod, writeFile } from "node:fs/promises";
import { join } from "node:path";
const project = process.argv.at(-1);
await writeFile(join(project, "call.json"), JSON.stringify({
  args: process.argv.slice(2),
  dyld: process.env.DYLD_FALLBACK_LIBRARY_PATH ?? null,
}));
${
  fail
    ? 'process.stderr.write("synthetic failure\\n"); process.exit(7);'
    : `
if (existsSync(join(project, "fail-refresh"))) {
  process.stderr.write("synthetic source token must stay private\\n");
  process.exit(8);
}
const headerFile = join(project, "editor.header");
await writeFile(headerFile, "Authorization: Bearer ${SOURCE_TOKEN}\\n", { mode: 0o600 });
await chmod(headerFile, 0o600);
process.stdout.write(JSON.stringify({ ok: true, command: "dev token", headerFile }));
`
}
`;
  await writeFile(path, source, { mode: 0o700 });
  await chmod(path, 0o700);
  return path;
}

test("serves discovery, signed tokens, health, and only fixed contract paths", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "wg-demo-server-"));
  const stateDir = await makeState(root);
  const server = await startDemoServer({
    stateDir,
    port: 0,
    noRefresh: true,
    log: () => {},
  });
  t.after(() => server.close());

  const origin = `http://127.0.0.1:${server.httpPort}`;
  const discoveryResponse = await fetch(
    `${origin}/.well-known/openid-configuration`,
  );
  assert.equal(discoveryResponse.status, 200);
  const discovery = await discoveryResponse.json();
  assert.deepEqual(discovery, {
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/jwks`,
    token_endpoint: `${ISSUER}/demo/token`,
    grant_types_supported: ["client_credentials"],
    token_endpoint_auth_methods_supported: ["none"],
    response_types_supported: ["token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
  });

  const jwksResponse = await fetch(`${origin}/jwks`);
  assert.equal(jwksResponse.status, 200);
  const jwks = await jwksResponse.json();
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0].kid, "wg-demo-key");
  assert.equal(jwks.keys[0].alg, "RS256");
  assert.deepEqual(await (await fetch(`${origin}/jwks.json`)).json(), jwks);

  const tokenResponse = await fetch(`${origin}/demo/token`);
  assert.equal(tokenResponse.status, 200);
  assert.equal(tokenResponse.headers.get("cache-control"), "no-store");
  const issued = await tokenResponse.json();
  assert.equal(issued.token_type, "Bearer");
  assert.equal(issued.expires_in, TOKEN_LIFETIME_SECONDS);
  assert.equal(typeof issued.access_token, "string");

  const [encodedHeader, encodedClaims, encodedSignature] =
    issued.access_token.split(".");
  assert.deepEqual(decodeJsonPart(encodedHeader), {
    alg: "RS256",
    typ: "at+jwt",
    kid: "wg-demo-key",
  });
  const claims = decodeJsonPart(encodedClaims);
  assert.equal(claims.iss, ISSUER);
  assert.equal(claims.aud, AUDIENCE);
  assert.equal(claims.client_id, CLIENT_ID);
  assert.equal(claims.sub, SUBJECT);
  assert.equal(claims.scope, "records.read records.write");
  assert.equal(claims.nbf, claims.iat);
  assert.equal(claims.exp - claims.iat, TOKEN_LIFETIME_SECONDS);
  assert.equal(
    verify(
      "RSA-SHA256",
      Buffer.from(`${encodedHeader}.${encodedClaims}`),
      createPublicKey({ key: jwks.keys[0], format: "jwk" }),
      Buffer.from(encodedSignature, "base64url"),
    ),
    true,
  );

  assert.deepEqual(await (await fetch(`${origin}/health`)).json(), {
    status: "ready",
    sourceTokenRefresh: { status: "disabled" },
  });
  assert.equal(
    (await (await fetch(`${origin}/contracts/dhis2/1.0.0/openapi.json`)).json())
      .info.title,
    "DHIS2",
  );
  assert.equal(
    (await (await fetch(`${origin}/contracts/breg/1.0.0/openapi.json`)).json())
      .info.title,
    "BReg",
  );
  assert.equal(
    (await fetch(`${origin}/contracts/dhis2/1.0.0/%2e%2e%2f%2e%2e%2fbreg.json`))
      .status,
    404,
  );
  assert.equal((await fetch(`${origin}/not-present`)).status, 404);
  assert.equal(
    (await fetch(`${origin}/health`, { method: "POST" })).status,
    405,
  );

  const keyMode =
    (await stat(join(stateDir, "secrets", "wg-demo-key.pem"))).mode & 0o777;
  assert.equal(keyMode, 0o600);
  assert.equal((await stat(stateDir)).mode & 0o077, 0);

  await server.close();
  await assert.rejects(fetch(`${origin}/health`));

  const restarted = await startDemoServer({
    stateDir,
    port: 0,
    noRefresh: true,
    log: () => {},
  });
  try {
    assert.deepEqual(
      await (await fetch(`http://127.0.0.1:${restarted.httpPort}/jwks`)).json(),
      jwks,
    );
  } finally {
    await restarted.close();
  }
});

test("refreshes the BReg source token through a value-free private file", async () => {
  const root = await mkdtemp(join(tmpdir(), "wg-demo-refresh-"));
  const stateDir = await makeState(root);
  const project = join(root, "breg-project");
  await mkdir(project);
  const bregctl = await makeFakeBregctl(root);
  const logs = [];
  const previousCarrier = process.env.REGISTRY_CARGO_RUNTIME_LIBRARY_PATH;
  process.env.REGISTRY_CARGO_RUNTIME_LIBRARY_PATH =
    "/synthetic/runtime-libraries";
  try {
    const result = await refreshBregSourceToken({
      stateDir,
      bregProject: project,
      bregctl,
      log: (entry) => logs.push(entry),
    });
    assert.equal(result.status, "ok");
  } finally {
    if (previousCarrier === undefined) {
      delete process.env.REGISTRY_CARGO_RUNTIME_LIBRARY_PATH;
    } else {
      process.env.REGISTRY_CARGO_RUNTIME_LIBRARY_PATH = previousCarrier;
    }
  }

  const tokenPath = join(stateDir, "secrets", "breg-source-token");
  assert.equal(await readFile(tokenPath, "utf8"), SOURCE_TOKEN);
  assert.equal((await stat(tokenPath)).mode & 0o777, 0o600);
  assert.equal((await stat(join(stateDir, "secrets"))).mode & 0o777, 0o700);
  assert.equal(JSON.stringify(logs).includes(SOURCE_TOKEN), false);

  const call = JSON.parse(await readFile(join(project, "call.json"), "utf8"));
  assert.deepEqual(call.args, [
    "--format",
    "json",
    "dev",
    "token",
    "editor",
    project,
  ]);
  assert.equal(
    bregctlChildEnvironment({
      REGISTRY_CARGO_RUNTIME_LIBRARY_PATH: "/synthetic/runtime-libraries",
    }).DYLD_FALLBACK_LIBRARY_PATH,
    "/synthetic/runtime-libraries",
  );
});

test("fails the initial refresh visibly without disclosing child output", async () => {
  const root = await mkdtemp(join(tmpdir(), "wg-demo-failed-refresh-"));
  const stateDir = await makeState(root);
  const project = join(root, "breg-project");
  await mkdir(project);
  const bregctl = await makeFakeBregctl(root, { fail: true });
  const logs = [];

  await assert.rejects(
    startDemoServer({
      stateDir,
      bregProject: project,
      bregctl,
      port: 0,
      log: (entry) => logs.push(entry),
    }),
    /initial BReg source token refresh failed/,
  );
  assert.equal(JSON.stringify(logs).includes("synthetic failure"), false);
  assert.deepEqual(logs.at(-1), {
    event: "source-token-refresh",
    status: "failed",
  });
});

test("retains the last source token and reports a value-free retry state", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "wg-demo-retry-"));
  const stateDir = await makeState(root);
  const project = join(root, "breg-project");
  await mkdir(project);
  const bregctl = await makeFakeBregctl(root);
  const logs = [];
  const server = await startDemoServer({
    stateDir,
    bregProject: project,
    bregctl,
    port: 0,
    refreshIntervalMs: 10,
    log: (entry) => logs.push(entry),
  });
  t.after(() => server.close());
  const tokenPath = join(stateDir, "secrets", "breg-source-token");
  const originalToken = await readFile(tokenPath, "utf8");
  await writeFile(join(project, "fail-refresh"), "fail");

  const deadline = Date.now() + 3_000;
  let health;
  do {
    health = await (
      await fetch(`http://127.0.0.1:${server.httpPort}/health`)
    ).json();
    if (health.status !== "degraded") {
      await new Promise((resolveWait) => setTimeout(resolveWait, 25));
    }
  } while (health.status !== "degraded" && Date.now() < deadline);

  assert.deepEqual(health, {
    status: "degraded",
    sourceTokenRefresh: { status: "retrying" },
  });
  assert.equal(await readFile(tokenPath, "utf8"), originalToken);
  assert.equal(JSON.stringify(logs).includes(SOURCE_TOKEN), false);
  assert.equal(JSON.stringify(logs).includes("synthetic source token"), false);
});
