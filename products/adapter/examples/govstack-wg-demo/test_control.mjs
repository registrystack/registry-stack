import { test } from "node:test";
import assert from "node:assert/strict";
import {
  configureProject,
  configurePack,
  extendNativeProject,
  runtimeConfig,
  redact,
} from "./control.mjs";

test("live DHIS2 variant keeps reusable acquisition and declares its real unique order", () => {
  const pack = {
    routeTemplates: [
      {
        id: "page-tracked-entities",
        readSupport: {
          order: [{ name: "tracked-entity" }],
          uniqueTieBreaker: "tracked-entity",
        },
        steps: [
          {
            to: {
              parameters: {
                query: {
                  order: { constant: "createdAt:desc,trackedEntity:asc" },
                },
              },
            },
          },
        ],
      },
      { id: "tracker-import", steps: [] },
    ],
  };
  const result = configurePack(pack, "lZGmxYbs97q");
  assert.deepEqual(result.routeTemplates[0].readSupport.order, [
    { name: "created-at", direction: "descending" },
    { name: "unique-attribute", direction: "ascending" },
  ]);
  assert.equal(
    result.routeTemplates[0].readSupport.uniqueTieBreaker,
    "unique-attribute",
  );
  assert.equal(
    result.routeTemplates[0].steps[0].to.parameters.query.order.constant,
    "createdAt:desc,lZGmxYbs97q:asc",
  );
  assert.equal(
    pack.routeTemplates[0].readSupport.uniqueTieBreaker,
    "tracked-entity",
  );
  assert.throws(() => configurePack(pack, "../bad"));
});

test("project owns program and versioned contract; Write is not enabled on DHIS2", () => {
  const p = {
    consultation: { contract: "old" },
    pack: { digest: "old" },
    templatedRoutes: [{ parameters: { program: "old" } }],
  };
  const r = configureProject(p, "dhis2", "WSGAb5XwJ3Y");
  assert.equal(
    r.consultation.contract,
    "https://127.0.0.1:19443/contracts/dhis2/1.0.0/openapi.json",
  );
  assert.equal(r.templatedRoutes[0].parameters.program, "WSGAb5XwJ3Y");
  assert.equal(r.write, undefined);
  assert.equal(p.consultation.contract, "old");
});

test("native authored project gains only required note and bounded batch support", () => {
  const text =
    "    mutationMode: mutable\n      - {id: jurisdiction, type: string, required: true, minimumLength: 1, maximumLength: 40, classification: internal}\noperations: [create, get, list, patch]\nreadableFields: [name, email, jurisdiction]\nwritableFields: [name, email, jurisdiction]\n";
  const result = extendNativeProject(text);
  assert.match(result, /maximumItems: 1/);
  assert.match(result, /id: note/);
  assert.match(result, /patch, batch/);
  assert.throws(() => extendNativeProject("unknown template"), /template/);
});

test("runtime confines local auth and uses file secrets with separate database references", () => {
  const r = runtimeConfig(
    "dhis2",
    "/private/demo",
    "https://play.im.dhis2.org/stable-2-43-2-1",
  );
  assert.equal(r.endpoints[0].credential.type, "basic");
  assert.equal(r.listener.bind, "127.0.0.1:18110");
  assert.equal(r.oidc.allowInsecureHttp, true);
  assert.equal(r.oidc.jwksSource.documentRef, "secret:file/facade-jwks");
  assert.equal(r.database.runtimeUrlRef, "secret:file/dhis2-database");
  assert.deepEqual(r.allowedClients, ["wg-demo-client"]);
});

test("diagnostic filter never exposes bearer credentials", () => {
  assert.equal(
    redact("Authorization: Bearer abc.def.ghi"),
    "Authorization: [REDACTED]",
  );
  assert.equal(redact("eyJhbGciOiJSUzI1NiJ9.abc.def"), "[REDACTED JWT]");
});

test("template extension changes the record field without altering action input fields", () => {
  const f =
    "      - {id: jurisdiction, type: string, required: true, minimumLength: 1, maximumLength: 40, classification: internal}\n";
  const text =
    "    mutationMode: mutable\n" +
    f +
    "actions:\n" +
    f +
    "operations: [create, get, list, patch]\nreadableFields: [name, email, jurisdiction]\nwritableFields: [name, email, jurisdiction]\n";
  const r = extendNativeProject(text);
  assert.equal(r.match(/id: note/g).length, 1);
  assert.ok(r.indexOf("id: note") < r.indexOf("actions:"));
});

test("private JSON is read from one validated handle and refuses aliases", async () => {
  const { privateJson } = await import("./control.mjs");
  const { mkdtemp, writeFile, link, symlink } =
    await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const base =
    process.platform === "darwin"
      ? "/Volumes/CodexWorktrees/targets"
      : tmpdir();
  const dir = await mkdtemp(base + "/wg-private-json-");
  const path = dir + "/config.json";
  await writeFile(path, JSON.stringify({ purpose: "demo" }), { mode: 0o600 });
  assert.deepEqual(await privateJson(path), { purpose: "demo" });
  await symlink(path, dir + "/symlink.json");
  await assert.rejects(privateJson(dir + "/symlink.json"), /symlink/);
  await link(path, dir + "/hardlink.json");
  await assert.rejects(privateJson(dir + "/hardlink.json"), /single-link/);
});
