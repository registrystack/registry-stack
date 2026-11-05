import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const control = join(here, "control.mjs");
const repo = resolve(here, "../../../..");
const scratchRoot =
  process.platform === "darwin" ? "/Volumes/CodexWorktrees/targets" : tmpdir();

async function privateFile(path, value) {
  await writeFile(
    path,
    typeof value === "string" ? value : JSON.stringify(value),
    { mode: 0o600 },
  );
  await chmod(path, 0o600);
}

async function fixture() {
  await mkdir(scratchRoot, { recursive: true });
  const root = await mkdtemp(join(scratchRoot, "wg-demo-lifecycle-"));
  const state = join(root, "state");
  const target = join(root, "target");
  const fakeBin = join(root, "fake-bin");
  const calls = join(root, "calls.jsonl");
  await mkdir(state, { mode: 0o700 });
  await mkdir(target, { mode: 0o700 });
  await mkdir(fakeBin, { mode: 0o700 });
  return { root, state, target, fakeBin, calls };
}

async function fakeCommands(
  f,
  { psCommand = "", container = "", label = "" } = {},
) {
  const source = (name) => `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(f.calls)}, JSON.stringify({
  command:${JSON.stringify(name)}, args,
  secrets:{
    DHIS2_USERNAME:process.env.DHIS2_USERNAME ?? null,
    DHIS2_PASSWORD:process.env.DHIS2_PASSWORD ?? null,
    SHELL_SECRET:process.env.SHELL_SECRET ?? null,
    GITHUB_TOKEN:process.env.GITHUB_TOKEN ?? null
  }
})+'\\n');
if (${JSON.stringify(name)} === 'which') process.stdout.write(${JSON.stringify(join(f.fakeBin, "docker") + "\n")});
if (${JSON.stringify(name)} === 'ps') process.stdout.write(${JSON.stringify(psCommand + "\n")});
if (${JSON.stringify(name)} === 'docker') {
  if (args[0] === 'ps') process.stdout.write(${JSON.stringify(container ? container + "\n" : "")});
  else if (args[0] === 'inspect') process.stdout.write(${JSON.stringify(label + "\n")});
  else if (args[0] === 'stop') process.stdout.write(${JSON.stringify(container + "\n")});
}
`;
  for (const name of ["which", "ps", "docker"]) {
    const path = join(f.fakeBin, name);
    await writeFile(path, source(name), { mode: 0o700 });
    await chmod(path, 0o700);
  }
}

async function runControl(f, command, extraEnvironment = {}) {
  return new Promise((complete, reject) => {
    const child = spawn(
      process.execPath,
      [
        control,
        command,
        "--state",
        f.state,
        "--repo",
        repo,
        "--target",
        f.target,
      ],
      {
        env: {
          HOME: f.root,
          PATH: f.fakeBin,
          LANG: "C",
          DHIS2_USERNAME: "bootstrap-user-must-not-propagate",
          DHIS2_PASSWORD: "bootstrap-password-must-not-propagate",
          SHELL_SECRET: "unrelated-shell-secret",
          GITHUB_TOKEN: "unrelated-github-token",
          ...extraEnvironment,
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.once("error", reject);
    child.once("close", (code) => complete({ code, stdout, stderr }));
  });
}

async function recordedCalls(path) {
  try {
    return (await readFile(path, "utf8"))
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

test("start refuses an existing state directory without its owner marker", async () => {
  const f = await fixture();
  const sentinel = join(f.state, "belongs-to-someone-else");
  await privateFile(sentinel, "preserve");

  const result = await runControl(f, "start");

  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /exists without this demo owner marker/);
  assert.equal(await readFile(sentinel, "utf8"), "preserve");
  await assert.rejects(readFile(join(f.state, "owner.json"), "utf8"), {
    code: "ENOENT",
  });
  assert.deepEqual(await recordedCalls(f.calls), []);
});

test("start refuses a changed source selection before touching its pinned project", async () => {
  const f = await fixture();
  await privateFile(join(f.state, "owner.json"), {
    kind: "govstack-wg-demo",
    repo,
  });
  const retained = {
    origin: "https://play.im.dhis2.org/stable-2-43-2-1",
    program: "WSGAb5XwJ3Y",
    tieBreakerAttribute: "lZGmxYbs97q",
  };
  const retainedConfig = {
    ...retained,
    username: "retained-user",
    password: "retained-password",
  };
  await privateFile(
    join(f.state, "source-selection.json"),
    JSON.stringify(retained, null, 2) + "\n",
  );
  await privateFile(
    join(f.state, "public-source.json"),
    JSON.stringify(retainedConfig, null, 2) + "\n",
  );
  await mkdir(join(f.state, "projects", "dhis2"), {
    recursive: true,
    mode: 0o700,
  });
  const pinnedProject = join(f.state, "projects", "dhis2", "project.yaml");
  await privateFile(pinnedProject, "pinned-project\n");
  await privateFile(join(f.state, "processes.json"), {
    issuer: process.pid,
    "adapter-dhis2": process.pid,
    "adapter-breg": process.pid,
  });
  const changedConfig = join(f.root, "changed-source.json");
  await privateFile(
    changedConfig,
    JSON.stringify({ ...retainedConfig, program: "Different01" }, null, 2) +
      "\n",
  );
  await fakeCommands(f, {
    psCommand: `node synthetic-service --state ${f.state}`,
  });

  const beforeSelection = await readFile(
    join(f.state, "source-selection.json"),
    "utf8",
  );
  const beforeConfig = await readFile(
    join(f.state, "public-source.json"),
    "utf8",
  );
  const result = await runControl(f, "start", {
    WG_DHIS2_SOURCE_CONFIG: changedConfig,
  });

  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /source selection changed/);
  assert.equal(
    await readFile(join(f.state, "source-selection.json"), "utf8"),
    beforeSelection,
  );
  assert.equal(
    await readFile(join(f.state, "public-source.json"), "utf8"),
    beforeConfig,
  );
  assert.equal(await readFile(pinnedProject, "utf8"), "pinned-project\n");
  assert.equal(
    (await recordedCalls(f.calls)).some((call) => call.command === "docker"),
    false,
  );
});

test("stop refuses a same-name container with the wrong owner label and scrubs child environments", async () => {
  const f = await fixture();
  await privateFile(join(f.state, "owner.json"), {
    kind: "govstack-wg-demo",
    repo,
  });
  const container =
    "govstack-wg-adapter-" +
    createHash("sha256").update(f.state).digest("hex").slice(0, 12);
  await fakeCommands(f, { container, label: "/another/demo/state" });

  const result = await runControl(f, "stop");
  const calls = await recordedCalls(f.calls);

  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /database container is not owned by this demo/);
  assert.equal(
    calls.some((call) => call.command === "docker" && call.args[0] === "stop"),
    false,
  );
  assert.ok(
    calls.some(
      (call) => call.command === "docker" && call.args[0] === "inspect",
    ),
  );
  for (const call of calls) {
    assert.deepEqual(call.secrets, {
      DHIS2_USERNAME: null,
      DHIS2_PASSWORD: null,
      SHELL_SECRET: null,
      GITHUB_TOKEN: null,
    });
  }
});

test("malformed private configuration never echoes its secret contents", async () => {
  const f = await fixture();
  await privateFile(join(f.state, "owner.json"), {
    kind: "govstack-wg-demo",
    repo,
  });
  const canary = "MALFORMED-PRIVATE-CONFIG-CANARY";
  await privateFile(
    join(f.state, "public-source.json"),
    `{"password":"${canary}" broken`,
  );
  await privateFile(join(f.state, "processes.json"), {
    issuer: process.pid,
    "adapter-dhis2": process.pid,
    "adapter-breg": process.pid,
  });
  await fakeCommands(f, { psCommand: `node control.mjs --state ${f.state}` });
  const result = await runControl(f, "start");
  assert.notEqual(result.code, 0);
  assert.ok(!(result.stdout + result.stderr).includes(canary));
  assert.match(result.stderr, /private configuration is not valid JSON/);
});
