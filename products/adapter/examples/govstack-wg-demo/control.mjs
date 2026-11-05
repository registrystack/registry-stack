#!/usr/bin/env node
// Retained local demo orchestration. No public DHIS2 mutation is performed.
import { execFile as execCallback, spawn } from "node:child_process";
import { promisify } from "node:util";
import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  chmod,
  cp,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  unlink,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
const exec = promisify(execCallback);
const here = dirname(fileURLToPath(import.meta.url));
const IMAGE =
  "docker.io/library/postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675";
const CLI_VERSION = "4.3.0";
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
export const redact = (s) =>
  s
    .replace(/Authorization:[^\r\n]*/gi, "Authorization: [REDACTED]")
    .replace(
      /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
      "[REDACTED JWT]",
    );
const json = (x) => JSON.stringify(x, null, 2) + "\n";
export function configureProject(original, kind, program) {
  const p = structuredClone(original);
  const contract = `https://127.0.0.1:19443/contracts/${kind}/1.0.0/openapi.json`;
  p.consultation.contract = contract;
  if (p.write) p.write.contract = contract;
  if (kind === "dhis2") {
    for (const route of p.templatedRoutes)
      if (route.parameters?.program) route.parameters.program = program;
  }
  return p;
}
export function configurePack(original, attribute) {
  if (!/^[A-Za-z][A-Za-z0-9]{10}$/.test(attribute))
    throw Error("invalid DHIS2 unique attribute UID");
  const p = structuredClone(original);
  for (const route of p.routeTemplates) {
    if (
      !["page-tracked-entities", "page-tracked-entities-by-org-unit"].includes(
        route.id,
      )
    )
      continue;
    route.readSupport.order = [
      { name: "created-at", direction: "descending" },
      { name: "unique-attribute", direction: "ascending" },
    ];
    route.readSupport.uniqueTieBreaker = "unique-attribute";
    for (const step of route.steps)
      if (step.to?.parameters?.query?.order)
        step.to.parameters.query.order.constant = `createdAt:desc,${attribute}:asc`;
  }
  return p;
}
export function extendNativeProject(text) {
  for (const [from, to] of [
    [
      "    mutationMode: mutable\n",
      "    mutationMode: mutable\n    batch: {maximumItems: 1, maximumBytes: 8192}\n",
    ],
    [
      "      - {id: jurisdiction, type: string, required: true, minimumLength: 1, maximumLength: 40, classification: internal}\n",
      "      - {id: jurisdiction, type: string, required: true, minimumLength: 1, maximumLength: 40, classification: internal}\n      - {id: note, type: string, required: false, minimumLength: 1, maximumLength: 240, classification: internal}\n",
    ],
    [
      "operations: [create, get, list, patch]",
      "operations: [create, get, list, patch, batch]",
    ],
    [
      "readableFields: [name, email, jurisdiction]",
      "readableFields: [name, email, jurisdiction, note]",
    ],
    [
      "writableFields: [name, email, jurisdiction]",
      "writableFields: [name, email, jurisdiction, note]",
    ],
  ]) {
    if (!text.includes(from))
      throw Error(
        "generated BReg template changed; inspect before bootstrapping",
      );
    text = text.replace(from, to);
  }
  return text;
}
export function runtimeConfig(kind, state, origin) {
  return {
    apiVersion: "id.registrystack.org/formats/adapter/runtime/v1alpha1",
    kind: "AdapterRuntimeConfig",
    id: `wg-${kind}-demo`,
    secretProviders: { file: { root: join(state, "secrets") } },
    endpoints: [
      {
        endpoint: kind === "dhis2" ? "tracker" : "registry",
        baseUrl: origin,
        credential:
          kind === "dhis2"
            ? {
                type: "basic",
                usernameRef: "secret:file/dhis2-username",
                passwordRef: "secret:file/dhis2-password",
              }
            : {
                type: "static-authorization",
                tokenRef: "secret:file/breg-source-token",
              },
      },
    ],
    listener: { bind: `127.0.0.1:${kind === "dhis2" ? 18110 : 18111}` },
    database: {
      runtimeUrlRef: `secret:file/${kind}-database`,
      migrationUrlRef: `secret:file/${kind}-database`,
      testOnlyPlaintext: true,
    },
    oidc: {
      issuer: "http://127.0.0.1:18109",
      audience: "registry-adapter-wg-demo",
      allowInsecureHttp: true,
      jwksSource: { type: "static", documentRef: "secret:file/facade-jwks" },
    },
    allowedClients: ["wg-demo-client"],
    allowedPrivateCidrs: ["192.168.0.0/16"],
    audit: { retentionDays: 90 },
    idempotency: { responseRetentionSeconds: 86400 },
    cursorKeyRef: `secret:file/${kind}-cursor`,
  };
}
async function exists(path) {
  try {
    await access(path);
    return true;
  } catch (e) {
    if (e.code === "ENOENT") return false;
    throw e;
  }
}
async function privateWrite(path, data) {
  const temporary =
    path + "." + process.pid + "." + randomBytes(6).toString("hex") + ".tmp";
  try {
    await writeFile(temporary, data, { mode: 0o600, flag: "wx" });
    await rename(temporary, path);
  } finally {
    try {
      await unlink(temporary);
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
    }
  }
}
export async function privateJson(path) {
  let handle;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const m = await handle.stat();
    if (
      !m.isFile() ||
      m.mode & 0o077 ||
      m.uid !== process.getuid() ||
      m.nlink !== 1 ||
      m.size > 262144
    )
      throw Error(
        "private configuration needs an owner-only single-link regular file",
      );
    const contents = await handle.readFile("utf8");
    try {
      return JSON.parse(contents);
    } catch {
      throw Error("private configuration is not valid JSON");
    }
  } catch (e) {
    if (e.code === "ELOOP")
      throw Error("private configuration must not be a symlink");
    throw e;
  } finally {
    await handle?.close();
  }
}
async function run(binary, args, env = process.env, input) {
  try {
    if (input !== undefined) {
      return await new Promise((ok, no) => {
        const p = spawn(binary, args, { env, stdio: ["pipe", "pipe", "pipe"] });
        let stdout = "",
          stderr = "";
        p.stdout.on("data", (x) => (stdout += x));
        p.stderr.on("data", (x) => (stderr += x));
        p.on("error", no);
        p.on("close", (code) =>
          code === 0
            ? ok(stdout)
            : no(
                Error(
                  `${binary.split("/").pop()} failed (${code}); inspect local prerequisites`,
                ),
              ),
        );
        p.stdin.end(input);
      });
    }
    const r = await exec(binary, args, {
      env,
      maxBuffer: 16 * 1024 * 1024,
      timeout: 240000,
    });
    return r.stdout;
  } catch (e) {
    // Do not forward external command output: it may contain source credentials.
    throw Error(
      `${binary.split("/").pop()} ${args[0] || ""} failed; inspect local prerequisites`,
      { cause: e },
    );
  }
}
async function waitFor(
  label,
  check,
  seconds = 90,
  stopped = async () => false,
) {
  for (let i = 0; i < seconds; i++) {
    if (await stopped()) throw Error(`${label} exited before readiness`);
    try {
      if (await check()) return;
    } catch {
      /* readiness retries are bounded; final error is visible */
    }
    await pause(1000);
  }
  throw Error(`${label} did not become ready within ${seconds}s`);
}
async function available(port) {
  await new Promise((ok, no) => {
    const s = createServer();
    s.once("error", () =>
      no(
        Error(
          `loopback port ${port} is occupied; leave the other service running`,
        ),
      ),
    );
    s.listen(port, "127.0.0.1", () => s.close(ok));
  });
}
async function main() {
  const [command = "status", ...argv] = process.argv.slice(2);
  const opts = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!["--state", "--repo", "--target"].includes(argv[i]) || !argv[i + 1])
      throw Error(
        "usage: control.mjs start|status|test|stop --state PATH --repo PATH --target PATH",
      );
    opts[argv[i].slice(2)] = resolve(argv[i + 1]);
  }
  const repo = opts.repo || resolve(here, "../../../..");
  const target =
    opts.target || "/Volumes/CodexWorktrees/targets/adapter-consultation";
  const state =
    opts.state ||
    process.env.WG_DEMO_STATE ||
    "/Volumes/CodexWorktrees/targets/govstack-wg-demo-state";
  if (
    !isAbsolute(state) ||
    state === "/" ||
    state === repo ||
    state === target ||
    state.startsWith(target + "/")
  )
    throw Error(
      "demo state must be an absolute directory outside the checkout and Cargo target",
    );
  const marker = join(state, "owner.json");
  if (!(await exists(marker))) {
    if (command !== "start") throw Error("demo has not been started");
    if (await exists(state))
      throw Error("state directory exists without this demo owner marker");
    await mkdir(state, { mode: 0o700, recursive: true });
    await privateWrite(marker, json({ kind: "govstack-wg-demo", repo }));
  }
  const owner = await privateJson(marker);
  if (owner.kind !== "govstack-wg-demo" || owner.repo !== repo)
    throw Error("demo state belongs to another checkout");
  const m = await lstat(state);
  if (m.isSymbolicLink() || m.uid !== process.getuid() || m.mode & 0o077)
    throw Error("state directory must be owner-only");
  for (const d of ["secrets", "logs", "contracts", "projects"])
    await mkdir(join(state, d), { recursive: true, mode: 0o700 });
  const env = Object.fromEntries(
    [
      "HOME",
      "PATH",
      "TMPDIR",
      "LANG",
      "LC_ALL",
      "USER",
      "LOGNAME",
      "DOCKER_HOST",
      "DOCKER_CONTEXT",
      "REGISTRY_CARGO_RUNTIME_LIBRARY_PATH",
      "DYLD_FALLBACK_LIBRARY_PATH",
    ]
      .filter((k) => process.env[k] !== undefined)
      .map((k) => [k, process.env[k]]),
  );
  const runtimePath = join(state, "cargo-runtime-path");
  if (env.REGISTRY_CARGO_RUNTIME_LIBRARY_PATH)
    await privateWrite(runtimePath, env.REGISTRY_CARGO_RUNTIME_LIBRARY_PATH);
  if (await exists(runtimePath)) {
    const path = (await readFile(runtimePath, "utf8")).trim();
    env.REGISTRY_CARGO_RUNTIME_LIBRARY_PATH = path;
    env.DYLD_FALLBACK_LIBRARY_PATH = path;
  }
  const bin = (n) => join(target, "debug", n);
  const docker = (await run("which", ["docker"], env)).trim();
  const native = join(state, "breg-project");
  const container =
    "govstack-wg-adapter-" +
    createHash("sha256").update(state).digest("hex").slice(0, 12);
  const pidFile = join(state, "processes.json");
  const pids = (await exists(pidFile)) ? await privateJson(pidFile) : {};
  async function alive(name) {
    const pid = pids[name];
    if (!pid) return false;
    try {
      process.kill(pid, 0);
    } catch (e) {
      if (e.code === "ESRCH") return false;
      throw e;
    }
    const cmd = await run("ps", ["-p", String(pid), "-o", "command="], env);
    if (!cmd.includes(state))
      throw Error(`${name} PID was reused; refusing to signal it`);
    return true;
  }
  async function launch(name, binary, args) {
    if (await alive(name)) return;
    const log = await open(join(state, "logs", name + ".log"), "a", 0o600);
    const child = spawn(binary, args, {
      env,
      detached: true,
      stdio: ["ignore", log.fd, log.fd],
    });
    const closed = new Promise((r) => child.once("close", r));
    await new Promise((ok, no) => {
      child.once("spawn", ok);
      child.once("error", no);
    });
    await log.close();
    pids[name] = child.pid;
    try {
      await privateWrite(pidFile, json(pids));
    } catch (e) {
      child.kill("SIGTERM");
      await closed;
      throw e;
    }
    child.unref();
  }
  if (command === "stop") {
    for (const name of ["adapter-dhis2", "adapter-breg", "issuer"])
      if (await alive(name)) {
        process.kill(pids[name], "SIGTERM");
        await waitFor(`${name} stop`, async () => !(await alive(name)), 20);
      }
    if (await exists(native))
      await run(
        bin("bregctl"),
        ["--format", "json", "dev", "stop", "--docker-bin", docker, native],
        env,
      );
    const found = await run(
      docker,
      [
        "ps",
        "-a",
        "--filter",
        `name=^/${container}$`,
        "--format",
        "{{.Names}}",
      ],
      env,
    );
    if (found.trim() === container) {
      const label = await run(
        docker,
        [
          "inspect",
          "--format",
          '{{index .Config.Labels "org.registrystack.wg-demo"}}',
          container,
        ],
        env,
      );
      if (label.trim() !== state)
        throw Error("database container is not owned by this demo");
      await run(docker, ["stop", container], env);
    }
    console.log("Owned demo services stopped; state and records retained.");
    return;
  }
  if (command === "start") {
    for (const [port, name] of [
      [19443, "issuer"],
      [18109, "issuer"],
      [18110, "adapter-dhis2"],
      [18111, "adapter-breg"],
    ])
      if (!(await alive(name))) await available(port);
    let config;
    const sourceFile =
      process.env.WG_DHIS2_SOURCE_CONFIG || join(state, "public-source.json");
    if (await exists(sourceFile)) config = await privateJson(sourceFile);
    else if (process.env.DHIS2_USERNAME && process.env.DHIS2_PASSWORD)
      config = {
        origin: "https://play.im.dhis2.org/stable-2-43-2-1",
        program: "WSGAb5XwJ3Y",
        tieBreakerAttribute: "lZGmxYbs97q",
        username: process.env.DHIS2_USERNAME,
        password: process.env.DHIS2_PASSWORD,
      };
    else
      throw Error(
        "first start needs DHIS2_USERNAME and DHIS2_PASSWORD from https://dhis2.org/demo/, or WG_DHIS2_SOURCE_CONFIG pointing to an owner-only JSON file",
      );
    const sourceUrl = new URL(config.origin);
    if (
      sourceUrl.protocol !== "https:" ||
      sourceUrl.hostname !== "play.im.dhis2.org" ||
      sourceUrl.username ||
      sourceUrl.password ||
      sourceUrl.search ||
      sourceUrl.hash
    )
      throw Error(
        "this rehearsal only permits the public DHIS2 demo over HTTPS",
      );
    if (!config.username || !config.password)
      throw Error("DHIS2 demo credentials are required");
    const selection = {
      origin: config.origin,
      program: config.program,
      tieBreakerAttribute: config.tieBreakerAttribute,
    };
    const selectionPath = join(state, "source-selection.json");
    if (
      (await exists(selectionPath)) &&
      json(await privateJson(selectionPath)) !== json(selection)
    )
      throw Error(
        "source selection changed; use fresh WG_DEMO_STATE to regenerate the pinned project",
      );
    await privateWrite(selectionPath, json(selection));
    await privateWrite(join(state, "public-source.json"), json(config));
    for (const [name, value] of [
      ["dhis2-username", config.username],
      ["dhis2-password", config.password],
    ])
      await privateWrite(join(state, "secrets", name), value);
    const passwordFile = join(state, "secrets", "database-password");
    if (!(await exists(passwordFile)))
      await privateWrite(passwordFile, randomBytes(24).toString("hex"));
    const password = await readFile(passwordFile, "utf8");
    const found = await run(
      docker,
      [
        "ps",
        "-a",
        "--filter",
        `name=^/${container}$`,
        "--format",
        "{{.Names}}",
      ],
      env,
    );
    if (!found.trim()) {
      await available(18115);
      await run(
        docker,
        [
          "run",
          "-d",
          "--name",
          container,
          "--label",
          `org.registrystack.wg-demo=${state}`,
          "-p",
          "127.0.0.1:18115:5432",
          "--env",
          "POSTGRES_PASSWORD",
          "--env",
          "POSTGRES_USER=adapter",
          "--env",
          "POSTGRES_DB=postgres",
          IMAGE,
        ],
        { ...env, POSTGRES_PASSWORD: password },
      );
    } else {
      const label = await run(
        docker,
        [
          "inspect",
          "--format",
          '{{index .Config.Labels "org.registrystack.wg-demo"}}',
          container,
        ],
        env,
      );
      if (label.trim() !== state)
        throw Error("database container is not owned by this demo");
      await run(docker, ["start", container], env);
    }
    await waitFor("Adapter PostgreSQL", async () => {
      await run(
        docker,
        ["exec", container, "pg_isready", "-U", "adapter"],
        env,
      );
      return true;
    });
    for (const kind of ["dhis2", "breg"]) {
      const db = "adapter_" + kind;
      const result = await run(
        docker,
        [
          "exec",
          container,
          "psql",
          "-U",
          "adapter",
          "-d",
          "postgres",
          "-Atc",
          `SELECT 1 FROM pg_database WHERE datname='${db}'`,
        ],
        env,
      );
      if (result.trim() !== "1")
        await run(
          docker,
          ["exec", container, "createdb", "-U", "adapter", db],
          env,
        );
      await privateWrite(
        join(state, "secrets", kind + "-database"),
        `postgresql://adapter:${password}@127.0.0.1:18115/${db}`,
      );
      if (!(await exists(join(state, "secrets", kind + "-cursor"))))
        await privateWrite(
          join(state, "secrets", kind + "-cursor"),
          randomBytes(32),
        );
    }
    if (!(await exists(native))) {
      await run(bin("bregctl"), ["--format", "json", "init", native], env);
    }
    const nativeConfigured = join(state, "native-configured.json");
    if (!(await exists(nativeConfigured))) {
      const path = join(native, "registry.yaml");
      await privateWrite(
        path,
        extendNativeProject(await readFile(path, "utf8")),
      );
      await privateWrite(nativeConfigured, json({ version: 1 }));
    }
    console.log("Starting retained local BReg source...");
    await run(
      bin("bregctl"),
      [
        "--format",
        "json",
        "dev",
        "start",
        "--breg-bin",
        bin("breg"),
        "--docker-bin",
        docker,
        "--breg-port",
        "18112",
        "--issuer-port",
        "18113",
        "--database-port",
        "18114",
        native,
      ],
      env,
    );
    for (const kind of ["dhis2", "breg"]) {
      const project = join(state, "projects", kind);
      const source = join(
        repo,
        "products/adapter/examples",
        kind === "dhis2" ? "dhis2-consultation" : "breg-govstack",
      );
      if (!(await exists(project))) {
        await cp(source, project, { recursive: true });
        const p = JSON.parse(
          await run("yq", ["-o=json", ".", join(project, "project.yaml")], env),
        );
        await privateWrite(
          join(project, "project.yaml"),
          json(configureProject(p, kind, config.program)),
        );
        const packSource = join(
          repo,
          "products/adapter/packs",
          kind === "dhis2" ? "dhis2-tracker" : "breg-records",
        );
        const packDir = join(project, "source-pack");
        await cp(packSource, packDir, { recursive: true });
        if (kind === "dhis2") {
          const pack = JSON.parse(
            await run("yq", ["-o=json", ".", join(packDir, "pack.yaml")], env),
          );
          await privateWrite(
            join(packDir, "pack.yaml"),
            json(configurePack(pack, config.tieBreakerAttribute)),
          );
        }
      }
      const pack = join(project, "source-pack/pack.yaml");
      // The authoring reader accepts JSON, but the lock tool rewrites block YAML.
      for (const path of [join(project, "project.yaml"), pack]) {
        const value = await run("yq", ["-o=json", ".", path], env);
        await privateWrite(
          path,
          await run("yq", ["-p=json", "-o=yaml", ".", "-"], env, value),
        );
      }
      await run(
        bin("adapterctl"),
        ["project", "lock", project, "--pack", pack],
        env,
      );
      await run(
        bin("adapterctl"),
        [
          "compile",
          project,
          "--pack",
          pack,
          "--output",
          join(state, "contracts", kind + ".json"),
        ],
        env,
      );
      await privateWrite(
        join(state, kind + "-runtime.yaml"),
        json(
          runtimeConfig(
            kind,
            state,
            kind === "dhis2" ? config.origin : "http://127.0.0.1:18112",
          ),
        ),
      );
    }
    if (!(await exists(join(state, "tls-key.pem")))) {
      await run(
        "openssl",
        [
          "req",
          "-x509",
          "-newkey",
          "rsa:2048",
          "-nodes",
          "-keyout",
          join(state, "tls-key.pem"),
          "-out",
          join(state, "tls-cert.pem"),
          "-days",
          "30",
          "-subj",
          "/CN=localhost",
          "-addext",
          "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        env,
      );
      await chmod(join(state, "tls-key.pem"), 0o600);
    }
    await launch("issuer", process.execPath, [
      join(here, "demo-server.mjs"),
      "--state",
      state,
      "--breg-project",
      native,
      "--bregctl",
      bin("bregctl"),
      "--port",
      "18109",
      "--tls-port",
      "19443",
      "--tls-key",
      join(state, "tls-key.pem"),
      "--tls-cert",
      join(state, "tls-cert.pem"),
    ]);
    await waitFor("demo issuer", async () => {
      const r = await fetch("http://127.0.0.1:18109/health");
      return r.ok && (await r.json()).status === "ready";
    });
    if (!(await exists(join(state, "secrets", "facade-jwks"))))
      throw Error(
        "demo issuer public key file is unavailable; stop then start to refresh the issuer",
      );
    for (const kind of ["dhis2", "breg"]) {
      const project = join(state, "projects", kind);
      await launch("adapter-" + kind, bin("adapter"), [
        "serve",
        "--runtime-config",
        join(state, kind + "-runtime.yaml"),
        "--project",
        project,
        "--pack",
        join(project, "source-pack/pack.yaml"),
      ]);
      await waitFor(
        kind + " Adapter",
        async () => {
          const r = await fetch(
            `http://127.0.0.1:${kind === "dhis2" ? 18110 : 18111}/govstack/registries/v1/collections/${kind === "dhis2" ? "people" : "contacts"}/records/test`,
          );
          return r.status === 401;
        },
        90,
        async () => !(await alive("adapter-" + kind)),
      );
    }
    console.log(
      "Checking live DHIS2 Consultation through Adapter (read only)...",
    );
    const tokenResponse = await fetch("http://127.0.0.1:18109/demo/token", {
      signal: AbortSignal.timeout(5000),
    });
    if (!tokenResponse.ok) throw Error("demo caller token unavailable");
    const accessToken = (await tokenResponse.json()).access_token;
    const consultation = await fetch(
      "http://127.0.0.1:18110/govstack/registries/v1/collections/people-summary/records?pageSize=1",
      {
        headers: { Authorization: "Bearer " + accessToken },
        signal: AbortSignal.timeout(30000),
      },
    );
    if (!consultation.ok)
      throw Error(
        `live DHIS2 Consultation preflight returned HTTP ${consultation.status}`,
      );
    const page = await consultation.json();
    if (!Array.isArray(page.items) || page.items.length === 0)
      throw Error("live DHIS2 Consultation returned no demo records");
    console.log("Live DHIS2 Consultation ready.");
    const cli = join(state, "bruno-cli");
    if (!(await exists(join(cli, "node_modules/@usebruno/cli/bin/bru.js")))) {
      console.log(`Preparing pinned Bruno CLI ${CLI_VERSION}...`);
      await run(
        "npm",
        [
          "install",
          "--prefix",
          cli,
          "--no-audit",
          "--no-fund",
          "--ignore-scripts",
          `@usebruno/cli@${CLI_VERSION}`,
        ],
        env,
      );
    }
    await privateWrite(
      join(state, "identity.json"),
      json({
        sourceHead: (
          await run(
            "git",
            ["--no-optional-locks", "-C", repo, "rev-parse", "HEAD"],
            env,
          )
        ).trim(),
        sourceWorkingTreeDirty: Boolean(
          (
            await run(
              "git",
              ["--no-optional-locks", "-C", repo, "status", "--porcelain"],
              env,
            )
          ).trim(),
        ),
        binarySha256: Object.fromEntries(
          await Promise.all(
            ["adapter", "adapterctl", "breg", "bregctl"].map(async (name) => [
              name,
              createHash("sha256")
                .update(await readFile(bin(name)))
                .digest("hex"),
            ]),
          ),
        ),
        buildFeatures: [
          "registry-breg/runtime",
          "registry-adapter/postgres-test",
        ],
        startedAt: new Date().toISOString(),
        brunoCliVersion: CLI_VERSION,
        publicSource: config.origin,
      }),
    );
  }
  if (command === "test") {
    const executable = join(state, "bruno-cli/node_modules/.bin/bru");
    console.log("Rehearsing live DHIS2 Read and local BReg Write in Bruno...");
    const result = await new Promise((ok, no) => {
      const child = spawn(
        executable,
        ["run", "--env", "LocalExample", "--bail"],
        { cwd: join(here, "bruno"), env, stdio: ["ignore", "pipe", "pipe"] },
      );
      let output = "";
      child.stdout.on("data", (x) => (output += x));
      child.stderr.on("data", (x) => (output += x));
      child.on("error", no);
      child.on("close", (code) => ok({ code, output }));
    });
    const safe = redact(result.output).replace(/\x1b\[[0-9;]*m/g, "");
    // Persist only test summaries, never full request/response or credentials.
    const lines = safe
      .split("\n")
      .filter((x) =>
        /^(?:[│├┼┤┌┐└┘─┬┴]|.*(?:AssertionError|expected |Request Error|Error:))/.test(
          x,
        ),
      )
      .slice(-40);
    await privateWrite(
      join(state, "last-rehearsal.json"),
      json({
        at: new Date().toISOString(),
        exitCode: result.code,
        summary: lines,
      }),
    );
    for (const line of lines) console.log(line);
    if (result.code !== 0)
      throw Error(
        "Bruno rehearsal failed; no public DHIS2 writes were attempted",
      );
    console.log("Bruno rehearsal passed.");
    return;
  }
  if (!["start", "status"].includes(command)) throw Error("unknown command");
  const health = await fetch("http://127.0.0.1:18109/health", {
    signal: AbortSignal.timeout(3000),
  })
    .then((r) => r.json())
    .catch(() => ({ status: "unreachable" }));
  console.log(
    `Demo issuer: ${health.status}; source token refresh: ${health.sourceTokenRefresh?.status || "unavailable"}`,
  );
  for (const name of ["issuer", "adapter-dhis2", "adapter-breg"])
    console.log(`${name}: ${(await alive(name)) ? "running" : "stopped"}`);
  console.log(`Bruno collection: ${join(here, "bruno")}`);
  console.log(`Private retained state: ${state}`);
  if (
    health.status !== "ready" ||
    !(await alive("adapter-dhis2")) ||
    !(await alive("adapter-breg"))
  )
    throw Error("demo is not ready; run start");
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  main().catch((e) => {
    console.error(`Demo: ${redact(e.message)}`);
    process.exitCode = 1;
  });
