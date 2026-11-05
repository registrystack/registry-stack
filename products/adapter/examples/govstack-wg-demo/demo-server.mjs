#!/usr/bin/env node

import { execFile as execFileCallback } from "node:child_process";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  unlink,
} from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFile = promisify(execFileCallback);

export const ISSUER = "http://127.0.0.1:18109";
export const AUDIENCE = "registry-adapter-wg-demo";
export const CLIENT_ID = "wg-demo-client";
export const SUBJECT = "wg-demo-presenter";
export const TOKEN_LIFETIME_SECONDS = 48 * 60 * 60;

const KEY_ID = "wg-demo-key";
const SCOPES = "records.read records.write";
const MAX_PRIVATE_FILE_BYTES = 64 * 1024;
const DEFAULT_REFRESH_INTERVAL_MS = 60_000;
const CONTRACT_PATHS = new Map([
  ["/contracts/dhis2/1.0.0/openapi.json", "dhis2.json"],
  ["/contracts/breg/1.0.0/openapi.json", "breg.json"],
]);

class DemoServerError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "DemoServerError";
    this.code = code;
  }
}

function defaultLog(entry) {
  process.stderr.write(`${JSON.stringify(entry)}\n`);
}

async function ensurePrivateDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new DemoServerError(
      "private state path is not a directory",
      "private-state-invalid",
    );
  }
  await chmod(path, 0o700);
}

async function readPrivateRegularFile(path) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    throw new DemoServerError(
      "private file is not a regular file",
      "private-file-invalid",
    );
  }
  if ((metadata.mode & 0o077) !== 0) {
    throw new DemoServerError(
      "private file is accessible to other users",
      "private-file-mode",
    );
  }
  if (
    typeof process.getuid === "function" &&
    metadata.uid !== process.getuid()
  ) {
    throw new DemoServerError(
      "private file has a different owner",
      "private-file-owner",
    );
  }
  if (metadata.size > MAX_PRIVATE_FILE_BYTES) {
    throw new DemoServerError(
      "private file exceeds the size limit",
      "private-file-size",
    );
  }
  return readFile(path);
}

async function atomicWritePrivate(path, bytes) {
  const parent = dirname(path);
  await ensurePrivateDirectory(parent);
  const temporaryPath = join(
    parent,
    `.${basename(path)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`,
  );
  let handle;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await chmod(temporaryPath, 0o600);
    await rename(temporaryPath, path);
    await chmod(path, 0o600);
  } catch (error) {
    if (handle !== undefined) {
      await handle.close().catch(() => {});
    }
    await unlink(temporaryPath).catch(() => {});
    throw error;
  }
}

async function loadOrCreateSigningKey(stateDir) {
  const secretsDir = join(stateDir, "secrets");
  await ensurePrivateDirectory(secretsDir);
  const keyPath = join(secretsDir, `${KEY_ID}.pem`);
  let privatePem;
  try {
    privatePem = await readPrivateRegularFile(keyPath);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
    const generated = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicExponent: 0x10001,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    privatePem = Buffer.from(generated.privateKey);
    await atomicWritePrivate(keyPath, privatePem);
  }

  const privateKey = createPrivateKey(privatePem);
  if (privateKey.asymmetricKeyType !== "rsa") {
    throw new DemoServerError("signing key is not RSA", "signing-key-invalid");
  }
  const details = privateKey.asymmetricKeyDetails;
  if (details?.modulusLength !== undefined && details.modulusLength < 2048) {
    throw new DemoServerError(
      "signing key is shorter than 2048 bits",
      "signing-key-invalid",
    );
  }
  const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
  return {
    privateKey,
    jwks: {
      keys: [{ ...publicJwk, kid: KEY_ID, use: "sig", alg: "RS256" }],
    },
  };
}

function mintAccessToken(
  privateKey,
  nowSeconds = Math.floor(Date.now() / 1000),
) {
  const header = { alg: "RS256", typ: "at+jwt", kid: KEY_ID };
  const claims = {
    iss: ISSUER,
    aud: AUDIENCE,
    client_id: CLIENT_ID,
    sub: SUBJECT,
    scope: SCOPES,
    iat: nowSeconds,
    nbf: nowSeconds,
    exp: nowSeconds + TOKEN_LIFETIME_SECONDS,
  };
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
    "base64url",
  );
  const encodedClaims = Buffer.from(JSON.stringify(claims)).toString(
    "base64url",
  );
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const signature = sign(
    "RSA-SHA256",
    Buffer.from(signingInput),
    privateKey,
  ).toString("base64url");
  return `${signingInput}.${signature}`;
}

function discoveryDocument() {
  return {
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/jwks`,
    token_endpoint: `${ISSUER}/demo/token`,
    grant_types_supported: ["client_credentials"],
    token_endpoint_auth_methods_supported: ["none"],
    response_types_supported: ["token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
  };
}

function sendJson(response, statusCode, value, extraHeaders = {}) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": body.length,
    ...extraHeaders,
  });
  response.end(body);
}

function sendNotFound(response) {
  sendJson(response, 404, { error: "not_found" });
}

function parseBearerHeader(bytes) {
  const text = bytes.toString("ascii");
  const match = /^Authorization: Bearer ([!-~]+)\r?\n?$/.exec(text);
  if (match === null || match[1].includes(" ")) {
    throw new DemoServerError(
      "BReg header file is malformed",
      "breg-header-invalid",
    );
  }
  return match[1];
}

function tokenExpiry(token) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return undefined;
  }
  try {
    const claims = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    );
    return Number.isSafeInteger(claims.exp) ? claims.exp : undefined;
  } catch {
    return undefined;
  }
}

export function bregctlChildEnvironment(environment = process.env) {
  const childEnvironment = { ...environment };
  const runtimeLibraries = environment.REGISTRY_CARGO_RUNTIME_LIBRARY_PATH;
  if (runtimeLibraries !== undefined && runtimeLibraries !== "") {
    childEnvironment.DYLD_FALLBACK_LIBRARY_PATH = runtimeLibraries;
  }
  return childEnvironment;
}

export async function refreshBregSourceToken({
  stateDir,
  bregProject,
  bregctl,
  log = defaultLog,
}) {
  try {
    if (!isAbsolute(bregctl)) {
      throw new DemoServerError(
        "bregctl path must be absolute",
        "bregctl-path-invalid",
      );
    }
    const executable = await lstat(bregctl);
    if (!executable.isFile() || executable.isSymbolicLink()) {
      throw new DemoServerError(
        "bregctl is not a regular file",
        "bregctl-path-invalid",
      );
    }

    const childEnvironment = bregctlChildEnvironment();
    const { stdout } = await execFile(
      bregctl,
      ["--format", "json", "dev", "token", "editor", bregProject],
      {
        env: childEnvironment,
        encoding: "utf8",
        maxBuffer: MAX_PRIVATE_FILE_BYTES,
        timeout: 30_000,
      },
    );
    const report = JSON.parse(stdout);
    if (
      report === null ||
      typeof report !== "object" ||
      report.ok !== true ||
      report.command !== "dev token" ||
      typeof report.headerFile !== "string" ||
      !isAbsolute(report.headerFile)
    ) {
      throw new DemoServerError(
        "bregctl returned invalid metadata",
        "bregctl-report-invalid",
      );
    }
    const token = parseBearerHeader(
      await readPrivateRegularFile(report.headerFile),
    );
    const tokenPath = join(stateDir, "secrets", "breg-source-token");
    await atomicWritePrivate(tokenPath, Buffer.from(token, "ascii"));
    log({ event: "source-token-refresh", status: "ok" });
    return { status: "ok", expiresAt: tokenExpiry(token) };
  } catch {
    log({ event: "source-token-refresh", status: "failed" });
    throw new DemoServerError(
      "BReg source token refresh failed",
      "source-token-refresh-failed",
    );
  }
}

function refreshDelay(expiresAt, refreshIntervalMs) {
  if (expiresAt === undefined) {
    return refreshIntervalMs;
  }
  const millisecondsUntilSafetyMargin = expiresAt * 1000 - Date.now() - 30_000;
  return Math.max(
    1_000,
    Math.min(refreshIntervalMs, millisecondsUntilSafetyMargin),
  );
}

function listen(server, port) {
  return new Promise((resolveListen, rejectListen) => {
    const onError = (error) => {
      server.off("listening", onListening);
      rejectListen(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolveListen(server.address().port);
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, "127.0.0.1");
  });
}

function closeServer(server) {
  if (server === undefined || !server.listening) {
    return Promise.resolve();
  }
  return new Promise((resolveClose, rejectClose) => {
    server.close((error) =>
      error === undefined ? resolveClose() : rejectClose(error),
    );
  });
}

export async function startDemoServer({
  stateDir,
  bregProject,
  bregctl,
  port = 18109,
  tlsPort,
  tlsKey,
  tlsCert,
  noRefresh = false,
  refreshIntervalMs = DEFAULT_REFRESH_INTERVAL_MS,
  log = defaultLog,
}) {
  if (typeof stateDir !== "string" || stateDir === "") {
    throw new DemoServerError("state directory is required", "state-required");
  }
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new DemoServerError("HTTP port is invalid", "port-invalid");
  }
  const tlsOptions = [tlsPort, tlsKey, tlsCert];
  if (
    tlsOptions.some((value) => value !== undefined) &&
    tlsOptions.some((value) => value === undefined)
  ) {
    throw new DemoServerError(
      "TLS port, key, and certificate must be supplied together",
      "tls-incomplete",
    );
  }
  if (
    tlsPort !== undefined &&
    (!Number.isInteger(tlsPort) || tlsPort < 1 || tlsPort > 65_535)
  ) {
    throw new DemoServerError("TLS port is invalid", "tls-port-invalid");
  }
  if (
    !noRefresh &&
    (typeof bregProject !== "string" || typeof bregctl !== "string")
  ) {
    throw new DemoServerError(
      "BReg project and bregctl are required",
      "breg-refresh-config-required",
    );
  }

  await ensurePrivateDirectory(stateDir);
  const signing = await loadOrCreateSigningKey(stateDir);
  let refreshState = noRefresh ? "disabled" : "starting";
  let latestExpiry;
  if (!noRefresh) {
    try {
      const refreshed = await refreshBregSourceToken({
        stateDir,
        bregProject,
        bregctl,
        log,
      });
      refreshState = "ok";
      latestExpiry = refreshed.expiresAt;
    } catch {
      throw new DemoServerError(
        "initial BReg source token refresh failed",
        "initial-source-token-refresh-failed",
      );
    }
  }

  const handler = async (request, response) => {
    try {
      if (request.method !== "GET") {
        response.setHeader("Allow", "GET");
        sendJson(response, 405, { error: "method_not_allowed" });
        return;
      }
      const pathname = new URL(request.url, ISSUER).pathname;
      if (pathname === "/health") {
        sendJson(response, 200, {
          status: refreshState === "retrying" ? "degraded" : "ready",
          sourceTokenRefresh: { status: refreshState },
        });
        return;
      }
      if (pathname === "/.well-known/openid-configuration") {
        sendJson(response, 200, discoveryDocument());
        return;
      }
      if (pathname === "/jwks" || pathname === "/jwks.json") {
        sendJson(response, 200, signing.jwks);
        return;
      }
      if (pathname === "/demo/token") {
        sendJson(
          response,
          200,
          {
            access_token: mintAccessToken(signing.privateKey),
            token_type: "Bearer",
            expires_in: TOKEN_LIFETIME_SECONDS,
          },
          { "Cache-Control": "no-store" },
        );
        return;
      }
      const contractFile = CONTRACT_PATHS.get(pathname);
      if (contractFile !== undefined) {
        try {
          const body = await readFile(
            join(stateDir, "contracts", contractFile),
          );
          response.writeHead(200, {
            "Content-Type": "application/json",
            "Content-Length": body.length,
          });
          response.end(body);
        } catch {
          sendNotFound(response);
        }
        return;
      }
      sendNotFound(response);
    } catch {
      sendJson(response, 500, { error: "internal_error" });
    }
  };

  const httpServer = createHttpServer(handler);
  let httpsServer;
  let httpPort;
  let actualTlsPort;
  try {
    httpPort = await listen(httpServer, port);
    if (tlsPort !== undefined) {
      const [key, cert] = await Promise.all([
        readPrivateRegularFile(tlsKey),
        readFile(tlsCert),
      ]);
      httpsServer = createHttpsServer({ key, cert }, handler);
      actualTlsPort = await listen(httpsServer, tlsPort);
    }
  } catch (error) {
    await Promise.allSettled([
      closeServer(httpServer),
      closeServer(httpsServer),
    ]);
    throw error;
  }

  let refreshTimer;
  let closed = false;
  const scheduleRefresh = () => {
    if (closed || noRefresh) {
      return;
    }
    refreshTimer = setTimeout(
      async () => {
        try {
          const refreshed = await refreshBregSourceToken({
            stateDir,
            bregProject,
            bregctl,
            log,
          });
          latestExpiry = refreshed.expiresAt;
          refreshState = "ok";
        } catch {
          refreshState = "retrying";
        }
        scheduleRefresh();
      },
      refreshDelay(latestExpiry, refreshIntervalMs),
    );
    refreshTimer.unref();
  };
  scheduleRefresh();

  let closePromise;
  const close = () => {
    if (closePromise !== undefined) {
      return closePromise;
    }
    closed = true;
    clearTimeout(refreshTimer);
    closePromise = Promise.all([
      closeServer(httpServer),
      closeServer(httpsServer),
    ]).then(() => undefined);
    return closePromise;
  };

  log({
    event: "demo-server",
    status: "ready",
    httpPort,
    ...(actualTlsPort === undefined ? {} : { tlsPort: actualTlsPort }),
  });
  return { httpPort, tlsPort: actualTlsPort, close };
}

export function parseArgs(argv) {
  const options = { port: 18109, noRefresh: false };
  const valueOptions = new Map([
    ["--state", "stateDir"],
    ["--breg-project", "bregProject"],
    ["--bregctl", "bregctl"],
    ["--port", "port"],
    ["--tls-port", "tlsPort"],
    ["--tls-key", "tlsKey"],
    ["--tls-cert", "tlsCert"],
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--no-refresh") {
      options.noRefresh = true;
      continue;
    }
    const property = valueOptions.get(argument);
    if (property === undefined || index + 1 >= argv.length) {
      throw new DemoServerError("invalid command line", "arguments-invalid");
    }
    const value = argv[index + 1];
    if (property === "port" || property === "tlsPort") {
      if (!/^\d+$/.test(value)) {
        throw new DemoServerError("invalid command line", "arguments-invalid");
      }
      options[property] = Number(value);
    } else {
      options[property] = value;
    }
    index += 1;
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const server = await startDemoServer(options);
  let stopping = false;
  const stop = async () => {
    if (stopping) {
      return;
    }
    stopping = true;
    defaultLog({ event: "demo-server", status: "stopping" });
    await server.close();
    defaultLog({ event: "demo-server", status: "stopped" });
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch((error) => {
    defaultLog({
      event: "demo-server",
      status: "failed",
      reason: error instanceof DemoServerError ? error.code : "internal-error",
    });
    process.exitCode = 1;
  });
}
