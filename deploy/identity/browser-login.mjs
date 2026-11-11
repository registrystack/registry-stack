#!/usr/bin/env node
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const appKitProject = required("APPKIT_PROJECT");
const live = required("APPKIT_LIVE_URL").replace(/\/$/, "");
if (!live.startsWith("https://")) throw new Error("APPKIT_LIVE_URL must use HTTPS");
const expectedIssuer = required("APPKIT_EXPECTED_ISSUER").replace(/\/$/, "");
if (!expectedIssuer.startsWith("https://")) {
  throw new Error("APPKIT_EXPECTED_ISSUER must use HTTPS");
}
const password = (await readFile(required("APPKIT_SYNTHETIC_PASSWORD_FILE"), "utf8")).trim();
const username = process.env.APPKIT_SYNTHETIC_USERNAME ?? "qualification-officer";
const expectedRole = process.env.APPKIT_EXPECTED_ROLE ?? "contact-editor";
const retainedRecordIds = (process.env.APPKIT_RETAINED_RECORD_IDS ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const requireFromAppKit = createRequire(`${appKitProject}/package.json`);
const { chromium } = requireFromAppKit("@playwright/test");
const args = [];
const spki = process.env.APPKIT_TLS_SPKI;
if (spki) args.push(`--ignore-certificate-errors-spki-list=${spki}`);
const hostResolverRules = process.env.APPKIT_HOST_RESOLVER_RULES;
if (hostResolverRules) args.push(`--host-resolver-rules=${hostResolverRules}`);
const proxyServer = process.env.APPKIT_PROXY_SERVER;
const browser = await chromium.launch({
  headless: process.env.HEADED !== "1",
  args,
  ...(proxyServer ? { proxy: { server: proxyServer } } : {}),
});
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(15_000);
  await page.goto(`${live}/staff/`);
  const anonymousModelStatus = await page.evaluate(async () =>
    fetch("/api/model").then((response) => response.status),
  );
  if (anonymousModelStatus !== 401) {
    throw new Error(`anonymous App Kit model request returned ${anonymousModelStatus}, expected 401`);
  }
  await page.getByRole("link", { name: "Sign in", exact: true }).click();
  await page.waitForURL((url) => url.origin === expectedIssuer);
  await page.getByRole("textbox", { name: /username/i }).fill(username);
  await page.locator("input[type=password]").fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  try {
    await page.waitForURL(`${live}/staff/**`);
  } catch {
    throw new Error("OIDC sign-in did not complete the App Kit callback");
  }
  const session = await page.evaluate(async () => {
    const response = await fetch("/api/session");
    if (!response.ok) throw new Error(`App Kit session endpoint returned ${response.status}`);
    return response.json();
  });
  if (session.authenticated !== true) throw new Error("App Kit session is not authenticated");
  if (session.role !== expectedRole) {
    throw new Error(`App Kit session role is ${session.role ?? "absent"}, expected ${expectedRole}`);
  }
  const authenticatedModelStatus = await page.evaluate(async () =>
    fetch("/api/model").then((response) => response.status),
  );
  if (authenticatedModelStatus !== 200) {
    throw new Error(`authenticated App Kit model request returned ${authenticatedModelStatus}`);
  }
  if (retainedRecordIds.length > 0) {
    let journey;
    try {
      journey = await page.evaluate(
        async ({ recordIds, csrfToken }) => {
          const retainedStatuses = [];
          for (const id of recordIds) {
            const response = await fetch(
              `/api/entities/contact/records/${encodeURIComponent(id)}`,
            );
            retainedStatuses.push(response.status);
          }

          const list = await fetch("/api/entities/contact/records");
          const page = list.ok ? await list.json() : undefined;
          const create = page?.actions?.find((action) => action.name === "create");
          if (!create?.ref) {
            return { retainedStatuses, listStatus: list.status };
          }
          const send = (jurisdiction, suffix) =>
            fetch("/api/tasks", {
              method: "POST",
              headers: {
                "content-type": "application/json",
                "x-csrf-token": csrfToken,
              },
              body: JSON.stringify({
                attemptId: crypto.randomUUID(),
                task: {
                  type: "create",
                  entity: "contact",
                  actionRef: create.ref,
                  values: {
                    name: `Qualification restored ${suffix} contact`,
                    email: `qualification-restored-${suffix.toLowerCase()}-${Date.now()}@example.invalid`,
                    jurisdiction,
                  },
                },
              }),
            });

          const allowed = await send("zone-a", "Zone-A");
          const allowedResult = allowed.ok ? await allowed.json() : undefined;
          const createdId = allowedResult?.resource?.id;
          const createdRead = createdId
            ? await fetch(`/api/entities/contact/records/${encodeURIComponent(createdId)}`)
            : undefined;
          const denied = await send("zone-b", "Zone-B");
          return {
            retainedStatuses,
            listStatus: list.status,
            allowedStatus: allowed.status,
            createdId,
            createdReadStatus: createdRead?.status,
            deniedStatus: denied.status,
          };
        },
        { recordIds: retainedRecordIds, csrfToken: session.csrfToken },
      );
    } catch {
      throw new Error("Restored-record browser journey did not complete");
    }
    if (journey.retainedStatuses?.some((status) => status !== 200)) {
      throw new Error("A retained contact record was not readable after restore");
    }
    if (journey.listStatus !== 200) {
      throw new Error("The restored contact list was not readable");
    }
    if (journey.allowedStatus !== 200 || !journey.createdId) {
      throw new Error("The permitted same-jurisdiction contact write was not confirmed");
    }
    if (journey.createdReadStatus !== 200) {
      throw new Error("The permitted contact was not readable after creation");
    }
    if (journey.deniedStatus !== 403) {
      throw new Error("The cross-jurisdiction contact write was not denied with 403");
    }
    console.log(
      `Browser OIDC restore qualification passed; retained records read: ${retainedRecordIds.join(", ")}; ` +
        `created and read permitted record ${journey.createdId}; cross-jurisdiction write denied with 403.`,
    );
  } else {
    console.log(
      "Browser OIDC qualification passed; App Kit established a synthetic human session; " +
        "anonymous model access was denied and authenticated model access was allowed.",
    );
  }
  await context.close();
} finally {
  await browser.close();
}
