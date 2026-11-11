#!/usr/bin/env node
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign,
  verify,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function decodeJson(value, label) {
  try {
    return JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  } catch {
    throw new Error(`the access token ${label} is not JSON`);
  }
}

const connectAddress = process.env.IDENTITY_CONNECT_ADDRESS;
if (connectAddress && !isIP(connectAddress)) {
  throw new Error("IDENTITY_CONNECT_ADDRESS must be an IPv4 or IPv6 address");
}
const connectPort = process.env.IDENTITY_CONNECT_PORT;
if (connectPort && (!/^\d+$/.test(connectPort) || Number(connectPort) > 65535)) {
  throw new Error("IDENTITY_CONNECT_PORT must be a TCP port");
}

function requestJson(url, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const options = { method, headers };
    if (connectPort) options.port = Number(connectPort);
    if (connectAddress) {
      options.lookup = (_hostname, lookupOptions, callback) => {
        const family = isIP(connectAddress);
        if (lookupOptions.all) {
          callback(null, [{ address: connectAddress, family }]);
          return;
        }
        callback(null, connectAddress, family);
      };
    }
    const request = httpsRequest(url, options, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > 1024 * 1024) {
          request.destroy(new Error("OIDC response exceeds 1 MiB"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        const status = response.statusCode ?? 0;
        let document;
        try {
          document = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          reject(new Error(`OIDC endpoint returned non-JSON with status ${status}`));
          return;
        }
        resolve({ ok: status >= 200 && status < 300, status, document });
      });
    });
    request.on("error", reject);
    if (body) request.write(body);
    request.end();
  });
}

const issuer = required("IDENTITY_ISSUER").replace(/\/$/, "");
if (!issuer.startsWith("https://")) throw new Error("IDENTITY_ISSUER must use HTTPS");
const clientId = required("IDENTITY_CLIENT_ID");
const resource = required("IDENTITY_RESOURCE");
const scopes = required("IDENTITY_SCOPES");
const privateJwk = JSON.parse(await readFile(required("IDENTITY_PRIVATE_JWK_FILE"), "utf8"));
const algorithm = privateJwk.alg ?? "ES256";
if (algorithm !== "ES256") throw new Error("the qualification client must use ES256");
if (!privateJwk.kid) throw new Error("the qualification client JWK needs kid");

const discoveryResponse = await requestJson(`${issuer}/.well-known/openid-configuration`);
if (!discoveryResponse.ok) throw new Error(`OIDC discovery returned ${discoveryResponse.status}`);
const discovery = discoveryResponse.document;
if (discovery.issuer !== issuer) throw new Error("OIDC discovery issuer does not match exactly");
if (discovery.token_endpoint !== `${issuer}/oauth2/token`) {
  throw new Error("OIDC discovery returned an unexpected token endpoint");
}
if (discovery.jwks_uri !== `${issuer}/oauth2/jwks`) {
  throw new Error("OIDC discovery returned an unexpected JWKS endpoint");
}

const now = Math.floor(Date.now() / 1000);
const header = base64urlJson({ alg: algorithm, kid: privateJwk.kid, typ: "JWT" });
const payload = base64urlJson({
  iss: clientId,
  sub: clientId,
  aud: issuer,
  iat: now,
  exp: now + 60,
  jti: randomUUID(),
});
const signingInput = `${header}.${payload}`;
const assertionSignature = sign("sha256", Buffer.from(signingInput), {
  key: createPrivateKey({ key: privateJwk, format: "jwk" }),
  dsaEncoding: "ieee-p1363",
}).toString("base64url");

const request = new URLSearchParams({
  grant_type: "client_credentials",
  client_id: clientId,
  client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  client_assertion: `${signingInput}.${assertionSignature}`,
  resource,
  scope: scopes,
});
const tokenResponse = await requestJson(discovery.token_endpoint, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: request.toString(),
});
if (!tokenResponse.ok) throw new Error(`token endpoint returned ${tokenResponse.status}`);
const tokenDocument = tokenResponse.document;
if (tokenDocument.token_type !== "Bearer" || typeof tokenDocument.access_token !== "string") {
  throw new Error("token endpoint did not return a Bearer access token");
}

const tokenParts = tokenDocument.access_token.split(".");
if (tokenParts.length !== 3) throw new Error("access token is not a compact JWT");
const tokenHeader = decodeJson(tokenParts[0], "header");
const tokenClaims = decodeJson(tokenParts[1], "payload");
if (tokenHeader.alg !== "RS256") throw new Error("access token algorithm is not RS256");
const jwksResponse = await requestJson(discovery.jwks_uri);
if (!jwksResponse.ok) throw new Error(`JWKS endpoint returned ${jwksResponse.status}`);
const jwks = jwksResponse.document;
const signingJwk = jwks.keys?.find((key) => key.kid === tokenHeader.kid);
if (!signingJwk) throw new Error("access token kid is absent from the issuer JWKS");
if (
  signingJwk.kty !== "RSA" ||
  typeof signingJwk.e !== "string" ||
  typeof signingJwk.n !== "string"
) {
  throw new Error("access token signing JWK is not an RSA public key");
}
const signingThumbprint = createHash("sha256")
  .update(JSON.stringify({ e: signingJwk.e, kty: signingJwk.kty, n: signingJwk.n }))
  .digest("base64url");
const signatureValid = verify(
  "RSA-SHA256",
  Buffer.from(`${tokenParts[0]}.${tokenParts[1]}`),
  createPublicKey({ key: signingJwk, format: "jwk" }),
  Buffer.from(tokenParts[2], "base64url"),
);
if (!signatureValid) throw new Error("access token signature is invalid");
if (tokenClaims.iss !== issuer) throw new Error("access token issuer does not match exactly");
const audiences = Array.isArray(tokenClaims.aud) ? tokenClaims.aud : [tokenClaims.aud];
if (!audiences.includes(resource)) throw new Error("access token audience does not include the resource");
if (!Number.isInteger(tokenClaims.exp) || tokenClaims.exp <= now) {
  throw new Error("access token is already expired or has no integer expiry");
}

const clientClaimName = ["client_id", "azp"].find((name) => name in tokenClaims) ?? "absent";
const audienceFormat = Array.isArray(tokenClaims.aud) ? "array" : typeof tokenClaims.aud;
console.log(
  `OIDC qualification passed for ${issuer}; signed resource token expires in ${tokenClaims.exp - now}s; ` +
    `header alg=${tokenHeader.alg}, typ=${tokenHeader.typ ?? "absent"}; ` +
    `client claim=${clientClaimName}; aud format=${audienceFormat}; ` +
    `signing JWK thumbprint=${signingThumbprint}.`,
);
