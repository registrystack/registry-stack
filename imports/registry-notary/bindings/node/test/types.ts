import {
  NotaryError,
  NotaryProblemError,
  NotaryTransportError,
  RegistryNotaryClient,
  RetryPolicy,
} from "../src/index.js";

const retryPolicy: Partial<RetryPolicy> = {
  maxAttempts: 2,
  retryUnavailable: true,
};

const client = new RegistryNotaryClient({
  baseUrl: "https://notary.example",
  bearerToken: "token",
  defaultPurpose: "benefits_eligibility",
  retryPolicy,
});

const highLevel: Promise<unknown> = client.evaluate({
  subject: { id: "subj-0000001", idType: "NATIONAL_ID" },
  claims: [{ id: "date-of-birth", version: "2026-05-29" }],
});

const raw: Promise<unknown> = client.evaluateRequest(
  {
    subject: { id: "subj-0000001", id_type: "NATIONAL_ID" },
    claims: ["date-of-birth"],
  },
  { purpose: "benefits_eligibility" },
);

const batch: Promise<unknown> = client.batchEvaluate(
  {
    subjects: [{ id: "subj-0000001", idType: "NATIONAL_ID" }],
    claims: ["date-of-birth"],
  },
  { idempotencyKey: "batch-2026-05-29-001" },
);

const claims: Promise<unknown> = client.listClaims({ requestId: "req-1" });
const claim: Promise<unknown> = client.getClaim("date-of-birth");
const rendered: Promise<unknown> = client.renderRequest({ evaluation_id: "eval-1", format: "json" });
const issued: Promise<unknown> = client.issueCredentialRequest({ subject: { id: "subj-0000001" } });
const status: Promise<unknown> = client.credentialStatus("cred-1");
const serviceDocument: Promise<unknown> = client.serviceDocument();
const jwks: Promise<unknown> = client.issuerJwks();
const refreshedJwks: Promise<unknown> = client.refreshJwks();
const jwk: Promise<Record<string, unknown> | undefined> = client.getJwk("key-1");
const oidMetadata: Promise<unknown> = client.oid4vciIssuerMetadata();
const oidOffer: Promise<unknown> = client.oid4vciCredentialOffer("config one");
const oidNonce: Promise<unknown> = client.oid4vciNonce();
const oidCredential: Promise<unknown> = client.oid4vciCredential({ proof: { jwt: "jwt" } });
const federation: Promise<string> = client.federationEvaluateJws("request.jws.compact");

const errors: NotaryError[] = [
  new NotaryError("client-side failure"),
  new NotaryTransportError(),
  new NotaryProblemError({ status: 404, code: "source.not_found", title: "Source record not found" }),
];

void highLevel;
void raw;
void batch;
void claims;
void claim;
void rendered;
void issued;
void status;
void serviceDocument;
void jwks;
void refreshedJwks;
void jwk;
void oidMetadata;
void oidOffer;
void oidNonce;
void oidCredential;
void federation;
void errors;
