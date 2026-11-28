// Source SHA-256 5f474bc27c918a57e56cd83314bbc6907a370925b1e6d287e3121a67b59a272e
import { type Transport, type Answer, type CallOptions, type JsonValue, type Operation, type Page, type RequestValues, type ResponseVariant, type WireBytes, type WireText } from "../core.ts"
import { validator } from "../schema.ts"

export type Schema_CredentialOffer = ({ "credential_configuration_ids": (Array<(string)>); "credential_issuer": (string); "grants": ({ "urn:ietf:params:oauth:grant-type:pre-authorized_code": Schema_PreAuthorizedCodeGrant }) })
export type Schema_Draft13CredentialOffer = ({ "credential_configuration_ids": (Array<(string)>); "credential_issuer": (string); "grants": ({ "urn:ietf:params:oauth:grant-type:pre-authorized_code": Schema_Draft13PreAuthorizedCodeGrant }) })
export type Schema_Draft13OfferResponse = ({ "credentialOffer": Schema_Draft13CredentialOffer; "credentialOfferUri": (string); "expiresIn": (number); "transactionCode"?: (string) })
export type Schema_Draft13PreAuthorizedCodeGrant = ({ "pre-authorized_code": (string); "tx_code"?: Schema_TransactionCodeDescription; "user_pin_required"?: false })
export type Schema_OfferRequest = ({ "credentialConfigurationId": (string); "subjects": (Array<Schema_RequestedSubject>); "transactionCode"?: (boolean) })
export type Schema_OfferResponse = ({ "credentialOffer": Schema_CredentialOffer; "credentialOfferUri": (string); "expiresIn": (number); "transactionCode"?: (string) })
export type Schema_PreAuthorizedCodeGrant = ({ "pre-authorized_code": (string); "tx_code"?: Schema_TransactionCodeDescription })
export type Schema_Problem = ({ "error": ("invalid_request" | "invalid_token" | "unsupported_grant_type" | "invalid_grant" | "invalid_credential_request" | "invalid_proof" | "invalid_nonce" | "credential_request_denied" | "temporarily_unavailable" | "server_error"); "error_description": (string) })
export type Schema_RequestedSubject = ({ "role": (string); "selectorValues"?: (Record<string, (string | number | boolean)>) })
export type Schema_TransactionCodeDescription = ({ "input_mode": "numeric"; "length": 6 })

export interface Operations {
  "createCredentialOffer": { input: CallOptions & ({ body: Schema_OfferRequest }) & { accept?: "application/json" | "*/*" }; required: true; output: Schema_OfferResponse }
  "createDraft13CredentialOffer": { input: CallOptions & ({ body: Schema_OfferRequest }) & { accept?: "application/json" | "*/*" }; required: true; output: Schema_Draft13OfferResponse }
}

const rules: Record<string, unknown> = Object.fromEntries([
  ["/components/schemas/CredentialOffer", JSON.parse("{\"additionalProperties\":false,\"properties\":{\"credential_configuration_ids\":{\"items\":{\"type\":\"string\"},\"maxItems\":1,\"minItems\":1,\"type\":\"array\"},\"credential_issuer\":{\"type\":\"string\"},\"grants\":{\"additionalProperties\":false,\"properties\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"$ref\":\"/components/schemas/PreAuthorizedCodeGrant\"}},\"required\":[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"],\"type\":\"object\"}},\"required\":[\"credential_issuer\",\"credential_configuration_ids\",\"grants\"],\"type\":\"object\"}")],
  ["/components/schemas/Draft13CredentialOffer", JSON.parse("{\"additionalProperties\":false,\"properties\":{\"credential_configuration_ids\":{\"items\":{\"type\":\"string\"},\"maxItems\":1,\"minItems\":1,\"type\":\"array\"},\"credential_issuer\":{\"type\":\"string\"},\"grants\":{\"additionalProperties\":false,\"properties\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"$ref\":\"/components/schemas/Draft13PreAuthorizedCodeGrant\"}},\"required\":[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"],\"type\":\"object\"}},\"required\":[\"credential_issuer\",\"credential_configuration_ids\",\"grants\"],\"type\":\"object\"}")],
  ["/components/schemas/Draft13OfferResponse", JSON.parse("{\"additionalProperties\":false,\"properties\":{\"credentialOffer\":{\"$ref\":\"/components/schemas/Draft13CredentialOffer\"},\"credentialOfferUri\":{\"type\":\"string\"},\"expiresIn\":{\"maximum\":900,\"minimum\":60,\"type\":\"integer\"},\"transactionCode\":{\"pattern\":\"^[0-9]{6}$\",\"type\":\"string\"}},\"required\":[\"credentialOffer\",\"credentialOfferUri\",\"expiresIn\"],\"type\":\"object\"}")],
  ["/components/schemas/Draft13PreAuthorizedCodeGrant", JSON.parse("{\"additionalProperties\":false,\"properties\":{\"pre-authorized_code\":{\"type\":\"string\"},\"tx_code\":{\"$ref\":\"/components/schemas/TransactionCodeDescription\"},\"user_pin_required\":{\"const\":false}},\"required\":[\"pre-authorized_code\"],\"type\":\"object\"}")],
  ["/components/schemas/OfferRequest", JSON.parse("{\"additionalProperties\":false,\"properties\":{\"credentialConfigurationId\":{\"type\":\"string\"},\"subjects\":{\"items\":{\"$ref\":\"/components/schemas/RequestedSubject\"},\"maxItems\":8,\"minItems\":1,\"type\":\"array\"},\"transactionCode\":{\"type\":\"boolean\"}},\"required\":[\"credentialConfigurationId\",\"subjects\"],\"type\":\"object\"}")],
  ["/components/schemas/OfferResponse", JSON.parse("{\"additionalProperties\":false,\"properties\":{\"credentialOffer\":{\"$ref\":\"/components/schemas/CredentialOffer\"},\"credentialOfferUri\":{\"type\":\"string\"},\"expiresIn\":{\"maximum\":900,\"minimum\":60,\"type\":\"integer\"},\"transactionCode\":{\"pattern\":\"^[0-9]{6}$\",\"type\":\"string\"}},\"required\":[\"credentialOffer\",\"credentialOfferUri\",\"expiresIn\"],\"type\":\"object\"}")],
  ["/components/schemas/PreAuthorizedCodeGrant", JSON.parse("{\"additionalProperties\":false,\"properties\":{\"pre-authorized_code\":{\"type\":\"string\"},\"tx_code\":{\"$ref\":\"/components/schemas/TransactionCodeDescription\"}},\"required\":[\"pre-authorized_code\"],\"type\":\"object\"}")],
  ["/components/schemas/Problem", JSON.parse("{\"additionalProperties\":false,\"properties\":{\"error\":{\"enum\":[\"invalid_request\",\"invalid_token\",\"unsupported_grant_type\",\"invalid_grant\",\"invalid_credential_request\",\"invalid_proof\",\"invalid_nonce\",\"credential_request_denied\",\"temporarily_unavailable\",\"server_error\"]},\"error_description\":{\"type\":\"string\"}},\"required\":[\"error\",\"error_description\"],\"type\":\"object\"}")],
  ["/components/schemas/RequestedSubject", JSON.parse("{\"additionalProperties\":false,\"properties\":{\"role\":{\"pattern\":\"^[a-z][a-z0-9._-]{0,63}$\",\"type\":\"string\"},\"selectorValues\":{\"additionalProperties\":{\"type\":[\"string\",\"integer\",\"boolean\"]},\"maxProperties\":16,\"type\":\"object\"}},\"required\":[\"role\"],\"type\":\"object\"}")],
  ["/components/schemas/TransactionCodeDescription", JSON.parse("{\"additionalProperties\":false,\"properties\":{\"input_mode\":{\"const\":\"numeric\"},\"length\":{\"const\":6}},\"required\":[\"input_mode\",\"length\"],\"type\":\"object\"}")],
  ["/paths/~1offers/post/responses/201/content/application~1json/schema", JSON.parse("{\"$ref\":\"/components/schemas/OfferResponse\"}")],
  ["/paths/~1protocol~1oid4vci~1draft-13~1offers/post/responses/201/content/application~1json/schema", JSON.parse("{\"$ref\":\"/components/schemas/Draft13OfferResponse\"}")],
])
const routes: Record<string, Operation> = Object.create(null)
type Definition = Omit<Operation, "responses"> & { problems?: Record<string, string>; responses: Record<number, Array<ResponseVariant & { rule?: string }>> }
const definitions: Record<string, Definition> = Object.fromEntries([
  ["createCredentialOffer", JSON.parse("{\"method\":\"POST\",\"path\":\"/offers\",\"responses\":{\"201\":[{\"mediaType\":\"application/json\",\"mode\":\"json\",\"rule\":\"/paths/~1offers/post/responses/201/content/application~1json/schema\"}]},\"keyed\":false,\"mutating\":true,\"requestMediaTypes\":[\"application/json\"],\"requestMediaType\":\"application/json\"}")],
  ["createDraft13CredentialOffer", JSON.parse("{\"method\":\"POST\",\"path\":\"/protocol/oid4vci/draft-13/offers\",\"responses\":{\"201\":[{\"mediaType\":\"application/json\",\"mode\":\"json\",\"rule\":\"/paths/~1protocol~1oid4vci~1draft-13~1offers/post/responses/201/content/application~1json/schema\"}]},\"keyed\":false,\"mutating\":true,\"requestMediaTypes\":[\"application/json\"],\"requestMediaType\":\"application/json\"}")],
])
for (const [id, definition] of Object.entries(definitions)) {
  const responses: Operation["responses"] = {}
  for (const [status, variants] of Object.entries(definition.responses)) {
    responses[Number(status)] = variants.map(variant => ({ ...variant, validate: variant.rule === undefined ? undefined : validator(rules, rules[variant.rule]) }))
  }
  routes[id] = { ...definition, product: "evidence-oid4vci", responses, problemValidators: Object.fromEntries(Object.entries(definition.problems ?? {}).map(([status, rule]) => [status, validator(rules, rules[rule])])) }
}

export class Client {
  readonly #transport: Transport
  constructor(transport: Transport) { this.#transport = transport }
  async call<K extends keyof Operations>(operation: K, ...args: Operations[K]["required"] extends true ? [Operations[K]["input"]] : [Operations[K]["input"]?]): Promise<Answer<Operations[K]["output"]>> {
    return this.#call(operation, args[0])
  }
  #call<T>(operation: string, options: RequestValues = {}): Promise<Answer<T>> {
    const route = routes[operation]
    if (!route) throw new TypeError("Unknown operation")
    return this.#transport.call(route, options)
  }
}
