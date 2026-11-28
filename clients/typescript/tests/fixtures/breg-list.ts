// Source SHA-256 84879cb95b7489ced99fad88fb61fbb7e3d800015d9624d6694d455c39d98c9f
import { Transport, type Answer, type CallOptions, type ClientOptions, type JsonValue, type Operation, type Page, type RequestValues, type ResponseVariant, type WireBytes, type WireText } from "../../core.ts"
import { validator } from "../../schema.ts"
import { listPage, listQuery, type FieldValue, type Filter, type ListPage, type ListRequest, type ListRules } from "../../core.ts"

export type Schema_Licence = ({ "domainData": ({ "holderId"?: (string); "holderName"?: (string); "licenceNumber"?: (string); "region"?: ("north" | "east" | "south" | "west") & (string); "status"?: ("active" | "suspended" | "expired") & (string); "expiresOn"?: (string); "fee"?: (number); "suspendedOn"?: (string | null) }); "recordIdentifier": (string); "revisionIdentifier": (string) })
export type Schema_LicencePage = ({ "count"?: (number); "items": (Array<Schema_Licence>); "pageInfo": ({ "nextCursor": (string | null) }) })
export type Schema_Site = ({ "domainData": ({ "label"?: (string); "siteCode"?: (string) }); "recordIdentifier": (string); "revisionIdentifier": (string) })
export type Schema_SitePage = ({ "items": (Array<Schema_Site>); "pageInfo": ({ "nextCursor": (string | null) }) })

export interface Operations {
  "records.licence.list": { input: CallOptions & { query?: { "accessProfile"?: "licence-holder" | "licence-officer"; "$select"?: (string); "$filter"?: (string); "$orderby"?: (string); "$top"?: (number); "$count"?: (boolean); "$skiptoken"?: (string) } } & { accept?: "application/json" | "*/*" }; required: false; output: Schema_LicencePage }
  "records.site.list": { input: CallOptions & { query?: { "$select"?: (string); "$filter"?: (string); "$orderby"?: (string); "$top"?: (number); "$skiptoken"?: (string) } } & { accept?: "application/json" | "*/*" }; required: false; output: Schema_SitePage }
}

// The row each list returns, and the list options its query profiles allow.
export interface ListRows {
  "records.licence.list": Schema_Licence
  "records.site.list": Schema_Site
}
export interface ListOptions {
  "records.licence.list": (CallOptions & { accessProfile: "licence-holder"; where: ({ "holderId": FieldValue<ListRows["records.licence.list"], "holderId"> } | { "licenceNumber": FieldValue<ListRows["records.licence.list"], "licenceNumber">; "status": FieldValue<ListRows["records.licence.list"], "status"> }) & { "holderId"?: Filter<FieldValue<ListRows["records.licence.list"], "holderId">, "equals">; "licenceNumber"?: Filter<FieldValue<ListRows["records.licence.list"], "licenceNumber">, "equals" | "in">; "status"?: Filter<FieldValue<ListRows["records.licence.list"], "status">, "equals"> }; orderBy?: never; select?: ReadonlyArray<"licenceNumber" | "status">; count?: never; top?: number }) | (CallOptions & { accessProfile: "licence-officer"; where?: { "expiresOn"?: Filter<FieldValue<ListRows["records.licence.list"], "expiresOn">, "range">; "fee"?: Filter<FieldValue<ListRows["records.licence.list"], "fee">, "equals" | "range">; "holderName"?: Filter<FieldValue<ListRows["records.licence.list"], "holderName">, "prefix" | "contains">; "region"?: Filter<FieldValue<ListRows["records.licence.list"], "region">, "equals" | "in">; "status"?: Filter<FieldValue<ListRows["records.licence.list"], "status">, "equals" | "in">; "suspendedOn"?: Filter<FieldValue<ListRows["records.licence.list"], "suspendedOn">, "is-null" | "is-not-null"> }; orderBy?: "expiresOn" | "holderName" | "holderName desc"; select?: ReadonlyArray<"expiresOn" | "fee" | "holderName" | "licenceNumber" | "region" | "status">; count?: boolean; top?: number })
  "records.site.list": (CallOptions & { accessProfile?: never; where?: { "siteCode"?: Filter<FieldValue<ListRows["records.site.list"], "siteCode">, "equals"> }; orderBy?: "label"; select?: ReadonlyArray<"label" | "siteCode">; count?: never; top?: number })
}
const listRules: Record<string, ListRules> = JSON.parse("{\"records.licence.list\":{\"accessProfileParameter\":true,\"profiles\":{\"licence-holder\":{\"maximumPageSize\":20,\"allowCount\":false,\"selectable\":[\"licenceNumber\",\"status\"],\"filterable\":{\"holderId\":[\"equals\"],\"licenceNumber\":[\"equals\",\"in\"],\"status\":[\"equals\"]},\"sortable\":{},\"requiredFilters\":[[\"holderId\"],[\"licenceNumber\",\"status\"]]},\"licence-officer\":{\"maximumPageSize\":50,\"allowCount\":true,\"selectable\":[\"expiresOn\",\"fee\",\"holderName\",\"licenceNumber\",\"region\",\"status\"],\"filterable\":{\"expiresOn\":[\"range\"],\"fee\":[\"equals\",\"range\"],\"holderName\":[\"prefix\",\"contains\"],\"region\":[\"equals\",\"in\"],\"status\":[\"equals\",\"in\"],\"suspendedOn\":[\"is-null\",\"is-not-null\"]},\"sortable\":{\"expiresOn\":[\"asc\"],\"holderName\":[\"asc\",\"desc\"]}}}},\"records.site.list\":{\"accessProfileParameter\":false,\"profiles\":{\"site-planner\":{\"maximumPageSize\":10,\"allowCount\":false,\"selectable\":[\"label\",\"siteCode\"],\"filterable\":{\"siteCode\":[\"equals\"]},\"sortable\":{\"label\":[\"asc\"]}}}}}")

const rules: Record<string, unknown> = Object.fromEntries([
  ["/components/schemas/Licence", JSON.parse("{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"domainData\",\"recordIdentifier\",\"revisionIdentifier\"],\"properties\":{\"domainData\":{\"type\":\"object\",\"additionalProperties\":false,\"properties\":{\"holderId\":{\"type\":\"string\"},\"holderName\":{\"type\":\"string\",\"maxLength\":160},\"licenceNumber\":{\"type\":\"string\",\"maxLength\":40},\"region\":{\"type\":\"string\",\"enum\":[\"north\",\"east\",\"south\",\"west\"]},\"status\":{\"type\":\"string\",\"enum\":[\"active\",\"suspended\",\"expired\"]},\"expiresOn\":{\"type\":\"string\"},\"fee\":{\"type\":\"integer\",\"minimum\":0},\"suspendedOn\":{\"type\":[\"string\",\"null\"]}}},\"recordIdentifier\":{\"type\":\"string\"},\"revisionIdentifier\":{\"type\":\"string\"}}}")],
  ["/components/schemas/LicencePage", JSON.parse("{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"items\",\"pageInfo\"],\"properties\":{\"count\":{\"type\":\"integer\",\"minimum\":0},\"items\":{\"type\":\"array\",\"items\":{\"$ref\":\"/components/schemas/Licence\"}},\"pageInfo\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"nextCursor\"],\"properties\":{\"nextCursor\":{\"type\":[\"string\",\"null\"],\"maxLength\":10978}}}}}")],
  ["/components/schemas/Site", JSON.parse("{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"domainData\",\"recordIdentifier\",\"revisionIdentifier\"],\"properties\":{\"domainData\":{\"type\":\"object\",\"additionalProperties\":false,\"properties\":{\"label\":{\"type\":\"string\"},\"siteCode\":{\"type\":\"string\"}}},\"recordIdentifier\":{\"type\":\"string\"},\"revisionIdentifier\":{\"type\":\"string\"}}}")],
  ["/components/schemas/SitePage", JSON.parse("{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"items\",\"pageInfo\"],\"properties\":{\"items\":{\"type\":\"array\",\"items\":{\"$ref\":\"/components/schemas/Site\"}},\"pageInfo\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"nextCursor\"],\"properties\":{\"nextCursor\":{\"type\":[\"string\",\"null\"],\"maxLength\":10978}}}}}")],
  ["/paths/~1v1~1records~1licences/get/responses/200/content/application~1json/schema", JSON.parse("{\"$ref\":\"/components/schemas/LicencePage\"}")],
  ["/paths/~1v1~1records~1sites/get/responses/200/content/application~1json/schema", JSON.parse("{\"$ref\":\"/components/schemas/SitePage\"}")],
])
const routes: Record<string, Operation> = Object.create(null)
type Definition = Omit<Operation, "responses"> & { problems?: Record<string, string>; responses: Record<number, Array<ResponseVariant & { rule?: string }>> }
const definitions: Record<string, Definition> = Object.fromEntries([
  ["records.licence.list", JSON.parse("{\"method\":\"GET\",\"path\":\"/v1/records/licences\",\"responses\":{\"200\":[{\"mediaType\":\"application/json\",\"mode\":\"json\",\"rule\":\"/paths/~1v1~1records~1licences/get/responses/200/content/application~1json/schema\"}]},\"keyed\":false,\"mutating\":false}")],
  ["records.site.list", JSON.parse("{\"method\":\"GET\",\"path\":\"/v1/records/sites\",\"responses\":{\"200\":[{\"mediaType\":\"application/json\",\"mode\":\"json\",\"rule\":\"/paths/~1v1~1records~1sites/get/responses/200/content/application~1json/schema\"}]},\"keyed\":false,\"mutating\":false}")],
])
for (const [id, definition] of Object.entries(definitions)) {
  const responses: Operation["responses"] = {}
  for (const [status, variants] of Object.entries(definition.responses)) {
    responses[Number(status)] = variants.map(variant => ({ ...variant, validate: variant.rule === undefined ? undefined : validator(rules, rules[variant.rule]) }))
  }
  routes[id] = { ...definition, responses, problemValidators: Object.fromEntries(Object.entries(definition.problems ?? {}).map(([status, rule]) => [status, validator(rules, rules[rule])])) }
}

export class Client {
  readonly #transport: Transport
  constructor(options: ClientOptions) { this.#transport = new Transport(options) }
  async call<K extends keyof Operations>(operation: K, ...args: Operations[K]["required"] extends true ? [Operations[K]["input"]] : [Operations[K]["input"]?]): Promise<Answer<Operations[K]["output"]>> {
    return this.#call(operation, args[0])
  }
  #call<T>(operation: string, options: RequestValues = {}): Promise<Answer<T>> {
    const route = routes[operation]
    if (!route) throw new TypeError("Unknown operation")
    return this.#transport.call(route, options)
  }
  async records_licence_listPage(options: Operations["records.licence.list"]["input"] = {}, cursor?: string): Promise<Page<Schema_Licence>> {
    const { data } = await this.call("records.licence.list", { ...options, query: cursor === undefined ? options.query : { accessProfile: options.query?.accessProfile, "$skiptoken": cursor } })
    return { items: data.items, nextCursor: data.pageInfo.nextCursor ?? null }
  }
  async records_site_listPage(options: Operations["records.site.list"]["input"] = {}, cursor?: string): Promise<Page<Schema_Site>> {
    const { data } = await this.call("records.site.list", { ...options, query: cursor === undefined ? options.query : { "$skiptoken": cursor } })
    return { items: data.items, nextCursor: data.pageInfo.nextCursor ?? null }
  }
  list<K extends keyof ListOptions>(operation: K, ...args: {} extends ListOptions[K] ? [options?: ListOptions[K], cursor?: string] : [options: ListOptions[K], cursor?: string]): Promise<ListPage<ListRows[K]>>
  async list(operation: string, options: ListRequest = {}, cursor?: string): Promise<ListPage<unknown>> {
    const rules = Object.hasOwn(listRules, operation) ? listRules[operation] : undefined
    if (!rules) throw new TypeError("Unknown list operation")
    const query = listQuery(rules, options, cursor)
    const { accessProfile, where, orderBy, select, count, top, ...call } = options
    const { data } = await this.#call<{ items: unknown[]; pageInfo: { nextCursor?: string | null }; count?: number }>(operation, { ...call, query })
    return listPage(data)
  }
}

// Every generated module exports this one factory name. The client it returns is typed to this
// registry's operations.
export function createRegistryClient(options: ClientOptions): Client {
  return new Client(options)
}

// Each Action's display text and inputs exactly as the source document declares them.
export const actionInputs = {} as const
