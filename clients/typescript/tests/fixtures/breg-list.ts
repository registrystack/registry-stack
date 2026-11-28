// Source SHA-256 d6cecd502062be04c49927fab37350294acbf11953092b7ad8e63df775b3c985
import { type Transport, type Answer, type CallOptions, type JsonValue, type Operation, type Page, type RequestValues, type ResponseVariant, type WireBytes, type WireText } from "../../core.ts"
import { validator } from "../../schema.ts"
import { listPage, listQuery, type FieldValue, type Filter, type ListPage, type ListRequest, type ListRules } from "../../core.ts"

export type Schema_Licence = ({ "domainData": ({ "holderId"?: (string); "holderName"?: (string); "licenceNumber"?: (string); "region"?: ("north" | "east" | "south" | "west") & (string); "status"?: ("active" | "suspended" | "expired") & (string); "expiresOn"?: (string); "fee"?: (number); "suspendedOn"?: (string | null) }); "recordIdentifier": (string); "revisionIdentifier": (string) })
export type Schema_LicencePage = ({ "count"?: (number); "items": (Array<Schema_Licence>); "pageInfo": ({ "nextCursor": (string | null) }) })
export type Schema_Site = ({ "domainData": ({ "label"?: (string); "siteCode"?: (string) }); "recordIdentifier": (string); "revisionIdentifier": (string) })
export type Schema_SitePage = ({ "items": (Array<Schema_Site>); "pageInfo": ({ "nextCursor": (string | null) }) })
export type Schema_Permit = ({ "domainData": ({ "label"?: (string); "permitCode"?: (string) }); "recordIdentifier": (string); "revisionIdentifier": (string) })
export type Schema_PermitPage = ({ "items": (Array<Schema_Permit>); "pageInfo": ({ "nextCursor": (string | null) }) })

export interface Operations {
  "records.licence.list": { input: CallOptions & { query?: { "accessProfile"?: "licence-holder" | "licence-officer"; "$select"?: (string); "$filter"?: (string); "$orderby"?: (string); "$top"?: (number); "$count"?: (boolean); "$skiptoken"?: (string) } } & { accept?: "application/json" | "*/*" }; required: false; output: Schema_LicencePage }
  "records.site.list": { input: CallOptions & { query?: { "$select"?: (string); "$filter"?: (string); "$orderby"?: (string); "$top"?: (number); "$skiptoken"?: (string) } } & { accept?: "application/json" | "*/*" }; required: false; output: Schema_SitePage }
  "records.permit.list": { input: CallOptions & { query?: { "accessProfile"?: "permit-clerk"; "$select"?: (string); "$filter"?: (string); "$orderby"?: (string); "$top"?: (number); "$skiptoken"?: (string) } } & { accept?: "application/json" | "*/*" }; required: false; output: Schema_PermitPage }
}

// The row each list returns, and the list options its query profiles allow.
export interface ListRows {
  "licence": Schema_Licence
  "site": Schema_Site
  "permit": Schema_Permit
}
export interface ListOptions {
  "licence": (CallOptions & { accessProfile?: "licence-holder"; where: ({ "holderId": FieldValue<ListRows["licence"], "holderId"> } | { "licenceNumber": FieldValue<ListRows["licence"], "licenceNumber">; "status": FieldValue<ListRows["licence"], "status"> }) & { "holderId"?: Filter<FieldValue<ListRows["licence"], "holderId">, "equals">; "licenceNumber"?: Filter<FieldValue<ListRows["licence"], "licenceNumber">, "equals" | "in">; "status"?: Filter<FieldValue<ListRows["licence"], "status">, "equals"> }; orderBy?: never; select?: ReadonlyArray<"licenceNumber" | "status">; count?: never; top?: number; after?: never }) | (CallOptions & { accessProfile?: "licence-holder"; after: string; where?: never; orderBy?: never; select?: never; count?: never; top?: never }) | (CallOptions & { accessProfile?: "licence-officer"; where?: { "expiresOn"?: Filter<FieldValue<ListRows["licence"], "expiresOn">, "range">; "fee"?: Filter<FieldValue<ListRows["licence"], "fee">, "equals" | "range">; "holderName"?: Filter<FieldValue<ListRows["licence"], "holderName">, "prefix" | "contains">; "region"?: Filter<FieldValue<ListRows["licence"], "region">, "equals" | "in">; "status"?: Filter<FieldValue<ListRows["licence"], "status">, "equals" | "in">; "suspendedOn"?: Filter<FieldValue<ListRows["licence"], "suspendedOn">, "is-null" | "is-not-null"> }; orderBy?: "expiresOn" | "holderName" | "holderName desc"; select?: ReadonlyArray<"expiresOn" | "fee" | "holderName" | "licenceNumber" | "region" | "status">; count?: boolean; top?: number; after?: never }) | (CallOptions & { accessProfile?: "licence-officer"; after: string; where?: never; orderBy?: never; select?: never; count?: never; top?: never })
  "site": (CallOptions & { accessProfile?: never; where?: { "siteCode"?: Filter<FieldValue<ListRows["site"], "siteCode">, "equals"> }; orderBy?: "label"; select?: ReadonlyArray<"label" | "siteCode">; count?: never; top?: number; after?: never }) | (CallOptions & { accessProfile?: never; after: string; where?: never; orderBy?: never; select?: never; count?: never; top?: never })
  "permit": (CallOptions & { accessProfile?: "permit-clerk"; where?: { "permitCode"?: Filter<FieldValue<ListRows["permit"], "permitCode">, "equals"> }; orderBy?: "label"; select?: ReadonlyArray<"label" | "permitCode">; count?: never; top?: number; after?: never }) | (CallOptions & { accessProfile?: "permit-clerk"; after: string; where?: never; orderBy?: never; select?: never; count?: never; top?: never })
}
const listRules: Record<string, ListRules & { operation: string }> = JSON.parse("{\"licence\":{\"operation\":\"records.licence.list\",\"requiresAccessProfile\":false,\"accessProfileParameter\":true,\"recordProperties\":[\"expiresOn\",\"fee\",\"holderId\",\"holderName\",\"licenceNumber\",\"region\",\"status\",\"suspendedOn\"],\"profiles\":{\"licence-holder\":{\"maximumPageSize\":20,\"allowCount\":false,\"selectable\":[\"licenceNumber\",\"status\"],\"filterable\":{\"holderId\":[\"equals\"],\"licenceNumber\":[\"equals\",\"in\"],\"status\":[\"equals\"]},\"sortable\":{},\"requiredFilters\":[[\"holderId\"],[\"licenceNumber\",\"status\"]]},\"licence-officer\":{\"maximumPageSize\":50,\"allowCount\":true,\"selectable\":[\"expiresOn\",\"fee\",\"holderName\",\"licenceNumber\",\"region\",\"status\"],\"filterable\":{\"expiresOn\":[\"range\"],\"fee\":[\"equals\",\"range\"],\"holderName\":[\"prefix\",\"contains\"],\"region\":[\"equals\",\"in\"],\"status\":[\"equals\",\"in\"],\"suspendedOn\":[\"is-null\",\"is-not-null\"]},\"sortable\":{\"expiresOn\":[\"asc\"],\"holderName\":[\"asc\",\"desc\"]}}}},\"site\":{\"operation\":\"records.site.list\",\"requiresAccessProfile\":false,\"accessProfileParameter\":false,\"recordProperties\":[\"label\",\"siteCode\"],\"profiles\":{\"site-planner\":{\"maximumPageSize\":10,\"allowCount\":false,\"selectable\":[\"label\",\"siteCode\"],\"filterable\":{\"siteCode\":[\"equals\"]},\"sortable\":{\"label\":[\"asc\"]}}}},\"permit\":{\"operation\":\"records.permit.list\",\"requiresAccessProfile\":true,\"accessProfileParameter\":true,\"recordProperties\":[\"label\",\"permitCode\"],\"profiles\":{\"permit-clerk\":{\"maximumPageSize\":10,\"allowCount\":false,\"selectable\":[\"label\",\"permitCode\"],\"filterable\":{\"permitCode\":[\"equals\"]},\"sortable\":{\"label\":[\"asc\"]}}}}}")

type RecordEnvelope = { recordIdentifier: string; revisionIdentifier: string; domainData: unknown }
export interface RecordRow<Data> { id: string; revision: string; data: Data }
function recordRow<Data>(record: RecordEnvelope & { domainData: Data }): RecordRow<Data> {
  return { id: record.recordIdentifier, revision: record.revisionIdentifier, data: record.domainData }
}

const rules: Record<string, unknown> = Object.fromEntries([
  ["/components/schemas/Licence", JSON.parse("{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"domainData\",\"recordIdentifier\",\"revisionIdentifier\"],\"properties\":{\"domainData\":{\"type\":\"object\",\"additionalProperties\":false,\"properties\":{\"holderId\":{\"type\":\"string\"},\"holderName\":{\"type\":\"string\",\"maxLength\":160},\"licenceNumber\":{\"type\":\"string\",\"maxLength\":40},\"region\":{\"type\":\"string\",\"enum\":[\"north\",\"east\",\"south\",\"west\"]},\"status\":{\"type\":\"string\",\"enum\":[\"active\",\"suspended\",\"expired\"]},\"expiresOn\":{\"type\":\"string\"},\"fee\":{\"type\":\"integer\",\"minimum\":0},\"suspendedOn\":{\"type\":[\"string\",\"null\"]}}},\"recordIdentifier\":{\"type\":\"string\"},\"revisionIdentifier\":{\"type\":\"string\"}}}")],
  ["/components/schemas/LicencePage", JSON.parse("{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"items\",\"pageInfo\"],\"properties\":{\"count\":{\"type\":\"integer\",\"minimum\":0},\"items\":{\"type\":\"array\",\"items\":{\"$ref\":\"/components/schemas/Licence\"}},\"pageInfo\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"nextCursor\"],\"properties\":{\"nextCursor\":{\"type\":[\"string\",\"null\"],\"maxLength\":10978}}}}}")],
  ["/components/schemas/Permit", JSON.parse("{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"domainData\",\"recordIdentifier\",\"revisionIdentifier\"],\"properties\":{\"domainData\":{\"type\":\"object\",\"additionalProperties\":false,\"properties\":{\"label\":{\"type\":\"string\"},\"permitCode\":{\"type\":\"string\"}}},\"recordIdentifier\":{\"type\":\"string\"},\"revisionIdentifier\":{\"type\":\"string\"}}}")],
  ["/components/schemas/PermitPage", JSON.parse("{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"items\",\"pageInfo\"],\"properties\":{\"items\":{\"type\":\"array\",\"items\":{\"$ref\":\"/components/schemas/Permit\"}},\"pageInfo\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"nextCursor\"],\"properties\":{\"nextCursor\":{\"type\":[\"string\",\"null\"],\"maxLength\":10978}}}}}")],
  ["/components/schemas/Site", JSON.parse("{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"domainData\",\"recordIdentifier\",\"revisionIdentifier\"],\"properties\":{\"domainData\":{\"type\":\"object\",\"additionalProperties\":false,\"properties\":{\"label\":{\"type\":\"string\"},\"siteCode\":{\"type\":\"string\"}}},\"recordIdentifier\":{\"type\":\"string\"},\"revisionIdentifier\":{\"type\":\"string\"}}}")],
  ["/components/schemas/SitePage", JSON.parse("{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"items\",\"pageInfo\"],\"properties\":{\"items\":{\"type\":\"array\",\"items\":{\"$ref\":\"/components/schemas/Site\"}},\"pageInfo\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"nextCursor\"],\"properties\":{\"nextCursor\":{\"type\":[\"string\",\"null\"],\"maxLength\":10978}}}}}")],
  ["/paths/~1v1~1records~1licences/get/responses/200/content/application~1json/schema", JSON.parse("{\"$ref\":\"/components/schemas/LicencePage\"}")],
  ["/paths/~1v1~1records~1permits/get/responses/200/content/application~1json/schema", JSON.parse("{\"$ref\":\"/components/schemas/PermitPage\"}")],
  ["/paths/~1v1~1records~1sites/get/responses/200/content/application~1json/schema", JSON.parse("{\"$ref\":\"/components/schemas/SitePage\"}")],
])
const routes: Record<string, Operation> = Object.create(null)
type Definition = Omit<Operation, "responses"> & { problems?: Record<string, string>; responses: Record<number, Array<ResponseVariant & { rule?: string }>> }
const definitions: Record<string, Definition> = Object.fromEntries([
  ["records.licence.list", JSON.parse("{\"method\":\"GET\",\"path\":\"/v1/records/licences\",\"responses\":{\"200\":[{\"mediaType\":\"application/json\",\"mode\":\"json\",\"rule\":\"/paths/~1v1~1records~1licences/get/responses/200/content/application~1json/schema\"}]},\"accessProfileParameter\":true,\"keyed\":false,\"mutating\":false}")],
  ["records.site.list", JSON.parse("{\"method\":\"GET\",\"path\":\"/v1/records/sites\",\"responses\":{\"200\":[{\"mediaType\":\"application/json\",\"mode\":\"json\",\"rule\":\"/paths/~1v1~1records~1sites/get/responses/200/content/application~1json/schema\"}]},\"keyed\":false,\"mutating\":false}")],
  ["records.permit.list", JSON.parse("{\"method\":\"GET\",\"path\":\"/v1/records/permits\",\"responses\":{\"200\":[{\"mediaType\":\"application/json\",\"mode\":\"json\",\"rule\":\"/paths/~1v1~1records~1permits/get/responses/200/content/application~1json/schema\"}]},\"accessProfileParameter\":true,\"accessProfileRequired\":true,\"keyed\":false,\"mutating\":false}")],
])
for (const [id, definition] of Object.entries(definitions)) {
  const responses: Operation["responses"] = {}
  for (const [status, variants] of Object.entries(definition.responses)) {
    responses[Number(status)] = variants.map(variant => ({ ...variant, validate: variant.rule === undefined ? undefined : validator(rules, rules[variant.rule]) }))
  }
  routes[id] = { ...definition, product: "breg", responses, problemValidators: Object.fromEntries(Object.entries(definition.problems ?? {}).map(([status, rule]) => [status, validator(rules, rules[rule])])) }
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
  async records_licence_listPage(options: Operations["records.licence.list"]["input"] = {}, cursor?: string): Promise<Page<Schema_Licence>> {
    const { data } = await this.call("records.licence.list", { ...options, query: cursor === undefined ? options.query : { accessProfile: options.query?.accessProfile, "$skiptoken": cursor } })
    return { items: data.items, nextCursor: data.pageInfo.nextCursor ?? null }
  }
  async records_site_listPage(options: Operations["records.site.list"]["input"] = {}, cursor?: string): Promise<Page<Schema_Site>> {
    const { data } = await this.call("records.site.list", { ...options, query: cursor === undefined ? options.query : { "$skiptoken": cursor } })
    return { items: data.items, nextCursor: data.pageInfo.nextCursor ?? null }
  }
  async records_permit_listPage(options: Operations["records.permit.list"]["input"] = {}, cursor?: string): Promise<Page<Schema_Permit>> {
    const { data } = await this.call("records.permit.list", { ...options, query: cursor === undefined ? options.query : { accessProfile: options.query?.accessProfile, "$skiptoken": cursor } })
    return { items: data.items, nextCursor: data.pageInfo.nextCursor ?? null }
  }
  list<K extends keyof ListOptions>(recordType: K, ...args: {} extends ListOptions[K] ? [options?: ListOptions[K]] : [options: ListOptions[K]]): Promise<ListPage<RecordRow<ListRows[K]["domainData"]>>>
  async list(recordType: string, options: ListRequest & { after?: string } = {}): Promise<ListPage<RecordRow<unknown>>> {
    const rules = Object.hasOwn(listRules, recordType) ? listRules[recordType] : undefined
    if (!rules) throw new TypeError("Unknown record type for list")
    const { accessProfile, where, orderBy, select, count, top, after, ...call } = options
    if (after !== undefined && [where, orderBy, select, count, top].some(value => value !== undefined)) {
      throw new TypeError("Use after without where, orderBy, select, count or top.")
    }
    if (after !== undefined && (typeof after !== "string" || !after)) throw new TypeError("Use a nonempty cursor for after.")
    const query = listQuery(rules, options, after, this.#transport.profile)
    const { data } = await this.#call<{ items: RecordEnvelope[]; pageInfo: { nextCursor?: string | null }; count?: number }>(rules.operation, { ...call, query })
    const page = listPage(data)
    return { ...page, items: page.items.map(recordRow) }
  }
}

// Each Action's display text and inputs exactly as the source document declares them.
export const actionInputs = {} as const
