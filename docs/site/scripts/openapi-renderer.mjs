// starlight-openapi 0.27 assumes property/item schemas are objects when
// generating examples. OpenAPI 3.1 also permits boolean JSON Schemas. Keep
// the product artifact unchanged and adapt only the renderer's input: true
// and {} accept the same values. Remove this adapter once the renderer
// supports native boolean schemas, including examples for false schemas.

const schemaMaps = new Set(['properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas']);
const schemaLists = new Set(['allOf', 'anyOf', 'oneOf', 'prefixItems']);
const schemaValues = new Set(['items', 'contains', 'not', 'if', 'then', 'else', 'propertyNames']);
const propertyFlags = new Set(['additionalProperties', 'unevaluatedProperties', 'unevaluatedItems', 'additionalItems']);

/** Create a renderer-only OpenAPI document without changing annotation data. */
export function projectOpenApiForRenderer(document) {
  function schema(value, path) {
    if (value === true) return {};
    if (value === false) {
      // {not:{}} is equivalent, but this renderer generates an invalid
      // placeholder example for it. Refuse instead of publishing that example.
      throw new Error(`OpenAPI renderer does not support false schema at ${path}; upgrade starlight-openapi before rendering this contract`);
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
    return Object.fromEntries(Object.entries(value).map(([key, child]) => {
      const childPath = `${path}/${escapePointer(key)}`;
      if (schemaMaps.has(key) && child && typeof child === 'object') {
        return [key, Object.fromEntries(Object.entries(child).map(([name, entry]) =>
          [name, schema(entry, `${childPath}/${escapePointer(name)}`)]))];
      }
      if (schemaLists.has(key) && Array.isArray(child)) {
        return [key, child.map((entry, index) => schema(entry, `${childPath}/${index}`))];
      }
      if (schemaValues.has(key)) {
        return [key, Array.isArray(child)
          ? child.map((entry, index) => schema(entry, `${childPath}/${index}`))
          : schema(child, childPath)];
      }
      // The renderer already handles these keyword booleans as flags.
      if (propertyFlags.has(key) && typeof child !== 'boolean') return [key, schema(child, childPath)];
      return [key, child];
    }));
  }

  function map(value, path, visit) {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) visit(child, `${path}/${escapePointer(key)}`);
  }
  function content(value, path) {
    map(value?.content, `${path}/content`, (media, mediaPath) => {
      if ('schema' in media) media.schema = schema(media.schema, `${mediaPath}/schema`);
      map(media.encoding, `${mediaPath}/encoding`, headers);
    });
  }
  function parameter(value, path) {
    if ('schema' in value) value.schema = schema(value.schema, `${path}/schema`);
    content(value, path);
  }
  function headers(value, path) {
    map(value?.headers, `${path}/headers`, parameter);
  }
  function response(value, path) {
    content(value, path);
    headers(value, path);
  }
  function callback(value, path) {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      if (key.startsWith('x-') || key === '$ref') continue;
      pathItem(child, `${path}/${escapePointer(key)}`);
    }
  }
  function pathItem(value, path) {
    if (!value || typeof value !== 'object') return;
    map(value.parameters, `${path}/parameters`, parameter);
    for (const method of ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']) {
      const operation = value[method];
      if (!operation) continue;
      const operationPath = `${path}/${method}`;
      map(operation.parameters, `${operationPath}/parameters`, parameter);
      content(operation.requestBody, `${operationPath}/requestBody`);
      map(operation.responses, `${operationPath}/responses`, response);
      map(operation.callbacks, `${operationPath}/callbacks`, callback);
    }
  }

  const result = structuredClone(document);
  if (result.components?.schemas) {
    result.components.schemas = Object.fromEntries(Object.entries(result.components.schemas)
      .map(([name, value]) => [name, schema(value, `#/components/schemas/${escapePointer(name)}`)]));
  }
  // Only OpenAPI locations that can contain Schema Objects are traversed.
  for (const key of ['paths', 'webhooks']) {
    map(result[key], `#/${key}`, (value, path) => {
      if (key === 'paths' && path.startsWith('#/paths/x-')) return;
      pathItem(value, path);
    });
  }
  for (const [key, visit] of Object.entries({ parameters: parameter, headers: parameter,
    responses: response, requestBodies: content, callbacks: callback, pathItems: pathItem })) {
    map(result.components?.[key], `#/components/${key}`, visit);
  }
  return result;
}

function escapePointer(value) {
  return value.replaceAll('~', '~0').replaceAll('/', '~1');
}
