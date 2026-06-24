const UPPERCASE = /[A-Z]/g;
const SNAKE_SEGMENT = /_([a-zA-Z0-9])/g;

/**
 * @param {string} key
 */
export function camelToSnakeKey(key) {
  return key.replace(UPPERCASE, (letter) => `_${letter.toLowerCase()}`);
}

/**
 * @param {string} key
 */
export function snakeToCamelKey(key) {
  return key.replace(SNAKE_SEGMENT, (_match, letter) => letter.toUpperCase());
}

/**
 * Recursively converts plain object keys. Values that are not JSON containers
 * are returned as-is so AbortSignal and other host objects are not traversed.
 *
 * @param {unknown} value
 * @param {(key: string) => string} convertKey
 * @returns {unknown}
 */
export function convertJsonKeys(value, convertKey) {
  if (Array.isArray(value)) {
    return value.map((item) => convertJsonKeys(item, convertKey));
  }

  if (!isPlainObject(value)) {
    return value;
  }

  /** @type {Record<string, unknown>} */
  const converted = {};
  for (const [key, item] of Object.entries(value)) {
    converted[convertKey(key)] = convertJsonKeys(item, convertKey);
  }
  return converted;
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
