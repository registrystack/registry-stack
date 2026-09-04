'use strict';

const PACKAGE_VERSION = '0.26.0';
const PRODUCTS = new Set(['discovery', 'evidence', 'relay', 'breg']);

function target() {
  if (process.platform === 'darwin' && process.arch === 'arm64') return 'darwin-arm64';
  if (process.platform === 'linux' && process.arch === 'arm64') return 'linux-arm64-gnu';
  if (process.platform === 'linux' && process.arch === 'x64') return 'linux-x64-gnu';
  throw new Error(`@registrystack/client does not support ${process.platform}-${process.arch}`);
}

function load(product) {
  if (!PRODUCTS.has(product)) throw new Error(`unknown Registry Stack client product: ${product}`);
  const suffix = target();
  const packageName = `@registrystack/client-${suffix}`;
  let bindings;
  try {
    bindings = require(packageName);
  } catch (error) {
    error.message = `Unable to load ${packageName}. Reinstall @registrystack/client for this platform. ${error.message}`;
    throw error;
  }
  const installedVersion = require(`${packageName}/package.json`).version;
  if (installedVersion !== PACKAGE_VERSION) {
    throw new Error(`Native client package version mismatch: expected ${PACKAGE_VERSION}, got ${installedVersion}`);
  }
  if (!Object.hasOwn(bindings, product)) {
    throw new Error(`${packageName} does not contain the ${product} binding`);
  }
  return bindings[product];
}

module.exports = { load };
