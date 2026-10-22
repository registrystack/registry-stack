// Which version label a release docset gives each product, decided by the
// release manifest and src/data/docset-release-artifacts.yaml. Release
// preparation writes these labels, and the docs tests hold archived docsets
// to them.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import YAML from 'yaml';

export const UNRELEASED_PRODUCT_VERSION = 'main source (unreleased)';
export const RELEASE_ARTIFACTS_FILE = 'docset-release-artifacts.yaml';

const releaseTagPattern = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

function releaseTagVersion(value) {
  const match = releaseTagPattern.exec(typeof value === 'string' ? value : '');
  return match ? match.slice(1).map(Number) : null;
}

function compareVersions(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

export async function loadReleaseArtifacts(siteRoot) {
  return YAML.parse(await readFile(resolve(siteRoot, 'src/data', RELEASE_ARTIFACTS_FILE), 'utf8'));
}

/** The manifest artifact that ships a docset product; throws when none is declared. */
export function releaseArtifactFor(productId, docsetId, releaseArtifacts) {
  const artifact = releaseArtifacts?.products?.[productId];
  if (typeof artifact !== 'string' || !artifact) {
    throw new Error(`docset ${docsetId} product ${productId} names no release artifact in ${RELEASE_ARTIFACTS_FILE}`);
  }
  return artifact;
}

/** The release version when the manifest ships the product, else the unreleased label. */
export function releaseProductVersion(productId, docsetId, manifest, releaseArtifacts) {
  const artifact = releaseArtifactFor(productId, docsetId, releaseArtifacts);
  if (!Object.hasOwn(manifest?.artifacts ?? {}, artifact)) return UNRELEASED_PRODUCT_VERSION;
  const version = manifest.artifacts[artifact];
  if (typeof version !== 'string' || !releaseTagPattern.test(`v${version}`)) {
    throw new Error(`release manifest artifact ${artifact} must be an unprefixed stable semantic version`);
  }
  return `v${version}`;
}

/**
 * Labels in release docsets from `applies_from` on that disagree with what
 * their release manifest ships. `manifests` maps a source tag to its manifest.
 */
export function releaseLabelErrors({ docsets, manifests, releaseArtifacts }) {
  const appliesFrom = releaseTagVersion(releaseArtifacts?.applies_from);
  if (!appliesFrom) return [`${RELEASE_ARTIFACTS_FILE} applies_from must be a release tag`];
  const errors = [];
  for (const docset of docsets?.docsets ?? []) {
    const version = releaseTagVersion(docset.id);
    if (!version || compareVersions(version, appliesFrom) < 0) continue;
    const manifest = manifests.get(docset.id);
    if (!manifest) {
      errors.push(`docset ${docset.id} has no release manifest`);
      continue;
    }
    for (const [productId, product] of Object.entries(docset.products ?? {})) {
      if (Object.hasOwn(manifest.external ?? {}, productId)) continue;
      let artifact;
      try {
        artifact = releaseArtifactFor(productId, docset.id, releaseArtifacts);
      } catch (error) {
        errors.push(error.message);
        continue;
      }
      const expected = releaseProductVersion(productId, docset.id, manifest, releaseArtifacts);
      if (product?.version === expected) continue;
      errors.push(expected === UNRELEASED_PRODUCT_VERSION
        ? `docset ${docset.id} labels ${productId} '${product?.version}' but release manifest ${docset.id} ships no ${artifact} artifact; label it '${UNRELEASED_PRODUCT_VERSION}'`
        : `docset ${docset.id} labels ${productId} '${product?.version}' but release manifest ${docset.id} ships its ${artifact} artifact; label it '${expected}'`);
    }
  }
  return errors;
}
