import { readFileSync } from 'node:fs'
import { findPackageJSON } from 'node:module'
import { pathToFileURL } from 'node:url'
import { compatibleClientVersions } from './version.ts'
import { clientVersion as generatorVersion } from './generated-client-version.ts'

export const packageFile = new URL(import.meta.filename.endsWith('.ts') ? './package.json' : '../package.json', import.meta.url)
export const { name: packageName, version: packageVersion } = JSON.parse(readFileSync(packageFile, 'utf8')) as {
  name: string
  version: string
}

// The release plan pins the web client to the Stack release version.
export const generatedVersionComment = '// Generated for Stack version ' + packageVersion + ', client version ' + packageVersion + '.'

export function checkInstalledClient(output: string): void {
  let installed = packageVersion
  try {
    const manifest = findPackageJSON(packageName, pathToFileURL(output))
    if (manifest) installed = (JSON.parse(readFileSync(manifest, 'utf8')) as { version: string }).version
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ERR_MODULE_NOT_FOUND') throw error
  }
  if (!compatibleClientVersions(generatorVersion, installed)) {
    throw new Error('Generator version ' + generatorVersion + ' is incompatible with installed ' + packageName + ' version ' + installed +
      ', so regenerate with the version ' + installed + ' command or install the version ' + generatorVersion + ' package.')
  }
}
