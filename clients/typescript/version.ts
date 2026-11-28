import { clientVersion } from './generated-client-version.ts'

export function compatibleClientVersions(first: string, second: string): boolean {
  const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u
  const left = semver.exec(first)
  const right = semver.exec(second)
  return !!left && !!right && left[1] === right[1] && (left[1] !== '0' || left[2] === right[2])
}

export function assertClientVersion(generatedFor: string): void {
  if (!compatibleClientVersions(generatedFor, clientVersion)) {
    throw new TypeError('Generated client version ' + generatedFor + ' is incompatible with runtime version ' + clientVersion +
      ', so regenerate with the version ' + clientVersion + ' command or install the version ' + generatedFor + ' package.')
  }
}
