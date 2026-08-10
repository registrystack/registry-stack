#!/usr/bin/env bash
set -euo pipefail

java_major_from_text() {
  sed -nE 's/.*version "([0-9]+)([^\"]*)".*/\1/p' <<<"$1" | head -n 1
}

android_components_present() {
  local sdk_root=$1
  [[ -d "$sdk_root/platforms/android-34" && -d "$sdk_root/build-tools/33.0.1" ]]
}

iphone_15_present() {
  grep -Eq '(^|[[:space:]])iPhone 15 \(' <<<"$1"
}

self_test_preflight_helpers() {
  [[ $(java_major_from_text 'openjdk version "17.0.20" 2026-07-15') == 17 ]]
  [[ $(java_major_from_text 'openjdk version "21.0.1" 2025-10-17') == 21 ]]
  [[ -z $(java_major_from_text 'not a Java version') ]]

  local fixture_root
  fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/registry-inji-preflight.XXXXXX")
  mkdir -p \
    "$fixture_root/platforms/android-34" \
    "$fixture_root/build-tools/33.0.1"
  android_components_present "$fixture_root"
  rm -rf -- "$fixture_root/build-tools/33.0.1"
  if android_components_present "$fixture_root"; then
    printf 'Android component preflight accepted a missing build-tools directory.\n' >&2
    rm -rf -- "$fixture_root"
    return 1
  fi
  rm -rf -- "$fixture_root"

  iphone_15_present '    iPhone 15 (00000000-0000-0000-0000-000000000000) (Shutdown)'
  if iphone_15_present '    iPhone 16 (00000000-0000-0000-0000-000000000000) (Shutdown)'; then
    printf 'Simulator preflight accepted the wrong device.\n' >&2
    return 1
  fi
  printf 'PASS: pinned Inji OID4VCI preflight helpers\n'
}

if [[ ${1:-} == --self-test ]]; then
  [[ $# == 1 ]] || {
    printf 'The preflight self-test accepts no additional arguments.\n' >&2
    exit 1
  }
  self_test_preflight_helpers
  exit 0
fi

[[ $# == 0 ]] || {
  printf 'The pinned Inji OID4VCI runner accepts no arguments.\n' >&2
  exit 1
}

if [[ ${EVIDENCE_INJI_OID4VCI:-0} != 1 ]]; then
  printf 'SKIP: set EVIDENCE_INJI_OID4VCI=1 to run pinned Inji source and client tests.\n'
  exit 0
fi

[[ $(uname -s) == Darwin ]] || {
  printf 'Pinned Inji OID4VCI checking requires macOS because the combined receipt includes iOS client tests.\n' >&2
  exit 1
}

for tool in git npm java xcodebuild xcrun; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'Pinned Inji OID4VCI checking needs %s on PATH.\n' "$tool" >&2
    exit 1
  }
done

java_version=$(java -version 2>&1) || {
  printf 'Pinned Inji OID4VCI checking needs an installed Java runtime.\n' >&2
  exit 1
}
java_major=$(java_major_from_text "$java_version")
[[ $java_major == 17 ]] || {
  printf 'Pinned Inji OID4VCI checking needs Java 17; the installed runtime is not Java 17.\n' >&2
  exit 1
}

android_sdk_root=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
[[ -n $android_sdk_root && -d $android_sdk_root ]] || {
  printf 'Pinned Inji OID4VCI checking needs ANDROID_HOME or ANDROID_SDK_ROOT to name an installed Android SDK.\n' >&2
  exit 1
}
android_components_present "$android_sdk_root" || {
  printf 'Pinned Inji OID4VCI checking needs Android SDK platform 34 and Build Tools 33.0.1.\n' >&2
  exit 1
}

xcodebuild -version >/dev/null 2>&1 || {
  printf 'Pinned Inji OID4VCI checking needs full Xcode, not Command Line Tools alone.\n' >&2
  exit 1
}
available_simulators=$(xcrun simctl list devices available) || {
  printf 'Pinned Inji OID4VCI checking could not inspect installed iOS simulators.\n' >&2
  exit 1
}
iphone_15_present "$available_simulators" || {
  printf 'Pinned Inji OID4VCI checking needs an available iPhone 15 simulator.\n' >&2
  exit 1
}

workspace=$(mktemp -d "${TMPDIR:-/tmp}/registry-inji-oid4vci.XXXXXX")
trap 'rm -rf -- "$workspace"' EXIT HUP INT TERM

clone_pinned() {
  name=$1
  repository=$2
  revision=$3
  destination="$workspace/$name"

  git clone --quiet --filter=blob:none --no-checkout --branch develop \
    "$repository" "$destination"
  git -C "$destination" cat-file -e "$revision^{commit}" 2>/dev/null || {
    printf '%s does not contain the reviewed revision.\n' "$name" >&2
    exit 1
  }
  git -C "$destination" -c advice.detachedHead=false checkout --quiet --detach "$revision"
  actual=$(git -C "$destination" rev-parse HEAD)
  [[ $actual == "$revision" ]] || {
    printf '%s checked out an unexpected revision.\n' "$name" >&2
    exit 1
  }
}

clone_pinned \
  inji-wallet \
  https://github.com/mosip/inji-wallet.git \
  2fa12c3285b6523db340c3dd2333454b750b40a4
clone_pinned \
  inji-vci-client \
  https://github.com/mosip/inji-vci-client.git \
  f1d7ee2b14e996e18bfc7c40fbf89ec31b768951
clone_pinned \
  inji-vci-client-ios-swift \
  https://github.com/mosip/inji-vci-client-ios-swift.git \
  dbe60eef9a8c7b71ba58ee81cc7d0e5a92af7c7c

# The wallet test proves the pinned app still routes credential-offer work
# through its VCI client boundary. Installation skips repository hooks and
# device builds, neither of which participates in this source-level check.
(
  cd "$workspace/inji-wallet"
  npm ci --ignore-scripts
  # This git dependency builds its distributable during `prepare`, which the
  # clean install intentionally skipped together with repository hooks. Build
  # that dependency alone, then expose the generated entry point under the
  # package name the pinned Jest setup mocks. Nothing in the checkout changes.
  npm rebuild telemetry-sdk
  ln -s js/dist/index.js node_modules/telemetry-sdk/index.js
  npx jest --runInBand machines/Issuers/IssuersService.test.ts --coverage=false
)

# These are the pinned clients' own Final-shape request, response, nonce, proof,
# and pre-authorized-flow tests. They exercise upstream serialization and
# parsing rather than reimplementing it in this repository.
(
  cd "$workspace/inji-vci-client/kotlin"
  ./gradlew --no-daemon :vci-client:testDebugUnitTest \
    --tests io.mosip.vciclient.credential.request.CredentialRequestFactoryV2Test \
    --tests io.mosip.vciclient.credential.response.CredentialResponseTest \
    --tests io.mosip.vciclient.preAuthCodeFlow.PreAuthCodeFlowServiceV1Test \
    --tests io.mosip.vciclient.proof.jwt.JWTProofTest
)

(
  cd "$workspace/inji-vci-client-ios-swift"
  xcodebuild test \
    -scheme VCIClientTests \
    -destination 'platform=iOS Simulator,OS=latest,name=iPhone 15' \
    -only-testing:VCIClientTests/CredentialRequestFactoryTests \
    -only-testing:VCIClientTests/CredentialResponseTest \
    -only-testing:VCIClientTests/PreAuthFlowServiceTests
)

printf 'PASS: pinned Inji OID4VCI source and client tests\n'
