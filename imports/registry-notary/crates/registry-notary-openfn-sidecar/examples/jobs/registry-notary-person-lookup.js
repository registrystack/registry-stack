// SPDX-License-Identifier: Apache-2.0
// Single lookup authored with @registry/notary-openfn helpers.
fn((state) => {
  assertNotaryRequest(state);

  const { field, value } = lookup(state);
  const records = state.configuration.fixture_records ?? [];

  if (value === 'target-auth') {
    return returnTargetAuthError(state);
  }
  if (value === 'target-rate-limit') {
    return returnTargetRateLimit(state, { retryAfterSeconds: 5 });
  }

  const data = records
    .filter((record) => String(record[field]) === String(value))
    .slice(0, 2);

  return returnRecords(state, data);
});
