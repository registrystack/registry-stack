// SPDX-License-Identifier: Apache-2.0
// Step 2: simulate a target registry lookup from fixture credentials.
fn((state) => {
  const lookup = state.data.prepared_lookup;

  if (lookup.value === 'target-auth') {
    return {
      ...state,
      data: {
        error: {
          code: 'target_auth',
        },
      },
    };
  }

  if (lookup.value === 'target-rate-limit') {
    return {
      ...state,
      data: {
        error: {
          code: 'target_rate_limit',
          retry_after_seconds: 5,
        },
      },
    };
  }

  const records = state.configuration.fixture_records ?? [];
  const matched_records = records
    .filter((record) => String(record[lookup.field]) === String(lookup.value))
    .slice(0, lookup.limit);

  return {
    ...state,
    data: {
      ...state.data,
      matched_records,
    },
  };
});
