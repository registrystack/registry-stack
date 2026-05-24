// SPDX-License-Identifier: Apache-2.0
// Sample OpenFn workflow for the sidecar's synchronous Registry Data API facade.
//
// This job uses @openfn/language-common so it can run without a live target
// registry. Production jobs should replace the fixture lookup with adaptor calls
// to the target service, then return an array of records in state.data.
fn((state) => {
  const { field, value } = state.data.lookup;
  const limit = state.data.limit ?? 2;
  const records = state.configuration.fixture_records ?? [];

  if (value === 'target-auth') {
    return {
      ...state,
      data: {
        error: {
          code: 'target_auth',
        },
      },
    };
  }

  if (value === 'target-rate-limit') {
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

  const data = records
    .filter((record) => String(record[field]) === String(value))
    .slice(0, limit);

  return {
    ...state,
    data,
  };
});
