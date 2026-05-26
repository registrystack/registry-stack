// SPDX-License-Identifier: Apache-2.0
// Step 1: preserve the sidecar lookup request as workflow-local state.
fn((state) => ({
  ...state,
  data: {
    ...state.data,
    prepared_lookup: {
      field: state.data.lookup.field,
      value: state.data.lookup.value,
      limit: state.data.limit ?? 2,
    },
  },
}));
