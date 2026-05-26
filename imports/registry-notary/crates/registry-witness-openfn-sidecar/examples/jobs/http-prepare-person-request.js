// SPDX-License-Identifier: Apache-2.0
// Step 1: derive the target request path from the sidecar lookup input.
fn((state) => ({
  ...state,
  data: {
    ...state.data,
    person_path: `/people/${encodeURIComponent(state.data.lookup.value)}`,
  },
}));
