// SPDX-License-Identifier: Apache-2.0
// Step 3: return the Registry Data API data array expected by the Rust sidecar.
fn((state) => {
  if (state.data?.error) {
    return state;
  }

  return {
    ...state,
    data: state.data.matched_records ?? [],
  };
});
