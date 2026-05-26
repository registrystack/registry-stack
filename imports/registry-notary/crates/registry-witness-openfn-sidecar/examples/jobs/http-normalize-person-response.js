// SPDX-License-Identifier: Apache-2.0
// Step 3: normalize the target response into an RDA-compatible data array.
fn((state) => {
  const records = Array.isArray(state.data?.data)
    ? state.data.data
    : Array.isArray(state.data?.records)
      ? state.data.records
      : [];

  return {
    ...state,
    data: records,
  };
});
