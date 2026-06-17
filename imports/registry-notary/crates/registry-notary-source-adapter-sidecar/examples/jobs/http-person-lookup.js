// SPDX-License-Identifier: Apache-2.0
// Legacy single-step OpenFn job using @openfn/language-http against a registry-like API.
//
// Expected sidecar input:
//   state.data.lookup.value: person id to fetch
//   state.data.limit: maximum records to return, usually 2
// Expected credentials:
//   state.configuration.baseUrl
//   state.configuration.apiToken
execute(
  get(
    state => `/people/${encodeURIComponent(state.data.lookup.value)}`,
    {
      headers: state => ({
        Authorization: `Bearer ${state.configuration.apiToken}`,
      }),
      parseAs: 'json',
    },
  ),
  fn(state => {
    const records = Array.isArray(state.data?.data)
      ? state.data.data
      : Array.isArray(state.data?.records)
        ? state.data.records
        : Array.isArray(state.response?.body?.data)
          ? state.response.body.data
          : Array.isArray(state.response?.body?.records)
            ? state.response.body.records
        : [];

    return {
      ...state,
      data: records,
    };
  }),
);
