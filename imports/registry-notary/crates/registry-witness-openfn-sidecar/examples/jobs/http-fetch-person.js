// SPDX-License-Identifier: Apache-2.0
// Step 2: call the registry-like HTTP API with sidecar-held credentials.
get(
  state => state.data.person_path,
  {
    headers: state => ({
      Authorization: `Bearer ${state.configuration.apiToken}`,
    }),
    parseAs: 'json',
  },
);
