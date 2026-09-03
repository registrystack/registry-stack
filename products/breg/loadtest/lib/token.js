// Token acquisition for the load-test harness.
//
// k6 acquires access tokens from Registry Mint with plain client_secret_post
// requests (the same OAuth client-credential grant the real driver client
// uses), caching each token until shortly before its expiry. The HERD mode
// bypasses the cache so every iteration exercises the token endpoint itself.

import http from 'k6/http';

const REFRESH_MARGIN_SECONDS = 60;

const state = {
  token: '',
  expiresAt: 0,
};

export function driverToken(tokenUrl, clientId, clientSecret, { herd = false } = {}) {
  if (!herd) {
    const now = Date.now() / 1000;
    if (state.token && now < state.expiresAt) {
      return state.token;
    }
  }
  const response = http.post(
    tokenUrl,
    {
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret,
    },
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, tags: { name: 'mint_token' } }
  );
  if (response.status !== 200) {
    throw new Error(`token endpoint returned ${response.status}`);
  }
  const body = response.json();
  if (!body.access_token) {
    throw new Error('token endpoint returned no access_token');
  }
  state.token = body.access_token;
  state.expiresAt = Date.now() / 1000 + (body.expires_in || 300) - REFRESH_MARGIN_SECONDS;
  return state.token;
}
