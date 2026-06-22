// Guard for every /services route: a session is required. The session subject is
// resolved server-side (never from a client-supplied id); unauthenticated visitors
// are sent back to the landing to sign in. The display name flows to the pages so
// the identity fields prefill without the browser ever seeing the raw national id.

import { redirect } from '@sveltejs/kit';
import { getSession } from '$lib/server/session';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = ({ cookies }) => {
  const session = getSession(cookies);
  if (!session) {
    throw redirect(302, '/');
  }
  return { displayName: session.displayName, subject: session.subject };
};
