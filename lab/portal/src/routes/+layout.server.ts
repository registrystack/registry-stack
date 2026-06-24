import { getSessionId } from '$lib/server/session';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = ({ cookies }) => ({
  proofFeedEnabled: Boolean(getSessionId(cookies))
});
