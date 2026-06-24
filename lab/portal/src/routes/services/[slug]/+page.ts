// Resolve the service form for the route slug, or 404. The descriptor is plain
// serializable data, so it loads on both server and client.

import { error } from '@sveltejs/kit';
import { getForm } from '$lib/forms';
import type { PageLoad } from './$types';

export const load: PageLoad = ({ params }) => {
  const form = getForm(params.slug);
  if (!form) {
    throw error(404, `Unknown service: ${params.slug}`);
  }
  return { form };
};
