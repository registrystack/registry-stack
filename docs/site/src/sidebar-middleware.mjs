import { limitSidebarDepth } from './lib/sidebar.mjs';

/** @type {import('@astrojs/starlight/route-data').RouteMiddlewareHandler} */
export const onRequest = async (context, next) => {
  // OpenAPI adds its operation/tag groups in plugin middleware. Flatten only
  // after those entries exist, before Starlight renders the navigation.
  await next();
  context.locals.starlightRoute.sidebar = limitSidebarDepth(context.locals.starlightRoute.sidebar);
};
