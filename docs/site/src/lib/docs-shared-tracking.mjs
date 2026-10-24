export function docsSharedTrackingEnabled({ isReleasedArchiveBuild, base, path }) {
  return Boolean(
    isReleasedArchiveBuild &&
      base === '/' &&
      path !== '/404/' &&
      path !== '/404',
  );
}
