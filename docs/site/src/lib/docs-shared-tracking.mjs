export function docsSharedTrackingEnabled({
  isReleasedArchiveBuild,
  isCurrentDocsetBuild,
  base,
  path,
}) {
  const isPublicBuild =
    (isReleasedArchiveBuild && base === '/') ||
    (isCurrentDocsetBuild && base === '/dev/');
  return Boolean(isPublicBuild && path !== '/404/' && path !== '/404');
}
