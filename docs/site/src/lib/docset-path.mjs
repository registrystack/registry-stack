function normalizeRoot(path) {
  const normalized = `/${String(path || '/').replace(/^\/+|\/+$/g, '')}/`;
  return normalized === '//' ? '/' : normalized;
}

function relativeToRoot(pathname, root) {
  const normalizedRoot = normalizeRoot(root);
  const rootWithoutSlash = normalizedRoot.replace(/\/$/, '');

  if (pathname === rootWithoutSlash) return '';
  if (normalizedRoot !== '/' && pathname.startsWith(normalizedRoot)) {
    return pathname.slice(normalizedRoot.length);
  }
  return pathname.replace(/^\//, '');
}

export function pathForDocset(currentPath, activePath, targetPath, basePath = '/') {
  const normalizedActive = normalizeRoot(activePath);
  const normalizedBase = normalizeRoot(basePath);
  const sourceRoot = normalizedActive === '/' ? normalizedBase : normalizedActive;
  const targetRoot =
    normalizedActive === '/' && normalizeRoot(targetPath) === normalizedActive
      ? normalizedBase
      : normalizeRoot(targetPath);
  const relativePath = relativeToRoot(currentPath, sourceRoot);

  return `${targetRoot}${relativePath}`.replace(/\/{2,}/g, '/');
}
