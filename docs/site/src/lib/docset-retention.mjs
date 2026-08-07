const releaseTagPattern =
  /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

function releaseVersion(docset) {
  const match = releaseTagPattern.exec(docset.id);
  if (!match) return null;
  return match.slice(1).map(Number);
}

function compareReleaseDocsets(left, right) {
  const leftVersion = releaseVersion(left);
  const rightVersion = releaseVersion(right);
  for (let index = 0; index < leftVersion.length; index += 1) {
    if (leftVersion[index] !== rightVersion[index]) {
      return rightVersion[index] - leftVersion[index];
    }
  }
  return 0;
}

export function publishedArchiveLimit(manifest) {
  const limit = manifest.published_archive_limit;
  if (limit === undefined) return Number.POSITIVE_INFINITY;
  if (!Number.isInteger(limit) || limit < 1) {
    throw new Error('docsets.yaml published_archive_limit must be a positive integer');
  }
  return limit;
}

export function publishedArchiveDocsets(manifest) {
  const limit = publishedArchiveLimit(manifest);
  const archived = manifest.docsets.filter((docset) => docset.status === 'archived');
  if (limit === Number.POSITIVE_INFINITY) return archived;
  return archived
    .filter((docset) => releaseVersion(docset))
    .sort(compareReleaseDocsets)
    .slice(0, limit);
}

export function selectableDocsets(manifest) {
  const publishedIds = new Set(
    publishedArchiveDocsets(manifest).map((docset) => docset.id),
  );
  return manifest.docsets.filter(
    (docset) => docset.id === manifest.current || publishedIds.has(docset.id),
  );
}
