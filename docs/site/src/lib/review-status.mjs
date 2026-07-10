export function reviewStatusLabel(value) {
  if (!value) return undefined;
  return value === 'unreviewed' ? 'Not yet source-reviewed' : `Last reviewed ${value}`;
}
